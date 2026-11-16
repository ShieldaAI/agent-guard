import { createHash } from 'node:crypto';
import type { Agent, Confidence, Finding, Grant, Location, RuleMeta, Severity } from './types.js';
import { CAPABILITY_LABELS } from './types.js';
import type { Project } from './model.js';
import { bashScope, parseRule, type PermissionRule } from './claude.js';
import { dockerImage, runnerPackage, splitSpec, type McpServer } from './mcp.js';
import { authority, primaryGrant } from './authority.js';
import { findHiddenCharacter, lineAt, mask } from './text.js';
import { UNTRUSTED_TRIGGERS } from './workflows.js';

interface Rule extends RuleMeta {
  check(project: Project, emit: Emit): void;
}

type Emit = (
  rule: RuleMeta,
  input: {
    readonly message: string;
    readonly location: Location;
    readonly subject: string;
    readonly agent?: Agent | undefined;
    readonly severity?: Severity;
    readonly confidence?: Confidence;
    readonly fix?: string;
  },
) => void;

export function fingerprint(ruleId: string, agentId: string, file: string, subject: string): string {
  return createHash('sha256').update(`${ruleId}\0${agentId}\0${file}\0${subject}`).digest('hex').slice(0, 20);
}

const ASI = {
  goal: 'ASI01',
  tools: 'ASI02',
  identity: 'ASI03',
  supply: 'ASI04',
  code: 'ASI05',
  memory: 'ASI06',
  cascade: 'ASI08',
  trust: 'ASI09',
  rogue: 'ASI10',
} as const;

const DESTRUCTIVE_TOOL =
  /(delete|remove|drop|destroy|truncate|merge|push|publish|deploy|send|post|transfer|pay|charge|refund|payment|wire)/i;
const DESTRUCTIVE_COMMAND =
  /^(git push|rm\b|npm publish|pnpm publish|yarn publish|terraform (apply|destroy)|kubectl (delete|apply)|docker push|gh (pr merge|release|repo delete)|aws s3 rm|gcloud .* delete)/;
const PIPE_TO_SHELL =
  /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(bash|sh|zsh)\s+<\(\s*(curl|wget)\b|\b(iex|Invoke-Expression)\b[^\n]*\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i;
const REMOTE_FETCH = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*https?:\/\//i;
const IDENTITY_WRITE =
  /(>>?|\btee(\s+-a)?|\bsed\s+-i\S*|\bcp\b|\bmv\b)\s+[^|;&\n]*?\b(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)\b/;
const SETTINGS_WRITE =
  /(>>?|\btee(\s+-a)?|\bsed\s+-i\S*|\bcp\b|\bmv\b|\bjq\b[^\n]*>)\s+[^|;&\n]*?\.claude\/(settings(\.local)?\.json|hooks|agents|skills)/;

const TOKEN_PATTERNS: readonly [string, RegExp][] = [
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}/],
  ['Stripe live key', /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
];
const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|^AUTH)/i;
const PLACEHOLDER =
  /^\$|\$\{|^<.*>$|^\{\{.*\}\}$|your|xxx|changeme|example|placeholder|dummy|redacted|replace|insert|\*\*\*|^(true|false|null|none)$/i;

/** A literal value that looks like a real credential rather than a placeholder or reference. */
function literalSecret(name: string, value: string): string | undefined {
  for (const [label, pattern] of TOKEN_PATTERNS) if (pattern.test(value)) return label;
  if (!SECRET_NAME.test(name)) return undefined;
  const bare = value.replace(/^(Bearer|Basic|token)\s+/i, '').trim();
  if (bare.length < 16 || PLACEHOLDER.test(bare) || !/[0-9]/.test(bare) || !/[A-Za-z]/.test(bare) || /\s/.test(bare))
    return undefined;
  return 'credential';
}

function knownToken(text: string): { label: string; index: number; value: string } | undefined {
  for (const [label, pattern] of TOKEN_PATTERNS) {
    const match = pattern.exec(text);
    if (match) return { label, index: match.index, value: match[0] };
  }
  return undefined;
}

const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/;

function rule(meta: RuleMeta, check: Rule['check']): Rule {
  return { ...meta, check };
}

function serverLabel(server: McpServer): string {
  return `MCP server "${server.name}"`;
}

function agentServers(project: Project): McpServer[] {
  return [...project.servers, ...project.workflows.flatMap(step => step.servers)];
}

function allowRules(project: Project): PermissionRule[] {
  return [...project.settings.flatMap(file => file.allow), ...project.workflows.flatMap(step => step.allowedTools)];
}

const hooks = (project: Project) => project.settings.flatMap(file => file.hooks);

export const RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-PERM-001',
      title: 'Agent runs every tool without asking',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.tools, ASI.trust],
      help: 'Bypass modes remove the approval step for every tool, including shell commands and outbound requests.',
    },
    (project, emit) => {
      for (const file of project.settings)
        if (file.defaultMode?.value === 'bypassPermissions')
          emit(RULES_BY_ID['AGC-PERM-001']!, {
            message: 'Claude Code runs every tool without asking (defaultMode: bypassPermissions).',
            location: file.defaultMode.location,
            subject: 'defaultMode',
            agent: project.agents.find(agent => agent.kind === 'claude-code'),
            fix: 'Remove defaultMode or set it to "default", and allow only the tools the agent needs.',
          });
      for (const step of project.workflows)
        if (step.skipPermissions) {
          const untrusted = step.triggers.some(trigger => UNTRUSTED_TRIGGERS.has(trigger));
          emit(RULES_BY_ID['AGC-PERM-001']!, {
            message: `The ${step.job} job runs the agent with approvals and sandbox turned off${untrusted ? ', on events outsiders can trigger' : ''}.`,
            location: step.skipPermissions,
            subject: `${step.job}/${step.step}`,
            agent: project.agents.find(agent => agent.id === `workflow:${step.path}#${step.job}/${step.step}`),
            severity: untrusted ? 'critical' : 'high',
            fix: 'Replace the bypass flag with --allowedTools listing only the tools this job needs.',
          });
        }
      for (const file of project.scripts) {
        const index = file.text.search(/--dangerously-(skip-permissions|bypass-approvals-and-sandbox)/);
        if (index >= 0)
          emit(RULES_BY_ID['AGC-PERM-001']!, {
            message: 'A script starts the agent with approvals turned off.',
            location: { file: file.path, line: lineAt(file.text, index) },
            subject: 'script',
            fix: 'Pass --allowedTools with the specific tools instead.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PERM-002',
      title: 'Wildcard tool allow',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools],
      help: 'An allow rule for every shell command, or every tool, removes approval for anything the agent decides to run.',
    },
    (project, emit) => {
      const servers = agentServers(project);
      for (const allowed of allowRules(project)) {
        if (allowed.tool === '*' || (allowed.tool === 'Bash' && bashScope(allowed.specifier) === 'any')) {
          emit(RULES_BY_ID['AGC-PERM-002']!, {
            message: `"${allowed.raw}" lets the agent run any ${allowed.tool === '*' ? 'tool' : 'shell command'} without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Replace it with the specific commands the agent needs, such as "Bash(npm test:*)".',
          });
        } else if (allowed.tool === 'mcp' && allowed.mcpTool === undefined) {
          const server = servers.find(item => item.name === allowed.server);
          const caps = server?.catalog?.capabilities ?? {};
          if (caps.egress === 'yes' || caps.spend === 'yes' || caps.write === 'yes')
            emit(RULES_BY_ID['AGC-PERM-002']!, {
              message: `"${allowed.raw}" allows every ${server!.catalog!.label} tool without asking, including ones that ${caps.spend === 'yes' ? 'spend money' : caps.egress === 'yes' ? 'send data out' : 'write'}.`,
              location: allowed.location,
              subject: allowed.raw,
              severity: 'medium',
              fix: `List the read-only ${server!.catalog!.label} tools the agent needs, for example "mcp__${allowed.server}__get_…", and leave the rest behind approval.`,
            });
        }
      }
    },
  ),
  rule(
    {
      id: 'AGC-PERM-003',
      title: 'Allowed command can send data out or run any code',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.code],
      help: 'Network tools and interpreters (curl, ssh, python, node, npx) can reach any host, so allowing them is close to allowing everything.',
    },
    (project, emit) => {
      for (const allowed of allowRules(project))
        if (allowed.tool === 'Bash' && bashScope(allowed.specifier) === 'network')
          emit(RULES_BY_ID['AGC-PERM-003']!, {
            message: `"${allowed.raw}" runs without asking and can reach the network or run arbitrary code.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Keep this command behind approval, or narrow it to a fixed script that cannot take arbitrary arguments.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-PERM-004',
      title: 'Agent can read files outside the project',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Home directories hold SSH keys, cloud credentials and tokens. An agent that can read them can leak them.',
    },
    (project, emit) => {
      for (const file of project.settings) {
        for (const allowed of file.allow)
          if (['Read', 'Glob', 'Grep', 'LS'].includes(allowed.tool) && /^(~|\/\/|\$HOME)/.test(allowed.specifier ?? ''))
            emit(RULES_BY_ID['AGC-PERM-004']!, {
              message: `"${allowed.raw}" lets the agent read outside the project without asking, where keys and tokens live.`,
              location: allowed.location,
              subject: allowed.raw,
              fix: 'Allow only the specific directory the agent needs, and deny ~/.ssh, ~/.aws and .env files.',
            });
        for (const directory of file.additionalDirectories)
          if (/^(~\/?|\/|\$HOME\/?)$/.test(directory.value.trim()))
            emit(RULES_BY_ID['AGC-PERM-004']!, {
              message: `additionalDirectories includes "${directory.value}", which opens the whole ${directory.value.trim() === '/' ? 'disk' : 'home directory'} to the agent.`,
              location: directory.location,
              subject: `dir:${directory.value}`,
              fix: 'List only the project directories the agent needs.',
            });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PERM-005',
      title: 'Destructive action allowed without approval',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.tools, ASI.trust],
      help: 'Deleting, publishing, merging, sending and paying are hard to undo; a person should confirm each one.',
    },
    (project, emit) => {
      for (const allowed of allowRules(project)) {
        const destructive =
          (allowed.tool === 'mcp' && allowed.mcpTool !== undefined && DESTRUCTIVE_TOOL.test(allowed.mcpTool)) ||
          (allowed.tool === 'Bash' && DESTRUCTIVE_COMMAND.test((allowed.specifier ?? '').trim()));
        if (destructive)
          emit(RULES_BY_ID['AGC-PERM-005']!, {
            message: `"${allowed.raw}" runs without asking, and it cannot easily be undone.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: `Move "${allowed.raw}" from allow to ask.`,
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TRI-001',
      title: 'Lethal trifecta: private data, untrusted input and an unguarded way out',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.goal, ASI.tools],
      help: 'An agent that reads private data and untrusted text, and can send data out without approval, can be steered by that text into leaking the data.',
    },
    (project, emit) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent') continue;
        const a = authority(agent);
        const legs = [a.privateData, a.untrustedInput, a.egress];
        if (!legs.every(state => state.value === 'yes') || a.egress.approval !== 'auto') continue;
        const way = primaryGrant(a.egress)!;
        emit(RULES_BY_ID['AGC-TRI-001']!, {
          message: `${agent.name} reads private data (${primaryGrant(a.privateData)!.via}), reads untrusted input (${primaryGrant(a.untrustedInput)!.via}) and can send data out without approval (${way.via}).`,
          location: way.location,
          subject: 'trifecta',
          agent,
          fix: `Require approval for "${way.via}", or remove one of the three legs.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TRI-002',
      title: 'Lethal trifecta behind one approval, or one leg unknown',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.goal],
      help: 'Untrusted input arrives without approval and the agent reads private data; only the approval prompt on sending data out stands in the way, or one leg could not be determined. Approval fatigue makes the first case fragile.',
    },
    (project, emit) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent') continue;
        const a = authority(agent);
        const legs = { privateData: a.privateData, untrustedInput: a.untrustedInput, egress: a.egress };
        const values = Object.values(legs).map(state => state.value);
        const yes = values.filter(value => value === 'yes').length;
        if (yes === 3 && a.egress.approval === 'ask' && a.untrustedInput.approval === 'auto') {
          const way = primaryGrant(a.egress)!;
          emit(RULES_BY_ID['AGC-TRI-002']!, {
            message: `${agent.name} has all three legs; only the approval prompt for "${way.via}" stands between untrusted input (${primaryGrant(a.untrustedInput)!.via}) and private data (${primaryGrant(a.privateData)!.via}).`,
            location: way.location,
            subject: 'trifecta-ask',
            agent,
            fix: 'Keep that prompt, and remove one leg where you can.',
          });
        } else if (yes === 2 && values.includes('unknown')) {
          const [unknownName, unknown] = Object.entries(legs).find(([, state]) => state.value === 'unknown')!;
          const autoLegs = Object.values(legs)
            .filter(state => state.value === 'yes')
            .every(state => state.approval === 'auto');
          if (unknown.approval !== 'auto' || !autoLegs) continue;
          const grant = primaryGrant(unknown)!;
          emit(RULES_BY_ID['AGC-TRI-002']!, {
            message: `${agent.name} has two legs of the trifecta without approval; whether it also ${CAPABILITY_LABELS[unknownName as 'egress']} through "${grant.via}" is unknown.`,
            location: grant.location,
            subject: `trifecta-unknown:${unknownName}`,
            agent,
            fix: 'Confirm what that path can do; if it can, treat this as AGC-TRI-001.',
          });
        }
      }
    },
  ),
  rule(
    {
      id: 'AGC-SUP-001',
      title: 'MCP server runs an unpinned package',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'npx, uvx and docker fetch whatever is newest at start-up. A compromised release then runs with the agent’s access.',
    },
    (project, emit) => {
      for (const server of agentServers(project)) {
        const runner = runnerPackage(server.command, server.args);
        if (runner) {
          const { name, version } = splitSpec(runner.spec);
          // A project dependency or a local path resolves inside the repo, not from the registry.
          if (
            runner.localOnly ||
            project.dependencies.has(name) ||
            /^(\.{1,2}\/|\/|file:|link:|workspace:)/.test(runner.spec)
          )
            continue;
          if (
            !version ||
            version === 'latest' ||
            version === 'next' ||
            version.startsWith('^') ||
            version.startsWith('~')
          )
            emit(RULES_BY_ID['AGC-SUP-001']!, {
              message: `${serverLabel(server)} starts "${runner.spec}" with ${runner.runner} and no pinned version, so every new release runs automatically.`,
              location: server.location,
              subject: `server:${server.name}`,
              fix: `Pin an exact version, for example "${name}${runner.runner === 'uvx' || runner.runner === 'pipx' ? '==' : '@'}<version>".`,
            });
          continue;
        }
        const image = dockerImage(server.command, server.args);
        if (image && !image.includes('@sha256:') && (!/:[^/:]+$/.test(image) || image.endsWith(':latest')))
          emit(RULES_BY_ID['AGC-SUP-001']!, {
            message: `${serverLabel(server)} runs image "${image}" with no fixed tag or digest.`,
            location: server.location,
            subject: `server:${server.name}`,
            fix: 'Pin the image by digest: image@sha256:<digest>.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-SUP-002',
      title: 'Remote MCP server over plain HTTP',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'Without TLS, anyone on the network path can read the traffic and replace tool descriptions or results.',
    },
    (project, emit) => {
      for (const server of agentServers(project)) {
        if (!server.url?.startsWith('http://')) continue;
        let host = '';
        try {
          host = new URL(server.url).hostname;
        } catch {
          continue;
        }
        if (LOCAL_HOST.test(host)) continue;
        emit(RULES_BY_ID['AGC-SUP-002']!, {
          message: `${serverLabel(server)} connects to ${host} over plain HTTP.`,
          location: server.location,
          subject: `server:${server.name}`,
          fix: 'Use https://.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-SUP-003',
      title: 'Remote content loaded into the agent at runtime',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply, ASI.goal],
      help: 'Hook output from SessionStart and UserPromptSubmit becomes part of the agent’s context. Fetching it from a URL lets whoever controls that URL instruct the agent.',
    },
    (project, emit) => {
      for (const hook of hooks(project))
        if (
          (hook.event === 'SessionStart' || hook.event === 'UserPromptSubmit') &&
          REMOTE_FETCH.test(hook.command) &&
          !PIPE_TO_SHELL.test(hook.command)
        )
          emit(RULES_BY_ID['AGC-SUP-003']!, {
            message: `A ${hook.event} hook fetches a URL; its output goes straight into the agent's context.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Keep the instructions in the repo, or pin the content by checksum before using it.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-SUP-004',
      title: 'Download piped into a shell',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.supply, ASI.code],
      help: 'curl … | sh runs whatever the server returns at that moment, with the agent’s access.',
    },
    (project, emit) => {
      for (const hook of hooks(project))
        if (PIPE_TO_SHELL.test(hook.command))
          emit(RULES_BY_ID['AGC-SUP-004']!, {
            message: `A ${hook.event} hook pipes a download into a shell.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Vendor the script into the repo, or download it, verify a checksum, then run it.',
          });
      for (const file of project.scripts) {
        const match = PIPE_TO_SHELL.exec(file.text);
        if (match)
          emit(RULES_BY_ID['AGC-SUP-004']!, {
            message: 'A skill or hook script pipes a download into a shell.',
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'script',
            fix: 'Vendor the script, or verify a checksum before running it.',
          });
      }
      for (const file of project.prompts) {
        const match = PIPE_TO_SHELL.exec(file.text);
        if (!match) continue;
        // Text that warns against the command ("never run …", "do not …"), in its paragraph or under a
        // heading that says so, is not an instruction to run it.
        const paragraph = file.text.slice(Math.max(0, file.text.lastIndexOf('\n\n', match.index)), match.index);
        const headingAt = file.text.lastIndexOf('\n#', match.index);
        const heading = file.text.slice(headingAt + 1, file.text.indexOf('\n', headingAt + 1));
        const negation = /\b(never|do not|don't|avoid|must not|dangerous)\b/i;
        if (
          negation.test(paragraph) ||
          (headingAt >= 0 && negation.test(heading)) ||
          (headingAt < 0 && file.text.startsWith('#') && negation.test(file.text.slice(0, file.text.indexOf('\n'))))
        )
          continue;
        emit(RULES_BY_ID['AGC-SUP-004']!, {
          message: 'Agent instructions tell it to pipe a download into a shell.',
          location: { file: file.path, line: lineAt(file.text, match.index) },
          subject: 'prompt',
          severity: 'medium',
          confidence: 'low',
          fix: 'Install the tool ahead of time, or give the agent a pinned, checksummed install step.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PER-001',
      title: 'Agent can rewrite its own instructions',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.memory, ASI.rogue],
      help: 'CLAUDE.md, AGENTS.md and memory files are read at every start. Text written there persists across sessions and users.',
    },
    (project, emit) => {
      for (const allowed of allowRules(project))
        if (
          ['Edit', 'Write', 'MultiEdit'].includes(allowed.tool) &&
          /(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)/.test(allowed.specifier ?? '')
        )
          emit(RULES_BY_ID['AGC-PER-001']!, {
            message: `"${allowed.raw}" lets the agent rewrite its own instruction files without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Remove this allow rule; let a person review instruction changes.',
          });
      for (const hook of hooks(project))
        if (IDENTITY_WRITE.test(hook.command))
          emit(RULES_BY_ID['AGC-PER-001']!, {
            message: `A ${hook.event} hook writes to an agent instruction file.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Write hook output to a log outside the instruction files.',
          });
      for (const file of project.scripts) {
        const match = IDENTITY_WRITE.exec(file.text);
        if (match)
          emit(RULES_BY_ID['AGC-PER-001']!, {
            message: 'A skill or hook script writes to an agent instruction file.',
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'script',
            fix: 'Write to a separate file that a person reviews.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PER-002',
      title: 'Agent can change its own permissions or hooks',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'An agent that can edit .claude/settings.json, hooks, agents or skills can grant itself more access.',
    },
    (project, emit) => {
      for (const allowed of allowRules(project))
        if (
          ['Edit', 'Write', 'MultiEdit'].includes(allowed.tool) &&
          /\.claude(\/\*\*?|\/?$|\/(settings[^/]*\.json|hooks|agents|skills|commands)\b)/.test(allowed.specifier ?? '')
        )
          emit(RULES_BY_ID['AGC-PER-002']!, {
            message: `"${allowed.raw}" lets the agent edit its own settings, hooks or skills without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Remove this allow rule and deny Edit(.claude/**).',
          });
      for (const hook of hooks(project))
        if (SETTINGS_WRITE.test(hook.command))
          emit(RULES_BY_ID['AGC-PER-002']!, {
            message: `A ${hook.event} hook writes into .claude/.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command}`,
            fix: 'Hooks should not modify agent configuration.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-SEC-001',
      title: 'Hardcoded credential',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Credentials in committed agent config are readable by everyone with repo access and by the agent itself.',
    },
    (project, emit) => {
      const report = (label: string, name: string, value: string, location: Location, subject: string) =>
        emit(RULES_BY_ID['AGC-SEC-001']!, {
          message: `${label} in ${name}: ${mask(value)}.`,
          location,
          subject,
          fix: 'Revoke it, then read it from the environment or a secret store, for example "${API_TOKEN}".',
        });
      for (const server of agentServers(project)) {
        for (const [name, value] of [...Object.entries(server.env), ...Object.entries(server.headers)]) {
          const label = literalSecret(name, value);
          if (label)
            report(
              label,
              `${serverLabel(server)} ${name}`,
              value.replace(/^(Bearer|Basic|token)\s+/i, ''),
              server.location,
              `server:${server.name}:${name}`,
            );
        }
        for (const arg of server.args) {
          const token = knownToken(arg);
          if (token)
            report(
              token.label,
              `${serverLabel(server)} arguments`,
              token.value,
              server.location,
              `server:${server.name}:arg`,
            );
        }
      }
      for (const file of project.settings)
        for (const item of file.env) {
          const label = literalSecret(item.name, item.value);
          if (label) report(label, `settings env ${item.name}`, item.value, item.location, `env:${item.name}`);
        }
      for (const step of project.workflows)
        for (const input of step.literalInputs) {
          const label = literalSecret(input.key, input.value);
          if (label)
            report(label, `workflow input ${input.key}`, input.value, input.location, `input:${step.job}:${input.key}`);
        }
      for (const file of [...project.prompts, ...project.scripts]) {
        const token = knownToken(file.text);
        if (token)
          report(
            token.label,
            file.path,
            token.value,
            { file: file.path, line: lineAt(file.text, token.index) },
            'text',
          );
      }
    },
  ),
  rule(
    {
      id: 'AGC-SEC-002',
      title: 'Secret passed on a command line',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Command-line arguments are visible to every process on the machine and often end up in logs.',
    },
    (project, emit) => {
      for (const server of agentServers(project)) {
        server.args.forEach((arg, index) => {
          const inline = /^--?(token|api-?key|password|secret|access-token|auth)=(.+)$/i.exec(arg);
          const flag = /^--?(token|api-?key|password|secret|access-token|auth)$/i.test(arg);
          const value = inline?.[2] ?? (flag ? server.args[index + 1] : undefined);
          if (!value || PLACEHOLDER.test(value) || knownToken(value)) return;
          emit(RULES_BY_ID['AGC-SEC-002']!, {
            message: `${serverLabel(server)} receives a secret as a command-line argument (${inline?.[1] ?? arg.replace(/^-+/, '')}).`,
            location: server.location,
            subject: `server:${server.name}:${index}`,
            fix: 'Pass it through env instead.',
          });
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-001',
      title: 'Hidden characters in agent instructions',
      severity: 'medium',
      confidence: 'low',
      owasp: [ASI.goal, ASI.memory],
      help: 'Zero-width, bidirectional and tag characters can hide instructions that a reviewer cannot see but the model reads.',
    },
    (project, emit) => {
      for (const file of [...project.prompts, ...project.scripts]) {
        const hidden = findHiddenCharacter(file.text);
        if (hidden)
          emit(RULES_BY_ID['AGC-TXT-001']!, {
            message: `Hidden character ${hidden.codePoint} in ${file.path}.`,
            location: { file: file.path, line: hidden.line },
            subject: 'hidden',
            fix: 'Remove it and review the surrounding text in a hex viewer.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-002',
      title: 'Instruction-override phrasing in shipped prompts',
      severity: 'medium',
      confidence: 'low',
      owasp: [ASI.goal],
      help: 'Phrases like "ignore previous instructions" or "do not tell the user" are typical of injected text.',
    },
    (project, emit) => {
      const pattern =
        /\b(ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|directions)|disregard (all |your |the )?(previous |prior )?(instructions|rules|guidelines)|do not (tell|inform|alert|notify) the user|without (telling|informing|alerting) the user|hide this from the user)\b/i;
      for (const file of project.prompts) {
        const match = pattern.exec(file.text);
        if (match)
          emit(RULES_BY_ID['AGC-TXT-002']!, {
            message: `"${match[0]}" in ${file.path}.`,
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'override',
            fix: 'Check who added this text and why.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-003',
      title: 'Long encoded blob in agent instructions',
      severity: 'low',
      confidence: 'low',
      owasp: [ASI.goal],
      help: 'Encoded text cannot be reviewed by reading it, but a model can decode and follow it.',
    },
    (project, emit) => {
      for (const file of project.prompts) {
        const match = /(?<!base64,)\b[A-Za-z0-9+/]{200,}={0,2}/.exec(file.text);
        if (match)
          emit(RULES_BY_ID['AGC-TXT-003']!, {
            message: `${match[0].length}-character encoded blob in ${file.path}.`,
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'blob',
            fix: 'Decode it and review it; keep instructions in plain text.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TXT-004',
      title: 'Instructions to act without asking',
      severity: 'medium',
      confidence: 'low',
      owasp: [ASI.tools, ASI.trust],
      help: 'Text that tells the agent not to ask for confirmation undermines the approval prompts the config relies on.',
    },
    (project, emit) => {
      const pattern =
        /\b(without (asking|requesting|seeking) (for )?(permission|confirmation|approval)|(never|don't|do not) ask (the user )?(for )?(permission|confirmation|approval)|skip (all )?(confirmation|approval)s?)\b/i;
      for (const file of project.prompts) {
        const match = pattern.exec(file.text);
        if (match)
          emit(RULES_BY_ID['AGC-TXT-004']!, {
            message: `"${match[0]}" in ${file.path}.`,
            location: { file: file.path, line: lineAt(file.text, match.index) },
            subject: 'no-ask',
            fix: 'Let the approval settings decide what needs a person, not the prompt.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-TRG-001',
      title: 'Agent triggered by outsiders with write access',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.goal, ASI.identity],
      help: 'Issue, comment and pull-request text is written by anyone. An agent that reads it while holding a write token can be told to use that token.',
    },
    (project, emit) => {
      for (const step of project.workflows) {
        const untrusted = step.triggers.filter(trigger => UNTRUSTED_TRIGGERS.has(trigger));
        if (!untrusted.length) continue;
        // id-token: write only mints OIDC tokens; it is repository write access only through the app token.
        const repoWrite = step.permissions.write.filter(scope => scope !== 'id-token');
        const write = repoWrite.length > 0 || step.appToken;
        if (step.permissions.known && !write) continue;
        const agent = project.agents.find(item => item.id === `workflow:${step.path}#${step.job}/${step.step}`);
        const open = step.nonWriteUsers?.value.trim() === '*';
        // claude-code-action only answers people with write access unless allowed_non_write_users widens it.
        const gated = step.action === 'claude-code-action' && !step.nonWriteUsers;
        const broad =
          step.skipPermissions !== undefined ||
          step.allowedTools.some(
            r => r.tool === '*' || (r.tool === 'Bash' && ['any', 'network'].includes(bashScope(r.specifier))),
          );
        const severity: Severity =
          step.checksOutPullRequest || (open && broad) ? 'critical' : open || !gated || broad ? 'high' : 'medium';
        const scope = step.appToken ? 'Claude GitHub App token' : repoWrite.join(', ');
        const why = step.checksOutPullRequest
          ? 'and checks out the pull request’s own code under pull_request_target'
          : open
            ? `with write access (${scope || 'default token'}), and allowed_non_write_users is "*", so anyone can start it`
            : !step.permissions.known && !step.appToken
              ? 'and sets no permissions, so it gets the repository’s default token'
              : gated
                ? `with write access (${scope}); only people with write access can start it, but the text it reads can come from anyone`
                : `with write access (${scope})`;
        emit(RULES_BY_ID['AGC-TRG-001']!, {
          message: `The ${step.job} job runs an agent on ${untrusted.join(', ')} ${why}.`,
          location: step.checksOutPullRequest ?? step.nonWriteUsers?.location ?? step.location,
          subject: `${step.job}/${step.step}`,
          ...(agent ? { agent } : {}),
          severity,
          fix: step.checksOutPullRequest
            ? 'Do not check out untrusted code under pull_request_target; use pull_request instead.'
            : 'Set the narrowest permissions the job needs, and keep the agent read-only on untrusted events.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-LIM-001',
      title: 'No turn limit on an automated agent',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.cascade],
      help: 'Without a turn limit a looping or steered agent keeps spending until the job times out.',
    },
    (project, emit) => {
      for (const step of project.workflows) {
        if (step.maxTurns || !step.action.startsWith('claude')) continue;
        const untrusted = step.triggers.some(trigger => UNTRUSTED_TRIGGERS.has(trigger));
        emit(RULES_BY_ID['AGC-LIM-001']!, {
          message: `The ${step.job} job sets no turn limit for the agent${step.timeout ? '' : ' and no timeout'}.`,
          location: step.location,
          subject: `${step.job}/${step.step}`,
          severity: untrusted && !step.timeout ? 'medium' : 'low',
          fix: 'Add --max-turns to claude_args.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-LIM-002',
      title: 'No timeout on an automated agent',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.cascade],
      help: 'GitHub’s default job timeout is six hours.',
    },
    (project, emit) => {
      for (const step of project.workflows)
        if (!step.timeout)
          emit(RULES_BY_ID['AGC-LIM-002']!, {
            message: `The ${step.job} job has no timeout-minutes, so a stuck agent can run for six hours.`,
            location: step.location,
            subject: `${step.job}/${step.step}`,
            fix: 'Set timeout-minutes on the job.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-IDN-001',
      title: 'Agent runs on a personal access token',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'A personal token carries everything its owner can do, across every repository they can reach.',
    },
    (project, emit) => {
      for (const step of project.workflows)
        for (const secret of step.secrets)
          if (/(^|_)PAT(_|$)|PERSONAL_ACCESS_TOKEN|PERSONAL_TOKEN/i.test(secret.name))
            emit(RULES_BY_ID['AGC-IDN-001']!, {
              message: `The ${step.job} job gives the agent secret ${secret.name}, which looks like a personal access token.`,
              location: secret.location,
              subject: `${step.job}:${secret.name}`,
              fix: 'Use a GitHub App token or the job’s GITHUB_TOKEN with narrow permissions.',
            });
    },
  ),
  rule(
    {
      id: 'AGC-GOV-001',
      title: 'Agent configuration has no code owner',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'Without a code owner, changes to agent permissions merge with whatever review the rest of the repo gets.',
    },
    (project, emit) => {
      const first = project.agents.find(agent => agent.kind !== 'subagent');
      if (!first) return;
      const owned = project.codeowners?.text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .some(line =>
          /^(\*|\/?\*\*|\/?\.claude\b|\/?\.mcp\.json|\/?\.github\b|\/?CLAUDE\.md|\/?AGENTS\.md)/.test(
            line.split(/\s+/)[0]!,
          ),
        );
      if (owned) return;
      emit(RULES_BY_ID['AGC-GOV-001']!, {
        message: project.codeowners
          ? 'CODEOWNERS does not cover agent configuration.'
          : 'No CODEOWNERS file covers agent configuration.',
        location: project.codeowners ? { file: project.codeowners.path, line: 1 } : first.location,
        subject: 'codeowners',
        fix: 'Add CODEOWNERS entries for .claude/, .mcp.json, CLAUDE.md and .github/workflows/.',
      });
    },
  ),
  rule(
    {
      id: 'AGC-GOV-002',
      title: 'Subagent has no stated purpose',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'Claude Code chooses subagents by their description; one without a description is unreviewable and may never be used as intended.',
    },
    (project, emit) => {
      for (const sub of project.subagents)
        if (!sub.description)
          emit(RULES_BY_ID['AGC-GOV-002']!, {
            message: `Subagent ${sub.name} has no description.`,
            location: sub.location,
            subject: sub.path,
            fix: 'Add a description to its front matter.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-COV-001',
      title: 'Risky actions with no runtime check',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.tools],
      help: 'Static config is a promise; a runtime check (Agent Guard, a pre-tool hook, an MCP gateway) is what stops a steered agent at call time.',
    },
    (project, emit) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent' || agent.mediators.length) continue;
        const a = authority(agent);
        // Only paths that reach an arbitrary host or run arbitrary code count. Running the project's own
        // commands is expected, and posting to the repository through its token is judged by AGC-TRG-001.
        const scopeOf = (grant: Grant) =>
          grant.tool === 'Bash' ? bashScope(parseRule(grant.via, grant.location).specifier) : undefined;
        const arbitrary = (grant: Grant) =>
          grant.approval === 'auto' &&
          grant.certainty === 'yes' &&
          !/^(GITHUB_TOKEN|Claude GitHub App token|default GITHUB_TOKEN)/.test(grant.via) &&
          !(grant.tool ?? '').startsWith('mcp__github_') &&
          (grant.tool !== 'Bash' || ['any', 'network'].includes(scopeOf(grant) ?? ''));
        const egress = a.egress.grants.filter(arbitrary);
        const exec = a.exec.grants.filter(arbitrary);
        const risky = [
          ...(egress.length ? [{ label: 'send data out', grant: egress[0]! }] : []),
          ...(exec.length ? [{ label: 'run code', grant: exec[0]! }] : []),
        ];
        if (!risky.length) continue;
        emit(RULES_BY_ID['AGC-COV-001']!, {
          message: `${agent.name} can ${risky.map(item => item.label).join(' and ')} without approval (${[...new Set(risky.map(item => item.grant.via))].join(', ')}), and nothing checks those calls at runtime.`,
          location: risky[0]!.grant.location,
          subject: 'coverage',
          agent,
          fix: 'Add a runtime check: Agent Guard, a PreToolUse hook, or an MCP gateway.',
        });
      }
    },
  ),
];

export const RULES_BY_ID: Readonly<Record<string, RuleMeta>> = Object.freeze(
  Object.fromEntries(RULES.map(({ check: _check, ...meta }) => [meta.id, meta])),
);

/**
 * Runs every rule. Duplicate findings (same fingerprint) are reported once. A rule that fails on
 * unexpected input is reported as an error and the other rules still run.
 */
export function runRules(project: Project, errors: { file: string; message: string }[] = []): Finding[] {
  const findings = new Map<string, Finding>();
  const emit: Emit = (meta, input) => {
    const agentId = input.agent?.id ?? '';
    const key = fingerprint(meta.id, agentId, input.location.file, input.subject);
    if (findings.has(key)) return;
    findings.set(key, {
      ruleId: meta.id,
      severity: input.severity ?? meta.severity,
      confidence: input.confidence ?? meta.confidence,
      message: input.message,
      location: input.location,
      ...(input.agent ? { agentId } : {}),
      fingerprint: key,
      ...(input.fix ? { fix: input.fix } : {}),
    });
  };
  for (const item of RULES) {
    try {
      item.check(project, emit);
    } catch (error) {
      errors.push({
        file: '',
        message: `${item.id} could not run: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  return [...findings.values()];
}
