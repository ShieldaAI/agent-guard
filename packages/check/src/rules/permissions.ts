import { ASI, DESTRUCTIVE_COMMAND, DESTRUCTIVE_TOOL, agentServers, allowRules, rule, serverKey } from './common.js';
import type { Rule } from './common.js';
import { bashScope, HARMLESS_TOOLS, isOutsideProject } from '../claude.js';
import { commands, unwrap } from '../shell.js';
import { lineAt } from '../text.js';
import { projectDir } from '../model.js';
import { UNTRUSTED_TRIGGERS } from '../workflows.js';

/** A hook matcher that names only tools that run nothing (`AskUserQuestion`, `TodoWrite`). */
function onlyHarmless(matcher: string): boolean {
  const names = matcher.split('|').map(name => name.trim());
  return matcher.trim() !== '' && names.every(name => HARMLESS_TOOLS.has(name));
}

export const PERMISSIONS_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-PERM-001',
      title: 'Agent runs every tool without asking',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.tools, ASI.trust],
      help: 'Bypass modes remove the approval step for every tool, including shell commands and outbound requests.',
    },
    (project, report) => {
      for (const file of project.settings)
        if (file.defaultMode?.value === 'bypassPermissions')
          report({
            message: 'Claude Code runs every tool without asking (defaultMode: bypassPermissions).',
            location: file.defaultMode.location,
            subject: 'defaultMode',
            agent: project.agents.find(agent => agent.kind === 'claude-code'),
            fix: 'Remove defaultMode or set it to "default", and allow only the tools the agent needs.',
          });
        else if (file.defaultMode?.value === 'auto')
          // A safety review approves calls instead of a person: less than a bypass, still no person.
          report({
            message:
              'Claude Code runs tools without a person approving them (defaultMode: auto); a safety review decides.',
            location: file.defaultMode.location,
            subject: 'defaultMode',
            severity: 'medium',
            agent: project.agents.find(agent => agent.kind === 'claude-code'),
            fix: 'Set defaultMode to "default" in shared settings; choose auto per session where it is wanted.',
          });
      for (const step of project.workflows)
        if (step.skipPermissions) {
          const untrusted = step.triggers.some(trigger => UNTRUSTED_TRIGGERS.has(trigger));
          report({
            message: `The ${step.job} job runs the agent with approvals and sandbox turned off${untrusted ? ', on events outsiders can trigger' : ''}.`,
            location: step.skipPermissions,
            subject: `${step.job}/${step.step}`,
            agent: project.agents.find(agent => agent.id === `workflow:${step.path}#${step.job}/${step.step}`),
            severity: untrusted ? 'critical' : 'high',
            fix: 'Replace the bypass flag with --allowedTools listing only the tools this job needs.',
          });
        }
      for (const bypass of project.bypasses)
        report({
          message: `${bypass.agent} runs every action without asking (${bypass.what}).`,
          location: bypass.location,
          subject: `bypass:${bypass.what}`,
          agent: project.agents.find(agent => agent.location.file === bypass.location.file),
          fix: bypass.agent.startsWith('Codex')
            ? 'Use approval_policy = "on-request" with sandbox_mode = "workspace-write".'
            : bypass.agent.startsWith('Gemini')
              ? 'Remove defaultApprovalMode "yolo", or set security.disableYoloMode to true.'
              : 'Turn this setting off in the repository, so each tool call is approved by a person.',
        });
      // A hook that answers "allow" for tool calls approves them instead of a person.
      for (const { hook, judgement } of project.hookJudgements)
        if (judgement.approves !== 'no' && !onlyHarmless(hook.matcher))
          report({
            message:
              judgement.approves === 'yes'
                ? `A ${hook.event} hook approves tool calls${hook.matcher ? ` matching "${hook.matcher}"` : ''}, so they run without a person deciding.`
                : `A ${hook.event} hook may approve tool calls${hook.matcher ? ` matching "${hook.matcher}"` : ''} (${judgement.why}); what it decides cannot be read.`,
            location: hook.location,
            subject: `hook-approves:${hook.event}:${hook.matcher}:${hook.command || hook.url || hook.type}`,
            severity: judgement.approves === 'yes' ? 'critical' : 'high',
            agent: project.agents.find(agent => agent.kind === 'claude-code'),
            fix: 'Let the hook deny or ask, never allow; keep approvals with a person or with permission rules a reviewer can read.',
          });
      for (const file of project.scripts) {
        const index = file.text.search(/--dangerously-(skip-permissions|bypass-approvals-and-sandbox)/);
        if (index >= 0)
          report({
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
    (project, report) => {
      const servers = agentServers(project);
      for (const allowed of allowRules(project)) {
        if (
          allowed.tool === '*' ||
          (['Bash', 'PowerShell', 'Monitor'].includes(allowed.tool) && bashScope(allowed.specifier) === 'any')
        ) {
          report({
            message: `"${allowed.raw}" lets the agent run any ${allowed.tool === '*' ? 'tool' : 'shell command'} without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Replace it with the specific commands the agent needs, such as "Bash(npm test:*)".',
          });
        } else if (allowed.tool === 'mcp' && allowed.mcpTool === undefined) {
          const server = servers.find(item => item.name === allowed.server);
          const caps = server?.catalog?.capabilities ?? {};
          if (caps.egress === 'yes' || caps.spend === 'yes' || caps.write === 'yes')
            report({
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
    (project, report) => {
      for (const allowed of allowRules(project))
        if (['Bash', 'PowerShell', 'Monitor'].includes(allowed.tool) && bashScope(allowed.specifier) === 'network')
          report({
            message: `"${allowed.raw}" runs without asking and can reach the network or run arbitrary code.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Keep this command behind approval, or narrow it to a fixed script that cannot take arbitrary arguments.',
          });
      // An MCP server whose command is itself a network tool or inline code (`curl -d @file url`,
      // `python3 -c "..."`): it runs when the server starts, whatever its tools are.
      for (const server of agentServers(project)) {
        if (!server.command) continue;
        const launch = [server.command, ...server.args].map(arg =>
          /[\s"']/.test(arg) ? `'${arg.replace(/'/g, `'\\''`)}'` : arg,
        );
        const call = unwrap(commands(launch.join(' '))[0] ?? []);
        if (!call) continue;
        const inline =
          /^(python[0-9.]*|node|nodejs|ruby|perl|php|deno|bun|bash|sh|zsh|dash|ksh|pwsh|powershell|osascript)$/.test(
            call.name,
          ) && call.args.some(arg => /^(-[a-zA-Z]*[ceE]|--eval|--command|--print|eval)$/.test(arg.text));
        if (inline || /^(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|telnet|ftp|rsync|openssl)$/.test(call.name))
          report({
            message: `MCP server ${server.name} starts \`${launch.join(' ').slice(0, 100)}\`, which runs when the server starts and can reach the network or run arbitrary code.`,
            location: server.location,
            subject: `mcp-command:${serverKey(server)}`,
            fix: 'Start the server from a package or a script in the repository, not from a network tool or inline code.',
          });
      }
      // Hooks run without asking, on every matching event: one that can reach the network or run
      // arbitrary code (or cannot be read) is such a command.
      for (const { hook, judgement } of project.hookJudgements)
        if (judgement.reach === 'network')
          report({
            message: `A ${hook.event} hook runs ${judgement.why} without asking; it can reach the network or run arbitrary code.`,
            location: hook.location,
            subject: `hook:${hook.event}:${hook.command || hook.url || hook.type}`,
            fix: 'Run a script from the repository that only does local work, or remove the hook.',
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
    (project, report) => {
      for (const allowed of allowRules(project))
        if (['Read', 'Glob', 'Grep', 'LS'].includes(allowed.tool) && isOutsideProject(allowed.specifier))
          report({
            message: `"${allowed.raw}" lets the agent read outside the project without asking, where keys and tokens live.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Allow only the specific directory the agent needs, and deny ~/.ssh, ~/.aws and .env files.',
          });
      for (const file of project.settings) {
        for (const directory of file.additionalDirectories)
          if (/^(~|\$HOME|\/)/.test(directory.value.trim()))
            report({
              message: /^(~\/?|\/|\$HOME\/?)$/.test(directory.value.trim())
                ? `additionalDirectories includes "${directory.value}", which opens the whole ${directory.value.trim() === '/' ? 'disk' : 'home directory'} to the agent.`
                : `additionalDirectories includes "${directory.value}", outside the project: the agent reads it without asking.`,
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
    (project, report) => {
      for (const allowed of allowRules(project)) {
        const destructive =
          (allowed.tool === 'mcp' && allowed.mcpTool !== undefined && DESTRUCTIVE_TOOL.test(allowed.mcpTool)) ||
          (allowed.tool === 'Bash' && DESTRUCTIVE_COMMAND.test((allowed.specifier ?? '').trim()));
        if (destructive)
          report({
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
      id: 'AGC-PERM-006',
      title: 'Subagent runs with broader permissions than its parent',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.trust],
      help: 'A subagent’s permissionMode replaces the session’s for its own calls. bypassPermissions skips every prompt; auto lets a classifier, not a person, approve most calls; acceptEdits writes files without asking. Claude Code ignores permissionMode for plugin subagents, not for project ones.',
    },
    (project, report) => {
      for (const sub of project.subagents) {
        const mode = sub.permissionMode;
        if (!mode) continue;
        const parentMode = [...project.settings]
          .reverse()
          // The session's own settings: the same project directory, settings.local.json first.
          .find(file => file.defaultMode && projectDir(file.path) === sub.projectDir)?.defaultMode?.value;
        const agent = project.agents.find(item => item.id === `subagent:${sub.path}`);
        if (
          (mode.value === 'bypassPermissions' && parentMode !== 'bypassPermissions') ||
          (mode.value === 'auto' && parentMode !== 'bypassPermissions' && parentMode !== 'auto')
        )
          report({
            message:
              mode.value === 'auto'
                ? `Subagent ${sub.name} sets permissionMode: auto, so a classifier, not a person, approves ${sub.tools ? `its tools (${sub.tools.join(', ')})` : 'every tool it inherits'}.`
                : `Subagent ${sub.name} sets permissionMode: bypassPermissions, so ${sub.tools ? `its tools (${sub.tools.join(', ')})` : 'every tool it inherits'} run without asking.`,
            location: mode.location,
            subject: `mode:${sub.path}`,
            agent,
            ...(mode.value === 'auto' ? { severity: 'medium' as const } : {}),
            fix: 'Remove permissionMode, or use plan or default and allow the specific tools it needs.',
          });
        else if (
          mode.value === 'acceptEdits' &&
          parentMode !== 'acceptEdits' &&
          parentMode !== 'bypassPermissions' &&
          parentMode !== 'auto'
        )
          report({
            message: `Subagent ${sub.name} sets permissionMode: ${mode.value}, so it edits files without asking while the session asks.`,
            location: mode.location,
            subject: `mode:${sub.path}`,
            agent,
            severity: 'low',
            fix: 'Remove permissionMode unless this subagent is meant to edit unattended.',
          });
      }
    },
  ),
];
