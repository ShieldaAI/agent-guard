import type { Agent, Grant, Location, Mediator } from './types.js';
import { EMPTY_EVIDENCE, readAgentGuardFiles, type AgentGuardEvidence } from './agent-guard.js';
import type { FileSource } from './source.js';
import {
  bashScope,
  deniesWholeTool,
  grantsForRule,
  parseRule,
  parseSettings,
  type ClaudeSettings,
  type PermissionRule,
} from './claude.js';
import { actionBuiltinServers, parseMcpConfig, serversFromObject, type McpServer } from './mcp.js';
import { asString, asStringArray, frontmatter, isRecord, lineOf } from './text.js';
import {
  parseCodex,
  parseGemini,
  parseMarketplace,
  parsePluginSettings,
  type Bypass,
  type ModelChoice,
  type OtherAgent,
  type PluginSource,
} from './formats.js';
import { parseWorkflow, PUBLISHING_SCOPES, UNTRUSTED_TRIGGERS, type WorkflowAgent } from './workflows.js';

export interface Subagent {
  readonly path: string;
  readonly name: string;
  readonly description?: string;
  readonly tools?: readonly string[];
  readonly disallowedTools: readonly string[];
  /** `permissionMode` from the frontmatter, with the line that sets it. */
  readonly permissionMode?: { readonly value: string; readonly location: Location };
  readonly model?: { readonly value: string; readonly location: Location };
  /** MCP servers defined inline for this subagent only. */
  readonly servers: readonly McpServer[];
  /** Server names it references from the project's `.mcp.json`. */
  readonly serverNames: readonly string[];
  readonly location: Location;
  readonly projectDir: string;
}

export interface TextFile {
  readonly path: string;
  readonly text: string;
}

/** Everything the rules look at. */
export interface Project {
  readonly settings: readonly ClaudeSettings[];
  readonly servers: readonly McpServer[];
  readonly workflows: readonly WorkflowAgent[];
  readonly subagents: readonly Subagent[];
  /** Markdown read by agents: CLAUDE.md, AGENTS.md, subagents, commands, skills. */
  readonly prompts: readonly TextFile[];
  /** Scripts shipped in skill and hook folders. */
  readonly scripts: readonly TextFile[];
  readonly codeowners?: TextFile;
  readonly usesAgentGuard?: Location;
  /** Packages the root package.json depends on: runners resolve these locally. */
  readonly dependencies: ReadonlySet<string>;
  readonly agents: readonly Agent[];
  readonly errors: readonly { readonly file: string; readonly message: string }[];
  readonly filesRead: number;
  /** Agent Guard's own records found in the repo or given on the command line (Mode B). */
  readonly agentGuard: AgentGuardEvidence;
  /** Tools other agents (Gemini CLI) run without asking, as Claude Code permission rules. */
  readonly otherAllow: readonly PermissionRule[];
  /** Settings that run every action without asking, outside Claude Code's own settings. */
  readonly bypasses: readonly Bypass[];
  /** Model names agents are configured with, for pinning checks. */
  readonly models: readonly ModelChoice[];
  /** Where plugins and plugin marketplaces are fetched from. */
  readonly pluginSources: readonly PluginSource[];
}

/** The directory a `.claude/...` or `.mcp.json` path belongs to ('' for the repo root). */
export function projectDir(path: string): string {
  const parts = path.split('/');
  const claude = parts.indexOf('.claude');
  if (claude >= 0) return parts.slice(0, claude).join('/');
  return parts.slice(0, -1).join('/');
}

function within(dir: string, name: string): string {
  return dir ? `${dir}/${name}` : name;
}

const BASELINE_TOOLS = ['Bash', 'Edit', 'WebFetch', 'WebSearch'] as const;

function baselineGrants(
  approval: 'ask' | 'auto',
  location: Location,
  servers: readonly McpServer[],
  allow: readonly PermissionRule[],
  deny: readonly PermissionRule[],
  skip: boolean,
): Grant[] {
  const out: Grant[] = [];
  for (const tool of BASELINE_TOOLS) {
    if (deniesWholeTool(deny, tool)) continue;
    out.push(...grantsForRule(parseRule(tool, location), approval, servers));
  }
  for (const server of servers) {
    if (deniesWholeTool(deny, 'mcp', server.name)) continue;
    const allowedWhole = allow.some(
      rule => rule.tool === 'mcp' && rule.server === server.name && rule.mcpTool === undefined,
    );
    const rule = parseRule(`mcp__${server.name}`, server.location);
    out.push(...grantsForRule(rule, skip || allowedWhole ? 'auto' : approval, servers));
  }
  return out;
}

function withoutDenied(grants: readonly Grant[], deny: readonly PermissionRule[]): Grant[] {
  return grants.filter(grant => {
    if (!grant.tool) return true;
    if (grant.tool.startsWith('mcp__')) return !deniesWholeTool(deny, 'mcp', grant.tool.slice(5));
    return !deniesWholeTool(deny, grant.tool);
  });
}

/** Whether a PreToolUse matcher (a tool name or a regular expression over names) covers Bash. */
function coversBash(matcher: string): boolean {
  const value = matcher.trim();
  if (value === '' || value === '*') return true;
  if (/^[A-Za-z0-9_|]+$/.test(value)) return value.split('|').includes('Bash');
  try {
    return new RegExp(`^(?:${value})$`).test('Bash');
  } catch {
    return false;
  }
}

/** An MCP server that names Agent Guard; not this scanner's own read-only MCP server, which guards nothing. */
const AGENT_GUARD_SERVER = /agent-guard(?!-check)/;

function mediatorsFor(settings: readonly ClaudeSettings[], servers: readonly McpServer[]): Mediator[] {
  const out: Mediator[] = [];
  // Only a hook that sees shell commands mediates the risky calls this check is about.
  for (const file of settings)
    for (const hook of file.hooks)
      if (hook.event === 'PreToolUse' && coversBash(hook.matcher))
        out.push({ kind: 'pre-tool-hook', location: hook.location });
  for (const server of servers) {
    const text = [server.command ?? '', ...server.args, server.url ?? ''].join(' ');
    if (AGENT_GUARD_SERVER.test(text)) out.push({ kind: 'agent-guard', location: server.location });
    else if (/\bmcp[- ]gateway\b|docker mcp gateway/.test(text))
      out.push({ kind: 'mcp-gateway', location: server.location });
  }
  return out;
}

/**
 * Reads every candidate file in a source and builds the project model. Never throws on bad input.
 * `extraFiles` are read as well (Agent Guard records given on the command line, for example).
 */
export function buildProject(source: FileSource, extraFiles: readonly TextFile[] = []): Project {
  const errors: { file: string; message: string }[] = [];
  const settings: ClaudeSettings[] = [];
  const servers: McpServer[] = [];
  const workflows: WorkflowAgent[] = [];
  const subagents: Subagent[] = [];
  const prompts: TextFile[] = [];
  const scripts: TextFile[] = [];
  let codeowners: TextFile | undefined;
  let usesAgentGuard: Location | undefined;
  const dependencies = new Set<string>();
  let filesRead = 0;
  const guardFiles: { path: string; text: string; data: unknown }[] = [];
  const others: OtherAgent[] = [];
  const pluginSources: PluginSource[] = [];
  const fail = (file: string, error: unknown) =>
    errors.push({ file, message: error instanceof Error ? error.message.split('\n')[0]! : String(error) });

  const extraPaths = new Set(extraFiles.map(file => file.path));
  const inputs = [
    ...source
      .list()
      .filter(path => !extraPaths.has(path))
      .map(path => ({ path, text: source.read(path) })),
    ...extraFiles,
  ];
  for (const { path, text } of inputs) {
    if (text === undefined) continue;
    filesRead += 1;
    const name = path.split('/').at(-1)!;
    const parent = path.split('/').at(-2);
    try {
      if (/^agent-guard[\w.-]*\.json$/.test(name) || extraPaths.has(path))
        guardFiles.push({ path, text, data: JSON.parse(text) as unknown });
      else if (parent === '.claude' && (name === 'settings.json' || name === 'settings.local.json')) {
        settings.push(parseSettings(path, text));
        pluginSources.push(...parsePluginSettings(path, text));
      } else if (parent === '.codex' && name === 'config.toml') others.push(parseCodex(path, text));
      else if (parent === '.gemini' && name === 'settings.json') others.push(parseGemini(path, text));
      else if (parent === '.claude-plugin' && name === 'marketplace.json')
        pluginSources.push(...parseMarketplace(path, text));
      else if (name === '.mcp.json') servers.push(...parseMcpConfig(path, text, 'claude-code'));
      else if (path.endsWith('.vscode/mcp.json')) servers.push(...parseMcpConfig(path, text, 'vscode'));
      else if (path.endsWith('.cursor/mcp.json')) servers.push(...parseMcpConfig(path, text, 'cursor'));
      else if (path.startsWith('.github/workflows/') && /\.ya?ml$/.test(name))
        workflows.push(...parseWorkflow(path, text));
      else if (name === 'CODEOWNERS') codeowners ??= { path, text };
      else if (path === 'package.json') {
        const data = JSON.parse(text) as unknown;
        if (isRecord(data)) {
          const deps = {
            ...(isRecord(data['dependencies']) ? data['dependencies'] : {}),
            ...(isRecord(data['devDependencies']) ? data['devDependencies'] : {}),
          };
          for (const dep of Object.keys(deps)) dependencies.add(dep);
          if (Object.keys(deps).some(dep => dep.startsWith('@shieldaai/agent-guard')))
            usesAgentGuard = {
              file: path,
              line: text.split('\n').findIndex(line => line.includes('@shieldaai/agent-guard')) + 1,
            };
        }
      } else if (path === '.agc.yaml') continue;
      else if (name.endsWith('.md')) {
        prompts.push({ path, text });
        if (path.split('/').includes('agents') && path.includes('.claude/agents/')) {
          const { data } = frontmatter(text);
          const tools = data['tools'] === undefined ? undefined : asStringArray(data['tools']);
          const description = asString(data['description']);
          // The line of a top-level frontmatter key (never a match in the body or a description).
          const fm = (key: string): Location => {
            const lines = text.split('\n');
            const end = lines.findIndex((line, i) => i > 0 && /^---\s*$/.test(line));
            const index = lines.slice(0, end < 0 ? lines.length : end).findIndex(line => line.startsWith(`${key}:`));
            return { file: path, line: index >= 0 ? index + 1 : 1 };
          };
          const permissionMode = asString(data['permissionMode']);
          const model = asString(data['model']);
          const inline: Record<string, unknown> = {};
          const serverNames: string[] = [];
          const declared = data['mcpServers'];
          if (Array.isArray(declared)) {
            for (const item of declared) {
              if (typeof item === 'string') serverNames.push(item);
              else if (isRecord(item)) {
                // `- name: {command...}` or `- {name: x, command: ...}`
                const named = asString(item['name']);
                if (named) inline[named] = item;
                else for (const [key, value] of Object.entries(item)) if (isRecord(value)) inline[key] = value;
              }
            }
          } else if (isRecord(declared)) Object.assign(inline, declared);
          const subServers = serversFromObject({ mcpServers: inline }, path, text, 'subagent');
          subagents.push({
            path,
            name: asString(data['name']) ?? name.replace(/\.md$/, ''),
            ...(description ? { description } : {}),
            ...(tools ? { tools } : {}),
            disallowedTools: data['disallowedTools'] === undefined ? [] : asStringArray(data['disallowedTools']),
            ...(permissionMode ? { permissionMode: { value: permissionMode, location: fm('permissionMode') } } : {}),
            ...(model ? { model: { value: model, location: fm('model') } } : {}),
            servers: subServers,
            serverNames,
            location: { file: path, line: 1 },
            projectDir: projectDir(path),
          });
        }
      } else scripts.push({ path, text });
    } catch (error) {
      fail(path, error);
    }
  }

  const agents: Agent[] = [];
  const dirs = new Set<string>([
    ...settings.map(file => projectDir(file.path)),
    ...servers.filter(server => server.client === 'claude-code').map(server => projectDir(server.location.file)),
    ...subagents.map(item => item.projectDir),
  ]);
  const rootSettings = settings.filter(file => projectDir(file.path) === '');
  const rootServers = servers.filter(
    server => server.client === 'claude-code' && projectDir(server.location.file) === '',
  );

  for (const dir of [...dirs].sort()) {
    const local = settings.filter(file => projectDir(file.path) === dir);
    const localServers = servers.filter(
      server => server.client === 'claude-code' && projectDir(server.location.file) === dir,
    );
    const allow = local.flatMap(file => file.allow);
    const deny = local.flatMap(file => file.deny);
    const mode = [...local].reverse().find(file => file.defaultMode)?.defaultMode?.value;
    const skip = mode === 'bypassPermissions';
    const anchor: Location = local[0]
      ? { file: local[0].path, line: 1 }
      : localServers[0]
        ? { file: localServers[0].location.file, line: 1 }
        : { file: within(dir, '.claude'), line: 1 };
    const grants = [
      ...baselineGrants(skip ? 'auto' : 'ask', anchor, localServers, allow, deny, skip),
      ...allow.flatMap(rule => grantsForRule(rule, 'auto', localServers)),
      ...(mode === 'acceptEdits'
        ? grantsForRule(parseRule('Edit', local.find(f => f.defaultMode)!.defaultMode!.location), 'auto', [])
        : []),
    ];
    const mediators = mediatorsFor(local, localServers);
    const main: Agent = {
      id: `claude-code:${dir || '.'}`,
      kind: 'claude-code',
      name: dir ? `Claude Code (${dir})` : 'Claude Code (project)',
      location: anchor,
      grants: withoutDenied(grants, deny),
      mediators,
      headless: false,
    };
    agents.push(main);
    for (const sub of subagents.filter(item => item.projectDir === dir)) {
      const mode = sub.permissionMode?.value;
      const bypass = mode === 'bypassPermissions';
      const edits = mode === 'acceptEdits' || mode === 'auto';
      // A subagent with no tools list, no own mode and no own servers is the main agent again.
      if (!sub.tools && !bypass && !edits && !sub.servers.length) continue;
      const tools = sub.tools;
      const keeps = (grant: Grant) =>
        tools === undefined ||
        (grant.tool !== undefined &&
          tools.some(
            tool =>
              tool === grant.tool ||
              (grant.tool!.startsWith('mcp__') && tool.startsWith(`${grant.tool}__`)) ||
              tool === `${grant.tool}__*`,
          ));
      const modeAt = sub.permissionMode?.location ?? sub.location;
      const own = sub.servers.flatMap(server =>
        grantsForRule(parseRule(`mcp__${server.name}`, server.location), bypass ? 'auto' : 'ask', sub.servers),
      );
      let grants = [...main.grants.filter(keeps), ...own].map(item =>
        bypass && item.approval === 'ask'
          ? {
              ...item,
              approval: 'auto' as const,
              via: `${item.via} (permissionMode: bypassPermissions)`,
              location: modeAt,
            }
          : item,
      );
      if (edits && (tools === undefined || tools.some(tool => ['Edit', 'Write', 'MultiEdit'].includes(tool))))
        grants.push(...grantsForRule(parseRule('Edit', modeAt), 'auto', []));
      const deny = sub.disallowedTools.map(tool => parseRule(tool, sub.location));
      grants = withoutDenied(grants, deny);
      agents.push({
        id: `subagent:${sub.path}`,
        kind: 'subagent',
        name: `Subagent ${sub.name}`,
        location: sub.location,
        grants,
        mediators,
        headless: false,
      });
    }
  }

  for (const step of workflows) {
    const at = step.location;
    const grants: Grant[] = [];
    const add = (grant: Omit<Grant, 'approval'> & { approval?: Grant['approval'] }) =>
      grants.push({ approval: 'auto', ...grant });
    for (const trigger of step.triggers)
      if (UNTRUSTED_TRIGGERS.has(trigger))
        add({
          capability: 'untrustedInput',
          via: `trigger ${trigger}`,
          certainty: 'yes',
          location: step.triggerLocation,
        });
    const publishing = step.permissions.write
      .filter(scope => scope === '*' || PUBLISHING_SCOPES.has(scope))
      .sort((a, b) => Number(a === 'contents') - Number(b === 'contents'));
    for (const scope of publishing)
      add({
        capability: 'egress',
        via: `GITHUB_TOKEN ${scope === '*' ? 'write-all' : `${scope}: write`}`,
        certainty: 'yes',
        location: step.permissions.location,
      });
    if (step.permissions.write.some(scope => scope === '*' || scope === 'contents'))
      add({
        capability: 'write',
        via: 'GITHUB_TOKEN contents: write',
        certainty: 'yes',
        location: step.permissions.location,
      });
    if (step.appToken) {
      add({
        capability: 'egress',
        via: 'Claude GitHub App token (id-token: write)',
        certainty: 'yes',
        location: step.permissions.location,
      });
      add({
        capability: 'write',
        via: 'Claude GitHub App token (id-token: write)',
        certainty: 'yes',
        location: step.permissions.location,
      });
    }
    if (step.customToken) {
      // The token's scopes live outside the repository: assume it can do what a bot token usually does.
      for (const capability of ['egress', 'write'] as const)
        add({
          capability,
          via: `token secrets.${step.customToken.name}`,
          certainty: 'unknown',
          location: step.customToken.location,
        });
    }
    if (!step.permissions.known && !step.appToken && !step.customToken)
      add({
        capability: 'egress',
        via: 'default GITHUB_TOKEN permissions (not set in the workflow)',
        certainty: 'unknown',
        location: step.triggerLocation,
      });
    for (const secret of step.agentSecrets)
      add({ capability: 'privateData', via: `secret ${secret.name}`, certainty: 'yes', location: secret.location });
    const reachable = [
      ...step.servers,
      ...(step.action.startsWith('claude') ? rootServers : []),
      ...(step.action === 'claude-code-action' ? actionBuiltinServers(at) : []),
    ];
    // Commands that publish to the repository (gh pr comment, git push) only work with a token that can write.
    const canPublish = publishing.length > 0 || step.appToken || step.customToken !== undefined;
    const toolGrants = [
      ...step.allowedTools.flatMap(rule => grantsForRule(rule, 'auto', reachable)),
      ...(step.action.startsWith('claude')
        ? rootSettings.flatMap(file => file.allow.flatMap(rule => grantsForRule(rule, 'auto', reachable)))
        : []),
    ];
    for (const grant of toolGrants) {
      const publishes =
        grant.tool === 'Bash' && bashScope(parseRule(grant.via, grant.location).specifier) === 'publish';
      if (!publishes || canPublish) grants.push(grant);
      else if (!step.permissions.known) grants.push({ ...grant, certainty: 'unknown' });
    }
    if (step.skipPermissions) grants.push(...baselineGrants('auto', step.skipPermissions, reachable, [], [], true));
    const deny = [
      ...step.disallowedTools,
      ...(step.action.startsWith('claude') ? rootSettings.flatMap(file => file.deny) : []),
    ];
    agents.push({
      id: `workflow:${step.path}#${step.job}/${step.step}`,
      kind: 'workflow',
      name: `Workflow ${step.path.split('/').at(-1)} › ${step.job}`,
      location: at,
      grants: withoutDenied(grants, deny),
      mediators: step.action.startsWith('claude') ? mediatorsFor(rootSettings, []) : [],
      headless: true,
    });
  }

  for (const client of ['vscode', 'cursor'] as const) {
    const list = servers.filter(server => server.client === client);
    if (!list.length) continue;
    const file = list[0]!.location.file;
    agents.push({
      id: `mcp-client:${file}`,
      kind: 'mcp-client',
      name: client === 'vscode' ? 'VS Code agent mode' : 'Cursor agent',
      location: { file, line: 1 },
      grants: list.flatMap(server => grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'ask', list)),
      mediators: mediatorsFor([], list),
      headless: false,
    });
  }

  for (const other of others) agents.push(other.agent);
  servers.push(...others.flatMap(other => other.servers), ...subagents.flatMap(sub => sub.servers));
  const models: ModelChoice[] = [
    ...others.flatMap(other => other.models),
    ...subagents.flatMap(sub =>
      sub.model ? [{ agent: `Subagent ${sub.name}`, model: sub.model.value, location: sub.model.location }] : [],
    ),
    ...workflows.flatMap(step =>
      step.model
        ? [
            {
              agent: `Workflow ${step.path.split('/').at(-1)} › ${step.job}`,
              model: step.model.value,
              location: step.model.location,
            },
          ]
        : [],
    ),
  ];

  return {
    settings,
    servers,
    workflows,
    subagents,
    prompts,
    scripts,
    ...(codeowners ? { codeowners } : {}),
    ...(usesAgentGuard ? { usesAgentGuard } : {}),
    dependencies,
    agents,
    errors,
    filesRead,
    agentGuard: guardFiles.length ? readAgentGuardFiles(guardFiles, errors) : EMPTY_EVIDENCE,
    otherAllow: others.flatMap(other => other.allow),
    bypasses: others.flatMap(other => other.bypasses),
    models,
    pluginSources,
  };
}
