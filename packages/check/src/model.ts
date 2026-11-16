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
import { actionBuiltinServers, parseMcpConfig, type McpServer } from './mcp.js';
import { asString, asStringArray, frontmatter, isRecord } from './text.js';
import { parseWorkflow, PUBLISHING_SCOPES, UNTRUSTED_TRIGGERS, type WorkflowAgent } from './workflows.js';

export interface Subagent {
  readonly path: string;
  readonly name: string;
  readonly description?: string;
  readonly tools?: readonly string[];
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

function mediatorsFor(settings: readonly ClaudeSettings[], servers: readonly McpServer[]): Mediator[] {
  const out: Mediator[] = [];
  for (const file of settings)
    for (const hook of file.hooks)
      if (hook.event === 'PreToolUse') out.push({ kind: 'pre-tool-hook', location: hook.location });
  for (const server of servers) {
    const text = [server.command ?? '', ...server.args, server.url ?? ''].join(' ');
    if (/agent-guard/.test(text)) out.push({ kind: 'agent-guard', location: server.location });
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
      else if (parent === '.claude' && (name === 'settings.json' || name === 'settings.local.json'))
        settings.push(parseSettings(path, text));
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
          subagents.push({
            path,
            name: asString(data['name']) ?? name.replace(/\.md$/, ''),
            ...(description ? { description } : {}),
            ...(tools ? { tools } : {}),
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
      if (!sub.tools) continue;
      const tools = sub.tools;
      const keeps = (grant: Grant) =>
        grant.tool !== undefined &&
        tools.some(
          tool =>
            tool === grant.tool ||
            (grant.tool!.startsWith('mcp__') && tool.startsWith(`${grant.tool}__`)) ||
            tool === `${grant.tool}__*`,
        );
      agents.push({
        id: `subagent:${sub.path}`,
        kind: 'subagent',
        name: `Subagent ${sub.name}`,
        location: sub.location,
        grants: main.grants.filter(keeps),
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
    if (!step.permissions.known && !step.appToken)
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
    const canPublish = publishing.length > 0 || step.appToken;
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
  };
}
