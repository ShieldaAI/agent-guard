import type { Agent, Grant, Location, Mediator, Unrecognized } from './types.js';
import { EMPTY_EVIDENCE, readAgentGuardFiles, type AgentGuardEvidence } from './agent-guard.js';
import { safeRelative, type FileSource } from './source.js';
import {
  bashScope,
  deniesWholeTool,
  grantsForRule,
  parseRule,
  parseSettings,
  type ClaudeSettings,
  type Hook,
  type PermissionRule,
} from './claude.js';
import {
  actionBuiltinServers,
  parseMcpConfig,
  serversFromObject,
  type CatalogContext,
  type DeclaredServer,
  type McpServer,
} from './mcp.js';
import { PACKAGE_SOURCE_FILES, packageSourceEcosystem } from './source.js';
import { asString, asStringArray, frontmatter, isRecord, lenientFrontmatter, lineOf, parseJsonc } from './text.js';
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
import { MANAGED_DIR } from './user.js';
import {
  isAgenticWorkflow,
  parseAgenticLockAlone,
  parseAgenticWorkflow,
  parseCopilotAgent,
  parseCursorCli,
  parseKiroMcp,
  parseOpenCode,
} from './agents.js';
import {
  isAgenticLock,
  parseWorkflow,
  PUBLISHING_SCOPES,
  UNTRUSTED_TRIGGERS,
  type WorkflowAgent,
} from './workflows.js';

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
  /** Settings the scanner does not model, and what it assumed instead. */
  readonly unrecognized: readonly Unrecognized[];
  /** Hooks that plugins in the repository install into every session that enables them. */
  readonly pluginHooks: readonly Hook[];
  /** Candidate files that were not read because they are too large. */
  readonly skippedFiles: readonly string[];
  /** Candidate files that are symbolic links, which are never followed. */
  readonly linkedFiles: readonly string[];
  /** Whether the directory walk stopped early, so some files were never looked at. */
  readonly truncated: boolean;
  /** Agent definitions whose settings could not be parsed (invalid front matter or YAML). */
  readonly unparsed: readonly { readonly path: string; readonly error: string }[];
}

/**
 * Plugin folders: a Claude Code plugin (`.claude-plugin/plugin.json`) or an Agent Plugin
 * (`plugin.json` beside `mcp.json` or a `skills/` folder). Returns each root ('' for the repo root).
 */
function pluginRoots(paths: readonly string[]): Set<string> {
  const roots = new Set<string>();
  const dirOf = (path: string, levels: number) => path.split('/').slice(0, -levels).join('/');
  const files = new Set(paths);
  for (const path of paths) {
    const parts = path.split('/');
    if (parts.at(-1) !== 'plugin.json') continue;
    if (parts.at(-2) === '.claude-plugin') roots.add(dirOf(path, 2));
    else {
      const root = dirOf(path, 1);
      // Tool folders (.kiro, .vscode, .cursor, ...) hold their own config, never an Agent Plugin.
      if (root.split('/').some(segment => segment.startsWith('.'))) continue;
      const prefix = root ? `${root}/` : '';
      if (files.has(`${prefix}mcp.json`) || paths.some(item => item.startsWith(`${prefix}skills/`))) roots.add(root);
    }
  }
  return roots;
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

/** Claude Code permission modes (`manual` is an alias for `default`). */
const CLAUDE_MODES = new Set(['default', 'manual', 'plan', 'acceptEdits', 'auto', 'dontAsk', 'bypassPermissions']);

/** File commands acceptEdits runs without asking, besides file edits. */
const ACCEPT_EDITS_COMMANDS = 'Bash(mkdir, touch, mv, cp)';

/**
 * Applies a permission mode to grants that would otherwise prompt. `bypassPermissions` and `auto`
 * (a classifier, not a person, approves) run them without asking; `dontAsk` denies them; an unknown
 * mode is assumed to run them without asking, with the capability marked unknown.
 */
function applyMode(grants: readonly Grant[], mode: string | undefined, at: Location, setting: string): Grant[] {
  if (mode === undefined || mode === 'default' || mode === 'manual' || mode === 'plan' || mode === 'acceptEdits')
    return [...grants];
  if (mode === 'dontAsk') return grants.filter(grant => grant.approval !== 'ask');
  const known = mode === 'bypassPermissions' || mode === 'auto';
  return grants.map(grant =>
    grant.approval === 'ask'
      ? {
          ...grant,
          approval: 'auto' as const,
          via: `${grant.via} (${setting}: ${mode})`,
          location: at,
          ...(known ? {} : { certainty: 'unknown' as const }),
        }
      : grant,
  );
}

/** What acceptEdits adds: file edits and common file commands without asking. */
function acceptEditsGrants(at: Location): Grant[] {
  return [
    ...grantsForRule(parseRule('Edit', at), 'auto', []),
    { capability: 'write', via: ACCEPT_EDITS_COMMANDS, tool: 'Bash', approval: 'auto', certainty: 'yes', location: at },
  ];
}

/** An MCP server that names Agent Guard; not this scanner's own read-only MCP server, which guards nothing. */
const AGENT_GUARD_SERVER = /agent-guard(?!-check)/;

function mediatorsFor(settings: readonly ClaudeSettings[], servers: readonly McpServer[]): Mediator[] {
  const out: Mediator[] = [];
  // Each mediator keeps what it sees: a hook its matcher, a guard or gateway only its own server's calls.
  // Hooks that never run see nothing: disableAllHooks anywhere turns them all off, and managed
  // allowManagedHooksOnly leaves only the managed ones.
  const hooksOff = settings.some(file => file.disableAllHooks);
  const managedOnly = settings.some(file => file.allowManagedHooksOnly && file.path.startsWith(`${MANAGED_DIR}/`));
  for (const file of settings)
    if (!hooksOff && (!managedOnly || file.path.startsWith(`${MANAGED_DIR}/`)))
      for (const hook of file.hooks)
        if (hook.event === 'PreToolUse')
          out.push({ kind: 'pre-tool-hook', location: hook.location, matcher: hook.matcher });
  for (const server of servers) {
    const text = [server.command ?? '', ...server.args, server.url ?? ''].join(' ');
    if (AGENT_GUARD_SERVER.test(text))
      out.push({ kind: 'agent-guard', location: server.location, server: server.name });
    else if (/\bmcp[- ]gateway\b|docker mcp gateway/.test(text))
      out.push({ kind: 'mcp-gateway', location: server.location, server: server.name });
  }
  return out;
}

/**
 * Reads every candidate file in a source and builds the project model. Never throws on bad input.
 * `extraFiles` are read as well (Agent Guard records given on the command line, for example).
 */
export interface BuildOptions {
  /** What MCP servers can do, as the team declared in `.agc.yaml`. */
  readonly declaredServers?: readonly DeclaredServer[];
  /** Settings outside the repository (`readUserConfig`), with `~/...` and `<managed>/...` paths. */
  readonly userFiles?: readonly TextFile[];
  /** The scanned folder's absolute path, to find its local-scope servers in `~/.claude.json`. */
  readonly root?: string;
}

/** Variables that send an agent's model traffic to another endpoint. */
export const MODEL_ENDPOINT =
  /^(ANTHROPIC_BASE_URL|ANTHROPIC_BEDROCK_BASE_URL|ANTHROPIC_VERTEX_BASE_URL|OPENAI_BASE_URL|HTTPS?_PROXY|ALL_PROXY|NODE_EXTRA_CA_CERTS)$/i;

/**
 * Whether a file the scanner could not read is agent configuration. `mcp.json` and `plugin.json`
 * are only configuration in a tool folder or a plugin (beside the other one or a `skills/` folder);
 * elsewhere they are unrelated files that happen to share the name.
 */
function isConfigPath(path: string, inputs: readonly { readonly path: string }[]): boolean {
  const parts = path.split('/');
  const name = parts.at(-1)!;
  if (name !== 'mcp.json' && name !== 'plugin.json') return true;
  if (['.vscode', '.cursor', '.claude-plugin', 'settings'].includes(parts.at(-2) ?? '')) return true;
  const folder = parts.slice(0, -1).join('/');
  const prefix = folder ? `${folder}/` : '';
  return inputs.some(
    input =>
      input.path === `${prefix}${name === 'mcp.json' ? 'plugin.json' : 'mcp.json'}` ||
      input.path.startsWith(`${prefix}skills/`),
  );
}

/** Folders that hold settings for every project rather than one: the user's and the managed ones. */
const USER_DIRS = new Set(['~', MANAGED_DIR]);

export function buildProject(
  source: FileSource,
  extraFiles: readonly TextFile[] = [],
  options: BuildOptions = {},
): Project {
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
  const unrecognized: Unrecognized[] = [];
  const pluginHooks: Hook[] = [];
  const plugins = new Map<string, { name: string; location: Location }>();
  /** Plugins whose server file could not be read: their reach is unknown. */
  const pluginUnknown = new Map<string, Location>();
  const pluginServerFiles = new Map<string, string[]>();
  /** Plugins whose hook file could not be read: they may run any command. */
  const pluginUnknownHooks = new Map<string, Location>();
  const cursorCli: TextFile[] = [];
  const unparsed: { path: string; error: string }[] = [];
  /** The first VS Code and Cursor MCP files: the IDE agent exists even when they list no server. */
  const ideFiles: { vscode?: string; cursor?: string } = {};
  const openCode: TextFile[] = [];
  const openCodeAgents: TextFile[] = [];
  const fail = (file: string, error: unknown) =>
    errors.push({ file, message: error instanceof Error ? error.message.split('\n')[0]! : String(error) });

  const extraPaths = new Set(extraFiles.map(file => file.path));
  // `~/...` and `<managed>/...` paths are settings outside the repository only when they come from
  // userFiles; from any other source they are dropped, so a repository cannot pose as them.
  const fromUser = new Set((options.userFiles ?? []).map(file => file.path));
  const posesAsUser = (path: string) => USER_DIRS.has(path.split('/')[0]!) && !fromUser.has(path);
  const inputs = [
    ...source
      .list()
      .filter(path => !extraPaths.has(path) && !posesAsUser(path))
      .map(path => ({ path, text: source.read(path) })),
    ...extraFiles.filter(file => !posesAsUser(file.path)),
    ...(options.userFiles ?? []),
  ];
  // Servers in ~/.claude.json: user scope (every project) and local scope (this folder only).
  const userServers: McpServer[] = [];
  const localScopeServers: McpServer[] = [];
  let managedDisablesBypass = false;
  // First pass: what identification needs. Every package.json in the repository names packages a
  // runner may resolve locally (its own name and its dependencies), and package-source files
  // redirect the runners of their ecosystem for their folder and below. One that is too large or a
  // link could not be read, so it is assumed to redirect.
  const localPackages = new Set<string>();
  const redirected = { npm: new Set<string>(), python: new Set<string>() };
  const folderOf = (path: string) => path.split('/').slice(0, -1).join('/');
  for (const { path, text } of inputs) {
    if (text === undefined) continue;
    const name = path.split('/').at(-1)!;
    if (name === 'package.json') {
      try {
        const data = JSON.parse(text) as unknown;
        if (isRecord(data)) {
          if (typeof data['name'] === 'string') localPackages.add(data['name']);
          for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'])
            if (isRecord(data[key])) for (const dep of Object.keys(data[key])) localPackages.add(dep);
        }
      } catch {
        // Reported when the file is parsed below.
      }
    }
    const ecosystem = packageSourceEcosystem(path, text);
    if (ecosystem) redirected[ecosystem].add(folderOf(path));
  }
  for (const path of [...(source.skippedFiles ?? []), ...(source.linkedFiles ?? [])]) {
    const name = path.split('/').at(-1)!;
    // Unread: it may redirect runners, or name local packages, so identification stops below it.
    if (PACKAGE_SOURCE_FILES.has(name) || name === 'package.json') {
      redirected.npm.add(folderOf(path));
      redirected.python.add(folderOf(path));
    }
  }
  const declaredServers: CatalogContext = {
    declared: options.declaredServers ?? [],
    localPackages,
    redirected,
  };
  const roots = pluginRoots(inputs.filter(input => !USER_DIRS.has(projectDir(input.path))).map(input => input.path));
  const rootOf = (path: string, levels: number) => path.split('/').slice(0, -levels).join('/');
  for (const { path, text } of inputs) {
    if (text === undefined) continue;
    filesRead += 1;
    const name = path.split('/').at(-1)!;
    const parent = path.split('/').at(-2);
    try {
      // Package-source files feed identification only (first pass), and a package.json below the root
      // only names local packages: neither holds agent settings.
      if (PACKAGE_SOURCE_FILES.has(name) || (name === 'package.json' && path !== 'package.json')) continue;
      if (path === '~/.claude.json') {
        const data = parseJsonc(text);
        if (isRecord(data)) {
          userServers.push(...serversFromObject(data, path, text, 'claude-code', 0, declaredServers));
          const projects = isRecord(data['projects']) ? data['projects'] : {};
          const own = options.root === undefined ? undefined : projects[options.root];
          if (isRecord(own))
            localScopeServers.push(...serversFromObject(own, path, text, 'claude-code', 0, declaredServers));
        }
        continue;
      }
      if (path === `${MANAGED_DIR}/managed-mcp.json`) {
        const data = parseJsonc(text);
        if (isRecord(data)) userServers.push(...serversFromObject(data, path, text, 'claude-code', 0, declaredServers));
        continue;
      }
      if (path === `${MANAGED_DIR}/managed-settings.json`) {
        settings.push(parseSettings(path, text));
        const data = parseJsonc(text);
        const permissions = isRecord(data) && isRecord(data['permissions']) ? data['permissions'] : {};
        managedDisablesBypass = permissions['disableBypassPermissionsMode'] === 'disable';
        continue;
      }
      if (parent === '.claude-plugin' && name === 'plugin.json' && roots.has(rootOf(path, 2))) {
        // A Claude Code plugin manifest: its name, and servers or hooks it declares inline.
        const data = parseJsonc(text);
        const root = rootOf(path, 2);
        const manifest = isRecord(data) ? data : {};
        plugins.set(root, {
          name: asString(manifest['name']) ?? (root.split('/').at(-1) || 'plugin'),
          location: { file: path, line: 1 },
        });
        if (isRecord(manifest['mcpServers']))
          servers.push(...serversFromObject(manifest, path, text, 'plugin', 0, declaredServers));
        if (isRecord(manifest['hooks'])) pluginHooks.push(...parseSettings(path, text).hooks);
        // Either may instead name a file in the plugin: read it from the same source.
        // Either may instead name a file, or a list of files, in the plugin: read them from the same
        // source. Anything else, or a file that cannot be read, is unknown and reported.
        for (const key of ['mcpServers', 'hooks'] as const) {
          const value = manifest[key];
          if (value === undefined || isRecord(value)) continue;
          const at: Location = { file: path, line: lineOf(text, JSON.stringify(key)) || 1 };
          const unread = (shown: string) => {
            unrecognized.push({
              agent: `Plugin ${plugins.get(root)!.name}`,
              setting: key,
              value: shown,
              assumed:
                key === 'mcpServers'
                  ? 'not read, so its servers may read private data, take in untrusted input and send data out'
                  : 'not read, so its hooks may run any command without asking',
              location: at,
            });
            (key === 'mcpServers' ? pluginUnknown : pluginUnknownHooks).set(root, at);
          };
          const entries = typeof value === 'string' ? [value] : Array.isArray(value) ? value : [value];
          for (const entry of entries) {
            if (isRecord(entry)) {
              if (key === 'mcpServers')
                servers.push(...serversFromObject({ mcpServers: entry }, path, text, 'plugin', 0, declaredServers));
              else pluginHooks.push(...parseSettings(path, JSON.stringify({ hooks: entry })).hooks);
              continue;
            }
            if (typeof entry !== 'string') {
              unread(JSON.stringify(entry) ?? String(entry));
              continue;
            }
            const relative = safeRelative(
              [root, entry.replace(/^\$\{CLAUDE_PLUGIN_ROOT\}\/?/, '').replace(/^\.\//, '')].filter(Boolean).join('/'),
            );
            const content = relative === undefined ? undefined : source.readNamed(relative);
            if (content === undefined || relative === undefined) {
              unread(entry);
              continue;
            }
            if (key === 'mcpServers') {
              servers.push(...parseMcpConfig(relative, content, 'plugin', declaredServers));
              pluginServerFiles.set(root, [...(pluginServerFiles.get(root) ?? []), relative]);
            } else pluginHooks.push(...parseSettings(relative, content).hooks);
          }
        }
        continue;
      }
      if (name === 'plugin.json' && roots.has(rootOf(path, 1))) {
        const data = parseJsonc(text);
        const root = rootOf(path, 1);
        plugins.set(root, {
          name: (isRecord(data) ? asString(data['name']) : undefined) ?? (root.split('/').at(-1) || 'plugin'),
          location: { file: path, line: 1 },
        });
        continue;
      }
      // An Agent Plugin's mcp.json. A `.mcp.json` stays Claude Code's project file even inside a
      // plugin folder: the plugin agent reads the same servers, it never takes them away.
      if (
        name === 'mcp.json' &&
        roots.has(rootOf(path, 1)) &&
        !path
          .split('/')
          .slice(0, -1)
          .some(s => s.startsWith('.'))
      ) {
        servers.push(...parseMcpConfig(path, text, 'plugin', declaredServers));
        continue;
      }
      if (parent === 'hooks' && name === 'hooks.json') {
        if (roots.has(rootOf(path, 2))) pluginHooks.push(...parseSettings(path, text).hooks);
        continue;
      }
      if (name === 'opencode.json' || name === 'opencode.jsonc') {
        openCode.push({ path, text });
        continue;
      }
      if (
        path.split('/').at(-3) === '.opencode' &&
        (parent === 'agent' || parent === 'agents') &&
        name.endsWith('.md')
      ) {
        openCodeAgents.push({ path, text });
        prompts.push({ path, text });
        continue;
      }
      if (parent === '.cursor' && name === 'cli.json') {
        cursorCli.push({ path, text });
        continue;
      }
      if (path.endsWith('.kiro/settings/mcp.json') && path.split('/').at(-3) === '.kiro') {
        others.push(parseKiroMcp(path, text, declaredServers));
        continue;
      }
      if (/^\.github\/workflows\/[^/]+\.md$/.test(path) && isAgenticWorkflow(text)) {
        others.push(
          parseAgenticWorkflow(path, text, declaredServers, item => {
            const relative = safeRelative(`.github/workflows/${item.replace(/^\.\//, '')}`);
            return relative === undefined ? undefined : source.readNamed(relative);
          }),
        );
        prompts.push({ path, text });
        continue;
      }
      if (/^\.github\/agents\/[^/]+\.md$/.test(path)) {
        others.push(parseCopilotAgent(path, text, declaredServers));
        prompts.push({ path, text });
        continue;
      }
      if (name === '.cursorrules' || name === '.windsurfrules' || name.endsWith('.mdc')) {
        prompts.push({ path, text });
        continue;
      }
      if (name === 'plugin.json' || (name === 'mcp.json' && parent !== '.vscode' && parent !== '.cursor')) continue;
      if (/^agent-guard[\w.-]*\.json$/.test(name) || extraPaths.has(path))
        guardFiles.push({ path, text, data: JSON.parse(text) as unknown });
      else if (parent === '.claude' && (name === 'settings.json' || name === 'settings.local.json')) {
        settings.push(parseSettings(path, text));
        pluginSources.push(...parsePluginSettings(path, text));
      } else if (parent === '.codex' && name === 'config.toml') others.push(parseCodex(path, text, declaredServers));
      else if (parent === '.gemini' && name === 'settings.json') others.push(parseGemini(path, text, declaredServers));
      else if (parent === '.claude-plugin' && name === 'marketplace.json')
        pluginSources.push(...parseMarketplace(path, text));
      else if (name === '.mcp.json') servers.push(...parseMcpConfig(path, text, 'claude-code', declaredServers));
      else if (path.endsWith('.vscode/mcp.json') && (ideFiles.vscode ??= path))
        servers.push(...parseMcpConfig(path, text, 'vscode', declaredServers));
      else if (path.endsWith('.cursor/mcp.json') && (ideFiles.cursor ??= path))
        servers.push(...parseMcpConfig(path, text, 'cursor', declaredServers));
      else if (path.startsWith('.github/workflows/') && /\.ya?ml$/.test(name))
        workflows.push(
          ...parseWorkflow(path, text, declaredServers, named => {
            const relative = safeRelative(named);
            return relative === undefined ? undefined : source.readNamed(relative);
          }),
        );
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
          const parsed = frontmatter(text);
          // Claude Code reads subagent front matter leniently (top-level `key: value` lines), so
          // that is the fallback; front matter that cannot be read either way hides the subagent's
          // settings: assume the worst.
          const lenient = parsed.error ? lenientFrontmatter(text) : undefined;
          if (parsed.error && !lenient) unparsed.push({ path, error: parsed.error });
          const data: Record<string, unknown> = parsed.error
            ? (lenient ?? { permissionMode: '(front matter not readable)' })
            : parsed.data;
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
          const subServers = serversFromObject({ mcpServers: inline }, path, text, 'subagent', 0, declaredServers);
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

  // User-scope and managed servers are judged by the server rules (pinning, secrets, policy) too.
  servers.push(...userServers, ...localScopeServers);
  const agents: Agent[] = [];
  // User and managed settings apply to every project; Claude Code runs at the root with them alone.
  const userLevel = [
    ...settings.filter(file => projectDir(file.path) === '~'),
    ...settings.filter(file => projectDir(file.path) === MANAGED_DIR),
  ];
  const managed = settings.filter(file => projectDir(file.path) === MANAGED_DIR);
  const dirs = new Set<string>(
    [
      ...settings.map(file => projectDir(file.path)),
      ...servers.filter(server => server.client === 'claude-code').map(server => projectDir(server.location.file)),
      ...subagents.map(item => item.projectDir),
      ...(userLevel.length || userServers.length || localScopeServers.length ? [''] : []),
    ].filter(dir => !USER_DIRS.has(dir)),
  );
  const rootSettings = settings.filter(file => projectDir(file.path) === '');
  const rootServers = servers.filter(
    server => server.client === 'claude-code' && projectDir(server.location.file) === '',
  );

  for (const dir of [...dirs].sort()) {
    const local = settings.filter(file => projectDir(file.path) === dir);
    const localServers = [
      ...servers.filter(server => server.client === 'claude-code' && projectDir(server.location.file) === dir),
      ...userServers,
      ...(dir === '' ? localScopeServers : []),
    ];
    const allow = [...local, ...userLevel].flatMap(file => file.allow);
    const deny = [...local, ...userLevel].flatMap(file => file.deny);
    // Managed settings win, then the project's own (local before shared), then the user's.
    const chosen =
      [...managed].reverse().find(file => file.defaultMode)?.defaultMode ??
      [...local].reverse().find(file => file.defaultMode)?.defaultMode ??
      userLevel.find(file => file.defaultMode)?.defaultMode;
    const modeSetting = chosen?.value === 'bypassPermissions' && managedDisablesBypass ? undefined : chosen;
    const mode = modeSetting?.value;
    const skip = mode === 'bypassPermissions';
    const anchor: Location = local[0]
      ? { file: local[0].path, line: 1 }
      : localServers[0]
        ? { file: localServers[0].location.file, line: 1 }
        : { file: within(dir, '.claude'), line: 1 };
    const name = dir ? `Claude Code (${dir})` : 'Claude Code (project)';
    if (modeSetting && !CLAUDE_MODES.has(modeSetting.value))
      unrecognized.push({
        agent: name,
        setting: 'defaultMode',
        value: modeSetting.value,
        assumed: 'every tool runs without asking',
        location: modeSetting.location,
      });
    // Model traffic sent somewhere else carries everything the agent reads. The scan does not count
    // that as sending data out (it is the model's own channel), but says so.
    for (const file of [...local, ...userLevel])
      for (const entry of file.env)
        if (MODEL_ENDPOINT.test(entry.name))
          unrecognized.push({
            agent: name,
            setting: `env.${entry.name}`,
            value: entry.value,
            assumed:
              'model traffic, with everything the agent reads, goes to this endpoint; it is not counted as sending data out',
            location: entry.location,
          });
    // Claude Code's Bash sandbox: sandboxed commands run and write without asking unless
    // autoAllowBashIfSandboxed is false. Network reach is left as the rules give it: a command can
    // leave the sandbox (allowUnsandboxedCommands, excludedCommands) through the normal permission
    // flow, where an allowed command still runs without asking, and the allowed domains are not
    // modelled, so the sandbox never lowers egress.
    const sandboxed = [...local, ...userLevel].find(file => file.sandbox);
    const sandboxAuto = sandboxed !== undefined && [...local, ...userLevel].every(file => file.autoAllowSandboxedBash);
    if (sandboxed)
      unrecognized.push({
        agent: name,
        setting: 'sandbox.enabled',
        value: 'true',
        assumed: sandboxAuto
          ? 'sandboxed Bash runs and writes without asking; its network reach is judged as if unsandboxed'
          : 'Bash asks before it runs; its network reach is judged as if unsandboxed',
        location: sandboxed.sandbox!,
      });
    const inSandbox = (list: readonly Grant[]): Grant[] =>
      !sandboxed
        ? [...list]
        : list.map(grant =>
            grant.tool !== 'Bash'
              ? grant
              : {
                  ...grant,
                  ...(sandboxAuto && grant.approval === 'ask' && grant.capability !== 'egress'
                    ? { approval: 'auto' as const, via: `${grant.via} (sandboxed, autoAllowBashIfSandboxed)` }
                    : {}),
                },
          );
    // What the session could do before its own mode: a subagent with its own mode starts from this.
    const unmoded = withoutDenied(
      [
        ...baselineGrants('ask', anchor, localServers, allow, deny, false),
        ...allow.flatMap(rule => grantsForRule(rule, 'auto', localServers)),
      ],
      deny,
    );
    const grants = [
      ...(skip
        ? baselineGrants('auto', modeSetting!.location, localServers, allow, deny, true)
        : applyMode(
            baselineGrants('ask', anchor, localServers, allow, deny, false),
            mode,
            modeSetting?.location ?? anchor,
            'defaultMode',
          )),
      ...allow.flatMap(rule => grantsForRule(rule, 'auto', localServers)),
      ...(mode === 'acceptEdits' ? acceptEditsGrants(modeSetting!.location) : []),
    ];
    // In auto mode Claude Code's safety review checks each call before it runs: a runtime check.
    const mediators = [
      ...mediatorsFor([...local, ...userLevel], localServers),
      ...(mode === 'auto' ? [{ kind: 'auto-mode' as const, location: modeSetting!.location }] : []),
    ];
    const main: Agent = {
      id: `claude-code:${dir || '.'}`,
      kind: 'claude-code',
      name,
      location: anchor,
      grants: inSandbox(withoutDenied(grants, deny)),
      mediators,
      headless: false,
    };
    agents.push(main);
    // Under a bypassPermissions or auto session, the session's mode wins: a subagent cannot narrow it.
    const sessionWins = mode === 'bypassPermissions' || mode === 'auto';
    for (const sub of subagents.filter(item => item.projectDir === dir)) {
      const mode = sub.permissionMode?.value;
      const edits = mode === 'acceptEdits' && !sessionWins;
      const ownMode =
        mode !== undefined &&
        mode !== 'default' &&
        mode !== 'manual' &&
        mode !== 'plan' &&
        (!sessionWins || mode === 'bypassPermissions');
      if (sub.permissionMode && !CLAUDE_MODES.has(sub.permissionMode.value))
        unrecognized.push({
          agent: `Subagent ${sub.name}`,
          setting: 'permissionMode',
          value: sub.permissionMode.value,
          assumed: 'every tool it has runs without asking',
          location: sub.permissionMode.location,
        });
      // A subagent with no tools list, no own mode and no own servers is the main agent again.
      if (!sub.tools && !ownMode && !sub.servers.length) continue;
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
        grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'ask', sub.servers),
      );
      // The subagent's own mode replaces the session's for its calls.
      // Its own mode replaces the session's, so it starts from the grants before the session's mode:
      // a session in dontAsk must not hide what a bypassPermissions subagent can do.
      let grants = ownMode
        ? applyMode([...unmoded.filter(keeps), ...own], mode, modeAt, 'permissionMode')
        : [...main.grants.filter(keeps), ...own];
      if (edits && (tools === undefined || tools.some(tool => ['Edit', 'Write', 'MultiEdit'].includes(tool))))
        grants.push(
          ...acceptEditsGrants(modeAt).filter(
            grant => tools === undefined || grant.tool !== 'Bash' || tools.includes('Bash'),
          ),
        );
      const deny = sub.disallowedTools.map(tool => parseRule(tool, sub.location));
      grants = inSandbox(withoutDenied(grants, deny));
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
    for (const endpoint of step.endpoints)
      unrecognized.push({
        agent: `Workflow ${step.path.split('/').at(-1)} › ${step.job}`,
        setting: `env.${endpoint.name}`,
        value: endpoint.value,
        assumed:
          'model traffic, with everything the agent reads, goes to this endpoint; it is not counted as sending data out',
        location: endpoint.location,
      });
    if (step.settingsUnreadable) {
      const { value, location } = step.settingsUnreadable;
      unrecognized.push({
        agent: `Workflow ${step.path.split('/').at(-1)} › ${step.job}`,
        setting: 'settings',
        value,
        assumed: 'they could not be read, so the step may run any tool without asking',
        location,
      });
      for (const capability of ['exec', 'write', 'egress'] as const)
        add({ capability, via: `settings ${value} (not read)`, certainty: 'unknown', location });
    }
    if (step.skipPermissions) grants.push(...baselineGrants('auto', step.skipPermissions, reachable, [], [], true));
    else if (step.autoMode)
      grants.push(
        ...baselineGrants('auto', step.autoMode, reachable, [], [], true).map(grant => ({
          ...grant,
          via: `${grant.via} (permission-mode auto)`,
        })),
      );
    else if (step.action === 'copilot-cli' || step.action === 'gemini-cli') {
      // Their tool settings are not read: what they may run, write and reach is unknown.
      for (const capability of ['exec', 'write', 'egress'] as const)
        add({
          capability,
          via: `${step.action === 'copilot-cli' ? 'Copilot CLI' : 'Gemini CLI'} (tools not read)`,
          certainty: 'unknown',
          location: at,
        });
    } else if (step.codex) {
      // Codex in a workflow runs commands without asking, inside its sandbox. What the commands can
      // write and reach is the sandbox's: read-only writes nothing; workspace-write writes the
      // checkout; the network is off unless the config or a permission profile turns it on.
      const { sandbox, profile, location } = step.codex;
      const via = `Codex ${sandbox ? `sandbox ${sandbox}` : profile ? `permission profile ${profile}` : 'default sandbox'}`;
      add({ capability: 'exec', via, tool: 'shell', certainty: 'yes', location });
      if (sandbox !== 'read-only')
        add({
          capability: 'write',
          via,
          tool: 'shell',
          certainty: sandbox === 'workspace-write' ? 'yes' : 'unknown',
          location,
        });
      add({ capability: 'egress', via, tool: 'shell', certainty: 'unknown', location });
    }
    // With a GitHub token and a shell, the agent can read any issue or pull request, which anyone can
    // write, whatever started the workflow. Whether its prompt does is not in the file: unknown.
    if (
      step.githubToken &&
      grants.some(grant => grant.capability === 'exec' && grant.approval === 'auto') &&
      !grants.some(grant => grant.capability === 'untrustedInput')
    )
      add({
        capability: 'untrustedInput',
        via: 'GitHub token with a shell (issue and pull-request text)',
        certainty: 'unknown',
        location: at,
      });
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
      mediators: [
        ...(step.action.startsWith('claude') ? mediatorsFor(rootSettings, []) : []),
        ...(step.autoMode ? [{ kind: 'auto-mode' as const, location: step.autoMode }] : []),
      ],
      headless: true,
    });
  }

  for (const client of ['vscode', 'cursor'] as const) {
    const list = servers.filter(server => server.client === client);
    const file = list[0]?.location.file ?? ideFiles[client];
    if (file === undefined) continue;
    agents.push({
      id: `mcp-client:${file}`,
      kind: 'mcp-client',
      name: client === 'vscode' ? 'VS Code agent mode' : 'Cursor agent',
      location: { file, line: 1 },
      // The IDE agent's own tools: it asks before terminal commands and fetches, and applies edits.
      grants: [
        ...grantsForRule(parseRule('Bash', { file, line: 1 }), 'ask', []),
        ...grantsForRule(parseRule('WebFetch', { file, line: 1 }), 'ask', []),
        ...grantsForRule(parseRule('Edit', { file, line: 1 }), 'auto', []),
        ...list.flatMap(server => grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'ask', list)),
      ],
      mediators: mediatorsFor([], list),
      headless: false,
    });
  }

  // OpenCode: one agent per folder, with the agents in its .opencode/agent(s)/ folder.
  const openCodeDir = (path: string) =>
    path.split('/').at(-2) === '.opencode'
      ? rootOf(path, 2)
      : path.includes('/.opencode/') || path.startsWith('.opencode/')
        ? rootOf(path, 3)
        : rootOf(path, 1);
  const openCodeDirs = new Set([...openCode, ...openCodeAgents].map(file => openCodeDir(file.path)));
  for (const dir of [...openCodeDirs].sort()) {
    const configs = openCode.filter(file => openCodeDir(file.path) === dir);
    const mine = openCodeAgents.filter(file => openCodeDir(file.path) === dir);
    try {
      if (configs.length)
        for (const config of configs) others.push(parseOpenCode(config.path, config.text, declaredServers, mine, dir));
      else others.push(parseOpenCode(mine[0]!.path, '{}', declaredServers, mine, dir));
    } catch (error) {
      fail(configs[0]?.path ?? mine[0]!.path, error);
    }
  }

  // A gh-aw lock file is judged from its source; one with no source beside it, as unknown reach.
  const inputPaths = new Set(inputs.map(input => input.path));
  for (const { path, text } of inputs)
    if (
      text !== undefined &&
      /^\.github\/workflows\/[^/]+\.lock\.ya?ml$/.test(path) &&
      isAgenticLock(text) &&
      !inputPaths.has(path.replace(/\.lock\.ya?ml$/, '.md'))
    )
      others.push(parseAgenticLockAlone(path, text));

  for (const file of cursorCli) {
    const dir = file.path.split('/').slice(0, -2).join('/');
    const own = servers.filter(server => server.client === 'cursor' && rootOf(server.location.file, 2) === dir);
    try {
      others.push(parseCursorCli(file.path, file.text, own));
    } catch (error) {
      fail(file.path, error);
    }
  }

  for (const [root, plugin] of [...plugins].sort(([a], [b]) => a.localeCompare(b))) {
    const prefix = root ? `${root}/` : '';
    const files = new Set([
      `${prefix}.mcp.json`,
      `${prefix}mcp.json`,
      `${prefix}.claude-plugin/plugin.json`,
      ...(pluginServerFiles.get(root) ?? []),
    ]);
    const unknownAt = pluginUnknown.get(root);
    const hooksAt = pluginUnknownHooks.get(root);
    const own = servers.filter(
      server => (server.client === 'plugin' || server.client === 'claude-code') && files.has(server.location.file),
    );
    // Whoever enables the plugin gets its servers; Claude Code asks before their tools run by default.
    agents.push({
      id: `plugin:${root || '.'}`,
      kind: 'plugin',
      name: `Plugin ${plugin.name}`,
      location: plugin.location,
      grants: [
        ...own.flatMap(server => grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'ask', own)),
        ...(unknownAt
          ? (['privateData', 'untrustedInput', 'egress'] as const).map(capability => ({
              capability,
              via: 'mcpServers (file not read)',
              approval: 'ask' as const,
              certainty: 'unknown' as const,
              location: unknownAt,
            }))
          : []),
        ...(hooksAt
          ? [
              {
                capability: 'exec' as const,
                via: 'hooks (file not read)',
                approval: 'auto' as const,
                certainty: 'unknown' as const,
                location: hooksAt,
              },
            ]
          : []),
      ],
      mediators: [],
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
    unrecognized: [...unrecognized, ...others.flatMap(other => other.unrecognized)],
    pluginHooks,
    skippedFiles: (source.skippedFiles ?? []).filter(path => isConfigPath(path, inputs)),
    linkedFiles: (source.linkedFiles ?? []).filter(path => isConfigPath(path, inputs)),
    truncated: source.truncated ?? false,
    unparsed: [...unparsed, ...others.flatMap(other => other.unparsed ?? [])],
  };
}
