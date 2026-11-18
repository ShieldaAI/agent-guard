import type { Agent, Grant, Location, Mediator, Unrecognized } from './types.js';
import { mediates } from './authority.js';
import { DECIDING_EVENTS, judgeHook, type HookJudgement } from './hooks.js';
import { MODEL_ENDPOINT, endpointSeverity } from './endpoints.js';
import { agenticFrontmatterHash, lockMetadata, lockMismatches, sourceAsks } from './ghaw.js';
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
import { PACKAGE_SOURCE_FILES, packageSourceEcosystem, SKIPPED_DIRECTORIES, unmodelledAgentFile } from './source.js';
import {
  asString,
  asStringArray,
  frontmatter,
  isRecord,
  lenientFrontmatter,
  lineOf,
  parseJsonc,
  toolNames,
} from './text.js';
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
  UNKNOWN_CALLER,
  inheritedTriggers,
  workflowCalls,
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
  /** Every hook with what it can reach and whether it can approve tool calls. */
  readonly hookJudgements: readonly { readonly hook: Hook; readonly judgement: HookJudgement }[];
  /** Candidate files that were not read because they are too large. */
  readonly skippedFiles: readonly string[];
  /** Candidate files that are symbolic links, which are never followed. */
  readonly linkedFiles: readonly string[];
  /** Whether the directory walk stopped early, so some files were never looked at. */
  /** Agent configuration inside a folder the walk skips: not read. */
  readonly skippedConfig: readonly string[];
  readonly truncated: boolean;
  /** Agent definitions whose settings could not be parsed (invalid front matter or YAML). */
  readonly unparsed: readonly { readonly path: string; readonly error: string }[];
  /** gh-aw lock files judged from their source, with both texts (to catch a lock edited alone). */
  readonly compiledLocks: readonly { readonly lock: string; readonly lockText: string; readonly sourceText: string }[];
  /** `allowed-tools` from skills and commands: tools that run without asking while one is active. */
  readonly skillAllow: readonly PermissionRule[];
  /** Paths that are configuration only when letter case is ignored, and case collisions. */
  readonly caseVariants: readonly string[];
  readonly caseCollisions: readonly (readonly [string, string])[];
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

/**
 * An agent that can edit any file without asking and run a project command without asking can
 * rewrite that command's code and run it: what it then reaches is unknown, not behind approval.
 */
function editThenRun(grants: Grant[]): Grant[] {
  const edits = grants.find(
    grant =>
      grant.capability === 'selfModify' &&
      grant.approval === 'auto' &&
      ['Edit', 'Write', 'MultiEdit', '*'].includes(grant.tool ?? ''),
  );
  const runs = grants.find(
    grant =>
      grant.capability === 'exec' &&
      grant.approval === 'auto' &&
      grant.tool === 'Bash' &&
      bashScope(parseRule(grant.via, grant.location).specifier) === 'project',
  );
  if (!edits || !runs) return grants;
  return [
    ...grants,
    {
      capability: 'egress',
      via: `${runs.via} after ${edits.via} (edited code runs without asking)`,
      tool: 'Bash',
      approval: 'auto',
      certainty: 'unknown',
      location: runs.location,
    },
  ];
}

/** The hooks that run for these settings: none with disableAllHooks, managed only with allowManagedHooksOnly. */
function activeHooks(settings: readonly ClaudeSettings[]): Hook[] {
  const hooksOff = settings.some(file => file.disableAllHooks);
  const managedOnly = settings.some(file => file.allowManagedHooksOnly && file.path.startsWith(`${MANAGED_DIR}/`));
  if (hooksOff) return [];
  return settings.filter(file => !managedOnly || file.path.startsWith(`${MANAGED_DIR}/`)).flatMap(file => file.hooks);
}

/**
 * Tool calls a PreToolUse or PermissionRequest hook can approve now run without asking. A hook
 * that says "allow" approves for certain; one whose text cannot be read may (unknown).
 */
function approvedByHooks(grants: Grant[], approvers: readonly Hook[], judge: (hook: Hook) => HookJudgement): Grant[] {
  const out = [...grants];
  for (const grant of grants) {
    if (grant.approval !== 'ask') continue;
    const hook = approvers.find(item =>
      mediates({ kind: 'pre-tool-hook', location: item.location, matcher: item.matcher }, grant.tool),
    );
    if (!hook) continue;
    out.push({
      ...grant,
      approval: 'auto',
      certainty: judge(hook).approves === 'yes' ? grant.certainty : 'unknown',
      via: `${grant.via} (approved by a ${hook.event} hook)`,
      location: hook.location,
    });
  }
  return out;
}

function mediatorsFor(
  settings: readonly ClaudeSettings[],
  servers: readonly McpServer[],
  judge: (hook: Hook) => HookJudgement,
): Mediator[] {
  const out: Mediator[] = [];
  // Each mediator keeps what it sees: a hook its matcher, a guard or gateway only its own server's calls.
  // Hooks that never run see nothing: disableAllHooks anywhere turns them all off, and managed
  // allowManagedHooksOnly leaves only the managed ones.
  // A hook that can approve calls (or whose text cannot be read) is not a check on them.
  for (const hook of activeHooks(settings))
    if (hook.event === 'PreToolUse' && judge(hook).approves === 'no')
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
export { MODEL_ENDPOINT, endpointSeverity } from './endpoints.js';

/**
 * Approval settings in editor and Aider config: VS Code's chat auto-approve, Zed's
 * always_allow_tool_actions and context servers, Aider's yes-always and test or lint commands.
 */
function approvalSettings(path: string, text: string, unrecognized: Unrecognized[], bypasses: Bypass[]): void {
  const at = (needle: string) => ({ file: path, line: lineOf(text, needle) || 1 });
  if (path.endsWith('.aider.conf.yml')) {
    if (/^\s*yes(-always)?\s*:\s*true\b/m.test(text))
      bypasses.push({ agent: 'Aider', what: 'yes-always: true', location: at('yes') });
    if (/^\s*(test|lint)-cmd\s*:/m.test(text))
      unrecognized.push({
        agent: 'Aider',
        setting: 'test-cmd / lint-cmd',
        value: path,
        assumed: 'it runs these commands after edits without asking',
        location: at('-cmd'),
        severity: 'high',
      });
    return;
  }
  let data: unknown;
  try {
    data = parseJsonc(text);
  } catch {
    return;
  }
  if (!isRecord(data)) return;
  let record: Record<string, unknown> = data;
  // A workspace file keeps its settings under `settings`; a dev container under
  // `customizations.vscode.settings`.
  if (path.endsWith('.code-workspace') || path.endsWith('devcontainer.json')) {
    const nested = path.endsWith('.code-workspace')
      ? record['settings']
      : isRecord(record['customizations']) && isRecord(record['customizations']['vscode'])
        ? record['customizations']['vscode']['settings']
        : undefined;
    if (!isRecord(nested)) return;
    record = nested;
  }
  if (
    path.endsWith('.vscode/settings.json') ||
    path.endsWith('.code-workspace') ||
    path.endsWith('devcontainer.json')
  ) {
    // URL fetches and edits approved by pattern: a wildcard sends data anywhere, or edits any file.
    for (const [key, capability] of [
      ['chat.tools.urls.autoApprove', 'fetches to any matching URL'],
      ['chat.tools.edits.autoApprove', 'edits to any matching file'],
    ] as const) {
      const rules = record[key];
      const wild =
        rules === true ||
        (isRecord(rules) &&
          Object.entries(rules).some(
            ([pattern, value]) =>
              (value === true || (isRecord(value) && Object.values(value).includes(true))) && /\*/.test(pattern),
          ));
      if (wild)
        unrecognized.push({
          agent: 'VS Code agent',
          setting: key,
          value: JSON.stringify(rules).slice(0, 120),
          assumed: `${capability} run without asking`,
          location: at(`"${key}"`),
          severity: key.includes('urls') ? 'high' : 'medium',
        });
    }
    for (const key of ['chat.tools.autoApprove', 'chat.tools.global.autoApprove'])
      if (record[key] === true)
        bypasses.push({ agent: 'VS Code agent', what: `${key}: true`, location: at(`"${key}"`) });
    for (const key of ['chat.tools.terminal.autoApprove', 'chat.agent.terminal.autoApprove']) {
      const rules = record[key];
      // A command approved as written is judged like a Bash rule; a pattern (`/.../`) may match anything.
      const wide = (command: string) =>
        command.startsWith('/') || !['local', 'read', 'fetch', 'edit', 'project'].includes(bashScope(command));
      if (
        isRecord(rules) &&
        Object.entries(rules).some(
          ([command, value]) => (value === true || (isRecord(value) && value['approve'] === true)) && wide(command),
        )
      )
        unrecognized.push({
          agent: 'VS Code agent',
          setting: key,
          value: JSON.stringify(rules).slice(0, 120),
          assumed: 'the terminal commands these patterns match run without asking, and may reach the network',
          location: at(`"${key}"`),
          severity: 'high',
        });
    }
    return;
  }
  // Zed: `agent.always_allow_tool_actions`, and context servers (MCP) it starts.
  const agent = isRecord(record['agent']) ? record['agent'] : isRecord(record['assistant']) ? record['assistant'] : {};
  if (agent['always_allow_tool_actions'] === true)
    bypasses.push({
      agent: 'Zed agent',
      what: 'always_allow_tool_actions: true',
      location: at('always_allow_tool_actions'),
    });
  if (isRecord(record['context_servers']) && Object.keys(record['context_servers']).length)
    unrecognized.push({
      agent: 'Zed agent',
      setting: 'context_servers',
      value: Object.keys(record['context_servers']).join(', '),
      assumed: 'these MCP servers may run code and send data out',
      location: at('context_servers'),
      severity: 'high',
    });
}

/** Environment variables that run code with every shell command or every program start. */
const SHELL_LOADER =
  /^(BASH_ENV|ENV|ZDOTDIR|PROMPT_COMMAND|CLAUDE_CODE_SHELL_PREFIX|CLAUDE_ENV_FILE|PATH|SHELL|LD_\w+|DYLD_\w+|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME|PYTHONUSERBASE|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|NODE_PATH|NODE_OPTIONS|GIT_\w*(SSH|ASKPASS|EXTERNAL_DIFF|EDITOR|PAGER|EXEC_PATH|TEMPLATE_DIR|PROXY_COMMAND)\w*|GIT_CONFIG\w*|SSH_ASKPASS|SUDO_ASKPASS|EDITOR|VISUAL|PAGER|MANPAGER|LESSOPEN|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|MAVEN_OPTS|GRADLE_OPTS|RUSTC_WRAPPER|RUSTC|RUSTC_WORKSPACE_WRAPPER|CARGO_\w*(RUSTC|RUNNER|WRAPPER|LINKER)\w*|GOFLAGS|GOTOOLCHAIN|CC|CXX|LD|MAKEFLAGS|npm_config_\w+|NPM_CONFIG_\w+|YARN_\w*(REGISTRY|PATH|PLUGINS)\w*|PIP_\w*(INDEX|FIND_LINKS|TRUSTED)\w*|UV_\w*(INDEX|FIND_LINKS)\w*|PIPX_\w*INDEX\w*|BUNDLE_\w+|GEM_\w+|DOTNET_STARTUP_HOOKS|DOTNET_ADDITIONAL_DEPS|CORECLR_\w+|COMPlus_\w+)$/i;

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
  const editorBypasses: Bypass[] = [];
  const pluginHooks: Hook[] = [];
  /** Cursor's hooks: judged and reported, never applied to Claude Code's grants. */
  const cursorHooks: Hook[] = [];
  const plugins = new Map<string, { name: string; location: Location }>();
  /** Plugins whose server file could not be read: their reach is unknown. */
  const pluginUnknown = new Map<string, Location>();
  const pluginServerFiles = new Map<string, string[]>();
  /** Plugins whose hook file could not be read: they may run any command. */
  const pluginUnknownHooks = new Map<string, Location>();
  const cursorCli: TextFile[] = [];
  const unparsed: { path: string; error: string }[] = [];
  const compiledLocks: { lock: string; lockText: string; sourceText: string }[] = [];
  /** The first VS Code and Cursor MCP files: the IDE agent exists even when they list no server. */
  const ideFiles: { vscode?: string; cursor?: string } = {};
  const openCode: TextFile[] = [];
  const openCodeAgents: TextFile[] = [];
  // A configuration file that cannot be parsed is not judged: a finding, not only a warning, so a
  // file broken on purpose (too many YAML aliases, a stray byte) cannot hide what it grants.
  const fail = (file: string, error: unknown) => {
    const message = error instanceof Error ? error.message.split('\n')[0]! : String(error);
    errors.push({ file, message });
    if (file && isConfigPath(file, inputs) && !unparsed.some(item => item.path === file))
      unparsed.push({ path: file, error: message });
  };

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
  const inputText = new Map(inputs.map(input => [input.path, input.text]));
  const sourceOf = (lock: string) => inputText.get(lock.replace(/\.lock\.ya?ml$/, '.md'));
  const compiledFromSource = (path: string, text: string) => {
    if (!/^\.github\/workflows\/[^/]+\.lock\.ya?ml$/.test(path) || !isAgenticLock(text)) return false;
    const md = sourceOf(path);
    return md !== undefined && isAgenticWorkflow(md);
  };
  const roots = pluginRoots(inputs.filter(input => !USER_DIRS.has(projectDir(input.path))).map(input => input.path));
  // A repository file a hook or lock names, read even when it is not a candidate.
  const readRepoFile = (named: string) => {
    const relative = safeRelative(named);
    return relative === undefined ? undefined : (inputText.get(relative) ?? source.readNamed(relative));
  };
  // Plugins whose code is in the repository (a plugin.json with a name): enabling one is judged here.
  const pluginNamesInRepo = new Set<string>();
  for (const input of inputs)
    if (input.text !== undefined && /(^|\/)plugin\.json$/.test(input.path))
      try {
        const manifest = JSON.parse(input.text) as unknown;
        if (isRecord(manifest) && typeof manifest['name'] === 'string') pluginNamesInRepo.add(manifest['name']);
      } catch {
        // Reported where the manifest is read.
      }
  const judged = new Map<Hook, HookJudgement>();
  const judgeOf = (hook: Hook): HookJudgement => {
    const known = judged.get(hook);
    if (known) return known;
    const file = hook.location.file;
    const dir = USER_DIRS.has(projectDir(file)) ? '' : projectDir(file);
    const root = [...roots].filter(item => !item || file.startsWith(`${item}/`)).sort((a, b) => b.length - a.length)[0];
    const judgement = judgeHook(hook, readRepoFile, dir, root ?? dir);
    judged.set(hook, judgement);
    return judgement;
  };
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
      // Cursor hooks (`{"hooks": {"afterFileEdit": [{"command": "..."}]}}`): judged as hooks are.
      if (path.endsWith('.cursor/hooks.json')) {
        const data = parseJsonc(text);
        const events = isRecord(data) && isRecord(data['hooks']) ? data['hooks'] : {};
        for (const [event, list] of Object.entries(events))
          for (const entry of Array.isArray(list) ? list : []) {
            const command = isRecord(entry) ? asString(entry['command']) : undefined;
            if (command)
              cursorHooks.push({
                event,
                matcher: '',
                command,
                type: 'command',
                location: { file: path, line: lineOf(text, JSON.stringify(command)) || 1 },
              });
          }
        continue;
      }
      // Agents the scanner does not model: reported, never judged.
      const unmodelled = unmodelledAgentFile(path);
      if (unmodelled) {
        // A Gemini command runs a shell command only with `!{...}`.
        if (unmodelled.tool !== 'Gemini CLI commands' || /!\{/.test(text))
          unrecognized.push({
            agent: unmodelled.tool,
            setting: 'file',
            value: path,
            assumed:
              unmodelled.runsCode || /!\{/.test(text)
                ? 'its servers, hooks or commands may run code and send data out without asking'
                : 'what it lets an agent do is unknown',
            location: { file: path, line: 1 },
            // Gemini CLI asks before the shell commands of a custom command: medium.
            severity: unmodelled.runsCode ? 'high' : 'medium',
          });
        continue;
      }
      if (
        path.endsWith('.vscode/settings.json') ||
        path.endsWith('.zed/settings.json') ||
        name === '.aider.conf.yml' ||
        name.endsWith('.code-workspace') ||
        path.endsWith('.devcontainer/devcontainer.json')
      ) {
        approvalSettings(path, text, unrecognized, editorBypasses);
        continue;
      }
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
        // An enabled plugin whose code is not in the repository: its hooks, servers and commands run
        // with the agent's access and are not judged. Anthropic's own marketplace is medium.
        const enabledData = parseJsonc(text);
        const enabled =
          isRecord(enabledData) && isRecord(enabledData['enabledPlugins']) ? enabledData['enabledPlugins'] : {};
        for (const [plugin, on] of Object.entries(enabled)) {
          if (on !== true) continue;
          const [pluginName, market] = plugin.split('@');
          if (pluginNamesInRepo.has(pluginName ?? '')) continue;
          unrecognized.push({
            agent: `Plugin ${plugin}`,
            setting: 'enabledPlugins',
            value: plugin,
            assumed:
              'its hooks, MCP servers and commands are not in the repository, so they may run code and send data out',
            location: { file: path, line: lineOf(text, JSON.stringify(plugin)) || 1 },
            severity: market === 'claude-plugins-official' ? 'medium' : 'high',
          });
        }
        // A marketplace in a folder of the repository the scan skips (node_modules/, vendor/, ...),
        // or outside the repository, is never read: its plugins' hooks and servers are unknown.
        const settingsData = parseJsonc(text);
        const known =
          isRecord(settingsData) && isRecord(settingsData['extraKnownMarketplaces'])
            ? settingsData['extraKnownMarketplaces']
            : {};
        for (const [market, entry] of Object.entries(known)) {
          const from = isRecord(entry) && isRecord(entry['source']) ? entry['source'] : undefined;
          const where =
            from && /^(directory|file|local)$/.test(String(from['source'])) ? asString(from['path']) : undefined;
          if (where === undefined) continue;
          const parts = where.split(/[\\/]/).filter(part => part !== '' && part !== '.');
          const outside = /^([\\/]|~|[A-Za-z]:)/.test(where) || parts.includes('..');
          if (outside || parts.some(part => SKIPPED_DIRECTORIES.has(part)))
            unrecognized.push({
              agent: `Marketplace ${market}`,
              setting: 'source.path',
              value: where,
              assumed: outside
                ? 'it is outside the repository, so its plugins’ hooks and servers may do anything'
                : 'it is in a folder the scan skips, so its plugins’ hooks and servers may do anything',
              location: { file: path, line: lineOf(text, JSON.stringify(where)) || 1 },
              severity: 'high',
            });
        }
      } else if (parent === '.codex' && name === 'config.toml') others.push(parseCodex(path, text, declaredServers));
      else if (parent === '.gemini' && name === 'settings.json') others.push(parseGemini(path, text, declaredServers));
      else if (parent === '.claude-plugin' && name === 'marketplace.json') {
        pluginSources.push(...parseMarketplace(path, text));
        // A plugin the marketplace keeps in a folder the scan skips (vendor/, dist/, build/, ...)
        // is never read: its hooks and servers are unknown, reported at high.
        const data = parseJsonc(text);
        const plugins = isRecord(data) && Array.isArray(data['plugins']) ? data['plugins'] : [];
        const base = path.split('/').slice(0, -2);
        for (const plugin of plugins) {
          const where = isRecord(plugin) ? plugin['source'] : undefined;
          if (typeof where !== 'string') continue;
          const parts = [...base, ...where.split('/')].filter(part => part !== '' && part !== '.');
          if (parts.some(part => SKIPPED_DIRECTORIES.has(part)))
            unrecognized.push({
              agent: `Plugin ${isRecord(plugin) ? (asString(plugin['name']) ?? where) : where}`,
              setting: 'source',
              value: where,
              assumed: 'it is in a folder the scan skips, so its hooks and servers may do anything',
              location: { file: path, line: lineOf(text, JSON.stringify(where)) || 1 },
              severity: 'high',
            });
        }
      } else if (name === '.mcp.json') servers.push(...parseMcpConfig(path, text, 'claude-code', declaredServers));
      else if (path.endsWith('.vscode/mcp.json') && (ideFiles.vscode ??= path))
        servers.push(...parseMcpConfig(path, text, 'vscode', declaredServers));
      else if (path.endsWith('.cursor/mcp.json') && (ideFiles.cursor ??= path))
        servers.push(...parseMcpConfig(path, text, 'cursor', declaredServers));
      else if (path.startsWith('.github/workflows/') && /\.ya?ml$/.test(name)) {
        // A gh-aw lock file (a `.lock.yml` with the gh-aw header and a gh-aw `.md` beside it) is
        // judged from its source; any other file is a workflow, whatever its first line says. A
        // compiled lock is judged from its source, except agent actions gh-aw never generates:
        // a lock that uses claude-code-action, codex-action or run-gemini-cli was edited by hand.
        const compiled = compiledFromSource(path, text);
        if (compiled) compiledLocks.push({ lock: path, lockText: text, sourceText: sourceOf(path) ?? '' });
        const steps = parseWorkflow(path, text, declaredServers, named => {
          const relative = safeRelative(named);
          return relative === undefined ? undefined : source.readNamed(relative);
        });
        workflows.push(...(compiled ? steps.filter(step => step.uses !== undefined) : steps));
      } else if (name === 'CODEOWNERS') codeowners ??= { path, text };
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
          // `tools: "*"` (or a list with `*`) is every tool, as if no list were given.
          const listed = data['tools'] === undefined ? undefined : toolNames(data['tools']);
          const tools = listed?.some(tool => tool.trim() === '*') ? undefined : listed;
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
            disallowedTools: data['disallowedTools'] === undefined ? [] : toolNames(data['disallowedTools']),
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
  // Skills and commands can list `allowed-tools`: while one is active those tools run without
  // asking, so they count as allow rules for the project they belong to.
  const skillAllow = new Map<string, PermissionRule[]>();
  // Skills, commands and subagents can carry `hooks:` in their front matter: they run while the
  // skill or subagent is active, and are judged as hooks. Plugin skills and commands count for the
  // project at the root, where the plugin is installed.
  for (const prompt of prompts) {
    const own = /(^|\/)\.claude\/(skills|commands|agents)\//.test(prompt.path);
    const inPlugin =
      !own &&
      [...roots].some(
        root =>
          (!root || prompt.path.startsWith(`${root}/`)) &&
          /^(skills\/[^/]+\/SKILL\.md|commands\/[^/]+\.md|agents\/[^/]+\.md)$/.test(
            root ? prompt.path.slice(root.length + 1) : prompt.path,
          ),
      );
    if (!own && !inPlugin) continue;
    const parsed = frontmatter(prompt.text);
    const data = parsed.error ? (lenientFrontmatter(prompt.text) ?? {}) : parsed.data;
    const lineOfKey = (key: string) => prompt.text.split('\n').findIndex(item => item.startsWith(`${key}:`)) + 1 || 1;
    if (isRecord(data['hooks']))
      pluginHooks.push(
        ...parseSettings(prompt.path, JSON.stringify({ hooks: data['hooks'] })).hooks.map(hook => ({
          ...hook,
          location: { file: prompt.path, line: lineOfKey('hooks') },
        })),
      );
    const tools = data['allowed-tools'];
    if (tools === undefined || /(^|\/)agents\/[^/]+\.md$/.test(prompt.path)) continue;
    const line = lineOfKey('allowed-tools');
    const rules = toolNames(tools).map(raw => parseRule(raw, { file: prompt.path, line }));
    // A plugin's skill grants its tools to whoever installs the plugin: kept under the plugin's own
    // folder, not given to the project that only ships it (unless the repository is the plugin).
    const dir = own
      ? projectDir(prompt.path)
      : ([...roots]
          .filter(root => !root || prompt.path.startsWith(`${root}/`))
          .sort((a, b) => b.length - a.length)[0] ?? '');
    skillAllow.set(dir, [...(skillAllow.get(dir) ?? []), ...rules]);
  }
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
      ...skillAllow.keys(),
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
    const allow = [...[...local, ...userLevel].flatMap(file => file.allow), ...(skillAllow.get(dir) ?? [])];
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
    // Variables that run code with every shell command: a startup file, a command prefix, a
    // search path that puts another program first, a loader.
    for (const file of local)
      for (const entry of file.env)
        if (SHELL_LOADER.test(entry.name))
          unrecognized.push({
            agent: name,
            setting: `env.${entry.name}`,
            value: entry.value,
            assumed: 'it runs its own code with every command the agent runs, without asking',
            location: entry.location,
            severity: 'high',
          });
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
            // In the repository's own settings it sends every developer's key and context there.
            ...(local.includes(file) ? { severity: endpointSeverity(entry.name, entry.value) } : {}),
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
      ...mediatorsFor([...local, ...userLevel], localServers, judgeOf),
      ...(mode === 'auto' ? [{ kind: 'auto-mode' as const, location: modeSetting!.location }] : []),
    ];
    const main: Agent = {
      id: `claude-code:${dir || '.'}`,
      kind: 'claude-code',
      name,
      location: anchor,
      grants: approvedByHooks(
        editThenRun(inSandbox(withoutDenied(grants, deny))),
        [
          ...activeHooks([...local, ...userLevel]),
          ...(local.concat(userLevel).some(file => file.disableAllHooks)
            ? []
            : pluginHooks.filter(hook => projectDir(hook.location.file) === dir)),
        ].filter(hook => DECIDING_EVENTS.has(hook.event) && judgeOf(hook).approves !== 'no'),
        judgeOf,
      ),
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

  // A reusable workflow runs on its callers' events: give it their triggers.
  const calls = new Map(
    inputs
      .filter(input => input.text !== undefined && /^\.github\/workflows\/[^/]+\.ya?ml$/.test(input.path))
      .map(input => [input.path, workflowCalls(input.text!)] as const),
  );
  // Once per reusable workflow, not once per step: callers of callers are walked a single time.
  const inheritedCache = new Map<string, string[]>();
  const inherited = (path: string) => {
    if (!inheritedCache.has(path)) inheritedCache.set(path, inheritedTriggers(path, calls));
    return inheritedCache.get(path)!;
  };
  for (const [index, step] of workflows.entries())
    if (step.triggers.includes('workflow_call'))
      workflows[index] = {
        ...step,
        triggers: [...new Set([...step.triggers, ...inherited(step.path)])],
      };

  const stepNames = new Map<string, number>();
  for (const step of workflows) {
    const key = `${step.path}\0${step.job}\0${step.step}`;
    stepNames.set(key, (stepNames.get(key) ?? 0) + 1);
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
          certainty: trigger === UNKNOWN_CALLER ? 'unknown' : 'yes',
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
        // The workflow's own file sends the repository's key and the agent's context there.
        severity: endpointSeverity(endpoint.name, endpoint.value),
      });
    if (step.settingsUnreadable) {
      const { value, location } = step.settingsUnreadable;
      unrecognized.push({
        agent: `Workflow ${step.path.split('/').at(-1)} › ${step.job}`,
        setting: 'settings',
        value,
        assumed: 'they could not be read, so the step may run any tool without asking',
        location,
        // Settings outside the repository (written at run time, or an expression) can grant anything.
        severity: 'high',
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
    else if (step.action === 'copilot-cli' || step.action === 'gemini-cli' || step.action === 'other-cli') {
      // Their tool settings are not read: what they may run, write and reach is unknown.
      for (const capability of ['exec', 'write', 'egress'] as const)
        add({
          capability,
          via: `${step.action === 'copilot-cli' ? 'Copilot CLI' : step.action === 'gemini-cli' ? 'Gemini CLI' : 'Agent'} (tools not read)`,
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
      // Two steps with one name are two agents: the step's position tells them apart.
      id: `workflow:${step.path}#${step.job}/${step.step}${
        (stepNames.get(`${step.path}\0${step.job}\0${step.step}`) ?? 0) > 1 ? `#${step.stepIndex}` : ''
      }`,
      kind: 'workflow',
      name: `Workflow ${step.path.split('/').at(-1)} › ${step.job}`,
      location: at,
      grants: withoutDenied(grants, deny),
      mediators: [
        ...(step.action.startsWith('claude') ? mediatorsFor(rootSettings, [], judgeOf) : []),
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
      mediators: mediatorsFor([], list, judgeOf),
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
  // A lock with triggers or agent flags its source does not explain was edited by hand: unknown
  // reach too. One whose source hash differs is out of date (or edited): reported.
  const inputPaths = new Set(inputs.map(input => input.path));
  const readRepo = readRepoFile;
  for (const { path, text } of inputs) {
    if (text === undefined || !/^\.github\/workflows\/[^/]+\.lock\.ya?ml$/.test(path) || !isAgenticLock(text)) continue;
    if (!compiledFromSource(path, text)) {
      others.push(parseAgenticLockAlone(path, text));
      continue;
    }
    const mdPath = path.replace(/\.lock\.ya?ml$/, '.md');
    const md = sourceOf(path)!;
    const mismatches = lockMismatches(text, frontmatter(md).data, sourceAsks(mdPath, md, readRepo));
    if (mismatches.length) others.push(parseAgenticLockAlone(path, text, mismatches.join('; ')));
    const meta = lockMetadata(text);
    const recorded = meta?.['frontmatter_hash'];
    if (meta?.['schema_version'] === 'v4' && typeof recorded === 'string') {
      const actual = agenticFrontmatterHash(mdPath, md, readRepo);
      if (actual !== undefined && actual !== recorded)
        unrecognized.push({
          agent: `Agentic workflow ${mdPath.split('/').at(-1)}`,
          setting: 'frontmatter_hash',
          value: path,
          assumed:
            'the lock was not compiled from this source (it is out of date or was edited), so what runs may differ from what was judged',
          location: { file: path, line: 1 },
          severity: 'medium',
        });
    }
  }

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
    bypasses: [...editorBypasses, ...others.flatMap(other => other.bypasses)],
    models,
    pluginSources,
    unrecognized: [...unrecognized, ...others.flatMap(other => other.unrecognized)],
    pluginHooks,
    hookJudgements: [...settings.flatMap(file => file.hooks), ...pluginHooks, ...cursorHooks].map(hook => ({
      hook,
      judgement: judgeOf(hook),
    })),
    skippedFiles: (source.skippedFiles ?? []).filter(path => isConfigPath(path, inputs)),
    linkedFiles: (source.linkedFiles ?? []).filter(path => isConfigPath(path, inputs)),
    skippedConfig: source.skippedConfig ?? [],
    truncated: source.truncated ?? false,
    unparsed: [...unparsed, ...others.flatMap(other => other.unparsed ?? [])],
    compiledLocks,
    skillAllow: [...skillAllow.values()].flat(),
    caseVariants: [...(source.caseVariants ?? [])],
    caseCollisions: [...(source.caseCollisions ?? [])],
  };
}
