import type { Approval, Capability, Grant, Location } from './types.js';
import type { McpServer } from './mcp.js';
import { asString, isRecord, lineOf, parseJsonc } from './text.js';

/** A Claude Code permission rule such as `Bash(npm test:*)` or `mcp__github__create_issue`. */
export interface PermissionRule {
  readonly raw: string;
  readonly tool: string;
  readonly specifier?: string;
  /** For MCP rules: the server name, and the tool name when the rule names one. */
  readonly server?: string;
  readonly mcpTool?: string;
  readonly location: Location;
}

export interface Hook {
  readonly event: string;
  readonly matcher: string;
  readonly command: string;
  readonly location: Location;
}

export interface ClaudeSettings {
  readonly path: string;
  readonly allow: readonly PermissionRule[];
  readonly deny: readonly PermissionRule[];
  readonly ask: readonly PermissionRule[];
  readonly defaultMode?: { readonly value: string; readonly location: Location };
  readonly additionalDirectories: readonly { readonly value: string; readonly location: Location }[];
  readonly hooks: readonly Hook[];
  readonly env: readonly { readonly name: string; readonly value: string; readonly location: Location }[];
  readonly enableAllProjectMcpServers: boolean;
  /** Where `sandbox.enabled: true` is set: Bash runs in a sandbox the scanner does not model. */
  readonly sandbox?: Location;
  /** `autoAllowBashIfSandboxed` (Claude Code defaults it to true). */
  readonly autoAllowSandboxedBash: boolean;
  /** `disableAllHooks: true`: no hook from any settings file runs. */
  readonly disableAllHooks: boolean;
  /** `allowManagedHooksOnly: true` (managed settings): only managed hooks run. */
  readonly allowManagedHooksOnly: boolean;
}

export function parseRule(raw: string, location: Location): PermissionRule {
  const trimmed = raw.trim();
  if (trimmed.startsWith('mcp__')) {
    const [, server = '', ...rest] = trimmed.split('__');
    const tool = rest.join('__');
    return {
      raw: trimmed,
      tool: 'mcp',
      server,
      ...(tool && tool !== '*' ? { mcpTool: tool } : {}),
      location,
    };
  }
  const match = /^([A-Za-z*][\w*]*)\s*(?:\((.*)\))?$/s.exec(trimmed);
  if (!match) return { raw: trimmed, tool: trimmed, location };
  const specifier = match[2]?.trim();
  return { raw: trimmed, tool: match[1]!, ...(specifier ? { specifier } : {}), location };
}

function rules(value: unknown, path: string, text: string): PermissionRule[] {
  if (!Array.isArray(value)) return [];
  const out: PermissionRule[] = [];
  let from = 0;
  for (const item of value) {
    if (typeof item !== 'string') continue;
    const needle = JSON.stringify(item);
    const index = text.indexOf(needle, from);
    if (index >= 0) from = index + needle.length;
    out.push(parseRule(item, { file: path, line: index >= 0 ? lineOf(text, needle, index) : 1 }));
  }
  return out;
}

/** Reads `.claude/settings.json` or `settings.local.json`. Throws on invalid JSON. */
export function parseSettings(path: string, text: string): ClaudeSettings {
  const parsed = parseJsonc(text);
  const data = isRecord(parsed) ? parsed : {};
  const permissions = isRecord(data['permissions']) ? data['permissions'] : {};
  const at = (needle: string): Location => ({ file: path, line: lineOf(text, needle) });
  const mode = asString(permissions['defaultMode']);
  const hooks: Hook[] = [];
  if (isRecord(data['hooks'])) {
    let from = 0;
    for (const [event, groups] of Object.entries(data['hooks'])) {
      if (!Array.isArray(groups)) continue;
      for (const group of groups) {
        if (!isRecord(group) || !Array.isArray(group['hooks'])) continue;
        const matcher = asString(group['matcher']) ?? '';
        for (const hook of group['hooks']) {
          const command = isRecord(hook) ? asString(hook['command']) : undefined;
          if (!command) continue;
          const needle = JSON.stringify(command);
          const index = text.indexOf(needle, from);
          if (index >= 0) from = index + needle.length;
          hooks.push({
            event,
            matcher,
            command,
            location: { file: path, line: index >= 0 ? lineOf(text, needle, index) : 1 },
          });
        }
      }
    }
  }
  const env = isRecord(data['env'])
    ? Object.entries(data['env'])
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
        .map(([name, value]) => ({ name, value, location: at(JSON.stringify(name)) }))
    : [];
  const directories = Array.isArray(permissions['additionalDirectories'])
    ? permissions['additionalDirectories']
        .filter((item): item is string => typeof item === 'string')
        .map(value => ({ value, location: at(JSON.stringify(value)) }))
    : [];
  return {
    path,
    allow: rules(permissions['allow'], path, text),
    deny: rules(permissions['deny'], path, text),
    ask: rules(permissions['ask'], path, text),
    ...(mode ? { defaultMode: { value: mode, location: at('"defaultMode"') } } : {}),
    additionalDirectories: directories,
    hooks,
    env,
    enableAllProjectMcpServers: data['enableAllProjectMcpServers'] === true,
    ...(isRecord(data['sandbox']) && data['sandbox']['enabled'] === true ? { sandbox: at('"sandbox"') } : {}),
    autoAllowSandboxedBash: !(isRecord(data['sandbox']) && data['sandbox']['autoAllowBashIfSandboxed'] === false),
    disableAllHooks: data['disableAllHooks'] === true,
    allowManagedHooksOnly: data['allowManagedHooksOnly'] === true,
  };
}

/** Commands that read local files only. */
const LOCAL_COMMANDS =
  /^(git (status|diff|log|show|branch|rev-parse|ls-files|blame|remote|checkout|switch|add|commit|stash|restore|merge|rebase|tag)|ls|cat|head|tail|wc|grep|rg|echo|pwd|which|tree|sort|uniq|diff|jq|date|kill|pkill|xargs kill|lsof|ps|cd|pushd|popd|file|stat|du|df|basename|dirname|realpath|readlink|git grep|git worktree|git config --get|true|test|\[)\b/;
/** Commands that change local files, including the agent's own settings, without running code. */
const EDIT_COMMANDS = /^(mkdir|touch|cp|mv|chmod|ln|rm|rmdir|tee|truncate)\b/;
/** Commands that bring in text from a remote repository: untrusted input, not egress. */
const FETCH_COMMANDS = /^git (fetch|pull|clone|submodule update)\b/;
// find -exec, awk system(), GNU sed's e command and xargs run arbitrary commands: they are not
// listed above, so they fall through to 'other' (runs code, may send data out).
/** The project's own test, lint, build and install commands: they run project code, nothing chosen by the agent. */
const PROJECT_COMMANDS =
  /^((npm|pnpm|yarn|bun) (test|install|ci|i|add|run|typecheck|lint|format|fmt|build|check|exec (tsc|eslint|prettier|vitest|jest))|(npx|bunx|pnpm exec) (tsc|eslint|prettier|vitest|jest|playwright test|biome|turbo|nx)|tsc|eslint|prettier|biome|vitest|jest|pytest|python3? -m (pytest|ruff|mypy|black|isort|flake8|pylint|unittest|pip install -r)|uv (run (pytest|ruff|mypy|python -m pytest)|sync|lock)|poetry (install|run (pytest|ruff|mypy))|ruff|mypy|black|go (test|build|vet|mod)|cargo (test|check|build|clippy|fmt|run)|make|just|gradlew? (test|build|check)|mvn (test|verify|package)|dotnet (test|build)|swift (test|build))\b/;
/** Commands that read from the network (issue and pull-request text) without sending anything. */
const READ_COMMANDS =
  /^gh (pr|issue|run|repo|release|search|workflow) (view|list|diff|checks|status|logs|watch|checkout)\b|^gh search\b|^gh api (-X GET |--method GET )?repos\/\S*\/(contents|commits|compare)\b/;
/** Commands that publish to the repository itself: comments, reviews, labels, pushes. */
const PUBLISH_COMMANDS =
  /^(gh (pr|issue) (comment|review|create|edit|close|reopen|merge|ready|lock|develop)\b|gh label\b|gh api (-X \w+ |--method \w+ )?repos\/|git push\b)/;
/** Commands that can reach any host, publish, or run arbitrary code. */
const NETWORK_COMMANDS =
  /^(curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|telnet|gh|git push|npm publish|pnpm publish|yarn publish|docker (push|login|run)|aws|gcloud|gsutil|az|kubectl|helm|terraform|python3?|node|deno|bun|ruby|perl|php|bash|sh|zsh|pwsh|powershell|npx|bunx|uvx|pipx|pip3? install|eval|env)\b/;

export type BashScope = 'any' | 'network' | 'publish' | 'read' | 'fetch' | 'edit' | 'local' | 'project' | 'other';

/** How much a `Bash(...)` rule lets the agent do. Narrower scopes are checked first. */
export function bashScope(specifier: string | undefined): BashScope {
  if (specifier === undefined) return 'any';
  const command = specifier
    .replace(/:\*$/, '')
    .replace(/\s*\*$/, '')
    .trim();
  if (command === '' || command === '*') return 'any';
  if (READ_COMMANDS.test(command)) return 'read';
  if (PUBLISH_COMMANDS.test(command)) return 'publish';
  if (PROJECT_COMMANDS.test(command)) return 'project';
  if (FETCH_COMMANDS.test(command)) return 'fetch';
  if (EDIT_COMMANDS.test(command)) return 'edit';
  if (LOCAL_COMMANDS.test(command)) return 'local';
  if (NETWORK_COMMANDS.test(command)) return 'network';
  return 'other';
}

/** Paths an agent reads its own instructions or permissions from. */
export const IDENTITY_PATH = /(^|[/*])(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)$|\.claude(\/|$|\*)/;

function isOutsideProject(specifier: string | undefined): boolean {
  if (!specifier) return false;
  return /^(~|\/\/|\$HOME|\/(etc|home|Users|root|var)\b)/.test(specifier.trim());
}

const READ_ONLY_TOOL = /^(get|list|search|read|query|describe|find|fetch_|view|show|lookup|resolve|count)/i;

/** The grants one tool reference gives an agent. `servers` resolves MCP rules to their catalog entries. */
export function grantsForRule(rule: PermissionRule, approval: Approval, servers: readonly McpServer[]): Grant[] {
  const location = rule.location;
  const make = (capability: Capability, certainty: 'yes' | 'unknown', tool: string): Grant => ({
    capability,
    via: rule.raw,
    tool,
    approval,
    certainty,
    location,
  });
  switch (rule.tool) {
    case '*':
      return (['exec', 'egress', 'write', 'untrustedInput'] as const).map(c => make(c, 'yes', '*'));
    case 'Bash': {
      const scope = bashScope(rule.specifier);
      if (scope === 'any' || scope === 'network')
        return [make('exec', 'yes', 'Bash'), make('egress', 'yes', 'Bash'), make('write', 'yes', 'Bash')];
      if (scope === 'publish') return [make('egress', 'yes', 'Bash'), make('write', 'yes', 'Bash')];
      if (scope === 'project') return [make('exec', 'yes', 'Bash')];
      if (scope === 'read' || scope === 'fetch') return [make('untrustedInput', 'yes', 'Bash')];
      if (scope === 'edit') return [make('write', 'yes', 'Bash')];
      if (scope === 'local') return [];
      return [make('exec', 'yes', 'Bash'), make('egress', 'unknown', 'Bash')];
    }
    case 'Read':
    case 'Glob':
    case 'Grep':
    case 'LS':
      return isOutsideProject(rule.specifier) ? [make('privateData', 'yes', rule.tool)] : [];
    case 'Edit':
    case 'Write':
    case 'MultiEdit':
    case 'NotebookEdit': {
      const out = [make('write', 'yes', rule.tool)];
      if (rule.specifier && IDENTITY_PATH.test(rule.specifier.replace(/\/\*\*$/, '/')))
        out.push(make('selfModify', 'yes', rule.tool));
      return out;
    }
    case 'WebFetch':
      return rule.specifier?.startsWith('domain:')
        ? [make('untrustedInput', 'yes', 'WebFetch')]
        : [make('untrustedInput', 'yes', 'WebFetch'), make('egress', 'yes', 'WebFetch')];
    case 'WebSearch':
      return [make('untrustedInput', 'yes', 'WebSearch')];
    case 'mcp': {
      const server = servers.find(item => item.name === rule.server);
      const tool = `mcp__${rule.server ?? ''}`;
      if (!server?.catalog) {
        return (['privateData', 'untrustedInput', 'egress'] as const).map(c => make(c, 'unknown', tool));
      }
      const readOnly = rule.mcpTool !== undefined && READ_ONLY_TOOL.test(rule.mcpTool);
      const out: Grant[] = [];
      for (const [capability, certainty] of Object.entries(server.catalog.capabilities) as [
        Capability,
        'yes' | 'unknown',
      ][]) {
        if (readOnly && (capability === 'egress' || capability === 'write' || capability === 'spend')) continue;
        out.push(make(capability, certainty, tool));
      }
      return out;
    }
    default:
      return [];
  }
}

/** True when a deny rule removes a whole tool (not just some uses of it). */
export function deniesWholeTool(deny: readonly PermissionRule[], tool: string, server?: string): boolean {
  return deny.some(rule => {
    if (rule.tool === 'mcp') return tool === 'mcp' && rule.server === server && rule.mcpTool === undefined;
    return rule.tool === tool && (rule.specifier === undefined || rule.specifier === '*' || rule.specifier === ':*');
  });
}

/** Whether a deny list covers a command prefix, e.g. `curl`. */
export function deniesCommand(deny: readonly PermissionRule[], command: string): boolean {
  return deny.some(rule => rule.tool === 'Bash' && (rule.specifier ?? '').replace(/[:*\s]+$/, '').startsWith(command));
}

/** Whether a deny list blocks reading a path pattern such as `.env`. */
export function deniesRead(deny: readonly PermissionRule[], fragment: string): boolean {
  return deny.some(rule => (rule.tool === 'Read' || rule.tool === 'Edit') && (rule.specifier ?? '').includes(fragment));
}
