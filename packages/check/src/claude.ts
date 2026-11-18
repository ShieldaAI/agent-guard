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
  /** The shell command; empty for a hook that is not a command (`http`, `prompt`, `agent`). */
  readonly command: string;
  /** `command`, `http` (posts the event to `url`), `prompt` or `agent` (a model decides), or another type. */
  readonly type: string;
  readonly url?: string;
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
          if (!isRecord(hook)) continue;
          // Every hook type is kept: one that is not a command (an HTTP call, a model's decision) is
          // judged as unknown, never dropped.
          const type = asString(hook['type']) ?? 'command';
          const command = asString(hook['command']) ?? '';
          const url = asString(hook['url']);
          if (!command && type === 'command') continue;
          const needle = JSON.stringify(command || url || type);
          const index = text.indexOf(needle, from);
          if (index >= 0) from = index + needle.length;
          hooks.push({
            event,
            matcher,
            command,
            type,
            ...(url ? { url } : {}),
            location: { file: path, line: index >= 0 ? lineOf(text, needle, index) : 1 },
          });
        }
      }
    }
  }
  // Commands Claude Code runs on its own, outside the hook events: judged by the same rules.
  for (const key of [
    'apiKeyHelper',
    'otelHeadersHelper',
    'awsAuthRefresh',
    'awsCredentialExport',
    'statusLine',
    'fileSuggestion',
  ]) {
    const value = data[key];
    const command = isRecord(value) ? asString(value['command']) : asString(value);
    if (command) hooks.push({ event: key, matcher: '', command, type: 'command', location: at(`"${key}"`) });
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

/**
 * Commands that read local files only, whatever arguments follow. Matched as whole words: a rule
 * for `git status` is not a rule for `git statusx`.
 */
const LOCAL_COMMANDS =
  /^(git (status|diff|log|show|branch|rev-parse|ls-files|blame|remote|checkout|switch|add|commit|stash|restore|tag|worktree list|config --get|describe|shortlog|reflog|cat-file|ls-tree|merge-base|check-ignore)|ls|cat|head|tail|wc|grep|egrep|fgrep|echo|printf|pwd|which|type|tree|uniq|diff|cmp|jq|yq|date|cd|pushd|popd|file|stat|du|df|basename|dirname|realpath|readlink|true|false|test|\[|ps|lsof|kill|pkill|killall|whoami|uname|hostname|id|nproc|sleep|cut|tr|column|nl|less|more|od|xxd|hexdump|md5sum|shasum|sha256sum|cksum|comm|paste|fold|rev|tac|seq|expr|bc)(?=\s|$)/;
/**
 * Commands that read local files only when the arguments are fixed: with a wildcard after them,
 * an option runs a program (`rg --pre`, `sort --compress-program`, `git grep -O`, `find -exec`,
 * `git rebase --exec`, `git -c alias...`).
 */
const LOCAL_FIXED_ARGS =
  /^(rg|sort|find|fd|git grep|git rebase|git merge|git cherry-pick|git bisect|git worktree|git submodule|git|awk|sed|tar|unzip|zip|make -n)(?=\s|$)/;
/** Commands that change local files, including the agent's own settings, without running code. */
const EDIT_COMMANDS =
  /^(mkdir|mktemp|touch|cp|mv|chmod|ln|rm|rmdir|tee|truncate|git reset|git rm|git mv|git clean|git restore)(?=\s|$)/;
/** Commands that bring in text from a remote repository: untrusted input, not egress. */
const FETCH_COMMANDS = /^git (fetch|pull|clone|submodule update)(?=\s|$)/;
/**
 * The project's own test, lint, build and install commands: they run project code, nothing chosen
 * by the agent. Matched as whole words, so `npx tsc-evil-pkg` is not `npx tsc`.
 */
const PROJECT_COMMANDS =
  /^((npm|pnpm|yarn|bun) (test|ci|run|typecheck|lint|format|fmt|build|check|exec (tsc|eslint|prettier|vitest|jest))|(npm|pnpm|yarn|bun) (install|i|add)|(npx|bunx|pnpx|pnpm exec) (tsc|eslint|prettier|vitest|jest|playwright test|biome|turbo|nx|oxlint|knip|stylelint)|tsc|eslint|prettier|biome|oxlint|knip|stylelint|vitest|jest|pytest|python3? -m (pytest|ruff|mypy|black|isort|flake8|pylint|unittest)|uv (run (pytest|ruff|mypy|pyright|basedpyright|ty|pre-commit|tox|nox|coverage|black|isort|flake8|pylint|python -m pytest)|sync|lock)|pre-commit run|pyright|basedpyright|tox|nox|poetry (install|run (pytest|ruff|mypy))|ruff|mypy|black|go (test|build|vet|mod tidy)|cargo (test|check|build|clippy|fmt|run|nextest run)|make|just|gradlew? (test|build|check)|\.\/gradlew (test|build|check)|mvn (test|verify|package)|dotnet (test|build)|swift (test|build))(?=\s|$)/;
/**
 * Project commands whose arguments choose what is installed or run: as a prefix rule they fetch
 * and run any package (`npm install evil`), so they are judged as network commands.
 */
const PROJECT_FIXED_ARGS = /^((npm|pnpm|yarn|bun) (install|i|add)|poetry install|uv sync)(?=\s|$)/;
/**
 * An interpreter running one named script file (`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/x.py"`), or
 * a script run by its path (`./scripts/check.sh`): code in the repository or plugin, like a
 * project command. `-c`, `-e`, `-` or an absolute path would not be.
 */
const SCRIPT_COMMAND =
  /^((python3?|node|bash|sh|zsh|ruby|perl|deno run|bun run|uv run( python3?)?|tsx) +("[^"\s;&|`$]*[^"\s]*\.(py|js|mjs|cjs|ts|sh|rb|pl)"|[^\s"'\-/][^\s;&|`]*\.(py|js|mjs|cjs|ts|sh|rb|pl))|\.\/[^\s;&|`$]+|[\w.-]+\/[\w./-]+\.(sh|bat|cmd|ps1|py|js|mjs|ts))(?=\s|$)/;
/** Commands that read from the network (issue and pull-request text) without sending anything. */
const READ_COMMANDS =
  /^gh (pr|issue|run|repo|release|search|workflow) (view|list|diff|checks|status|logs|watch|checkout)(?=\s|$)|^gh search(?=\s|$)|^gh api (-X GET |--method GET )?repos\/\S*\/(contents|commits|compare)\b/;
/** Commands that publish to the repository itself: comments, reviews, labels, pushes. */
const PUBLISH_COMMANDS =
  /^(gh (pr|issue) (comment|review|create|edit|close|reopen|merge|ready|lock|develop)(?=\s|$)|gh label(?=\s|$)|gh api (-X \w+ |--method \w+ )?repos\/|git push(?=\s|$))/;
/** Commands that run whatever follows them: a rule for one is a rule for every command. */
const WRAPPERS =
  /^(sudo|doas|su|runuser|chroot|timeout|xargs|env|nice|ionice|nohup|time|exec|command|builtin|stdbuf|unbuffer|watch|strace|ltrace|setsid|flock|parallel|script|busybox|toybox|eval|source|\.)(?=\s|$)/;

export type BashScope = 'any' | 'network' | 'publish' | 'read' | 'fetch' | 'edit' | 'local' | 'project' | 'other';

/**
 * How much a `Bash(...)` rule lets the agent do. Fail closed: a rule is narrower than "any network
 * command" only when it matches a known command shape. An unknown command, a wrapper that runs
 * another command (`sudo`, `timeout`, `xargs`), a wildcard inside the command (`c*`, `*url`) and a
 * prefix rule for a command whose options run programs (`git:*`, `find:*`, `rg:*`) can run
 * anything, so they count as running code that may reach the network.
 */
export function bashScope(specifier: string | undefined): BashScope {
  if (specifier === undefined) return 'any';
  const raw = specifier.trim();
  let command = raw
    .replace(/:\*$/, '')
    .replace(/\s*\*$/, '')
    .trim();
  if (command === '' || command === '*') return 'any';
  const prefix = command !== raw;
  // Variable assignments before the command (`GIT_TERMINAL_PROMPT=0 git ...`) are dropped, unless
  // they load code or change what runs.
  while (/^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/.test(command)) {
    if (
      /^(BASH_ENV|ENV|PATH|LD_\w+|DYLD_\w+|NODE_OPTIONS|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_PAGER|PAGER|EDITOR|GIT_EDITOR|GIT_CONFIG_\w+|SHELL)=/.test(
        command,
      )
    )
      return 'network';
    command = command.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/, '');
  }
  // A package script named with a trailing wildcard (`pnpm app:cdp*`) runs one of the project's scripts.
  if (/^(pnpm|yarn|bun|npm run) [a-z][\w:.-]*\*$/.test(command) && !/ (dlx|exec|x|add|install|i|create)/.test(command))
    return 'project';
  // A wildcard left inside the command matches other commands too; one inside a quoted argument
  // (`-name "X-2*"`) is part of that argument.
  if (/[*?]/.test(command.replace(/"[^"]*"|'[^']*'/g, '""'))) return command.startsWith('*') ? 'any' : 'network';
  // `/usr/bin/curl` is curl; a path elsewhere is an unknown program.
  command = command.replace(/^\/(usr\/(local\/)?)?s?bin\/(?=\S)/, '');
  if (/^xargs kill(?=\s|$)/.test(command)) return 'local';
  // pnpm's workspace flags choose where a command runs, not what: `pnpm -w run lint` is `pnpm run lint`.
  command = command.replace(/^pnpm( (-w|-r|--workspace-root|--recursive))+(?=\s)/, 'pnpm');
  // Package managers' read-only commands.
  if (/^(pnpm|npm|yarn|bun) (why|list|ls|outdated|view|info|explain|audit)(?=\s|$)/.test(command)) return 'local';
  if (WRAPPERS.test(command)) return 'network';
  // A path that climbs out of the project (`./../../usr/bin/curl`) is not a project script.
  if (/(^|\/)\.\.(\/|\s|$)/.test(command.split(/\s/)[0] ?? '')) return 'network';
  // `gh api PATH` reads only as written: a prefix rule also allows `-X PUT`, `-f` or `--input`.
  if (READ_COMMANDS.test(command) && !(prefix && /^gh api(?=\s|$)/.test(command))) return 'read';
  if (PUBLISH_COMMANDS.test(command)) return 'publish';
  if (PROJECT_FIXED_ARGS.test(command) && prefix) return 'network';
  // A package script by name (`pnpm fix`, `yarn lint`, `bun run dev`): project code. Arguments
  // after the script name go to the script, so a prefix rule is still that script.
  if (
    /^(pnpm|yarn|bun)( run)? (?!(dlx|exec|x|add|install|i|create|link|global|publish|node|why)(\s|$))[a-z][\w:.-]*$/.test(
      command,
    )
  )
    return 'project';
  if (PROJECT_COMMANDS.test(command) || (SCRIPT_COMMAND.test(command) && !/\$\(|`/.test(command))) return 'project';
  if (FETCH_COMMANDS.test(command)) return 'fetch';
  if (EDIT_COMMANDS.test(command)) return 'edit';
  if (LOCAL_COMMANDS.test(command)) return 'local';
  if (LOCAL_FIXED_ARGS.test(command)) return prefix ? 'network' : 'local';
  return 'network';
}

/** Paths an agent reads its own instructions or permissions from. */
export const IDENTITY_PATH = /(^|[/*])(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)$|\.claude(\/|$|\*)/;

export function isOutsideProject(specifier: string | undefined): boolean {
  if (!specifier) return false;
  const spec = specifier.trim();
  // `~/`, `//abs`, `$HOME`, system folders, and `..` that climbs out of the project.
  return /^(~|\/\/|\$HOME|\/(etc|home|Users|root|var|private|opt|tmp)\b)/.test(spec) || /(^|\/)\.\.(\/|$)/.test(spec);
}

const READ_ONLY_TOOL = /^(get|list|search|read|query|describe|find|fetch_|view|show|lookup|resolve|count)/i;

/** Servers by name, built once per list: a lookup per rule rather than a scan of every server. */
const serverIndex = new WeakMap<readonly McpServer[], Map<string, McpServer>>();
function serverByName(servers: readonly McpServer[]): Map<string, McpServer> {
  let index = serverIndex.get(servers);
  if (!index) {
    index = new Map();
    for (const server of servers) if (!index.has(server.name)) index.set(server.name, server);
    serverIndex.set(servers, index);
  }
  return index;
}

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
      return (['exec', 'egress', 'write', 'untrustedInput', 'selfModify'] as const).map(c => make(c, 'yes', '*'));
    case 'Bash': {
      const scope = bashScope(rule.specifier);
      // A shell that can write any file can rewrite the agent's own settings and instructions.
      if (scope === 'any' || scope === 'network')
        return [
          make('exec', 'yes', 'Bash'),
          make('egress', 'yes', 'Bash'),
          make('write', 'yes', 'Bash'),
          make('selfModify', 'yes', 'Bash'),
        ];
      if (scope === 'publish') return [make('egress', 'yes', 'Bash'), make('write', 'yes', 'Bash')];
      if (scope === 'project') return [make('exec', 'yes', 'Bash')];
      if (scope === 'read' || scope === 'fetch') return [make('untrustedInput', 'yes', 'Bash')];
      if (scope === 'edit') return [make('write', 'yes', 'Bash'), make('selfModify', 'yes', 'Bash')];
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
      // Unrestricted (or every-file) edits reach the agent's own files too.
      // A pattern that starts with a wildcard (`**/*.md`, `/**`, `.*/**`) or climbs out (`src/../**`)
      // can match the agent's own settings or instructions.
      const spec = rule.specifier?.trim();
      const everyFile = !spec || /^(\.\/)?\/{0,2}(\*|\.\*|\.\w*\*)/.test(spec) || spec.includes('..');
      if (everyFile || (rule.specifier && IDENTITY_PATH.test(rule.specifier.replace(/\/\*\*$/, '/'))))
        out.push(make('selfModify', 'yes', rule.tool));
      return out;
    }
    case 'WebFetch': {
      // A request carries data in its URL: a wildcard domain can send it anywhere; one named
      // domain sends it to that host only.
      const domain = rule.specifier?.startsWith('domain:') ? rule.specifier.slice(7).trim() : undefined;
      return domain !== undefined && domain && !domain.includes('*')
        ? [make('untrustedInput', 'yes', 'WebFetch')]
        : [make('untrustedInput', 'yes', 'WebFetch'), make('egress', 'yes', 'WebFetch')];
    }
    case 'PowerShell':
    case 'Monitor':
      // Both run shell commands; their command patterns are judged as Bash's are.
      return grantsForRule({ ...rule, tool: 'Bash' }, approval, servers).map(grant => ({ ...grant, tool: rule.tool }));
    case 'WebSearch':
      return [make('untrustedInput', 'yes', 'WebSearch')];
    case 'mcp': {
      const server = serverByName(servers).get(rule.server ?? '');
      const tool = `mcp__${rule.server ?? ''}`;
      // A server the scanner cannot identify may be anything, including code from the repository.
      if (!server?.catalog) {
        return (['privateData', 'untrustedInput', 'egress', 'write', 'exec'] as const).map(c =>
          make(c, 'unknown', tool),
        );
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
      // Tools that only plan, ask, track or read what the agent already has run nothing. Any
      // other tool name is one the scanner does not know: it may do anything (fail closed).
      if (HARMLESS_TOOLS.has(rule.tool)) return [];
      return (['exec', 'egress', 'write'] as const).map(c => make(c, 'unknown', rule.tool));
  }
}

/** Built-in tools that run nothing and reach nothing beyond what other rules already grant. */
export const HARMLESS_TOOLS = new Set([
  'Task',
  'Agent',
  'TodoWrite',
  'TodoRead',
  'ExitPlanMode',
  'EnterPlanMode',
  'NotebookRead',
  'BashOutput',
  'KillShell',
  'KillBash',
  'AskUserQuestion',
  'ListMcpResourcesTool',
  'ReadMcpResourceTool',
  'SlashCommand',
  'Skill',
  'TaskOutput',
  'TaskStop',
  'ToolSearch',
  'Workflow',
]);

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
