import { bashScope, type Hook } from './claude.js';
import { commands, localImports, unwrap } from './shell.js';
import { PIPE_TO_SHELL } from './rules/common.js';

/**
 * What a hook does when it runs. Hooks run without asking, on every matching event, so a hook is
 * judged like a command the agent may run: what its commands can reach, and whether it can approve
 * tool calls on a person's behalf.
 */
export interface HookJudgement {
  /**
   * `local`: reads or edits local files only. `project`: runs a script from the repository or plugin
   * (read and judged too). `network`: can reach the network or run arbitrary code, or is unknown.
   */
  readonly reach: 'local' | 'project' | 'network';
  /**
   * For PreToolUse and PermissionRequest hooks: whether it can answer "allow" for a tool call, so the
   * call runs without a person. `unknown` when its text cannot be read (an HTTP hook, a model's
   * decision, a program outside the repository).
   */
  readonly approves: 'no' | 'yes' | 'unknown';
  /** What the hook runs, for messages: the first command that set its reach. */
  readonly why: string;
}

/** Events whose hook output can decide a tool call. */
export const DECIDING_EVENTS = new Set(['PreToolUse', 'PermissionRequest']);
/** Cursor hook events whose output can allow a shell command or MCP call. */
export const CURSOR_DECIDING_EVENTS = new Set(['beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile']);

/**
 * Text that answers "allow" or "approve": `permissionDecision: "allow"`, `"behavior": "allow"`,
 * `"decision": "approve"` (the older form), in JSON, in a heredoc or in code that builds it.
 */
const APPROVES =
  /permissionDecision["'\s:=\\]*(allow|approve)|["']?(behavior|decision|permission)["']?\s*[:=]\s*\\?["'](allow|approve)/i;
/** A decision key: the hook output fields that answer for a tool call. */
const DECISION_KEY = /["'`]?(permissionDecision|decision|behavior|permission)["'`]?\s*[:=]\s*/gi;

/**
 * Whether text may answer "allow" in a way the scan cannot read: a decision key whose value is not
 * a literal deny, ask or block, or `allow` / `approve` written as a value (`D=allow`, `"allow"`, a
 * `printf` argument). Words such as "allowed" or "allowlist" in prose are not counted.
 */
/** Output built so the text does not show it: decoding, reversing, character codes, escapes. */
const OBFUSCATED = /\b(b64decode|base64|atob|fromCharCode|codecs\.decode|fromhex|unhexlify|rev|chr\s*\()/i;

function mayApprove(text: string): boolean {
  // Output a deciding hook builds in a way the scan cannot read may say anything, including allow.
  if (OBFUSCATED.test(text)) return true;
  // A decision key written in pieces (`"permission" + "Decision"`): its value is not readable either.
  if (
    /ecision|hookSpecificOutput/i.test(text) &&
    !/permissionDecision["'\s:=\\]*(deny|ask)|["']decision["']\s*:\s*["']block/i.test(text)
  )
    return true;
  for (const match of text.matchAll(DECISION_KEY)) {
    const value = text.slice(match.index! + match[0].length, match.index! + match[0].length + 40);
    if (!/^\\?["'`]?\s*(deny|ask|block)\b/i.test(value)) return true;
  }
  return /(["'`]\s*|=\s*|\bprintf\b[^\n]*\s)(allow|approve)(?![\w-])/i.test(text);
}

/** Interpreters whose first argument is the script they run. */
const INTERPRETERS = new Set(['python', 'python3', 'node', 'bash', 'sh', 'zsh', 'ruby', 'perl', 'deno', 'bun', 'tsx']);
const RANK = { local: 0, project: 1, network: 2 } as const;

/** A repository path from a hook's command, with `$CLAUDE_PROJECT_DIR` and `${CLAUDE_PLUGIN_ROOT}` resolved. */
function repoPath(word: string, projectDir: string, pluginRoot: string): string | undefined {
  const replaced = word
    .replace(/^\$\{?CLAUDE_PROJECT_DIR\}?/, projectDir || '.')
    .replace(/^\$\{?CLAUDE_PLUGIN_ROOT\}?/, pluginRoot || '.');
  if (replaced.startsWith('/') || replaced.startsWith('~') || replaced.includes('$')) return undefined;
  const parts: string[] = [];
  const base = replaced === word && !word.startsWith('.') && projectDir ? `${projectDir}/` : '';
  for (const part of `${base}${replaced}`.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!parts.length) return undefined;
      parts.pop();
    } else parts.push(part);
  }
  return parts.length ? parts.join('/') : undefined;
}

/**
 * Judges one hook. `readFile` reads a repository file (a script the hook runs); `projectDir` is the
 * folder Claude Code runs in for this hook's settings and `pluginRoot` the plugin's folder.
 */
export function judgeHook(
  hook: Hook,
  readFile: (path: string) => string | undefined,
  projectDir: string,
  pluginRoot: string,
): HookJudgement {
  const deciding = DECIDING_EVENTS.has(hook.event) || CURSOR_DECIDING_EVENTS.has(hook.event);
  if (hook.type !== 'command')
    // An HTTP hook sends the event (the tool's input) to its URL; a prompt or agent hook lets a
    // model decide. Neither can be read here.
    return {
      reach: hook.type === 'http' ? 'network' : 'local',
      approves: deciding ? 'unknown' : 'no',
      why: hook.type === 'http' ? `an HTTP hook to ${hook.url ?? 'a URL'}` : `a ${hook.type} hook`,
    };
  let reach: HookJudgement['reach'] = 'local';
  let why = hook.command;
  let readable = true;
  const texts = [hook.command];
  const visit = (raw: string, depth: number, scriptDir?: string) => {
    // A script's own folder (`$(dirname "$0")`, `${0%/*}`): files it prints are read from there.
    const script =
      scriptDir === undefined
        ? raw
        : raw.replace(
            /\$\(\s*dirname\s+"?\$\{?0\}?"?\s*\)|\$\{0%\/\*\}|\$\{BASH_SOURCE(\[0\])?%\/\*\}/g,
            scriptDir || '.',
          );
    for (const words of commands(script)) {
      const call = unwrap(words);
      if (!call) continue;
      let found: HookJudgement['reach'];
      // A pinned package (`npx prettier@3.5.3`) is the package; a path is kept as written.
      let shown = [call.head.includes('/') ? call.head : call.name, ...call.args.map(arg => arg.text)].join(' ');
      const projectPath = /^\$\{?CLAUDE_(PROJECT_DIR|PLUGIN_ROOT)\}?\//.test(call.head);
      // A script from the repository or the plugin: read it and judge what it runs.
      // An interpreter's script is its first argument that names a file (`python -m tool` runs a module).
      const target = INTERPRETERS.has(call.name)
        ? call.args.some(arg => arg.text === '-m')
          ? undefined
          : call.args.find(arg => !arg.text.startsWith('-') && /[/.]/.test(arg.text))?.text
        : call.head.includes('/') || call.head.startsWith('$CLAUDE') || call.head.startsWith('${CLAUDE')
          ? call.head
          : undefined;
      const inline = INTERPRETERS.has(call.name) && call.args.some(arg => /^-[a-zA-Z]*[ce]$/.test(arg.text));
      const path = target && !inline ? repoPath(target, projectDir, pluginRoot) : undefined;
      const text = path === undefined ? undefined : readFile(path);
      // Files the hook prints or fills in (`cat ok.json`, `jq -f x.jq`, `envsubst < t.json`) are its output.
      if (/^(cat|jq|head|tail|envsubst|tac|less|more)$/.test(call.name))
        for (const arg of call.args) {
          const file =
            /[/.]/.test(arg.text) && !arg.text.startsWith('-') ? repoPath(arg.text, projectDir, pluginRoot) : undefined;
          const content = file === undefined ? undefined : readFile(file);
          if (content !== undefined) texts.push(content);
        }
      if (call.dynamic && !projectPath) {
        found = 'network';
        readable = false;
      } else if (text !== undefined && depth < 2) {
        texts.push(text, ...localImports(path!, text, readFile));
        // A script from the repository is project code, like `npm test`, unless it pipes a download
        // into a shell. A shell script is read for the scripts it runs and for approvals.
        found = PIPE_TO_SHELL.test(text) ? 'network' : 'project';
        shown = path!;
        if (/\.(sh|bash|zsh)$/.test(path!) || /^#!.*\b(ba|z)?sh\b/.test(text)) {
          const before = reach;
          visit(text, depth + 1, path!.split('/').slice(0, -1).join('/'));
          if (reach === 'network' && before !== 'network' && !PIPE_TO_SHELL.test(text)) reach = before;
        }
      } else if (target !== undefined && !inline && path === undefined) {
        // A program outside the repository (`~/bin/x`, `/opt/x`): unknown.
        found = 'network';
        readable = false;
      } else if (target !== undefined && !inline && text === undefined) {
        found = 'network';
        readable = false;
      } else {
        // An exact command, not a rule pattern: a glob in its arguments is not a wildcard command.
        const scope = bashScope(shown.replace(/[*?]/g, '_'));
        found =
          scope === 'local' || scope === 'read' || scope === 'fetch' || scope === 'edit'
            ? 'local'
            : scope === 'project'
              ? 'project'
              : 'network';
      }
      if (RANK[found] > RANK[reach]) {
        reach = found;
        why = shown;
      }
    }
  };
  visit(hook.command, 0);
  // Fail closed: a deciding hook approves for certain when it says "allow" as written, and may
  // approve when it builds a decision the scan cannot read (`"permissionDecision": "al" + "low"`,
  // `D=allow`), or when its text cannot be read at all. Only a hook whose decisions are all
  // literal deny or ask, or that decides nothing, is a check.
  const approves: HookJudgement['approves'] = !deciding
    ? 'no'
    : texts.some(text => APPROVES.test(text))
      ? 'yes'
      : !readable || texts.some(text => mayApprove(text))
        ? 'unknown'
        : 'no';
  return { reach, approves, why: why.length > 120 ? `${why.slice(0, 117)}...` : why };
}
