/**
 * Just enough shell to find agent CLIs in a workflow `run:` script: simple commands split on
 * `;`, `&&`, `||`, `|`, `&`, new lines and parentheses, words with their quotes removed, variable
 * assignments and wrapper commands (`env`, `time`, `sudo`, `npx`, ...) skipped, and the text of
 * `bash -c "..."`, `$(...)` and back quotes read as commands of their own. It is not a shell: what
 * it cannot resolve (an unquoted `$FLAGS`) is reported as dynamic, so the caller can assume the worst.
 */

/** One word of a command, with quotes removed. */
export interface Word {
  readonly text: string;
  /** Contains a variable or command substitution the scan could not resolve. */
  readonly dynamic: boolean;
  /** Dynamic and not inside double quotes: the shell may split it into several arguments. */
  readonly splits: boolean;
}

const MAX_SCRIPT = 200_000;
const BRACED = /\{([A-Za-z_][A-Za-z0-9_]*)\}/y;
const PLAIN = /([A-Za-z_][A-Za-z0-9_]*)/y;
/** `${...}` (bounded, so an unclosed one is not read to the end), `$@`, `$1`, ... */
const OTHER = /(\{[^}\n]{0,200}\}|[@*#?$!0-9-])/y;
const MAX_NESTING = 4;

/** Removes heredoc bodies; a body fed to a shell (`bash <<EOF`) is kept as script text. */
function stripHeredocs(text: string): string {
  const lines = text.split('\n');
  const out: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    out.push(line);
    const match = /<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/.exec(line);
    if (!match) continue;
    const runsBody = /(^|[\s;&|(])(ba|z|da|k)?sh(\s|$)/.test(line.slice(0, match.index));
    const end = match[3]!;
    for (i += 1; i < lines.length; i += 1) {
      const body = lines[i]!;
      if ((match[1] ? body.trim() : body) === end) break;
      if (runsBody) out.push(body);
    }
  }
  return out.join('\n');
}

/** The text inside `$( ... )` and back quotes, wherever they are, including inside double quotes. */
function substitutions(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === '$' && text[i + 1] === '(' && text[i + 2] !== '(') {
      let depth = 1;
      let j = i + 2;
      for (; j < text.length && depth > 0; j += 1) {
        if (text[j] === '(') depth += 1;
        else if (text[j] === ')') depth -= 1;
      }
      out.push(text.slice(i + 2, j - 1));
      i = j - 1;
    } else if (text[i] === '`') {
      const j = text.indexOf('`', i + 1);
      if (j < 0) break;
      out.push(text.slice(i + 1, j));
      i = j;
    }
  }
  return out;
}

/**
 * Splits a script into simple commands. `vars` resolves `$NAME` and `${NAME}` (step env and
 * assignments earlier in the script); anything else with a `$` is dynamic.
 */
export function commands(script: string, vars: ReadonlyMap<string, string> = new Map(), nesting = 0): Word[][] {
  const text = stripHeredocs(script.slice(0, MAX_SCRIPT).replace(/\\\r?\n/g, ' '));
  const known = new Map(vars);
  const out: Word[][] = [];
  let command: Word[] = [];
  let word = '';
  let inWord = false;
  let dynamic = false;
  let splits = false;
  // The index of the parenthesis that closes the one at `open`.
  const closing = (open: number): number => {
    let depth = 0;
    for (let j = open; j < text.length; j += 1) {
      if (text[j] === '(') depth += 1;
      else if (text[j] === ')' && --depth === 0) return j;
    }
    return text.length - 1;
  };
  const endWord = () => {
    if (inWord) command.push({ text: word, dynamic, splits });
    word = '';
    inWord = false;
    dynamic = false;
    splits = false;
  };
  const endCommand = () => {
    endWord();
    if (command.length) {
      // `NAME=value` alone sets a shell variable later commands can expand.
      const assigns = command.every(item => /^[A-Za-z_][A-Za-z0-9_]*=/.test(item.text) && !item.dynamic);
      const exported = command[0]?.text === 'export' && command.length > 1;
      if (assigns || exported)
        for (const item of exported ? command.slice(1) : command) {
          const [name, value] = item.text.split(/=(.*)/s, 2);
          if (name && value !== undefined && !item.dynamic) known.set(name, value);
        }
      out.push(command);
    }
    command = [];
  };
  // Reads `$NAME`, `${NAME}`, `$1`, `$@`, `$(...)`; returns the characters consumed and the value
  // if known. A command substitution is read on its own (see `substitutions`), not here.
  const expand = (at: number): { length: number; value?: string } => {
    if (text[at + 1] === '(') return { length: closing(at + 1) - at + 1 };
    // Sticky patterns read at the offset: slicing the rest of the text for every `$` is quadratic.
    BRACED.lastIndex = at + 1;
    PLAIN.lastIndex = at + 1;
    const braced = BRACED.exec(text);
    const plain = braced ? null : PLAIN.exec(text);
    const name = braced?.[1] ?? plain?.[1];
    if (name !== undefined) {
      const length = 1 + (braced ? braced[0].length : plain![0].length);
      return known.has(name) ? { length, value: known.get(name)! } : { length };
    }
    OTHER.lastIndex = at + 1;
    const other = OTHER.exec(text);
    return { length: 1 + (other ? other[0].length : 0) };
  };
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!;
    if (char === "'") {
      const end = text.indexOf("'", i + 1);
      word += end < 0 ? text.slice(i + 1) : text.slice(i + 1, end);
      inWord = true;
      i = end < 0 ? text.length : end;
    } else if (char === '"') {
      inWord = true;
      for (i += 1; i < text.length && text[i] !== '"'; i += 1) {
        if (text[i] === '\\' && i + 1 < text.length) {
          word += text[i + 1];
          i += 1;
        } else if (text[i] === '$') {
          const { length, value } = expand(i);
          if (value !== undefined) word += value;
          else {
            word += text.slice(i, i + length);
            dynamic = true;
          }
          i += length - 1;
        } else word += text[i];
      }
    } else if (char === '\\') {
      word += text[i + 1] ?? '';
      inWord = true;
      i += 1;
    } else if (char === '$') {
      const { length, value } = expand(i);
      if (value !== undefined) {
        // An unquoted variable is split on spaces: its value may be several arguments.
        const parts = value.split(/\s+/).filter(Boolean);
        if (parts.length > 1 || !value.trim()) {
          word += parts[0] ?? '';
          inWord = inWord || parts.length > 0;
          for (const part of parts.slice(1)) {
            endWord();
            word = part;
            inWord = true;
          }
        } else {
          word += value;
          inWord = true;
        }
      } else {
        word += text.slice(i, i + length);
        inWord = true;
        dynamic = true;
        splits = true;
      }
      i += length - 1;
    } else if (char === '`') {
      // Back quotes: a command substitution, read on its own.
      const end = text.indexOf('`', i + 1);
      word += '`';
      inWord = true;
      dynamic = true;
      splits = true;
      i = end < 0 ? text.length : end;
    } else if (char === '#' && !inWord) {
      const end = text.indexOf('\n', i);
      i = end < 0 ? text.length : end - 1;
    } else if (/[\s]/.test(char)) {
      if (char === '\n') endCommand();
      else endWord();
    } else if (/[;&|(){}]/.test(char) && !(char === '{' && inWord) && !(char === '}' && inWord)) {
      endCommand();
    } else if (char === '<' || char === '>') {
      // A redirection (`> out`, `2>&1`, `<<<`): the file descriptor number is not an argument.
      if (inWord && /^\d+$/.test(word) && !dynamic) {
        word = '';
        inWord = false;
      } else endWord();
      while (text[i + 1] === '>' || text[i + 1] === '&' || text[i + 1] === '<') i += 1;
      // `>&2`, `2>&1`, `>&-`: a descriptor, not a file name.
      if (text[i] === '&') while (/[0-9-]/.test(text[i + 1] ?? '')) i += 1;
    } else {
      word += char;
      inWord = true;
    }
  }
  endCommand();
  if (nesting < MAX_NESTING) for (const inner of substitutions(text)) out.push(...commands(inner, known, nesting + 1));
  return out;
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
/** Wrappers that run the rest of the line as a command, and how many of their options take a value. */
const WRAPPER_VALUE_OPTIONS: Record<string, Set<string>> = {
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  sudo: new Set(['-u', '-g', '-h', '-p', '-U', '-C', '-D', '-R', '-T']),
  time: new Set(['-f', '-o']),
  nice: new Set(['-n']),
  timeout: new Set(['-s', '-k', '--signal', '--kill-after']),
  exec: new Set(['-a']),
  nohup: new Set(),
  command: new Set(),
  builtin: new Set(),
  stdbuf: new Set(['-i', '-o', '-e']),
  'xvfb-run': new Set(['-n', '-s', '-e', '-f', '-p']),
  xargs: new Set(['-I', '-n', '-P', '-L', '-d', '-s', '-E', '-a']),
  npx: new Set(['-p', '--package', '-c', '--call']),
  pnpx: new Set(['-p', '--package']),
  bunx: new Set(['-p', '--package']),
  uvx: new Set(['--from', '--with', '-p', '--python']),
};
/** `pnpm dlx`, `yarn dlx`, `npm exec`, `bun x`: package runners that start with a subcommand. */
const RUNNER_SUBCOMMANDS: Record<string, Set<string>> = {
  pnpm: new Set(['dlx', 'exec']),
  yarn: new Set(['dlx', 'exec']),
  npm: new Set(['exec', 'x']),
  bun: new Set(['x']),
};

/** The last path segment, without an npm version (`./bin/claude`, `@anthropic-ai/claude-code@1`). */
function commandName(text: string): string {
  if (/^@[^/]+\/[^/]+$/.test(text.replace(/@[^@/]*$/, ''))) return text.replace(/(.)@[^@/]*$/, '$1');
  return (text.split('/').at(-1) ?? text).replace(/(.)@[^@]*$/, '$1');
}

/**
 * The command a simple command runs once assignments and wrappers are removed: its name and
 * arguments. `bash -c "script"` is not unwrapped here (see `agentCalls`).
 */
export function unwrap(
  words: readonly Word[],
): { name: string; head: string; dynamic: boolean; args: Word[] } | undefined {
  let i = 0;
  // Shell keywords start a command too: `if claude -p ...`, `then claude ...`, `! claude ...`.
  while (i < words.length && SHELL_KEYWORDS.has(words[i]!.text) && !words[i]!.dynamic) i += 1;
  while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]!.text)) i += 1;
  for (let guard = 0; guard < 8 && i < words.length; guard += 1) {
    const name = commandName(words[i]!.text);
    if (words[i]!.dynamic) break;
    // `command -v claude` and `type claude` look a program up; they do not run it.
    if (name === 'command' && /^-[vV]$/.test(words[i + 1]?.text ?? '')) return undefined;
    if (RUNNER_SUBCOMMANDS[name]?.has(words[i + 1]?.text ?? '')) i += 2;
    else if (WRAPPER_VALUE_OPTIONS[name]) i += 1;
    else break;
    const takesValue = WRAPPER_VALUE_OPTIONS[name] ?? new Set<string>();
    while (i < words.length) {
      const word = words[i]!.text;
      if (word === '--') {
        i += 1;
        break;
      }
      if (word.startsWith('-') && word.length > 1) {
        i += takesValue.has(word) ? 2 : 1;
        continue;
      }
      // `env NAME=value cmd`, `timeout 10m cmd`, `nice 10 cmd`.
      if ((name === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) || (name === 'timeout' && /^\d/.test(word))) {
        i += 1;
        continue;
      }
      break;
    }
  }
  const head = words[i];
  if (!head) return undefined;
  return { name: commandName(head.text), head: head.text, dynamic: head.dynamic, args: words.slice(i + 1) };
}

const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', 'coproc']);

/**
 * Agent CLIs. `other` stands for agents whose permissions the scanner does not model (OpenCode,
 * Cursor's CLI, Aider, Amp, Goose, Qwen Code, Crush): unknown reach.
 */
export type AgentCli = 'claude' | 'codex' | 'copilot' | 'gemini' | 'other';
/** Program names of agents the scanner does not model, and how each runs headless (undefined: always). */
const OTHER_AGENTS: Record<string, RegExp | undefined> = {
  opencode: /^(run|serve|github)$/,
  'opencode-ai': /^(run|serve|github)$/,
  'cursor-agent': /^(-p|--print|-[a-zA-Z]*p[a-zA-Z]*)$/,
  aider: undefined,
  'aider-chat': undefined,
  amp: /^(-x|--execute)$/,
  '@sourcegraph/amp': /^(-x|--execute)$/,
  goose: /^run$/,
  qwen: undefined,
  '@qwen-code/qwen-code': undefined,
  crush: /^run$/,
};
const CLI_NAMES: Record<string, AgentCli> = {
  ...Object.fromEntries(Object.keys(OTHER_AGENTS).map(name => [name, 'other' as const])),
  claude: 'claude',
  'claude-code': 'claude',
  '@anthropic-ai/claude-code': 'claude',
  codex: 'codex',
  '@openai/codex': 'codex',
  copilot: 'copilot',
  '@github/copilot': 'copilot',
  gemini: 'gemini',
  'gemini-cli': 'gemini',
  '@google/gemini-cli': 'gemini',
};
/** Subcommands that manage the CLI rather than run the agent. */
const MANAGEMENT: Record<AgentCli, Set<string>> = {
  claude: new Set(['mcp', 'config', 'update', 'doctor', 'install', 'migrate-installer', 'setup-token', 'plugin']),
  codex: new Set([
    'login',
    'logout',
    'mcp',
    'completion',
    'help',
    'apply',
    'a',
    'mcp-server',
    'app-server',
    'features',
  ]),
  copilot: new Set(['help', 'version', 'login', 'logout', 'mcp', 'plugin']),
  gemini: new Set(['mcp', 'extensions', 'extension']),
  other: new Set(['auth', 'login', 'logout', 'models', 'upgrade', 'mcp', 'config', 'session', 'info']),
};
const INFO_FLAGS = new Set(['--version', '-v', '-V', '--help', '-h']);
/** Codex options before the subcommand that take a value. */
const CODEX_VALUE = new Set([
  '-c',
  '--config',
  '-m',
  '--model',
  '-p',
  '--profile',
  '-s',
  '--sandbox',
  '-a',
  '--ask-for-approval',
  '-C',
  '--cd',
  '-i',
  '--image',
  '--enable',
  '--disable',
  '--local-provider',
  '--add-dir',
]);

/** One call of an agent CLI in a script. */
export interface AgentCall {
  readonly cli: AgentCli;
  /** The program as named (`claude`, `opencode`, ...). */
  readonly program: string;
  /** Why the call is unknown: an agent named in a script the scan could not follow. */
  readonly unknown?: string;
  /** The arguments after the command name, quotes removed. */
  readonly args: readonly string[];
  /** Arguments the scan could not resolve and that may be several flags (`$FLAGS`, `"$@"`). */
  readonly unresolved: readonly string[];
}

/**
 * Whether a call runs the agent rather than a management command. Claude Code and Copilot CLI
 * run headless only with `-p`/`--print`/`--prompt` (also in a short-flag cluster such as `-cp`);
 * Codex with `exec` (or `e`); Gemini CLI with any prompt. Unresolved arguments could be any of these.
 */
function runsAgent(cli: AgentCli, args: readonly Word[], program = ''): boolean {
  const texts = args.map(arg => arg.text);
  const unresolved = args.some(arg => arg.splits);
  if (texts.length && texts.every(text => INFO_FLAGS.has(text))) return false;
  if (cli === 'other') {
    const first = texts.find(text => !text.startsWith('-'));
    if (first !== undefined && MANAGEMENT.other.has(first) && texts[0] === first) return false;
    const runs = OTHER_AGENTS[program];
    return runs === undefined || unresolved || texts.some(text => runs.test(text));
  }
  if (cli === 'codex') {
    let i = 0;
    while (i < args.length && args[i]!.text.startsWith('-')) i += CODEX_VALUE.has(args[i]!.text) ? 2 : 1;
    const sub = args[i]?.text;
    if (sub === 'exec' || sub === 'e') return true;
    return unresolved && sub === undefined;
  }
  const first = texts.find(text => !text.startsWith('-'));
  if (
    first !== undefined &&
    MANAGEMENT[cli].has(first) &&
    texts.indexOf(first) === texts.findIndex(t => !t.startsWith('-'))
  )
    if (!texts.slice(0, texts.indexOf(first)).some(text => text === '-p' || text === '--print')) return false;
  if (cli === 'gemini') return true;
  const prompt = cli === 'claude' ? /^(--print|-[a-zA-Z]*p[a-zA-Z]*)$/ : /^(--prompt|-[a-zA-Z]*p[a-zA-Z]*)$/;
  // Flags that change what the agent may do mean it runs, with or without `-p` (input on stdin).
  const permission = /^--(dangerously|allow|yolo|permission|allowed|disallowed|mcp-config|settings)/;
  return unresolved || texts.some(text => prompt.test(text) || text.startsWith('--prompt=') || permission.test(text));
}

/** An agent CLI named in text: a program name on its own, or the Claude Code package. */
export const AGENT_MENTION =
  /(^|[\s"'`;&|(/=])(claude|codex|copilot|gemini|opencode|cursor-agent|aider|amp|goose|qwen|crush)(?=[\s"'`;&|)]|$)|@anthropic-ai\/claude-code|@openai\/codex|@google\/gemini-cli/m;
/** Commands that install or look up an agent CLI rather than run it. */
const INSTALL_LINE =
  /^\s*(npm|pnpm|yarn|bun)\s+(i|install|add|ci)\b|^\s*(pip|pipx|uv)\s+(tool\s+)?install\b|^\s*brew\s+install\b|^\s*(which|command -v|type)\b|^\s*(echo|printf)\b|^\s*#/;
/** Whether a script names an agent CLI outside install, lookup and echo lines. */
export function namesAgent(text: string): boolean {
  // An echo piped into a shell is a command, not a message.
  return text
    .split('\n')
    .some(line => (!INSTALL_LINE.test(line) || /\|\s*(ba|z|da)?sh\b/.test(line)) && AGENT_MENTION.test(line));
}

/** Where agent calls can read files a script runs: package.json scripts, Makefile targets, shell scripts. */
export interface ScriptContext {
  readonly readFile?: (path: string) => string | undefined;
  /** The folder the script runs in, relative to the repository root. */
  readonly cwd?: string;
}

function joinRepo(cwd: string, path: string): string | undefined {
  if (path.startsWith('/') || path.startsWith('~') || path.includes('$')) return undefined;
  const parts: string[] = [];
  for (const part of `${cwd}/${path}`.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!parts.length) return undefined;
      parts.pop();
    } else parts.push(part);
  }
  return parts.join('/');
}

/** The text of a `make` target's recipe. */
function makeTarget(makefile: string, target: string): string | undefined {
  const lines = makefile.split('\n');
  const start = lines.findIndex(line =>
    new RegExp(`^${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:`).test(line),
  );
  if (start < 0) return undefined;
  const out: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (!/^\t/.test(line)) break;
    out.push(line.replace(/^\t[@-]*/, ''));
  }
  return out.join('\n');
}

/**
 * Agent CLI calls in a script. Read as well: `bash -c "..."` and `eval` text, repository scripts it
 * runs (`./ci/agent.sh`, `bash x.sh`, `source x.sh`), `npm run` scripts and `make` targets, the CLI
 * inside `docker run` or started through `node .../cli.js`. An agent named where the scan cannot
 * follow (a script it cannot read, a non-shell script, stdin piped into a shell) is an unknown call.
 */
export function agentCalls(
  script: string,
  vars: ReadonlyMap<string, string> = new Map(),
  nesting = 0,
  context: ScriptContext = {},
): AgentCall[] {
  const out: AgentCall[] = [];
  const cwd = context.cwd ?? '';
  const unknown = (program: string, why: string) =>
    out.push({ cli: 'other', program, args: [], unresolved: [], unknown: why });
  const follow = (text: string, why: string, shell: boolean) => {
    if (nesting >= MAX_NESTING) {
      if (namesAgent(text)) unknown('agent', why);
      return;
    }
    const found = shell ? agentCalls(text, vars, nesting + 1, context) : [];
    if (found.length) out.push(...found);
    else if (namesAgent(text)) unknown('agent', why);
  };
  for (const words of commands(script, vars)) {
    const call = unwrap(words);
    if (!call) continue;
    const args = call.args.map(arg => arg.text);
    if (SHELLS.has(call.name) || call.name === 'eval') {
      // `bash -c "script"`, `sh -ec 'script'`, `eval "..."`, `bash ./ci/x.sh`.
      const at = call.args.findIndex(arg => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg.text));
      if (call.name === 'eval') follow(args.join(' '), 'eval', true);
      else if (at >= 0 && call.args[at + 1]) follow(call.args[at + 1]!.text, `${call.name} -c`, true);
      else {
        const file = args.find(arg => !arg.startsWith('-'));
        const path = file === undefined ? undefined : joinRepo(cwd, file);
        const text = path === undefined ? undefined : context.readFile?.(path);
        if (text !== undefined) follow(text, path!, true);
        else if (file !== undefined && /\.(sh|bash)$/.test(file)) follow(file, `script ${file}`, false);
      }
      continue;
    }
    // `source x.sh`, `. x.sh`, `./ci/agent.sh`.
    const scriptPath =
      call.name === 'source' || call.name === '.'
        ? args[0]
        : !call.dynamic && /^\.{0,2}\/|^[\w.-]+\/[\w./-]+$/.test(call.head) && !CLI_NAMES[call.name]
          ? call.head
          : undefined;
    if (scriptPath !== undefined) {
      const path = joinRepo(cwd, scriptPath);
      const text = path === undefined ? undefined : context.readFile?.(path);
      if (text !== undefined) follow(text, path!, /\.(sh|bash|zsh)$/.test(path!) || /^#!.*\b(ba|z|da)?sh\b/.test(text));
      continue;
    }
    // `npm run agent`, `pnpm agent`, `yarn agent`, `make agent`, `just agent`.
    if (/^(npm|pnpm|yarn|bun)$/.test(call.name) && context.readFile) {
      const name = args[0] === 'run' || args[0] === 'run-script' ? args[1] : call.name === 'npm' ? undefined : args[0];
      const manifest = context.readFile(joinRepo(cwd, 'package.json') ?? 'package.json');
      if (name && manifest) {
        try {
          const scripts = (JSON.parse(manifest) as { scripts?: Record<string, unknown> }).scripts ?? {};
          const body = scripts[name];
          if (typeof body === 'string') follow(body, `${call.name} run ${name}`, true);
        } catch {
          // An unreadable package.json names no script.
        }
      }
      continue;
    }
    if ((call.name === 'make' || call.name === 'just') && context.readFile) {
      const file = context.readFile(joinRepo(cwd, call.name === 'make' ? 'Makefile' : 'justfile') ?? '');
      const target = args.find(arg => !arg.startsWith('-') && !arg.includes('='));
      if (file !== undefined && target !== undefined) {
        const body = makeTarget(file, target);
        if (body !== undefined) follow(body, `${call.name} ${target}`, true);
      }
      continue;
    }
    // The CLI in a container, or Claude Code's own entry point run by node.
    if ((call.name === 'docker' || call.name === 'podman') && /^(run|exec|compose)$/.test(args[0] ?? '')) {
      const at = args.findIndex(arg => CLI_NAMES[commandName(arg)] !== undefined);
      if (at >= 0) {
        const cli = CLI_NAMES[commandName(args[at]!)]!;
        out.push({ cli, program: commandName(args[at]!), args: args.slice(at + 1), unresolved: [] });
      } else if (namesAgent(args.join(' '))) unknown('agent', `${call.name} ${args[0]}`);
      continue;
    }
    if (call.name === 'node' && args[0] && /claude-code\/cli\.m?js$/.test(args[0])) {
      out.push({
        cli: 'claude',
        program: 'claude',
        args: args.slice(1),
        unresolved: call.args
          .slice(1)
          .filter(arg => arg.splits)
          .map(arg => arg.text),
      });
      continue;
    }
    // An agent binary passed by path to another program: `"$NODE" harness.cjs "$TEMP/bin/copilot" ...`.
    const binary = call.args.findIndex(arg => arg.text.includes('/') && CLI_NAMES[commandName(arg.text)] !== undefined);
    if (binary >= 0 && (call.dynamic || /^(node|bun|deno|npx|bunx|exec|env)$/.test(call.name))) {
      const program = commandName(call.args[binary]!.text);
      const rest = call.args.slice(binary + 1);
      const cli = CLI_NAMES[program]!;
      if (runsAgent(cli, rest, program))
        out.push({
          cli,
          program,
          args: rest.map(arg => arg.text),
          unresolved: rest.filter(arg => arg.splits).map(arg => arg.text),
        });
      continue;
    }
    // A dynamic command word that names the agent: `"$(which claude)"`, `$HOME/.local/bin/claude`.
    const named = call.dynamic
      ? /(claude|codex|copilot|gemini|opencode|cursor-agent|aider|goose|qwen|crush)\b/.exec(call.head)?.[1]
      : undefined;
    const cli = call.dynamic ? (named ? CLI_NAMES[named] : undefined) : CLI_NAMES[call.name];
    const program = named ?? call.name;
    if (!cli || !runsAgent(cli, call.args, program)) continue;
    out.push({
      cli,
      program,
      args,
      unresolved: call.args.filter(arg => arg.splits).map(arg => arg.text),
    });
  }
  return out;
}
