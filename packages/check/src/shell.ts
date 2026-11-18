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
    const rest = text.slice(at + 1);
    const braced = /^\{([A-Za-z_][A-Za-z0-9_]*)\}/.exec(rest);
    const plain = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(rest);
    const name = braced?.[1] ?? plain?.[1];
    if (name !== undefined) {
      const length = 1 + (braced ? braced[0].length : plain![0].length);
      return known.has(name) ? { length, value: known.get(name)! } : { length };
    }
    const other = /^(\{[^}]*\}|[@*#?$!0-9-])/.exec(rest);
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
export function unwrap(words: readonly Word[]): { name: string; dynamic: boolean; args: Word[] } | undefined {
  let i = 0;
  while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]!.text)) i += 1;
  for (let guard = 0; guard < 8 && i < words.length; guard += 1) {
    const name = commandName(words[i]!.text);
    if (words[i]!.dynamic) break;
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
  return { name: commandName(head.text), dynamic: head.dynamic, args: words.slice(i + 1) };
}

export type AgentCli = 'claude' | 'codex' | 'copilot' | 'gemini';
const CLI_NAMES: Record<string, AgentCli> = {
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
function runsAgent(cli: AgentCli, args: readonly Word[]): boolean {
  const texts = args.map(arg => arg.text);
  const unresolved = args.some(arg => arg.splits);
  if (texts.length && texts.every(text => INFO_FLAGS.has(text))) return false;
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
  return unresolved || texts.some(text => prompt.test(text) || text.startsWith('--prompt='));
}

/** Agent CLI calls in a script, with `bash -c "..."` scripts read as well. */
export function agentCalls(script: string, vars: ReadonlyMap<string, string> = new Map(), nesting = 0): AgentCall[] {
  const out: AgentCall[] = [];
  for (const words of commands(script, vars)) {
    const call = unwrap(words);
    if (!call) continue;
    if (SHELLS.has(call.name)) {
      // `bash -c "script"`, `sh -ec 'script'`, `bash -lc "$CMD"`.
      const at = call.args.findIndex(arg => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg.text));
      const inner = at >= 0 ? call.args[at + 1] : undefined;
      if (inner && nesting < MAX_NESTING) out.push(...agentCalls(inner.text, vars, nesting + 1));
      continue;
    }
    const cli = call.dynamic ? undefined : CLI_NAMES[call.name];
    if (!cli || !runsAgent(cli, call.args)) continue;
    out.push({
      cli,
      args: call.args.map(arg => arg.text),
      unresolved: call.args.filter(arg => arg.splits).map(arg => arg.text),
    });
  }
  return out;
}
