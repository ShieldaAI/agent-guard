import { createHash } from 'node:crypto';
import { parse as parseYaml } from 'yaml';
import { isRecord, toolNames } from './text.js';
import { agentCalls } from './shell.js';
import { UNTRUSTED_TRIGGERS } from './workflows.js';

/**
 * GitHub Agentic Workflows: checks that a compiled `.lock.yml` matches its `.md` source. The lock
 * is what runs; the scan judges the source. A lock whose agent flags or triggers the source does
 * not explain was edited by hand, so the source tells nothing about it.
 */

type ReadFile = (path: string) => string | undefined;

/** Splits gh-aw's way: the front matter is the text between a first `---` line and the next. */
function split(text: string): { front: string; body: string } | undefined {
  const content = text.replace(/\r\n/g, '\n');
  const lines = content.split('\n');
  if (lines[0]?.trim() !== '---') return { front: '', body: content };
  const end = lines.findIndex((line, i) => i > 0 && line.trim() === '---');
  if (end < 0) return undefined;
  return { front: lines.slice(1, end).join('\n'), body: lines.slice(end + 1).join('\n') };
}

const norm = (text: string) => text.replace(/\r\n/g, '\n').trim();
const indentOf = (line: string) => line.length - line.trimStart().length;

/** gh-aw's text scan of `imports:` (a list, or the `aw:` list of the object form). */
function importsOf(front: string): string[] {
  const out: string[] = [];
  let inImports = false;
  let base = 0;
  let objectForm = false;
  let inAw = false;
  let awIndent = 0;
  for (const line of front.split('\n')) {
    const text = line.trim();
    if (!text || text.startsWith('#')) continue;
    if (text.startsWith('imports:')) {
      inImports = true;
      inAw = false;
      objectForm = false;
      base = indentOf(line);
      continue;
    }
    if (!inImports) continue;
    const indent = indentOf(line);
    if (indent <= base) break;
    if (indent === base + 2 && text.startsWith('aw:')) {
      objectForm = true;
      inAw = true;
      awIndent = indent;
      continue;
    }
    if (objectForm && indent === base + 2 && text.includes(':') && !text.startsWith('-')) {
      inAw = false;
      continue;
    }
    if (!text.startsWith('-')) continue;
    if (objectForm && (!inAw || indent <= awIndent)) continue;
    let item = text.slice(1).trim();
    if (item.startsWith('uses:') || item.startsWith('path:')) item = item.slice(5).trim();
    item = item.replace(/^["']+|["']+$/g, '');
    if (item) out.push(item);
  }
  return out;
}

/** `${{ ... }}` expressions, with gh-aw's quote-aware end: `}}` inside a '...' string does not close. */
function expressions(text: string): { full: string; inner: string }[] {
  const out: { full: string; inner: string }[] = [];
  let at = 0;
  while (at < text.length) {
    const start = text.indexOf('${{', at);
    if (start < 0) break;
    let i = start + 3;
    let quoted = false;
    let end = -1;
    while (i < text.length) {
      const char = text[i];
      if (char === "'") {
        if (quoted && text[i + 1] === "'") {
          i += 2;
          continue;
        }
        quoted = !quoted;
      } else if (!quoted && char === '}' && text[i + 1] === '}') {
        end = i;
        break;
      }
      i += 1;
    }
    // No `}}` closes it, so none of the later ones closes either: stop rather than rescan.
    if (end < 0) break;
    out.push({ full: text.slice(start, end + 2), inner: text.slice(start + 3, end) });
    at = end + 2;
  }
  return out;
}

/** Joins and normalises a repository path; undefined when it leaves the root. */
function joinPath(base: string, path: string): string | undefined {
  const parts: string[] = [];
  for (const part of `${base}/${path}`.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (!parts.length) return undefined;
      parts.pop();
    } else parts.push(part);
  }
  return parts.join('/');
}
const dirOf = (path: string) => path.split('/').slice(0, -1).join('/');

/** `{{#runtime-import path}}` and `{{#import path}}`: files whose expressions the hash includes. */
const RUNTIME_IMPORT = /\{\{#(?:runtime-import|import)\??(?:[ \t]+|[ \t]*:[ \t]*)([^{}]+?)\}\}/g;

function runtimeCandidates(path: string, base: string): string[] {
  let name = path.trim().replace(/\\/g, '/');
  if (name.startsWith('/')) {
    name = name.replace(/^\/+/, '');
    if (!name.startsWith('.github/') && !name.startsWith('.agents/')) return [];
  }
  if (name.startsWith('./')) name = name.slice(2);
  if (!name || name.startsWith('../') || name.includes('/../')) return [];
  const parts = base.split('/');
  const github = parts.lastIndexOf('.github');
  const root = github >= 0 ? parts.slice(0, github).join('/') : base;
  if (name.startsWith('.agents/') || name.startsWith('.github/')) return [joinPath(root, name)!].filter(Boolean);
  return [
    ...new Set([joinPath(root, `.github/${name}`), joinPath(root, `.github/workflows/${name}`), joinPath(base, name)]),
  ].filter((item): item is string => item !== undefined);
}

function runtimeExpressions(body: string, base: string, readFile: ReadFile, seen: Set<string>): Set<string> {
  const out = new Set<string>();
  const refs: [string, number, number][] = [];
  const keys = new Set<string>();
  for (const match of body.matchAll(RUNTIME_IMPORT)) {
    const target = match[1]!.trim();
    if (!target) continue;
    const range = /^(.+?):(\d+)-(\d+)$/.exec(target);
    const [path, from, to] = range ? [range[1]!.trim(), Number(range[2]), Number(range[3])] : [target, 0, 0];
    if (/^https?:\/\//.test(path)) continue;
    const key = `${path}:${from}-${to}`;
    if (keys.has(key)) continue;
    keys.add(key);
    refs.push([path, from, to]);
  }
  for (const [path, from, to] of refs)
    for (const candidate of runtimeCandidates(path, base)) {
      const key = `${candidate}:${from}-${to}`;
      if (seen.has(key)) break;
      let content = readFile(candidate);
      if (content === undefined) continue;
      seen.add(key);
      if (from > 0 || to > 0) {
        const lines = content.split('\n');
        const start = from > 0 ? from : 1;
        const end = to > 0 && to <= lines.length ? to : lines.length;
        content = start > end || start > lines.length ? '' : lines.slice(start - 1, end).join('\n');
      }
      const body = split(content)?.body ?? content;
      for (const item of expressions(body)) if (item.inner.trim()) out.add(item.full);
      for (const item of runtimeExpressions(body, base, readFile, seen)) out.add(item);
      break;
    }
  return out;
}

/** JSON the way Go's encoder writes it with HTML escaping off: also escapes U+2028 and U+2029. */
const goJson = (value: string) =>
  JSON.stringify(value).replace(/[\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16)}`);

/**
 * gh-aw's `frontmatter_hash` of a workflow source (schema v4, compilers 1.0 to 1.2): sha256 of a
 * canonical JSON of the front matter text, its imports' front matter, and the `env.`/`vars.`
 * expressions of the body. Undefined when the source cannot be split.
 */
export function agenticFrontmatterHash(path: string, text: string, readFile: ReadFile): string | undefined {
  const parts = split(text);
  if (!parts) return undefined;
  const base = dirOf(path);
  const files: string[] = [];
  const fronts: string[] = [];
  const bodies: string[] = [];
  const visited = new Set<string>();
  const walk = (front: string, folder: string) => {
    for (const item of importsOf(front).sort()) {
      const full = joinPath(folder, item.split('#')[0]!.replace(/^\/+/, ''));
      if (full === undefined || visited.has(full)) continue;
      visited.add(full);
      const content = readFile(full);
      if (content === undefined) continue;
      const imported = split(content);
      if (!imported) continue;
      files.push(item);
      fronts.push(imported.front);
      bodies.push(imported.body);
      walk(imported.front, dirOf(full));
    }
  };
  walk(parts.front, base);
  const canonical: Record<string, string | string[]> = { 'frontmatter-text': norm(parts.front) };
  if (files.length) canonical['imports'] = [...files].sort();
  if (fronts.length) canonical['imported-frontmatters'] = fronts.map(norm).sort().join('\n---\n');
  if (/^inlined-imports:\s*(true|True|TRUE|yes|on)\s*(#.*)?$/m.test(parts.front)) {
    const body = norm(parts.body);
    if (body) canonical['body-text'] = body;
  } else {
    const found = new Set<string>();
    for (const item of expressions(parts.body)) if (/env\.|vars\./.test(item.inner)) found.add(item.full);
    for (const item of runtimeExpressions(parts.body, base, readFile, new Set())) found.add(item);
    for (const body of bodies) {
      for (const item of expressions(body)) if (item.inner.trim()) found.add(item.full);
      for (const item of runtimeExpressions(body, base, readFile, new Set())) found.add(item);
    }
    found.delete('');
    if (found.size) canonical['template-expressions'] = [...found].sort();
  }
  const keys = Object.keys(canonical).sort((a, b) => (Buffer.from(a) < Buffer.from(b) ? -1 : 1));
  const json = `{${keys
    .map(key => {
      const value = canonical[key]!;
      return `${goJson(key)}:${Array.isArray(value) ? `[${value.map(goJson).join(',')}]` : goJson(value)}`;
    })
    .join(',')}}`;
  return createHash('sha256').update(json, 'utf8').digest('hex');
}

/** What a source's front matter (and the front matter it imports) asks gh-aw to compile in. */
export interface SourceAsks {
  /** Every word of `engine.args`. */
  readonly args: ReadonlySet<string>;
  /** `engine.permission-mode`. */
  readonly modes: ReadonlySet<string>;
  /** `tools.bash` allows every command (`"*"`, `":*"`, `true` with no list). */
  readonly bashAll: boolean;
  readonly edit: boolean;
  readonly webFetch: boolean;
  /** `engine` (or `engine.id`): the agent gh-aw compiles in; `copilot` when not set. */
  readonly engine: string;
}

/** Reads what the source and its imports ask for, from front matter only: prose explains nothing. */
export function sourceAsks(path: string, text: string, readFile: ReadFile): SourceAsks {
  const args = new Set<string>();
  const modes = new Set<string>();
  let bashAll = false;
  let edit = false;
  let webFetch = false;
  let engineId: string | undefined;
  const visited = new Set<string>();
  const read = (front: string) => {
    let data: unknown;
    try {
      data = parseYaml(front, { maxAliasCount: 50 });
    } catch {
      return;
    }
    if (!isRecord(data)) return;
    const engine = isRecord(data['engine']) ? data['engine'] : {};
    // The workflow's own engine wins over an imported one.
    engineId ??=
      typeof data['engine'] === 'string' ? data['engine'] : typeof engine['id'] === 'string' ? engine['id'] : undefined;
    const list = Array.isArray(engine['args'])
      ? engine['args']
      : typeof engine['args'] === 'string'
        ? [engine['args']]
        : [];
    for (const item of list)
      if (typeof item === 'string') for (const word of item.split(/[\s=]+/)) if (word) args.add(word);
    if (typeof engine['permission-mode'] === 'string') modes.add(engine['permission-mode']);
    const tools = isRecord(data['tools']) ? data['tools'] : {};
    const bash = tools['bash'];
    if (
      bash === true ||
      bash === null ||
      (Array.isArray(bash) && bash.some(item => item === '*' || item === ':*')) ||
      bash === '*'
    )
      bashAll = true;
    if (tools['edit'] !== undefined && tools['edit'] !== false) edit = true;
    if (tools['web-fetch'] !== undefined && tools['web-fetch'] !== false) webFetch = true;
  };
  const walk = (front: string, folder: string, depth: number) => {
    read(front);
    if (depth > 3) return;
    for (const item of importsOf(front)) {
      const full = joinPath(folder, item.split('#')[0]!.replace(/^\/+/, ''));
      if (full === undefined || visited.has(full)) continue;
      visited.add(full);
      const content = readFile(full);
      if (content !== undefined) walk(split(content)?.front ?? '', dirOf(full), depth + 1);
    }
  };
  walk(split(text)?.front ?? '', dirOf(path), 0);
  return { args, modes, bashAll, edit, webFetch, engine: engineId ?? 'copilot' };
}

/** The `# gh-aw-metadata:` header of a lock file. */
export function lockMetadata(text: string): Record<string, unknown> | undefined {
  const line = /^# gh-aw-metadata:(.*)$/m.exec(text.slice(0, 4096))?.[1];
  if (line === undefined) return undefined;
  try {
    const data = JSON.parse(line) as unknown;
    return isRecord(data) ? data : undefined;
  } catch {
    return undefined;
  }
}

/** Events gh-aw compiles a source trigger into. */
const TRIGGER_EXPANSION: Record<string, readonly string[]> = {
  slash_command: [
    'issues',
    'issue_comment',
    'pull_request',
    'pull_request_review_comment',
    'discussion',
    'discussion_comment',
  ],
  command: [
    'issues',
    'issue_comment',
    'pull_request',
    'pull_request_review_comment',
    'discussion',
    'discussion_comment',
  ],
  label_command: ['issues', 'pull_request', 'discussion'],
};
/** The triggers gh-aw adds when the source has no `on:` at all. */
const DEFAULT_TRIGGERS = ['schedule', 'issues', 'issue_comment', 'pull_request', 'push', 'workflow_dispatch'];

function triggersOf(value: unknown): string[] {
  if (typeof value === 'string') {
    const text = value.trim();
    if (text.startsWith('/')) return ['slash_command', 'workflow_dispatch'];
    if (/^label-command\b/.test(text)) return ['label_command', 'workflow_dispatch'];
    if (/\blabeled\b/.test(text)) return ['issues', 'pull_request', 'discussion', 'workflow_dispatch'];
    return [text, 'schedule', 'workflow_dispatch'];
  }
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string');
  if (isRecord(value)) return Object.keys(value);
  return [];
}

/** Permission flags gh-aw never writes for an engine unless the source asks (engine.args, permission-mode, bash: "*"). */
const CLAUDE_UNLIMITED = /^(--dangerously-skip-permissions|--allow-dangerously-skip-permissions)$/;
const COPILOT_UNLIMITED = /^--(allow-all-tools|allow-all|yolo)(=.*)?$/;
/** gh-aw engines that are agent CLIs the scan recognises. */
const AGENTIC_CLIS = new Set(['claude', 'codex', 'copilot', 'gemini']);
/** Claude permission modes gh-aw writes by default. */
const DEFAULT_MODES = new Set(['dontAsk', 'default']);

/**
 * Why a compiled lock does not match its source: untrusted triggers the source does not have, and
 * agent permission flags or allowed tools the source's front matter does not ask for.
 */
export function lockMismatches(lockText: string, sourceFront: Record<string, unknown>, asks: SourceAsks): string[] {
  const out: string[] = [];
  let lock: unknown;
  try {
    lock = parseYaml(lockText, { maxAliasCount: 50 });
  } catch {
    return ['the lock file is not valid YAML'];
  }
  if (!isRecord(lock)) return ['the lock file is not a workflow'];
  const source = 'on' in sourceFront ? triggersOf(sourceFront['on']) : DEFAULT_TRIGGERS;
  const explained = new Set(source.flatMap(trigger => [trigger, ...(TRIGGER_EXPANSION[trigger] ?? [])]));
  const extra = triggersOf(lock['on']).filter(trigger => UNTRUSTED_TRIGGERS.has(trigger) && !explained.has(trigger));
  if (extra.length) out.push(`triggers ${extra.join(', ')} that the source does not have`);
  const jobs = isRecord(lock['jobs']) ? Object.values(lock['jobs']) : [];
  const flags = new Set<string>();
  for (const job of jobs) {
    if (!isRecord(job) || !Array.isArray(job['steps'])) continue;
    for (const step of job['steps']) {
      if (!isRecord(step) || typeof step['run'] !== 'string') continue;
      for (const call of agentCalls(step['run'])) {
        const args = call.args.flatMap(arg => (/^--[\w-]+=/.test(arg) ? arg.split(/=(.*)/s, 2) : [arg]));
        // gh-aw compiles in the source's engine only: another agent CLI was put there by hand.
        if (call.cli !== 'other' && !call.unknown && call.cli !== asks.engine && AGENTIC_CLIS.has(asks.engine))
          flags.add(`${call.program} (the source's engine is ${asks.engine})`);
        const asked = (word: string) => asks.args.has(word);
        if (call.cli === 'claude') {
          for (const [i, arg] of args.entries()) {
            if (CLAUDE_UNLIMITED.test(arg) && !asked(arg)) flags.add(arg);
            if (arg === '--permission-mode') {
              const mode = args[i + 1] ?? '';
              if (!DEFAULT_MODES.has(mode) && !asks.modes.has(mode) && !asked(mode))
                flags.add(`--permission-mode ${mode}`);
            }
            // Allowed tools the source's tools do not give: every Bash command, web fetches, edits.
            if (arg === '--allowed-tools' || arg === '--allowedTools') {
              // Variadic, split on commas and on spaces outside parentheses, as Claude Code reads it.
              const values: string[] = [];
              for (let k = i + 1; k < args.length && !args[k]!.startsWith('-'); k += 1) values.push(args[k]!);
              const tools = values.flatMap(value => toolNames(value));
              if (!asks.bashAll && tools.some(tool => /^Bash(\((\*|:\*)?\))?$/.test(tool)))
                flags.add('--allowed-tools Bash');
              if (!asks.webFetch && tools.includes('WebFetch')) flags.add('--allowed-tools WebFetch');
              if (!asks.edit && tools.some(tool => /^(Edit|Write|MultiEdit)$/.test(tool)))
                flags.add('--allowed-tools Edit');
            }
          }
        } else if (call.cli === 'copilot') {
          for (const arg of args)
            if (
              COPILOT_UNLIMITED.test(arg) &&
              !asked(arg.split('=')[0]!) &&
              !(arg.startsWith('--allow-all-tools') && asks.bashAll)
            )
              flags.add(arg);
        } else if (call.cli === 'other' || call.unknown) flags.add(`${call.program} (an agent gh-aw does not compile)`);
      }
    }
  }
  if (flags.size) out.push(`agent flags ${[...flags].join(', ')} that the source does not ask for`);
  return out;
}
