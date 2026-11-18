import { parse as parseYaml } from 'yaml';

/** 1-based line of the first occurrence of `needle` at or after `from`; 1 when absent. */
export function lineOf(text: string, needle: string, from = 0): number {
  const index = needle ? text.indexOf(needle, from) : -1;
  return index < 0 ? 1 : lineAt(text, index);
}

/**
 * A fast line finder for large files: line starts are computed once and needles are looked up
 * from a moving cursor (records usually appear in file order), falling back to the start.
 */
export function lineLocator(text: string): (needle: string) => number {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  let cursor = 0;
  return needle => {
    if (!needle) return 1;
    let index = text.indexOf(needle, cursor);
    if (index < 0) index = text.indexOf(needle);
    if (index < 0) return 1;
    cursor = index + needle.length;
    let low = 0;
    let high = starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if (starts[mid]! <= index) low = mid;
      else high = mid - 1;
    }
    return low + 1;
  };
}

/** Line starts of recently used texts: a lookup per call instead of a count from the start. */
const lineStarts = new Map<string, number[]>();

/** 1-based line of a character offset. */
export function lineAt(text: string, index: number): number {
  // Short texts are counted directly; long ones once, then searched.
  if (text.length < 4096) {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i += 1) if (text.charCodeAt(i) === 10) line += 1;
    return line;
  }
  let starts = lineStarts.get(text);
  if (!starts) {
    starts = [0];
    for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) starts.push(i + 1);
    if (lineStarts.size >= 8) lineStarts.delete(lineStarts.keys().next().value!);
    lineStarts.set(text, starts);
  }
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (starts[mid]! <= index) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/**
 * Parses JSON that may contain comments and trailing commas (VS Code and Cursor allow both).
 * Strings are respected: a `//` inside a string is kept.
 */
export function parseJsonc(text: string): unknown {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i += 1;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end < 0 ? n : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += c;
      i += 1;
    }
  }
  // Trailing commas before a closing bracket, outside strings (strings were copied verbatim above,
  // so re-scan with the same rule to avoid touching them).
  let cleaned = '';
  for (let k = 0; k < out.length; k += 1) {
    const ch = out[k]!;
    if (ch === '"') {
      let j = k + 1;
      while (j < out.length && out[j] !== '"') j += out[j] === '\\' ? 2 : 1;
      cleaned += out.slice(k, j + 1);
      k = j;
      continue;
    }
    if (ch === ',') {
      let j = k + 1;
      while (j < out.length && /\s/.test(out[j]!)) j += 1;
      if (out[j] === '}' || out[j] === ']') continue;
    }
    cleaned += ch;
  }
  return JSON.parse(cleaned.replace(/^﻿/, ''));
}

export interface Frontmatter {
  readonly data: Record<string, unknown>;
  readonly body: string;
  /** Lines before the body starts, so body offsets can be turned into file lines. */
  readonly bodyLine: number;
  /** Set when the front matter is there but could not be read (invalid YAML, too many aliases, a duplicate key). */
  readonly error?: string;
}

/** Splits `---` YAML front matter from a Markdown file. Invalid YAML yields empty data. */
export function frontmatter(text: string): Frontmatter {
  const source = text.replace(/^\uFEFF/, '');
  // Claude Code accepts spaces after either delimiter (`---  `).
  const match = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(\r?\n|$)/.exec(source);
  if (!match) return { data: {}, body: source, bodyLine: 1 };
  const body = source.slice(match[0].length);
  const bodyLine = lineAt(source, match[0].length);
  try {
    // Merge keys (`<<: *defaults`) are read, so settings they bring in are seen.
    const parsed = parseYaml(match[1]!, { maxAliasCount: 50, merge: true });
    if (parsed === null || parsed === undefined) return { data: {}, body, bodyLine };
    if (!isRecord(parsed)) return { data: {}, body, bodyLine, error: 'front matter is not a mapping' };
    return { data: parsed, body, bodyLine };
  } catch (error) {
    // Never treated as empty: a caller that grants tools from it must assume the worst.
    return {
      data: {},
      body,
      bodyLine,
      error: (error instanceof Error ? error.message : String(error)).split('\n')[0]!,
    };
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string');
  if (typeof value === 'string')
    return value
      .split(',')
      .map(item => item.trim())
      .filter(Boolean);
  return [];
}

/**
 * A tool list from front matter: a YAML list, or one string split on commas and on spaces outside
 * parentheses, as Claude Code splits `allowed-tools: Read Bash(git log:*) WebFetch`.
 */
export function toolNames(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string').flatMap(toolNames);
  if (typeof value !== 'string') return [];
  const out: string[] = [];
  let depth = 0;
  let word = '';
  for (const char of value) {
    if (char === '(') depth += 1;
    else if (char === ')') depth = Math.max(0, depth - 1);
    if (depth === 0 && (char === ',' || /\s/.test(char))) {
      if (word.trim()) out.push(word.trim());
      word = '';
    } else word += char;
  }
  if (word.trim()) out.push(word.trim());
  return out;
}

/** Characters that hide text from a human reader: zero-width, bidirectional controls, tag characters. */
const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩\u{E0000}-\u{E007F}]/u;

export interface HiddenCharacter {
  readonly line: number;
  readonly codePoint: string;
}

const HIDDEN_ALL = new RegExp(HIDDEN.source, 'gu');
/** Before a joiner: a pictograph, optionally with a variation selector or skin-tone modifier. */
const EMOJI_BEFORE = /\p{Extended_Pictographic}(?:\u{FE0F}|\p{Emoji_Modifier})?$/u;
const EMOJI_AFTER = /^\p{Extended_Pictographic}/u;

/**
 * The first hidden character in a text, ignoring a leading byte-order mark. A zero-width joiner
 * between two pictographs is part of an emoji (🧑‍💻), not hidden text.
 */
export function findHiddenCharacter(text: string): HiddenCharacter | undefined {
  for (const match of text.matchAll(HIDDEN_ALL)) {
    const index = match.index;
    if (
      match[0] === '\u200D' &&
      EMOJI_BEFORE.test(text.slice(Math.max(0, index - 4), index)) &&
      EMOJI_AFTER.test(text.slice(index + 1, index + 3))
    )
      continue;
    const codePoint = match[0].codePointAt(0)!;
    return { line: lineAt(text, index), codePoint: `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}` };
  }
  return undefined;
}

/** Shows only the first and last characters of a secret. */
export function mask(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 6, 12))}${value.slice(-2)}`;
}

/** Line breaks, other C0 and C1 controls, and the invisible characters in HIDDEN. */
const UNSAFE_IN_LINE =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u{E0000}-\u{E007F}]/gu;

/**
 * Makes untrusted text safe for one line of a log: controls and line breaks become spaces, and a
 * line cannot start with `::`, which GitHub Actions reads as a workflow command (annotations,
 * add-mask, stop-commands).
 */
export function oneLine(text: string): string {
  return text.replace(UNSAFE_IN_LINE, ' ').replace(/^(\s*):(?=:)/, '$1: ');
}

/**
 * Top-level `key: value` lines of front matter, read the way Claude Code reads a subagent file when
 * the block is not valid YAML (an unquoted `Examples: ...` inside a description, for example).
 * Undefined when there is no front matter block or no such line.
 */
export function lenientFrontmatter(text: string): Record<string, unknown> | undefined {
  const match = /^\uFEFF?---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(\r?\n|$)/.exec(text);
  if (!match) return undefined;
  const out: Record<string, unknown> = {};
  for (const line of match[1]!.split(/\r?\n/)) {
    // The value is trimmed below, so the spaces after the colon need no pattern of their own.
    const pair = /^([A-Za-z][\w-]*):(.*)$/.exec(line);
    if (!pair) continue;
    const value = pair[2]!.trim().replace(/^(["'])(.*)\1$/, '$2');
    if (pair[1]! in out) return undefined; // A key set twice: which one wins is not clear.
    out[pair[1]!] = value;
  }
  return Object.keys(out).length ? out : undefined;
}
