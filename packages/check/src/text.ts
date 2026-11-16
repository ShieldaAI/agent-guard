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

/** 1-based line of a character offset. */
export function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
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
}

/** Splits `---` YAML front matter from a Markdown file. Invalid YAML yields empty data. */
export function frontmatter(text: string): Frontmatter {
  const source = text.replace(/^﻿/, '');
  const match = /^---\r?\n([\s\S]*?)\r?\n---[ \t]*(\r?\n|$)/.exec(source);
  if (!match) return { data: {}, body: source, bodyLine: 1 };
  let data: Record<string, unknown> = {};
  try {
    const parsed = parseYaml(match[1]!, { maxAliasCount: 50 });
    if (isRecord(parsed)) data = parsed;
  } catch {
    data = {};
  }
  return { data, body: source.slice(match[0].length), bodyLine: lineAt(source, match[0].length) };
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

/** Characters that hide text from a human reader: zero-width, bidirectional controls, tag characters. */
const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩\u{E0000}-\u{E007F}]/u;

export interface HiddenCharacter {
  readonly line: number;
  readonly codePoint: string;
}

/** The first hidden character in a text, ignoring a leading byte-order mark. */
export function findHiddenCharacter(text: string): HiddenCharacter | undefined {
  const match = HIDDEN.exec(text);
  if (!match) return undefined;
  const codePoint = match[0].codePointAt(0)!;
  return { line: lineAt(text, match.index), codePoint: `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}` };
}

/** Shows only the first and last characters of a secret. */
export function mask(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(value.length - 6, 12))}${value.slice(-2)}`;
}
