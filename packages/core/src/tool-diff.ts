import { canonicalJson, immutableJson, type JsonObject, type JsonValue } from './json.js';
import { GuardError } from './types.js';
import type { Json, ToolChange, ToolChangeHint, ToolDefinitionDiff } from './types.js';

/** Most changes one diff reports. More than this sets `truncated`. */
export const MAX_TOOL_CHANGES = 256;

function isObject(value: JsonValue): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function isPrimitiveArray(value: JsonValue): value is readonly JsonValue[] {
  return Array.isArray(value) && value.every(item => item === null || typeof item !== 'object');
}
/** One RFC 6901 reference token. */
function token(key: string): string {
  return key.replaceAll('~', '~0').replaceAll('/', '~1');
}
function same(a: JsonValue, b: JsonValue): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  return canonicalJson(a) === canonicalJson(b);
}

// Heuristics only. They point a reviewer at a change; they never decide anything.
const INSTRUCTION_TEXT = new RegExp(
  [
    String.raw`\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|other|system|instructions?|rules?|polic(y|ies)|approvals?|checks?)\b`,
    String.raw`\b(do not|don't|never)\s+(tell|mention|reveal|inform|show|disclose|ask|notify|warn)\b`,
    String.raw`\byou\s+(must|should|need to|have to|are required to|are now|will)\b`,
    String.raw`\b(always|first|before (using|calling|invoking|you|any))\b[^.\n]{0,60}\b(call|read|send|include|pass|run|execute|use|invoke|fetch|upload|forward|copy)\b`,
    String.raw`\bsystem prompt\b`,
    String.raw`<\s*(?:/\s*)?(important|system|instructions?|secret|admin)\b`,
    String.raw`\b(secretly|silently|quietly|without (telling|asking|informing|notifying|mentioning))\b`,
    String.raw`\b(api[_ -]?keys?|passwords?|credentials?|private keys?|access tokens?|id_rsa|\.env|\.ssh)\b`,
  ].join('|'),
  'i',
);
// Characters a reader does not see: C0/C1 controls (not tab, LF, CR), soft hyphen, zero-width and
// bidirectional marks, invisible fillers, line and paragraph separators, variation selectors and tags.
const HIDDEN_CHARACTERS =
  /[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F-\u1160\u17B4-\u17B5\u180B-\u180F\u200B-\u200F\u2028-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]|[\u{E0000}-\u{E01EF}]/u;

/** Every string in a value, keys included, visited once each. */
function strings(value: JsonValue | undefined, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, out);
  else if (value !== undefined && isObject(value))
    for (const key of Object.keys(value)) {
      out.push(key);
      strings(value[key]!, out);
    }
  return out;
}

const SCHEMA_CONTAINERS = new Set(['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas']);
/** Constraints whose removal, or any change, accepts input that was refused before. */
const CONSTRAINTS = new Set([
  'pattern',
  'const',
  'format',
  'not',
  'propertyNames',
  'uniqueItems',
  'multipleOf',
  'dependentRequired',
  'contentEncoding',
  'contentMediaType',
]);
const UPPER_BOUNDS = new Set(['maximum', 'exclusiveMaximum', 'maxLength', 'maxItems', 'maxProperties', 'maxContains']);
const LOWER_BOUNDS = new Set(['minimum', 'exclusiveMinimum', 'minLength', 'minItems', 'minProperties', 'minContains']);
const CLOSED = new Set(['additionalProperties', 'unevaluatedProperties', 'additionalItems', 'unevaluatedItems']);
const UNTRUSTED_RANK: Readonly<Record<string, number>> = Object.freeze({ allow: 0, require_approval: 1, deny: 2 });

function list(value: JsonValue | undefined): readonly JsonValue[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}
function missingFrom(items: readonly JsonValue[], others: readonly JsonValue[]): boolean {
  const known = new Set(others.map(canonicalJson));
  return items.some(item => !known.has(canonicalJson(item)));
}

function flagLoosened(key: string, before: JsonValue | undefined, after: JsonValue | undefined): boolean {
  switch (key) {
    case 'requiresApproval':
    case 'controlPlane':
    case 'parsedArguments':
    case 'readsUntrusted':
      return before === true && after !== true;
    case 'sendsExternal':
      return before === false && after !== false;
    case 'untrustedContext': {
      // Absent means the guard's default, which this comparison cannot see: an explicit
      // 'allow' that was not there before is marked too.
      const was = typeof before === 'string' ? (UNTRUSTED_RANK[before] ?? 0) : undefined;
      const now = typeof after === 'string' ? (UNTRUSTED_RANK[after] ?? 0) : undefined;
      return was === undefined ? now === 0 : (now ?? 0) < was;
    }
    case 'maxCost':
      return typeof before === 'number' && typeof after === 'number' && after > before;
    default:
      return false;
  }
}

function schemaLoosened(key: string, before: JsonValue | undefined, after: JsonValue | undefined): boolean {
  if (key === 'required') return missingFrom(list(before), list(after));
  if (key === 'enum') return after === undefined || missingFrom(list(after), list(before));
  if (key === 'type') return after === undefined || missingFrom(list(after), list(before));
  if (CONSTRAINTS.has(key)) return before !== undefined;
  if (CLOSED.has(key)) return before === false && after !== false;
  if (UPPER_BOUNDS.has(key)) return typeof before === 'number' && (typeof after !== 'number' || after > before);
  if (LOWER_BOUNDS.has(key)) return typeof before === 'number' && (typeof after !== 'number' || after < before);
  return false;
}

/** Fields of a tool definition that are never dropped from a truncated diff. */
const ALWAYS_LISTED = new Set([
  'name',
  'description',
  'requiresApproval',
  'controlPlane',
  'maxCost',
  'parsedArguments',
  'readsUntrusted',
  'untrustedContext',
  'sendsExternal',
]);

/**
 * Where the last segment of a path below `inputSchema` stands: a schema keyword, or a name
 * inside `container` (a property called `required` or `properties` is a name, not a keyword).
 */
function schemaPosition(segments: readonly string[]): { named: boolean; container: string | undefined } | undefined {
  const start = segments.indexOf('inputSchema');
  if (start === -1 || start === segments.length - 1) return undefined;
  let named = false;
  let container: string | undefined;
  for (let index = start + 1; index < segments.length; index++) {
    if (named) {
      // This segment is a name; what follows it is a schema again.
      if (index === segments.length - 1) return { named: true, container };
      named = false;
    } else if (SCHEMA_CONTAINERS.has(segments[index]!)) {
      container = segments[index]!;
      named = true;
    }
  }
  return { named: false, container: undefined };
}

function hintsFor(
  segments: readonly string[],
  kind: ToolChange['kind'],
  before: JsonValue | undefined,
  after: JsonValue | undefined,
): readonly ToolChangeHint[] {
  const hints: ToolChangeHint[] = [];
  const key = segments.at(-1);
  // New text only: a string that was already approved is not flagged again.
  const old = new Set(strings(before));
  const added = strings(after).filter(text => !old.has(text));
  if (kind === 'added' && key !== undefined) added.push(key);
  if (added.some(text => INSTRUCTION_TEXT.test(text))) hints.push('INSTRUCTION_TEXT');
  if (added.some(text => HIDDEN_CHARACTERS.test(text))) hints.push('HIDDEN_CHARACTERS');
  if (key !== undefined && segments.length === 1 && flagLoosened(key, before, after)) hints.push('FLAG_LOOSENED');
  const position = schemaPosition(segments);
  if (key !== undefined && position !== undefined) {
    const { named, container } = position;
    if (
      kind === 'added' &&
      (named ? container === 'properties' || container === 'patternProperties' : SCHEMA_CONTAINERS.has(key))
    )
      hints.push('SCHEMA_FIELD_ADDED');
    const parent = segments.at(-2);
    // One more alternative accepts more input.
    const alternative = kind === 'added' && !named && (parent === 'anyOf' || parent === 'oneOf');
    if (!named && (alternative || schemaLoosened(key, before, after))) hints.push('SCHEMA_LOOSENED');
  }
  return Object.freeze(hints);
}

function compare(before: JsonValue, after: JsonValue): ToolDefinitionDiff {
  const changes: ToolChange[] = [];
  let truncated = false;
  let listed = 0;
  const record = (
    segments: readonly string[],
    kind: ToolChange['kind'],
    old: JsonValue | undefined,
    next: JsonValue | undefined,
  ): void => {
    // The guard's own fields are always listed: a long schema diff cannot push a weakened flag out.
    const always = segments.length === 1 && ALWAYS_LISTED.has(segments[0]!);
    if (listed >= MAX_TOOL_CHANGES && !always) {
      truncated = true;
      return;
    }
    if (!always) listed++;
    changes.push(
      Object.freeze({
        path: segments.map(segment => `/${token(segment)}`).join(''),
        kind,
        ...(old === undefined ? {} : { before: old as Json }),
        ...(next === undefined ? {} : { after: next as Json }),
        hints: hintsFor(segments, kind, old, next),
      }),
    );
  };
  const visit = (old: JsonValue, next: JsonValue, segments: readonly string[]): void => {
    if (truncated && segments.length > 1) return;
    if (isObject(old) && isObject(next)) {
      const keys = new Set([...Object.keys(old), ...Object.keys(next)]);
      for (const key of [...keys].sort()) {
        const path = [...segments, key];
        if (!Object.hasOwn(next, key)) record(path, 'removed', old[key]!, undefined);
        else if (!Object.hasOwn(old, key)) record(path, 'added', undefined, next[key]!);
        else visit(old[key]!, next[key]!, path);
      }
      return;
    }
    // Lists of plain values (required, enum, type) read best whole; lists of objects go by index.
    if (Array.isArray(old) && Array.isArray(next) && !(isPrimitiveArray(old) && isPrimitiveArray(next))) {
      const shared = Math.min(old.length, next.length);
      for (let index = 0; index < shared; index++) visit(old[index]!, next[index]!, [...segments, String(index)]);
      for (let index = shared; index < old.length; index++)
        record([...segments, String(index)], 'removed', old[index]!, undefined);
      for (let index = shared; index < next.length; index++)
        record([...segments, String(index)], 'added', undefined, next[index]!);
      return;
    }
    if (!same(old, next)) record(segments, 'changed', old, next);
  };
  visit(before, after, []);
  return Object.freeze({ changes: Object.freeze(changes), truncated });
}

/** For values the guard already copied and froze. */
export function diffFrozenDefinitions(before: JsonValue, after: JsonValue): ToolDefinitionDiff {
  return compare(before, after);
}

/**
 * Compares two JSON definitions structurally and returns one entry per changed JSON path, in
 * path order. `path` is an RFC 6901 JSON Pointer. Objects are compared key by key; arrays
 * that hold objects are compared by index; arrays of plain values (`required`, `enum`) and
 * everything else are compared whole. At most 256 changes are returned, plus the top-level
 * guard fields (`description`, `requiresApproval` and the other flags), which are never
 * dropped; `truncated` says when there were more. `hints` are heuristics for a human reviewer, never a verdict: an
 * empty list does not mean a change is safe. Throws INVALID_JSON when a value is not plain
 * JSON within the default limits.
 */
export function diffToolDefinitions(before: unknown, after: unknown): ToolDefinitionDiff {
  let old: JsonValue;
  let next: JsonValue;
  try {
    old = immutableJson(before);
    next = immutableJson(after);
  } catch {
    throw new GuardError('INVALID_JSON', 'INVALID_JSON');
  }
  return compare(old, next);
}
