import type { Json } from '@shieldaai/agent-guard';
import { AdapterError } from './errors.js';

/** One reason a value failed a schema. `path` is an RFC 6901 JSON Pointer into the value. */
export interface SchemaIssue {
  readonly path: string;
  /** The schema keyword that failed, for example `required` or `maxLength`. */
  readonly keyword: string;
  /** The safe detail code a parser throws for this keyword, for example SCHEMA_REQUIRED. */
  readonly code: string;
}

/** Options for `jsonSchemaParser()` and `validateJsonSchema()`. */
export interface JsonSchemaOptions {
  /**
   * What to do with object properties the schema does not list when it says nothing about
   * `additionalProperties`. `'schema'` follows JSON Schema and allows them (default);
   * `'reject'` refuses them; `'strip'` drops them from the parsed value (outside `anyOf`,
   * `oneOf`, `allOf` and `not`, where values are checked but never changed).
   */
  additionalProperties?: 'schema' | 'reject' | 'strip';
  /**
   * Allow `pattern` values with a quantified group that contains a quantifier, such as
   * `(a+)+`. Refused by default: patterns run on model input, and that shape can take
   * exponential time. Default false.
   */
  allowNestedQuantifiers?: boolean;
}

type Schema = boolean | { readonly [key: string]: unknown };

const ANNOTATIONS = new Set([
  '$schema',
  '$id',
  '$comment',
  'title',
  'description',
  'examples',
  'default',
  'deprecated',
  'readOnly',
  'writeOnly',
  'format',
  'contentMediaType',
  'contentEncoding',
]);
const KEYWORDS = new Set([
  'type',
  'enum',
  'const',
  'nullable',
  'properties',
  'required',
  'additionalProperties',
  'minProperties',
  'maxProperties',
  'items',
  'minItems',
  'maxItems',
  'uniqueItems',
  'minLength',
  'maxLength',
  'pattern',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'multipleOf',
  'anyOf',
  'oneOf',
  'allOf',
  'not',
]);
const TYPES = new Set(['null', 'boolean', 'object', 'array', 'number', 'integer', 'string']);
const CODES: Readonly<Record<string, string>> = Object.freeze({
  type: 'SCHEMA_TYPE',
  enum: 'SCHEMA_ENUM',
  const: 'SCHEMA_CONST',
  required: 'SCHEMA_REQUIRED',
  additionalProperties: 'SCHEMA_ADDITIONAL_PROPERTIES',
  minProperties: 'SCHEMA_PROPERTY_COUNT',
  maxProperties: 'SCHEMA_PROPERTY_COUNT',
  minItems: 'SCHEMA_ITEMS',
  maxItems: 'SCHEMA_ITEMS',
  uniqueItems: 'SCHEMA_ITEMS',
  minLength: 'SCHEMA_LENGTH',
  maxLength: 'SCHEMA_LENGTH',
  pattern: 'SCHEMA_PATTERN',
  minimum: 'SCHEMA_RANGE',
  maximum: 'SCHEMA_RANGE',
  exclusiveMinimum: 'SCHEMA_RANGE',
  exclusiveMaximum: 'SCHEMA_RANGE',
  multipleOf: 'SCHEMA_MULTIPLE_OF',
  anyOf: 'SCHEMA_COMBINATION',
  oneOf: 'SCHEMA_COMBINATION',
  allOf: 'SCHEMA_COMBINATION',
  not: 'SCHEMA_COMBINATION',
});

function pointer(base: string, token: string | number): string {
  return `${base}/${String(token).replaceAll('~', '~0').replaceAll('/', '~1')}`;
}
function isRecord(value: unknown): value is { readonly [key: string]: unknown } {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

type Compiled = { patterns: Map<string, RegExp>; allowNestedQuantifiers: boolean };
/**
 * True when a quantified group contains a variable quantifier at any depth, such as `(a+)+`,
 * `((a+))+`, `(?:a*b?)*` or `(a+){12}`: the shape behind catastrophic backtracking. A small
 * tokenizer, so escapes (`\\(`, `\\p{L}`) and character classes (`[)+]`) are not mistaken for
 * groups or quantifiers. Overlapping alternatives such as `(a|a)+` are not detected.
 */
export function hasNestedQuantifier(pattern: string): boolean {
  const stack: { inner: boolean }[] = [{ inner: false }];
  let index = 0;
  /** Reads a quantifier at `index`; returns its bounds, or undefined. */
  const quantifier = (): { min: number; max: number } | undefined => {
    const char = pattern[index];
    let bounds: { min: number; max: number } | undefined;
    if (char === '*') bounds = { min: 0, max: Infinity };
    else if (char === '+') bounds = { min: 1, max: Infinity };
    else if (char === '?') bounds = { min: 0, max: 1 };
    else if (char === '{') {
      const match = /^\{(\d+)(,(\d*))?\}/.exec(pattern.slice(index));
      if (!match) return undefined;
      const min = Number(match[1]);
      const max = match[2] === undefined ? min : match[3] === '' ? Infinity : Number(match[3]);
      index += match[0].length;
      if (pattern[index] === '?') index += 1;
      return { min, max };
    } else return undefined;
    index += 1;
    if (pattern[index] === '?') index += 1; // lazy
    return bounds;
  };
  const markVariable = () => {
    stack[stack.length - 1]!.inner = true;
  };
  while (index < pattern.length) {
    const char = pattern[index]!;
    if (char === '\\') {
      const next = pattern[index + 1];
      index += 2;
      if ((next === 'p' || next === 'P' || next === 'u' || next === 'x') && pattern[index] === '{') {
        const close = pattern.indexOf('}', index);
        index = close < 0 ? pattern.length : close + 1;
      } else if (next === 'k' && pattern[index] === '<') {
        const close = pattern.indexOf('>', index);
        index = close < 0 ? pattern.length : close + 1;
      }
    } else if (char === '[') {
      index += 1;
      while (index < pattern.length && pattern[index] !== ']') index += pattern[index] === '\\' ? 2 : 1;
      index += 1;
    } else if (char === '(') {
      stack.push({ inner: false });
      index += 1;
      continue;
    } else if (char === ')') {
      index += 1;
      const group = stack.length > 1 ? stack.pop()! : { inner: false };
      const bounds = quantifier();
      if (bounds && bounds.max > 1 && group.inner) return true;
      if (group.inner || (bounds && bounds.max !== bounds.min)) markVariable();
      continue;
    } else index += 1;
    const bounds = quantifier();
    if (bounds && bounds.max !== bounds.min) markVariable();
  }
  return false;
}

/** Checks that every keyword is one this module enforces; compiles patterns once. */
function compile(schema: unknown, at: string, compiled: Compiled): void {
  if (typeof schema === 'boolean') return;
  if (!isRecord(schema)) throw new AdapterError('UNSUPPORTED_SCHEMA', at || '/');
  for (const [key, value] of Object.entries(schema)) {
    const here = pointer(at, key);
    if (ANNOTATIONS.has(key)) continue;
    if (!KEYWORDS.has(key)) throw new AdapterError('UNSUPPORTED_SCHEMA', here);
    switch (key) {
      case 'type': {
        const types = Array.isArray(value) ? value : [value];
        if (types.length === 0 || types.some(type => typeof type !== 'string' || !TYPES.has(type)))
          throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      }
      case 'enum':
        if (!Array.isArray(value) || value.length === 0) throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      case 'nullable':
      case 'uniqueItems':
        if (typeof value !== 'boolean') throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      case 'properties':
        if (!isRecord(value)) throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        for (const [name, child] of Object.entries(value)) compile(child, pointer(here, name), compiled);
        break;
      case 'required':
        if (!Array.isArray(value) || value.some(name => typeof name !== 'string'))
          throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      case 'additionalProperties':
      case 'items':
      case 'not':
        // Tuple-form `items` (an array) is not supported.
        compile(value, here, compiled);
        break;
      case 'anyOf':
      case 'oneOf':
      case 'allOf':
        if (!Array.isArray(value) || value.length === 0) throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        value.forEach((child, index) => compile(child, pointer(here, index), compiled));
        break;
      case 'minProperties':
      case 'maxProperties':
      case 'minItems':
      case 'maxItems':
      case 'minLength':
      case 'maxLength':
        if (!isNonNegativeInteger(value)) throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      case 'minimum':
      case 'maximum':
      case 'exclusiveMinimum':
      case 'exclusiveMaximum':
        if (typeof value !== 'number' || !Number.isFinite(value)) throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      case 'multipleOf':
        if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0)
          throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        break;
      case 'pattern':
        if (typeof value !== 'string') throw new AdapterError('UNSUPPORTED_SCHEMA', here);
        if (!compiled.allowNestedQuantifiers && hasNestedQuantifier(value))
          throw new AdapterError('UNSUPPORTED_SCHEMA', `${here} (nested quantifier)`);
        if (!compiled.patterns.has(value)) {
          try {
            compiled.patterns.set(value, new RegExp(value, 'u'));
          } catch {
            throw new AdapterError('UNSUPPORTED_SCHEMA', here);
          }
        }
        break;
      default:
        break;
    }
  }
}

function equal(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    const other = b as unknown[];
    return a.length === other.length && a.every((item, index) => equal(item, other[index]));
  }
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every(key => Object.hasOwn(right, key) && equal(left[key], right[key]))
  );
}

function typeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}
function hasType(value: unknown, type: string): boolean {
  switch (type) {
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    default:
      return typeOf(value) === type;
  }
}

/** Exact for integer steps; for decimal steps, exact at the step's own number of decimals. */
function isMultipleOf(value: number, step: number): boolean {
  // The remainder of two doubles is exact, so an integer step needs no tolerance.
  if (Number.isInteger(step)) return Number.isInteger(value) && value % step === 0;
  const text = String(step);
  const decimals = /e/i.test(text) ? -1 : (text.split('.')[1]?.length ?? 0);
  if (decimals < 0 || decimals > 15) {
    const quotient = value / step;
    return Math.abs(quotient - Math.round(quotient)) <= Number.EPSILON * Math.max(1, Math.abs(quotient)) * 4;
  }
  const scale = 10 ** decimals;
  const scaled = value * scale;
  // Past 2^53 the product is no longer exact; refuse rather than guess.
  if (!Number.isSafeInteger(Math.round(scaled)) || !Number.isSafeInteger(Math.round(step * scale))) return false;
  const rounded = Math.round(scaled);
  if (Math.abs(scaled - rounded) > Number.EPSILON * Math.max(1, Math.abs(scaled)) * 4) return false;
  return rounded % Math.round(step * scale) === 0;
}

/** Canonical JSON (sorted keys), so equal values give equal text. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map(key => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(',')}}`;
}
/** Linear-time uniqueness: one canonical text per item. */
function allDistinct(items: readonly unknown[]): boolean {
  const seen = new Set<string>();
  for (const item of items) {
    const key = canonical(item);
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

/** Property names an object schema declares, including those of its allOf, anyOf and oneOf branches. */
function declaredNames(schema: { readonly [key: string]: unknown }): ReadonlySet<string> {
  const names = new Set<string>();
  const visit = (node: unknown) => {
    if (!isRecord(node)) return;
    if (isRecord(node.properties)) for (const name of Object.keys(node.properties)) names.add(name);
    if (Array.isArray(node.required)) for (const name of node.required) if (typeof name === 'string') names.add(name);
    for (const keyword of ['allOf', 'anyOf', 'oneOf'])
      if (Array.isArray(node[keyword])) for (const branch of node[keyword] as unknown[]) visit(branch);
  };
  visit(schema);
  return names;
}

class Validator {
  readonly issues: SchemaIssue[] = [];
  constructor(
    readonly compiled: Compiled,
    readonly extra: 'schema' | 'reject' | 'strip',
  ) {}
  #issue(path: string, keyword: string): void {
    this.issues.push(Object.freeze({ path: path || '/', keyword, code: CODES[keyword] ?? 'SCHEMA_MISMATCH' }));
  }
  /** Validates and returns the (possibly stripped) value. `transform` is false inside combinators. */
  check(schema: Schema, value: unknown, path: string, transform: boolean): unknown {
    if (schema === true) return value;
    if (schema === false) {
      this.#issue(path, 'not');
      return value;
    }
    const s = schema;
    const before = this.issues.length;
    if (s.type !== undefined) {
      const types = (Array.isArray(s.type) ? s.type : [s.type]) as string[];
      const nullOk = s.nullable === true && value === null;
      if (!nullOk && !types.some(type => hasType(value, type))) {
        this.#issue(path, 'type');
        return value;
      }
    }
    if (s.enum !== undefined && !(s.enum as unknown[]).some(option => equal(option, value))) this.#issue(path, 'enum');
    if (s.const !== undefined && !equal(s.const, value)) this.#issue(path, 'const');
    let result = value;
    if (typeof value === 'string') {
      const length = [...value].length;
      const tooShort = typeof s.minLength === 'number' && length < s.minLength;
      const tooLong = typeof s.maxLength === 'number' && length > s.maxLength;
      if (tooShort) this.#issue(path, 'minLength');
      if (tooLong) this.#issue(path, 'maxLength');
      // A text over its bound is never run through the pattern: that bounds the regex work.
      if (!tooLong && typeof s.pattern === 'string' && !this.compiled.patterns.get(s.pattern)!.test(value))
        this.#issue(path, 'pattern');
    } else if (typeof value === 'number') {
      if (typeof s.minimum === 'number' && value < s.minimum) this.#issue(path, 'minimum');
      if (typeof s.maximum === 'number' && value > s.maximum) this.#issue(path, 'maximum');
      if (typeof s.exclusiveMinimum === 'number' && value <= s.exclusiveMinimum) this.#issue(path, 'exclusiveMinimum');
      if (typeof s.exclusiveMaximum === 'number' && value >= s.exclusiveMaximum) this.#issue(path, 'exclusiveMaximum');
      if (typeof s.multipleOf === 'number' && !isMultipleOf(value, s.multipleOf)) this.#issue(path, 'multipleOf');
    } else if (Array.isArray(value)) {
      const tooMany = typeof s.maxItems === 'number' && value.length > s.maxItems;
      if (typeof s.minItems === 'number' && value.length < s.minItems) this.#issue(path, 'minItems');
      if (tooMany) this.#issue(path, 'maxItems');
      // Past maxItems the items are not examined at all, so an oversized list costs one comparison.
      if (!tooMany && s.uniqueItems === true && !allDistinct(value)) this.#issue(path, 'uniqueItems');
      if (!tooMany && s.items !== undefined) {
        const items = value.map((item, index) => this.check(s.items as Schema, item, pointer(path, index), transform));
        if (transform) result = items;
      }
    } else if (isRecord(value)) {
      const properties = (isRecord(s.properties) ? s.properties : {}) as Record<string, Schema>;
      const declared = this.extra === 'schema' ? undefined : declaredNames(s);
      const keys = Object.keys(value);
      if (typeof s.minProperties === 'number' && keys.length < s.minProperties) this.#issue(path, 'minProperties');
      if (typeof s.maxProperties === 'number' && keys.length > s.maxProperties) this.#issue(path, 'maxProperties');
      for (const name of (s.required as string[] | undefined) ?? [])
        if (!Object.hasOwn(value, name)) this.#issue(pointer(path, name), 'required');
      const out: Record<string, unknown> = {};
      // defineProperty, not assignment: an own "__proto__" key must stay an ordinary key.
      const put = (key: string, child: unknown) =>
        Object.defineProperty(out, key, { value: child, enumerable: true, writable: true, configurable: true });
      for (const key of keys) {
        const child = value[key];
        if (Object.hasOwn(properties, key)) {
          put(key, this.check(properties[key]!, child, pointer(path, key), transform));
        } else if (s.additionalProperties === false) {
          this.#issue(pointer(path, key), 'additionalProperties');
        } else if (s.additionalProperties !== undefined) {
          put(key, this.check(s.additionalProperties as Schema, child, pointer(path, key), transform));
        } else if (this.extra === 'reject' && !declared!.has(key)) {
          this.#issue(pointer(path, key), 'additionalProperties');
        } else if (this.extra === 'strip' && transform && !declared!.has(key)) {
          // Dropped from the parsed value.
        } else put(key, child);
      }
      if (transform) result = out;
    }
    const branch = (child: Schema) => {
      // Branches check their own constraints; unknown properties are judged once, by the
      // enclosing object, against every name it and its branches declare.
      const nested = new Validator(this.compiled, 'schema');
      nested.check(child, value, path, false);
      return nested.issues.length === 0;
    };
    if (Array.isArray(s.allOf) && !(s.allOf as Schema[]).every(branch)) this.#issue(path, 'allOf');
    if (Array.isArray(s.anyOf) && !(s.anyOf as Schema[]).some(branch)) this.#issue(path, 'anyOf');
    if (Array.isArray(s.oneOf) && (s.oneOf as Schema[]).filter(branch).length !== 1) this.#issue(path, 'oneOf');
    if (s.not !== undefined && branch(s.not as Schema)) this.#issue(path, 'not');
    return this.issues.length === before ? result : value;
  }
}

function prepare(schema: unknown, options: JsonSchemaOptions | undefined) {
  const extra = options?.additionalProperties ?? 'schema';
  if (!['schema', 'reject', 'strip'].includes(extra)) throw new AdapterError('INVALID_OPTIONS');
  const allowNestedQuantifiers = options?.allowNestedQuantifiers ?? false;
  if (typeof allowNestedQuantifiers !== 'boolean') throw new AdapterError('INVALID_OPTIONS');
  const compiled: Compiled = { patterns: new Map(), allowNestedQuantifiers };
  compile(schema, '', compiled);
  return { compiled, extra, schema: schema as Schema };
}

/**
 * Checks a value against a JSON Schema and lists every issue. Supports the keywords tool
 * schemas use (types, properties, required, additionalProperties, enum, const, string, number
 * and array bounds, pattern, items, anyOf, oneOf, allOf, not, nullable); any other keyword,
 * including `$ref`, throws UNSUPPORTED_SCHEMA rather than being silently ignored.
 */
export function validateJsonSchema(
  schema: unknown,
  value: unknown,
  options?: JsonSchemaOptions,
): { readonly valid: boolean; readonly issues: readonly SchemaIssue[] } {
  const { compiled, extra, schema: root } = prepare(schema, options);
  const validator = new Validator(compiled, extra);
  validator.check(root, value, '', false);
  return Object.freeze({ valid: validator.issues.length === 0, issues: Object.freeze(validator.issues) });
}

/**
 * A synchronous `parse` for a tool definition, built from the same JSON Schema the model is
 * shown, so the model's arguments are enforced, not just described. The schema is checked
 * once, here. On a mismatch the parser throws with a safe `code` (for example SCHEMA_REQUIRED),
 * which the guard reports as ARGUMENT_INVALID with that detail and the dispatcher turns into
 * a hint the model can act on; the failing value is never included. The optional type
 * parameter names the parsed type for `defineTool`; it is not checked against the schema.
 */
export function jsonSchemaParser<Args extends Json = Json>(
  schema: unknown,
  options?: JsonSchemaOptions,
): (input: Json) => Args {
  const { compiled, extra, schema: root } = prepare(schema, options);
  return function parse(input: Json): Args {
    const validator = new Validator(compiled, extra);
    const value = validator.check(root, input, '', true);
    const first = validator.issues[0];
    if (first) throw Object.assign(new Error('Arguments do not match the schema'), { code: first.code });
    return value as Args;
  };
}
