import { type Json } from '@shieldaai/agent-guard';
import { canonicalJson } from '@shieldaai/agent-guard/internal';
import { Ajv } from '@modelcontextprotocol/client/validators/ajv';
import { isProxy } from 'node:util/types';

/** Every code the MCP boundary can throw. Codes never carry request or server data. */
export type McpBoundaryErrorCode =
  | 'ACTIVE_CONTENT_DENIED'
  | 'ARGUMENTS_INVALID'
  | 'AUTHORIZATION_DENIED'
  | 'CAPABILITY_DENIED'
  | 'CONNECTION_CHANGED'
  | 'CONNECTION_FAILED'
  | 'CONNECTION_UNAVAILABLE'
  | 'CREDENTIAL_REFLECTED'
  | 'CREDENTIAL_REPLACEMENT_PENDING'
  | 'ENDPOINT_DENIED'
  | 'IDENTITY_DENIED'
  | 'INVALID_ARGUMENTS'
  | 'INVALID_CONFIGURATION'
  | 'INVALID_JSON'
  | 'JSON_LIMIT'
  | 'MCP_INVENTORY_CLOCK_INVALID'
  | 'MCP_INVENTORY_INVALID'
  | 'MCP_INVENTORY_LIMIT_EXCEEDED'
  | 'MCP_OPERATION_FAILED'
  | 'MESSAGE_BUDGET'
  | 'MESSAGE_REJECTED'
  | 'REDIRECT_DENIED'
  | 'REGISTRY_LIMIT'
  | 'REGISTRY_REJECTED'
  | 'RESOURCE_MISMATCH'
  | 'RESPONSE_LIMIT'
  | 'SCHEMA_INVALID'
  | 'SCHEMA_LIMIT'
  | 'SCHEMA_REFERENCE_DENIED'
  | 'SCHEMA_UNSUPPORTED';
export class McpBoundaryError extends Error {
  constructor(readonly code: McpBoundaryErrorCode) {
    super(code);
    this.name = 'McpBoundaryError';
  }
}

export interface JsonLimits {
  maxBytes: number;
  maxNodes: number;
  maxDepth: number;
}
export const MESSAGE_LIMITS: Readonly<JsonLimits> = Object.freeze({
  maxBytes: 1_048_576,
  maxNodes: 10_000,
  maxDepth: 32,
});
const SCHEMA_LIMITS = Object.freeze({ maxBytes: 65_536, maxNodes: 2_048, maxDepth: 16 });

/** Copies only JSON data properties, without invoking getters or toJSON hooks. */
export function boundedJson(input: unknown, limits: JsonLimits = MESSAGE_LIMITS): Json {
  const seen = new Set<object>();
  let nodes = 0;
  let bytes = 0;
  function copy(value: unknown, depth: number): Json {
    if (++nodes > limits.maxNodes || depth > limits.maxDepth) throw new McpBoundaryError('JSON_LIMIT');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      bytes += Buffer.byteLength(value);
      if (bytes > limits.maxBytes) throw new McpBoundaryError('JSON_LIMIT');
      return value;
    }
    if (typeof value !== 'object' || value === null || isProxy(value) || seen.has(value))
      throw new McpBoundaryError('INVALID_JSON');
    if (
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null
    )
      throw new McpBoundaryError('INVALID_JSON');
    seen.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result: Json[] | Record<string, Json> = Array.isArray(value) ? [] : Object.create(null);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (Array.isArray(value) && key === 'length') continue;
      if (typeof key !== 'string') throw new McpBoundaryError('INVALID_JSON');
      const descriptor = descriptors[key]!;
      if (!descriptor.enumerable || !('value' in descriptor)) throw new McpBoundaryError('INVALID_JSON');
      // SDK in-memory transports retain absent optional fields; JSON wire transports omit them.
      if (!Array.isArray(value) && descriptor.value === undefined) continue;
      if (Array.isArray(value) && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))
        throw new McpBoundaryError('INVALID_JSON');
      bytes += Buffer.byteLength(key);
      if (bytes > limits.maxBytes) throw new McpBoundaryError('JSON_LIMIT');
      Object.defineProperty(result, key, { value: copy(descriptor.value, depth + 1), enumerable: true });
    }
    if (Array.isArray(value) && Object.keys(result).length !== value.length) throw new McpBoundaryError('INVALID_JSON');
    seen.delete(value);
    return Object.freeze(result);
  }
  const result = copy(input, 0);
  if (Buffer.byteLength(JSON.stringify(result)) > limits.maxBytes) throw new McpBoundaryError('JSON_LIMIT');
  return result;
}

/** This profile has no renderer or server-selected application/widget channel. */
export function passiveJson(input: unknown): Json {
  const value = boundedJson(input);
  function visit(item: Json): void {
    if (item === null || typeof item !== 'object') return;
    if (!Array.isArray(item)) {
      const record = item as Record<string, Json>;
      if (
        typeof record.mimeType === 'string' &&
        ['text/html', 'application/xhtml+xml', 'application/javascript', 'text/javascript', 'image/svg+xml'].includes(
          record.mimeType.toLowerCase().split(';')[0]!.trim(),
        )
      )
        throw new McpBoundaryError('ACTIVE_CONTENT_DENIED');
      if (typeof record.uri === 'string' && record.uri.startsWith('ui:'))
        throw new McpBoundaryError('ACTIVE_CONTENT_DENIED');
      const meta = record._meta;
      if (
        meta &&
        typeof meta === 'object' &&
        !Array.isArray(meta) &&
        Object.keys(meta).some(
          key =>
            key === 'ui' || key.startsWith('ui/') || key.startsWith('openai/widget') || key === 'openai/outputTemplate',
        )
      )
        throw new McpBoundaryError('ACTIVE_CONTENT_DENIED');
    }
    for (const child of Object.values(item)) visit(child);
  }
  visit(value);
  return value;
}

// `format` and content keywords are annotations by default in JSON Schema; they never validate here.
const annotations = new Set([
  'title',
  'description',
  '$comment',
  'default',
  'examples',
  'deprecated',
  'readOnly',
  'writeOnly',
  'format',
  'contentEncoding',
  'contentMediaType',
]);
const dialects = new Set([
  'http://json-schema.org/draft-07/schema#',
  'https://json-schema.org/draft-07/schema#',
  'http://json-schema.org/draft-07/schema',
  'https://json-schema.org/draft-07/schema',
  'https://json-schema.org/draft/2019-09/schema',
  'https://json-schema.org/draft/2019-09/schema#',
  'https://json-schema.org/draft/2020-12/schema',
  'https://json-schema.org/draft/2020-12/schema#',
]);
/** Strings longer than this never match a schema `pattern`; it bounds regex work per value. */
export const PATTERN_INPUT_LIMIT = 4_096;
const PATTERN_SOURCE_LIMIT = 512;
/**
 * Pattern work per validated value, charged as length squared (the worst case for an
 * admitted pattern). Bounds the total regex time for one argument object.
 */
const PATTERN_WORK_LIMIT = 2 ** 26;
let patternWork = Number.POSITIVE_INFINITY;

/**
 * Accepts only regexes whose backtracking stays bounded on PATTERN_INPUT_LIMIT input:
 * no backreferences or lookaround, no quantified group containing a quantifier or
 * alternation (star height 1), and few variable-length quantifiers (one, or two when
 * the pattern is anchored at the start and has no top-level alternation).
 */
export function safePattern(source: unknown): string {
  if (typeof source !== 'string' || !source.length || source.length > PATTERN_SOURCE_LIMIT)
    throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
  try {
    new RegExp(source, 'u');
  } catch {
    throw new McpBoundaryError('SCHEMA_INVALID');
  }
  type Group = { quantified: boolean; alternation: boolean };
  const groups: Group[] = [{ quantified: false, alternation: false }];
  let variable = 0;
  let topAlternation = false;
  const quantifierAt = (index: number): { length: number; variable: boolean } | undefined => {
    const char = source[index];
    if (char === '*' || char === '+' || char === '?')
      return { length: source[index + 1] === '?' ? 2 : 1, variable: true };
    const match = char === '{' ? /^\{(\d+)(,(\d*))?\}\??/.exec(source.slice(index)) : null;
    if (!match) return undefined;
    return { length: match[0].length, variable: match[2] !== undefined && match[3] !== match[1] };
  };
  // Marks every open group as containing a quantifier.
  const nested = () => {
    for (const group of groups) group.quantified = true;
  };
  let index = 0;
  const atomEnd = (): void => {
    const quantifier = quantifierAt(index);
    if (!quantifier) return;
    if (quantifier.variable) variable++;
    nested();
    index += quantifier.length;
  };
  while (index < source.length) {
    const char = source[index]!;
    if (char === '\\') {
      const next = source[index + 1] ?? '';
      if (/[1-9]/.test(next) || next === 'k') throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
      if ('upP'.includes(next) && next !== '' && source[index + 2] === '{') {
        const end = source.indexOf('}', index);
        index = end < 0 ? source.length : end + 1;
      } else index += next === 'u' ? 6 : next === 'x' ? 4 : next === 'c' ? 3 : 2;
      atomEnd();
    } else if (char === '[') {
      index++;
      while (index < source.length && source[index] !== ']') index += source[index] === '\\' ? 2 : 1;
      index++;
      atomEnd();
    } else if (char === '(') {
      if (source[index + 1] === '?') {
        const kind = source.slice(index + 2, index + 4);
        if (kind.startsWith('=') || kind.startsWith('!') || kind === '<=' || kind === '<!')
          throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
      }
      groups.push({ quantified: false, alternation: false });
      index += source[index + 1] === '?' ? (source[index + 2] === ':' ? 3 : source.indexOf('>', index) + 1 - index) : 1;
    } else if (char === ')') {
      const group = groups.pop();
      if (!group || !groups.length) throw new McpBoundaryError('SCHEMA_INVALID');
      index++;
      const quantifier = quantifierAt(index);
      if (quantifier) {
        if (group.quantified || group.alternation) throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
        if (quantifier.variable) variable++;
        nested();
        index += quantifier.length;
      }
      if (group.alternation) groups.at(-1)!.alternation = true;
      if (group.quantified) groups.at(-1)!.quantified = true;
    } else if (char === '|') {
      groups.at(-1)!.alternation = true;
      if (groups.length === 1) topAlternation = true;
      index++;
    } else {
      index++;
      atomEnd();
    }
  }
  const anchored = source.startsWith('^') && !topAlternation;
  if (variable > (anchored ? 2 : 1)) throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
  return source;
}
function lengthCappedRegExp(pattern: string, flags: string): { test(value: string): boolean } {
  const expression = new RegExp(pattern, flags);
  return {
    test: value => {
      if (value.length > PATTERN_INPUT_LIMIT) return false;
      patternWork -= Math.max(1, value.length) ** 2;
      return patternWork >= 0 && expression.test(value);
    },
    toString: () => `/${pattern}/${flags}`,
  } as { test(value: string): boolean };
}
lengthCappedRegExp.code = 'lengthCappedRegExp';
const UNIQUE_ITEMS = 'shieldaUniqueItems';
const simple = new Set([
  'type',
  'enum',
  'const',
  'required',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'multipleOf',
  'minItems',
  'maxItems',
  'minProperties',
  'maxProperties',
]);
const schemas = new Set(['items', 'additionalProperties', 'not']);
const schemaMaps = new Set(['properties', '$defs', 'definitions']);
const schemaArrays = new Set(['allOf', 'anyOf', 'oneOf']);

/**
 * A deliberately bounded structural JSON Schema profile, evaluated by maintained AJV.
 * Local JSON-pointer references are expanded with cycle/expansion bounds. Network,
 * file, dynamic and recursive processing are never enabled. `format` is an annotation;
 * `pattern` is accepted only for regexes that safePattern() admits.
 */
export function compileBoundedSchema(input: unknown): (value: unknown) => boolean {
  const root = boundedJson(input, SCHEMA_LIMITS);
  let expanded = 0;
  function expand(value: Json, active: Set<Json>, depth: number): Json {
    if (++expanded > 2_048 || depth > 16 || active.has(value)) throw new McpBoundaryError('SCHEMA_LIMIT');
    if (typeof value === 'boolean') return value;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new McpBoundaryError('SCHEMA_INVALID');
    active.add(value);
    const out: Record<string, Json> = Object.create(null);
    for (const [key, item] of Object.entries(value)) {
      if (key === '$schema') {
        if (typeof item !== 'string' || !dialects.has(item)) throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
      } else if (key === 'pattern') out.pattern = safePattern(item);
      else if (key === 'uniqueItems') {
        if (typeof item !== 'boolean') throw new McpBoundaryError('SCHEMA_INVALID');
        // Linear canonical-JSON comparison instead of a pairwise deep-equality scan.
        if (item) out[UNIQUE_ITEMS] = true;
      } else if (key === '$ref') {
        if (typeof item !== 'string' || !item.startsWith('#/')) throw new McpBoundaryError('SCHEMA_REFERENCE_DENIED');
        let target: Json = root;
        for (const part of item.slice(2).split('/')) {
          if (/~(?![01])/.test(part) || part.includes('%')) throw new McpBoundaryError('SCHEMA_REFERENCE_DENIED');
          const name = part.replace(/~1/g, '/').replace(/~0/g, '~');
          if (target === null || typeof target !== 'object' || !Object.hasOwn(target, name))
            throw new McpBoundaryError('SCHEMA_REFERENCE_DENIED');
          target = (target as Record<string, Json>)[name]!;
        }
        const expandedTarget = expand(target, active, depth + 1);
        out.allOf = Array.isArray(out.allOf) ? [...out.allOf, expandedTarget] : [expandedTarget];
      } else if (annotations.has(key)) {
        // Annotation contents have already been bounded. They never run as schema.
      } else if (simple.has(key)) out[key] = item;
      else if (schemas.has(key)) out[key] = expand(item, active, depth + 1);
      else if (schemaMaps.has(key)) {
        if (!item || typeof item !== 'object' || Array.isArray(item)) throw new McpBoundaryError('SCHEMA_INVALID');
        const children: Record<string, Json> = Object.create(null);
        for (const [name, child] of Object.entries(item)) children[name] = expand(child, active, depth + 1);
        if (key === 'properties') out.properties = children;
      } else if (schemaArrays.has(key)) {
        if (!Array.isArray(item) || item.length > 8) throw new McpBoundaryError('SCHEMA_LIMIT');
        const children = item.map(child => expand(child, active, depth + 1));
        out[key] = key === 'allOf' && Array.isArray(out.allOf) ? [...out.allOf, ...children] : children;
      } else throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
    }
    active.delete(value);
    return out;
  }
  // Count the expanded tree as well. A compact group of local references may repeat
  // a large enum or const many times in the source handed to the code generator.
  const schema = boundedJson(expand(root, new Set(), 0), SCHEMA_LIMITS);
  try {
    const ajv = new Ajv({
      strict: true,
      strictTypes: false,
      allErrors: false,
      validateFormats: false,
      coerceTypes: false,
      useDefaults: false,
      removeAdditional: false,
      code: { regExp: lengthCappedRegExp as never },
    });
    ajv.addKeyword({
      keyword: UNIQUE_ITEMS,
      type: 'array',
      schemaType: 'boolean',
      errors: false,
      validate: (enabled: boolean, data: Json[]) =>
        !enabled || new Set(data.map(item => canonicalJson(item))).size === data.length,
    });
    const validate = ajv.compile(schema as boolean | Record<string, unknown>);
    return value => {
      patternWork = PATTERN_WORK_LIMIT;
      try {
        return validate(boundedJson(value)) === true;
      } catch {
        return false;
      } finally {
        patternWork = Number.POSITIVE_INFINITY;
      }
    };
  } catch {
    throw new McpBoundaryError('SCHEMA_INVALID');
  }
}
