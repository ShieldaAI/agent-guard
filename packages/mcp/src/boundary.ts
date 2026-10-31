import type { Json } from '@shieldaai/agent-guard';
import { Ajv } from '@modelcontextprotocol/client/validators/ajv';

export class McpBoundaryError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'McpBoundaryError'; }
}

export interface JsonLimits { maxBytes: number; maxNodes: number; maxDepth: number }
export const MESSAGE_LIMITS: Readonly<JsonLimits> = Object.freeze({ maxBytes: 1_048_576, maxNodes: 10_000, maxDepth: 32 });
const SCHEMA_LIMITS = Object.freeze({ maxBytes: 65_536, maxNodes: 2_048, maxDepth: 16 });

/** Copies only JSON data properties, without invoking getters or toJSON hooks. */
export function boundedJson(input: unknown, limits: JsonLimits = MESSAGE_LIMITS): Json {
  const seen = new Set<object>(); let nodes = 0; let bytes = 0;
  function copy(value: unknown, depth: number): Json {
    if (++nodes > limits.maxNodes || depth > limits.maxDepth) throw new McpBoundaryError('JSON_LIMIT');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      bytes += Buffer.byteLength(value); if (bytes > limits.maxBytes) throw new McpBoundaryError('JSON_LIMIT');
      return value;
    }
    if (typeof value !== 'object' || value === null || seen.has(value)) throw new McpBoundaryError('INVALID_JSON');
    if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new McpBoundaryError('INVALID_JSON');
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
      if (Array.isArray(value) && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) throw new McpBoundaryError('INVALID_JSON');
      bytes += Buffer.byteLength(key); if (bytes > limits.maxBytes) throw new McpBoundaryError('JSON_LIMIT');
      Object.defineProperty(result, key, { value: copy(descriptor.value, depth + 1), enumerable: true });
    }
    if (Array.isArray(value) && Object.keys(result).length !== value.length) throw new McpBoundaryError('INVALID_JSON');
    seen.delete(value); return Object.freeze(result);
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
      if (typeof record.mimeType === 'string' && ['text/html', 'application/xhtml+xml', 'application/javascript', 'text/javascript', 'image/svg+xml'].includes(record.mimeType.toLowerCase().split(';')[0]!.trim())) throw new McpBoundaryError('ACTIVE_CONTENT_DENIED');
      if (typeof record.uri === 'string' && record.uri.startsWith('ui:')) throw new McpBoundaryError('ACTIVE_CONTENT_DENIED');
      const meta = record._meta;
      if (meta && typeof meta === 'object' && !Array.isArray(meta) && Object.keys(meta).some(key => key === 'ui' || key.startsWith('ui/') || key.startsWith('openai/widget') || key === 'openai/outputTemplate')) throw new McpBoundaryError('ACTIVE_CONTENT_DENIED');
    }
    for (const child of Object.values(item)) visit(child);
  }
  visit(value); return value;
}

const annotations = new Set(['title', 'description', '$comment', 'default', 'examples', 'deprecated', 'readOnly', 'writeOnly']);
const simple = new Set(['type', 'enum', 'const', 'required', 'minLength', 'maxLength', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'minItems', 'maxItems', 'minProperties', 'maxProperties']);
const schemas = new Set(['items', 'additionalProperties', 'not']);
const schemaMaps = new Set(['properties', '$defs', 'definitions']);
const schemaArrays = new Set(['allOf', 'anyOf', 'oneOf']);

/**
 * A deliberately bounded structural JSON Schema profile, evaluated by maintained AJV.
 * Local JSON-pointer references are expanded with cycle/expansion bounds. Network,
 * file, dynamic, recursive, regex and format processing are never enabled.
 */
export function compileBoundedSchema(input: unknown): (value: unknown) => boolean {
  const root = boundedJson(input, SCHEMA_LIMITS); let expanded = 0;
  function expand(value: Json, active: Set<Json>, depth: number): Json {
    if (++expanded > 2_048 || depth > 16 || active.has(value)) throw new McpBoundaryError('SCHEMA_LIMIT');
    if (typeof value === 'boolean') return value;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new McpBoundaryError('SCHEMA_INVALID');
    active.add(value);
    const out: Record<string, Json> = Object.create(null);
    for (const [key, item] of Object.entries(value)) {
      if (key === '$schema') {
        if (item !== 'http://json-schema.org/draft-07/schema#' && item !== 'https://json-schema.org/draft-07/schema#') throw new McpBoundaryError('SCHEMA_UNSUPPORTED');
      } else if (key === '$ref') {
        if (typeof item !== 'string' || !item.startsWith('#/')) throw new McpBoundaryError('SCHEMA_REFERENCE_DENIED');
        let target: Json = root;
        for (const part of item.slice(2).split('/')) {
          if (/~(?![01])/.test(part) || part.includes('%')) throw new McpBoundaryError('SCHEMA_REFERENCE_DENIED');
          const name = part.replace(/~1/g, '/').replace(/~0/g, '~');
          if (target === null || typeof target !== 'object' || !Object.hasOwn(target, name)) throw new McpBoundaryError('SCHEMA_REFERENCE_DENIED');
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
    active.delete(value); return out;
  }
  const schema = expand(root, new Set(), 0);
  try {
    const ajv = new Ajv({ strict: true, strictTypes: false, allErrors: false, validateFormats: false, coerceTypes: false, useDefaults: false, removeAdditional: false });
    const validate = ajv.compile(schema as boolean | Record<string, unknown>);
    return value => {
      try { return validate(boundedJson(value)) === true; } catch { return false; }
    };
  } catch { throw new McpBoundaryError('SCHEMA_INVALID'); }
}
