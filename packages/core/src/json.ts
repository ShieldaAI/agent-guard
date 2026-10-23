import { createHash } from 'node:crypto';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

export class InvalidJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidJsonError';
  }
}

/** Copy JSON data without invoking accessors, retaining caller references or coercing values. */
export function immutableJson(value: unknown, maxDepth = 64, maxNodes = 100_000): JsonValue {
  const ancestors = new Set<object>();
  let nodes = 0;
  function visit(input: unknown, depth: number): JsonValue {
    if (++nodes > maxNodes) throw new InvalidJsonError('JSON value exceeds the node limit');
    if (depth > maxDepth) throw new InvalidJsonError('JSON value exceeds the depth limit');
    if (input === null || typeof input === 'string' || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isFinite(input)) throw new InvalidJsonError('JSON numbers must be finite');
      return Object.is(input, -0) ? 0 : input;
    }
    if (typeof input !== 'object') throw new InvalidJsonError('Only JSON values are accepted');
    if (ancestors.has(input)) throw new InvalidJsonError('Circular JSON value');
    const prototype = Object.getPrototypeOf(input);
    if ((Array.isArray(input) && prototype !== Array.prototype) ||
        (!Array.isArray(input) && prototype !== null && prototype !== Object.prototype)) {
      throw new InvalidJsonError('JSON objects must have a plain or null prototype');
    }
    if (Object.getOwnPropertySymbols(input).length) throw new InvalidJsonError('JSON symbol keys are unsupported');
    ancestors.add(input);
    try {
      if (Array.isArray(input)) {
        const keys = Object.getOwnPropertyNames(input);
        if (keys.length !== input.length + 1 || input.length > maxNodes) {
          throw new InvalidJsonError('Sparse, oversized arrays and extra array properties are unsupported');
        }
        const result: JsonValue[] = [];
        for (let i = 0; i < input.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(input, String(i));
          if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
            throw new InvalidJsonError('Array accessors and missing values are unsupported');
          }
          result.push(visit(descriptor.value, depth + 1));
        }
        return Object.freeze(result);
      }
      const result: Record<string, JsonValue> = Object.create(null);
      for (const key of Object.getOwnPropertyNames(input).sort()) {
        const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
        if (!descriptor.enumerable || !('value' in descriptor)) {
          throw new InvalidJsonError('Non-enumerable fields and accessors are unsupported');
        }
        Object.defineProperty(result, key, {
          value: visit(descriptor.value, depth + 1), enumerable: true,
          writable: false, configurable: false,
        });
      }
      return Object.freeze(result);
    } finally {
      ancestors.delete(input);
    }
  }
  return visit(value, 0);
}

/** Stable serialization over already validated data; object keys are ordered at every depth. */
export function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as JsonObject;
  return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(object[key]!)}`).join(',')}}`;
}

export function digestJson(value: JsonValue): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}
