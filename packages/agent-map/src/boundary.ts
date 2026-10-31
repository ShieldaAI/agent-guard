import { MapQueryError } from './types.js';

export function fail(code: string): never { throw new MapQueryError(code); }
export function fields(value: unknown, allowed: readonly string[], required: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![null, Object.prototype].includes(Object.getPrototypeOf(value)) || Object.getOwnPropertySymbols(value).length) fail('MAP_CONFIG_INVALID');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!allowed.includes(key) || !descriptor.enumerable || !('value' in descriptor)) fail('MAP_CONFIG_INVALID');
    result[key] = descriptor.value;
  }
  if (required.some(key => !Object.hasOwn(result, key))) fail('MAP_CONFIG_INVALID');
  return result;
}
export function integer(value: unknown, fallback: number, min: number, max: number): number {
  const result = value === undefined ? fallback : value;
  if (typeof result !== 'number' || !Number.isSafeInteger(result) || result < min || result > max) fail('MAP_CONFIG_INVALID');
  return result;
}

/** Bounded strict JSON, including duplicate decoded keys that JSON.parse would discard. */
export function parseRequest(bytes: Uint8Array, maximum = 65_536): unknown {
  if (bytes.byteLength > maximum) fail('MAP_REQUEST_TOO_LARGE');
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    let offset = 0; let nodes = 0;
    const space = (): void => { while (/[\t\n\r ]/.test(text[offset] ?? '\0')) offset++; };
    const string = (): string => {
      const start = offset++;
      while (offset < text.length) {
        const char = text[offset++]!;
        if (char === '\\') offset++;
        else if (char === '"') return JSON.parse(text.slice(start, offset)) as string;
      }
      throw new Error();
    };
    const value = (depth: number): unknown => {
      if (++nodes > 2048 || depth > 12) throw new Error();
      space(); const char = text[offset];
      if (char === '"') return string();
      if (char === '{') {
        offset++; space(); const object: Record<string, unknown> = Object.create(null);
        if (text[offset] === '}') { offset++; return object; }
        while (true) {
          space(); if (text[offset] !== '"') throw new Error();
          const key = string(); if (Object.hasOwn(object, key)) throw new Error();
          space(); if (text[offset++] !== ':') throw new Error();
          object[key] = value(depth + 1); space();
          if (text[offset] === '}') { offset++; return object; }
          if (text[offset++] !== ',') throw new Error();
        }
      }
      if (char === '[') {
        offset++; space(); const array: unknown[] = [];
        if (text[offset] === ']') { offset++; return array; }
        while (true) {
          array.push(value(depth + 1)); space();
          if (text[offset] === ']') { offset++; return array; }
          if (text[offset++] !== ',') throw new Error();
        }
      }
      const token = /^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(offset))?.[0];
      if (token === undefined) throw new Error();
      offset += token.length; const parsed: unknown = JSON.parse(token);
      if (typeof parsed === 'number' && !Number.isFinite(parsed)) throw new Error();
      return parsed;
    };
    const parsed = value(0); space(); if (offset !== text.length) throw new Error();
    return parsed;
  } catch { return fail('MAP_REQUEST_INVALID'); }
}
