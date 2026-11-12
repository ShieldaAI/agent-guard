import { constants, type Stats } from 'node:fs';
import { open } from 'node:fs/promises';
import { fail } from './common.js';

// Configuration selects credential destinations. Viewer assets run in authenticated browsers.
// Check the descriptor after open so the test applies to the bytes that will be used.
export function trustedHostFile(info: Stats): boolean {
  return (
    typeof process.geteuid === 'function' &&
    info.isFile() &&
    (info.uid === 0 || info.uid === process.geteuid()) &&
    (info.mode & 0o022) === 0
  );
}
/** Which files a launcher accepts. The rules differ by what the file is for, and each caller states its own. */
export interface HostFileRule {
  /** Refuse a symbolic link at the path itself. */
  readonly noFollow: boolean;
  /** `service`: owned by this user. `service-or-root`: owned by the effective user or by root. */
  readonly owner: 'service' | 'service-or-root';
  /** Refuse a file with more than one hard link. */
  readonly singleLink: boolean;
  /** Refuse any group or other access, as for a key or a file that names secrets. */
  readonly private: boolean;
}
/**
 * Reads at most `maximum` bytes of a regular file that is not writable by group or others.
 * The checks and the read use one non-blocking descriptor, so they apply to the bytes that
 * are used, and a file that grows after the check is refused rather than read without bound.
 */
export async function readHostFile(path: string, maximum: number, rule: HostFileRule): Promise<Buffer> {
  if (
    typeof constants.O_NONBLOCK !== 'number' ||
    (rule.noFollow && !constants.O_NOFOLLOW) ||
    (rule.owner === 'service' && typeof process.getuid !== 'function')
  )
    fail('MAP_CONFIG_INVALID');
  const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | (rule.noFollow ? constants.O_NOFOLLOW : 0));
  try {
    const info = await file.stat();
    const owned =
      rule.owner === 'service'
        ? info.isFile() && info.uid === process.getuid!() && (info.mode & 0o022) === 0
        : trustedHostFile(info);
    if (
      !owned ||
      info.size > maximum ||
      (rule.singleLink && info.nlink !== 1) ||
      (rule.private && (info.mode & 0o077) !== 0)
    )
      fail('MAP_CONFIG_INVALID');
    const data = Buffer.alloc(maximum + 1);
    let bytes = 0;
    while (bytes < data.length) {
      const read = await file.read(data, bytes, data.length - bytes, null);
      if (!read.bytesRead) break;
      bytes += read.bytesRead;
    }
    if (bytes > maximum) fail('MAP_CONFIG_INVALID');
    // Do not retain the full maximum-sized allocation for a small file.
    return Buffer.from(data.subarray(0, bytes));
  } finally {
    await file.close();
  }
}
export function fields(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[] = [],
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(value)) ||
    Object.getOwnPropertySymbols(value).length
  )
    fail('MAP_CONFIG_INVALID');
  if (Object.getOwnPropertyNames(value).some(key => !allowed.includes(key))) fail('MAP_CONFIG_INVALID');
  // Copy by the allowed names, never by a name the input supplied.
  const result: Record<string, unknown> = Object.create(null);
  for (const key of allowed) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) continue;
    if (!descriptor.enumerable || !('value' in descriptor)) fail('MAP_CONFIG_INVALID');
    result[key] = descriptor.value;
  }
  if (required.some(key => !Object.hasOwn(result, key))) fail('MAP_CONFIG_INVALID');
  return result;
}
/** Bounded strict JSON, including duplicate decoded keys that JSON.parse would discard. */
export function parseRequest(bytes: Uint8Array, maximum = 65_536): unknown {
  if (bytes.byteLength > maximum) fail('MAP_REQUEST_TOO_LARGE');
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    let offset = 0;
    let nodes = 0;
    const space = (): void => {
      while (/[\t\n\r ]/.test(text[offset] ?? '\0')) offset++;
    };
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
      space();
      const char = text[offset];
      if (char === '"') return string();
      if (char === '{') {
        offset++;
        space();
        // Members are collected first and become own data properties of a null-prototype
        // object in one step, so a name from the text is never used as a write target.
        const members: [string, unknown][] = [];
        const names = new Set<string>();
        const object = (): Record<string, unknown> =>
          Object.assign(Object.create(null) as Record<string, unknown>, Object.fromEntries(members));
        if (text[offset] === '}') {
          offset++;
          return object();
        }
        while (true) {
          space();
          if (text[offset] !== '"') throw new Error();
          const key = string();
          if (names.has(key)) throw new Error();
          names.add(key);
          space();
          if (text[offset++] !== ':') throw new Error();
          members.push([key, value(depth + 1)]);
          space();
          if (text[offset] === '}') {
            offset++;
            return object();
          }
          if (text[offset++] !== ',') throw new Error();
        }
      }
      if (char === '[') {
        offset++;
        space();
        const array: unknown[] = [];
        if (text[offset] === ']') {
          offset++;
          return array;
        }
        while (true) {
          array.push(value(depth + 1));
          space();
          if (text[offset] === ']') {
            offset++;
            return array;
          }
          if (text[offset++] !== ',') throw new Error();
        }
      }
      const token = /^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(offset))?.[0];
      if (token === undefined) throw new Error();
      offset += token.length;
      const parsed: unknown = JSON.parse(token);
      if (typeof parsed === 'number' && !Number.isFinite(parsed)) throw new Error();
      return parsed;
    };
    const parsed = value(0);
    space();
    if (offset !== text.length) throw new Error();
    return parsed;
  } catch {
    return fail('MAP_REQUEST_INVALID');
  }
}
