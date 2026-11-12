import { GuardError } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';

/**
 * The one relative-path rule shared by the private-file adapter, sandbox inputs and
 * exports, the sandbox archive reader, artifact receipts and build-artifact policy.
 *
 * A portable path:
 * - is a non-empty, well-formed string of at most 240 UTF-8 bytes in Unicode NFC;
 * - uses "/" between segments, with no leading or trailing "/";
 * - contains none of \ : * ? " < > | and no control character (U+0000-U+001F, U+007F);
 * - has no empty, "." or ".." segment, no segment ending in "." or a space, and no
 *   Windows device name (CON, PRN, AUX, NUL, COM0-COM9, LPT0-LPT9, with or without extension);
 * - is not the reserved provenance sidecar name ".agent-guard-provenance.json" (any case).
 *
 * A list holds at most 256 paths. Two paths collide when they are equal ignoring case,
 * when one is a directory prefix of the other ignoring case, or when they spell a shared
 * directory with different case.
 */
export const MAX_PATH_BYTES = 240;
export const MAX_PATH_COUNT = 256;
export const PROVENANCE_SIDECAR = '.agent-guard-provenance.json';

export type PathProblem =
  | 'PATH_NOT_STRING'
  | 'PATH_EMPTY'
  | 'PATH_TOO_LONG'
  | 'PATH_NOT_NFC'
  | 'PATH_CHARACTER'
  | 'PATH_SEGMENT'
  | 'PATH_RESERVED';
export type PathListProblem = PathProblem | 'PATH_LIST_INVALID' | 'PATH_COUNT' | 'PATH_COLLISION';

const FORBIDDEN = /[\\:*?"<>|\u0000-\u001f\u007f]/u;
const LONE_SURROGATE = /\p{Cs}/u;
const DEVICE = /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu;

/** Comparison key for case-insensitive volumes. Paths are already NFC, so case is the only fold. */
export function foldPath(value: string): string {
  return value.toUpperCase().toLowerCase();
}

/** Returns the first rule the value breaks, or undefined for a portable path. Never throws. */
export function portablePathProblem(value: unknown): PathProblem | undefined {
  if (typeof value !== 'string') return 'PATH_NOT_STRING';
  if (!value) return 'PATH_EMPTY';
  // A UTF-16 unit is at least one UTF-8 byte: reject oversized input before scanning it.
  if (value.length > MAX_PATH_BYTES || Buffer.byteLength(value, 'utf8') > MAX_PATH_BYTES) return 'PATH_TOO_LONG';
  if (FORBIDDEN.test(value) || LONE_SURROGATE.test(value)) return 'PATH_CHARACTER';
  if (value.normalize('NFC') !== value) return 'PATH_NOT_NFC';
  for (const part of value.split('/')) {
    if (!part || part === '.' || part === '..' || /[. ]$/u.test(part)) return 'PATH_SEGMENT';
    if (DEVICE.test(part)) return 'PATH_RESERVED';
  }
  if (foldPath(value) === PROVENANCE_SIDECAR) return 'PATH_RESERVED';
  return undefined;
}

/** Returns the first rule the list breaks, or undefined when every path is portable and none collide. */
export function portablePathListProblem(values: unknown, maximum = MAX_PATH_COUNT): PathListProblem | undefined {
  if (!Array.isArray(values)) return 'PATH_LIST_INVALID';
  const count: unknown = Object.getOwnPropertyDescriptor(values, 'length')?.value;
  if (typeof count !== 'number' || count > maximum) return 'PATH_COUNT';
  const files = new Set<string>();
  // Folded directory -> the one spelling every path must use for it.
  const directories = new Map<string, string>();
  const names: string[] = [];
  for (let index = 0; index < count; index++) {
    // Array.map skips holes and would invoke accessors; read each own data property.
    const entry = Object.getOwnPropertyDescriptor(values, index);
    if (!entry || !('value' in entry)) return 'PATH_LIST_INVALID';
    const problem = portablePathProblem(entry.value);
    if (problem) return problem;
    names.push(entry.value as string);
  }
  for (const name of names) {
    const folded = foldPath(name);
    if (files.has(folded)) return 'PATH_COLLISION';
    files.add(folded);
    for (let end = name.indexOf('/'); end !== -1; end = name.indexOf('/', end + 1)) {
      const directory = name.slice(0, end);
      const key = foldPath(directory);
      const spelling = directories.get(key);
      if (spelling === undefined) directories.set(key, directory);
      else if (spelling !== directory) return 'PATH_COLLISION';
    }
  }
  for (const folded of files) if (directories.has(folded)) return 'PATH_COLLISION';
  return undefined;
}

/**
 * Coded pipeline error with a fixed, human-readable hint. The hint is a constant chosen by
 * this package: it never carries a path, a command, guest output or request data.
 */
export function pipelineError(
  code: string,
  hint: string,
  options: { detail?: string; cause?: unknown } = {},
): ExecutorError {
  const error = new ExecutorError(code, options);
  error.message = `${code}: ${hint}`;
  return error;
}

/** Uppercase identifier taken from a caught error, when it has one that is safe to relay. */
export function safeErrorCode(error: unknown): string | undefined {
  try {
    const code: unknown = (error as { code?: unknown } | null | undefined)?.code;
    return typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Keeps a coded error as it is and gives anything else the stated code. The errno, never the
 * error text, becomes the detail; the original stays reachable in-process as the cause.
 */
export function codedError(error: unknown, code: string, hint: string): GuardError | ExecutorError {
  if (error instanceof ExecutorError || error instanceof GuardError) return error;
  const detail = safeErrorCode(error);
  return pipelineError(code, hint, { ...(detail === undefined ? {} : { detail }), cause: error });
}
