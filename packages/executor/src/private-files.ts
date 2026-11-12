/**
 * The one set of checks for private local files and the directories that hold them:
 * the ledger, its keyrings, custody and recovery files, the pilot policy and the
 * inventory manifest all go through this module.
 *
 * Ownership is compared with the effective user ID. That is the identity the kernel
 * uses when this process opens and creates files, so it is the owner a file written by
 * this process has. It equals the real user ID unless the process is set-uid.
 *
 * Nothing here throws on its own: every refusal goes through the caller's `refuse`
 * callback with a safe reason, so each caller keeps its own error codes.
 */
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  type BigIntStats,
} from 'node:fs';
import { dirname } from 'node:path';

/** Why a path was refused. Safe to show: it never contains a path or file content. */
export type PrivateFileProblem =
  | 'DIRECTORY_MISSING'
  | 'DIRECTORY_UNSAFE'
  | 'DIRECTORY_UNREADABLE'
  | 'FILE_MISSING'
  | 'FILE_EXISTS'
  | 'FILE_UNSAFE'
  | 'FILE_TOO_LARGE'
  | 'FILE_CHANGED'
  | 'FILE_UNREADABLE';
export type Refuse = (problem: PrivateFileProblem, cause?: unknown) => never;

/** False on Windows, where owner and mode bits carry no meaning; those checks are skipped there. */
export const posixPermissions = (): boolean => process.platform !== 'win32' && typeof process.geteuid === 'function';
const self = (): bigint => BigInt(process.geteuid!());
const errno = (error: unknown): string | undefined => (error as NodeJS.ErrnoException | undefined)?.code;
const missing = (error: unknown): boolean => errno(error) === 'ENOENT' || errno(error) === 'ENOTDIR';

/**
 * Walk `directory` and every ancestor up to the root. Each must be a real directory
 * (never a link) owned by root or this process's user, and not writable by group or
 * others unless it is sticky (like /tmp). Returns each directory's device and inode,
 * nearest first, so callers can compare two locations for overlap.
 */
export function trustedDirectoryChain(directory: string, refuse: Refuse): string[] {
  const chain: string[] = [];
  for (let current = directory; ; current = dirname(current)) {
    let stat: BigIntStats;
    try {
      stat = lstatSync(current, { bigint: true });
    } catch (error) {
      return refuse(missing(error) ? 'DIRECTORY_MISSING' : 'DIRECTORY_UNREADABLE', error);
    }
    if (
      !stat.isDirectory() ||
      (posixPermissions() &&
        ((stat.uid !== 0n && stat.uid !== self()) || ((stat.mode & 0o022n) !== 0n && (stat.mode & 0o1000n) === 0n)))
    )
      refuse('DIRECTORY_UNSAFE');
    chain.push(`${stat.dev}:${stat.ino}`);
    if (current === dirname(current)) return chain;
  }
}

/**
 * `directory` must be spelled canonically (no link anywhere in it), be a directory,
 * belong to this process's user and grant nothing to group or others.
 */
export function privateDirectory(directory: string, refuse: Refuse): void {
  let stat: BigIntStats, canonical: string;
  try {
    stat = lstatSync(directory, { bigint: true });
    canonical = realpathSync(directory);
  } catch (error) {
    return refuse(missing(error) ? 'DIRECTORY_MISSING' : 'DIRECTORY_UNREADABLE', error);
  }
  if (
    !stat.isDirectory() ||
    canonical !== directory ||
    (posixPermissions() && (stat.uid !== self() || (stat.mode & 0o077n) !== 0n))
  )
    refuse('DIRECTORY_UNSAFE');
}

export interface PrivateFileRule {
  /** Largest accepted size in bytes; omit for no bound. */
  readonly maximum?: number;
  /** `self`: this process's user. `trusted`: root or this process's user. `any`: not checked. */
  readonly owner: 'self' | 'trusted' | 'any';
  /** Mode bits that must be clear: 0o077 (private), 0o022 (not writable by others) or 0. */
  readonly deny: 0o077 | 0o022 | 0;
  /**
   * Also require the name to show the same size and change time as the open descriptor.
   * Leave it off for a file another process may legitimately be writing (a live database).
   */
  readonly quiet: boolean;
}
/** A file only this process's user can read or write. */
export const PRIVATE_FILE = Object.freeze({ owner: 'self', deny: 0o077, quiet: true }) satisfies PrivateFileRule;

/**
 * Check the open descriptor that will supply (or receive) the bytes, then check that
 * `path` still names that same file: a regular file with exactly one link.
 */
export function checkOpenFile(fd: number, path: string, rule: PrivateFileRule, refuse: Refuse): BigIntStats {
  let opened: BigIntStats, named: BigIntStats;
  try {
    opened = fstatSync(fd, { bigint: true });
    named = lstatSync(path, { bigint: true });
  } catch (error) {
    return refuse(missing(error) ? 'FILE_CHANGED' : 'FILE_UNREADABLE', error);
  }
  if (
    !opened.isFile() ||
    opened.nlink !== 1n ||
    !named.isFile() ||
    named.dev !== opened.dev ||
    named.ino !== opened.ino ||
    (rule.quiet && (named.size !== opened.size || named.ctimeNs !== opened.ctimeNs))
  )
    refuse('FILE_UNSAFE');
  if (
    posixPermissions() &&
    ((opened.mode & BigInt(rule.deny)) !== 0n ||
      (rule.owner === 'self' && opened.uid !== self()) ||
      (rule.owner === 'trusted' && opened.uid !== 0n && opened.uid !== self()))
  )
    refuse('FILE_UNSAFE');
  if (rule.maximum !== undefined && opened.size > BigInt(rule.maximum)) refuse('FILE_TOO_LARGE');
  return opened;
}

/** Open without following a final link and without blocking on a FIFO. */
export function openChecked(path: string, flags: number, refuse: Refuse, mode = 0o600): number {
  try {
    return openSync(path, flags | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0), mode);
  } catch (error) {
    return refuse(
      missing(error) ? 'FILE_MISSING' : errno(error) === 'EEXIST' ? 'FILE_EXISTS' : 'FILE_UNREADABLE',
      error,
    );
  }
}

/**
 * Read a whole checked file. The file is checked before and after the read and must
 * not change in between. On any refusal the partial buffer is erased first.
 */
export function readPrivateFile(path: string, rule: PrivateFileRule & { maximum: number }, refuse: Refuse): Buffer {
  const fd = openChecked(path, constants.O_RDONLY, refuse);
  let bytes: Buffer | undefined;
  try {
    const before = checkOpenFile(fd, path, rule, refuse);
    // One spare byte shows a file that grew after it was checked.
    bytes = Buffer.alloc(Number(before.size) + 1);
    let count = 0;
    try {
      while (count < bytes.length) {
        const read = readSync(fd, bytes, count, bytes.length - count, null);
        if (!read) break;
        count += read;
      }
    } catch (error) {
      return refuse('FILE_UNREADABLE', error);
    }
    const after = checkOpenFile(fd, path, rule, refuse);
    if (
      BigInt(count) !== before.size ||
      after.size !== before.size ||
      after.ctimeNs !== before.ctimeNs ||
      after.mtimeNs !== before.mtimeNs
    )
      refuse('FILE_CHANGED');
    const result = bytes.subarray(0, count);
    bytes = undefined;
    return result;
  } finally {
    bytes?.fill(0);
    closeSync(fd);
  }
}
