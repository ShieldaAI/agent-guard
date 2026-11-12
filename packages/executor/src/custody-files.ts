import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  writeSync,
  type BigIntStats,
} from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { ExecutorError } from './store.js';
import {
  PRIVATE_FILE,
  checkOpenFile,
  openChecked,
  privateDirectory as checkPrivateDirectory,
  readPrivateFile,
  trustedDirectoryChain,
  type PrivateFileProblem,
  type Refuse,
} from './private-files.js';

export function custodyFail(code: string, options: { detail?: string; cause?: unknown } = {}): never {
  throw new ExecutorError(code, options);
}
/** One mapping from a shared path refusal to the custody codes. The detail says which check failed. */
const refuse: Refuse = (problem: PrivateFileProblem, cause?: unknown) => {
  const code =
    problem === 'DIRECTORY_MISSING' || problem === 'DIRECTORY_UNREADABLE'
      ? 'CUSTODY_PATH_UNAVAILABLE'
      : problem === 'DIRECTORY_UNSAFE'
        ? 'CUSTODY_PATH_UNSAFE'
        : problem === 'FILE_MISSING' || problem === 'FILE_UNREADABLE'
          ? 'CUSTODY_FILE_UNAVAILABLE'
          : problem === 'FILE_EXISTS'
            ? 'CUSTODY_FILE_EXISTS'
            : problem === 'FILE_CHANGED'
              ? 'CUSTODY_FILE_CHANGED'
              : 'CUSTODY_FILE_UNSAFE';
  return custodyFail(code, { detail: problem, cause });
};
/** A canonical private directory under trusted ancestors. Returns each ancestor's identity, nearest first. */
function privateChain(path: string): string[] {
  if (!['linux', 'darwin'].includes(process.platform) || typeof path !== 'string' || !isAbsolute(path))
    custodyFail('CUSTODY_PATH_UNSAFE', { detail: 'DIRECTORY_UNSAFE' });
  checkPrivateDirectory(path, refuse);
  return trustedDirectoryChain(path, refuse);
}
export function privateDirectory(path: string): void {
  privateChain(path);
}
export function checkPrivate(fd: number, path: string, maximum = 4 * 1024 ** 3): BigIntStats {
  return checkOpenFile(fd, path, { ...PRIVATE_FILE, maximum }, refuse);
}
export function syncDirectory(path: string): void {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
export function privateBytes(path: string, maximum: number): Buffer {
  privateDirectory(dirname(path));
  return readPrivateFile(path, { ...PRIVATE_FILE, maximum }, refuse);
}
/**
 * Remove a file this call created, and only while `path` still names that same file.
 * A failed step must not leave a partial private copy behind.
 */
export function discardCreated(fd: number, path: string): void {
  try {
    const created = fstatSync(fd, { bigint: true }),
      named = lstatSync(path, { bigint: true });
    if (created.dev !== named.dev || created.ino !== named.ino) return;
    unlinkSync(path);
    syncDirectory(dirname(path));
  } catch {
    /* The original failure is the one to report. */
  }
}
/** Remove this operation's own uniquely named staging file, if it is still there. */
export function discardStaged(path: string): void {
  try {
    rmSync(path, { force: true });
    rmSync(path + '-journal', { force: true });
    syncDirectory(dirname(path));
  } catch {
    /* The original failure is the one to report. */
  }
}
/** Open an existing file for reading; a missing or unreadable one is CUSTODY_FILE_UNAVAILABLE, never a raw errno. */
export function openPrivate(path: string): number {
  return openChecked(path, constants.O_RDONLY, refuse);
}
/** Create a new private file exclusively; an existing name is refused with CUSTODY_FILE_EXISTS. */
export function createPrivate(path: string): number {
  return openChecked(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL, refuse);
}
export function writeNewPrivate(path: string, bytes: Uint8Array): void {
  privateDirectory(dirname(path));
  const fd = openChecked(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, refuse);
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } catch (error) {
    discardCreated(fd, path);
    throw error instanceof ExecutorError ? error : custodyFail('CUSTODY_FILE_UNAVAILABLE', { cause: error });
  } finally {
    closeSync(fd);
  }
  syncDirectory(dirname(path));
}
/**
 * Hash `source`, and copy it to a new private `destination` when one is given.
 *
 * A copy that fails for any reason (changed source, wrong digest, write error) removes
 * the destination it created, so the same call can be repeated. A destination that
 * already holds exactly the expected bytes counts as done; any other existing
 * destination is refused with `CUSTODY_FILE_EXISTS` and never overwritten.
 */
export function copyPrivate(
  source: string,
  destination?: string,
  expectedSha256?: string,
): { sha256: string; bytes: number } {
  privateDirectory(dirname(source));
  if (destination) privateDirectory(dirname(destination));
  const input = openChecked(source, constants.O_RDONLY, refuse);
  let output: number | undefined,
    complete = false;
  const buffer = Buffer.alloc(1024 * 1024),
    digest = createHash('sha256');
  try {
    const before = checkPrivate(input, source);
    if (destination) {
      try {
        output = openSync(
          destination,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST')
          return custodyFail('CUSTODY_FILE_UNAVAILABLE', { cause: error });
        // An earlier attempt may already have finished this exact copy.
        if (expectedSha256) {
          let existing: { sha256: string; bytes: number } | undefined;
          try {
            existing = copyPrivate(destination);
          } catch {
            /* Not a readable private file: refused below. */
          }
          if (existing?.sha256 === expectedSha256 && BigInt(existing.bytes) === before.size) {
            if (copyPrivate(source).sha256 !== expectedSha256) custodyFail('CUSTODY_DIGEST_MISMATCH');
            return existing;
          }
        }
        return custodyFail('CUSTODY_FILE_EXISTS', { detail: 'FILE_EXISTS', cause: error });
      }
    }
    let bytes = 0;
    for (;;) {
      const count = readSync(input, buffer, 0, buffer.length, null);
      if (!count) break;
      bytes += count;
      if (BigInt(bytes) > before.size) custodyFail('CUSTODY_FILE_CHANGED', { detail: 'FILE_CHANGED' });
      digest.update(buffer.subarray(0, count));
      if (output !== undefined) {
        let offset = 0;
        while (offset < count) offset += writeSync(output, buffer, offset, count - offset);
      }
    }
    const after = checkPrivate(input, source);
    if (BigInt(bytes) !== before.size || before.ctimeNs !== after.ctimeNs || before.mtimeNs !== after.mtimeNs)
      custodyFail('CUSTODY_FILE_CHANGED', { detail: 'FILE_CHANGED' });
    const sha256 = digest.digest('hex');
    if (expectedSha256 && sha256 !== expectedSha256) custodyFail('CUSTODY_DIGEST_MISMATCH');
    if (output !== undefined) fsyncSync(output);
    if (destination) syncDirectory(dirname(destination));
    complete = true;
    return { sha256, bytes };
  } catch (error) {
    throw error instanceof ExecutorError ? error : custodyFail('CUSTODY_FILE_UNAVAILABLE', { cause: error });
  } finally {
    buffer.fill(0);
    closeSync(input);
    if (output !== undefined) {
      if (!complete && destination) discardCreated(output, destination);
      closeSync(output);
    }
  }
}
/**
 * Why no key opened a ledger, as a safe detail plus the original error. The store's own
 * detail wins (for example LOCKED or KEY_MISMATCH); otherwise the store code is the detail,
 * refined to FILE_MISSING or LOCKED when that is what a look at the file shows.
 */
export function storeOpenFailure(database: string, error: unknown): { detail?: string; cause?: unknown } {
  let detail = error instanceof ExecutorError ? (error.detail ?? error.code) : undefined;
  if (detail === undefined || detail === 'STORE_UNAVAILABLE' || detail === 'STORE_WITNESS_UNAVAILABLE') {
    if (!existsSync(database)) detail = 'FILE_MISSING';
    else if (ledgerOwned(database)) detail = 'LOCKED';
  }
  return {
    ...(detail !== undefined && /^[A-Z][A-Z0-9_]{0,63}$/.test(detail) ? { detail } : {}),
    ...(error === undefined ? {} : { cause: error }),
  };
}
/** True while another process owns the ledger: its exclusive SQLite lock refuses even a read. */
function ledgerOwned(database: string): boolean {
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(database, { readOnly: true });
    db.exec('PRAGMA busy_timeout=0');
    db.prepare('SELECT COUNT(*) AS n FROM sqlite_schema').get();
    return false;
  } catch (error) {
    return (
      (error as { errcode?: unknown }).errcode === 5 || /database is locked/i.test(String((error as Error).message))
    );
  } finally {
    try {
      db?.close();
    } catch {
      /* Probe only. */
    }
  }
}
export function independentDirectories(paths: readonly string[]): void {
  const chains = paths.map(privateChain);
  for (let i = 0; i < chains.length; i++)
    for (let j = i + 1; j < chains.length; j++) {
      if (chains[i]!.includes(chains[j]![0]!) || chains[j]!.includes(chains[i]![0]!))
        custodyFail('CUSTODY_DIRECTORIES_OVERLAP');
    }
}
