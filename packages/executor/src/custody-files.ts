import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { ExecutorError } from './store.js';

export function custodyFail(code: string): never {
  throw new ExecutorError(code);
}
export function privateDirectory(path: string): void {
  if (
    !['linux', 'darwin'].includes(process.platform) ||
    typeof path !== 'string' ||
    !isAbsolute(path) ||
    realpathSync(path) !== path
  )
    custodyFail('CUSTODY_PATH_UNSAFE');
  for (let current = path; ; current = dirname(current)) {
    const stat = lstatSync(current);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.uid !== 0 && stat.uid !== process.geteuid!()) ||
      ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0) ||
      (current === path && (stat.uid !== process.geteuid!() || (stat.mode & 0o077) !== 0))
    )
      custodyFail('CUSTODY_PATH_UNSAFE');
    if (current === dirname(current)) break;
  }
}
export function checkPrivate(fd: number, path: string, maximum = 4 * 1024 ** 3): ReturnType<typeof fstatSync> {
  const stat = fstatSync(fd),
    named = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.nlink !== 1 ||
    stat.uid !== process.geteuid!() ||
    (stat.mode & 0o077) !== 0 ||
    !Number.isSafeInteger(stat.size) ||
    stat.size > maximum ||
    !named.isFile() ||
    named.isSymbolicLink() ||
    stat.dev !== named.dev ||
    stat.ino !== named.ino ||
    stat.size !== named.size ||
    stat.ctimeMs !== named.ctimeMs
  )
    custodyFail('CUSTODY_FILE_UNSAFE');
  return stat;
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
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes: Buffer | undefined;
  try {
    const before = checkPrivate(fd, path, maximum);
    bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (!read) custodyFail('CUSTODY_FILE_CHANGED');
      offset += read;
    }
    const after = checkPrivate(fd, path, maximum);
    if (before.ctimeMs !== after.ctimeMs || before.mtimeMs !== after.mtimeMs) custodyFail('CUSTODY_FILE_CHANGED');
    const result = bytes;
    bytes = undefined;
    return result;
  } finally {
    bytes?.fill(0);
    closeSync(fd);
  }
}
export function writeNewPrivate(path: string, bytes: Uint8Array): void {
  privateDirectory(dirname(path));
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  syncDirectory(dirname(path));
}
export function atomicPrivate(path: string, bytes: Uint8Array): void {
  const temporary = join(dirname(path), `.custody-write-${randomBytes(16).toString('hex')}`);
  try {
    writeNewPrivate(temporary, bytes);
    renameSync(temporary, path);
    syncDirectory(dirname(path));
  } finally {
    rmSync(temporary, { force: true });
  }
}
export function copyPrivate(
  source: string,
  destination?: string,
  expectedSha256?: string,
): { sha256: string; bytes: number } {
  privateDirectory(dirname(source));
  if (destination) privateDirectory(dirname(destination));
  const input = openSync(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let output: number | undefined;
  const buffer = Buffer.alloc(1024 * 1024),
    digest = createHash('sha256');
  try {
    const before = checkPrivate(input, source);
    if (destination)
      output = openSync(
        destination,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    let bytes = 0;
    for (;;) {
      const count = readSync(input, buffer, 0, buffer.length, null);
      if (!count) break;
      bytes += count;
      if (bytes > before.size) custodyFail('CUSTODY_FILE_CHANGED');
      digest.update(buffer.subarray(0, count));
      if (output !== undefined) {
        let offset = 0;
        while (offset < count) offset += writeSync(output, buffer, offset, count - offset);
      }
    }
    const after = checkPrivate(input, source);
    if (bytes !== before.size || before.ctimeMs !== after.ctimeMs || before.mtimeMs !== after.mtimeMs)
      custodyFail('CUSTODY_FILE_CHANGED');
    const sha256 = digest.digest('hex');
    if (expectedSha256 && sha256 !== expectedSha256) custodyFail('CUSTODY_DIGEST_MISMATCH');
    if (output !== undefined) fsyncSync(output);
    if (destination) syncDirectory(dirname(destination));
    return { sha256, bytes };
  } finally {
    buffer.fill(0);
    closeSync(input);
    if (output !== undefined) closeSync(output);
  }
}
export function independentDirectories(paths: readonly string[]): void {
  const chains = paths.map(path => {
    privateDirectory(path);
    const chain: string[] = [];
    for (let current = path; ; current = dirname(current)) {
      const stat = lstatSync(current, { bigint: true });
      chain.push(`${stat.dev}:${stat.ino}`);
      if (current === dirname(current)) return chain;
    }
  });
  for (let i = 0; i < chains.length; i++)
    for (let j = i + 1; j < chains.length; j++) {
      if (chains[i]!.includes(chains[j]![0]!) || chains[j]!.includes(chains[i]![0]!))
        custodyFail('CUSTODY_DIRECTORIES_OVERLAP');
    }
}
