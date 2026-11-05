import { closeSync, constants, fstatSync, openSync, readlinkSync, readSync, realpathSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { readWindowsWorkspaceInput } from './workspace-input-windows.js';

// Darwin's open(2) rejects symlinks at every component. Node only names O_NOFOLLOW,
// which protects the final component. See XNU bsd/sys/fcntl.h for this ABI value.
const DARWIN_NOFOLLOW_ANY = 0x20000000;

function openLinuxInput(path: string, readFlags: number): number {
  // Each lookup starts from a live directory descriptor. A rename cannot
  // redirect the next lookup through an attacker-controlled replacement.
  const parts = path.split('/').filter(Boolean);
  const filename = parts.pop()!;
  const directoryFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
  let directory = openSync('/', directoryFlags);
  try {
    for (const part of parts) {
      const child = openSync(`/proc/self/fd/${directory}/${part}`, directoryFlags);
      closeSync(directory);
      directory = child;
    }
    const file = openSync(`/proc/self/fd/${directory}/${filename}`, readFlags);
    try {
      // Preserve the literal selected name on Linux volumes with case folding.
      if (readlinkSync(`/proc/self/fd/${file}`) !== path) throw new Error();
      return file;
    } catch (error) {
      closeSync(file);
      throw error;
    }
  } finally {
    closeSync(directory);
  }
}

function openPosixInput(root: string, name: string): number {
  const flags = constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOCTTY;
  try {
    if (process.platform === 'linux') return openLinuxInput(join(root, name), flags | constants.O_NOFOLLOW);
    if (process.platform === 'darwin') {
      // Accept macOS's standard startup-volume aliases even for callers using os.tmpdir().
      const canonicalRoot = root.replace(/^\/(var|tmp|etc)(?=\/|$)/, '/private/$1');
      const selected = join(canonicalRoot, name);
      // Preserve exact spelling on case-insensitive volumes. The kernel flag,
      // rather than this earlier observation, enforces confinement at open.
      if (realpathSync.native(selected) !== selected) throw new Error();
      return openSync(selected, flags | DARWIN_NOFOLLOW_ANY);
    }
  } catch {
    throw new Error('Workspace input could not be opened without symlinks');
  }
  throw new Error('Unsupported workspace input platform');
}

/** Read only the object opened inside the selected workspace, with a fixed byte ceiling. */
export function readWorkspaceInput(root: string, name: string, maximum: number): Buffer {
  if (!isAbsolute(root) || !name || name.includes('\\') || name.includes('\0') ||
      name.split('/').some(part => !part || part === '.' || part === '..') ||
      !Number.isSafeInteger(maximum) || maximum < 0 || maximum > 64 * 1024 * 1024) {
    throw new Error('Invalid workspace input selection');
  }
  if (process.platform === 'win32') return readWindowsWorkspaceInput(root, name, maximum);

  const fd = openPosixInput(root, name);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) {
      throw new Error('Inputs must be bounded regular files without hard links');
    }
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    if (BigInt(length) !== before.size || after.size !== before.size || after.nlink !== 1n ||
        before.ctimeNs !== after.ctimeNs || before.mtimeNs !== after.mtimeNs) {
      throw new Error('Workspace input changed during its bounded copy');
    }
    return bytes.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}
