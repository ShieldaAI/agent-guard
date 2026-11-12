import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync, realpathSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { pipelineError, safeErrorCode } from './path-rules.js';
import { ExecutorError } from './store.js';
import { readWindowsWorkspaceInput } from './workspace-input-windows.js';

// Darwin's open(2) rejects symlinks at every component. Node only names O_NOFOLLOW,
// which protects the final component. See XNU bsd/sys/fcntl.h for this ABI value.
const DARWIN_NOFOLLOW_ANY = 0x20000000;

/** The spelling check failed: the opened object is not the literal selected name. */
class AliasedInput extends Error {}

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
      if (readlinkSync(`/proc/self/fd/${file}`) !== path) throw new AliasedInput();
      return file;
    } catch (error) {
      closeSync(file);
      throw error;
    }
  } finally {
    closeSync(directory);
  }
}

/**
 * Name the open failure without guessing: a missing file is not a symlink problem, and an
 * unexpected OS error keeps its errno as the detail. Like the Windows reader, the result
 * carries no cause, because the OS error text holds the private host path.
 */
function openFailure(error: unknown, selected: string): ExecutorError {
  const errno = safeErrorCode(error);
  if (errno === 'ENOENT') {
    let dangling = false;
    try {
      // A dangling final symlink also reports ENOENT. Classification only: nothing is opened here.
      dangling = lstatSync(selected).isSymbolicLink();
    } catch {
      // The selected name does not exist.
    }
    if (!dangling) return pipelineError('WORKSPACE_INPUT_MISSING', 'Workspace input does not exist');
  }
  if (error instanceof AliasedInput || errno === 'ENOENT' || errno === 'ELOOP' || errno === 'ENOTDIR')
    return pipelineError('WORKSPACE_INPUT_UNSAFE', 'Workspace input could not be opened without symlinks', {
      detail: error instanceof AliasedInput ? 'INPUT_ALIAS' : 'INPUT_SYMLINK',
    });
  return pipelineError(
    'WORKSPACE_INPUT_UNAVAILABLE',
    'Workspace input could not be opened',
    errno === undefined ? {} : { detail: errno },
  );
}

function openPosixInput(root: string, name: string): number {
  const flags = constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOCTTY;
  let selected = join(root, name);
  try {
    if (process.platform === 'linux') return openLinuxInput(selected, flags | constants.O_NOFOLLOW);
    if (process.platform === 'darwin') {
      // Accept macOS's standard startup-volume aliases even for callers using os.tmpdir().
      const canonicalRoot = root.replace(/^\/(var|tmp|etc)(?=\/|$)/, '/private/$1');
      selected = join(canonicalRoot, name);
      // Preserve exact spelling on case-insensitive volumes. The kernel flag,
      // rather than this earlier observation, enforces confinement at open.
      if (realpathSync.native(selected) !== selected) throw new AliasedInput();
      return openSync(selected, flags | DARWIN_NOFOLLOW_ANY);
    }
  } catch (error) {
    throw openFailure(error, selected);
  }
  throw pipelineError('WORKSPACE_INPUT_UNAVAILABLE', 'Unsupported workspace input platform', {
    detail: 'PLATFORM_UNSUPPORTED',
  });
}

/** Read only the object opened inside the selected workspace, with a fixed byte ceiling. */
export function readWorkspaceInput(root: string, name: string, maximum: number): Buffer {
  if (
    typeof root !== 'string' ||
    typeof name !== 'string' ||
    !isAbsolute(root) ||
    !name ||
    name.includes('\\') ||
    name.includes('\0') ||
    name.split('/').some(part => !part || part === '.' || part === '..') ||
    !Number.isSafeInteger(maximum) ||
    maximum < 0 ||
    maximum > 64 * 1024 * 1024
  ) {
    throw pipelineError('WORKSPACE_INPUT_INVALID', 'Invalid workspace input selection');
  }
  if (process.platform === 'win32') return readWindowsWorkspaceInput(root, name, maximum);

  const fd = openPosixInput(root, name);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n)
      throw pipelineError('WORKSPACE_INPUT_UNSAFE', 'Inputs must be regular files without hard links', {
        detail: before.isFile() ? 'INPUT_HARD_LINK' : 'INPUT_NOT_REGULAR',
      });
    if (before.size > BigInt(maximum))
      throw pipelineError('WORKSPACE_INPUT_LIMIT', 'Workspace input exceeds its bounded size');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    if (
      BigInt(length) !== before.size ||
      after.size !== before.size ||
      after.nlink !== 1n ||
      before.ctimeNs !== after.ctimeNs ||
      before.mtimeNs !== after.mtimeNs
    ) {
      throw pipelineError('WORKSPACE_INPUT_CHANGED', 'Workspace input changed during its bounded copy');
    }
    return bytes.subarray(0, length);
  } catch (error) {
    if (error instanceof ExecutorError) throw error;
    const errno = safeErrorCode(error);
    throw pipelineError(
      'WORKSPACE_INPUT_UNAVAILABLE',
      'Workspace input could not be read',
      errno === undefined ? {} : { detail: errno },
    );
  } finally {
    closeSync(fd);
  }
}
