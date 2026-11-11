import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parseEvidenceJson } from './evidence-json.js';
import { validateInventoryManifest, type InventoryManifest } from './inventory-manifest.js';
import { ExecutorError } from './store.js';

/** The same byte limit `validateInventoryManifest` applies to a manifest value. */
const MAX_BYTES = 2 * 1024 * 1024;
const FILE_INVALID = 'INVENTORY_MANIFEST_FILE_INVALID';

/**
 * Load one operator-reviewed host manifest from a private local file, for
 * `startInventoryServer({ manifests: [loadInventoryManifestFile(path)] })`.
 *
 * Call it once at startup with a path from the host's own reviewed configuration, never
 * one chosen by a request, a task or an agent. The file is read once: a later edit takes
 * effect only when the host restarts and loads it again.
 *
 * The file must be a regular file with one link, owned by the user the host runs as, with
 * no group or other permissions (`chmod 600`), at most 2 MiB of UTF-8 JSON without
 * duplicate object members. A symbolic link is refused. Anything else about the file throws
 * `INVENTORY_MANIFEST_FILE_INVALID`; a platform without POSIX ownership and permissions
 * (Windows) throws `INVENTORY_MANIFEST_FILE_UNSUPPORTED`. The parsed value then goes through
 * `validateInventoryManifest`, which throws its own codes. No error carries file content.
 */
export function loadInventoryManifestFile(path: string): InventoryManifest {
  if (typeof process.getuid !== 'function' || !constants.O_NOFOLLOW)
    throw new ExecutorError('INVENTORY_MANIFEST_FILE_UNSUPPORTED');
  if (typeof path !== 'string' || path.includes('\0') || !isAbsolute(path)) throw new ExecutorError(FILE_INVALID);
  let descriptor: number | undefined;
  let bytes: Buffer;
  try {
    // Checks run on the opened descriptor, so the path cannot be swapped between check and
    // read. O_NONBLOCK keeps a FIFO from blocking startup before it is refused.
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = fstatSync(descriptor);
    if (
      !info.isFile() ||
      info.nlink !== 1 ||
      info.uid !== process.getuid() ||
      (info.mode & 0o077) !== 0 ||
      info.size > MAX_BYTES
    )
      throw new Error();
    const data = Buffer.alloc(info.size + 1);
    let length = 0;
    while (length < data.length) {
      const read = readSync(descriptor, data, length, data.length - length, null);
      if (!read) break;
      length += read;
    }
    // A file that grew while it was read is not the file that was checked.
    if (length !== info.size) throw new Error();
    bytes = data.subarray(0, length);
  } catch {
    throw new ExecutorError(FILE_INVALID);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  let value: unknown;
  try {
    value = parseEvidenceJson(bytes, MAX_BYTES, 100_000);
  } catch {
    throw new ExecutorError(FILE_INVALID);
  }
  return validateInventoryManifest(value);
}
