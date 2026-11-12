import { constants } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parseEvidenceJson } from './evidence-json.js';
import {
  MAX_INVENTORY_MANIFEST_VALUES,
  validateInventoryManifest,
  type InventoryManifest,
} from './inventory-manifest.js';
import { ExecutorError } from './store.js';
import { PRIVATE_FILE, posixPermissions, readPrivateFile } from './private-files.js';

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
 * no group or other permissions (`chmod 600`), at most 2 MiB of UTF-8 JSON with at most
 * 200,000 values (the limits `validateInventoryManifest` applies) and no duplicate object
 * members. A symbolic link is refused. More than 200,000 values throws
 * `INVENTORY_MANIFEST_LIMIT_EXCEEDED`, as the validator does; anything else about the file
 * throws `INVENTORY_MANIFEST_FILE_INVALID`; a platform without POSIX ownership and permissions
 * (Windows) throws `INVENTORY_MANIFEST_FILE_UNSUPPORTED`. The parsed value then goes through
 * `validateInventoryManifest`, which throws its own codes. No error carries file content.
 */
export function loadInventoryManifestFile(path: string): InventoryManifest {
  if (typeof process.getuid !== 'function' || !posixPermissions() || !constants.O_NOFOLLOW)
    throw new ExecutorError('INVENTORY_MANIFEST_FILE_UNSUPPORTED');
  if (typeof path !== 'string' || path.includes('\0') || !isAbsolute(path)) throw new ExecutorError(FILE_INVALID);
  // The shared private-file read (private-files.ts): checks run on the opened descriptor,
  // before and after the read, so the path cannot be swapped between check and read. The
  // detail says which check failed (FILE_MISSING, FILE_UNSAFE, FILE_TOO_LARGE, FILE_CHANGED).
  const bytes = readPrivateFile(path, { ...PRIVATE_FILE, maximum: MAX_BYTES }, (problem, cause) => {
    throw new ExecutorError(FILE_INVALID, { detail: problem, cause });
  });
  let value: unknown;
  try {
    value = parseEvidenceJson(bytes, MAX_BYTES, MAX_INVENTORY_MANIFEST_VALUES);
  } catch (error) {
    // More values than a manifest may hold is the validator's limit, reported with its code.
    if (error instanceof Error && error.message === 'JSON value exceeds the node limit')
      throw new ExecutorError('INVENTORY_MANIFEST_LIMIT_EXCEEDED');
    throw new ExecutorError(FILE_INVALID);
  }
  return validateInventoryManifest(value);
}
