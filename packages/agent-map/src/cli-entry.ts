import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { MapQueryError } from './types.js';

/** Optional `neo4j` configuration keys passed to the store as its per-read limits. */
export const STORE_LIMITS = ['maxNodes', 'maxEdges', 'maxBytes'] as const;
export const PACKAGE_VERSION = (createRequire(import.meta.url)('../package.json') as { version: string }).version;

/** npm's POSIX executable is a symlink. Node resolves it when loading the module. */
export function isCliEntry(meta: ImportMeta): boolean {
  if (typeof meta.main === 'boolean') return meta.main;
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    // Older supported Node versions do not expose import.meta.main.
    return pathToFileURL(realpathSync(entry)).href === meta.url;
  } catch {
    // Imports from eval/stdin can supply an argv value that is not a file.
    return false;
  }
}

// One fixed line per cause. Nothing from the error itself is printed: its message can hold a
// path, an argument or a configuration value.
const STARTUP_HINTS: Readonly<Record<string, string>> = Object.freeze({
  MAP_ARGUMENT_INVALID: 'an argument is unknown or incomplete, or --config is missing.',
  MAP_CONFIG_NOT_FOUND: 'the configuration file, or a file it names, does not exist.',
  MAP_CONFIG_UNREADABLE:
    'the configuration file, or a file it names, cannot be opened; check its type, owner and permissions.',
  MAP_CONFIG_INVALID:
    'the configuration is not accepted; check that it is strict JSON with known field names and valid values, and that each file is a regular file owned by the service user and not writable by others.',
  MAP_CREDENTIAL_REQUIRED: 'an environment variable the configuration names is unset or empty.',
  MAP_SCOPE_INVALID: 'a credential or binding scope is not valid.',
  MAP_LISTEN_FAILED: 'the configured address and port could not be opened; another process may be using the port.',
  MAP_IDENTITY_INVALID:
    'the identity provider metadata does not match the configuration (issuer, RS256, S256 PKCE, client authentication or endpoint origins).',
  MAP_IDENTITY_UNAVAILABLE: 'the identity provider did not answer within the deadline.',
  MAP_UNAVAILABLE: 'a required service or capability is unavailable.',
  MAP_START_FAILED: 'unexpected failure during startup.',
});
/** The specific safe code for a startup failure, and whether the usage line helps. */
export function startupFailure(error: unknown): { code: string; hint: string; usage: boolean } {
  const raw = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
  const syscall = error && typeof error === 'object' && 'syscall' in error ? String(error.syscall) : '';
  let code = 'MAP_START_FAILED';
  if (error instanceof MapQueryError) {
    // A configuration file that is not strict JSON, or too large, is a configuration fault.
    code = ['MAP_REQUEST_INVALID', 'MAP_REQUEST_TOO_LARGE'].includes(raw) ? 'MAP_CONFIG_INVALID' : raw;
  } else if (raw.startsWith('ERR_PARSE_ARGS')) code = 'MAP_ARGUMENT_INVALID';
  else if (syscall === 'listen' || raw === 'EADDRINUSE' || raw === 'EADDRNOTAVAIL') code = 'MAP_LISTEN_FAILED';
  else if (raw === 'ENOENT' || raw === 'ENOTDIR') code = 'MAP_CONFIG_NOT_FOUND';
  else if (['EACCES', 'EPERM', 'ELOOP', 'EISDIR', 'ENXIO', 'EMFILE', 'ENFILE'].includes(raw))
    code = 'MAP_CONFIG_UNREADABLE';
  if (!Object.hasOwn(STARTUP_HINTS, code)) code = 'MAP_START_FAILED';
  return { code, hint: STARTUP_HINTS[code]!, usage: code === 'MAP_ARGUMENT_INVALID' };
}
/** Prints `MAP_START_FAILED <code>: <hint>` (and the usage for an argument error) and sets the exit code. */
export function reportStartupFailure(error: unknown, usage: string): void {
  const failure = startupFailure(error);
  const cause = failure.code === 'MAP_START_FAILED' ? '' : ` ${failure.code}`;
  process.stderr.write(`MAP_START_FAILED${cause}: ${failure.hint}\n${failure.usage ? `Usage: ${usage}\n` : ''}`);
  process.exitCode = 1;
}
