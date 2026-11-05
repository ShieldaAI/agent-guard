import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

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
