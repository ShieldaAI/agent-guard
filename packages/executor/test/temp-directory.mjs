import { rmSync } from 'node:fs';

const pending = [];

/**
 * Remove a test's temporary directory when the test file exits, after every test hook has
 * closed its ledger. Hooks run in the order they were registered, and Windows cannot delete
 * an open SQLite file: a removal hook registered before the hook that closes the executor
 * fails the test there, and the close never runs.
 */
export function removeAtExit(path) {
  if (pending.length === 0)
    process.once('exit', () => {
      for (const item of pending)
        try {
          rmSync(item, { recursive: true, force: true });
        } catch {
          // Best effort: a leftover temporary directory must not change the test result.
        }
    });
  pending.push(path);
}
