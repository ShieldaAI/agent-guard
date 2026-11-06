// Static child worker for recovery fault tests. Test data is JSON on stdin, never
// interpolated JavaScript, and this fixture is excluded from published packages.
import fs from 'node:fs';
import { dirname } from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import { LedgerStore } from '../../dist/store.js';
import { loadLedgerKey } from '../../dist/ledger-maintenance.js';
import { manageLedgerRecovery } from '../../dist/ledger-recovery.js';

const mode = process.argv[2];
if (!['before-commit', 'after-commit', 'super-journal', 'partial-promotion'].includes(mode)) throw Error('UNKNOWN_RECOVERY_FIXTURE');
const options = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = options.stores[0];
if (mode === 'partial-promotion') {
  const preview = manageLedgerRecovery(options, { operation: 'repair' });
  const link = fs.linkSync;
  fs.linkSync = function(from, to) {
    const result = link.call(this, from, to);
    if (to === source.database) process.kill(process.pid, 'SIGKILL');
    return result;
  };
  syncBuiltinESMExports();
  manageLedgerRecovery(options, { operation: 'repair' }, { expectedDigest: preview.digest });
} else {
  const selected = loadLedgerKey({ ...source, keyringFile: options.keyringFile, maxBytes: 64 * 1024 * 1024 });
  let store;
  try { store = new LedgerStore(source.database, selected.key, 64 * 1024 * 1024, { path: source.witnessPath, mode: 'resume' }, { existingOnly: true }); }
  finally { selected.key.fill(0); }
  try {
    if (mode === 'super-journal') {
      store.transaction(state => { state.largeFixture = 'B'.repeat(24 * 1024 * 1024); state.epoch = 99; });
      process.stdout.write('ACKNOWLEDGED\n');
    } else {
      const exec = DatabaseSync.prototype.exec;
      DatabaseSync.prototype.exec = function(sql) {
        if (sql === 'COMMIT') {
          if (mode === 'after-commit') exec.call(this, sql);
          fs.rmSync(dirname(source.database), { recursive: true });
          process.kill(process.pid, 'SIGKILL');
        }
        return exec.call(this, sql);
      };
      store.transaction(state => { state.epoch = 42; state.audit.push({ time: 2, event: 'new transaction' }); });
    }
  } finally { store.close(); }
}
