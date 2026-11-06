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
if (!['before-commit', 'after-commit', 'super-journal', 'super-journal-probe', 'partial-promotion'].includes(mode)) throw Error('UNKNOWN_RECOVERY_FIXTURE');
const options = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = options.stores[0];
if (mode === 'super-journal-probe') {
  // Unarmed matching paths and armed unrelated paths must retain native unlink
  // behavior. These disposable probe files never stand in for the real journal.
  delete process.env.AGENT_GUARD_TEST_MJ_ARMED;
  const unarmed = source.witnessPath + '-mj000000900';
  fs.writeFileSync(unarmed, 'unarmed probe', { flag: 'wx', mode: 0o600 });
  fs.unlinkSync(unarmed);
  process.env.AGENT_GUARD_TEST_MJ_ARMED = '1';
  for (const suffix of ['.unrelated', '.other-mj000000900']) {
    const path = source.witnessPath + suffix;
    fs.writeFileSync(path, 'unrelated probe', { flag: 'wx', mode: 0o600 });
    fs.unlinkSync(path);
  }
  try { fs.unlinkSync(source.witnessPath + '.missing'); throw Error('UNLINK_DID_NOT_FAIL'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  process.stdout.write('HOOK_PROBE_OK\n');
} else if (mode === 'partial-promotion') {
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
      // Arm only after opening the actual enrolled store. The native hook runs
      // at its final pre-commit unlink, not during startup or recovery cleanup.
      process.env.AGENT_GUARD_TEST_MJ_ARMED = '1';
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
