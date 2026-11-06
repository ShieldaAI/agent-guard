// Installed public API only: current-state repair cannot reset spent authority.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DurableExecutor, createLedgerKeyring, readLedgerKeyring, manageLedgerRecovery } from '@shieldaai/agent-guard-executor';

if (process.platform === 'win32') {
  console.log('POSIX current-state recovery is outside the Windows deployment profile.');
} else {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'guard-packed-recovery-')));
  for (const name of ['data', 'witness', 'keys']) mkdirSync(join(root, name), { mode: 0o700 });
  const source = { id: 'authority', database: join(root, 'data', 'state.sqlite'), witnessPath: join(root, 'witness', 'state.sqlite') };
  const keyringFile = join(root, 'keys', 'ring.json');
  createLedgerKeyring({ keyringFile, keyId: 'initial' });
  const [{ key }] = readLedgerKeyring({ keyringFile });
  const options = { database: source.database, encryptionKey: key, clock: () => 1000 };
  let owner, effects = 0;
  try {
    owner = new DurableExecutor({ ...options, rollbackWitness: { path: source.witnessPath, mode: 'create', recovery: 'mirror' } });
    const task = { id: 'spent', tenantId: 'company', principalId: 'operator', grants: [{ tool: 'write', resources: ['record'] }],
      budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: 100_000 } };
    const fingerprint = owner.registerTool({ name: 'write', description: 'Disposable protected effect', maxCost: 1,
      resolve: () => ({ tenantId: 'company', resourceId: 'record' }), execute: () => { effects++; return { value: true, actualCost: 1 }; } });
    owner.approveTool('write', fingerprint); owner.createTask(task);
    const prepared = await owner.prepare(task.id, { tool: 'write', args: {} }); await owner.execute(task.id, prepared.id);
    const before = owner.snapshot(task.id); assert.equal(before.calls, 1); assert.equal(before.spent, 1);
    owner.close(); owner = undefined;
    const witness = readFileSync(source.witnessPath);
    rmSync(join(root, 'data'), { recursive: true }); mkdirSync(join(root, 'data'), { mode: 0o700 });
    const recovery = { keyringFile, stores: [source] }, preview = manageLedgerRecovery(recovery, { operation: 'repair' });
    assert.equal(preview.applied, false);
    assert.equal(manageLedgerRecovery(recovery, { operation: 'repair' }, { expectedDigest: preview.digest }).applied, true);
    assert.deepEqual(readFileSync(source.witnessPath), witness);
    owner = new DurableExecutor({ ...options, rollbackWitness: { path: source.witnessPath, mode: 'resume' } });
    assert.equal(owner.snapshot(task.id).calls, 1); assert.equal(owner.snapshot(task.id).spent, 1);
    assert.throws(() => owner.createTask(task), { code: 'DUPLICATE_TASK' });
    assert.equal(effects, 1);
    console.log('Installed current-state repair preserves spent authority, task identity and exact witness after complete primary directory loss.');
  } finally { owner?.close(); key.fill(0); rmSync(root, { recursive: true, force: true }); }
}
