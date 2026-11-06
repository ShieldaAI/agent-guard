import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DurableExecutor } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';

test('executor ledger byte limits accept only bounded integer configuration', () => {
  for (const maxLedgerBytes of [0, 1024, 1024 * 1024 - 1, 64 * 1024 * 1024 + 1, 1.5, NaN, Infinity, '16777216', null])
    assert.throws(() => new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), maxLedgerBytes }), { code: 'INVALID_INPUT' });
  for (const maxLedgerBytes of [undefined, 1024 * 1024, 64 * 1024 * 1024]) {
    const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), maxLedgerBytes });
    executor.close();
  }
});

test('larger ledgers reopen only within the configured cap and failed shrinkage preserves authority', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-guard-ledger-limits-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'ledger.sqlite'), key = randomBytes(32), cap = 32 * 1024 * 1024;
  const store = new LedgerStore(database, key, cap);
  store.transaction(state => { state.retainedHostEvidence = 'x'.repeat(16 * 1024 * 1024); });
  const instance = store.read().inventoryInstanceId; store.close();
  const before = readFileSync(database);
  assert.throws(() => new DurableExecutor({ database, encryptionKey: key }), { code: 'STORE_UNAVAILABLE' });
  assert.deepEqual(readFileSync(database), before);
  const executor = new DurableExecutor({ database, encryptionKey: key, maxLedgerBytes: cap });
  executor.createTask({ id: 'retained-task', principalId: 'owner', tenantId: 'tenant', grants: [],
    budget: { maxCalls: 0, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
  executor.close();
  const after = readFileSync(database);
  assert.throws(() => new DurableExecutor({ database, encryptionKey: key, maxLedgerBytes: 1024 * 1024 }), { code: 'STORE_UNAVAILABLE' });
  assert.deepEqual(readFileSync(database), after);
  const reopened = new LedgerStore(database, key, cap);
  try {
    const state = reopened.read();
    assert.equal(state.inventoryInstanceId, instance);
    assert.equal(state.retainedHostEvidence.length, 16 * 1024 * 1024);
    assert.equal(state.tasks['retained-task'].options.tenantId, 'tenant');
  } finally { reopened.close(); key.fill(0); }
});
