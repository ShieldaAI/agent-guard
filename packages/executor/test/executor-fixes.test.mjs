import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';
import { createLedgerKeyring, loadLedgerKey } from '../dist/entry-ops.js';
import { removeAtExit } from './temp-directory.mjs';

function directory(t) {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'executor-fixes-')));
  removeAtExit(path);
  return path;
}
const KEY = Buffer.alloc(32, 51);

test('a backward clock step is refused unless the operator accepts it once, within the stated skew', t => {
  const database = join(directory(t), 'ledger.sqlite');
  let now = 1_000_000;
  new DurableExecutor({ database, encryptionKey: KEY, clock: () => now }).close();
  now = 995_000;
  assert.throws(() => new DurableExecutor({ database, encryptionKey: KEY, clock: () => now }), {
    code: 'CLOCK_INVALID',
  });
  assert.throws(
    () => new DurableExecutor({ database, encryptionKey: KEY, clock: () => now, acceptClockSkewMs: 4_000 }),
    { code: 'CLOCK_INVALID' },
    'a larger step than accepted still fails',
  );
  const executor = new DurableExecutor({ database, encryptionKey: KEY, clock: () => now, acceptClockSkewMs: 10_000 });
  assert.ok(executor.audit().some(event => event.event === 'CLOCK_SKEW_ACCEPTED'));
  executor.close();
  assert.doesNotThrow(
    () => new DurableExecutor({ database, encryptionKey: KEY, clock: () => now }).close(),
    'later opens need no override',
  );
  for (const acceptClockSkewMs of [0, 1.5, 24 * 60 * 60_000 + 1]) {
    assert.throws(() => new DurableExecutor({ database, encryptionKey: KEY, clock: () => now, acceptClockSkewMs }), {
      code: 'INVALID_INPUT',
    });
  }
});

test('an effect that completes after its deadline is reported as committed, not uncertain', async t => {
  let now = 1_000;
  const executor = new DurableExecutor({
    database: join(directory(t), 'ledger.sqlite'),
    encryptionKey: KEY,
    clock: () => now,
  });
  t.after(() => executor.close());
  executor.approveTool(
    'slow',
    executor.registerTool({
      name: 'slow',
      description: 'x',
      maxCost: 1,
      resolve: () => ({ resourceId: 'r', tenantId: 'a' }),
      execute: () => {
        now = 6_000;
        return { value: 'written', actualCost: 1 };
      },
    }),
  );
  executor.createTask({
    id: 't',
    principalId: 'p',
    tenantId: 'a',
    grants: [{ tool: 'slow', resources: ['r'] }],
    budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 5, deadline: 5_000 },
  });
  const action = await executor.prepare('t', { tool: 'slow', args: {} });
  const error = await executor.execute('t', action.id).catch(caught => caught);
  assert.equal(error.code, 'EXECUTION_ABORTED');
  assert.equal(error.detail, 'EFFECT_COMMITTED');
  assert.equal(executor.execution('t', action.id).status, 'SUCCEEDED');
  assert.equal(executor.snapshot('t').reserved, 0, 'no reservation is held for a committed effect');
});

test('the executor and the /ops key tools accept the same minimum ledger size', t => {
  const root = directory(t);
  assert.throws(
    () => new DurableExecutor({ database: join(root, 'a.sqlite'), encryptionKey: KEY, maxLedgerBytes: 512 * 1024 }),
    { code: 'INVALID_INPUT' },
  );
  createLedgerKeyring({ keyringFile: join(root, 'keys.json'), keyId: 'k' });
  assert.throws(
    () =>
      loadLedgerKey({ database: join(root, 'a.sqlite'), keyringFile: join(root, 'keys.json'), maxBytes: 512 * 1024 }),
    { code: 'STORE_CONFIG_INVALID' },
  );
});

test('numbered task IDs are an executor scheme any host can build and that fences recognize', async () => {
  const { numberedTaskId, NUMBERED_TASK_PREFIX } = await import('../dist/index.js');
  const namespace = '3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b';
  assert.equal(numberedTaskId(namespace, 42), `${NUMBERED_TASK_PREFIX}${namespace}-42`);
  assert.equal(NUMBERED_TASK_PREFIX, 'ticket:', 'fixed: persisted fences and digests depend on it');
  for (const [ns, sequence] of [
    ['not-a-uuid', 1],
    [namespace, 0],
    [namespace, 1.5],
    [namespace, 1e16],
  ]) {
    assert.throws(() => numberedTaskId(ns, sequence), { code: 'INVALID_INPUT' });
  }
});
