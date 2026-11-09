import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor, ExecutorClient } from '../dist/index.js';

function setup(t, options = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-retention-')));
  const executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 13), clock: () => 1000, ...options });
  t.after(() => { executor.close(); rmSync(directory, { recursive: true, force: true }); });
  const fingerprint = executor.registerTool({
    name: 'write', description: 'Write a tenant record', maxCost: 1,
    resolve: (_args, task) => ({ resourceId: 'record', tenantId: task.tenantId }),
    execute: args => { if (args?.fail) throw new Error('backend disconnected'); return { value: 'ok' }; },
  });
  executor.approveTool('write', fingerprint);
  for (const tenant of ['alpha', 'beta']) {
    executor.createTask({ id: tenant, principalId: `${tenant}-operator`, tenantId: tenant, grants: [{ tool: 'write', resources: ['record'] }],
      budget: { maxCalls: 1000, maxConcurrent: 2, maxCost: 1000, deadline: 100_000 } });
  }
  const run = async (taskId, args = {}) => { const action = await executor.prepare(taskId, { tool: 'write', args }); await executor.execute(taskId, action.id); return action; };
  return { executor, run };
}

for (const [name, options] of [['the default per-family cap', {}], ['only the shared caps', { maxReceiptsPerFamily: 4096 }]]) {
  test(`300 executions by another tenant leave this tenant's receipt intact under ${name}`, async t => {
    const f = setup(t, options);
    const mine = await f.run('alpha');
    let first;
    for (let index = 0; index < 300; index++) { const action = await f.run('beta'); first ??= action; }
    assert.equal(f.executor.execution('alpha', mine.id).status, 'SUCCEEDED');
    const flooded = f.executor.execution('beta', first.id);
    assert.equal(flooded.status, 'PRUNED');
    assert.equal(flooded.outcome, 'SUCCEEDED');
    assert.equal(flooded.charged, 1);
    assert.equal(f.executor.snapshot('beta').calls, 300, 'pruning never resets counters');
  });
}

test('a pruned reconciled failure keeps its outcome, charge and evidence hash', async t => {
  const f = setup(t, { maxReceiptsPerFamily: 2 });
  const failing = await f.executor.prepare('alpha', { tool: 'write', args: { fail: true } });
  await assert.rejects(f.executor.execute('alpha', failing.id));
  assert.equal(f.executor.execution('alpha', failing.id).status, 'UNKNOWN');
  f.executor.reconcile(failing.id, { outcome: 'FAILED', actualCost: 0, reference: 'provider-receipt' });
  for (let index = 0; index < 3; index++) await f.run('alpha');
  const receipt = f.executor.execution('alpha', failing.id);
  assert.deepEqual({ ...receipt, reconciliation: { ...receipt.reconciliation } }, {
    id: failing.id, status: 'PRUNED', outcome: 'FAILED', charged: 0,
    reconciliation: { referenceHash: createHash('sha256').update('provider-receipt').digest('hex'), time: 1000 },
  });
  assert.equal(Object.isFrozen(receipt), true);
  // A stub is scoped to its task: another task or tenant cannot read it.
  assert.throws(() => f.executor.execution('beta', failing.id), { code: 'INVALID_PREPARED' });
});

test('the task client accepts a PRUNED receipt only with an outcome', async t => {
  const fake = body => new ExecutorClient({ endpoint: 'http://127.0.0.1:1/', token: 'T'.repeat(43), fetch: async () => Response.json(body) });
  assert.deepEqual(await fake({ id: 'a', status: 'PRUNED', outcome: 'SUCCEEDED', charged: 1 }).execution('a'),
    { id: 'a', status: 'PRUNED', outcome: 'SUCCEEDED', charged: 1 });
  for (const body of [{ id: 'a', status: 'PRUNED' }, { id: 'a', status: 'PRUNED', outcome: 'UNKNOWN' }, { id: 'a', status: 'SUCCEEDED', outcome: 'SUCCEEDED' }]) {
    await assert.rejects(fake(body).execution('a'), { code: 'EXECUTOR_RESPONSE_INVALID' });
  }
});

test('recent events are bounded per tenant and one tenant cannot evict another', async t => {
  const f = setup(t, { maxRecentEventsPerTenant: 64 });
  for (let index = 0; index < 5; index++) await f.run('alpha');
  const before = f.executor.audit({ tenantId: 'alpha' });
  assert.equal(before.length, 5 * 3 + 1, 'task creation plus prepared, admitted and settled per call');
  for (let index = 0; index < 400; index++) await f.run('beta');
  assert.deepEqual(f.executor.audit({ tenantId: 'alpha' }), before);
  assert.equal(f.executor.audit({ tenantId: 'beta' }).length, 64);
  const all = f.executor.audit();
  assert.ok(all.every((event, index) => index === 0 || event.sequence > all[index - 1].sequence), 'sequence is strictly increasing');
  assert.ok(all.some(event => event.tenantId === undefined && event.event === 'EXECUTOR_STARTED'), 'host events keep their own bucket');
});

test('the shared event cap trims the busiest tenant first', async t => {
  const f = setup(t, { maxRecentEventsPerTenant: 1000 });
  for (let index = 0; index < 3; index++) await f.run('alpha');
  const before = f.executor.audit({ tenantId: 'alpha' });
  for (let index = 0; index < 400; index++) await f.run('beta');
  assert.equal(f.executor.audit().length, 1000);
  assert.deepEqual(f.executor.audit({ tenantId: 'alpha' }), before);
});

test('retention options are validated', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-retention-options-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const open = (options, index) => new DurableExecutor({ database: join(directory, `bad-${index}.sqlite`), encryptionKey: Buffer.alloc(32, 1), ...options });
  [{ maxReceiptsPerFamily: 0 }, { maxReceiptsPerFamily: 4097 }, { maxReceiptsPerFamily: 1.5 },
    { maxRecentEventsPerTenant: 15 }, { maxRecentEventsPerTenant: 1001 }].forEach((options, index) => {
    assert.throws(() => open(options, index), { code: 'INVALID_INPUT' });
  });
});

test('archiving a family moves its pruned stubs out of the live ledger', async t => {
  const f = setup(t, { maxReceiptsPerFamily: 1 });
  const first = await f.run('alpha'); await f.run('alpha'); await f.run('alpha'); // Pruning runs on the next preparation.
  assert.equal(f.executor.execution('alpha', first.id).status, 'PRUNED');
  const decide = () => ({ tenantId: 'alpha', taskId: 'alpha', expectedDigest: f.executor.previewTaskFamilyRetirement({ tenantId: 'alpha', taskId: 'alpha' }).reviewDigest });
  f.executor.retireTaskFamily(decide());
  const receipt = f.executor.archiveTaskFamily(decide());
  assert.equal(f.executor.verifyTaskFamilyArchive({ tenantId: 'alpha', archiveId: receipt.archiveId }).archiveId, receipt.archiveId);
  assert.throws(() => f.executor.execution('alpha', first.id), { code: 'INVALID_PREPARED' });
  assert.ok(f.executor.audit().some(event => event.event === 'FAMILY_ARCHIVED' && event.tenantId === 'alpha'));
});
