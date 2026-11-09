import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';

function setup(t, budget = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-capacity-')));
  const executor = new DurableExecutor({
    database: join(directory, 'ledger.sqlite'),
    encryptionKey: Buffer.alloc(32, 9),
    clock: () => 1000,
  });
  let release;
  const blocked = new Promise(resolve => {
    release = resolve;
  });
  let calls = 0;
  const fingerprint = executor.registerTool({
    name: 'write',
    description: 'Write a record',
    requiresApproval: true,
    maxCost: 5,
    resolve: () => ({ resourceId: 'record', tenantId: 'tenant' }),
    execute: async () => {
      calls++;
      if (calls === 1) await blocked;
      return { value: calls, actualCost: 5 };
    },
  });
  executor.approveTool('write', fingerprint);
  executor.createTask({
    id: 'task',
    principalId: 'operator',
    tenantId: 'tenant',
    grants: [{ tool: 'write', resources: ['record'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 20, deadline: 100_000, ...budget },
  });
  t.after(() => {
    release();
    executor.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return { executor, release: () => release() };
}
const approve = (executor, id) => executor.approve(id, { approverId: 'reviewer', expiresAt: 2000 });
const settle = () => new Promise(resolve => setImmediate(resolve));

test('durable preparation and approval are not refused by a call in flight', async t => {
  const { executor, release } = setup(t);
  const first = await executor.prepare('task', { tool: 'write', args: {} });
  const running = executor.execute('task', first.id, { approvalId: approve(executor, first.id) });
  await settle();
  assert.equal(executor.snapshot('task').concurrent, 1);

  const second = await executor.prepare('task', { tool: 'write', args: {} });
  const approvalId = approve(executor, second.id);
  await assert.rejects(executor.execute('task', second.id, { approvalId }), { code: 'CONCURRENCY_EXCEEDED' });

  release();
  assert.equal(await running, 1);
  assert.equal(
    await executor.execute('task', second.id, { approvalId }),
    2,
    'the durable approval survives the refused dispatch',
  );
});

test('durable dispatch still enforces reserved cost; permanent capacity refuses preparation', async t => {
  const { executor, release } = setup(t, { maxConcurrent: 2, maxCost: 5 });
  const first = await executor.prepare('task', { tool: 'write', args: {} });
  const running = executor.execute('task', first.id, { approvalId: approve(executor, first.id) });
  await settle();
  const second = await executor.prepare('task', { tool: 'write', args: {} });
  const approvalId = approve(executor, second.id);
  await assert.rejects(executor.execute('task', second.id, { approvalId }), { code: 'COST_BUDGET_EXCEEDED' });
  release();
  await running;
  await assert.rejects(executor.prepare('task', { tool: 'write', args: {} }), { code: 'COST_BUDGET_EXCEEDED' });
});
