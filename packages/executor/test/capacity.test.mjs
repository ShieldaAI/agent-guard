import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DurableExecutor, startExecutorServer } from '../dist/index.js';

const task = (id, extra = {}) => ({
  id,
  principalId: 'operator',
  tenantId: 'tenant',
  grants: [{ tool: 'test', resources: ['item'] }],
  budget: { maxCalls: 50, maxConcurrent: 2, maxCost: 250, deadline: 100_000 },
  ...extra,
});
function setup(t, options = {}) {
  let now = 1000;
  let effects = 0;
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: Buffer.alloc(32, 7),
    clock: () => now,
    maxRecords: 16,
    maxPendingActionsPerFamily: 2,
    maxTasksPerFamily: 3,
    ...options,
  });
  t.after(() => executor.close());
  const register = (extra = {}) => {
    const fp = executor.registerTool({
      name: 'test',
      description: 'bounded fixture',
      maxCost: 5,
      resolve: () => ({ resourceId: 'item', tenantId: 'tenant' }),
      execute: () => {
        effects++;
        return { value: 'ok', actualCost: 3 };
      },
      ...extra,
    });
    executor.approveTool('test', fp);
  };
  register();
  return {
    executor,
    register,
    now: value => {
      now = value;
    },
    effects: () => effects,
  };
}
const prepare = (executor, taskId, args = null) => executor.prepare(taskId, { tool: 'test', args });

test('an HTTP task family cannot flood a stalled policy or block unrelated work', { timeout: 5000 }, async t => {
  const signals = [];
  let unblock, full;
  const held = new Promise(resolve => {
    unblock = resolve;
  });
  const saturated = new Promise(resolve => {
    full = resolve;
  });
  const { executor, effects } = setup(t, {
    policy: async (_action, task, { signal }) => {
      if (task.id !== 'other') {
        signals.push(signal);
        if (signals.length === 8) full();
        await held;
      }
      return 'allow';
    },
  });
  const parent = executor.createTask(task('parent'));
  const handoff = executor.createTask(task('handoff'), { sourceTaskId: 'parent' });
  executor.createTask(task('other'));
  const service = await startExecutorServer({ executor, adminToken: 'A'.repeat(43), operatorId: 'operator' });
  t.after(() => service.close());
  const post = async token => {
    const response = await fetch(service.url + '/v1/task/prepare', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify({ tool: 'test', args: null }),
    });
    return response.json();
  };
  try {
    const pending = Promise.all(Array.from({ length: 8 }, (_, i) => post(i % 2 ? parent.token : handoff.token)));
    await saturated;
    assert.deepEqual(await post(handoff.token), { error: 'POLICY_BUSY', retryable: true });
    const action = await prepare(executor, 'other');
    assert.equal(await executor.execute('other', action.id), 'ok');
    executor.revokeTask('parent');
    assert.deepEqual(await pending, Array(8).fill({ error: 'TASK_REVOKED', retryable: false }));
    assert(signals.every(signal => signal.aborted));
    assert.equal(signals.length, 8);
    assert.equal(effects(), 1);
    assert.equal(executor.snapshot('parent').calls, 0);
  } finally {
    unblock();
  }
});

test('pending action count is shared by delegates and leaves capacity for another family', async t => {
  const { executor, effects } = setup(t);
  executor.createTask(task('parent'));
  const { principalId: _principal, tenantId: _tenant, ...child } = task('child');
  executor.delegateTask('parent', child);
  executor.createTask(task('other'));
  await prepare(executor, 'parent');
  await prepare(executor, 'child');
  await assert.rejects(prepare(executor, 'child'), { code: 'FAMILY_PENDING_LIMIT' });
  await assert.rejects(prepare(executor, 'parent'), { code: 'FAMILY_PENDING_LIMIT' });
  const other = await prepare(executor, 'other');
  assert.equal(await executor.execute('other', other.id), 'ok');
  assert.equal(effects(), 1);
  assert.equal(executor.snapshot('parent').calls, 0);
});

test('oversized prepared arguments cannot consume a family or the whole ledger', async t => {
  const { executor, effects } = setup(t, { maxPendingBytesPerFamily: 1500 });
  executor.createTask(task('attacker'));
  executor.createTask(task('other'));
  await assert.rejects(prepare(executor, 'attacker', { text: 'x'.repeat(2000) }), {
    code: 'FAMILY_PENDING_BYTES_LIMIT',
  });
  const own = await prepare(executor, 'attacker');
  const other = await prepare(executor, 'other');
  assert.equal(await executor.execute('attacker', own.id), 'ok');
  assert.equal(await executor.execute('other', other.id), 'ok');
  assert.equal(effects(), 2);
});

test('task count and task-option bytes are bounded across delegation and handoffs', t => {
  const { executor } = setup(t, { maxTasksPerFamily: 2, maxTaskBytesPerFamily: 1500 });
  executor.createTask(task('parent'));
  const { principalId: _principal, tenantId: _tenant, ...child } = task('child');
  executor.delegateTask('parent', child);
  assert.throws(() => executor.delegateTask('parent', { ...child, id: 'third' }), { code: 'FAMILY_TASK_LIMIT' });
  assert.throws(() => executor.createTask(task('handoff'), { sourceTaskId: 'parent' }), { code: 'FAMILY_TASK_LIMIT' });
  const oversized = task('oversized', { allowedRecipients: ['r'.repeat(2000)] });
  assert.throws(() => executor.createTask(oversized), { code: 'FAMILY_TASK_BYTES_LIMIT' });
  assert.equal(executor.createTask(task('other')).taskId, 'other');
});

test('expired and revoked preparations are pruned without consuming calls', async t => {
  const { executor, now } = setup(t);
  executor.createTask(task('expired', { budget: { ...task('').budget, deadline: 2000 } }));
  executor.createTask(task('revoked'));
  executor.createTask(task('other'));
  const expired = await prepare(executor, 'expired');
  const revoked = await prepare(executor, 'revoked');
  executor.revokeTask('revoked');
  now(2000);
  await prepare(executor, 'other');
  assert.throws(() => executor.execution('expired', expired.id), { code: 'INVALID_PREPARED' });
  assert.throws(() => executor.execution('revoked', revoked.id), { code: 'INVALID_PREPARED' });
  assert.equal(executor.snapshot('expired').calls, 0);
  assert.equal(executor.snapshot('revoked').calls, 0);
});

test('metadata and policy invalidation release preparation slots and destroy their approvals', async t => {
  const { executor, register } = setup(t, { maxPendingActionsPerFamily: 1 });
  executor.createTask(task('task'));
  const oldTool = await prepare(executor, 'task');
  const staleApproval = executor.approve(oldTool.id, { approverId: 'operator', expiresAt: 3000 });
  register({ description: 'changed metadata' });
  const oldPolicy = await prepare(executor, 'task');
  assert.throws(() => executor.execution('task', oldTool.id), { code: 'INVALID_PREPARED' });
  executor.setPolicy(() => 'allow');
  const current = await prepare(executor, 'task');
  assert.throws(() => executor.execution('task', oldPolicy.id), { code: 'INVALID_PREPARED' });
  await assert.rejects(executor.execute('task', current.id, { approvalId: staleApproval }), {
    code: 'APPROVAL_INVALID',
  });
  assert.equal(await executor.execute('task', current.id), 'ok');
});

test('expired approvals can be renewed indefinitely within the active approval bound', async t => {
  const { executor, now } = setup(t);
  executor.createTask(task('task'));
  const action = await prepare(executor, 'task');
  for (let i = 0; i < 30; i++) {
    now(1000 + i);
    executor.approve(action.id, { approverId: 'reviewer', expiresAt: 1001 + i });
  }
  for (let i = 0; i < 3; i++) executor.approve(action.id, { approverId: 'reviewer', expiresAt: 3000 });
  assert.throws(() => executor.approve(action.id, { approverId: 'reviewer', expiresAt: 3000 }), {
    code: 'ACTION_APPROVAL_LIMIT',
  });
  now(4000);
  const approvalId = executor.approve(action.id, { approverId: 'reviewer', expiresAt: 5000 });
  assert.equal(await executor.execute('task', action.id, { approvalId }), 'ok');
});

test('pruning preserves UNKNOWN and reservations; reconciliation validates outcomes and records evidence hash', async t => {
  const { executor, register, now } = setup(t, { maxPendingActionsPerFamily: 1 });
  register({
    execute: () => {
      throw Error('backend disconnected');
    },
  });
  executor.createTask(task('task'));
  executor.createTask(task('other'));
  const action = await prepare(executor, 'task');
  await assert.rejects(executor.execute('task', action.id), { code: 'TOOL_FAILED' });
  await prepare(executor, 'other');
  await assert.rejects(prepare(executor, 'task'), { code: 'FAMILY_PENDING_LIMIT' });
  assert.equal(executor.execution('task', action.id).status, 'UNKNOWN');
  assert.equal(executor.snapshot('task').reserved, 5);
  assert.equal(executor.snapshot('task').concurrent, 1);
  for (const outcome of ['UNKNOWN', 'PREPARED', null, undefined]) {
    assert.throws(() => executor.reconcile(action.id, { outcome, actualCost: 0, reference: 'forged' }), {
      code: 'RECONCILIATION_INVALID',
    });
    assert.equal(executor.snapshot('task').reserved, 5);
    assert.equal(executor.snapshot('task').concurrent, 1);
  }
  now(1500);
  executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 2, reference: 'private-provider-receipt' });
  const result = executor.execution('task', action.id);
  assert.deepEqual(
    { ...result.reconciliation },
    { referenceHash: createHash('sha256').update('private-provider-receipt').digest('hex'), time: 1500 },
  );
  assert.equal(JSON.stringify(result).includes('private-provider-receipt'), false);
  assert.equal(Object.isFrozen(result.reconciliation), true);
  assert.equal(executor.snapshot('task').calls, 1);
  assert.equal(executor.snapshot('task').spent, 2);
  assert.equal(executor.snapshot('task').reserved, 0);
  assert.equal(executor.snapshot('task').concurrent, 0);
  assert.throws(() => executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 0, reference: 'again' }), {
    code: 'RECONCILIATION_INVALID',
  });
  await prepare(executor, 'task');
});

test('bounded terminal retention never resets cumulative call or spend budgets', async t => {
  const { executor, effects } = setup(t, { maxRecords: 8, maxTasksPerFamily: 2 });
  executor.createTask(task('task', { budget: { ...task('').budget, maxCalls: 7 } }));
  let first;
  for (let i = 0; i < 7; i++) {
    const action = await prepare(executor, 'task');
    first ??= action;
    await executor.execute('task', action.id);
  }
  const pruned = executor.execution('task', first.id);
  assert.equal(pruned.status, 'PRUNED');
  assert.equal(pruned.outcome, 'SUCCEEDED');
  assert.equal(pruned.charged, 3);
  await assert.rejects(prepare(executor, 'task'), { code: 'CALL_BUDGET_EXCEEDED' });
  assert.equal(effects(), 7);
  assert.equal(executor.snapshot('task').calls, 7);
  assert.equal(executor.snapshot('task').spent, 21);
});
