import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, monotonicClock } from '@shieldaai/agent-guard';

function fixture(options = {}, tool = {}) {
  const events = [];
  const guard = new AgentGuard({ onDecision: event => events.push(event), ...options });
  const register = (extra = {}) =>
    guard.registerTool({
      name: 'write',
      description: 'fixture',
      maxCost: 5,
      resolve: () => ({ resourceId: 'doc', tenantId: 'acme' }),
      execute: () => ({ value: 'done', actualCost: 2 }),
      ...tool,
      ...extra,
    });
  guard.approveTool('write', register());
  const task = (id = 'task', budget = {}) =>
    guard.createTask({
      id,
      principalId: 'alice',
      tenantId: 'acme',
      grants: [{ tool: 'write', resources: ['doc'] }],
      budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 100, deadline: Date.now() + 60_000, ...budget },
    });
  return { guard, events, register, task };
}
const prepare = (guard, task) => guard.prepare(task, { tool: 'write', args: { secret: 'never-in-events' } });

test('executeDetailed returns the value, the charged cost and the action ID', async () => {
  const f = fixture();
  const task = f.task();
  const prepared = await prepare(f.guard, task);
  const result = await f.guard.executeDetailed(prepared);
  assert.deepEqual({ ...result }, { value: 'done', charged: 2, actionId: prepared.id });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(await f.guard.execute(await prepare(f.guard, task)), 'done');
});

test('retireTask frees the ID and memory; old handles and prepared actions stop working', async () => {
  const f = fixture();
  const old = f.task('job');
  const child = f.guard.delegateTask(old, {
    id: 'job-child',
    grants: [{ tool: 'write', resources: ['doc'] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 5, deadline: Date.now() + 30_000 },
  });
  const prepared = await prepare(f.guard, old);
  f.guard.retireTask(old);
  assert.throws(() => f.guard.snapshot(old), { code: 'INVALID_TASK' });
  await assert.rejects(f.guard.execute(prepared), { code: 'TASK_REVOKED' });
  assert.equal(f.guard.snapshot(child).revoked, true, 'descendants stay revoked');
  const reused = f.task('job');
  assert.equal(await f.guard.execute(await prepare(f.guard, reused)), 'done', 'the ID can be reused');
});

test('unapproveTool and unregisterTool withdraw a tool from prepared actions', async () => {
  const f = fixture();
  const task = f.task();
  let prepared = await prepare(f.guard, task);
  f.guard.unapproveTool('write');
  await assert.rejects(f.guard.execute(prepared), { code: 'TOOL_UNAPPROVED' });
  await assert.rejects(prepare(f.guard, task), { code: 'TOOL_UNAPPROVED' });
  f.guard.approveTool('write', f.register());
  prepared = await prepare(f.guard, task);
  f.guard.unregisterTool('write');
  await assert.rejects(f.guard.execute(prepared), { code: 'TOOL_CHANGED' });
  await assert.rejects(prepare(f.guard, task), { code: 'TOOL_UNKNOWN' });
  assert.throws(() => f.guard.unregisterTool('write'), { code: 'TOOL_UNKNOWN' });
  assert.throws(() => f.guard.unapproveTool('missing'), { code: 'TOOL_UNKNOWN' });
});

test('onDecision records each decision with identifiers only, and cannot change an outcome', async () => {
  const f = fixture({}, { requiresApproval: true });
  const task = f.task();
  const prepared = await prepare(f.guard, task);
  await assert.rejects(f.guard.execute(prepared), { code: 'APPROVAL_REQUIRED' });
  const approvalId = f.guard.approve(prepared, { approverId: 'bob', expiresAt: Date.now() + 10_000 });
  await f.guard.execute(prepared, { approvalId });
  await assert.rejects(f.guard.prepare(task, { tool: 'write-typo', args: {} }), { code: 'TOOL_UNKNOWN' });
  assert.deepEqual(
    f.events.map(event => [event.operation, event.outcome, event.code]),
    [
      ['prepare', 'allowed', undefined],
      ['execute', 'denied', 'APPROVAL_REQUIRED'],
      ['approve', 'allowed', undefined],
      ['execute', 'succeeded', undefined],
      ['prepare', 'denied', 'TOOL_UNKNOWN'],
    ],
  );
  assert.equal(f.events[2].approverId, 'bob');
  assert.equal(f.events[4].tool, undefined, 'an unregistered tool name from the model is not echoed');
  assert.equal(JSON.stringify(f.events).includes('never-in-events'), false);
  const throwing = new AgentGuard({
    onDecision: () => {
      throw new Error('collector down');
    },
  });
  throwing.approveTool(
    't',
    throwing.registerTool({
      name: 't',
      description: 'x',
      resolve: () => ({ resourceId: 'r', tenantId: 'a' }),
      execute: () => ({ value: 1 }),
    }),
  );
  const handle = throwing.createTask({
    id: 'x',
    principalId: 'p',
    tenantId: 'a',
    grants: [{ tool: 't', resources: ['r'] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 10_000 },
  });
  assert.equal(await throwing.execute(await throwing.prepare(handle, { tool: 't', args: {} })), 1);
});

test('a dispatched failure is reported as failed, not denied', async () => {
  const f = fixture(
    {},
    {
      execute: () => {
        throw new Error('backend down');
      },
    },
  );
  await assert.rejects(f.guard.execute(await prepare(f.guard, f.task())), { code: 'TOOL_FAILED' });
  assert.deepEqual(f.events.at(-1).outcome, 'failed');
});

test('snapshot includes the budget and lineage revocation', () => {
  const f = fixture();
  const task = f.task('s', { maxCalls: 3 });
  const snapshot = f.guard.snapshot(task);
  assert.equal(snapshot.budget.maxCalls, 3);
  assert.equal(snapshot.revoked, false);
  f.guard.revokeTask(task);
  assert.equal(f.guard.snapshot(task).revoked, true);
});

test('limits replace the fixed approval and policy bounds and are validated', async () => {
  const f = fixture({ limits: { maxApprovalsPerAction: 1 } }, { requiresApproval: true });
  const prepared = await prepare(f.guard, f.task());
  f.guard.approve(prepared, { approverId: 'bob', expiresAt: Date.now() + 10_000 });
  assert.throws(() => f.guard.approve(prepared, { approverId: 'bob', expiresAt: Date.now() + 10_000 }), {
    code: 'ACTION_APPROVAL_LIMIT',
  });
  const slow = new AgentGuard({
    limits: { policyTimeoutMs: 100 },
    policy: () => new Promise(resolve => setTimeout(() => resolve('allow'), 400)),
  });
  slow.approveTool(
    't',
    slow.registerTool({
      name: 't',
      description: 'x',
      resolve: () => ({ resourceId: 'r', tenantId: 'a' }),
      execute: () => ({ value: 1 }),
    }),
  );
  const handle = slow.createTask({
    id: 'x',
    principalId: 'p',
    tenantId: 'a',
    grants: [{ tool: 't', resources: ['r'] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 10_000 },
  });
  await assert.rejects(slow.prepare(handle, { tool: 't', args: {} }), { code: 'POLICY_TIMEOUT' });
  for (const limits of [
    { maxApprovalsPerAction: 0 },
    { maxPolicyEvaluations: 1025 },
    { policyTimeoutMs: 99 },
    { maxPolicyEvaluationsPerFamily: 1.5 },
    null,
  ]) {
    assert.throws(() => new AgentGuard({ limits }), { code: 'INVALID_INPUT' }, JSON.stringify(limits));
  }
  assert.throws(() => new AgentGuard({ onDecision: 'yes' }), { code: 'INVALID_INPUT' });
});

test('monotonicClock is a millisecond clock close to wall time', () => {
  const now = monotonicClock();
  assert.ok(Number.isSafeInteger(now) && Math.abs(now - Date.now()) < 60_000);
  assert.ok(monotonicClock() >= now);
  assert.doesNotThrow(() => new AgentGuard({ clock: monotonicClock }));
});
