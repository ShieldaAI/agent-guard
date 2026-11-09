import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, assertActionAuthority } from '../dist/index.js';

function gated(t, budget = {}) {
  const guard = new AgentGuard();
  let release;
  const blocked = new Promise(resolve => {
    release = resolve;
  });
  let calls = 0;
  const fingerprint = guard.registerTool({
    name: 'write',
    description: 'Write a record',
    requiresApproval: true,
    maxCost: 5,
    resolve: () => ({ resourceId: 'record', tenantId: 'acme' }),
    execute: async () => {
      calls++;
      if (calls === 1) await blocked;
      return { value: calls, actualCost: 5 };
    },
  });
  guard.approveTool('write', fingerprint);
  const task = guard.createTask({
    id: 'task',
    principalId: 'operator',
    tenantId: 'acme',
    grants: [{ tool: 'write', resources: ['record'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 20, deadline: Date.now() + 60_000, ...budget },
  });
  t.after(() => release());
  return { guard, task, release: () => release(), calls: () => calls };
}
const approve = (guard, prepared) =>
  guard.approve(prepared, { approverId: 'reviewer', expiresAt: Date.now() + 30_000 });

test('a call in flight does not refuse preparation or a reviewer approval', async t => {
  const { guard, task, release } = gated(t);
  const first = await guard.prepare(task, { tool: 'write', args: {} });
  const running = guard.execute(first, { approvalId: approve(guard, first) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(guard.snapshot(task).concurrent, 1);

  const second = await guard.prepare(task, { tool: 'write', args: {} });
  const approvalId = approve(guard, second);
  await assert.rejects(guard.execute(second, { approvalId }), { code: 'CONCURRENCY_EXCEEDED' });

  release();
  assert.equal(await running, 1);
  assert.equal(await guard.execute(second, { approvalId }), 2, 'the approval survives the refused dispatch');
});

test('cost reserved by a call in flight is enforced at dispatch, not at preparation', async t => {
  const { guard, task, release } = gated(t, { maxConcurrent: 2, maxCost: 5 });
  const first = await guard.prepare(task, { tool: 'write', args: {} });
  const running = guard.execute(first, { approvalId: approve(guard, first) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(guard.snapshot(task).reserved, 5);

  const second = await guard.prepare(task, { tool: 'write', args: {} });
  const approvalId = approve(guard, second);
  await assert.rejects(guard.execute(second, { approvalId }), { code: 'COST_BUDGET_EXCEEDED' });
  release();
  await running;
  // Once settled, the cost is spent: permanent capacity now refuses preparation as well.
  await assert.rejects(guard.prepare(task, { tool: 'write', args: {} }), { code: 'COST_BUDGET_EXCEEDED' });
});

test('permanent capacity still refuses preparation', async t => {
  const { guard, task, release } = gated(t, { maxCalls: 1 });
  const first = await guard.prepare(task, { tool: 'write', args: {} });
  const running = guard.execute(first, { approvalId: approve(guard, first) });
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(guard.prepare(task, { tool: 'write', args: {} }), { code: 'CALL_BUDGET_EXCEEDED' });
  release();
  await running;
});

test('shared gates default to dispatch and reject an unknown phase', () => {
  const action = { tool: 'write', resourceId: 'record', tenantId: 'acme', args: {} };
  const ancestor = {
    identity: { id: 'task', principalId: 'operator', tenantId: 'acme' },
    grants: [{ tool: 'write', resources: ['record'] }],
    allowedRecipients: [],
    allowControlPlane: false,
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 10, deadline: 10_000 },
    snapshot: { calls: 1, concurrent: 1, spent: 0, reserved: 8, sensitive: false },
    revoked: false,
  };
  const options = { now: 1, maxCost: 5, controlPlane: false, sensitive: false, secretValues: [] };
  assert.throws(() => assertActionAuthority(action, [ancestor], options), { code: 'CONCURRENCY_EXCEEDED' });
  assert.throws(() => assertActionAuthority(action, [ancestor], { ...options, phase: 'dispatch' }), {
    code: 'CONCURRENCY_EXCEEDED',
  });
  assert.doesNotThrow(() => assertActionAuthority(action, [ancestor], { ...options, phase: 'prepare' }));
  assert.throws(() => assertActionAuthority(action, [ancestor], { ...options, phase: 'later' }), {
    code: 'INVALID_INPUT',
  });
  assert.throws(
    () => assertActionAuthority(action, [{ ...ancestor, revoked: true }], { ...options, phase: 'prepare' }),
    { code: 'TASK_REVOKED' },
  );
});
