import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, GuardError } from '../dist/index.js';

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
const budget = () => ({ maxCalls: 10, maxConcurrent: 4, maxCost: 10, deadline: Date.now() + 60_000 });
const rejectedWith = expected => error => error instanceof GuardError && error.code === expected;
function fixture(policy, execute = () => ({ value: 'ok' })) {
  let effects = 0;
  const guard = new AgentGuard({ policy });
  const fingerprint = guard.registerTool({
    name: 'record', description: 'Record a local fixture effect', maxCost: 1,
    resolve: (_args, task) => ({ resourceId: 'one', tenantId: task.tenantId }),
    execute: (args, context) => { effects++; return execute(args, context); },
  });
  guard.approveTool('record', fingerprint);
  const task = guard.createTask({
    id: 'task', principalId: 'user', tenantId: 'tenant',
    grants: [{ tool: 'record', resources: ['one'] }], budget: budget(),
  });
  return { guard, task, effects: () => effects, prepare: (args = {}) => guard.prepare(task, { tool: 'record', args }) };
}

test('simultaneous executions cannot reuse a custom policy decision over stale counters', async () => {
  const f = fixture((_action, snapshot) => snapshot.calls < 1 ? 'allow' : 'deny');
  const prepared = await Promise.all([f.prepare(), f.prepare()]);
  const outcomes = await Promise.allSettled(prepared.map(action => f.guard.execute(action)));
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  const rejectedIndex = outcomes.findIndex(result => result.status === 'rejected');
  assert.ok(rejectedWith('POLICY_STATE_CHANGED')(outcomes[rejectedIndex].reason));
  assert.equal(f.effects(), 1);
  assert.equal(f.guard.snapshot(f.task).calls, 1);
  // Rejection did not consume the prepared action, but a fresh policy evaluation now denies it.
  await assert.rejects(f.guard.execute(prepared[rejectedIndex]), rejectedWith('POLICY_DENIED'));
  assert.equal(f.effects(), 1);
});

test('preparation rejects a policy decision when task state changed while it awaited', async () => {
  const entered = deferred(); const release = deferred();
  let pause = false;
  const f = fixture(async () => {
    if (pause) { pause = false; entered.resolve(); await release.promise; }
    return 'allow';
  });
  const other = await f.prepare();
  pause = true;
  const pending = f.prepare();
  const checked = assert.rejects(pending, rejectedWith('POLICY_STATE_CHANGED'));
  await entered.promise;
  await f.guard.execute(other);
  release.resolve();
  await checked;
  assert.equal(f.effects(), 1);
});

test('settlement changes invalidate pending policy snapshots even without a new call', async () => {
  const handlerEntered = deferred(); const handlerRelease = deferred();
  const policyEntered = deferred(); const policyRelease = deferred();
  let pause = false;
  const f = fixture(async action => {
    if (pause && action.args.second) { policyEntered.resolve(); await policyRelease.promise; }
    return 'allow';
  }, async args => {
    if (!args.second) { handlerEntered.resolve(); await handlerRelease.promise; }
    return { value: 'ok', actualCost: 1 };
  });
  const first = await f.prepare(); const second = await f.prepare({ second: true });
  const active = f.guard.execute(first);
  await handlerEntered.promise;
  pause = true;
  const pending = f.guard.execute(second);
  const checked = assert.rejects(pending, rejectedWith('POLICY_STATE_CHANGED'));
  await policyEntered.promise;
  const before = f.guard.snapshot(f.task);
  handlerRelease.resolve(); await active;
  assert.equal(f.guard.snapshot(f.task).calls, before.calls);
  policyRelease.resolve(); await checked;
  assert.equal(f.effects(), 1);
  assert.equal(f.guard.snapshot(f.task).spent, 1);
  pause = false;
  assert.equal(await f.guard.execute(second), 'ok');
  assert.equal(f.effects(), 2);
});

test('sibling sensitivity invalidates a pending custom policy decision for an internal action', async () => {
  const entered = deferred(); const release = deferred();
  let pause = false; let effects = 0;
  const guard = new AgentGuard({ policy: async (action, snapshot) => {
    if (pause && action.tool === 'act') { entered.resolve(); await release.promise; }
    return snapshot.sensitive ? 'deny' : 'allow';
  } });
  for (const name of ['read', 'act']) {
    const fingerprint = guard.registerTool({
      name, description: name,
      resolve: (_args, task) => ({ resourceId: 'one', tenantId: task.tenantId, sensitive: name === 'read' }),
      execute: () => { if (name === 'act') effects++; return { value: 'ok' }; },
    });
    guard.approveTool(name, fingerprint);
  }
  const grants = ['read', 'act'].map(tool => ({ tool, resources: ['one'] }));
  const parent = guard.createTask({ id: 'parent', principalId: 'user', tenantId: 'tenant', grants, budget: budget() });
  const childBudget = { ...budget(), deadline: Date.now() + 30_000 };
  const reader = guard.delegateTask(parent, { id: 'reader', grants, budget: childBudget });
  const actor = guard.delegateTask(parent, { id: 'actor', grants, budget: childBudget });
  const read = await guard.prepare(reader, { tool: 'read', args: {} });
  const action = await guard.prepare(actor, { tool: 'act', args: {} });
  pause = true;
  const pending = guard.execute(action);
  const checked = assert.rejects(pending, rejectedWith('POLICY_STATE_CHANGED'));
  await entered.promise;
  await guard.execute(read);
  release.resolve(); await checked;
  assert.equal(guard.snapshot(actor).calls, 0);
  assert.equal(guard.snapshot(actor).sensitive, true);
  assert.equal(effects, 0);
});
