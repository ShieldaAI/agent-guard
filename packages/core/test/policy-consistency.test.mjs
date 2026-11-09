import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, GuardError } from '../dist/index.js';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const code = expected => error => error instanceof GuardError && error.code === expected;

function fixture({ policy, maxPolicyAttempts, maxConcurrent = 10, maxCalls = 20, handlerMs = 30 } = {}) {
  let effects = 0; let evaluations = 0;
  const guard = new AgentGuard({
    ...(maxPolicyAttempts === undefined ? {} : { maxPolicyAttempts }),
    policy: async (action, snapshot, context) => { evaluations++; return policy(action, snapshot, context); },
  });
  const fingerprint = guard.registerTool({
    name: 'call', description: 'Parallel-safe fixture call', maxCost: 1,
    resolve: (_args, task) => ({ resourceId: 'one', tenantId: task.tenantId }),
    execute: async () => { effects++; await sleep(handlerMs); return { value: effects }; },
  });
  guard.approveTool('call', fingerprint);
  const task = guard.createTask({
    id: 'task', principalId: 'user', tenantId: 'tenant', grants: [{ tool: 'call', resources: ['one'] }],
    budget: { maxCalls, maxConcurrent, maxCost: 100, deadline: Date.now() + 60_000 },
  });
  const prepare = () => guard.prepare(task, { tool: 'call', args: {} });
  return { guard, task, prepare, effects: () => effects, evaluations: () => evaluations };
}

test('parallel executions on one task succeed under an async allow-all policy', async () => {
  const f = fixture({ policy: async () => { await sleep(10); return 'allow'; } });
  const prepared = await Promise.all(Array.from({ length: 5 }, f.prepare));
  const outcomes = await Promise.allSettled(prepared.map(action => f.guard.execute(action)));
  assert.deepEqual(outcomes.map(result => result.status), Array(5).fill('fulfilled'));
  assert.equal(f.effects(), 5);
  assert.equal(f.guard.snapshot(f.task).calls, 5);
  assert.equal(f.guard.snapshot(f.task).concurrent, 0);
});

test('parallel preparations on a busy task succeed under an async policy', async () => {
  const f = fixture({ policy: async () => { await sleep(10); return 'allow'; }, handlerMs: 25 });
  const running = Promise.all((await Promise.all([f.prepare(), f.prepare()])).map(action => f.guard.execute(action)));
  // Counters change while these preparations wait on the policy.
  const prepared = await Promise.all(Array.from({ length: 3 }, f.prepare));
  assert.equal(prepared.length, 3);
  await running;
});

test('a counter-aware policy is re-evaluated on fresh counters, never reused over stale ones', async () => {
  const f = fixture({ policy: async (_action, snapshot) => { await sleep(5); return snapshot.calls < 2 ? 'allow' : 'deny'; } });
  const prepared = await Promise.all(Array.from({ length: 4 }, f.prepare));
  const outcomes = await Promise.allSettled(prepared.map(action => f.guard.execute(action)));
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 2);
  assert.ok(outcomes.filter(result => result.status === 'rejected').every(result => code('POLICY_DENIED')(result.reason)));
  assert.equal(f.effects(), 2, 'the policy limit of two calls holds under concurrency');
});

test('re-evaluation is bounded by maxPolicyAttempts', async () => {
  // Every evaluation of the victim call is invalidated: while it waits, another call on the
  // same task dispatches. The victim must stop after exactly maxPolicyAttempts evaluations.
  let victimEvaluations = 0; let noise = []; let armed = false;
  const f = fixture({
    maxPolicyAttempts: 3, handlerMs: 1,
    policy: async action => {
      if (!action.args.victim || !armed) return 'allow';
      victimEvaluations++;
      const next = noise.shift();
      const running = next && f.guard.execute(next);
      await sleep(15);
      await running;
      return 'allow';
    },
  });
  noise = await Promise.all(Array.from({ length: 5 }, f.prepare));
  const victim = await f.guard.prepare(f.task, { tool: 'call', args: { victim: true } });
  armed = true;
  await assert.rejects(f.guard.execute(victim), code('POLICY_STATE_CHANGED'));
  assert.equal(victimEvaluations, 3);
  assert.equal(f.effects(), 3, 'only the interleaved calls ran');
  // Every policy slot and turn was released: later work on the task is admitted.
  assert.equal(typeof (await f.guard.execute(await f.prepare())), 'number');
});

test('maxPolicyAttempts 1 keeps the strict single-evaluation behaviour', async () => {
  const f = fixture({ policy: async () => { await sleep(10); return 'allow'; }, maxPolicyAttempts: 1 });
  const prepared = await Promise.all([f.prepare(), f.prepare(), f.prepare()]);
  const outcomes = await Promise.allSettled(prepared.map(action => f.guard.execute(action)));
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  assert.ok(outcomes.filter(result => result.status === 'rejected').every(result => code('POLICY_STATE_CHANGED')(result.reason)));
});

test('maxPolicyAttempts must be an integer from 1 to 16', () => {
  for (const value of [0, 17, 1.5, '3', null, Number.NaN]) {
    assert.throws(() => new AgentGuard({ maxPolicyAttempts: value }), code('INVALID_INPUT'));
  }
  assert.doesNotThrow(() => new AgentGuard({ maxPolicyAttempts: 16 }));
});
