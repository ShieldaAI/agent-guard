import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, isGuardError } from '@shieldaai/agent-guard';
import { random } from './helpers/random.mjs';

const MAX_COST = 4;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Random interleavings of prepare/execute on a two-level task tree, with handlers that
 * succeed (random actual cost), throw, or report an invalid cost, plus random child
 * revocation. After every step and at the end, the guard's counters must match a
 * simple model and never exceed any ancestor's budget.
 */
async function run(seed) {
  const rng = random(seed);
  const guard = new AgentGuard();
  const charges = []; let invocations = 0;
  guard.approveTool('work', guard.registerTool({ name: 'work', description: 'model fixture', maxCost: MAX_COST,
    resolve: () => ({ resourceId: 'r', tenantId: 't' }),
    execute: async args => {
      invocations++;
      await sleep(args.delay);
      if (args.mode === 'throw') { charges.push(MAX_COST); throw new Error('handler failed'); }
      if (args.mode === 'bad-cost') { charges.push(MAX_COST); return { value: 0, actualCost: MAX_COST + 1 }; }
      charges.push(args.cost);
      return { value: 1, actualCost: args.cost };
    } }));
  const budget = { maxCalls: rng.int(3, 12), maxConcurrent: rng.int(1, 4), maxCost: rng.int(4, 30), deadline: Date.now() + 60_000 };
  const root = guard.createTask({ id: 'root', principalId: 'p', tenantId: 't', grants: [{ tool: 'work', resources: ['r'] }], budget });
  const children = [0, 1].map(index => guard.delegateTask(root, { id: `child-${index}`, grants: [{ tool: 'work', resources: ['r'] }],
    budget: { maxCalls: rng.int(1, budget.maxCalls), maxConcurrent: rng.int(1, budget.maxConcurrent), maxCost: rng.int(1, budget.maxCost), deadline: budget.deadline } }));
  const tasks = [root, ...children];
  const check = label => {
    const [r, ...kids] = tasks.map(task => guard.snapshot(task));
    for (const snapshot of [r, ...kids]) {
      assert.ok(snapshot.calls <= snapshot.budget.maxCalls, `${label}: calls within budget`);
      assert.ok(snapshot.concurrent <= snapshot.budget.maxConcurrent, `${label}: concurrency within budget`);
      assert.ok(snapshot.spent + snapshot.reserved <= snapshot.budget.maxCost, `${label}: cost within budget`);
      assert.ok(snapshot.calls <= r.calls && snapshot.spent <= r.spent, `${label}: root counts every descendant`);
    }
    assert.equal(r.calls, invocations, `${label}: one call per handler invocation`);
  };
  const running = [];
  for (let step = 0; step < 30; step++) {
    const task = rng.pick(tasks);
    if (rng.next() < 0.08 && task !== root) guard.revokeTask(task);
    const args = { delay: rng.int(0, 4), mode: rng.pick(['ok', 'ok', 'ok', 'throw', 'bad-cost']), cost: rng.int(0, MAX_COST) };
    running.push(guard.prepare(task, { tool: 'work', args }).then(prepared => guard.execute(prepared)).catch(error => {
      assert.ok(isGuardError(error), `seed ${seed}: only GuardError escapes (${error})`);
    }));
    check(`seed ${seed} step ${step}`);
    if (rng.next() < 0.4) await sleep(rng.int(0, 3));
  }
  await Promise.all(running);
  check(`seed ${seed} end`);
  const final = guard.snapshot(root);
  assert.equal(final.concurrent, 0, `seed ${seed}: nothing left running`);
  assert.equal(final.reserved, 0, `seed ${seed}: every reservation released`);
  assert.equal(final.spent, charges.reduce((sum, cost) => sum + cost, 0), `seed ${seed}: spent equals the sum of charges`);
}

test('budgets and reservations match a model under random interleavings', { timeout: 60_000 }, async () => {
  for (let seed = 1; seed <= 60; seed++) await run(seed);
});
