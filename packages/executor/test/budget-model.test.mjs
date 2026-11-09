import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';
import { random } from '../../core/test/helpers/random.mjs';

const MAX_COST = 4;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Random interleavings on a durable task tree. Thrown handlers leave the effect UNKNOWN
 * with its reservation held until reconciled. Counters must stay within every ancestor's
 * budget at each step, and match the model after reconciliation and a restart.
 */
async function run(t, seed) {
  const rng = random(seed);
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-model-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'ledger.sqlite'), key = Buffer.alloc(32, 31);
  const charges = new Map(); let invocations = 0;
  const register = executor => executor.approveTool('work', executor.registerTool({ name: 'work', description: 'model fixture', maxCost: MAX_COST,
    resolve: () => ({ resourceId: 'r', tenantId: 't' }),
    execute: async args => {
      const call = ++invocations;
      await sleep(args.delay);
      if (args.mode === 'throw') throw new Error('backend lost');
      charges.set(call, args.cost);
      return { value: 1, actualCost: args.cost };
    } }));
  let executor = new DurableExecutor({ database, encryptionKey: key });
  register(executor);
  const budget = { maxCalls: rng.int(3, 10), maxConcurrent: rng.int(1, 3), maxCost: rng.int(4, 24), deadline: Date.now() + 120_000 };
  executor.createTask({ id: 'root', principalId: 'p', tenantId: 't', grants: [{ tool: 'work', resources: ['r'] }], budget });
  executor.delegateTask('root', { id: 'child', grants: [{ tool: 'work', resources: ['r'] }],
    budget: { maxCalls: rng.int(1, budget.maxCalls), maxConcurrent: rng.int(1, budget.maxConcurrent), maxCost: rng.int(1, budget.maxCost), deadline: budget.deadline } });
  const ids = ['root', 'child'];
  const unknown = [];
  const check = label => {
    const budgets = { root: budget, child: null };
    const [root, child] = ids.map(id => executor.snapshot(id));
    for (const snapshot of [root, child]) {
      assert.ok(snapshot.concurrent >= 0 && snapshot.reserved >= 0, `${label}: non-negative counters`);
      assert.ok(snapshot.calls <= root.calls && snapshot.spent <= root.spent, `${label}: root counts every descendant`);
    }
    assert.ok(root.calls <= budgets.root.maxCalls && root.spent + root.reserved <= budgets.root.maxCost, `${label}: root budget holds`);
    assert.equal(root.calls, invocations, `${label}: one call per handler invocation`);
  };
  const running = [];
  for (let step = 0; step < 16; step++) {
    const taskId = rng.pick(ids);
    const args = { delay: rng.int(0, 3), mode: rng.pick(['ok', 'ok', 'ok', 'throw']), cost: rng.int(0, MAX_COST) };
    running.push(executor.prepare(taskId, { tool: 'work', args }).then(prepared =>
      executor.execute(taskId, prepared.id).catch(error => {
        // Only a dispatched call has an uncertain effect; a refusal before dispatch has none.
        if (executor.execution(taskId, prepared.id).status === 'UNKNOWN') unknown.push(prepared.id); else throw error;
      }))
      .catch(error => assert.match(String(error.code), /^[A-Z_]+$/, `seed ${seed}: coded refusal (${error})`)));
    check(`seed ${seed} step ${step}`);
    if (rng.next() < 0.5) await sleep(rng.int(0, 3));
  }
  await Promise.all(running);
  check(`seed ${seed} settled`);
  assert.equal(executor.snapshot('root').reserved, unknown.length * MAX_COST, `seed ${seed}: only uncertain effects keep a reservation`);
  for (const actionId of unknown) executor.reconcile(actionId, { outcome: 'FAILED', actualCost: MAX_COST, reference: `receipt-${actionId}` });
  executor.close();
  executor = new DurableExecutor({ database, encryptionKey: key });
  const root = executor.snapshot('root');
  executor.close();
  assert.equal(root.concurrent, 0, `seed ${seed}: nothing running after restart`);
  assert.equal(root.reserved, 0, `seed ${seed}: every reservation released`);
  assert.equal(root.calls, invocations, `seed ${seed}: calls survive restart`);
  assert.equal(root.spent, [...charges.values()].reduce((sum, cost) => sum + cost, 0) + unknown.length * MAX_COST, `seed ${seed}: spent matches the model`);
}

test('durable budgets and reservations match a model under random interleavings and restart', { timeout: 120_000 }, async t => {
  for (let seed = 1; seed <= 25; seed++) await run(t, seed);
});
