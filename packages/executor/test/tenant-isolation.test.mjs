import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';
import { removeAtExit } from './temp-directory.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function setup(t, { policy, maxPolicyAttempts } = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-tenants-')));
  const executor = new DurableExecutor({
    database: join(directory, 'ledger.sqlite'),
    encryptionKey: Buffer.alloc(32, 11),
    clock: () => 1000,
    ...(policy ? { policy } : {}),
    ...(maxPolicyAttempts === undefined ? {} : { maxPolicyAttempts }),
  });
  t.after(() => {
    executor.close();
    rmSync(directory, { recursive: true, force: true });
  });
  let effects = 0;
  const fingerprint = executor.registerTool({
    name: 'write',
    description: 'Write a tenant record',
    maxCost: 1,
    resolve: (_args, task) => ({ resourceId: 'record', tenantId: task.tenantId }),
    execute: async () => {
      effects++;
      await sleep(5);
      return { value: effects };
    },
  });
  executor.approveTool('write', fingerprint);
  for (const tenant of ['alpha', 'beta']) {
    executor.createTask({
      id: tenant,
      principalId: `${tenant}-operator`,
      tenantId: tenant,
      grants: [{ tool: 'write', resources: ['record'] }],
      budget: { maxCalls: 50, maxConcurrent: 10, maxCost: 50, deadline: 100_000 },
    });
  }
  const prepare = taskId => executor.prepare(taskId, { tool: 'write', args: {} });
  return { executor, prepare, effects: () => effects };
}

test("another tenant's writes during an awaited policy do not fail this tenant's calls", async t => {
  const slow = async (_action, snapshot) => {
    if (snapshot.tenantId === 'alpha') await sleep(30);
    return 'allow';
  };
  const f = setup(t, { policy: slow, maxPolicyAttempts: 1 });
  // maxPolicyAttempts 1: any invalidation would fail immediately, so success proves none happened.
  const pendingPrepare = f.prepare('alpha');
  for (let index = 0; index < 5; index++) await f.executor.execute('beta', (await f.prepare('beta')).id);
  const action = await pendingPrepare;
  const pendingExecute = f.executor.execute('alpha', action.id);
  for (let index = 0; index < 5; index++) await f.executor.execute('beta', (await f.prepare('beta')).id);
  assert.equal(typeof (await pendingExecute), 'number');
  assert.equal(f.executor.snapshot('alpha').calls, 1);
  assert.equal(f.executor.snapshot('beta').calls, 10);
});

test('a write to the same task during an awaited policy is re-evaluated on fresh counters', async t => {
  const seen = [];
  const policy = async (_action, snapshot) => {
    seen.push(snapshot.calls);
    await sleep(10);
    return snapshot.calls < 1 ? 'allow' : 'deny';
  };
  const f = setup(t, { policy });
  const [first, second] = await Promise.all([f.prepare('alpha'), f.prepare('alpha')]);
  seen.length = 0;
  const outcomes = await Promise.allSettled([
    f.executor.execute('alpha', first.id),
    f.executor.execute('alpha', second.id),
  ]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  const rejected = outcomes.find(result => result.status === 'rejected');
  assert.equal(rejected.reason.code, 'POLICY_DENIED', 'the stale allow was not reused');
  assert.ok(seen.includes(1), 'the losing call was evaluated again on calls = 1');
  assert.equal(f.effects(), 1);
});

test('parallel executions on one durable task succeed under an async allow-all policy', async t => {
  const f = setup(t, {
    policy: async () => {
      await sleep(10);
      return 'allow';
    },
  });
  const actions = await Promise.all(Array.from({ length: 4 }, () => f.prepare('alpha')));
  const outcomes = await Promise.allSettled(actions.map(action => f.executor.execute('alpha', action.id)));
  assert.deepEqual(
    outcomes.map(result => result.status),
    Array(4).fill('fulfilled'),
  );
  assert.equal(f.executor.snapshot('alpha').calls, 4);
  assert.equal(f.executor.snapshot('alpha').concurrent, 0);
});

test('durable maxPolicyAttempts is validated', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-attempts-')));
  removeAtExit(directory);
  for (const value of [0, 17, 1.5]) {
    assert.throws(
      () =>
        new DurableExecutor({
          database: join(directory, `bad-${value}.sqlite`),
          encryptionKey: Buffer.alloc(32, 1),
          maxPolicyAttempts: value,
        }),
      { code: 'INVALID_INPUT' },
    );
  }
});
