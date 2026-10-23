import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, GuardError } from '../dist/index.js';

function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
function setup({ execute, budget = {}, maxCost = 2, policy } = {}) {
  const guard = new AgentGuard(policy ? { policy } : {});
  const fp = guard.registerTool({ name: 'run', description: 'A bounded operation', maxCost,
    resolve: (_args, task) => ({ resourceId: 'resource:1', tenantId: task.tenantId }),
    execute: execute ?? (() => ({ value: 'ok', actualCost: 1 })),
  });
  guard.approveTool('run', fp);
  const limits = { maxCalls: 10, maxConcurrent: 2, maxCost: 10, deadline: Date.now() + 60_000, ...budget };
  const grants = [{ tool: 'run', resources: ['resource:1'] }];
  const parent = guard.createTask({ id: 'parent', principalId: 'principal', tenantId: 'tenant', grants, budget: limits });
  const child = guard.delegateTask(parent, { id: 'child', grants, budget: limits });
  const sibling = guard.delegateTask(parent, { id: 'sibling', grants, budget: limits });
  const prepare = (task = child) => guard.prepare(task, { tool: 'run', args: {} });
  return { guard, parent, child, sibling, prepare };
}
const isCode = expected => error => { assert.ok(error instanceof GuardError); assert.equal(error.code, expected); return true; };

test('simultaneous sibling execution reserves aggregate costs before either handler settles', async () => {
  let effects = 0; const entered = deferred(); const release = deferred();
  const f = setup({ budget: { maxCost: 3 }, execute: async () => { effects++; entered.resolve(); await release.promise; return { value: 'ok', actualCost: 1 }; } });
  const [a, b] = await Promise.all([f.prepare(f.child), f.prepare(f.sibling)]);
  const first = f.guard.execute(a);
  const second = f.guard.execute(b);
  await entered.promise;
  await assert.rejects(second, isCode('COST_BUDGET_EXCEEDED'));
  assert.equal(effects, 1);
  assert.equal(f.guard.snapshot(f.parent).reserved, 2);
  assert.equal(f.guard.snapshot(f.parent).concurrent, 1);
  release.resolve();
  assert.equal(await first, 'ok');
  const snapshot = f.guard.snapshot(f.parent);
  assert.equal(snapshot.spent, 1); assert.equal(snapshot.reserved, 0); assert.equal(snapshot.concurrent, 0);
  assert.equal(await f.guard.execute(b), 'ok');
  assert.equal(f.guard.snapshot(f.parent).spent, 2);
});

test('call and concurrency admission are atomic across sibling tasks', async t => {
  for (const [field, expected] of [['maxCalls', 'CALL_BUDGET_EXCEEDED'], ['maxConcurrent', 'CONCURRENCY_EXCEEDED']]) {
    await t.test(field, async () => {
      const release = deferred(); let effects = 0;
      const f = setup({ budget: { [field]: 1 }, execute: async () => { effects++; await release.promise; return { value: 'ok' }; } });
      const [a, b] = await Promise.all([f.prepare(f.child), f.prepare(f.sibling)]);
      const first = f.guard.execute(a); const second = f.guard.execute(b);
      await assert.rejects(second, isCode(expected));
      assert.equal(effects, 1);
      release.resolve(); await first;
      assert.equal(f.guard.snapshot(f.parent).calls, 1);
      assert.equal(f.guard.snapshot(f.sibling).calls, 0);
    });
  }
});

test('revocation aborts descendant signal and holds concurrency until ignored cancellation settles', async () => {
  const entered = deferred(); const release = deferred(); let signal;
  const f = setup({ execute: async (_args, context) => { signal = context.signal; entered.resolve(); await release.promise; return { value: 'effect may have happened', actualCost: 1 }; } });
  const pending = f.guard.execute(await f.prepare());
  await entered.promise;
  f.guard.revokeTask(f.parent);
  assert.equal(signal.aborted, true);
  assert.equal(signal.reason.code, 'TASK_REVOKED');
  assert.equal(f.guard.snapshot(f.parent).concurrent, 1);
  assert.equal(f.guard.snapshot(f.parent).reserved, 2);
  release.resolve();
  await assert.rejects(pending, isCode('EXECUTION_ABORTED'));
  assert.equal(f.guard.snapshot(f.parent).concurrent, 0);
  assert.equal(f.guard.snapshot(f.child).spent, 1);
  assert.equal(f.guard.snapshot(f.parent).calls, 1);
});

test('deadline requests cooperative cancellation and releases only after the handler settles', async () => {
  let started = false;
  const f = setup({ budget: { deadline: Date.now() + 40 }, execute: (_args, { signal }) => new Promise(resolve => {
    started = true;
    signal.addEventListener('abort', () => resolve({ value: signal.reason.code, actualCost: 0 }), { once: true });
  }) });
  await assert.rejects(f.guard.execute(await f.prepare()), isCode('EXECUTION_ABORTED'));
  assert.equal(started, true);
  assert.equal(f.guard.snapshot(f.parent).concurrent, 0);
  assert.equal(f.guard.snapshot(f.parent).spent, 0);
});

test('failed handlers remain charged, consumed and never retried automatically', async () => {
  let effects = 0;
  const f = setup({ execute: () => { effects++; throw new Error('private provider response'); } });
  const prepared = await f.prepare();
  await assert.rejects(f.guard.execute(prepared), error => { isCode('TOOL_FAILED')(error); assert.equal(error.message, 'TOOL_FAILED'); return true; });
  await assert.rejects(f.guard.execute(prepared), isCode('ACTION_USED'));
  assert.equal(effects, 1);
  assert.equal(f.guard.snapshot(f.parent).spent, 2);
  assert.equal(f.guard.snapshot(f.child).calls, 1);
  assert.equal(f.guard.snapshot(f.child).reserved, 0);
});

test('absent actual cost charges full reservation; valid cost releases unused reservation', async () => {
  for (const [result, expected] of [[{ value: 'ok' }, 2], [{ value: 'ok', actualCost: 0 }, 0], [{ value: 'ok', actualCost: 1 }, 1]]) {
    const f = setup({ execute: () => result });
    await f.guard.execute(await f.prepare());
    for (const task of [f.parent, f.child]) {
      assert.equal(f.guard.snapshot(task).spent, expected);
      assert.equal(f.guard.snapshot(task).reserved, 0);
    }
  }
});

test('invalid and overrun cost reports revoke the task and retain full charge', async t => {
  for (const [name, result] of [
    ['overrun', { value: 'ok', actualCost: 3 }], ['negative', { value: 'ok', actualCost: -1 }],
    ['string', { value: 'ok', actualCost: '0' }], ['nonfinite', { value: 'ok', actualCost: NaN }],
    ['fractional', { value: 'ok', actualCost: 0.5 }], ['unsafe integer', { value: 'ok', actualCost: Number.MAX_SAFE_INTEGER + 1 }],
    ['missing value', { actualCost: 0 }], ['invalid value', { value: undefined, actualCost: 0 }],
  ]) await t.test(name, async () => {
    const f = setup({ execute: () => result });
    await assert.rejects(f.guard.execute(await f.prepare()), error => { assert.ok(error instanceof GuardError); assert.ok(['COST_REPORT_INVALID', 'RESULT_INVALID'].includes(error.code)); return true; });
    await assert.rejects(f.prepare(), isCode('TASK_REVOKED'));
    for (const task of [f.parent, f.child]) {
      assert.equal(f.guard.snapshot(task).spent, 2);
      assert.equal(f.guard.snapshot(task).reserved, 0);
      assert.equal(f.guard.snapshot(task).concurrent, 0);
    }
  });
});

test('cost configuration rejects fractional and unsafe integer units', () => {
  for (const cost of [0.1, 1.5, Number.MAX_SAFE_INTEGER + 1, 1e16]) {
    assert.throws(() => setup({ maxCost: cost }), isCode('INVALID_INPUT'));
    assert.throws(() => setup({ budget: { maxCost: cost } }), isCode('INVALID_INPUT'));
  }
});

test('safe-integer boundary denies the next unit after an exact full charge', async () => {
  const f = setup({ maxCost: Number.MAX_SAFE_INTEGER, budget: { maxCost: Number.MAX_SAFE_INTEGER }, execute: () => ({ value: 'charged' }) });
  await f.guard.execute(await f.prepare());
  assert.equal(f.guard.snapshot(f.parent).spent, Number.MAX_SAFE_INTEGER);
  const fp = f.guard.registerTool({ name: 'run', description: 'one unit', maxCost: 1,
    resolve: (_args, task) => ({ resourceId: 'resource:1', tenantId: task.tenantId }),
    execute: () => { assert.fail('one-unit overflow must not dispatch'); },
  });
  f.guard.approveTool('run', fp);
  await assert.rejects(f.prepare(), isCode('COST_BUDGET_EXCEEDED'));
  assert.equal(f.guard.snapshot(f.parent).calls, 1);
});

test('safe-integer boundary respects outstanding reservations from sibling tasks', async () => {
  const release = deferred();
  const f = setup({ maxCost: Number.MAX_SAFE_INTEGER - 1, budget: { maxCost: Number.MAX_SAFE_INTEGER }, execute: async () => { await release.promise; return { value: 'charged' }; } });
  const first = f.guard.execute(await f.prepare());
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.guard.snapshot(f.parent).reserved, Number.MAX_SAFE_INTEGER - 1);
  const fp = f.guard.registerTool({ name: 'run', description: 'two units', maxCost: 2,
    resolve: (_args, task) => ({ resourceId: 'resource:1', tenantId: task.tenantId }),
    execute: () => { assert.fail('two units exceed remaining reservation headroom'); },
  });
  f.guard.approveTool('run', fp);
  await assert.rejects(f.prepare(f.sibling), isCode('COST_BUDGET_EXCEEDED'));
  release.resolve(); await first;
  assert.equal(f.guard.snapshot(f.parent).spent, Number.MAX_SAFE_INTEGER - 1);
});

test('zero budgets are valid and deny dispatch without reservation', async () => {
  for (const [budget, expected] of [
    [{ maxCalls: 0 }, 'CALL_BUDGET_EXCEEDED'], [{ maxConcurrent: 0 }, 'CONCURRENCY_EXCEEDED'], [{ maxCost: 0 }, 'COST_BUDGET_EXCEEDED'],
  ]) {
    const f = setup({ budget });
    await assert.rejects(f.prepare(), isCode(expected));
    assert.equal(f.guard.snapshot(f.parent).calls, 0);
  }
});
