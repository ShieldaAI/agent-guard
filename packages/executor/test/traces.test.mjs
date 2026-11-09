import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { DurableExecutor, ExecutorError } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';

const names = {
  tenant: 'PRIVATE_TENANT_CANARY',
  task: 'PRIVATE_TASK_CANARY',
  tool: 'PRIVATE_TOOL_CANARY',
  resource: 'PRIVATE_RESOURCE_CANARY',
  args: 'PRIVATE_ARGUMENT_CANARY',
  result: 'PRIVATE_RESULT_CANARY',
  reviewer: 'PRIVATE_REVIEWER_CANARY',
  reference: 'PRIVATE_RECEIPT_CANARY',
};
function setup(t, options = {}) {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    decisionTraces: {},
    ...options,
  });
  t.after(() => executor.close());
  let effects = 0;
  const register = (
    execute = () => {
      effects++;
      return { value: names.result };
    },
    requiresApproval = true,
  ) => {
    executor.approveTool(
      names.tool,
      executor.registerTool({
        name: names.tool,
        description: names.tool,
        requiresApproval,
        resolve: (_args, task) => ({ tenantId: task.tenantId, resourceId: names.resource }),
        execute,
      }),
    );
  };
  const task = (id = names.task, tenantId = names.tenant) =>
    executor.createTask({
      id,
      tenantId,
      principalId: names.reviewer,
      grants: [{ tool: names.tool, resources: [names.resource] }],
      budget: { maxCalls: 30, maxCost: 0, maxConcurrent: 4, deadline: Date.now() + 60_000 },
    });
  const prepare = (taskId = names.task) => executor.prepare(taskId, { tool: names.tool, args: { text: names.args } });
  const approve = action => executor.approve(action.id, { approverId: names.reviewer, expiresAt: Date.now() + 20_000 });
  const snapshot = (tenantId = names.tenant) => executor.decisionTraceSnapshot({ tenantId });
  register();
  task();
  return { executor, register, task, prepare, approve, snapshot, effects: () => effects };
}

test('trace lifecycle reconstructs one approved effect and denials without payload or identity leakage', async t => {
  const f = setup(t);
  await assert.rejects(f.executor.prepare(names.task, { tool: 'unknown', args: names.args }));
  const action = await f.prepare();
  await assert.rejects(f.executor.execute(names.task, action.id), { code: 'APPROVAL_REQUIRED' });
  const approvalId = f.approve(action);
  assert.equal(await f.executor.execute(names.task, action.id, { approvalId }), names.result);
  await assert.rejects(f.executor.execute(names.task, action.id, { approvalId }), { code: 'ACTION_USED' });
  const snapshot = f.snapshot();
  assert.equal(f.effects(), 1);
  assert.deepEqual(
    snapshot.events.map(e => e.event),
    ['deny', 'prepare', 'deny', 'review', 'admit', 'settle', 'deny'],
  );
  const linked = snapshot.events.slice(1);
  assert.equal(new Set(linked.map(e => e.actionRef)).size, 1);
  assert.equal(new Set(snapshot.events.map(e => e.taskRef)).size, 1);
  assert.equal(linked.find(e => e.event === 'settle').outcome, 'SUCCEEDED');
  for (const e of snapshot.events) {
    assert(Number.isFinite(e.durationMs) && e.durationMs >= 0);
    assert(Number.isSafeInteger(e.policyRevision));
    assert(Object.isFrozen(e));
  }
  const serialized = JSON.stringify(snapshot);
  for (const value of [...Object.values(names), action.id, action.digest, approvalId])
    assert(!serialized.includes(value), value);
  assert(Object.isFrozen(snapshot.events));
});

test('traced admission reuses the authority snapshot without extra ledger reads or changed effects', async t => {
  const original = LedgerStore.prototype.read;
  let reads = 0;
  LedgerStore.prototype.read = function (...args) {
    reads++;
    return original.apply(this, args);
  };
  t.after(() => {
    LedgerStore.prototype.read = original;
  });
  const observed = [];
  for (const enabled of [false, true]) {
    const f = setup(t, { decisionTraces: enabled ? {} : undefined });
    let effects = 0,
      admissionReads = 0;
    f.register(() => {
      effects++;
      admissionReads = reads;
      return { value: true };
    });
    const action = await f.prepare();
    const approvalId = f.approve(action);
    reads = 0;
    assert.equal(await f.executor.execute(names.task, action.id, { approvalId }), true);
    assert.equal(effects, 1);
    observed.push(admissionReads);
    if (enabled)
      assert.deepEqual(
        f.snapshot().events.map(event => event.event),
        ['prepare', 'review', 'admit', 'settle'],
      );
  }
  assert(observed[0] > 0);
  assert.equal(observed[1], observed[0], 'Observation must reuse the already-read admission state');
});

test('tenant reads, task filters and sequence counters stay scoped, including foreign action attempts', async t => {
  const f = setup(t);
  const a = await f.prepare();
  const before = f.snapshot();
  f.task('foreign-task', 'foreign-tenant');
  const b = await f.prepare('foreign-task');
  assert.deepEqual(f.snapshot(), before);
  await assert.rejects(f.executor.execute(names.task, b.id), { code: 'INVALID_PREPARED' });
  assert.equal(f.snapshot().events.at(-1).toolRevision, 0);
  const foreign = f.snapshot('foreign-tenant');
  assert.equal(foreign.events.length, 1);
  assert.equal(foreign.events[0].sequence, 1);
  assert.notEqual(foreign.events[0].actionRef, f.snapshot().events.at(-1).actionRef);
  assert.throws(() => f.executor.decisionTraceSnapshot({ tenantId: names.tenant, taskId: 'foreign-task' }), {
    code: 'TRACE_SCOPE_DENIED',
  });
  assert.equal(
    f.executor.decisionTraceSnapshot({ tenantId: names.tenant, taskId: names.task, afterSequence: 1, limit: 1 }).events
      .length,
    1,
  );
  assert.equal(f.snapshot('unobserved-tenant').accepting, false);
  assert.equal(f.snapshot('unobserved-tenant').events.length, 0);
  assert.notEqual(a.id, b.id);
});

test('prepared traces retain the admitted registration revision across a post-commit microtask replacement', async t => {
  const f = setup(t);
  const pending = f.prepare();
  let replaced = false;
  const replacement = new Promise((resolve, reject) => {
    let polls = 0;
    const poll = () => {
      if (f.executor.audit().some(entry => entry.event === 'ACTION_PREPARED')) {
        f.register();
        replaced = true;
        resolve();
      } else if (++polls < 100) queueMicrotask(poll);
      else reject(new Error('Preparation did not commit within the fixture microtasks'));
    };
    queueMicrotask(poll);
  });
  const action = await pending;
  assert.equal(replaced, true, 'Replacement must precede the public prepare continuation');
  await replacement;
  assert.equal(f.snapshot().events[0].toolRevision, 1);
  assert.equal(f.snapshot().events[0].policyRevision, action.action.policyVersion);
  await assert.rejects(f.executor.execute(names.task, action.id), { code: 'TOOL_CHANGED' });
  await f.prepare();
  assert.equal(f.snapshot().events.at(-1).toolRevision, 2);
});

test('full buffers and tenant capacity are counted without blocking authority', async t => {
  const f = setup(t, { decisionTraces: { maxEventsPerTenant: 2, maxTenants: 1, retentionMs: 60_000 } });
  const a = await f.prepare();
  await f.executor.execute(names.task, a.id, { approvalId: f.approve(a) });
  assert.equal(f.snapshot().events.length, 2);
  assert.equal(f.snapshot().dropped, 2);
  const before = f.snapshot();
  f.task('foreign', 'foreign');
  const b = await f.prepare('foreign');
  await f.executor.execute('foreign', b.id, { approvalId: f.approve(b) });
  assert.deepEqual(f.executor.decisionTraceStatistics(), { tenants: 1, tenantCapacityDrops: 4 });
  assert.equal(f.snapshot('foreign').events.length, 0);
  assert.equal(f.snapshot('foreign').dropped, 0);
  assert.equal(f.snapshot().dropped, before.dropped);
  assert.equal(f.effects(), 2);
});

test('volatile retention expiry is counted independently of buffer overflow', async t => {
  const f = setup(t, { decisionTraces: { retentionMs: 1 } });
  await f.prepare();
  await sleep(10);
  assert.equal(f.snapshot().events.length, 0);
  assert.equal(f.snapshot().expired, 1);
  assert.equal(f.snapshot().dropped, 0);
});

test('failed export retries only immutable trace events and successful export acknowledges only its snapshot', async t => {
  const f = setup(t);
  const a = await f.prepare();
  await f.executor.execute(names.task, a.id, { approvalId: f.approve(a) });
  const original = f.snapshot();
  let calls = 0;
  const failed = await f.executor.exportDecisionTraces({ tenantId: names.tenant }, batch => {
    calls++;
    assert(Object.isFrozen(batch.events));
    assert.deepEqual(batch.events, original.events);
    throw new Error(names.args);
  });
  assert.deepEqual(failed, { status: 'failed', count: 0 });
  assert.equal(f.snapshot().exportFailures, 1);
  assert.deepEqual(f.snapshot().events, original.events);
  let finish;
  const pending = f.executor.exportDecisionTraces({ tenantId: names.tenant }, async batch => {
    calls++;
    assert.deepEqual(batch.events, original.events);
    await new Promise(resolve => {
      finish = resolve;
    });
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(
    await f.executor.exportDecisionTraces({ tenantId: names.tenant }, () => {
      calls++;
    }),
    { status: 'busy', count: 0 },
  );
  await f.prepare(); // Recording remains available while the exporter waits.
  finish();
  assert.deepEqual(await pending, { status: 'exported', count: 4 });
  assert.equal(f.snapshot().events.length, 1);
  assert.equal(f.snapshot().exported, 4);
  assert.equal(f.effects(), 1);
  assert.equal(calls, 2);
});

test('hung exporter is bounded, signalled and cannot accumulate retries or acknowledge a late success', async t => {
  const f = setup(t);
  await f.prepare();
  let finish, signal;
  const result = await f.executor.exportDecisionTraces(
    { tenantId: names.tenant },
    (_batch, options) => {
      signal = options.signal;
      return new Promise(resolve => {
        finish = resolve;
      });
    },
    { timeoutMs: 10 },
  );
  assert.deepEqual(result, { status: 'timeout', count: 0 });
  assert.equal(signal.aborted, true);
  assert.equal((await f.executor.exportDecisionTraces({ tenantId: names.tenant }, () => assert.fail())).status, 'busy');
  finish();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.snapshot().events.length, 1);
  assert.equal((await f.executor.exportDecisionTraces({ tenantId: names.tenant }, () => {})).count, 1);
  assert.equal(f.effects(), 0);
});

test('parallel approvals, refusal and cancellation do not manufacture authority', async t => {
  const f = setup(t);
  const a = await f.prepare();
  f.executor.recordReviewDecision(a.id, 'denied');
  assert.equal(f.snapshot().events.at(-1).code, 'REVIEW_DENIED');
  await assert.rejects(f.executor.execute(names.task, a.id), { code: 'APPROVAL_REQUIRED' });
  const approvals = await Promise.all([
    Promise.resolve().then(() => f.approve(a)),
    Promise.resolve().then(() => f.approve(a)),
  ]);
  const results = await Promise.allSettled(
    approvals.map(approvalId => f.executor.execute(names.task, a.id, { approvalId })),
  );
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(f.effects(), 1);
  assert.equal(f.snapshot().events.filter(e => e.event === 'admit').length, 1);
  const pending = await f.prepare();
  f.executor.cancel(names.task, pending.id);
  assert.equal(f.snapshot().events.at(-1).outcome, 'CANCELLED');
  await assert.rejects(f.executor.execute(names.task, pending.id), { code: 'ACTION_USED' });
});

test('unknown effects and success followed by abort remain distinct from a prevented action', async t => {
  const f = setup(t);
  const forged = new ExecutorError('PRIVATE_FORGED_ERROR_CANARY');
  f.register(() => {
    throw forged;
  });
  const a = await f.prepare();
  await assert.rejects(f.executor.execute(names.task, a.id, { approvalId: f.approve(a) }), error => error === forged);
  let events = f.snapshot().events;
  assert.deepEqual(
    events.slice(-2).map(e => [e.event, e.outcome, e.code]),
    [
      ['unknown', 'UNKNOWN', 'OUTCOME_UNKNOWN'],
      ['error', 'ERROR', 'OPERATION_FAILED'],
    ],
  );
  assert(!JSON.stringify(events).includes(forged.code));
  f.executor.reconcile(a.id, { outcome: 'FAILED', actualCost: 0, reference: names.reference });
  assert.equal(f.snapshot().events.at(-1).event, 'reconcile');
  // A tool can observe cancellation after its actual result exists.
  let actionId;
  f.register(() => {
    f.executor.cancel(names.task, actionId);
    return { value: true };
  });
  const b = await f.prepare();
  actionId = b.id;
  await assert.rejects(f.executor.execute(names.task, b.id, { approvalId: f.approve(b) }), {
    code: 'EXECUTION_ABORTED',
  });
  events = f.snapshot().events.filter(e => e.actionRef === f.snapshot().events.at(-1).actionRef);
  assert.equal(f.executor.execution(names.task, b.id).status, 'SUCCEEDED');
  assert.deepEqual(
    events.slice(-2).map(e => [e.event, e.outcome]),
    [
      ['settle', 'SUCCEEDED'],
      ['error', 'ERROR'],
    ],
  );
  assert.equal(events.filter(e => e.outcome === 'DENIED').length, 0);
});

test('error-code accessors and reconciliation accessors never execute in trace observation', async t => {
  const f = setup(t);
  let getters = 0;
  const error = new ExecutorError('ignored');
  Object.defineProperty(error, 'code', {
    get() {
      getters++;
      throw new Error(names.args);
    },
  });
  f.register(() => {
    throw error;
  });
  const a = await f.prepare();
  await assert.rejects(f.executor.execute(names.task, a.id, { approvalId: f.approve(a) }), caught => caught === error);
  assert.equal(getters, 0);
  assert.equal(f.snapshot().events.at(-1).code, 'OPERATION_FAILED');
  const evidence = { actualCost: 0, reference: names.reference };
  Object.defineProperty(evidence, 'outcome', {
    enumerable: true,
    get() {
      getters++;
      return 'FAILED';
    },
  });
  assert.throws(() => f.executor.reconcile(a.id, evidence));
  assert.equal(getters, 0);
  assert.equal(f.executor.execution(names.task, a.id).status, 'UNKNOWN');
  f.executor.reconcile(a.id, { outcome: 'FAILED', actualCost: 0, reference: names.reference });
});

test('disabled trace and invalid options leave the existing executor contract explicit', t => {
  const f = setup(t, { decisionTraces: undefined });
  assert.throws(() => f.snapshot(), { code: 'TRACE_DISABLED' });
  for (const decisionTraces of [
    null,
    { maxTenants: 0 },
    { maxEventsPerTenant: 5000 },
    { retentionMs: -1 },
    { sink: () => {} },
  ]) {
    assert.throws(() => new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), decisionTraces }), {
      code: 'TRACE_CONFIG_INVALID',
    });
  }
});

test('restart reports unknown durable work with stable opaque correlation and a fresh session', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'trace-recovery-')));
  let e;
  t.after(() => {
    try {
      e?.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  const database = join(directory, 'state.sqlite');
  const module = new URL('../dist/index.js', import.meta.url).href;
  const script = `import {DurableExecutor} from ${JSON.stringify(module)};
    const e=new DurableExecutor({database:process.argv[1],encryptionKey:Buffer.alloc(32,7),clock:()=>1000,decisionTraces:{}});
    e.approveTool('run',e.registerTool({name:'run',description:'run',resolve:()=>({tenantId:'tenant',resourceId:'item'}),execute:()=>process.exit(17)}));
    e.createTask({id:'task',tenantId:'tenant',principalId:'host',grants:[{tool:'run',resources:['item']}],budget:{maxCalls:2,maxConcurrent:1,maxCost:0,deadline:10000}});
    const a=await e.prepare('task',{tool:'run',args:null});
    console.log(JSON.stringify({id:a.id,event:e.decisionTraceSnapshot({tenantId:'tenant'}).events[0]}));
    await e.execute('task',a.id);`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script, database], {
    encoding: 'utf8',
    timeout: 10_000,
  });
  assert.equal(child.status, 17, child.stderr);
  const before = JSON.parse(child.stdout);
  e = new DurableExecutor({ database, encryptionKey: Buffer.alloc(32, 7), clock: () => 1000, decisionTraces: {} });
  const event = e.decisionTraceSnapshot({ tenantId: 'tenant' }).events[0];
  assert.equal(event.event, 'unknown');
  assert.equal(event.code, 'RECOVERY_UNKNOWN');
  assert.equal(event.actionRef, before.event.actionRef);
  assert.equal(event.taskRef, before.event.taskRef);
  assert.notEqual(event.sessionRef, before.event.sessionRef);
  e.reconcile(before.id, { outcome: 'FAILED', actualCost: 0, reference: names.reference });
  assert.equal(e.decisionTraceSnapshot({ tenantId: 'tenant' }).events.at(-1).outcome, 'FAILED');
});
