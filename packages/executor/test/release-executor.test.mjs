import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GuardError } from '@shieldaai/agent-guard';
import { DurableExecutor, ExecutorError, createModelTool } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';
import { recordPruned, prunedReceipt, stubLimits } from '../dist/retention.js';
import { removeAtExit } from './temp-directory.mjs';

const KEY = Buffer.alloc(32, 77);
const posix = process.platform !== 'win32';

function directory() {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'release-executor-')));
  removeAtExit(path);
  return path;
}
function open(t, options = {}) {
  const executor = new DurableExecutor({
    database: join(directory(), 'ledger.sqlite'),
    encryptionKey: KEY,
    clock: () => 1_000,
    ...options,
  });
  t.after(() => {
    try {
      executor.close();
    } catch {
      /* Already closed by the test. */
    }
  });
  return executor;
}
function tool(executor, name, execute, extra = {}) {
  executor.approveTool(
    name,
    executor.registerTool({
      name,
      description: name,
      maxCost: 1,
      resolve: (_args, owner) => ({ resourceId: 'record', tenantId: owner.tenantId }),
      execute,
      ...extra,
    }),
  );
}
function task(executor, id, tenantId = 'alpha', tools = ['work'], extra = {}) {
  return executor.createTask({
    id,
    principalId: `${tenantId}-operator`,
    tenantId,
    grants: tools.map(name => ({ tool: name, resources: ['record'] })),
    budget: { maxCalls: 10_000, maxConcurrent: 8, maxCost: 10_000, deadline: 1_000_000 },
    ...extra,
  });
}
async function run(executor, taskId, toolName = 'work') {
  const action = await executor.prepare(taskId, { tool: toolName, args: {} });
  return { action, result: await executor.execute(taskId, action.id).catch(error => error) };
}
/** Replace LedgerStore.transaction for the duration of `during`. */
async function withStorePatch(patch, during) {
  const original = LedgerStore.prototype.transaction;
  LedgerStore.prototype.transaction = function (operation, options) {
    return patch.call(this, original, operation, options);
  };
  try {
    return await during();
  } finally {
    LedgerStore.prototype.transaction = original;
  }
}

// ---------------------------------------------------------------- 1. handler errors

test('a host handler error is TOOL_FAILED with a safe detail, never an executor decision', async t => {
  const executor = open(t);
  let thrown;
  tool(executor, 'work', () => {
    throw thrown;
  });
  task(executor, 'a');
  for (const [error, detail] of [
    [new GuardError('APPROVAL_REQUIRED'), 'APPROVAL_REQUIRED'],
    [new GuardError('CONCURRENCY_EXCEEDED'), 'CONCURRENCY_EXCEEDED'],
    [new ExecutorError('CAPACITY_EXCEEDED'), 'CAPACITY_EXCEEDED'],
    [new ExecutorError('MEMORY_VERSION_CHANGED'), 'MEMORY_VERSION_CHANGED'],
    [Object.assign(new Error('upstream said no'), { code: 'IDENTITY_DENIED' }), 'IDENTITY_DENIED'],
    [Object.assign(new Error('x'), { code: 'not safe: /etc/passwd' }), undefined],
    [new Error('plain'), undefined],
    ['a string', undefined],
  ]) {
    thrown = error;
    const { action, result } = await run(executor, 'a');
    assert.equal(result.name, 'GuardError');
    assert.equal(result.code, 'TOOL_FAILED', `handler threw ${String(error)}`);
    assert.equal(result.detail, detail);
    assert.notEqual(result, error);
    assert.equal(executor.execution('a', action.id).status, 'UNKNOWN', 'the caller and the ledger agree');
  }
});

test('a host handler that fails after an abort is EXECUTION_ABORTED without a detail', async t => {
  const executor = open(t);
  let actionId;
  tool(executor, 'work', () => {
    executor.cancel('a', actionId);
    throw new GuardError('APPROVAL_REQUIRED');
  });
  task(executor, 'a');
  const action = await executor.prepare('a', { tool: 'work', args: {} });
  actionId = action.id;
  const error = await executor.execute('a', action.id).catch(caught => caught);
  assert.equal(error.code, 'EXECUTION_ABORTED');
  assert.equal(error.detail, undefined);
  assert.equal(executor.execution('a', action.id).status, 'UNKNOWN');
});

test('a memory version race keeps its code and settles FAILED at zero cost', async t => {
  const executor = open(t);
  const memory = executor.registerMemoryTools();
  executor.approveTool('memory.read', memory.read);
  executor.approveTool('memory.write', memory.write);
  executor.createTask({
    id: 'a',
    principalId: 'p',
    tenantId: 'alpha',
    grants: [{ tool: 'memory.write', resources: ['note'] }],
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 10, deadline: 1_000_000 },
  });
  const first = await executor.prepare('a', { tool: 'memory.write', args: { id: 'note', value: 1, ifVersion: 0 } });
  const second = await executor.prepare('a', { tool: 'memory.write', args: { id: 'note', value: 2, ifVersion: 0 } });
  assert.deepEqual(
    { ...(await executor.execute('a', first.id)) },
    { id: 'note', version: 1, sensitive: false, trusted: false },
  );
  await assert.rejects(executor.execute('a', second.id), { name: 'ExecutorError', code: 'MEMORY_VERSION_CHANGED' });
  assert.deepEqual({ ...executor.execution('a', second.id) }, { id: second.id, status: 'FAILED', charged: 0 });
  const counters = executor.snapshot('a');
  assert.equal(counters.concurrent, 0, 'the refused write holds no concurrency slot');
  assert.equal(counters.reserved, 0);
  // With maxConcurrent 1 an UNKNOWN outcome would block this third call.
  const third = await executor.prepare('a', { tool: 'memory.write', args: { id: 'note', value: 3, ifVersion: 1 } });
  assert.equal((await executor.execute('a', third.id)).version, 2);
});

test('the model tool keeps RESULT_INVALID; a provider error is a tool failure', async t => {
  const executor = open(t);
  let respond;
  const model = createModelTool({
    name: 'model',
    model: 'm',
    tenantId: 'alpha',
    recipient: 'provider',
    maxCost: 1,
    maxOutputTokens: 10,
    complete: async () => respond(),
  });
  executor.approveTool('model', executor.registerTool(model));
  executor.approveTool(
    'wrapped',
    executor.registerTool({ ...model, name: 'wrapped', execute: (args, context) => model.execute(args, context) }),
  );
  executor.createTask({
    id: 'a',
    principalId: 'p',
    tenantId: 'alpha',
    grants: [
      { tool: 'model', resources: ['m'] },
      { tool: 'wrapped', resources: ['m'] },
    ],
    allowedRecipients: ['provider'],
    budget: { maxCalls: 10, maxConcurrent: 4, maxCost: 10, deadline: 1_000_000 },
  });
  const call = async name => {
    const action = await executor.prepare('a', { tool: name, args: { prompt: 'hi', maxOutputTokens: 5 } });
    return executor.execute('a', action.id).catch(error => error);
  };
  respond = () => ({ response: { text: 42 } });
  const builtIn = await call('model');
  assert.equal(builtIn.code, 'RESULT_INVALID');
  respond = () => {
    throw new GuardError('APPROVAL_REQUIRED');
  };
  const provider = await call('model');
  assert.deepEqual([provider.code, provider.detail], ['TOOL_FAILED', 'APPROVAL_REQUIRED']);
  // Even the tool's own documented code is a tool failure when the provider throws it.
  respond = () => {
    throw new GuardError('RESULT_INVALID');
  };
  const forgedByProvider = await call('model');
  assert.deepEqual([forgedByProvider.code, forgedByProvider.detail], ['TOOL_FAILED', 'RESULT_INVALID']);
  respond = () => ({ response: { text: 42 } });
  // A host tool that lets the built-in tool's own refusal through keeps that refusal's code.
  assert.equal((await call('wrapped')).code, 'RESULT_INVALID');
  // The class alone earns nothing: the same code thrown by host code is a tool failure.
  executor.approveTool(
    'forged',
    executor.registerTool({
      ...model,
      name: 'forged',
      execute: () => {
        throw new GuardError('RESULT_INVALID');
      },
    }),
  );
  executor.createTask({
    id: 'b',
    principalId: 'p',
    tenantId: 'alpha',
    grants: [{ tool: 'forged', resources: ['m'] }],
    allowedRecipients: ['provider'],
    budget: { maxCalls: 10, maxConcurrent: 4, maxCost: 10, deadline: 1_000_000 },
  });
  const forged = await executor.prepare('b', { tool: 'forged', args: { prompt: 'hi', maxOutputTokens: 5 } });
  const error = await executor.execute('b', forged.id).catch(caught => caught);
  assert.deepEqual([error.code, error.detail], ['TOOL_FAILED', 'RESULT_INVALID']);
});

// ---------------------------------------------------------------- 2. headroom at the byte cap

/** Import memory in ever smaller pieces until less than about 1 KiB is left below the soft limit. */
function fillToSoftLimit(executor) {
  let refusals = 0;
  let index = 0;
  for (const size of [60_000, 8_000, 800]) {
    const chunk = 'x'.repeat(size);
    for (;;) {
      try {
        executor.importMemory({ id: `fill-${index++}`, tenantId: 'filler', origin: 'operator', value: chunk });
      } catch (error) {
        assert.equal(error.code, 'STORE_CAPACITY_EXCEEDED');
        assert.equal(error.detail, 'SOFT_LIMIT');
        refusals++;
        break;
      }
      assert.ok(index < 400, 'the ledger never reached its soft limit');
    }
  }
  assert.equal(refusals, 3);
}
/** Resolves once `count` handlers have started. */
function starts(count) {
  let seen = 0;
  let done;
  const all = new Promise(resolve => {
    done = resolve;
  });
  return { started: () => ++seen >= count && done(), all };
}

test('at the soft limit growth is refused, and revoke, cancel, settle, UNKNOWN and reconcile still commit', async t => {
  const executor = open(t, { maxLedgerBytes: 1024 * 1024 });
  // Long identifiers make every record and event of these tasks larger than what the fill leaves free.
  const a = 'a'.repeat(2_000);
  const b = 'b'.repeat(2_000);
  let release;
  const gate = new Promise(resolve => {
    release = resolve;
  });
  const begun = starts(2);
  tool(executor, 'work', async args => {
    begun.started();
    await gate;
    if (args.fail) throw new Error('boom');
    return { value: 'done' };
  });
  task(executor, a);
  task(executor, b);
  const succeed = await executor.prepare(a, { tool: 'work', args: {} });
  const fail = await executor.prepare(a, { tool: 'work', args: { fail: true } });
  const waiting = await executor.prepare(a, { tool: 'work', args: { later: true } });
  const running = [executor.execute(a, succeed.id), executor.execute(a, fail.id).catch(error => error)];
  try {
    await begun.all;
    fillToSoftLimit(executor);

    // Growth-only operations are refused before the hard bound.
    const refused = { name: 'ExecutorError', code: 'STORE_CAPACITY_EXCEEDED', detail: 'SOFT_LIMIT' };
    assert.throws(() => task(executor, 'c'.repeat(2_000)), refused);
    await assert.rejects(executor.prepare(a, { tool: 'work', args: {} }), refused);
    assert.throws(() => executor.approve(waiting.id, { approverId: 'r'.repeat(2_000), expiresAt: 2_000 }), refused);
    await assert.rejects(executor.execute(a, waiting.id), refused);
    assert.equal(executor.execution(a, waiting.id).status, 'PREPARED', 'a refused admission changes nothing');

    // The reserve carries every write that must not fail.
    executor.cancel(a, waiting.id);
    assert.equal(executor.execution(a, waiting.id).status, 'FAILED');
  } finally {
    release();
  }
  assert.equal(await running[0], 'done');
  assert.equal(executor.execution(a, succeed.id).status, 'SUCCEEDED');
  assert.equal((await running[1]).code, 'TOOL_FAILED');
  assert.equal(executor.execution(a, fail.id).status, 'UNKNOWN', 'not orphaned in RUNNING');
  executor.reconcile(fail.id, { outcome: 'FAILED', actualCost: 0, reference: 'ticket-1' });
  assert.equal(executor.execution(a, fail.id).status, 'FAILED');
  executor.revokeTask(b);
  assert.throws(() => executor.assertProvenance(b), { code: 'TASK_REVOKED' });
  assert.equal(executor.snapshot(a).concurrent, 0);
});

test('a ledger at its hard bound still opens, recovers and revokes by dropping recent events', async t => {
  const database = join(directory(), 'ledger.sqlite');
  const maxLedgerBytes = 1024 * 1024;
  const first = new DurableExecutor({ database, encryptionKey: KEY, clock: () => 1_000, maxLedgerBytes });
  tool(first, 'work', () => ({ value: 1 }));
  task(first, 'a');
  for (let index = 0; index < 40; index++) await run(first, 'a');
  const events = first.audit().length;
  first.close();
  // Pad the ledger so that not one more byte fits: every later commit is over the bound.
  const store = new LedgerStore(database, KEY, maxLedgerBytes);
  const bytes = Buffer.byteLength(JSON.stringify(store.read()));
  store.transaction(state => {
    // The commit itself adds one to the revision; leave no room beyond that.
    state.retainedHostEvidence = 'x'.repeat(maxLedgerBytes - bytes - ',"retainedHostEvidence":""'.length - 1);
  });
  assert.ok(Buffer.byteLength(JSON.stringify(store.read())) >= maxLedgerBytes - 2);
  store.close();

  const executor = new DurableExecutor({ database, encryptionKey: KEY, clock: () => 1_000, maxLedgerBytes });
  t.after(() => executor.close());
  assert.ok(executor.audit().length < events, 'the oldest recent events made room');
  assert.equal(executor.audit().at(-1).event, 'EXECUTOR_STARTED');
  executor.revokeTask('a');
  assert.throws(() => executor.assertProvenance('a'), { code: 'TASK_REVOKED' });
  assert.throws(() => task(executor, 'b'), { code: 'STORE_CAPACITY_EXCEEDED', detail: 'SOFT_LIMIT' });
});

test('revoke and cancel stop the handler even when the ledger write fails, and the first error survives', async t => {
  const executor = open(t);
  const aborted = [];
  const begun = starts(2);
  tool(executor, 'work', (args, context) => {
    begun.started();
    return new Promise((_resolve, reject) => {
      context.signal.addEventListener('abort', () => {
        aborted.push(args.name);
        reject(new Error('stopped'));
      });
    });
  });
  const credential = task(executor, 'a');
  task(executor, 'b');
  const byRevoke = await executor.prepare('a', { tool: 'work', args: { name: 'revoked' } });
  const byCancel = await executor.prepare('b', { tool: 'work', args: { name: 'cancelled' } });
  const running = [
    executor.execute('a', byRevoke.id).catch(error => error),
    executor.execute('b', byCancel.id).catch(error => error),
  ];
  await begun.all;
  const broken = new ExecutorError('STORE_CAPACITY_EXCEEDED');
  const [revoked, cancelled] = await withStorePatch(
    () => {
      throw broken;
    },
    async () => {
      // The failed revocation says that it is not durable and keeps the store error as its cause.
      assert.throws(
        () => executor.revokeTask('a'),
        error =>
          error instanceof ExecutorError &&
          error.code === 'OPERATION_FAILED' &&
          error.detail === 'REVOCATION_NOT_DURABLE' &&
          error.cause === broken,
      );
      assert.throws(
        () => executor.cancel('b', byCancel.id),
        error => error === broken,
      );
      // Another task cannot stop a handler through a failing ledger.
      assert.throws(
        () => executor.cancel('a', byCancel.id),
        error => error === broken,
      );
      return Promise.all(running);
    },
  );
  assert.deepEqual(aborted.sort(), ['cancelled', 'revoked']);
  for (const error of [revoked, cancelled]) {
    assert.equal(error.name, 'GuardError');
    assert.equal(error.code, 'EXECUTION_ABORTED', 'the handler error is reported, not the recovery failure');
    assert.equal(error.ledgerError, broken, 'the failed UNKNOWN write is attached');
  }
  // The revocation was not durable, but this process denies the task until it is.
  assert.throws(() => executor.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => executor.assertProvenance('a'), { code: 'TASK_REVOKED' });
  // Both actions are stranded in RUNNING with no live handler: reconcile settles them.
  for (const [taskId, action] of [
    ['a', byRevoke],
    ['b', byCancel],
  ]) {
    assert.equal(executor.execution(taskId, action.id).status, 'RUNNING');
    executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 0, reference: 'checked' });
    assert.equal(executor.execution(taskId, action.id).status, 'FAILED');
    assert.equal(executor.snapshot(taskId).concurrent, 0);
  }
  executor.revokeTask('a');
  assert.throws(() => executor.assertProvenance('a'), { code: 'TASK_REVOKED' });
});

test('reconcile refuses an action whose handler is still running', async t => {
  const executor = open(t);
  let release;
  const begun = starts(1);
  tool(executor, 'work', () => {
    begun.started();
    return new Promise(resolve => {
      release = () => resolve({ value: 1 });
    });
  });
  task(executor, 'a');
  const action = await executor.prepare('a', { tool: 'work', args: {} });
  const pending = executor.execute('a', action.id);
  await begun.all;
  assert.equal(executor.execution('a', action.id).status, 'RUNNING');
  assert.throws(() => executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 0, reference: 'r' }), {
    code: 'RECONCILIATION_INVALID',
  });
  release();
  assert.equal(await pending, 1);
});

test('a finished handler whose settlement cannot be recorded reports the committed effect', async t => {
  const executor = open(t);
  let effects = 0;
  let fail = false;
  tool(executor, 'work', () => {
    effects++;
    fail = true;
    return { value: 'secret result' };
  });
  task(executor, 'a');
  const action = await executor.prepare('a', { tool: 'work', args: {} });
  const broken = new ExecutorError('STORE_CAPACITY_EXCEEDED');
  const error = await withStorePatch(
    function (original, operation, options) {
      if (fail) throw broken;
      return original.call(this, operation, options);
    },
    () => executor.execute('a', action.id).catch(caught => caught),
  );
  assert.equal(effects, 1);
  assert.deepEqual([error.code, error.detail], ['EXECUTION_ABORTED', 'EFFECT_COMMITTED']);
  assert.equal(error.ledgerError, broken);
  executor.reconcile(action.id, { outcome: 'SUCCEEDED', actualCost: 1, reference: 'r' });
  assert.equal(executor.execution('a', action.id).status, 'SUCCEEDED');
});

// ---------------------------------------------------------------- 3. per-tenant retention

test("one tenant's many single-receipt families never evict another tenant's receipt", async t => {
  const executor = open(t);
  tool(executor, 'work', () => ({ value: 1 }));
  task(executor, 'mine');
  const mine = await run(executor, 'mine');
  // Before per-tenant retention the shared total of 256 evicted from "the busiest family, ties to
  // the oldest": 300 one-receipt families of another tenant evicted this tenant's only receipt.
  let first;
  for (let index = 0; index < 300; index++) {
    task(executor, `beta-${index}`, 'beta');
    const { action } = await run(executor, `beta-${index}`);
    first ??= action;
  }
  task(executor, 'beta-last', 'beta'); // Pruning runs when the next task or preparation is written.
  assert.equal(executor.execution('mine', mine.action.id).status, 'SUCCEEDED');
  const evicted = executor.execution('beta-0', first.id);
  assert.deepEqual([evicted.status, evicted.outcome, evicted.charged], ['PRUNED', 'SUCCEEDED', 1]);
});

test("stubs are capped per tenant: another tenant's stubs never displace this tenant's", () => {
  const limits = stubLimits(4 * 1024 * 1024);
  assert.deepEqual(limits, { perFamily: 256, perTenant: 1024, total: 1024 });
  assert.deepEqual(stubLimits(16 * 1024 * 1024), { perFamily: 256, perTenant: 1024, total: 4096 });
  assert.deepEqual(stubLimits(1024 * 1024), { perFamily: 256, perTenant: 256, total: 256 });
  const state = { tasks: Object.create(null), audit: [] };
  const settle = (family, tenantId, index) => {
    state.tasks[family] ??= { options: { id: family, tenantId }, family };
    recordPruned(state, family, { id: `${family}-${index}`, taskId: family, status: 'SUCCEEDED', charged: 1 }, limits);
  };
  settle('alpha-family', 'alpha', 0);
  // 1,100 one-stub families of another tenant: more than the total. Ties used to go to the oldest family.
  for (let index = 0; index < 1100; index++) settle(`beta-${index}`, 'beta', 0);
  assert.equal(prunedReceipt(state, 'alpha-family', 'alpha-family-0')?.outcome, 'SUCCEEDED');
  assert.equal(prunedReceipt(state, 'beta-0', 'beta-0-0'), undefined, 'the flooding tenant lost its own oldest');
  assert.ok(prunedReceipt(state, 'beta-1099', 'beta-1099-0'));
  const total = Object.values(state.retention.pruned).reduce((sum, group) => sum + Object.keys(group).length, 0);
  assert.equal(total, 1024);
  // A single tenant is held to its own cap even when the ledger-wide total has room.
  const wide = { perFamily: 256, perTenant: 300, total: 4096 };
  const other = { tasks: Object.create(null), audit: [] };
  for (const [family, tenantId, count] of [
    ['g1', 'gamma', 200],
    ['g2', 'gamma', 200],
    ['d1', 'delta', 5],
  ]) {
    other.tasks[family] = { options: { id: family, tenantId }, family };
    for (let index = 0; index < count; index++)
      recordPruned(other, family, { id: `${family}-${index}`, taskId: family, status: 'FAILED' }, wide);
  }
  const held = family => Object.keys(other.retention.pruned[family]).length;
  assert.equal(held('g1') + held('g2'), 300);
  assert.equal(held('d1'), 5);
});

test('an action that settled is PRUNED, not INVALID_PREPARED, while its settlement is still on record', async t => {
  const database = join(directory(), 'ledger.sqlite');
  const first = new DurableExecutor({ database, encryptionKey: KEY, clock: () => 1_000, maxReceiptsPerFamily: 1 });
  tool(first, 'work', () => ({ value: 1 }));
  task(first, 'a');
  const old = await run(first, 'a');
  await run(first, 'a');
  await first.prepare('a', { tool: 'work', args: {} }); // Pruning runs at the next preparation.
  assert.equal(first.execution('a', old.action.id).outcome, 'SUCCEEDED');
  first.close();
  // Drop the compact stub, as a full per-tenant stub store would.
  const store = new LedgerStore(database, KEY);
  store.transaction(state => {
    delete state.retention.pruned.a[old.action.id];
  });
  store.close();
  const executor = new DurableExecutor({ database, encryptionKey: KEY, clock: () => 1_000, maxReceiptsPerFamily: 1 });
  t.after(() => executor.close());
  assert.deepEqual({ ...executor.execution('a', old.action.id) }, { id: old.action.id, status: 'PRUNED' });
  assert.throws(() => executor.execution('a', '00000000-0000-4000-8000-000000000000'), { code: 'INVALID_PREPARED' });
  task(executor, 'b');
  assert.throws(() => executor.execution('b', old.action.id), { code: 'INVALID_PREPARED' }, 'only for the owner');
});

// ---------------------------------------------------------------- 4. memory events

test('memory events are recorded under their tenant and never displace system events', t => {
  const executor = open(t);
  tool(executor, 'work', () => ({ value: 1 }));
  executor.setPolicy(() => 'allow');
  for (let index = 0; index < 300; index++)
    executor.importMemory({ id: `note-${index % 100}`, tenantId: 'alpha', origin: 'operator', value: index });
  executor.quarantineMemory('alpha', 'note-1');
  executor.rollbackMemory('alpha', 'note-2', 1);
  const all = executor.audit();
  for (const event of ['EXECUTOR_STARTED', 'TOOL_REGISTERED', 'TOOL_APPROVED', 'POLICY_CHANGED'])
    assert.ok(
      all.some(entry => entry.event === event),
      `${event} survived 300 memory writes`,
    );
  const memory = all.filter(entry => entry.event.startsWith('MEMORY_'));
  assert.equal(memory.length, 256, "the tenant's own ring is full");
  assert.ok(memory.every(entry => entry.tenantId === 'alpha'));
  const scoped = executor.audit({ tenantId: 'alpha' });
  assert.ok(scoped.some(entry => entry.event === 'MEMORY_QUARANTINED'));
  assert.ok(scoped.some(entry => entry.event === 'MEMORY_ROLLED_BACK'));
  assert.equal(executor.audit({ tenantId: 'beta' }).length, 0);
});

test('tenant events at the total cap never trim the system bucket', t => {
  const executor = open(t);
  for (let index = 0; index < 5; index++)
    for (let write = 0; write < 256; write++)
      executor.importMemory({ id: `n-${write % 64}`, tenantId: `tenant-${index}`, origin: 'operator', value: write });
  const all = executor.audit();
  assert.ok(all.length <= 1000);
  assert.ok(all.some(entry => entry.event === 'EXECUTOR_STARTED'));
});

// ---------------------------------------------------------------- 5. error contract

test('every refused host call is a GuardError or ExecutorError with a code', async t => {
  const executor = open(t);
  const fingerprint = executor.registerTool({
    name: 'work',
    description: 'x',
    resolve: () => ({ resourceId: 'record', tenantId: 'alpha' }),
    execute: () => ({ value: 1 }),
  });
  assert.throws(() => executor.approveTool('missing', fingerprint), { name: 'GuardError', code: 'TOOL_UNKNOWN' });
  assert.throws(() => executor.approveTool('work', 'sha256:other'), { name: 'GuardError', code: 'TOOL_CHANGED' });
  executor.approveTool('work', fingerprint);
  task(executor, 'a');
  const invalid = { name: 'GuardError', code: 'INVALID_INPUT' };
  await assert.rejects(executor.prepare('a', null), invalid);
  await assert.rejects(executor.prepare('a', undefined), { name: 'GuardError' });
  await assert.rejects(executor.prepare('a', []), invalid);
  const action = await executor.prepare('a', { tool: 'work', args: {} });
  assert.throws(() => executor.approve(action.id, undefined), invalid);
  assert.throws(() => executor.approve(action.id, null), invalid);
  await assert.rejects(executor.execute('a', action.id, null), invalid);
  assert.throws(() => executor.createTask(null), invalid);
  assert.throws(() => executor.createTask({ id: 'x' }, null), invalid);
  assert.throws(() => executor.delegateTask('a', null), invalid);
  assert.throws(() => executor.audit(null), invalid);
  assert.throws(() => executor.importMemory(null), invalid);
  assert.throws(() => new DurableExecutor(), invalid);
  assert.throws(() => new DurableExecutor(null), invalid);
  // Data that is not JSON is INVALID_JSON, as in the guard, not an InvalidJsonError.
  const json = { name: 'GuardError', code: 'INVALID_JSON' };
  const cyclic = {};
  cyclic.self = cyclic;
  await assert.rejects(executor.prepare('a', { tool: 'work', args: { when: new Date() } }), json);
  await assert.rejects(executor.prepare('a', { tool: 'work', args: cyclic }), json);
  assert.throws(() => executor.createTask({ id: 'x', extra: 1n }), json);
  assert.throws(() => executor.importMemory({ id: 'n', tenantId: 'alpha', origin: 'operator', value: () => 1 }), json);
  // Store configuration is one class and code, whichever option is wrong.
  const config = { name: 'ExecutorError', code: 'STORE_CONFIG_INVALID' };
  const database = join(directory(), 'l.sqlite');
  assert.throws(() => new DurableExecutor({ database, encryptionKey: KEY, maxLedgerBytes: 1024 }), config);
  assert.throws(() => new DurableExecutor({ database, encryptionKey: Buffer.alloc(16) }), config);
  assert.throws(() => new DurableExecutor({ database, encryptionKey: 'key' }), config);
  assert.throws(() => new DurableExecutor({ encryptionKey: KEY }), config);
  assert.equal(existsSync(database), false);
});

test('quarantining a memory entry that does not exist is refused and leaves no event', t => {
  const executor = open(t);
  executor.importMemory({ id: 'note', tenantId: 'alpha', origin: 'operator', value: 1 });
  const before = executor.audit().length;
  for (const [tenantId, entryId] of [
    ['alpha', 'missing'],
    ['beta', 'note'],
  ])
    assert.throws(() => executor.quarantineMemory(tenantId, entryId), {
      name: 'ExecutorError',
      code: 'MEMORY_UNAVAILABLE',
    });
  assert.equal(executor.audit().length, before);
  executor.quarantineMemory('alpha', 'note');
  executor.quarantineMemory('alpha', 'note');
  assert.equal(executor.audit().at(-1).event, 'MEMORY_QUARANTINED');
});

test('a ledger that will not open says why: wrong key, second owner, damaged file, missing directory', t => {
  const root = directory();
  const database = join(root, 'ledger.sqlite');
  const owner = new DurableExecutor({ database, encryptionKey: KEY });
  t.after(() => owner.close());
  const failure = options => {
    try {
      new DurableExecutor({ database, encryptionKey: KEY, ...options }).close();
    } catch (error) {
      return error;
    }
    return assert.fail('the ledger opened');
  };
  const locked = failure({});
  assert.deepEqual([locked.name, locked.code, locked.detail], ['ExecutorError', 'STORE_UNAVAILABLE', 'LOCKED']);
  owner.close();
  const wrongKey = failure({ encryptionKey: Buffer.alloc(32, 1) });
  assert.deepEqual([wrongKey.code, wrongKey.detail], ['STORE_UNAVAILABLE', 'KEY_MISMATCH']);
  assert.ok(!JSON.stringify([wrongKey.message, wrongKey.detail]).includes(root), 'no path in the error');
  new DurableExecutor({ database, encryptionKey: KEY }).close(); // The right key still opens it.
  const damaged = join(root, 'damaged.sqlite');
  writeFileSync(damaged, Buffer.alloc(8192, 0x5a), { mode: 0o600 });
  const corrupt = failure({ database: damaged });
  assert.deepEqual([corrupt.code, corrupt.detail], ['STORE_UNAVAILABLE', 'CORRUPT']);
  const missing = failure({ database: join(root, 'absent', 'ledger.sqlite') });
  assert.equal(missing.name, 'ExecutorError');
  assert.deepEqual([missing.code, missing.detail], ['STORE_DIRECTORY_UNSAFE', 'DIRECTORY_MISSING']);
});

test('exportDecisionTraces reports every failure as a rejection, never a synchronous throw', async t => {
  const disabled = open(t);
  let promise;
  assert.doesNotThrow(() => {
    promise = disabled.exportDecisionTraces({ tenantId: 'alpha' }, () => {});
  });
  await assert.rejects(promise, { name: 'ExecutorError', code: 'TRACE_DISABLED' });
  const enabled = open(t, { decisionTraces: {} });
  const cyclic = {};
  cyclic.self = cyclic;
  await assert.rejects(
    enabled.exportDecisionTraces(cyclic, () => {}),
    {
      name: 'ExecutorError',
      code: 'TRACE_SCOPE_INVALID',
    },
  );
  assert.throws(() => enabled.decisionTraceSnapshot(null), { name: 'ExecutorError', code: 'TRACE_SCOPE_INVALID' });
});

// ---------------------------------------------------------------- 6. tool removal

test('unapproveTool and unregisterTool follow the guard', async t => {
  const executor = open(t);
  const definition = {
    name: 'work',
    description: 'x',
    resolve: () => ({ resourceId: 'record', tenantId: 'alpha' }),
    execute: () => ({ value: 1 }),
  };
  const fingerprint = executor.registerTool(definition);
  executor.approveTool('work', fingerprint);
  task(executor, 'a');
  const unknown = { name: 'GuardError', code: 'TOOL_UNKNOWN' };
  assert.throws(() => executor.unapproveTool('missing'), unknown);
  assert.throws(() => executor.unregisterTool('missing'), unknown);

  const held = await executor.prepare('a', { tool: 'work', args: {} });
  executor.unapproveTool('work');
  await assert.rejects(executor.execute('a', held.id), { code: 'TOOL_UNAPPROVED' });
  await assert.rejects(executor.prepare('a', { tool: 'work', args: {} }), { code: 'TOOL_UNAPPROVED' });
  executor.approveTool('work', fingerprint);
  assert.equal(await executor.execute('a', held.id), 1);

  const stale = await executor.prepare('a', { tool: 'work', args: {} });
  executor.unregisterTool('work');
  await assert.rejects(executor.execute('a', stale.id), { code: 'TOOL_CHANGED' });
  await assert.rejects(executor.prepare('a', { tool: 'work', args: {} }), unknown);
  assert.throws(() => executor.approveTool('work', fingerprint), unknown);
  assert.throws(() => executor.unregisterTool('work'), unknown);
  // The same definition registered again needs a new approval and never revives the old action.
  assert.equal(executor.registerTool(definition), fingerprint);
  await assert.rejects(executor.prepare('a', { tool: 'work', args: {} }), { code: 'TOOL_UNAPPROVED' });
  executor.approveTool('work', fingerprint);
  await assert.rejects(executor.execute('a', stale.id), { code: 'TOOL_CHANGED' });
  assert.equal((await run(executor, 'a')).result, 1);
  assert.deepEqual(
    executor
      .audit()
      .map(entry => entry.event)
      .filter(event => event.startsWith('TOOL_') && event !== 'TOOL_REGISTERED' && event !== 'TOOL_APPROVED'),
    ['TOOL_APPROVAL_WITHDRAWN', 'TOOL_UNREGISTERED'],
  );
});

test('tool records can be removed, so maxRecords distinct names do not block registration forever', t => {
  const database = join(directory(), 'ledger.sqlite');
  const definition = name => ({
    name,
    description: 'x',
    resolve: () => ({ resourceId: 'record', tenantId: 'alpha' }),
    execute: () => ({ value: 1 }),
  });
  const options = { database, encryptionKey: KEY, clock: () => 1_000, maxRecords: 4 };
  let executor = new DurableExecutor(options);
  for (const name of ['a', 'b', 'c', 'd']) executor.registerTool(definition(name));
  assert.throws(() => executor.registerTool(definition('e')), { code: 'CAPACITY_EXCEEDED' });
  executor.unregisterTool('a');
  executor.registerTool(definition('e'));
  assert.throws(() => executor.registerTool(definition('f')), { code: 'CAPACITY_EXCEEDED' });
  executor.close();
  // After a restart the four records belong to no registration: new names reclaim them.
  executor = new DurableExecutor(options);
  t.after(() => executor.close());
  executor.registerTool(definition('b'));
  for (const name of ['w', 'x', 'y']) executor.registerTool(definition(name));
  assert.throws(() => executor.registerTool(definition('z')), { code: 'CAPACITY_EXCEEDED' });
  // A record with no registration in this process can still be removed by name.
  executor.close();
  executor = new DurableExecutor(options);
  executor.unregisterTool('w');
  assert.throws(() => executor.unregisterTool('w'), { code: 'TOOL_UNKNOWN' });
});

// ---------------------------------------------------------------- 7. failed witnessed create

test('a failed witnessed create leaves no empty ledger behind, and the retry succeeds', { skip: !posix }, t => {
  const root = directory();
  const data = join(root, 'data');
  const witness = join(root, 'witness');
  mkdirSync(data, { mode: 0o700 });
  mkdirSync(witness, { mode: 0o700 });
  const database = join(data, 'ledger.sqlite');
  const witnessPath = join(witness, 'ledger.sqlite');
  writeFileSync(witnessPath, 'left over from an earlier attempt', { mode: 0o600 });
  const options = { database, encryptionKey: KEY, rollbackWitness: { path: witnessPath, mode: 'create' } };
  assert.throws(() => new DurableExecutor(options), { name: 'ExecutorError', code: 'STORE_WITNESS_UNAVAILABLE' });
  assert.equal(existsSync(database), false, 'no zero-byte ledger remains');
  assert.equal(
    readFileSync(witnessPath, 'utf8'),
    'left over from an earlier attempt',
    'a file it did not create stays',
  );
  // Second attempt with the obstacle still there fails the same way, not on the ledger it left.
  assert.throws(() => new DurableExecutor(options), { code: 'STORE_WITNESS_UNAVAILABLE', detail: 'FILE_EXISTS' });
  writeFileSync(witnessPath, '');
  assert.throws(() => new DurableExecutor(options), { code: 'STORE_WITNESS_UNAVAILABLE' });
  assert.equal(existsSync(database), false);
  // Remove the obstacle: the create now works and resumes.
  rmSync(witnessPath);
  new DurableExecutor(options).close();
  new DurableExecutor({ ...options, rollbackWitness: { path: witnessPath, mode: 'resume' } }).close();
});

// ---------------------------------------------------------------- 12. smaller items

test('maxApprovalsPerAction bounds the unused approvals of one action', async t => {
  for (const [options, limit] of [
    [{}, 4],
    [{ maxApprovalsPerAction: 2 }, 2],
    [{ maxApprovalsPerAction: 6 }, 6],
  ]) {
    const executor = open(t, options);
    tool(executor, 'work', () => ({ value: 1 }));
    task(executor, 'a');
    const action = await executor.prepare('a', { tool: 'work', args: {} });
    for (let index = 0; index < limit; index++) executor.approve(action.id, { approverId: 'r', expiresAt: 2_000 });
    assert.throws(() => executor.approve(action.id, { approverId: 'r', expiresAt: 2_000 }), {
      code: 'ACTION_APPROVAL_LIMIT',
    });
  }
  for (const maxApprovalsPerAction of [0, 65, 1.5, '4'])
    assert.throws(() => new DurableExecutor({ database: ':memory:', encryptionKey: KEY, maxApprovalsPerAction }), {
      name: 'GuardError',
      code: 'INVALID_INPUT',
    });
});

test('one execution is two ledger commits: admission and settlement', async t => {
  const executor = open(t);
  let during;
  let action;
  tool(executor, 'work', () => {
    during = executor.execution('a', action.id).status;
    return { value: 1 };
  });
  task(executor, 'a');
  action = await executor.prepare('a', { tool: 'work', args: {} });
  let commits = 0;
  await withStorePatch(
    function (original, operation, options) {
      commits++;
      return original.call(this, operation, options);
    },
    () => executor.execute('a', action.id),
  );
  assert.equal(commits, 2);
  assert.equal(during, 'RUNNING');
  assert.deepEqual(
    executor
      .audit({ tenantId: 'alpha' })
      .filter(entry => entry.actionId === action.id)
      .map(entry => entry.event),
    ['ACTION_PREPARED', 'ACTION_ADMITTED', 'ACTION_SETTLED'],
  );
});

test('revoking a task quarantines memory written by every task derived from it', async t => {
  const executor = open(t);
  const memory = executor.registerMemoryTools();
  executor.approveTool('memory.write', memory.write);
  const options = id => ({
    id,
    principalId: 'p',
    tenantId: 'alpha',
    grants: [{ tool: 'memory.write', resources: [`note-${id}`] }],
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 10, deadline: 1_000_000 },
  });
  executor.createTask(options('root'));
  executor.createTask(options('handoff'), { sourceTaskId: 'root' });
  executor.createTask(options('later'), { sourceTaskId: 'handoff' });
  executor.createTask(options('unrelated'));
  for (const id of ['root', 'handoff', 'later', 'unrelated']) {
    const action = await executor.prepare(id, {
      tool: 'memory.write',
      args: { id: `note-${id}`, value: id, ifVersion: 0 },
    });
    await executor.execute(id, action.id);
  }
  executor.revokeTask('handoff');
  const refused = { code: 'MEMORY_UNAVAILABLE' };
  assert.throws(() => executor.rollbackMemory('alpha', 'note-handoff', 1), refused);
  assert.throws(() => executor.rollbackMemory('alpha', 'note-later', 1), refused);
  assert.doesNotThrow(() => executor.rollbackMemory('alpha', 'note-root', 1));
  assert.doesNotThrow(() => executor.rollbackMemory('alpha', 'note-unrelated', 1));
  assert.throws(() => executor.assertProvenance('later'), { code: 'TASK_REVOKED' });
  assert.doesNotThrow(() => executor.assertProvenance('root'));
});
