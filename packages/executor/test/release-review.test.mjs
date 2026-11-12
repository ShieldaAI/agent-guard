import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GuardError } from '@shieldaai/agent-guard';
import { DurableExecutor, ExecutorError, createOutboundJsonTool, startExecutorServer } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';
import { removeAtExit } from './temp-directory.mjs';

// Regression tests for the pre-release review of 1.0.0: revocation durability, host callbacks
// inside built-in tools, rate-limit order and tool registration at the soft limit.

const KEY = Buffer.alloc(32, 78);
const MiB = 1024 * 1024;

function directory() {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'release-review-')));
  removeAtExit(path);
  return path;
}
function open(t, database, options = {}) {
  const executor = new DurableExecutor({ database, encryptionKey: KEY, clock: () => 1_000, ...options });
  t.after(() => {
    try {
      executor.close();
    } catch {
      /* Already closed by the test. */
    }
  });
  return executor;
}
const work = (execute = () => ({ value: 'done' }), extra = {}) => ({
  name: 'work',
  description: 'work',
  maxCost: 1,
  resolve: (_args, owner) => ({ resourceId: 'record', tenantId: owner.tenantId }),
  execute,
  ...extra,
});
function register(executor, definition) {
  const fingerprint = executor.registerTool(definition);
  executor.approveTool(definition.name, fingerprint);
  return fingerprint;
}
const options = (id, grants = [{ tool: 'work', resources: ['record'] }], extra = {}) => ({
  id,
  principalId: 'operator',
  tenantId: 'alpha',
  grants,
  budget: { maxCalls: 100, maxConcurrent: 8, maxCost: 100, deadline: 1_000_000 },
  ...extra,
});
/** Replace LedgerStore.transaction for the duration of `during`. */
async function withStorePatch(patch, during) {
  const original = LedgerStore.prototype.transaction;
  LedgerStore.prototype.transaction = function (operation, writeOptions) {
    return patch.call(this, original, operation, writeOptions);
  };
  try {
    return await during();
  } finally {
    LedgerStore.prototype.transaction = original;
  }
}
/** What a failing disk looks like to the executor: a plain error from SQLite, not a coded one. */
const diskFailure = () => Object.assign(new Error('disk I/O error'), { code: 'ERR_SQLITE_ERROR', errcode: 10 });
const failingStore = during =>
  withStorePatch(() => {
    throw diskFailure();
  }, during);
const notDurable = error =>
  error instanceof ExecutorError &&
  error.code === 'OPERATION_FAILED' &&
  error.detail === 'REVOCATION_NOT_DURABLE' &&
  error.cause instanceof Error &&
  error.cause.message === 'disk I/O error';
/** The ledger as the next process will find it. */
function stored(database) {
  const store = new LedgerStore(database, KEY);
  try {
    return store.read();
  } finally {
    store.close();
  }
}

// ---------------------------------------------------------------- 1. revocation durability

test('a revocation whose write failed is recorded by the next ledger write, even a refused one', async t => {
  const database = join(directory(), 'ledger.sqlite');
  let executor = open(t, database);
  register(executor, work());
  const memory = executor.registerMemoryTools();
  executor.approveTool('memory.write', memory.write);
  const credential = executor.createTask(
    options('a', [
      { tool: 'work', resources: ['record'] },
      { tool: 'memory.write', resources: ['note'] },
    ]),
  );
  const child = executor.delegateTask('a', {
    id: 'a-child',
    grants: [{ tool: 'work', resources: ['record'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 5, deadline: 1_000_000 },
  });
  executor.createTask(options('other'));
  const note = await executor.prepare('a', { tool: 'memory.write', args: { id: 'note', value: 'x', ifVersion: 0 } });
  await executor.execute('a', note.id);

  await failingStore(() => assert.throws(() => executor.revokeTask('a'), notDurable));
  // Denied in this process, with nothing in the ledger yet.
  assert.throws(() => executor.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => executor.authenticate(child.token), { code: 'UNAUTHENTICATED' });
  assert.equal(
    executor.audit().some(event => event.event === 'TASK_REVOKED'),
    false,
  );

  // The next write is refused for its own reason; the revocation is recorded all the same.
  assert.throws(() => executor.createTask(options('other')), { code: 'DUPLICATE_TASK' });
  const events = executor.audit().filter(event => event.event === 'TASK_REVOKED');
  assert.deepEqual(
    events.map(event => event.taskId),
    ['a'],
    'one TASK_REVOKED event, as a revocation that succeeded at once would leave',
  );
  // Later writes do not record it again.
  executor.markSensitive('other');
  assert.equal(executor.audit().filter(event => event.event === 'TASK_REVOKED').length, 1);

  executor.close();
  const ledger = stored(database);
  assert.equal(ledger.tasks.a.revoked, true);
  assert.equal(
    Object.values(ledger.memory)
      .flat()
      .every(entry => entry.quarantined),
    true,
    'memory the revoked task wrote is quarantined, as by a normal revoke',
  );
  // After a restart the task and everything derived from it stay revoked.
  executor = open(t, database, { clock: () => 2_000 });
  assert.throws(() => executor.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => executor.authenticate(child.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => executor.assertProvenance('a-child'), { code: 'TASK_REVOKED' });
});

test('repeating a failed revocation is safe, and unknown tasks are never remembered', async t => {
  const executor = open(t, ':memory:');
  executor.createTask(options('a'));
  executor.createTask(options('b'));
  await failingStore(() => {
    assert.throws(() => executor.revokeTask('a'), notDurable);
    // An unknown task has nothing to deny: its own error comes back unchanged.
    assert.throws(
      () => executor.revokeTask('missing'),
      error => error.message === 'disk I/O error',
    );
  });
  assert.throws(() => executor.revokeTask('missing'), { code: 'INVALID_TASK' });
  // Revoking another task records the pending one in the same commit.
  executor.revokeTask('b');
  assert.deepEqual(
    executor
      .audit()
      .filter(event => event.event === 'TASK_REVOKED')
      .map(event => event.taskId)
      .sort(),
    ['a', 'b'],
  );
  executor.revokeTask('a');
  assert.throws(() => executor.assertProvenance('a'), { code: 'TASK_REVOKED' });
});

test('close() records a pending revocation; one that no write could record is lost on restart', async t => {
  for (const closeFails of [false, true]) {
    const database = join(directory(), 'ledger.sqlite');
    let executor = open(t, database);
    const credential = executor.createTask(options('a'));
    await failingStore(async () => {
      assert.throws(() => executor.revokeTask('a'), notDurable);
      if (closeFails) executor.close();
    });
    if (!closeFails) executor.close();
    assert.equal(stored(database).tasks.a.revoked, !closeFails);
    executor = open(t, database, { clock: () => 2_000 });
    if (closeFails)
      // The documented limit: nothing was written before the process ended, so the task is valid again.
      assert.equal(executor.authenticate(credential.token), 'a');
    else assert.throws(() => executor.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
    executor.close();
  }
});

test('the admin route reports a revocation that is not durable as retryable 503 with a detail', async t => {
  const executor = open(t, ':memory:');
  register(
    executor,
    work(() => {
      throw new ExecutorError('OPERATION_FAILED', { detail: 'REVOCATION_NOT_DURABLE' });
    }),
  );
  const credential = executor.createTask(options('a'));
  const forger = executor.createTask(options('forger'));
  const adminToken = randomBytes(32).toString('base64url');
  const server = await startExecutorServer({ executor, adminToken, operatorId: 'op-1' });
  t.after(() => server.close());
  const post = async (path, token, body = {}) => {
    const response = await fetch(server.url + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return [response.status, await response.json()];
  };

  assert.deepEqual(await failingStore(() => post('/v1/admin/revoke', adminToken, { taskId: 'a' })), [
    503,
    { error: 'OPERATION_FAILED', retryable: true, detail: 'REVOCATION_NOT_DURABLE' },
  ]);
  assert.deepEqual(await post('/v1/task/snapshot', credential.token), [
    401,
    { error: 'UNAUTHENTICATED', retryable: false },
  ]);
  // Repeating the request, as the response says, makes it durable.
  assert.deepEqual(await post('/v1/admin/revoke', adminToken, { taskId: 'a' }), [200, { revoked: true }]);
  assert.equal(executor.audit().filter(event => event.event === 'TASK_REVOKED').length, 1);

  // A malformed request is still a 400, an unknown task a 404, and neither carries a detail.
  assert.deepEqual(await post('/v1/admin/revoke', adminToken, { taskId: 5 }), [
    400,
    { error: 'REQUEST_INVALID', retryable: false },
  ]);
  assert.deepEqual(await post('/v1/admin/revoke', adminToken, { taskId: 'missing' }), [
    404,
    { error: 'INVALID_TASK', retryable: false },
  ]);
  // A handler cannot borrow the detail: task routes never send one.
  const prepared = await executor.prepare('forger', { tool: 'work', args: {} });
  assert.deepEqual(await post('/v1/task/execute', forger.token, { actionId: prepared.id }), [
    503,
    { error: 'TOOL_FAILED', retryable: false },
  ]);
});

// ---------------------------------------------------------------- 2. host callbacks in built-in tools

test("an error from the outbound tool's credential callback is a tool failure, whatever its code", async t => {
  const executor = open(t, ':memory:');
  let credential;
  const tool = createOutboundJsonTool({
    name: 'message.send',
    tenantId: 'alpha',
    resourcePrefix: 'messages',
    resource: 'room',
    recipient: 'room:review',
    endpoint: 'https://chat.example.invalid/send',
    credentialVersion: 'v1',
    credential: () => credential(),
    parsePayload: value => value,
    payloadSchema: { type: 'object' },
    network: { allowedOrigins: ['https://chat.example.invalid'] },
  });
  register(executor, tool);
  executor.createTask(
    options('a', [{ tool: 'message.send', resources: ['messages/room'] }], { allowedRecipients: ['room:review'] }),
  );
  const call = async () => {
    const action = await executor.prepare('a', { tool: 'message.send', args: { payload: { message: 'hi' } } });
    const approvalId = executor.approve(action.id, { approverId: 'reviewer', expiresAt: 500_000 });
    return executor.execute('a', action.id, { approvalId }).catch(error => error);
  };
  for (const thrown of [new ExecutorError('ADAPTER_HTTP_STATUS'), new ExecutorError('DESTINATION_DENIED')]) {
    credential = () => {
      throw thrown;
    };
    const error = await call();
    assert.deepEqual([error.name, error.code, error.detail], ['GuardError', 'TOOL_FAILED', thrown.code]);
  }
  // The adapter's own refusal, raised by the adapter, keeps its code.
  credential = () => ({ value: 'token', version: 'v2' });
  assert.equal((await call()).code, 'ADAPTER_CREDENTIAL_CHANGED');
});

// ---------------------------------------------------------------- 3. rate limits before the ledger read

test('a request over a limit costs no ledger read, and only authenticated requests spend the shared window', async t => {
  const executor = open(t, ':memory:');
  register(executor, work());
  const busy = executor.createTask(options('busy'));
  const quiet = executor.createTask(options('quiet'));
  const revoked = executor.createTask(options('revoked'));
  executor.revokeTask('revoked');
  const adminToken = randomBytes(32).toString('base64url');
  const server = await startExecutorServer({
    executor,
    adminToken,
    operatorId: 'op-1',
    requestsPerMinutePerCredential: 3,
    requestsPerMinute: 5,
  });
  t.after(() => server.close());
  const post = (path, token, body = {}) =>
    fetch(server.url + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then(response => response.status);
  let reads = 0;
  const read = LedgerStore.prototype.read;
  LedgerStore.prototype.read = function () {
    reads++;
    return read.call(this);
  };
  t.after(() => {
    LedgerStore.prototype.read = read;
  });
  const readsDuring = async during => {
    const before = reads;
    await during();
    return reads - before;
  };

  for (let i = 0; i < 3; i++) assert.equal(await post('/v1/task/snapshot', busy.token), 200);
  // Over its own limit: refused without touching the ledger, however often it asks.
  assert.equal(
    await readsDuring(async () => {
      for (let i = 0; i < 25; i++) assert.equal(await post('/v1/task/snapshot', busy.token), 429);
    }),
    0,
  );
  // An unknown token costs no read either, and spends nothing.
  assert.equal(
    await readsDuring(async () => {
      for (let i = 0; i < 10; i++)
        assert.equal(await post('/v1/task/snapshot', randomBytes(32).toString('base64url')), 401);
    }),
    0,
  );
  // A token this executor issued for a task that is now revoked is refused by the ledger read and
  // takes nothing from the shared window.
  for (let i = 0; i < 3; i++) assert.equal(await post('/v1/task/snapshot', revoked.token), 401);
  // None of the 38 refused requests spent the shared window: the quiet task has the two that are left.
  for (let i = 0; i < 2; i++) assert.equal(await post('/v1/task/snapshot', quiet.token), 200);
  // The shared window is now used up: the next task request is refused before the ledger read.
  assert.equal(await readsDuring(async () => assert.equal(await post('/v1/task/snapshot', quiet.token), 429)), 0);
  // Administration is outside the shared window.
  assert.equal(await post('/v1/admin/revoke', adminToken, { taskId: 'busy' }), 200);
});

test('knowsToken is an in-memory lookup and never authentication', t => {
  const executor = open(t, ':memory:');
  const credential = executor.createTask(options('a'));
  assert.equal(executor.knowsToken(credential.token), true);
  for (const unknown of [randomBytes(32).toString('base64url'), '', 'short', undefined, 5, {}])
    assert.equal(executor.knowsToken(unknown), false);
  executor.revokeTask('a');
  assert.equal(executor.knowsToken(credential.token), true, 'recognized, yet not authenticated');
  assert.throws(() => executor.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
});

// ---------------------------------------------------------------- 4. tool registration at the soft limit

test('a process can register its unchanged tools again inside the reserve; new and changed tools are refused', async t => {
  const database = join(directory(), 'ledger.sqlite');
  let executor = open(t, database, { maxLedgerBytes: 2 * MiB });
  const definition = work();
  const fingerprint = register(executor, definition);
  // Fill to the soft limit of a 2 MiB ledger: about 1.75 MiB.
  const chunk = 'x'.repeat(60_000);
  for (let index = 0; ; index++) {
    assert.ok(index < 100, 'the ledger never reached its soft limit');
    try {
      executor.importMemory({ id: `fill-${index}`, tenantId: 'filler', origin: 'operator', value: chunk });
    } catch (error) {
      assert.deepEqual([error.code, error.detail], ['STORE_CAPACITY_EXCEEDED', 'SOFT_LIMIT']);
      break;
    }
  }
  executor.close();

  // The same ledger under a slightly smaller bound is inside the reserve, as an existing ledger
  // can be after an upgrade: every growth is refused.
  executor = open(t, database, { maxLedgerBytes: 1_900_000, clock: () => 2_000 });
  const refused = { name: 'ExecutorError', code: 'STORE_CAPACITY_EXCEEDED', detail: 'SOFT_LIMIT' };
  assert.throws(() => executor.createTask(options('a')), refused);
  let commits = 0;
  await withStorePatch(
    function (original, operation, writeOptions) {
      commits++;
      return original.call(this, operation, writeOptions);
    },
    () => {
      // The start of every process: register the tools again. Nothing is written.
      assert.equal(executor.registerTool(definition), fingerprint);
      assert.equal(commits, 0);
      // Approval is a plain write and still fits.
      executor.approveTool('work', fingerprint);
      assert.equal(commits, 1);
      // A new tool and a changed one add to the ledger: refused.
      assert.throws(() => executor.registerTool({ ...work(), name: 'other' }), refused);
      assert.throws(() => executor.registerTool(work(undefined, { description: 'changed' })), refused);
      // Registering the same tool once more in this process withdraws its approval and still fits.
      assert.equal(executor.registerTool(definition), fingerprint);
    },
  );
  executor.close();
  const store = new LedgerStore(database, KEY, 2 * MiB);
  try {
    const tools = store.read().tools;
    assert.equal(tools.work.approved, false, 'the repeated registration withdrew the approval');
    assert.equal(tools.work.revision, 2, 'kept by the first registration after the start, raised by the second');
    assert.equal(Object.hasOwn(tools, 'other'), false);
  } finally {
    store.close();
  }
});

test('an unchanged registration after a restart keeps no earlier preparation alive', async t => {
  const database = join(directory(), 'ledger.sqlite');
  let executor = open(t, database);
  const definition = work();
  register(executor, definition);
  executor.createTask(options('a'));
  const before = await executor.prepare('a', { tool: 'work', args: {} });
  executor.close();

  executor = open(t, database, { clock: () => 2_000 });
  // Registered but not approved: opening the executor withdrew the approval.
  const fingerprint = executor.registerTool(definition);
  await assert.rejects(executor.prepare('a', { tool: 'work', args: {} }), { code: 'TOOL_UNAPPROVED' });
  executor.approveTool('work', fingerprint);
  // The tool keeps its revision, but the restart ended every earlier preparation.
  await assert.rejects(
    executor.execute('a', before.id),
    error => error instanceof GuardError && error.code === 'POLICY_CHANGED',
  );
  const fresh = await executor.prepare('a', { tool: 'work', args: {} });
  // Registering the same definition again in this process still ends what was prepared for it.
  executor.approveTool('work', executor.registerTool(definition));
  await assert.rejects(executor.execute('a', fresh.id), { code: 'TOOL_CHANGED' });
  const current = await executor.prepare('a', { tool: 'work', args: {} });
  assert.equal(await executor.execute('a', current.id), 'done');
});

test('withdrawing and removing a tool are critical writes, like revoke', async t => {
  const executor = open(t, ':memory:');
  register(executor, work());
  const seen = [];
  await withStorePatch(
    function (original, operation, writeOptions) {
      seen.push(writeOptions);
      return original.call(this, operation, writeOptions);
    },
    () => {
      executor.unapproveTool('work');
      executor.unregisterTool('work');
    },
  );
  assert.equal(seen.length, 2);
  for (const writeOptions of seen) {
    assert.equal(typeof writeOptions?.relief, 'function', 'may use the reserve and drop recent events');
    assert.equal(writeOptions.growth, undefined);
  }
});
