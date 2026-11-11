import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import { Server } from 'node:http';
import os from 'node:os';
import workerThreads from 'node:worker_threads';
import { syncBuiltinESMExports } from 'node:module';
import * as publicApi from '../dist/index.js';
import { DurableExecutor, startInventoryServer, createInventoryObserverToken } from '../dist/index.js';
import { createInventoryObservationSession, readInventoryWorkerScheduling } from '../dist/inventory-observer.js';
import { configureInventoryWorkerScheduling, currentLinuxThreadPriority } from '../dist/inventory-scheduling.js';

const fixture = new URL('./fixtures/inventory-scheduling-worker.mjs', import.meta.url);
const config = { companyId: 'company', sourceId: 'source', enrollmentGeneration: 'generation' };
function executor(t) {
  const result = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), inventory: config });
  t.after(() => result.close());
  return result;
}
const request = () => ({
  scope: { tenantId: 'tenant' },
  profile: 'core',
  signal: new AbortController().signal,
  deadline: performance.now() + 10_000,
});
async function fixtureResult(workerData) {
  const worker = new Worker(fixture, { workerData, execArgv: [], env: {} });
  try {
    return (await once(worker, 'message'))[0];
  } finally {
    await worker.terminate();
  }
}

test('worker scheduling is a private opt-in; default never reads or changes native priority', async t => {
  assert.equal(Object.hasOwn(publicApi, 'readInventoryWorkerScheduling'), false);
  assert.equal(Object.hasOwn(publicApi, 'configureInventoryWorkerScheduling'), false);
  const evidence = await fixtureResult({ case: 'default' });
  assert.deepEqual(evidence.evidence, { mode: 'default' });
  assert.equal(evidence.opened, 0);
  assert.equal(evidence.reads, 0);
  assert.deepEqual(evidence.calls, []);
  assert.deepEqual(evidence.setCalls, []);
  const owner = executor(t),
    session = await createInventoryObservationSession(owner);
  t.after(() => session.close());
  assert.deepEqual(readInventoryWorkerScheduling(owner), { mode: 'default', verified: false });
  await assert.rejects(createInventoryObservationSession(owner, 'linux-background'), {
    code: 'INVENTORY_SCHEDULING_UNAVAILABLE',
  });
  assert.equal(JSON.parse((await session.snapshot(request())).json).profile, 'core');
  await session.close();
  assert.throws(() => readInventoryWorkerScheduling(owner), { code: 'INVENTORY_SCHEDULING_UNAVAILABLE' });
});

test('native priority selection is lower-only, bounded, and targets the validated native thread', async () => {
  for (const name of ['valid', 'negative', 'clamp', 'lowest', 'chunked']) {
    const result = await fixtureResult({ case: name });
    const target = Math.min(19, result.initialNice + 5);
    assert.equal(result.code, null, name);
    assert.deepEqual(result.evidence, {
      mode: 'linux-background',
      workerTid: result.tid,
      beforeNice: result.initialNice,
      afterNice: target,
    });
    assert.ok(result.calls.every(id => id === result.tid));
    assert.deepEqual(result.setCalls, target === result.initialNice ? [] : [{ id: result.tid, value: target }]);
    assert.equal(result.closed, result.opened);
    assert.equal(result.opened, 2);
  }
});

test('unavailable or ambiguous native scheduling fails closed with fixed errors and bounded descriptor reads', async () => {
  for (const name of [
    'nonlinux',
    'empty',
    'missing',
    'duplicate',
    'wrong-group',
    'main-tid',
    'zero',
    'negative-id',
    'leading-zero',
    'overflow',
    'oversize',
    'open-failure',
    'read-failure',
    'bad-nice',
    'nan-nice',
    'changed-tid',
    'set-failure',
    'readback-failure',
    'wrong-policy-readback',
  ]) {
    const result = await fixtureResult({ case: name });
    assert.equal(result.code, 'INVENTORY_SCHEDULING_UNAVAILABLE', name);
    assert.equal(result.message, 'INVENTORY_SCHEDULING_UNAVAILABLE', name);
    assert.equal(result.evidence, null, name);
    assert.equal(result.closed, result.opened - (name === 'open-failure' ? 1 : 0), name);
    assert.ok(result.reads <= 4, name);
    if (!['changed-tid', 'set-failure', 'readback-failure', 'wrong-policy-readback'].includes(name))
      assert.deepEqual(result.setCalls, [], name);
  }
  assert.throws(() => configureInventoryWorkerScheduling('linux-background'), {
    code: 'INVENTORY_SCHEDULING_UNAVAILABLE',
  });
  assert.throws(() => configureInventoryWorkerScheduling('private-invalid'), {
    code: 'INVENTORY_SCHEDULING_UNAVAILABLE',
  });
});

test('HTTP configuration rejects invalid scheduling and accessors before starting an observer', async t => {
  const owner = executor(t),
    base = { executor: owner, observers: [{ token: createInventoryObserverToken(), tenantIds: ['tenant'] }] };
  for (const workerScheduling of [null, 5, {}, 'background'])
    await assert.rejects(startInventoryServer({ ...base, workerScheduling }), {
      code: 'INVENTORY_SERVER_CONFIG_INVALID',
    });
  let called = false;
  await assert.rejects(
    startInventoryServer({
      ...base,
      get workerScheduling() {
        called = true;
        return 'linux-background';
      },
    }),
    { code: 'INVENTORY_SERVER_CONFIG_INVALID' },
  );
  assert.equal(called, false);
  if (process.platform !== 'linux')
    await assert.rejects(startInventoryServer({ ...base, workerScheduling: 'linux-background' }), {
      code: 'INVENTORY_SCHEDULING_UNAVAILABLE',
    });
  const server = await startInventoryServer({ ...base, workerScheduling: 'default' });
  await server.close();
});

test('native Linux worker policy preserves owner and unrelated thread priority, and survives worker replacement', async t => {
  if (process.platform !== 'linux') {
    assert.throws(currentLinuxThreadPriority, { code: 'INVENTORY_SCHEDULING_UNAVAILABLE' });
    return;
  }
  const before = currentLinuxThreadPriority(),
    unrelated = new Worker(fixture, { workerData: { kind: 'actual', mode: 'default' }, execArgv: [], env: {} });
  t.after(() => unrelated.terminate());
  const [otherBefore] = await once(unrelated, 'message');
  const owner = executor(t),
    session = await createInventoryObservationSession(owner, 'linux-background');
  t.after(() => session.close());
  const first = readInventoryWorkerScheduling(owner);
  assert.equal(first.verified, true);
  assert.notEqual(first.workerTid, before.tid);
  assert.notEqual(first.workerTid, otherBefore.after.tid);
  assert.equal(first.afterNice, Math.min(19, first.beforeNice + 5));
  assert.equal(first.currentNice, first.afterNice);
  assert.equal(first.ownerBeforeNice, before.nice);
  assert.equal(first.ownerCurrentNice, before.nice);
  const originalPriority = os.getPriority;
  const prioritySpy = t.mock.method(os, 'getPriority', tid =>
    tid === before.tid ? (before.nice === 19 ? 18 : before.nice + 1) : originalPriority(tid),
  );
  try {
    syncBuiltinESMExports();
    assert.throws(() => readInventoryWorkerScheduling(owner), { code: 'INVENTORY_SCHEDULING_UNAVAILABLE' });
  } finally {
    prioritySpy.mock.restore();
    syncBuiltinESMExports();
  }
  assert.deepEqual(readInventoryWorkerScheduling(owner), first);
  await assert.rejects(createInventoryObservationSession(owner, 'default'), {
    code: 'INVENTORY_SCHEDULING_UNAVAILABLE',
  });
  await session.snapshot(request());
  const original = Worker.prototype.postMessage;
  let onceFailed = false;
  const spy = t.mock.method(Worker.prototype, 'postMessage', function (message, transfer) {
    if (message.type === 'snapshot' && !onceFailed) {
      onceFailed = true;
      throw new Error('test-send-failure');
    }
    return original.call(this, message, transfer);
  });
  await assert.rejects(session.snapshot(request()), { code: 'INVENTORY_UNAVAILABLE' });
  spy.mock.restore();
  await session.snapshot(request());
  const replacement = readInventoryWorkerScheduling(owner);
  assert.equal(replacement.mode, 'linux-background');
  assert.equal(replacement.currentNice, Math.min(19, replacement.beforeNice + 5));
  assert.equal(replacement.ownerCurrentNice, before.nice);
  const otherPending = once(unrelated, 'message');
  unrelated.postMessage('read');
  const [otherAfter] = await otherPending;
  assert.deepEqual(otherAfter, otherBefore.after);
  assert.deepEqual(currentLinuxThreadPriority(), before);
  await session.close();
  const ordinary = await createInventoryObservationSession(owner, 'default');
  await ordinary.close();
});

test('background readiness proof cannot open HTTP before its exact native policy is verified', async t => {
  if (process.platform !== 'linux') {
    const owner = executor(t);
    await assert.rejects(createInventoryObservationSession(owner, 'linux-background'), {
      code: 'INVENTORY_SCHEDULING_UNAVAILABLE',
    });
    return;
  }
  const owner = executor(t),
    emit = Worker.prototype.emit,
    terminate = Worker.prototype.terminate,
    listen = Server.prototype.listen;
  let stopped = 0,
    listened = 0;
  const cleanup = t.mock.method(Worker.prototype, 'terminate', function () {
    return terminate.call(this).then(value => {
      stopped++;
      return value;
    });
  });
  const listener = t.mock.method(Server.prototype, 'listen', function (...args) {
    listened++;
    return listen.apply(this, args);
  });
  for (const change of [
    { workerTid: process.pid },
    { afterNice: -20 },
    { mode: 'default' },
    { beforeNice: 0, afterNice: 10 },
  ]) {
    const spy = t.mock.method(Worker.prototype, 'emit', function (event, ...args) {
      if (event === 'message' && args[0]?.type === 'ready')
        args[0] = { ...args[0], scheduling: { ...args[0].scheduling, ...change } };
      return emit.call(this, event, ...args);
    });
    try {
      await assert.rejects(
        startInventoryServer({
          executor: owner,
          workerScheduling: 'linux-background',
          observers: [{ token: createInventoryObserverToken(), tenantIds: ['tenant'] }],
        }),
        { code: 'INVENTORY_SCHEDULING_UNAVAILABLE' },
      );
    } finally {
      spy.mock.restore();
    }
  }
  assert.equal(listened, 0);
  assert.equal(stopped, 4);
  listener.mock.restore();
  cleanup.mock.restore();
  const OriginalWorker = workerThreads.Worker;
  workerThreads.Worker = class extends OriginalWorker {
    constructor(url, options) {
      super(url, { ...options, workerData: { scheduling: 'invalid-test-policy' } });
    }
  };
  const noListen = t.mock.method(Server.prototype, 'listen', function (...args) {
    listened++;
    return listen.apply(this, args);
  });
  try {
    syncBuiltinESMExports();
    // Actual fixed worker entry throws during its startup policy configuration.
    await assert.rejects(
      startInventoryServer({
        executor: owner,
        workerScheduling: 'linux-background',
        observers: [{ token: createInventoryObserverToken(), tenantIds: ['tenant'] }],
      }),
      { code: 'INVENTORY_SCHEDULING_UNAVAILABLE' },
    );
    assert.equal(listened, 0);
  } finally {
    workerThreads.Worker = OriginalWorker;
    syncBuiltinESMExports();
    noListen.mock.restore();
  }
  const ordinary = await createInventoryObservationSession(owner);
  await ordinary.close();
});

test('an actual rejected +10 native worker cannot satisfy the restored +5 startup contract before HTTP listens', async t => {
  if (process.platform !== 'linux') {
    const result = await fixtureResult({ case: 'wrong-policy-readback' });
    assert.equal(result.initialNice, 0);
    assert.equal(result.nice, 10);
    assert.equal(result.code, 'INVENTORY_SCHEDULING_UNAVAILABLE');
    return;
  }
  const owner = executor(t),
    before = currentLinuxThreadPriority(),
    OriginalWorker = workerThreads.Worker;
  const emit = Worker.prototype.emit,
    terminate = Worker.prototype.terminate,
    listen = Server.prototype.listen;
  let observed,
    nativeNice,
    stopped = 0,
    listened = 0;
  const ready = t.mock.method(Worker.prototype, 'emit', function (event, ...args) {
    if (event === 'message' && args[0]?.type === 'ready') {
      observed = args[0].scheduling;
      nativeNice = os.getPriority(observed.workerTid);
    }
    return emit.call(this, event, ...args);
  });
  const cleanup = t.mock.method(Worker.prototype, 'terminate', function () {
    return terminate.call(this).then(value => {
      stopped++;
      return value;
    });
  });
  const listener = t.mock.method(Server.prototype, 'listen', function (...args) {
    listened++;
    return listen.apply(this, args);
  });
  workerThreads.Worker = class extends OriginalWorker {
    constructor(_url, options) {
      super(fixture, { ...options, workerData: { kind: 'wrong-ten' } });
    }
  };
  try {
    syncBuiltinESMExports();
    const start = () =>
      startInventoryServer({
        executor: owner,
        workerScheduling: 'linux-background',
        observers: [{ token: createInventoryObserverToken(), tenantIds: ['tenant'] }],
      });
    if (Math.min(19, before.nice + 5) !== Math.min(19, before.nice + 10)) {
      await assert.rejects(start(), { code: 'INVENTORY_SCHEDULING_UNAVAILABLE' });
      assert.equal(listened, 0);
      assert.equal(stopped, 1);
    } else {
      // A parent already at nice >=14 yields the same clamped target under both
      // policies. Such valid evidence must not be rejected as distinguishable.
      const server = await start();
      await server.close();
      assert.equal(listened, 1);
      assert.equal(stopped, 1);
    }
    assert.equal(observed.beforeNice, before.nice);
    assert.equal(observed.afterNice, Math.min(19, before.nice + 10));
    assert.equal(nativeNice, observed.afterNice);
    assert.deepEqual(currentLinuxThreadPriority(), before);
    t.diagnostic(
      JSON.stringify({
        rejectedPolicyBeforeNice: observed.beforeNice,
        rejectedPolicyAfterNice: observed.afterNice,
        currentPolicyAfterNice: Math.min(19, observed.beforeNice + 5),
        listened,
        terminated: stopped,
      }),
    );
  } finally {
    workerThreads.Worker = OriginalWorker;
    syncBuiltinESMExports();
    ready.mock.restore();
    cleanup.mock.restore();
    listener.mock.restore();
  }
});
