import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createCipheriv } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, mkdirSync, rmSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DurableExecutor } from '../dist/index.js';
import { composeInventorySnapshot, composeMcpInventorySnapshot } from '../dist/entry-inventory.js';
import {
  createInventoryObservationSession,
  bindLedgerObservation,
  bindExecutorObservation,
} from '../dist/inventory-observer.js';
import { LedgerStore } from '../dist/store.js';
import { captureInventoryRegistrations } from '../dist/inventory.js';
import { captureMcpBefore, captureMcpAfter } from '../dist/inventory-mcp-capture.js';

const enrollment = { companyId: 'company', sourceId: 'installation', enrollmentGeneration: 'generation' };
const definition = {
  name: 'read',
  description: 'private-description',
  maxCost: 0,
  requiresApproval: false,
  resolve: () => ({ resourceId: 'resource', tenantId: 'alpha' }),
  execute: () => ({ value: null }),
};
function setup(t, options = {}) {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    inventory: enrollment,
    ...options,
  });
  const fingerprint = executor.registerTool(definition);
  executor.approveTool('read', fingerprint);
  for (const tenantId of ['alpha', 'beta'])
    executor.createTask({
      id: tenantId,
      tenantId,
      principalId: `principal-${tenantId}`,
      grants: [{ tool: 'read', resources: [`private-resource-${tenantId}`] }],
      budget: { maxCalls: 20, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000 },
    });
  t.after(() => executor.close());
  return { executor, fingerprint };
}
async function session(t, executor) {
  const value = await createInventoryObservationSession(executor);
  t.after(() => value.close());
  return value;
}
const request = (extra = {}) => ({
  scope: { tenantId: 'alpha' },
  profile: 'core',
  signal: new AbortController().signal,
  deadline: performance.now() + 10_000,
  ...extra,
});
const plain = value => JSON.parse(JSON.stringify(value));
function normalize(value) {
  const copy = plain(value);
  delete copy.snapshotId;
  delete copy.generatedAt;
  if (copy.mcp) delete copy.mcp.observedAt;
  for (const item of Object.values(copy.coverage)) delete item.observedAt;
  return copy;
}
function manifest(core) {
  return {
    schemaVersion: 1,
    evidenceKind: 'host_asserted',
    source: core.source,
    manifestId: 'catalog',
    revision: 1,
    observedAt: '2026-10-30T00:00:00Z',
    agents: [{ id: 'agent', name: 'Agent', ownerId: null, teamId: 'team' }],
    deployments: [{ id: 'deployment', agentId: 'agent', environment: 'test' }],
    taskBindings: [{ taskId: 'alpha', deploymentId: 'deployment' }],
    executionBindings: [
      {
        id: 'binding',
        deploymentId: 'deployment',
        tool: 'read',
        connectionId: 'documents',
        identitySelection: 'unknown',
        identity: null,
      },
    ],
    resourceBindings: [],
  };
}
function mcp(fingerprint) {
  return {
    schemaVersion: 1,
    identity: {
      serverId: 'documents',
      transportRef: `opaque:${'a'.repeat(64)}`,
      principalId: 'operator',
      tenantId: 'alpha',
    },
    sessionId: 'session',
    revision: 2,
    authorizationEpoch: 1,
    metadataRevision: 1,
    state: 'ready',
    metadataState: 'current',
    observedAt: '2026-10-30T00:00:00Z',
    operations: [{ name: 'read', kind: 'tool', fingerprint: fingerprint.slice(7) }],
  };
}

test('worker projections preserve opaque/raw tenant output and capture fresh state on each dispatch', async t => {
  for (const referenceMode of ['opaque', 'raw']) {
    const { executor } = setup(t, { inventory: { ...enrollment, referenceMode } }),
      observer = await session(t, executor);
    const before = executor.inventorySnapshot({ tenantId: 'alpha' });
    const pending = observer.snapshot(request());
    executor.revokeTask('alpha');
    const changedFingerprint = executor.registerTool({ ...definition, requiresApproval: true });
    executor.approveTool('read', changedFingerprint);
    const serialized = await pending;
    assert.equal(serialized.bytes, Buffer.byteLength(serialized.json));
    const captured = JSON.parse(serialized.json),
      next = JSON.parse((await observer.snapshot(request())).json);
    assert.deepEqual(normalize(captured), normalize(before));
    assert.equal(captured.tasks[0].revoked, false);
    // The worker's direct JSON must preserve the synchronous canonical key order,
    // not merely parse into an equivalent object. Only per-snapshot IDs/time vary.
    assert.equal(JSON.stringify(normalize(captured)), JSON.stringify(normalize(before)));
    assert.equal(next.tasks[0].revoked, true);
    assert.ok(next.ledgerRevision > captured.ledgerRevision);
    assert.equal(JSON.stringify(next).includes('beta'), false);
    assert.equal(next.tools[0].registered, true);
    assert.equal(next.tools[0].approved, true);
    assert.equal(captured.tools[0].requiresApproval, false);
    assert.equal(next.tools[0].requiresApproval, true);
    assert.ok(next.tools[0].revision > captured.tools[0].revision);
    assert.equal(next.tasks[0].grants[0].resources[0].startsWith('opaque:'), referenceMode === 'opaque');
  }
});

test('one worker is shared; closing one observer preserves another, and last close waits before replacement', async t => {
  const { executor } = setup(t),
    first = await session(t, executor),
    second = await session(t, executor);
  await first.close();
  assert.equal(JSON.parse((await second.snapshot(request())).json).tasks.length, 1);
  const terminate = Worker.prototype.terminate,
    on = Worker.prototype.on;
  let release,
    terminating = false,
    replacementReady = false;
  let replacementListeners = 0;
  const listenerSpy = t.mock.method(Worker.prototype, 'on', function (event, handler) {
    if (event === 'message') replacementListeners++;
    return on.call(this, event, handler);
  });
  const barrier = new Promise(resolve => {
    release = resolve;
  });
  const spy = t.mock.method(Worker.prototype, 'terminate', function () {
    terminating = true;
    const ended = terminate.call(this);
    return ended.then(async code => {
      await barrier;
      return code;
    });
  });
  const closing = second.close();
  assert.equal(terminating, true);
  const replacement = createInventoryObservationSession(executor).then(value => {
    replacementReady = true;
    return value;
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(replacementReady, false);
  assert.equal(replacementListeners, 0);
  release();
  await closing;
  spy.mock.restore();
  const third = await replacement;
  t.after(() => third.close());
  assert.equal(replacementListeners, 1);
  listenerSpy.mock.restore();
  assert.equal(JSON.parse((await third.snapshot(request())).json).tasks.length, 1);
});

test('failed worker termination permanently refuses replacement sessions for that executor', async t => {
  const { executor } = setup(t),
    observer = await createInventoryObservationSession(executor);
  const terminate = Worker.prototype.terminate,
    on = Worker.prototype.on;
  let heldWorker,
    replacementListeners = 0;
  const listenerSpy = t.mock.method(Worker.prototype, 'on', function (event, handler) {
    if (event === 'message') replacementListeners++;
    return on.call(this, event, handler);
  });
  const spy = t.mock.method(Worker.prototype, 'terminate', function () {
    heldWorker = this;
    return Promise.reject(new Error('private-shutdown-failure'));
  });
  try {
    await assert.rejects(observer.close(), { code: 'INVENTORY_UNAVAILABLE', message: 'INVENTORY_UNAVAILABLE' });
    spy.mock.restore();
    for (let attempt = 0; attempt < 2; attempt++)
      await assert.rejects(createInventoryObservationSession(executor), { code: 'INVENTORY_UNAVAILABLE' });
    assert.equal(replacementListeners, 0);
  } finally {
    spy.mock.restore();
    listenerSpy.mock.restore();
    // The injected termination failure deliberately leaves the real worker alive.
    // Explicit test cleanup does not change the pool's failed-closed decision.
    if (heldWorker) await terminate.call(heldWorker);
  }
});

test('abort retains the worker slot until exit and queued jobs capture later fresh revisions', async t => {
  const { executor } = setup(t),
    observer = await session(t, executor),
    controller = new AbortController();
  const terminate = Worker.prototype.terminate;
  let release;
  const barrier = new Promise(resolve => {
    release = resolve;
  });
  const spy = t.mock.method(Worker.prototype, 'terminate', function () {
    return terminate.call(this).then(async code => {
      await barrier;
      return code;
    });
  });
  const active = observer.snapshot(request({ signal: controller.signal }));
  const rejected = assert.rejects(active, { code: 'REQUEST_TIMEOUT' });
  controller.abort();
  const queued = Array.from({ length: 3 }, () => observer.snapshot(request()));
  await assert.rejects(observer.snapshot(request()), { code: 'INVENTORY_BUSY' });
  executor.revokeTask('alpha');
  release();
  spy.mock.restore();
  await rejected;
  for (const pending of queued) assert.equal(JSON.parse((await pending).json).tasks[0].revoked, true);
});

test('postMessage and worker failures expose only generic codes and allow a clean later worker', async t => {
  const { executor } = setup(t),
    observer = await session(t, executor),
    original = Worker.prototype.postMessage;
  for (const mode of ['send', 'worker']) {
    let injected = false;
    const spy = t.mock.method(Worker.prototype, 'postMessage', function (message, transfer) {
      if (!injected && message.type === 'snapshot') {
        injected = true;
        if (mode === 'send') throw new Error('private-worker-secret');
        const result = original.call(this, message, transfer);
        this.emit('error', new Error('private-worker-secret'));
        return result;
      }
      return original.call(this, message, transfer);
    });
    await assert.rejects(observer.snapshot(request()), {
      code: 'INVENTORY_UNAVAILABLE',
      message: 'INVENTORY_UNAVAILABLE',
    });
    spy.mock.restore();
    assert.equal(JSON.parse((await observer.snapshot(request())).json).profile, 'core');
  }
});

test('worker startup fails closed and verified cleanup runs before the observer is returned', async t => {
  const { executor } = setup(t),
    on = Worker.prototype.on,
    terminate = Worker.prototype.terminate;
  let stopped = 0;
  const closing = t.mock.method(Worker.prototype, 'terminate', function () {
    return terminate.call(this).then(code => {
      stopped++;
      return code;
    });
  });
  const spy = t.mock.method(Worker.prototype, 'on', function (event, handler) {
    const result = on.call(this, event, handler);
    if (event === 'message') process.nextTick(() => handler({ type: 'invalid-private-worker-message' }));
    return result;
  });
  await assert.rejects(createInventoryObservationSession(executor), { code: 'INVENTORY_UNAVAILABLE' });
  assert.equal(stopped, 1);
  spy.mock.restore();
  closing.mock.restore();
  const observer = await session(t, executor);
  assert.equal(JSON.parse((await observer.snapshot(request())).json).profile, 'core');
});

test('closing the executor rejects captured pending output and later observations', async t => {
  const { executor } = setup(t),
    observer = await session(t, executor);
  const pending = observer.snapshot(request());
  const denied = assert.rejects(pending, { code: 'INVENTORY_UNAVAILABLE' });
  executor.close();
  await denied;
  await observer.close();
  await assert.rejects(observer.snapshot(request()), { code: 'INVENTORY_UNAVAILABLE' });
});

test('tool captures reject descriptors without running them and preserve large unrelated host registries', () => {
  let called = false;
  const invalid = new Map([
    [
      'read',
      {
        fingerprint: 'a'.repeat(64),
        revision: 1,
        definition: {
          get requiresApproval() {
            called = true;
            return false;
          },
        },
      },
    ],
  ]);
  assert.throws(() => captureInventoryRegistrations(invalid, 16 * 1024 * 1024), { code: 'INVENTORY_STATE_INVALID' });
  assert.equal(called, false);
  const live = new Map(
    Array.from({ length: 10_001 }, (_, index) => [
      `tool-${index}`,
      {
        fingerprint: 'a'.repeat(64),
        revision: 1,
        definition: {
          maxCost: 0,
          requiresApproval: false,
          controlPlane: false,
          execute: () => {},
          description: 'private-description',
        },
      },
    ]),
  );
  const captured = captureInventoryRegistrations(live, 16 * 1024 * 1024);
  assert.equal(captured.length, 10_001);
  assert.equal(JSON.stringify(captured).includes('private-description'), false);
  assert.deepEqual(Object.keys(captured[0][1].definition).sort(), ['controlPlane', 'maxCost', 'requiresApproval']);
});

test('MCP live second capture brackets worker projection and observes omitted-operation changes', async t => {
  const { executor, fingerprint } = setup(t),
    observer = await session(t, executor),
    inventory = mcp(fingerprint);
  inventory.operations.push({ name: 'unselected', kind: 'tool', fingerprint: 'b'.repeat(64) });
  const host = manifest(executor.inventorySnapshot({ tenantId: 'alpha' }));
  let captures = 0,
    snapshotSent = false;
  const sources = [
    {
      tenantId: 'alpha',
      connectionId: 'documents',
      source: {
        inventory() {
          captures++;
          if (captures === 2) assert.equal(snapshotSent, true);
          return inventory;
        },
      },
    },
  ];
  const original = Worker.prototype.postMessage;
  const spy = t.mock.method(Worker.prototype, 'postMessage', function (message, transfer) {
    const result = original.call(this, message, transfer);
    if (message.type === 'snapshot') {
      snapshotSent = true;
      inventory.operations[1].fingerprint = 'c'.repeat(64);
    }
    return result;
  });
  const result = JSON.parse(
    (await observer.snapshot(request({ profile: 'host-mcp', manifest: host, mcpSources: sources }))).json,
  );
  spy.mock.restore();
  assert.equal(captures, 2);
  assert.equal(result.mcp.connections[0].reason, 'changed');
  assert.equal(result.coverage.mcp.status, 'unavailable');
  assert.equal(JSON.stringify(result).includes('unselected'), false);
});

test('MCP transfer omits large unselected metadata but retains full lifecycle digest and aggregate cap', () => {
  const fingerprint = `sha256:${'a'.repeat(64)}`,
    inventory = mcp(fingerprint);
  for (let index = 0; index < 120; index++)
    inventory.operations.push({
      name: `unselected-${index}-${'x'.repeat(4000)}`,
      kind: 'tool',
      fingerprint: 'b'.repeat(64),
    });
  const host = { source: { tenantId: 'alpha' }, executionBindings: [{ connectionId: 'documents', tool: 'read' }] };
  const sources = [{ tenantId: 'alpha', connectionId: 'documents', source: { inventory: () => inventory } }];
  const before = captureMcpBefore(host, sources),
    after = captureMcpAfter(host, sources);
  assert.equal(before[0].inventory.operations.length, 1);
  assert.ok(Buffer.byteLength(JSON.stringify(before)) < 2048);
  assert.equal(before[0].digest, after[0].digest);
  inventory.operations[1].fingerprint = 'c'.repeat(64);
  assert.notEqual(before[0].digest, captureMcpAfter(host, sources)[0].digest);
  const many = [],
    bindings = [];
  for (let connection = 0; connection < 40; connection++) {
    const copy = structuredClone(inventory);
    copy.operations = Array.from({ length: 256 }, (_, index) => ({
      name: `op-${index}`,
      kind: 'tool',
      fingerprint: 'b'.repeat(64),
    }));
    many.push({ tenantId: 'alpha', connectionId: `connection-${connection}`, source: { inventory: () => copy } });
    bindings.push(
      ...copy.operations.map(operation => ({ connectionId: `connection-${connection}`, tool: operation.name })),
    );
  }
  assert.throws(() => captureMcpBefore({ source: host.source, executionBindings: bindings }, many), {
    code: 'INVENTORY_MCP_LIMIT_EXCEEDED',
  });
});

test('MCP aggregate byte overflow stops incremental capture before any worker dispatch', async t => {
  const { executor, fingerprint } = setup(t),
    observer = await session(t, executor);
  const host = manifest(executor.inventorySnapshot({ tenantId: 'alpha' })),
    sources = [];
  host.executionBindings = [];
  let captures = 0,
    dispatches = 0;
  // Each source is below the existing 2 MiB input cap; all 2,560 operations
  // are below the 10,000 count cap. Their selected bytes exceed 8 MiB.
  for (let connection = 0; connection < 10; connection++) {
    const inventory = mcp(fingerprint);
    inventory.operations = Array.from({ length: 256 }, (_, index) => ({
      name: `operation-${index}-${'x'.repeat(4000)}`,
      kind: 'tool',
      fingerprint: 'a'.repeat(64),
    }));
    const connectionId = `connection-${connection}`;
    sources.push({
      tenantId: 'alpha',
      connectionId,
      source: {
        inventory() {
          captures++;
          return inventory;
        },
      },
    });
    host.executionBindings.push(
      ...inventory.operations.map((operation, index) => ({
        id: `${connectionId}-${index}`,
        deploymentId: 'deployment',
        tool: operation.name,
        connectionId,
        identitySelection: 'unknown',
        identity: null,
      })),
    );
  }
  const post = Worker.prototype.postMessage;
  const spy = t.mock.method(Worker.prototype, 'postMessage', function (message, transfer) {
    if (message.type === 'snapshot') dispatches++;
    return post.call(this, message, transfer);
  });
  await assert.rejects(observer.snapshot(request({ profile: 'host-mcp', manifest: host, mcpSources: sources })), {
    code: 'INVENTORY_MCP_LIMIT_EXCEEDED',
  });
  assert.ok(captures > 1 && captures < sources.length);
  assert.equal(dispatches, 0);
  spy.mock.restore();
  assert.equal(JSON.parse((await observer.snapshot(request())).json).tasks.length, 1);
});

test('worker host and MCP composition match synchronous scoped projection', async t => {
  const { executor, fingerprint } = setup(t),
    observer = await session(t, executor);
  const core = executor.inventorySnapshot({ tenantId: 'alpha' }),
    host = manifest(core);
  const sources = [{ tenantId: 'alpha', connectionId: 'documents', source: { inventory: () => mcp(fingerprint) } }];
  const expectedHost = composeInventorySnapshot(core, host),
    expectedMcp = composeMcpInventorySnapshot(expectedHost, sources);
  for (const [profile, expected] of [
    ['host', expectedHost],
    ['host-mcp', expectedMcp],
  ]) {
    const actual = JSON.parse(
      (await observer.snapshot(request({ profile, manifest: host, mcpSources: sources }))).json,
    );
    assert.deepEqual(normalize(actual), normalize(expected));
    assert.equal(JSON.stringify(actual).includes('beta'), false);
  }
});

test(
  'fresh owner-thread witness and mirror integrity checks precede worker dispatch',
  { skip: process.platform === 'win32' },
  async t => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'guard-inventory-worker-')));
    for (const name of ['data', 'witness']) mkdirSync(join(root, name), { mode: 0o700 });
    const { executor } = setup(t, {
      database: join(root, 'data', 'ledger.sqlite'),
      rollbackWitness: { path: join(root, 'witness', 'witness.sqlite'), mode: 'create', recovery: 'mirror' },
    });
    const observer = await session(t, executor),
      prepare = DatabaseSync.prototype.prepare,
      post = Worker.prototype.postMessage;
    let dispatches = 0;
    const postSpy = t.mock.method(Worker.prototype, 'postMessage', function (message, transfer) {
      if (message.type === 'snapshot') dispatches++;
      return post.call(this, message, transfer);
    });
    try {
      for (const table of ['authority.ledger', 'main.commitment', 'main.ledger']) {
        const spy = t.mock.method(DatabaseSync.prototype, 'prepare', function (sql) {
          const statement = prepare.call(this, sql);
          if (!sql.startsWith('SELECT ') || !sql.includes(`FROM ${table} `)) return statement;
          return {
            get(...args) {
              const row = statement.get(...args);
              return table.endsWith('commitment')
                ? { ...row, digest: '0'.repeat(64) }
                : { ...row, payload: 'private-corrupt-payload' };
            },
          };
        });
        await assert.rejects(observer.snapshot(request()), {
          code: 'INVENTORY_UNAVAILABLE',
          message: 'INVENTORY_UNAVAILABLE',
        });
        spy.mock.restore();
        assert.equal(dispatches, 0);
      }
      assert.equal(JSON.parse((await observer.snapshot(request())).json).tasks.length, 1);
      assert.equal(dispatches, 1);
    } finally {
      postSpy.mock.restore();
      await observer.close();
      executor.close();
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test('worker authenticates ciphertext and rejects schema or unverified mirror semantics', async t => {
  const key = randomBytes(32),
    store = new LedgerStore(':memory:', key),
    initial = store.read();
  const executor = {},
    ledger = {};
  let captured = { state: initial, witnessed: false, mirror: false, corrupt: false };
  bindLedgerObservation(ledger, 16 * 1024 * 1024, () => {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(captured.witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1'));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(captured.state)), cipher.final()]),
      tag = cipher.getAuthTag();
    if (captured.corrupt) tag[0] ^= 1;
    return {
      payload: JSON.stringify([iv.toString('base64'), tag.toString('base64'), ciphertext.toString('base64')]),
      key: new Uint8Array(key),
      maxBytes: 16 * 1024 * 1024,
      witnessed: captured.witnessed,
      mirror: captured.mirror,
    };
  });
  bindExecutorObservation(executor, ledger, () => ({ source: enrollment, registrations: [], referenceKey: undefined }));
  const observer = await session(t, executor);
  t.after(() => {
    store.close();
    key.fill(0);
  });
  assert.equal(JSON.parse((await observer.snapshot(request())).json).tasks.length, 0);
  for (const change of [
    { corrupt: true },
    { state: { ...initial, schema: 999 } },
    { state: { ...initial, schema: 3, recoveryMirror: 1 } },
    { state: { ...initial, schema: 3, recoveryMirror: 1 }, witnessed: true, mirror: false },
  ]) {
    captured = { state: initial, witnessed: false, mirror: false, corrupt: false, ...change };
    await assert.rejects(observer.snapshot(request()), {
      code: 'INVENTORY_UNAVAILABLE',
      message: 'INVENTORY_UNAVAILABLE',
    });
  }
  captured = { state: initial, witnessed: false, mirror: false, corrupt: false };
  assert.equal(JSON.parse((await observer.snapshot(request())).json).profile, 'core');
});

test('serialized worker replies must match request scope, identity and exact body integrity', async t => {
  const { executor } = setup(t),
    observer = await session(t, executor),
    emit = Worker.prototype.emit;
  for (const change of [{ tenantId: 'beta' }, { sourceId: 'foreign' }, { sha256: '0'.repeat(64) }, { bytes: -1 }]) {
    let injected = false;
    const spy = t.mock.method(Worker.prototype, 'emit', function (event, ...args) {
      if (event === 'message' && args[0]?.type === 'result') {
        args[0] = { ...args[0], ...change };
        injected = true;
      }
      return emit.call(this, event, ...args);
    });
    await assert.rejects(observer.snapshot(request()), {
      code: 'INVENTORY_UNAVAILABLE',
      message: 'INVENTORY_UNAVAILABLE',
    });
    assert.equal(injected, true);
    spy.mock.restore();
    assert.equal(JSON.parse((await observer.snapshot(request())).json).source.tenantId, 'alpha');
  }
});

test('moderate private ledger state stays observable without serializing its private values', async t => {
  const { executor } = setup(t);
  // Private memory is part of the authenticated snapshot, but never part of observation output.
  for (let index = 0; index < 32; index++)
    executor.importMemory({
      tenantId: 'alpha',
      id: `private-${index}`,
      value: 'private-memory-canary'.repeat(2500),
      origin: 'host',
    });
  const observer = await session(t, executor),
    result = await observer.snapshot(request());
  assert.equal(JSON.parse(result.json).tasks.length, 1);
  assert.equal(result.json.includes('private-memory-canary'), false);
});

test('private capture transfers exact detached key buffers and uses the current key after offline rotation', async t => {
  const firstKey = randomBytes(32),
    nextKey = randomBytes(32),
    referenceKey = randomBytes(32);
  const ledger = new LedgerStore(':memory:', firstKey),
    owner = {};
  bindExecutorObservation(owner, ledger, () => ({
    source: enrollment,
    registrations: [],
    referenceKey: new Uint8Array(referenceKey),
  }));
  const post = Worker.prototype.postMessage;
  let expectedKey = firstKey,
    dispatches = 0;
  const spy = t.mock.method(Worker.prototype, 'postMessage', function (message, transfer) {
    if (message.type !== 'snapshot') return post.call(this, message, transfer);
    dispatches++;
    for (const key of [message.ledger.key, message.metadata.referenceKey]) {
      assert.equal(key.byteOffset, 0);
      assert.equal(key.byteLength, 32);
      assert.equal(key.buffer.byteLength, 32);
      assert.ok(transfer.includes(key.buffer));
    }
    assert.equal(Buffer.from(message.ledger.key).equals(expectedKey), true);
    assert.equal(Buffer.from(message.metadata.referenceKey).equals(referenceKey), true);
    const result = post.call(this, message, transfer);
    assert.equal(message.ledger.key.byteLength, 0);
    assert.equal(message.metadata.referenceKey.byteLength, 0);
    return result;
  });
  let observer;
  try {
    observer = await createInventoryObservationSession(owner);
    const before = JSON.parse((await observer.snapshot(request())).json);
    await observer.close();
    ledger.rotateEncryptionKey(nextKey);
    expectedKey = nextKey;
    observer = await createInventoryObservationSession(owner);
    const after = JSON.parse((await observer.snapshot(request())).json);
    assert.deepEqual(normalize(after), normalize(before));
    assert.equal(dispatches, 2);
  } finally {
    spy.mock.restore();
    await observer?.close();
    ledger.close();
    firstKey.fill(0);
    nextKey.fill(0);
    referenceKey.fill(0);
  }
});
