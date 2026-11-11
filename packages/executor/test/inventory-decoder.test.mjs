import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import {
  LedgerStore,
  decodeLedgerObservation as baseline,
  decodeCoreInventoryObservation as candidate,
} from '../dist/store.js';
import * as publicApi from '../dist/index.js';
import { composeInventorySnapshot } from '../dist/inventory-manifest.js';
import { projectCapturedMcp, finishCapturedMcp } from '../dist/inventory-mcp-capture.js';
import { projectInventory, projectInventoryJson } from '../dist/inventory.js';
const now = 1793980800000;
function fixture() {
  const ledger = {
    schema: 1,
    revision: 1310,
    epoch: 10,
    lastClock: now,
    inventoryInstanceId: '00000000-0000-4000-8000-000000000001',
    tasks: {},
    families: {},
    tools: {},
    actions: {},
    approvals: {},
    memory: {},
    audit: [],
  };
  for (let i = 0; i < 10; i++)
    ledger.tools[`synthetic.read-${i}`] = { fingerprint: 'a'.repeat(64), revision: 1, approved: true };
  for (let i = 0; i < 100; i++) {
    const id = `synthetic-task-${i}`,
      family = `synthetic-family-${i}`;
    ledger.tasks[id] = {
      options: {
        id,
        tenantId: 'synthetic-admission',
        principalId: `synthetic-agent-${i}`,
        grants: Array.from({ length: 10 }, (_, j) => ({
          tool: `synthetic.read-${j}`,
          resources: ['synthetic-record'],
        })),
        budget: { maxCalls: 301, maxConcurrent: 1, maxCost: 0, deadline: now + 3600000 },
        allowedRecipients: [],
      },
      parent: null,
      family,
      tokenHash: 'b'.repeat(64),
      revoked: false,
      calls: i === 0 ? 300 : 0,
      concurrent: 0,
      spent: 0,
      reserved: 0,
    };
    ledger.families[family] = { sensitive: false };
  }
  for (let i = 0; i < 300; i++) {
    const id = `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`;
    ledger.actions[id] = {
      id,
      taskId: 'synthetic-task-0',
      action: {
        tool: 'synthetic.read-0',
        args: { value: i },
        resourceId: 'synthetic-record',
        tenantId: 'synthetic-admission',
        sensitive: false,
        controlPlane: false,
        toolFingerprint: 'a'.repeat(64),
        policyVersion: 10,
      },
      digest: 'sha256:' + 'c'.repeat(64),
      toolRevision: 1,
      requiresApproval: false,
      status: 'SUCCEEDED',
      maxCost: 0,
      charged: 0,
    };
    for (const event of ['ACTION_PREPARED', 'ACTION_ADMITTED', 'ACTION_RUNNING', 'ACTION_SUCCEEDED'])
      ledger.audit.push({ time: now + i, event, taskId: 'synthetic-task-0', actionId: id });
  }

  return ledger;
}

const key = Buffer.alloc(32, 7),
  maximum = 16 * 1024 * 1024;
const source = {
  companyId: 'synthetic-company',
  sourceId: 'synthetic-source',
  enrollmentGeneration: 'synthetic-generation',
};
const scope = { tenantId: 'synthetic-admission' };
const live = new Map(
  Array.from({ length: 10 }, (_, i) => [
    `synthetic.read-${i}`,
    {
      fingerprint: 'a'.repeat(64),
      revision: 1,
      definition: { maxCost: 0, requiresApproval: false, controlPlane: false },
    },
  ]),
);
const seal = (text, witnessed = true) => {
  const iv = crypto.randomBytes(12),
    c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1'));
  const bytes = Buffer.concat([c.update(text), c.final()]);
  return JSON.stringify([iv.toString('base64'), c.getAuthTag().toString('base64'), bytes.toString('base64')]);
};
const wire = (state, referenceKey, selected = scope) =>
  projectInventoryJson(state, live, source, selected, now, referenceKey).json.replace(
    /"snapshotId":"[a-f0-9-]+"/,
    '"snapshotId":"normalized"',
  );
const outcome = fn => {
  try {
    return { ok: true, result: fn() };
  } catch (e) {
    return { ok: false, name: e.name, code: e.code ?? null };
  }
};
function compare(text, selected = scope) {
  const payload = seal(text);
  for (const referenceKey of [undefined, Buffer.alloc(32, 9)]) {
    const a = outcome(() => wire(baseline(payload, key, maximum, true), referenceKey, selected));
    const b = outcome(() => wire(candidate(payload, key, maximum, true), referenceKey, selected));
    assert.deepEqual(b, a);
  }
}
function inspectWipe(fn) {
  const original = crypto.createDecipheriv,
    updates = [],
    events = [];
  crypto.createDecipheriv = function (...args) {
    const c = Reflect.apply(original, this, args),
      u = c.update,
      f = c.final;
    c.update = function (...args) {
      events.push('update');
      const b = Reflect.apply(u, this, args);
      updates.push(b);
      return b;
    };
    c.final = function (...args) {
      events.push('final');
      return Reflect.apply(f, this, args);
    };
    return c;
  };
  syncBuiltinESMExports();
  try {
    fn({ updates, events });
  } finally {
    crypto.createDecipheriv = original;
    syncBuiltinESMExports();
  }
}
const zeroed = b => assert.ok(b.every(x => x === 0));

test('authenticated late-ledger fixture is unchanged; values and fresh observations match while only nested prototypes differ', () => {
  const text = JSON.stringify(fixture());
  assert.equal(Buffer.byteLength(text), 426660);
  assert.equal(
    crypto.createHash('sha256').update(text).digest('hex'),
    '44dfe5b52d6352f86ec2481f84a5a48d65ffe9c3893abb3f062dcd9bf29efe9f',
  );
  const payload = seal(text),
    a = baseline(payload, key, maximum, true),
    b = candidate(payload, key, maximum, true);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.equal(Object.getPrototypeOf(b), null);
  assert.equal(Object.getPrototypeOf(b.tasks), Object.prototype);
  assert.equal(Object.getPrototypeOf(a.tasks), null);
  compare(text);
  b.tasks['synthetic-task-0'].calls = 999;
  assert.equal(candidate(payload, key, maximum, true).tasks['synthetic-task-0'].calls, 300);
  assert.notEqual(candidate(payload, key, maximum, true).tasks, candidate(payload, key, maximum, true).tasks);
});

test('dangerous literal keys, arrays, Unicode, duplicate keys and negative zero preserve canonical projected output', () => {
  const s = fixture();
  s.tasks = Object.create(null);
  s.families = Object.create(null);
  s.tools = Object.create(null);
  for (const [i, id] of ['__proto__', 'constructor', 'prototype', 'toJSON', 'then', '雪😀'].entries()) {
    const t = fixture().tasks['synthetic-task-0'];
    t.options.id = id;
    t.options.principalId = id;
    t.family = id;
    t.options.grants = [{ tool: id, resources: [id, '雪😀\\"'] }];
    t.calls = i;
    t.options.allowedRecipients = [id];
    s.tasks[id] = t;
    s.families[id] = { sensitive: false };
    s.tools[id] = { fingerprint: 'a'.repeat(64), revision: 1, approved: true };
  }
  s.actions = JSON.parse(
    '{"__proto__":{"private":true},"constructor":{"prototype":{"sensitive":true}},"toJSON":[{"value":"unused"}]}',
  );
  let text = JSON.stringify(s).replace('"spent":0', '"spent":-0');
  text = text.slice(0, -1) + ',"revision":1310}';
  compare(text);
  const decoded = candidate(seal(text), key, maximum, true);
  assert.equal(Object.hasOwn(decoded.tasks, '__proto__'), true);
  assert.equal(Object.hasOwn(Object.prototype, 'private'), false);
  assert.equal(Object.is(decoded.tasks.__proto__.spent, -0), true);
  const snap = projectInventory(decoded, live, source, scope, now);
  assert.equal(Object.getPrototypeOf(snap), null);
  assert.ok(Object.isFrozen(snap));
  assert.equal(Object.getPrototypeOf(snap.tasks[0]), null);
  assert.ok(Object.isFrozen(snap.tasks[0].grants));
});

test('cross-tenant completeness, relation checks and malformed state reject identically', () => {
  const s = fixture();
  s.tasks['synthetic-task-99'].options.tenantId = 'foreign';
  s.tasks['synthetic-task-99'].options.principalId = { unvalidated: 'foreign-private' };
  compare(JSON.stringify(s));
  compare(JSON.stringify(fixture()), { tenantId: 'empty' });
  const changes = [
    s => delete s.tasks['synthetic-task-0'].options.tenantId,
    s => (s.tasks['synthetic-task-0'].options.grants[0].resources = ['\ud800']),
    s => (s.tasks['synthetic-task-0'].parent = 'missing'),
    s => (s.tasks['synthetic-task-0'].parent = 'synthetic-task-0'),
    s => delete s.families['synthetic-family-0'].sensitive,
    s => (s.tasks['synthetic-task-0'].options.budget.maxCalls = 1.5),
    s => (s.tools['synthetic.read-0'].fingerprint = 'invalid'),
    s => (s.tasks = []),
    s => (s.families = null),
    s => (s.tasks['synthetic-task-0'].options.grants[0].resources = Array.from({ length: 1025 }, (_, i) => 'r' + i)),
    s => (s.tasks['synthetic-task-0'].options.id = 'x'.repeat(4097)),
  ];
  for (const change of changes) {
    const s = fixture();
    change(s);
    compare(JSON.stringify(s));
  }
});

test('missing own fields never resolve from Object.prototype at root or projected nested records', () => {
  let invoked = 0;
  const old = Object.getOwnPropertyDescriptor(Object.prototype, 'sensitive');
  assert.equal(old, undefined);
  Object.defineProperty(Object.prototype, 'sensitive', {
    configurable: true,
    get() {
      invoked++;
      throw Error('must not call');
    },
  });
  try {
    const s = fixture();
    delete s.families['synthetic-family-0'].sensitive;
    compare(JSON.stringify(s));
    assert.equal(invoked, 0);
  } finally {
    delete Object.prototype.sensitive;
  }
  Object.defineProperty(Object.prototype, 'recoveryMirror', {
    configurable: true,
    get() {
      invoked++;
      throw Error('must not call');
    },
  });
  try {
    const s = candidate(seal(JSON.stringify(fixture())), key, maximum, true);
    assert.equal(s.recoveryMirror, undefined);
    assert.equal(invoked, 0);
  } finally {
    delete Object.prototype.recoveryMirror;
  }
});

test('every fresh decode authenticates and wipes plaintext, including schema/JSON/byte-size failures', () => {
  for (const decode of [baseline, candidate]) {
    for (const witnessed of [false, true]) {
      const text = JSON.stringify(fixture()),
        payload = seal(text, witnessed);
      inspectWipe(({ updates, events }) => {
        decode(payload, key, Buffer.byteLength(text), witnessed);
        assert.deepEqual(events, ['update', 'final']);
        updates.forEach(zeroed);
      });
      inspectWipe(({ updates, events }) => {
        assert.throws(() => decode(payload, key, Buffer.byteLength(text) - 1, witnessed));
        assert.deepEqual(events, ['update', 'final']);
        updates.forEach(zeroed);
      });
    }
    for (const text of [
      '{"schema":1,',
      'null',
      '[]',
      'true',
      '42',
      '"text"',
      JSON.stringify({ ...fixture(), schema: 4 }),
      JSON.stringify({ ...fixture(), revision: 0.25 }),
      JSON.stringify({ ...fixture(), inventoryInstanceId: 'invalid' }),
      JSON.stringify({ ...fixture(), actions: null }),
      JSON.stringify({ ...fixture(), tasks: null }),
    ]) {
      inspectWipe(({ updates, events }) => {
        assert.throws(() => decode(seal(text), key, maximum, true));
        assert.deepEqual(events, ['update', 'final']);
        updates.forEach(zeroed);
      });
    }
  }
});

test('tampered ciphertext/tag/IV, wrong key/AAD and early encoded bounds are unchanged', () => {
  const payload = seal(JSON.stringify(fixture())),
    parts = JSON.parse(payload),
    cases = [];
  for (const i of [0, 1, 2]) {
    const p = [...parts],
      bytes = Buffer.from(p[i], 'base64');
    bytes[0] ^= 1;
    p[i] = bytes.toString('base64');
    cases.push([JSON.stringify(p), key, true]);
  }
  cases.push([payload, Buffer.alloc(32, 8), true], [payload, key, false]);
  for (const decode of [baseline, candidate])
    for (const [p, k, w] of cases)
      inspectWipe(({ updates, events }) => {
        assert.throws(() => decode(p, k, maximum, w));
        assert.deepEqual(events, ['update', 'final']);
        updates.forEach(zeroed);
      });
  const p = [...parts];
  p[2] = 'x'.repeat(2049);
  for (const decode of [baseline, candidate])
    inspectWipe(({ updates, events }) => {
      assert.throws(() => decode(JSON.stringify(p), key, 1024, true));
      assert.deepEqual(events, []);
      assert.deepEqual(updates, []);
    });
});

async function worker(t) {
  const w = new Worker(new URL('../dist/inventory-worker.js', import.meta.url), {
    execArgv: [],
    env: {},
    stdout: true,
    stderr: true,
    workerData: { scheduling: 'default' },
    resourceLimits: { maxOldGenerationSizeMb: 640, maxYoungGenerationSizeMb: 32, stackSizeMb: 4 },
  });
  w.stdout.resume();
  w.stderr.resume();
  t.after(() => w.terminate());
  const [ready] = await once(w, 'message');
  assert.equal(ready.type, 'ready');
  return w;
}
let sequence = 0;
async function observe(w, state, profile = 'core', extra = {}, after = [], capture = {}) {
  const id = ++sequence;
  const message = {
    type: 'snapshot',
    id,
    ledger: {
      payload: seal(JSON.stringify(state), capture.witnessed ?? true),
      key: new Uint8Array(key),
      maxBytes: maximum,
      witnessed: true,
      mirror: false,
      ...capture,
    },
    metadata: { source, registrations: [...live], referenceKey: new Uint8Array(32).fill(9) },
    scope,
    generatedAt: now,
    profile,
    ...extra,
  };
  const waiting = once(w, 'message');
  w.postMessage(message);
  let [result] = await waiting;
  if (result.type === 'mcp-after') {
    const p = once(w, 'message');
    w.postMessage({ type: 'mcp-after', id, after });
    [result] = await p;
  }
  return result;
}
const normal = x => {
  const v = JSON.parse(x);
  v.snapshotId = 'normalized';
  if (v.profile !== 'core') v.generatedAt = 'normalized';
  if (v.mcp) {
    v.mcp.observedAt = 'normalized';
    v.coverage.mcp.observedAt = 'normalized';
  }
  return JSON.stringify(v);
};

test('actual worker preserves authority-derived core/host/MCP bytes and lifecycle errors', async t => {
  const actual = await worker(t);
  const state = fixture(),
    core = projectInventory(
      baseline(seal(JSON.stringify(state)), key, maximum, true),
      live,
      source,
      scope,
      now,
      Buffer.alloc(32, 9),
    );
  const manifest = {
    schemaVersion: 1,
    evidenceKind: 'host_asserted',
    source: core.source,
    manifestId: 'catalog',
    revision: 1,
    observedAt: '2026-11-06T00:00:00Z',
    agents: [{ id: 'agent', name: 'Agent', ownerId: null, teamId: 'team' }],
    deployments: [{ id: 'deployment', agentId: 'agent', environment: 'test' }],
    taskBindings: [{ taskId: 'synthetic-task-0', deploymentId: 'deployment' }],
    executionBindings: [
      {
        id: 'binding',
        deploymentId: 'deployment',
        tool: 'synthetic.read-0',
        connectionId: 'documents',
        identitySelection: 'unknown',
        identity: null,
      },
    ],
    resourceBindings: [],
  };
  const inventory = {
    schemaVersion: 1,
    identity: {
      serverId: 'documents',
      transportRef: `opaque:${'a'.repeat(64)}`,
      principalId: 'operator',
      tenantId: scope.tenantId,
    },
    sessionId: 'session',
    revision: 2,
    authorizationEpoch: 1,
    metadataRevision: 1,
    state: 'ready',
    metadataState: 'current',
    observedAt: '2026-11-06T00:00:00Z',
    operations: [{ name: 'synthetic.read-0', kind: 'tool', fingerprint: 'a'.repeat(64) }],
  };
  const mcpBefore = [{ tenantId: scope.tenantId, connectionId: 'documents', inventory, digest: 'b'.repeat(64) }];
  for (const [profile, changed] of [
    ['core', false],
    ['host', false],
    ['host-mcp', false],
    ['host-mcp', true],
  ]) {
    const extra = profile === 'core' ? {} : { manifest, mcpBefore };
    const after = [{ tenantId: scope.tenantId, connectionId: 'documents', digest: (changed ? 'c' : 'b').repeat(64) }];
    const expected =
      profile === 'core'
        ? projectInventoryJson(
            baseline(seal(JSON.stringify(state)), key, maximum, true),
            live,
            source,
            scope,
            now,
            Buffer.alloc(32, 9),
          ).json
        : JSON.stringify(
            profile === 'host'
              ? composeInventorySnapshot(core, manifest)
              : finishCapturedMcp(
                  projectCapturedMcp(composeInventorySnapshot(core, manifest), mcpBefore),
                  mcpBefore,
                  after,
                ),
          );
    const right = await observe(actual, state, profile, extra, after);
    assert.equal(right.type, 'result');
    assert.equal(normal(right.json), normal(expected));
    assert.equal(right.bytes, Buffer.byteLength(right.json));
    assert.equal(right.sha256, crypto.createHash('sha256').update(right.json).digest('hex'));
    if (changed) assert.equal(JSON.parse(right.json).mcp.connections[0].reason, 'changed');
  }
  for (const mutate of [
    s => (s.schema = 4),
    s => (s.inventoryInstanceId = 'invalid'),
    s => (s.recoveryMirror = 1),
    s => (s.schema = 3),
  ]) {
    const s = fixture();
    mutate(s);
    const right = await observe(actual, s);
    assert.equal(right.type, 'error');
    assert.equal(right.code, 'INVENTORY_UNAVAILABLE');
  }
});

test('actual core-only worker preserves every schema/witness/mirror consistency combination', async t => {
  const actual = await worker(t);
  for (const schema of [1, 2, 3])
    for (const mode of [undefined, 1, 2, null])
      for (const witnessed of [false, true])
        for (const mirror of [false, true]) {
          const s = fixture();
          s.schema = schema;
          if (mode !== undefined) s.recoveryMirror = mode;
          const accepted =
            (mode === undefined && schema !== 3 && !mirror) || (witnessed && mirror && mode === 1 && schema === 3);
          const right = await observe(actual, s, 'core', {}, [], { witnessed, mirror });
          assert.equal(right.type, accepted ? 'result' : 'error', JSON.stringify({ schema, mode, witnessed, mirror }));
          if (accepted) {
            const expected = projectInventoryJson(
              baseline(seal(JSON.stringify(s), witnessed), key, maximum, witnessed),
              live,
              source,
              scope,
              now,
              Buffer.alloc(32, 9),
            );
            assert.equal(normal(right.json), normal(expected.json));
          } else assert.equal(right.code, 'INVENTORY_UNAVAILABLE');
        }
});

test('core decoder stays absent from the public index and never changes authority read prototypes', () => {
  assert.equal(Object.hasOwn(publicApi, 'decodeCoreInventoryObservation'), false);
  const store = new LedgerStore(':memory:', key);
  try {
    store.transaction(state => {
      state.memory.fixture = [
        {
          id: 'memory',
          tenantId: scope.tenantId,
          origin: 'fixture',
          sensitive: false,
          trusted: false,
          version: 1,
          parentIds: [],
          quarantined: false,
          value: JSON.parse('{"__proto__":{"literal":true},"nested":[{"value":7}]}'),
        },
      ];
    });
    const first = store.read(),
      second = store.read();
    for (const state of [first, second]) {
      assert.equal(Object.getPrototypeOf(state), null);
      assert.equal(Object.getPrototypeOf(state.tasks), null);
      assert.equal(Object.getPrototypeOf(state.actions), null);
      assert.equal(Object.getPrototypeOf(state.memory.fixture[0]), null);
      assert.equal(Object.getPrototypeOf(state.memory.fixture[0].value.nested[0]), null);
      assert.equal(Object.hasOwn(state.memory.fixture[0].value, '__proto__'), true);
    }
    first.memory.fixture[0].value.nested[0].value = 99;
    assert.equal(second.memory.fixture[0].value.nested[0].value, 7);
    assert.equal(store.read().memory.fixture[0].value.nested[0].value, 7);
  } finally {
    store.close();
  }
});
