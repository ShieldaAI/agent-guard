import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { projectInventory, validateInventorySource } from '../dist/inventory.js';

const source = { companyId: 'company', sourceId: 'executor', enrollmentGeneration: 'enrollment' };
const scope = { tenantId: 'tenant' };
const time = Date.UTC(2026, 9, 29);
const fingerprint = 'a'.repeat(64);
const rawTask = (id = 'task', tenantId = 'tenant') => ({
  options: { id, tenantId, principalId: 'principal', grants: [{ tool: 'read', resources: ['item'] }],
    budget: { maxCalls: 4, maxConcurrent: 2, maxCost: 9, deadline: time + 0.25 } },
  parent: null, family: 'family', revoked: false, tokenHash: 'private hash',
  calls: 1, concurrent: 0, spent: 2, reserved: 0,
});
const ledger = () => ({
  schema: 1, revision: 7, epoch: 2, lastClock: time,
  inventoryInstanceId: '00000000-0000-4000-8000-000000000001',
  tasks: { task: rawTask() }, families: { family: { sensitive: true } },
  tools: { read: { fingerprint, revision: 3, approved: true } },
  actions: {}, approvals: {}, memory: {}, audit: [],
});
const project = (state, registrations = new Map(), selected = scope, key) =>
  projectInventory(state, registrations, source, selected, time, key);
const plain = value => JSON.parse(JSON.stringify(value));

test('projection copies only allowed fields and normalizes grants without evaluating implementations', () => {
  const state = ledger();
  const task = state.tasks.task;
  task.options.grants = [
    { tool: 'read', resources: ['z', 'item', 'item'] },
    { tool: 'unknown', resources: [] },
    { tool: 'read', resources: ['a', 'z'] },
  ];
  task.options.allowedRecipients = ['team:b', 'team:a', 'team:a'];
  task.options.extra = 'private task option';
  state.actions = { private: { args: 'private args', result: 'private result' } };
  state.memory = { private: ['private memory'] };
  let callbacks = 0;
  const forbidden = () => { callbacks++; throw new Error('callback'); };
  const definition = { name: 'read', description: 'private description', inputSchema: { private: 'schema' },
    metadata: { private: 'metadata' }, resolve: forbidden, execute: forbidden, parse: forbidden,
    requiresApproval: true, controlPlane: true, maxCost: 5 };
  Object.defineProperty(definition, 'unrelated', { get: forbidden });
  const before = JSON.stringify(state);
  const result = project(state, new Map([['read', { fingerprint, revision: 3, definition }]]));
  assert.equal(callbacks, 0);
  assert.equal(JSON.stringify(state), before);
  assert.deepEqual(plain(result.tasks[0].grants), [
    { tool: 'read', resources: ['a', 'item', 'z'] }, { tool: 'unknown', resources: [] },
  ]);
  assert.deepEqual([...result.tasks[0].allowedRecipients], ['team:a', 'team:b']);
  assert.equal(result.tasks[0].budget.deadline, time + 0.25);
  assert.deepEqual(plain(result.tools), [{ name: 'read', fingerprint, revision: 3, registered: true,
    approved: true, requiresApproval: true, controlPlane: true, maxCost: 5 }]);
  assert.equal(JSON.stringify(result).includes('private'), false);
  assert.equal(Object.isFrozen(result.tasks[0].grants[0].resources), true);
  assert.throws(() => { result.tasks[0].usage.calls = 999; }, TypeError);
  state.tasks.task.calls = 100;
  assert.equal(result.tasks[0].usage.calls, 1);
});

test('projection includes expired and revoked tasks but excludes another tenant and unrelated tools', () => {
  const state = ledger();
  state.tasks.task.revoked = true;
  state.tasks.task.options.budget.deadline = 0;
  state.tasks.other = rawTask('other', 'other-tenant');
  state.tasks.other.options.grants = [{ tool: 'private-other-tool', resources: ['other-resource'] }];
  state.tools['private-other-tool'] = { fingerprint, revision: 1, approved: true };
  state.tools.unused = { fingerprint, revision: 1, approved: true };
  const result = project(state);
  assert.deepEqual(result.tasks.map(task => task.id), ['task']);
  assert.equal(result.tasks[0].revoked, true);
  assert.equal(result.tasks[0].budget.deadline, 0);
  assert.deepEqual(result.tools.map(tool => tool.name), ['read']);
  assert.equal(JSON.stringify(result).includes('other'), false);
  const empty = project(state, new Map(), { tenantId: 'empty-tenant' });
  assert.deepEqual([...empty.tasks], []);
  assert.deepEqual([...empty.tools], []);
  assert.equal(empty.coverage.tasks.status, 'complete');
});

test('live metadata availability requires matching persisted fingerprint and revision', () => {
  const native = ledger(); native.tools.read.fingerprint = `sha256:${fingerprint}`;
  const normalized = project(native, new Map([['read', { fingerprint: `sha256:${fingerprint}`, revision: 3, definition: {} }]]));
  assert.equal(normalized.tools[0].fingerprint, fingerprint);
  assert.equal(normalized.tools[0].registered, true);
  for (const registration of [undefined, { fingerprint, revision: 2, definition: {} },
    { fingerprint: 'b'.repeat(64), revision: 3, definition: {} }]) {
    const result = project(ledger(), new Map(registration ? [['read', registration]] : []));
    assert.deepEqual(plain(result.tools[0]), { name: 'read', fingerprint, revision: 3, registered: false,
      approved: true, requiresApproval: null, controlPlane: null, maxCost: null });
  }
  let invoked = false;
  const definition = {};
  Object.defineProperty(definition, 'requiresApproval', { get() { invoked = true; return true; } });
  assert.throws(() => project(ledger(), new Map([['read', { fingerprint, revision: 3, definition }]])),
    { code: 'INVENTORY_STATE_INVALID' });
  assert.equal(invoked, false);
});

test('opaque references are stable, tenant scoped and domain separated, preserving the wildcard selector', () => {
  const state = ledger();
  state.tasks.task.options.grants[0].resources = ['*', 'https://user:password@host/resource?token=secret'];
  state.tasks.task.options.allowedRecipients = ['https://user:password@host/resource?token=secret'];
  const key = Buffer.alloc(32, 4);
  const first = project(state, new Map(), scope, key);
  const second = project(state, new Map(), scope, key);
  assert.deepEqual(first.tasks[0].grants, second.tasks[0].grants);
  assert.equal(first.tasks[0].grants[0].resources[0], '*');
  const opaque = first.tasks[0].grants[0].resources[1];
  assert.match(opaque, /^opaque:[a-f0-9]{64}$/);
  assert.notEqual(opaque, first.tasks[0].allowedRecipients[0]);
  assert.equal(JSON.stringify(first).includes('password'), false);
  assert.equal(JSON.stringify(first).includes('secret'), false);
  state.tasks.task.options.tenantId = 'other';
  assert.notEqual(project(state, new Map(), { tenantId: 'other' }, key).tasks[0].grants[0].resources[1], opaque);
});

test('repeated opaque references preserve every value beyond the cache bound and across scope changes', () => {
  const state = ledger();
  const many = ['shared', ...Array.from({ length: 1023 }, (_, index) => `resource-${index}`)];
  state.tasks = { alpha: rawTask('alpha'), beta: rawTask('beta'), gamma: rawTask('gamma') };
  state.tasks.alpha.options.grants[0].resources = many;
  for (const name of ['beta', 'gamma']) {
    state.tasks[name].options.grants[0].resources = ['shared', 'overflow', '*'];
    state.tasks[name].options.allowedRecipients = ['shared', '*'];
  }
  const expected = (key, tenantId, kind, value) => key === undefined || (kind === 'resource' && value === '*') ? value :
    `opaque:${createHmac('sha256', key).update(JSON.stringify(['agent-guard-inventory-v1', tenantId, kind, value])).digest('hex')}`;
  for (const [key, tenantId] of [[Buffer.alloc(32, 4), 'tenant'], [Buffer.alloc(32, 5), 'tenant'],
    [Buffer.alloc(32, 4), 'other'], [undefined, 'tenant']]) {
    for (const task of Object.values(state.tasks)) task.options.tenantId = tenantId;
    const before = JSON.stringify(state);
    const result = project(state, new Map(), { tenantId }, key);
    assert.equal(JSON.stringify(state), before);
    for (const task of result.tasks) {
      const original = state.tasks[task.id].options;
      assert.deepEqual(task.grants[0].resources,
        original.grants[0].resources.map(value => expected(key, tenantId, 'resource', value)).sort());
      assert.deepEqual(task.allowedRecipients,
        (original.allowedRecipients ?? []).map(value => expected(key, tenantId, 'recipient', value)).sort());
    }
  }
  state.tasks.gamma.options.grants[0].resources = ['shared', 'invalid\0reference'];
  assert.throws(() => project(state, new Map(), scope, Buffer.alloc(32, 4)), { code: 'INVENTORY_STATE_INVALID' });
});

test('configuration and scope reject extra fields and accessors without invoking them', () => {
  assert.throws(() => validateInventorySource({ ...source, tenantId: 'other' }), { code: 'INVENTORY_CONFIG_INVALID' });
  assert.throws(() => validateInventorySource({ ...source, sourceId: ' ' }), { code: 'INVENTORY_CONFIG_INVALID' });
  for (const sourceId of ['\u0085', '\u001c\u001d\u001e\u001f', ' \u0085\n']) {
    assert.throws(() => validateInventorySource({ ...source, sourceId }), { code: 'INVENTORY_CONFIG_INVALID' });
  }
  assert.throws(() => project(ledger(), new Map(), { tenantId: 'tenant', taskIds: ['task'] }), { code: 'INVENTORY_SCOPE_INVALID' });
  let invoked = false;
  const malicious = { ...source };
  Object.defineProperty(malicious, 'companyId', { get() { invoked = true; return 'company'; } });
  assert.throws(() => validateInventorySource(malicious), { code: 'INVENTORY_CONFIG_INVALID' });
  assert.equal(invoked, false);
  const scopeGetter = { get tenantId() { invoked = true; return 'tenant'; } };
  assert.throws(() => project(ledger(), new Map(), scopeGetter), { code: 'INVENTORY_SCOPE_INVALID' });
  assert.equal(invoked, false);
  const value = validateInventorySource(source);
  assert.equal(Object.isFrozen(value), true);
  assert.notEqual(value, source);
});

test('observation time has a bounded UTC representation and is independent of the authorization clock', () => {
  const state = ledger(); state.lastClock = time + 10000;
  assert.equal(project(state).generatedAt, new Date(time).toISOString());
  for (const invalid of [NaN, Infinity, -1, 0.5, 253_402_300_800_000]) {
    assert.throws(() => projectInventory(state, new Map(), source, scope, invalid), { code: 'INVENTORY_CLOCK_INVALID' });
  }
});

for (const [name, corrupt] of [
  ['task key mismatch', state => { state.tasks.task.options.id = 'different'; }],
  ['missing family', state => { delete state.families.family; }],
  ['missing parent', state => { state.tasks.task.parent = 'missing'; }],
  ['cross-tenant parent', state => { state.tasks.other = rawTask('other', 'other'); state.tasks.task.parent = 'other'; }],
  ['parent cycle', state => { state.tasks.task.parent = 'task'; }],
  ['provenance cycle', state => { state.tasks.task.sourceTaskId = 'task'; }],
  ['parent principal mismatch', state => { state.tasks.parent = rawTask('parent'); state.tasks.parent.options.principalId = 'other'; state.tasks.task.parent = 'parent'; }],
  ['provenance family mismatch', state => { state.tasks.parent = rawTask('parent'); state.tasks.parent.family = 'other'; state.families.other = { sensitive: true }; state.tasks.task.sourceTaskId = 'parent'; }],
  ['negative usage', state => { state.tasks.task.calls = -1; }],
  ['unsafe revision', state => { state.revision = Number.MAX_SAFE_INTEGER + 1; }],
  ['invalid deadline', state => { state.tasks.task.options.budget.deadline = Infinity; }],
  ['invalid fingerprint', state => { state.tools.read.fingerprint = 'secret is not a fingerprint'; }],
  ['invalid approved state', state => { state.tools.read.approved = 'true'; }],
  ['null optional boolean', state => { state.tasks.task.options.allowControlPlane = null; }],
  ['Python-only whitespace', state => { state.tasks.task.options.principalId = '\u001c\u0085'; }],
  ['unpaired unicode', state => { state.tasks.task.options.principalId = '\ud800'; }],
  ['identifier too long', state => { state.tasks.task.options.principalId = 'x'.repeat(4097); }],
]) {
  test(`invalid inventory state fails closed: ${name}`, () => {
    const state = ledger(); corrupt(state);
    assert.throws(() => project(state), error => error.code === 'INVENTORY_STATE_INVALID' && error.message === error.code);
  });
}

test('distinct provenance preserves principal differences and supports deep valid ancestry', () => {
  const state = ledger();
  state.tasks.parent = rawTask('parent');
  state.tasks.parent.options.principalId = 'different-principal';
  state.tasks.task.sourceTaskId = 'parent';
  for (let i = 0; i < 100; i++) {
    const task = rawTask(`child-${i}`); task.parent = i === 0 ? 'task' : `child-${i - 1}`;
    state.tasks[task.options.id] = task;
  }
  assert.equal(project(state).tasks.length, 102);
});

test('byte cap reserves headroom for the Python consumer numeric serializer', () => {
  const state = ledger(); state.tasks = {};
  for (let i = 0; i < 2; i++) {
    const task = rawTask(`task-${i}`);
    task.options.budget.deadline = 1e-7;
    task.options.grants[0].resources = Array.from({ length: 1024 }, (_, j) => `${j}:` + 'x'.repeat(4000));
    state.tasks[task.options.id] = task;
  }
  const baseline = project(state);
  // Pad valid identifiers to an encoded length below 8 MiB but inside the reserved headroom.
  let remaining = 8 * 1024 * 1024 - 10 - Buffer.byteLength(JSON.stringify(baseline));
  for (const task of Object.values(state.tasks)) {
    const resources = task.options.grants[0].resources;
    for (let i = 0; i < resources.length && remaining > 0; i++) {
      const count = Math.min(4096 - resources[i].length, remaining);
      resources[i] += 'x'.repeat(count); remaining -= count;
    }
  }
  assert.equal(remaining, 0);
  assert.throws(() => project(state), { code: 'INVENTORY_LIMIT_EXCEEDED' });
});

for (const [name, expand] of [
  ['task count', state => { state.tasks = Object.fromEntries(Array.from({ length: 10001 }, (_, i) => [`task-${i}`, rawTask(`task-${i}`)])); }],
  ['normalized grant count', state => { state.tasks.task.options.grants = Array.from({ length: 2049 }, (_, i) => ({ tool: `tool-${i}`, resources: [] })); }],
  ['per-grant resource count', state => { state.tasks.task.options.grants[0].resources = Array.from({ length: 1025 }, (_, i) => `resource-${i}`); }],
  ['recipient count', state => { state.tasks.task.options.allowedRecipients = Array.from({ length: 1025 }, (_, i) => `recipient-${i}`); }],
  ['total selector count', state => {
    const resources = Array.from({ length: 1024 }, (_, i) => `resource-${i}`);
    state.tasks = Object.fromEntries(Array.from({ length: 98 }, (_, i) => {
      const task = rawTask(`task-${i}`); task.options.grants[0].resources = resources; return [task.options.id, task];
    }));
  }],
  ['tool count', state => {
    state.tasks = {}; state.tools = {};
    for (let i = 0; i < 5; i++) {
      const task = rawTask(`task-${i}`);
      task.options.grants = Array.from({ length: 2048 }, (_, j) => {
        const tool = `tool-${i}-${j}`; state.tools[tool] = { fingerprint, revision: 0, approved: false };
        return { tool, resources: [] };
      }); state.tasks[task.options.id] = task;
    }
  }],
  ['serialized byte cap', state => {
    const resources = Array.from({ length: 1024 }, (_, i) => `${i}:` + 'x'.repeat(4000));
    state.tasks = Object.fromEntries(Array.from({ length: 3 }, (_, i) => {
      const task = rawTask(`task-${i}`); task.options.grants[0].resources = resources; return [task.options.id, task];
    }));
  }],
  ['JSON value count', state => {
    const grants = Array.from({ length: 2048 }, (_, i) => ({ tool: `tool-${i}`, resources: [] }));
    state.tasks = Object.fromEntries(Array.from({ length: 85 }, (_, i) => {
      const task = rawTask(`task-${i}`); task.options.grants = grants; return [task.options.id, task];
    }));
  }],
]) {
  test(`inventory limit rejects the entire snapshot: ${name}`, () => {
    const state = ledger(); expand(state);
    const before = state.revision;
    assert.throws(() => project(state), { code: 'INVENTORY_LIMIT_EXCEEDED' });
    assert.equal(state.revision, before);
  });
}
