import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { projectInventory, projectInventoryJson } from '../dist/inventory.js';
import { projectInventory as previousProjection } from './fixtures/inventory-before-finalizer.mjs';

const source = { companyId: 'company', sourceId: 'executor', enrollmentGeneration: 'enrollment' };
const scope = { tenantId: 'tenant' };
const time = Date.UTC(2026, 10, 6);
const fingerprint = 'a'.repeat(64);
const task = id => ({
  options: {
    id,
    tenantId: scope.tenantId,
    principalId: 'agent',
    grants: [{ tool: 'read', resources: ['item'] }],
    allowedRecipients: [],
    budget: { maxCalls: 4, maxConcurrent: 2, maxCost: 0, deadline: time + 0.25 },
  },
  parent: null,
  family: 'family',
  revoked: false,
  calls: 0,
  concurrent: 0,
  spent: 0,
  reserved: 0,
});
const ledger = () => ({
  schema: 1,
  revision: 7,
  epoch: 2,
  inventoryInstanceId: '00000000-0000-4000-8000-000000000001',
  tasks: { task: task('task') },
  families: { family: { sensitive: false } },
  tools: { read: { fingerprint, revision: 3, approved: true } },
});
const project = (implementation, state, key, registrations = new Map()) =>
  implementation(state, registrations, source, scope, time, key);

function equivalent(actual, expected, path = '') {
  if (path === '.snapshotId') {
    assert.match(actual, /^[a-f0-9-]{36}$/);
    return;
  }
  if (expected === null || typeof expected !== 'object') {
    assert.equal(actual, expected, path);
    return;
  }
  assert.equal(Object.isFrozen(actual), true, path);
  assert.equal(Object.getPrototypeOf(actual), Object.getPrototypeOf(expected), path);
  if (!Array.isArray(actual)) assert.equal(Object.getPrototypeOf(actual), null, path);
  else assert.equal(Object.getPrototypeOf(actual), Array.prototype, path);
  const keys = Object.getOwnPropertyNames(expected);
  assert.deepEqual(Object.getOwnPropertyNames(actual), keys, path);
  assert.deepEqual(Object.getOwnPropertySymbols(actual), [], path);
  for (const name of keys) {
    const left = Object.getOwnPropertyDescriptor(actual, name),
      right = Object.getOwnPropertyDescriptor(expected, name);
    assert.equal(left.enumerable, right.enumerable, `${path}.${name}`);
    assert.equal(left.writable, false, `${path}.${name}`);
    assert.equal(left.configurable, false, `${path}.${name}`);
    assert.ok('value' in left);
    equivalent(left.value, right.value, `${path}.${name}`);
  }
}
function compare(state, key, registrations) {
  const actual = project(projectInventory, state, key, registrations);
  const expected = project(previousProjection, state, key, registrations);
  const encoded = project(projectInventoryJson, state, key, registrations);
  equivalent(actual, expected);
  // UUID generation is the only varying field; preserve exact serialized key order.
  assert.equal(
    JSON.stringify(actual),
    JSON.stringify(expected).replace(`"snapshotId":"${expected.snapshotId}"`, `"snapshotId":"${actual.snapshotId}"`),
  );
  exactWire(encoded, actual);
  return actual;
}
function exactWire(encoded, expected) {
  const wire = JSON.parse(encoded.json);
  assert.equal(
    encoded.json,
    JSON.stringify(expected).replace(`"snapshotId":"${expected.snapshotId}"`, `"snapshotId":"${wire.snapshotId}"`),
  );
  assert.equal(encoded.bytes, Buffer.byteLength(encoded.json));
  assert.equal(encoded.profile, expected.profile);
  assert.deepEqual({ ...encoded.source }, { ...expected.source });
  assert.equal(Object.isFrozen(encoded), true);
  assert.equal(Object.isFrozen(encoded.source), true);
  assert.match(wire.snapshotId, /^[a-f0-9-]{36}$/);
}
const values = value =>
  value === null || typeof value !== 'object'
    ? 1
    : 1 + Object.values(value).reduce((sum, item) => sum + values(item), 0);

test('projection differential oracle remains the exact pre-optimization compiled implementation', () => {
  const fixture = readFileSync(new URL('./fixtures/inventory-before-finalizer.mjs', import.meta.url), 'utf8');
  const restored = fixture
    .split('\n')
    .slice(4)
    .join('\n')
    .replace("from '../../dist/store.js'", "from './store.js'")
    // 1.0 removed the root alias; the original imported immutableJson from the package root.
    .replace("from '@shieldaai/agent-guard/internal'", "from '@shieldaai/agent-guard'");
  assert.equal(
    createHash('sha256').update(restored).digest('hex'),
    'cc3208d926b91d13cc42d4d40e24cb6408ea022c1c941a0cadf3a566628be62b',
  );
});

test('constructed inventory is equivalent across scopes, Unicode, escaping, normalization and reference modes', () => {
  for (const key of [undefined, Buffer.alloc(32, 4), Buffer.alloc(32, 5)]) {
    const state = ledger();
    state.tasks.task.options.principalId = 'agent-雪-😀-"-\\-\n';
    state.tasks.task.options.grants = [
      { tool: 'read', resources: ['z', '*', 'quote"', 'back\\slash', '雪😀', 'line\nfeed', 'z'] },
      { tool: '__proto__', resources: [] },
      { tool: 'read', resources: ['a', 'z'] },
    ];
    state.tasks.task.options.allowedRecipients = ['team:雪', 'quote"', 'team:雪'];
    state.tasks.task.options.budget = { maxCalls: -0, maxConcurrent: -0, maxCost: -0, deadline: -0 };
    state.tasks.task.calls = -0;
    state.tasks.task.spent = -0;
    state.revision = -0;
    state.tasks.child = task('child');
    state.tasks.child.parent = 'task';
    state.tasks.child.options.principalId = state.tasks.task.options.principalId;
    state.tasks.delegated = task('delegated');
    state.tasks.delegated.sourceTaskId = 'task';
    state.tasks.other = task('other');
    state.tasks.other.options.tenantId = 'other-tenant';
    state.tasks.other.options.principalId = 'PRIVATE-OTHER-TENANT';
    const registrations = new Map([
      ['read', { fingerprint, revision: 3, definition: { maxCost: -0, requiresApproval: true, controlPlane: false } }],
    ]);
    const before = JSON.stringify(state),
      result = compare(state, key, registrations);
    assert.equal(JSON.stringify(state), before);
    assert.equal(JSON.stringify(result).includes('PRIVATE-OTHER-TENANT'), false);
    for (const number of Object.values(result.tasks.find(item => item.id === 'task').budget))
      assert.equal(Object.is(number, -0), false);
    state.tasks.task.options.allowedRecipients.push('later');
    state.tasks.task.calls = 99;
    assert.equal(result.tasks.find(item => item.id === 'task').usage.calls, 0);
    assert.equal(result.tasks.find(item => item.id === 'task').allowedRecipients.includes('later'), false);
    assert.throws(() => {
      result.tasks[0].usage.calls = 99;
    }, TypeError);
  }
  const empty = ledger();
  empty.tasks = {};
  compare(empty);
});

test('finalization never evaluates inherited object or array serialization hooks', () => {
  const state = ledger();
  let invoked = 0,
    actual,
    expected,
    encoded;
  const hook = () => {
    invoked++;
    throw new Error('inherited serialization hook');
  };
  const oldObject = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
  const oldArray = Object.getOwnPropertyDescriptor(Array.prototype, 'toJSON');
  try {
    Object.defineProperty(Object.prototype, 'toJSON', { configurable: true, get: hook });
    Object.defineProperty(Array.prototype, 'toJSON', { configurable: true, get: hook });
    actual = project(projectInventory, state);
    expected = project(previousProjection, state);
    encoded = project(projectInventoryJson, state);
  } finally {
    if (oldObject) Object.defineProperty(Object.prototype, 'toJSON', oldObject);
    else delete Object.prototype.toJSON;
    if (oldArray) Object.defineProperty(Array.prototype, 'toJSON', oldArray);
    else delete Array.prototype.toJSON;
  }
  assert.equal(invoked, 0);
  equivalent(actual, expected);
  exactWire(encoded, expected);
});

test('encoded-length cache preserves every value beyond 1024 entries and across snapshots', () => {
  const state = ledger();
  state.tasks.second = task('second');
  state.tasks.task.options.grants[0].resources = Array.from({ length: 1024 }, (_, index) => `resource-${index}:雪\\"`);
  state.tasks.second.options.grants[0].resources = ['resource-0:雪\\"', 'overflow:😀', '*'];
  state.tasks.second.options.allowedRecipients = ['overflow:😀', 'resource-0:雪\\"'];
  compare(state);
  compare(state, Buffer.alloc(32, 4));
  state.tasks.second.options.grants[0].resources[0] = 'changed:雪';
  compare(state);
});

test('cache hits charge exact UTF-8 bytes at the reserved consumer boundary', () => {
  const state = ledger();
  state.tasks = { alpha: task('alpha'), beta: task('beta') };
  const resources = Array.from({ length: 1024 }, (_, index) => `${index}:` + 'x'.repeat(4000));
  for (const item of Object.values(state.tasks)) {
    item.options.grants[0].resources = resources;
    item.options.budget.deadline = 1e-7;
  }
  const maximum = 8 * 1024 * 1024 - 16 * 2;
  let remaining = maximum - Buffer.byteLength(JSON.stringify(project(previousProjection, state)));
  for (let index = 0; index < resources.length && remaining > 1; index++) {
    const count = Math.min(4096 - resources[index].length, Math.floor(remaining / 2));
    resources[index] += 'x'.repeat(count);
    remaining -= count * 2;
  }
  assert.ok(remaining === 0 || remaining === 1);
  state.tasks.alpha.options.principalId += 'x'.repeat(remaining);
  const accepted = compare(state);
  assert.equal(Buffer.byteLength(JSON.stringify(accepted)), maximum);
  state.tasks.alpha.options.principalId += 'x';
  for (const implementation of [previousProjection, projectInventory, projectInventoryJson])
    assert.throws(() => project(implementation, state), { code: 'INVENTORY_LIMIT_EXCEEDED' });
});

test('constructed inventory preserves the exact 500000-value boundary', () => {
  const state = ledger();
  state.tasks = Object.fromEntries(Array.from({ length: 85 }, (_, index) => [`task-${index}`, task(`task-${index}`)]));
  let remaining = 500000 - values(project(previousProjection, state));
  for (const item of Object.values(state.tasks)) {
    while (remaining >= 3 && item.options.grants.length < 2048) {
      item.options.grants.push({ tool: `extra-${item.options.grants.length}`, resources: [] });
      remaining -= 3;
    }
  }
  assert.ok(remaining >= 0 && remaining <= 2);
  state.tasks['task-0'].options.grants[0].resources.push(
    ...Array.from({ length: remaining }, (_, index) => `extra-${index}`),
  );
  const actual = project(projectInventory, state),
    expected = project(previousProjection, state);
  assert.equal(values(actual), 500000);
  assert.equal(values(expected), 500000);
  assert.equal(
    JSON.stringify(actual),
    JSON.stringify(expected).replace(`"snapshotId":"${expected.snapshotId}"`, `"snapshotId":"${actual.snapshotId}"`),
  );
  exactWire(project(projectInventoryJson, state), expected);
  state.tasks['task-0'].options.grants[0].resources.push('one-over');
  for (const implementation of [previousProjection, projectInventory, projectInventoryJson])
    assert.throws(() => project(implementation, state), { code: 'INVENTORY_LIMIT_EXCEEDED' });
});
