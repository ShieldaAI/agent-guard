import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DurableExecutor } from '../dist/index.js';
import { composeInventorySnapshot, validateInventoryManifest } from '../dist/inventory-manifest.js';

const fixture = JSON.parse(readFileSync(new URL('fixtures/inventory-manifest-v2.json', import.meta.url), 'utf8'));
const plain = value => JSON.parse(JSON.stringify(value));
const opaque = digit => `opaque:${digit.repeat(64)}`;
const entry = (id, overrides = {}) => ({
  id: opaque(id),
  deploymentId: 'deployment',
  kind: 'shell',
  targetRef: null,
  description: 'Runs scripts on the build host without the guard',
  ...overrides,
});
const manifest = (directAccess = [entry('a')]) => ({ ...plain(fixture), schemaVersion: 3, directAccess });
const code = value => {
  try {
    validateInventoryManifest(value);
  } catch (error) {
    return error.code;
  }
  return 'ACCEPTED';
};

function setup() {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'executor', enrollmentGeneration: 'enrollment' },
  });
  executor.approveTool(
    'read',
    executor.registerTool({
      name: 'read',
      description: 'read',
      resolve: () => assert.fail('inventory called a resolver'),
      execute: () => assert.fail('inventory executed a tool'),
    }),
  );
  executor.createTask({
    id: 'task',
    tenantId: 'tenant',
    principalId: 'caller',
    grants: [{ tool: 'read', resources: ['item'] }],
    budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: 100_000 },
  });
  const core = executor.inventorySnapshot({ tenantId: 'tenant' });
  const value = manifest();
  value.source = plain(core.source);
  value.resourceBindings[0].resourceRef = core.tasks[0].grants[0].resources[0];
  return { executor, core, value };
}

test('v3 keeps the declaration detached and immutable; [] is a valid declaration', () => {
  const input = manifest([entry('a'), entry('b', { kind: 'database', targetRef: opaque('c') })]);
  const output = validateInventoryManifest(input);
  assert.deepEqual(plain(output), input);
  input.directAccess[0].kind = 'other';
  assert.equal(output.directAccess[0].kind, 'shell');
  assert.throws(() => {
    output.directAccess[0].kind = 'other';
  }, TypeError);
  assert.deepEqual(plain(validateInventoryManifest(manifest([]))).directAccess, []);
});

test('v3 requires the declaration and refuses it on v1 and v2', () => {
  const missing = manifest();
  delete missing.directAccess;
  assert.equal(code(missing), 'INVENTORY_MANIFEST_INVALID', 'v3 must say what it declared, even []');
  const v2 = manifest();
  v2.schemaVersion = 2;
  assert.equal(code(v2), 'INVENTORY_MANIFEST_INVALID', 'v2 has no directAccess field');
  assert.equal(code({ ...manifest(), schemaVersion: 4 }), 'INVENTORY_MANIFEST_INVALID');
});

test('v3 entries are checked one by one', () => {
  const cases = [
    [{ id: 'raw-name' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ deploymentId: 'missing' }, 'INVENTORY_MANIFEST_REFERENCE_INVALID'],
    [{ kind: 'ssh' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ targetRef: 'prod-db.internal' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ description: '' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ description: 'x'.repeat(1025) }, 'INVENTORY_MANIFEST_INVALID'],
    [{ extra: true }, 'INVENTORY_MANIFEST_INVALID'],
  ];
  for (const [overrides, expected] of cases)
    assert.equal(code(manifest([entry('a', overrides)])), expected, JSON.stringify(overrides));
  assert.equal(code(manifest([entry('a'), entry('a')])), 'INVENTORY_MANIFEST_INVALID', 'ids are unique');
});

test('v3 allows at most 32 entries per deployment', () => {
  const ids = Array.from({ length: 33 }, (_, index) => `opaque:${index.toString(16).padStart(64, '0')}`);
  const entries = ids.map(id => ({ ...entry('a'), id }));
  assert.equal(code(manifest(entries.slice(0, 32))), 'ACCEPTED');
  assert.equal(code(manifest(entries)), 'INVENTORY_MANIFEST_LIMIT_EXCEEDED');
});

test('composing v3 over a v1 core emits a v2 snapshot with neutral outside-content fields', t => {
  const { executor, core, value } = setup();
  t.after(() => executor.close());
  assert.equal(core.schemaVersion, 1);
  const output = plain(composeInventorySnapshot(core, value));
  assert.equal(output.schemaVersion, 2, 'manifest v3 only fits the v2 snapshot schema');
  assert.equal(output.manifest.schemaVersion, 3);
  assert.deepEqual(output.manifest.directAccess, value.directAccess);
  assert.ok(output.tasks.every(task => task.untrusted === false));
  assert.ok(
    output.tools.every(
      tool => tool.readsUntrusted === null && tool.untrustedContext === null && tool.sendsExternal === null,
    ),
    'no labels were declared, so they stay unknown',
  );
  const { directAccess: _declared, ...rest } = value;
  const v2 = composeInventorySnapshot(core, { ...rest, schemaVersion: 2 });
  assert.equal(v2.schemaVersion, 1, 'a v2 manifest leaves a v1 core unchanged');
});
