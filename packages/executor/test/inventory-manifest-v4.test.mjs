import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DurableExecutor } from '../dist/index.js';
import { composeInventorySnapshot, validateInventoryManifest } from '../dist/inventory-manifest.js';

const fixture = JSON.parse(readFileSync(new URL('fixtures/inventory-manifest-v2.json', import.meta.url), 'utf8'));
const plain = value => JSON.parse(JSON.stringify(value));
const opaque = digit => `opaque:${digit.repeat(64)}`;
const entry = (overrides = {}) => ({
  deploymentId: 'deployment',
  segmentId: opaque('a'),
  egress: 'allowlist',
  egressTargets: [opaque('b')],
  sandbox: 'container',
  ...overrides,
});
const manifest = (networkIsolation = [entry()]) => {
  const value = { ...plain(fixture), schemaVersion: 4, directAccess: [], networkIsolation };
  // A second deployment of the same agent, so one can declare and the other not.
  value.deployments.push({ ...value.deployments[0], id: 'other-deployment' });
  return value;
};
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

test('v4 keeps the declaration detached and immutable; [] is a valid declaration', () => {
  const input = manifest([
    entry(),
    entry({ deploymentId: 'other-deployment', segmentId: null, egress: 'none', egressTargets: [], sandbox: 'vm' }),
  ]);
  const output = validateInventoryManifest(input);
  assert.deepEqual(plain(output), input);
  input.networkIsolation[0].egress = 'open';
  assert.equal(output.networkIsolation[0].egress, 'allowlist');
  assert.throws(() => {
    output.networkIsolation[0].egressTargets.push(opaque('c'));
  }, TypeError);
  assert.deepEqual(plain(validateInventoryManifest(manifest([]))).networkIsolation, []);
});

test('v4 requires both declarations and refuses networkIsolation on v1 to v3', () => {
  const missing = manifest();
  delete missing.networkIsolation;
  assert.equal(code(missing), 'INVENTORY_MANIFEST_INVALID', 'v4 must say what it declared, even []');
  const noDirect = manifest();
  delete noDirect.directAccess;
  assert.equal(code(noDirect), 'INVENTORY_MANIFEST_INVALID', 'v4 is v3 plus networkIsolation');
  const v3 = manifest();
  v3.schemaVersion = 3;
  assert.equal(code(v3), 'INVENTORY_MANIFEST_INVALID', 'v3 has no networkIsolation field');
  delete v3.networkIsolation;
  assert.equal(code(v3), 'ACCEPTED');
  assert.equal(code({ ...manifest(), schemaVersion: 5 }), 'INVENTORY_MANIFEST_INVALID');
});

test('v4 entries are checked one by one', () => {
  const cases = [
    [{ deploymentId: 'missing' }, 'INVENTORY_MANIFEST_REFERENCE_INVALID'],
    [{ deploymentId: '' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ segmentId: 'segment-a' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ segmentId: `${opaque('a')}\n` }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egress: 'restricted' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egress: null }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egressTargets: ['api.example.com'] }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egressTargets: [opaque('b'), opaque('b')] }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egressTargets: null }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egress: 'none' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ egress: 'open' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ sandbox: 'jail' }, 'INVENTORY_MANIFEST_INVALID'],
    [{ extra: true }, 'INVENTORY_MANIFEST_INVALID'],
  ];
  for (const [overrides, expected] of cases)
    assert.equal(code(manifest([entry(overrides)])), expected, JSON.stringify(overrides));
  const missing = entry();
  delete missing.egressTargets;
  assert.equal(code(manifest([missing])), 'INVENTORY_MANIFEST_INVALID', 'egressTargets is required');
  for (const egress of ['none', 'open'])
    assert.equal(code(manifest([entry({ egress, egressTargets: [] })])), 'ACCEPTED', egress);
  assert.equal(code(manifest([entry({ egressTargets: [] })])), 'ACCEPTED', 'an empty allowlist admits nothing');
  assert.equal(code(manifest([entry(), entry()])), 'INVENTORY_MANIFEST_INVALID', 'one entry per deployment');
});

test('v4 allows at most 32 egress targets and 1,000 entries', () => {
  const targets = Array.from({ length: 33 }, (_, index) => `opaque:${index.toString(16).padStart(64, '0')}`);
  assert.equal(code(manifest([entry({ egressTargets: targets.slice(0, 32) })])), 'ACCEPTED');
  assert.equal(code(manifest([entry({ egressTargets: targets })])), 'INVENTORY_MANIFEST_LIMIT_EXCEEDED');
  const many = manifest([]);
  many.deployments = Array.from({ length: 1000 }, (_, index) => ({ ...many.deployments[0], id: `d-${index}` }));
  many.taskBindings = [];
  many.executionBindings = [];
  many.networkIsolation = many.deployments.map(deployment => entry({ deploymentId: deployment.id }));
  assert.equal(code(many), 'ACCEPTED');
  // The length limit applies before the one-per-deployment rule.
  many.networkIsolation.push(entry({ deploymentId: 'd-0' }));
  assert.equal(code(many), 'INVENTORY_MANIFEST_LIMIT_EXCEEDED');
});

test('composing v4 over a v1 core emits a v2 snapshot exactly like v3', t => {
  const { executor, core, value } = setup();
  t.after(() => executor.close());
  assert.equal(core.schemaVersion, 1);
  const output = plain(composeInventorySnapshot(core, value));
  assert.equal(output.schemaVersion, 2, 'manifest v4 only fits the v2 snapshot schema');
  assert.equal(output.manifest.schemaVersion, 4);
  assert.deepEqual(output.manifest.networkIsolation, value.networkIsolation);
  const { networkIsolation: _declared, ...rest } = value;
  const v3 = plain(composeInventorySnapshot(core, { ...rest, schemaVersion: 3 }));
  for (const field of ['schemaVersion', 'untrustedContextDefault', 'tasks', 'tools', 'ledgerRevision', 'policyEpoch'])
    assert.deepEqual(output[field], v3[field], `${field} is the same as with manifest v3`);
});
