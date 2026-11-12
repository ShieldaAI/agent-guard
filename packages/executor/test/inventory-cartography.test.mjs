import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '../dist/index.js';
import {
  composeInventorySnapshot,
  validateInventoryManifest,
  createInventoryObserverToken,
  startInventoryServer,
} from '../dist/entry-inventory.js';
import { LedgerStore } from '../dist/store.js';

const fixture = JSON.parse(readFileSync(new URL('fixtures/inventory-manifest-v2.json', import.meta.url), 'utf8'));
const plain = value => JSON.parse(JSON.stringify(value));
const manifest = () => plain(fixture);
const hostTarget = (id = '1') => ({
  provider: 'host',
  id: `opaque:${id.repeat(64)}`,
  name: 'Company report database',
  kind: 'database',
});

function setup() {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'executor', enrollmentGeneration: 'enrollment' },
  });
  const fingerprint = executor.registerTool({
    name: 'read',
    description: 'private-description-canary',
    resolve: () => assert.fail('cartography called a resolver'),
    execute: () => assert.fail('cartography executed a tool'),
  });
  executor.approveTool('read', fingerprint);
  for (const [id, tenantId] of [
    ['task', 'tenant'],
    ['foreign-task', 'foreign-tenant'],
  ])
    executor.createTask({
      id,
      tenantId,
      principalId: 'caller',
      grants: [{ tool: 'read', resources: ['private-selector-canary'] }],
      budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: 100_000 },
    });
  const core = executor.inventorySnapshot({ tenantId: 'tenant' });
  const value = manifest();
  value.source = plain(core.source);
  value.resourceBindings[0].resourceRef = core.tasks[0].grants[0].resources[0];
  return { executor, core, value };
}

test('v2 catalog is detached, deeply immutable, and keeps explicit ownership/provenance', () => {
  const input = manifest();
  const output = validateInventoryManifest(input);
  assert.deepEqual(plain(output), input);
  input.owners[0].name = 'changed';
  input.credentialReferences[0].audienceRefs.length = 0;
  assert.equal(output.owners[0].name, 'Reports team');
  assert.equal(output.credentialReferences[0].audienceRefs.length, 1);
  assert.equal(Object.isFrozen(output.credentialReferences[0].recipientRefs), true);
  assert.throws(() => {
    output.agents[0].purpose = 'changed';
  }, TypeError);
  for (const ownershipStatus of ['unassigned', 'unknown']) {
    const value = manifest();
    Object.assign(value.agents[0], { ownerId: null, ownershipStatus, ownershipSource: null });
    assert.equal(validateInventoryManifest(value).agents[0].ownershipStatus, ownershipStatus);
  }
});

test('v2 accepts exact host resources and AWS bindings without treating either as effective authority', () => {
  const value = manifest();
  value.resourceBindings[0].target = hostTarget();
  value.resourceBindings[0].actions = ['record.read'];
  assert.equal(validateInventoryManifest(value).resourceBindings[0].target.provider, 'host');
  value.resourceBindings.push({
    ...plain(value.resourceBindings[0]),
    id: 'prefix',
    resourceRef: 'prefix-selector',
    scope: 'prefix',
    dependsOn: ['report'],
  });
  const result = validateInventoryManifest(value);
  assert.equal(result.resourceBindings[1].scope, 'prefix');
  assert.equal(result.evidenceKind, 'host_asserted');
  assert.deepEqual(result.resourceBindings[1].dependsOn, ['report']);
  value.resourceBindings[1].target.name = 'conflicting-host-identity';
  assert.throws(() => validateInventoryManifest(value), { code: 'INVENTORY_MANIFEST_REFERENCE_INVALID' });
});

test('actual v2 composition leaves authority, grants, receipts and independent captures untouched', t => {
  const { executor, core, value } = setup();
  t.after(() => executor.close());
  const before = plain(core);
  const writes = t.mock.method(LedgerStore.prototype, 'transaction', () => assert.fail('inventory wrote authority'));
  const output = composeInventorySnapshot(core, value);
  const after = executor.inventorySnapshot({ tenantId: 'tenant' });
  writes.mock.restore();
  for (const key of ['tasks', 'tools', 'ledgerRevision', 'policyEpoch', 'source']) {
    assert.deepEqual(output[key], core[key]);
    assert.deepEqual(after[key], core[key]);
  }
  assert.deepEqual(plain(core), before);
  assert.equal(output.manifest.schemaVersion, 2);
  assert.equal(output.coverage.tasks.observedAt, core.coverage.tasks.observedAt);
  assert.equal(output.coverage.manifest.observedAt, value.observedAt);
  assert.equal(output.coverage.cloud.status, 'not_collected');
  assert.equal(JSON.stringify(output).includes('foreign-task'), false);
});

test('actual v2 observer enforces profile and tenant scope and exports no credential or action payload', async t => {
  const { executor, core, value } = setup();
  const hostToken = createInventoryObserverToken(),
    coreToken = createInventoryObserverToken();
  let server;
  t.after(async () => {
    await server?.close();
    executor.close();
  });
  server = await startInventoryServer({
    executor,
    manifests: [value],
    observers: [
      { token: hostToken, tenantIds: ['tenant'], profile: 'host' },
      { token: coreToken, tenantIds: ['tenant'], profile: 'core' },
    ],
  });
  value.credentialReferences[0].name = 'mutated-private-canary';
  const post = async (token, body = { tenantId: 'tenant' }) => {
    const response = await fetch(`${server.url}/v1/inventory/snapshot`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: response.status, text: await response.text() };
  };
  const writes = t.mock.method(LedgerStore.prototype, 'transaction', () =>
    assert.fail('observation changed authority'),
  );
  const captured = await post(hostToken);
  writes.mock.restore();
  assert.equal(captured.status, 200);
  const snapshot = JSON.parse(captured.text);
  assert.equal(snapshot.manifest.schemaVersion, 2);
  assert.equal(snapshot.ledgerRevision, core.ledgerRevision);
  for (const secret of [
    'foreign-task',
    'private-selector-canary',
    'private-description-canary',
    'mutated-private-canary',
    hostToken,
    coreToken,
  ])
    assert.equal(captured.text.includes(secret), false);
  assert.equal(snapshot.manifest.credentialReferences[0].id, `opaque:${'a'.repeat(64)}`);
  assert.equal(Object.hasOwn(JSON.parse((await post(coreToken)).text), 'manifest'), false);
  assert.equal((await post(hostToken, { tenantId: 'foreign-tenant' })).status, 403);
  assert.equal((await post(coreToken, { tenantId: 'tenant', profile: 'host' })).status, 400);
});

for (const [name, mutate] of [
  [
    'unsupported version',
    v => {
      v.schemaVersion = 3;
    },
  ],
  [
    'v2 metadata on v1',
    v => {
      v.schemaVersion = 1;
    },
  ],
  [
    'missing authority',
    v => {
      delete v.authorityId;
    },
  ],
  [
    'extra credential payload',
    v => {
      v.credentialReferences[0].token = 'private-canary';
    },
  ],
  [
    'credential URL',
    v => {
      v.credentialReferences[0].id = 'https://user:private-canary@example.com';
    },
  ],
  [
    'raw issuer',
    v => {
      v.credentialReferences[0].issuerRef = 'private-canary';
    },
  ],
  [
    'raw recipient',
    v => {
      v.credentialReferences[0].recipientRefs = ['private-canary'];
    },
  ],
  [
    'newline reference',
    v => {
      v.credentialReferences[0].id += '\n';
    },
  ],
  [
    'uppercase reference',
    v => {
      v.credentialReferences[0].id = `opaque:${'A'.repeat(64)}`;
    },
  ],
  [
    'duplicate credential',
    v => {
      v.credentialReferences.push(plain(v.credentialReferences[0]));
    },
  ],
  [
    'duplicate audience',
    v => {
      v.credentialReferences[0].audienceRefs.push(v.credentialReferences[0].audienceRefs[0]);
    },
  ],
  [
    'unknown deployment credential',
    v => {
      v.deployments[0].credentialReferenceIds = [`opaque:${'0'.repeat(64)}`];
    },
  ],
  [
    'duplicate deployment credential',
    v => {
      v.deployments[0].credentialReferenceIds.push(v.deployments[0].credentialReferenceIds[0]);
    },
  ],
  [
    'secret runtime URL',
    v => {
      v.deployments[0].runtimeRef = 'https://example.com/?token=private-canary';
    },
  ],
  [
    'unknown owner',
    v => {
      v.agents[0].ownerId = 'hidden-owner';
    },
  ],
  [
    'duplicate owner',
    v => {
      v.owners.push(plain(v.owners[0]));
    },
  ],
  [
    'assigned without owner',
    v => {
      v.agents[0].ownerId = null;
    },
  ],
  [
    'unassigned with owner',
    v => {
      v.agents[0].ownershipStatus = 'unassigned';
    },
  ],
  [
    'unknown resource owner',
    v => {
      v.resourceBindings[0].ownerId = 'hidden-owner';
    },
  ],
  [
    'unknown dependency',
    v => {
      v.resourceBindings[0].dependsOn = ['missing'];
    },
  ],
  [
    'self dependency',
    v => {
      v.resourceBindings[0].dependsOn = ['report'];
    },
  ],
  [
    'unsafe destination',
    v => {
      v.resourceBindings[0].approvedDestinations = ['https://example.com/?key=private-canary'];
    },
  ],
  [
    'unknown lifecycle',
    v => {
      v.agents[0].lifecycleState = 'approved';
    },
  ],
  [
    'unbounded purpose',
    v => {
      v.agents[0].purpose = 'x'.repeat(1025);
    },
  ],
  [
    'unbounded owner name',
    v => {
      v.owners[0].name = 'x'.repeat(257);
    },
  ],
  [
    'host resource raw identity',
    v => {
      v.resourceBindings[0].target = { ...hostTarget(), id: 'private-canary' };
    },
  ],
  [
    'host resource secret field',
    v => {
      v.resourceBindings[0].target = { ...hostTarget(), password: 'private-canary' };
    },
  ],
  [
    'empty host actions',
    v => {
      v.resourceBindings[0].target = hostTarget();
      v.resourceBindings[0].actions = [];
    },
  ],
  [
    'AWS action on wrong service',
    v => {
      v.resourceBindings[0].actions = ['iam:CreateRole'];
    },
  ],
])
  test(`v2 rejects ${name} without reflecting private input`, () => {
    const value = manifest();
    mutate(value);
    assert.throws(
      () => validateInventoryManifest(value),
      error => {
        assert.match(error.code, /^INVENTORY_MANIFEST_(INVALID|REFERENCE_INVALID)$/);
        assert.equal(error.message, error.code);
        assert.equal(error.message.includes('private-canary'), false);
        return true;
      },
    );
  });

test('v2 refuses accessors and catalog bounds without partial or side-effecting validation', () => {
  const value = manifest();
  let invoked = false;
  Object.defineProperty(value.credentialReferences[0], 'name', {
    enumerable: true,
    get() {
      invoked = true;
      return 'private-canary';
    },
  });
  assert.throws(() => validateInventoryManifest(value), { code: 'INVENTORY_MANIFEST_INVALID' });
  assert.equal(invoked, false);
  const many = manifest();
  many.owners = Array.from({ length: 1001 }, (_, i) => ({ id: `owner-${i}`, name: 'Owner', kind: 'team' }));
  assert.throws(() => validateInventoryManifest(many), { code: 'INVENTORY_MANIFEST_LIMIT_EXCEEDED' });
});
