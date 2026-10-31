import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor, createInventoryObserverToken, startInventoryServer } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';

function setup(t) {
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'source', enrollmentGeneration: 'host-profile-1' } });
  t.after(() => executor.close());
  const fingerprint = executor.registerTool({ name: 'records.read', description: 'private-description-canary',
    resolve: () => assert.fail('inventory evaluated a tool resolver'), execute: () => assert.fail('inventory executed a tool') });
  executor.approveTool('records.read', fingerprint);
  for (const [id, tenantId] of [['bound', 'alpha'], ['unassigned', 'alpha'], ['foreign', 'beta']]) executor.createTask({
    id, tenantId, principalId: 'caller-application', grants: [{ tool: 'records.read', resources: ['private-alias-canary'] }],
    budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: 100_000 },
  });
  const core = executor.inventorySnapshot({ tenantId: 'alpha' });
  const manifest = {
    schemaVersion: 1, evidenceKind: 'host_asserted', source: { ...core.source }, manifestId: 'host-manifest',
    revision: 1, observedAt: '2026-10-29T00:00:00Z',
    agents: [{ id: 'agent-one', name: 'Report reader', ownerId: 'owner', teamId: 'team' }],
    deployments: [{ id: 'deployment-one', agentId: 'agent-one', environment: 'production' }],
    taskBindings: [{ taskId: 'bound', deploymentId: 'deployment-one' }],
    resourceBindings: [{ id: 'resource-one', tool: 'records.read', resourceRef: core.tasks[0].grants[0].resources[0],
      target: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
        arn: 'arn:aws:s3:::reports/report.txt', kind: 'object' }, actions: ['s3:GetObject'], scope: 'exact' }],
    executionBindings: [{ id: 'execution-one', tool: 'records.read', deploymentId: 'deployment-one', connectionId: null,
      identitySelection: 'static', identity: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
        arn: 'arn:aws:iam::111122223333:role/reader' } }],
  };
  return { executor, core, manifest };
}
async function service(t, executor, manifest, options = {}) {
  const coreToken = createInventoryObserverToken(), hostToken = createInventoryObserverToken();
  const server = await startInventoryServer({ executor, observers: [
    { token: coreToken, tenantIds: ['alpha'], profile: 'core' },
    { token: hostToken, tenantIds: ['alpha'], profile: 'host' },
  ], manifests: [manifest], ...options });
  t.after(() => server.close());
  return { ...server, coreToken, hostToken };
}
async function post(server, token, input = { tenantId: 'alpha' }) {
  const response = await fetch(`${server.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify(input) });
  const text = await response.text();
  return { response, text, data: JSON.parse(text) };
}

test('host observer composes one ledger read while core credentials never receive manifest fields', async t => {
  const { executor, core, manifest } = setup(t);
  const server = await service(t, executor, manifest);
  manifest.agents[0].name = 'changed-caller-canary'; manifest.taskBindings.length = 0;
  const original = LedgerStore.prototype.read;
  let reads = 0;
  const reader = t.mock.method(LedgerStore.prototype, 'read', function () { reads++; return original.call(this); });
  const write = t.mock.method(LedgerStore.prototype, 'transaction', () => assert.fail('composition wrote authority'));
  const result = await post(server, server.hostToken);
  assert.equal(reads, 1);
  reader.mock.restore(); write.mock.restore();
  assert.equal(result.response.status, 200, result.text);
  assert.equal(result.data.profile, 'host');
  assert.equal(result.data.manifest.agents[0].name, 'Report reader');
  assert.deepEqual(result.data.manifest.taskBindings, [{ taskId: 'bound', deploymentId: 'deployment-one' }]);
  assert.deepEqual(result.data.tasks, JSON.parse(JSON.stringify(core.tasks)));
  assert.deepEqual(result.data.tools, JSON.parse(JSON.stringify(core.tools)));
  assert.equal(result.data.ledgerRevision, core.ledgerRevision);
  assert.equal(result.data.policyEpoch, core.policyEpoch);
  assert.equal(result.data.manifest.revision, 1);
  assert.equal(result.data.coverage.manifest.observedAt, '2026-10-29T00:00:00Z');
  assert.notEqual(result.data.coverage.tasks.observedAt, result.data.coverage.manifest.observedAt);
  assert.equal(result.data.coverage.mcp.status, 'not_collected');
  assert.equal(result.data.coverage.cloud.status, 'not_collected');
  assert.equal(result.response.headers.get('cache-control'), 'no-store');
  for (const canary of ['foreign', 'private-alias-canary', 'private-description-canary', 'changed-caller-canary']) {
    assert.equal(result.text.includes(canary), false);
  }
  const basic = await post(server, server.coreToken);
  assert.equal(basic.response.status, 200); assert.equal(basic.data.profile, 'core');
  assert.equal(Object.hasOwn(basic.data, 'manifest'), false);
  assert.equal(basic.data.coverage.manifest.status, 'not_collected');
  assert.equal((await post(server, server.coreToken, { tenantId: 'alpha', profile: 'host' })).response.status, 400);
  assert.equal((await post(server, server.hostToken, { tenantId: 'beta' })).response.status, 403);
});

test('manifest runtime scope and binding failures expose no partial host snapshot and leave core observation usable', async t => {
  for (const corrupt of [
    manifest => { manifest.source.inventoryInstanceId = 'another-ledger'; },
    manifest => { manifest.source.companyId = 'another-company'; },
    manifest => { manifest.taskBindings[0].taskId = 'foreign'; },
    manifest => { manifest.resourceBindings[0].resourceRef = 'private-alias-canary'; },
    manifest => { manifest.executionBindings[0].tool = 'unrelated-tool'; },
  ]) {
    const { executor, manifest, core } = setup(t);
    corrupt(manifest);
    const server = await service(t, executor, manifest);
    const result = await post(server, server.hostToken);
    assert.equal(result.response.status, 503);
    assert.deepEqual(result.data, { error: 'INVENTORY_UNAVAILABLE' });
    const basic = await post(server, server.coreToken);
    assert.equal(basic.response.status, 200); assert.equal(basic.data.ledgerRevision, core.ledgerRevision);
  }
});

test('host profile requires detached valid manifests for every allowed tenant and rejects ambiguous configuration', async t => {
  const { executor, manifest } = setup(t);
  const token = createInventoryObserverToken();
  const options = { executor, observers: [{ token, tenantIds: ['alpha'], profile: 'host' }] };
  for (const invalid of [
    {}, { manifests: [] }, { manifests: [manifest, manifest] },
    { manifests: [{ ...manifest, grants: [{ tool: '*', resources: ['*'] }] }] },
    { manifests: [{ ...manifest, metadata: { token: 'private-token-canary' } }] },
    { manifests: [manifest], observers: [{ token, tenantIds: ['alpha', 'beta'], profile: 'host' }] },
  ]) await assert.rejects(startInventoryServer({ ...options, ...invalid }),
    { code: 'INVENTORY_SERVER_CONFIG_INVALID', message: 'INVENTORY_SERVER_CONFIG_INVALID' });
  let invoked = false;
  await assert.rejects(startInventoryServer({ ...options, manifests: [{ ...manifest,
    get agents() { invoked = true; return []; } }] }), { code: 'INVENTORY_SERVER_CONFIG_INVALID' });
  assert.equal(invoked, false);
});

test('host composition keeps observer response bounds and never silently falls back to the core profile', async t => {
  const { executor, manifest } = setup(t);
  const server = await service(t, executor, manifest, { maxResponseBytes: 128 });
  const result = await post(server, server.hostToken);
  assert.equal(result.response.status, 413);
  assert.deepEqual(result.data, { error: 'INVENTORY_RESPONSE_TOO_LARGE' });
  assert.ok(Buffer.byteLength(result.text) <= 128);
});
