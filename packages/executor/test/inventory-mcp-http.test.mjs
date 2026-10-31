import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor, createInventoryObserverToken, startInventoryServer } from '../dist/index.js';

function setup(t) {
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
    inventory: { companyId: 'company', sourceId: 'executor', enrollmentGeneration: 'mcp-enrollment' } });
  t.after(() => executor.close());
  const fingerprint = executor.registerTool({ name: 'mcp:documents:read', description: 'description-canary',
    resolve: () => assert.fail('inventory resolved an operation'), execute: () => assert.fail('inventory executed') });
  executor.createTask({ id: 'task', tenantId: 'alpha', principalId: 'operator',
    grants: [{ tool: 'mcp:documents:read', resources: ['alias-canary'] }],
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 100_000 } });
  const core = executor.inventorySnapshot({ tenantId: 'alpha' });
  const manifest = { schemaVersion: 1, evidenceKind: 'host_asserted', source: core.source,
    manifestId: 'deployment-config', revision: 1, observedAt: '2026-10-30T00:00:00Z',
    agents: [{ id: 'agent', name: 'Reader', ownerId: null, teamId: null }],
    deployments: [{ id: 'deployment', agentId: 'agent', environment: 'test' }],
    taskBindings: [{ taskId: 'task', deploymentId: 'deployment' }], resourceBindings: [],
    executionBindings: [{ id: 'binding', tool: 'mcp:documents:read', deploymentId: 'deployment',
      connectionId: 'documents', identitySelection: 'unknown', identity: null }] };
  const inventory = { schemaVersion: 1,
    identity: { serverId: 'documents', transportRef: `opaque:${'a'.repeat(64)}`, principalId: 'operator', tenantId: 'alpha' },
    sessionId: 'session', revision: 2, authorizationEpoch: 1, metadataRevision: 1,
    state: 'ready', metadataState: 'current', observedAt: '2026-10-30T00:00:00Z',
    operations: [{ name: 'mcp:documents:read', kind: 'tool', fingerprint: fingerprint.slice(7) }] };
  return { executor, core, manifest, inventory };
}
async function service(t, executor, manifest, mcpSources, extra = {}) {
  const tokens = Object.fromEntries(['core', 'host', 'host-mcp'].map(profile => [profile, createInventoryObserverToken()]));
  const server = await startInventoryServer({ executor, manifests: [manifest], mcpSources,
    observers: Object.entries(tokens).map(([profile, token]) => ({ profile, token, tenantIds: ['alpha'] })), ...extra });
  t.after(() => server.close());
  return { ...server, tokens };
}
async function post(server, profile = 'host-mcp', body = { tenantId: 'alpha' }) {
  const response = await fetch(`${server.url}/v1/inventory/snapshot`, { method: 'POST',
    headers: { authorization: `Bearer ${server.tokens[profile]}`, 'content-type': 'application/json' },
    body: JSON.stringify(body) });
  const text = await response.text();
  return { response, text, data: JSON.parse(text) };
}

test('only host-mcp credentials capture fixed tenant sources and preserve executor authority', async t => {
  const { executor, core, manifest, inventory } = setup(t);
  let captures = 0;
  class Source { inventory() { captures++; return inventory; } }
  const source = new Source();
  const bindings = [{ tenantId: 'alpha', connectionId: 'documents', source },
    { tenantId: 'beta', connectionId: 'documents', source: { inventory() { assert.fail('foreign tenant read'); } } },
    { tenantId: 'alpha', connectionId: 'unbound', source: { inventory() { assert.fail('unbound source read'); } } }];
  const server = await service(t, executor, manifest, bindings);
  source.inventory = () => assert.fail('mutated reader used');
  bindings[0].tenantId = 'beta'; bindings.length = 0;
  for (const profile of ['core', 'host']) {
    const result = await post(server, profile);
    assert.equal(result.response.status, 200, result.text);
    assert.equal(result.data.profile, profile);
    assert.equal(Object.hasOwn(result.data, 'mcp'), false);
    assert.equal(captures, 0);
  }
  const result = await post(server);
  assert.equal(result.response.status, 200, result.text);
  assert.equal(result.data.profile, 'host-mcp'); assert.equal(captures, 2);
  assert.equal(result.data.mcp.connections[0].inventory.state, 'ready');
  assert.equal(result.data.coverage.mcp.status, 'complete');
  for (const key of ['tasks', 'tools', 'ledgerRevision', 'policyEpoch']) assert.deepEqual(result.data[key], JSON.parse(JSON.stringify(core[key])));
  assert.equal(result.response.headers.get('cache-control'), 'no-store');
  for (const canary of ['description-canary', 'alias-canary', 'unbound', 'foreign']) assert.equal(result.text.includes(canary), false);
  assert.equal((await post(server, 'host-mcp', { tenantId: 'beta' })).response.status, 403);
  assert.equal((await post(server, 'core', { tenantId: 'alpha', profile: 'host-mcp' })).response.status, 400);
  assert.equal(captures, 2);
});

test('missing and failed optional captures publish explicit unavailability with fresh core state', async t => {
  for (const [reason, source] of [
    ['missing', undefined],
    ['capture_failed', { inventory() { throw new Error('credential-canary'); } }],
    ['capture_failed', { inventory() { return Promise.reject(new Error('async-credential-canary')); } }],
  ]) {
    const { executor, manifest } = setup(t);
    const server = await service(t, executor, manifest, source ? [{ tenantId: 'alpha', connectionId: 'documents', source }] : []);
    executor.revokeTask('task');
    const result = await post(server);
    assert.equal(result.response.status, 200, result.text);
    assert.deepEqual(result.data.mcp.connections, [{ connectionId: 'documents', status: 'unavailable', reason }]);
    assert.equal(result.data.coverage.mcp.status, 'unavailable');
    assert.equal(result.data.tasks[0].revoked, true);
    assert.equal(result.text.includes('credential-canary'), false);
  }
});

test('racing, foreign and mismatched observations never export ready operations', async t => {
  for (const reason of ['changed', 'scope_mismatch', 'registration_mismatch']) {
    const { executor, manifest, inventory } = setup(t);
    let reads = 0;
    const source = { inventory() {
      reads++;
      const value = structuredClone(inventory);
      if (reason === 'changed') value.revision += reads;
      if (reason === 'scope_mismatch') value.identity.tenantId = 'beta';
      if (reason === 'registration_mismatch') value.operations[0].fingerprint = '0'.repeat(64);
      return value;
    } };
    const server = await service(t, executor, manifest, [{ tenantId: 'alpha', connectionId: 'documents', source }]);
    const result = await post(server);
    assert.equal(result.response.status, 200, result.text);
    assert.deepEqual(result.data.mcp.connections, [{ connectionId: 'documents', status: 'unavailable', reason }]);
    assert.equal(reads, 2);
  }
});

test('host-mcp configuration rejects ambiguous readers and accessors without invoking them', async t => {
  const { executor, manifest, inventory } = setup(t);
  const binding = { tenantId: 'alpha', connectionId: 'documents', source: { inventory() { return inventory; } } };
  const options = { executor, observers: [{ token: createInventoryObserverToken(), tenantIds: ['alpha'], profile: 'host-mcp' }] };
  for (const invalid of [
    {}, { manifests: [] }, { manifests: [manifest], mcpSources: null },
    { manifests: [manifest], mcpSources: [binding, binding] },
    { manifests: [manifest], mcpSources: [{ ...binding, source: { get inventory() { assert.fail('getter invoked'); } } }] },
  ]) await assert.rejects(startInventoryServer({ ...options, ...invalid }), { code: 'INVENTORY_SERVER_CONFIG_INVALID' });
});

test('host-mcp observer enforces response and elapsed capture limits', async t => {
  const { executor, manifest, inventory } = setup(t);
  const source = { inventory() { return inventory; } };
  const binding = { tenantId: 'alpha', connectionId: 'documents', source };
  const bounded = await service(t, executor, manifest, [binding], { maxResponseBytes: 128 });
  const large = await post(bounded);
  assert.equal(large.response.status, 413);
  assert.deepEqual(large.data, { error: 'INVENTORY_RESPONSE_TOO_LARGE' });
  const slow = { inventory() { const until = performance.now() + 25; while (performance.now() < until) {} return inventory; } };
  const timed = await service(t, executor, manifest, [{ ...binding, source: slow }], { requestTimeoutMs: 20 });
  const elapsed = await post(timed);
  assert.equal(elapsed.response.status, 408);
  assert.deepEqual(elapsed.data, { error: 'REQUEST_TIMEOUT' });
});
