import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { composeInventorySnapshot } from '../dist/inventory-manifest.js';
import { composeMcpInventorySnapshot, validateMcpConnectionInventory, validateMcpInventorySources } from '../dist/inventory-mcp.js';

const plain = value => JSON.parse(JSON.stringify(value));
const fixture = JSON.parse(readFileSync(new URL('fixtures/inventory-manifest.json', import.meta.url), 'utf8'));
const time = '2026-10-29T00:00:00.000Z';
function host(ids = ['connection']) {
  const manifest = plain(fixture);
  manifest.deployments = ids.map((id, i) => ({ id: `deployment-${i}`, agentId: 'agent', environment: null }));
  manifest.taskBindings = []; manifest.resourceBindings = [];
  manifest.executionBindings = ids.map((id, i) => ({ ...manifest.executionBindings[0],
    id: `binding-${i}`, deploymentId: `deployment-${i}`, connectionId: id }));
  const core = { schemaVersion: 1, profile: 'core', source: manifest.source, snapshotId: 'snapshot', generatedAt: time,
    ledgerRevision: 19, policyEpoch: 7, tasks: [],
    tools: [{ name: 'read', fingerprint: 'a'.repeat(64), revision: 2, registered: true, approved: false,
      requiresApproval: true, controlPlane: false, maxCost: 1 }],
    coverage: { tasks: { status: 'complete', observedAt: time }, tools: { status: 'complete', observedAt: time },
      manifest: { status: 'not_collected' }, mcp: { status: 'not_collected' }, cloud: { status: 'not_collected' } } };
  return composeInventorySnapshot(core, manifest);
}
function inventory() {
  return { schemaVersion: 1, identity: { serverId: 'server', transportRef: `opaque:${'b'.repeat(64)}`,
    principalId: 'mcp-local-caller', tenantId: 'tenant' }, sessionId: 'local-session', revision: 4,
    authorizationEpoch: 2, metadataRevision: 1, state: 'ready', metadataState: 'current', observedAt: time,
    operations: [{ name: 'read', kind: 'tool', fingerprint: 'a'.repeat(64) }] };
}
const source = (value = inventory(), connectionId = 'connection', tenantId = 'tenant') => ({ tenantId, connectionId,
  source: { inventory: typeof value === 'function' ? value : () => value } });
const record = value => value.mcp.connections[0];

test('MCP validation produces closed detached immutable observations', () => {
  const value = inventory(); const validated = validateMcpConnectionInventory(value);
  assert.deepEqual(plain(validated), value); assert.notEqual(validated, value);
  value.identity.serverId = 'changed'; value.operations.length = 0;
  assert.equal(validated.identity.serverId, 'server'); assert.equal(validated.operations.length, 1);
  assert.ok(Object.isFrozen(validated.operations[0])); assert.ok(Object.isFrozen(validated.identity));
});

test('composition preserves authority, manifest and independent capture timestamps', () => {
  const base = host(); const before = plain(base); const value = inventory();
  value.operations.push({ name: 'unbound-secret-tool', kind: 'prompt', fingerprint: 'c'.repeat(64) });
  const composed = composeMcpInventorySnapshot(base, [source(value)]);
  assert.equal(composed.profile, 'host-mcp'); assert.notEqual(composed.snapshotId, base.snapshotId);
  for (const key of ['source', 'ledgerRevision', 'policyEpoch', 'tasks', 'tools', 'manifest']) assert.deepEqual(composed[key], base[key]);
  for (const key of ['tasks', 'tools', 'manifest', 'cloud']) assert.deepEqual(composed.coverage[key], base.coverage[key]);
  assert.equal(composed.coverage.mcp.status, 'complete');
  assert.equal(composed.coverage.mcp.observedAt, composed.mcp.observedAt);
  assert.equal(record(composed).inventory.observedAt, time);
  assert.equal(record(composed).inventory.identity.principalId, 'mcp-local-caller');
  assert.equal(record(composed).inventory.operations.length, 1);
  assert.equal(JSON.stringify(composed).includes('unbound-secret-tool'), false);
  assert.deepEqual(plain(base), before); assert.equal(value.operations.length, 2);
  assert.ok(Object.isFrozen(record(composed).inventory.operations));
});

test('registry isolates tenant aliases and never calls irrelevant readers', () => {
  let selected = 0; let irrelevant = 0;
  const composed = composeMcpInventorySnapshot(host(), [source(() => { selected++; return inventory(); }),
    source(() => { irrelevant++; throw Error('foreign-private-data'); }, 'connection', 'foreign'),
    source(() => { irrelevant++; throw Error('unbound-private-data'); }, 'unbound')]);
  assert.equal(record(composed).status, 'observed'); assert.equal(selected, 2); assert.equal(irrelevant, 0);
  const missing = composeMcpInventorySnapshot(host(), [source(() => { irrelevant++; }, 'connection', 'foreign')]);
  assert.equal(record(missing).reason, 'missing'); assert.equal(irrelevant, 0);
});

test('registry captures class methods and context without retaining mutable binding records', () => {
  class Reader { #value = inventory(); inventory() { return this.#value; } }
  const reader = new Reader(); const input = [source()]; input[0].source = reader;
  const validated = validateMcpInventorySources(input);
  input[0].tenantId = 'foreign'; reader.inventory = () => { throw Error('replacement'); };
  assert.equal(validated[0].tenantId, 'tenant'); assert.equal(validated[0].source.inventory().state, 'ready');
  assert.ok(Object.isFrozen(validated)); assert.ok(Object.isFrozen(validated[0])); assert.ok(Object.isFrozen(validated[0].source));
  assert.equal(record(composeMcpInventorySnapshot(host(), validated)).status, 'observed');
});

test('missing and failed optional sources report bounded unavailable records', () => {
  const composed = composeMcpInventorySnapshot(host(['good', 'missing', 'bad']), [source(inventory(), 'good'),
    source(() => { throw Error('credential-private-canary'); }, 'bad')]);
  assert.equal(composed.coverage.mcp.status, 'partial');
  assert.deepEqual(plain(composed.mcp.connections).map(value => [value.connectionId, value.status, value.reason]),
    [['bad', 'unavailable', 'capture_failed'], ['good', 'observed', undefined], ['missing', 'unavailable', 'missing']]);
  assert.equal(JSON.stringify(composed).includes('credential-private-canary'), false);
  assert.equal(composeMcpInventorySnapshot(host(), []).coverage.mcp.status, 'unavailable');
});

test('empty expected connections are complete and do not read any source', () => {
  let invoked = false;
  const composed = composeMcpInventorySnapshot(host([]), [source(() => { invoked = true; })]);
  assert.equal(composed.coverage.mcp.status, 'complete'); assert.deepEqual(composed.mcp.connections, []); assert.equal(invoked, false);
  const base = plain(host()); base.manifest.executionBindings[0].connectionId = null;
  assert.equal(composeMcpInventorySnapshot(base, []).coverage.mcp.status, 'complete');
});

test('scope mismatch does not expose the foreign connection data', () => {
  const value = inventory(); value.identity.tenantId = 'foreign-private-tenant';
  const composed = composeMcpInventorySnapshot(host(), [source(value)]);
  assert.deepEqual(plain(record(composed)), { connectionId: 'connection', status: 'unavailable', reason: 'scope_mismatch' });
  assert.equal(JSON.stringify(composed).includes('foreign-private-tenant'), false);
});

test('nonready lifecycle observations are complete observations with no callable operations', () => {
  for (const state of ['connecting', 'refreshing', 'quarantined', 'closed']) {
    for (const metadataRevision of [0, 2]) {
      const value = inventory(); Object.assign(value, { state, metadataRevision,
        metadataState: metadataRevision ? 'stale' : 'unobserved', operations: [] });
      const composed = composeMcpInventorySnapshot(host(), [source(value)]);
      assert.equal(composed.coverage.mcp.status, 'complete'); assert.equal(record(composed).inventory.state, state);
      assert.deepEqual(record(composed).inventory.operations, []);
    }
  }
});

test('removed operations remain absent without inventing an unresolved binding target', () => {
  const value = inventory(); value.metadataRevision = 2; value.operations = [];
  const composed = composeMcpInventorySnapshot(host(), [source(value)]);
  assert.equal(record(composed).status, 'observed'); assert.equal(record(composed).inventory.state, 'ready');
  assert.deepEqual(record(composed).inventory.operations, []); assert.equal(composed.manifest.executionBindings[0].tool, 'read');
});

test('selected registrations require current core fingerprints, not approval or caller identity equality', () => {
  for (const change of [value => { value.tools[0].fingerprint = 'f'.repeat(64); },
    value => { Object.assign(value.tools[0], { registered: false, requiresApproval: null, controlPlane: null, maxCost: null }); },
    value => { value.tools = []; value.tasks = [{ id: 'task', tenantId: 'tenant', principalId: 'different-application-caller',
      parentTaskId: null, sourceTaskId: null, familyId: 'task', grants: [{ tool: 'read', resources: [] }],
      budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: 1000 }, allowedRecipients: [],
      allowControlPlane: false, revoked: false, sensitive: false, usage: { calls: 0, concurrent: 0, spent: 0, reserved: 0 } }]; }]) {
    const base = plain(host()); change(base);
    const composed = composeMcpInventorySnapshot(base, [source()]);
    assert.equal(record(composed).reason, 'registration_mismatch'); assert.equal(Object.hasOwn(record(composed), 'inventory'), false);
  }
  assert.equal(record(composeMcpInventorySnapshot(host(), [source()])).status, 'observed');
});

for (const [name, change] of [
  ['revision', value => { value.revision++; }],
  ['session', value => { value.sessionId = 'new-session'; }],
  ['authorization epoch', value => { value.authorizationEpoch++; }],
  ['metadata revision', value => { value.metadataRevision++; }],
  ['identity', value => { value.identity.principalId = 'new-caller'; }],
  ['fingerprint', value => { value.operations[0].fingerprint = 'd'.repeat(64); }],
  ['unbound operation', value => { value.operations.push({ name: 'unbound', kind: 'resource', fingerprint: 'e'.repeat(64) }); }],
  ['lifecycle', value => { Object.assign(value, { state: 'quarantined', metadataState: 'stale', operations: [] }); }],
]) test(`a changed ${name} between captures discards all projected ready data`, () => {
  let calls = 0;
  const composed = composeMcpInventorySnapshot(host(), [source(() => { const value = inventory(); if (calls++) change(value); return value; })]);
  assert.equal(calls, 2); assert.deepEqual(plain(record(composed)), { connectionId: 'connection', status: 'unavailable', reason: 'changed' });
});

test('observation time alone is ignored and every first read precedes every second read', () => {
  const order = []; let first = 0; let second = 0;
  const composed = composeMcpInventorySnapshot(host(['a', 'b']), [source(() => {
    order.push(`a${++first}`); const value = inventory(); value.observedAt = `2026-10-29T00:00:0${first}.000Z`; return value;
  }, 'a'), source(() => { order.push(`b${++second}`); return inventory(); }, 'b')]);
  assert.deepEqual(order, ['a1', 'b1', 'a2', 'b2']); assert.equal(composed.coverage.mcp.status, 'complete');
});

test('second capture failure never retains a previous ready inventory', () => {
  let count = 0;
  const composed = composeMcpInventorySnapshot(host(), [source(() => { if (count++) throw Error('private'); return inventory(); })]);
  assert.equal(record(composed).reason, 'capture_failed'); assert.equal(Object.hasOwn(record(composed), 'inventory'), false);
});

test('async sources are unavailable and rejected promises are observed; arbitrary thenables are not invoked', async () => {
  const composed = composeMcpInventorySnapshot(host(), [source(() => Promise.reject(Error('private-rejection')))]);
  assert.equal(record(composed).reason, 'capture_failed');
  let invoked = false; const thenable = { then() { invoked = true; } };
  assert.equal(record(composeMcpInventorySnapshot(host(), [source(thenable)])).reason, 'capture_failed');
  await new Promise(resolve => setImmediate(resolve)); assert.equal(invoked, false);
});

for (const [name, change] of [
  ['extra metadata', value => { value.credentials = 'private'; }],
  ['raw transport URL', value => { value.identity.transportRef = 'https://private.invalid'; }],
  ['missing identity field', value => { delete value.identity.principalId; }],
  ['remote operation name', value => { value.operations[0].remoteName = 'private'; }],
  ['prefixed fingerprint', value => { value.operations[0].fingerprint = 'sha256:' + 'a'.repeat(64); }],
  ['duplicate name', value => { value.operations.push(plain(value.operations[0])); }],
  ['unknown kind', value => { value.operations[0].kind = 'other'; }],
  ['unsafe revision', value => { value.revision = Number.MAX_SAFE_INTEGER + 1; }],
  ['unknown lifecycle', value => { value.state = 'error'; }],
  ['ready without metadata', value => { value.metadataRevision = 0; }],
  ['ready stale metadata', value => { value.metadataState = 'stale'; }],
  ['closed retained operations', value => { value.state = 'closed'; value.metadataState = 'stale'; }],
  ['closed current metadata', value => { value.state = 'closed'; value.operations = []; }],
  ['closed false unobserved', value => { value.state = 'closed'; value.operations = []; value.metadataState = 'unobserved'; }],
  ['impossible timestamp', value => { value.observedAt = '2026-02-30T00:00:00Z'; }],
  ['year zero', value => { value.observedAt = '0000-01-01T00:00:00Z'; }],
  ['blank unicode', value => { value.identity.serverId = '\u0085'; }],
  ['unpaired unicode', value => { value.identity.serverId = '\ud800'; }],
  ['oversized identifier', value => { value.identity.serverId = 'a'.repeat(4097); }],
]) test(`connection validation rejects ${name}`, () => {
  const value = inventory(); change(value);
  assert.throws(() => validateMcpConnectionInventory(value), { code: 'INVENTORY_MCP_INVALID', message: 'INVENTORY_MCP_INVALID' });
  assert.equal(record(composeMcpInventorySnapshot(host(), [source(value)])).reason, 'capture_failed');
});

test('data and configuration accessors or serialization hooks are never invoked', () => {
  let invoked = false;
  const value = inventory(); Object.defineProperty(value.identity, 'serverId', { get() { invoked = true; return 'private'; } });
  assert.throws(() => validateMcpConnectionInventory(value), { code: 'INVENTORY_MCP_INVALID' });
  const custom = inventory(); custom.toJSON = () => { invoked = true; return inventory(); };
  assert.throws(() => validateMcpConnectionInventory(custom), { code: 'INVENTORY_MCP_INVALID' });
  const getter = { tenantId: 'tenant', connectionId: 'connection', source: { get inventory() { invoked = true; return () => inventory(); } } };
  assert.throws(() => validateMcpInventorySources([getter]), { code: 'INVENTORY_MCP_CONFIG_INVALID' });
  const binding = source(); Object.defineProperty(binding, 'tenantId', { get() { invoked = true; return 'tenant'; } });
  assert.throws(() => validateMcpInventorySources([binding]), { code: 'INVENTORY_MCP_CONFIG_INVALID' });
  assert.equal(invoked, false);
});

test('invalid, duplicate and oversized registries fail closed with stable configuration errors', () => {
  const values = [null, {}, [source(), source()], [{ ...source(), secret: 'private' }],
    [{ ...source(), tenantId: '' }], [undefined], new Array(1), Array.from({ length: 1025 }, (_, i) => source(inventory(), `${i}`))];
  for (const value of values) assert.throws(() => validateMcpInventorySources(value), {
    code: 'INVENTORY_MCP_CONFIG_INVALID', message: 'INVENTORY_MCP_CONFIG_INVALID',
  });
  assert.equal(record(composeMcpInventorySnapshot(host(), [source(null)])).reason, 'capture_failed');
});

for (const [name, change] of [
  ['extra root field', value => { value.secret = 'private'; }],
  ['wrong profile', value => { value.profile = 'core'; }],
  ['extra coverage field', value => { value.coverage.extra = { status: 'complete' }; }],
  ['wrong manifest status', value => { value.coverage.manifest.status = 'not_collected'; }],
  ['manifest timestamp mismatch', value => { value.coverage.manifest.observedAt = time; }],
  ['extra manifest coverage property', value => { value.coverage.manifest.secret = 'private'; }],
  ['manifest source mismatch', value => { value.manifest.source.tenantId = 'foreign'; }],
  ['unknown bound tool', value => { value.manifest.executionBindings[0].tool = 'unknown'; }],
  ['invalid tool revision', value => { value.tools[0].revision = -1; }],
  ['existing MCP claim', value => { value.mcp = { connections: [] }; }],
  ['existing MCP coverage', value => { value.coverage.mcp = { status: 'complete', observedAt: time }; }],
]) test(`composition rejects malformed host input: ${name}`, () => {
  const base = plain(host()); change(base); let invoked = false;
  assert.throws(() => composeMcpInventorySnapshot(base, [source(() => { invoked = true; return inventory(); })]),
    { code: 'INVENTORY_SNAPSHOT_INVALID' }); assert.equal(invoked, false);
});

test('connection and selection limits fail without truncation', () => {
  const count = inventory(); count.operations = Array.from({ length: 257 }, (_, i) => ({ ...count.operations[0], name: `operation-${i}` }));
  assert.throws(() => validateMcpConnectionInventory(count), { code: 'INVENTORY_MCP_LIMIT_EXCEEDED' });
  const bytes = inventory(); bytes.operations = Array.from({ length: 200 }, (_, i) => ({ ...bytes.operations[0], name: `${i}:${'😀'.repeat(3000)}` }));
  assert.throws(() => validateMcpConnectionInventory(bytes), { code: 'INVENTORY_MCP_LIMIT_EXCEEDED' });
  const base = host(Array.from({ length: 129 }, (_, i) => `connection-${i}`));
  let invoked = false;
  assert.throws(() => composeMcpInventorySnapshot(base, [source(() => { invoked = true; })]), { code: 'INVENTORY_MCP_LIMIT_EXCEEDED' });
  assert.equal(invoked, false);
});

test('the composed output enforces its total byte bound after adding MCP observations', () => {
  const base = plain(host());
  base.tasks = Array.from({ length: 3 }, (_, i) => ({ id: `task-${i}`, tenantId: 'tenant', principalId: 'caller',
    parentTaskId: null, sourceTaskId: null, familyId: `task-${i}`, grants: [{ tool: 'read', resources: [] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: 1000.5 }, allowedRecipients: [],
    allowControlPlane: false, revoked: false, sensitive: false, usage: { calls: 0, concurrent: 0, spent: 0, reserved: 0 } }));
  const maximum = 8 * 1024 * 1024 - 16 * base.tasks.length;
  let remaining = maximum - 100 - Buffer.byteLength(JSON.stringify(base));
  for (const task of base.tasks) {
    const resources = task.grants[0].resources;
    for (let i = 0; i < 1024 && remaining > 20; i++) {
      const overhead = resources.length ? 3 : 2;
      const length = Math.min(4000, remaining - overhead);
      const prefix = `${task.id}-${i}:`;
      resources.push(prefix + 'x'.repeat(length - prefix.length)); remaining -= length + overhead;
    }
  }
  assert.ok(Buffer.byteLength(JSON.stringify(base)) < maximum);
  const { manifest, ...core } = base;
  // The existing host payload fits; the added projection exceeds the full response envelope.
  composeInventorySnapshot({ ...core, profile: 'core', coverage: { ...core.coverage, manifest: { status: 'not_collected' } } }, manifest);
  assert.throws(() => composeMcpInventorySnapshot(base, [source()]), { code: 'INVENTORY_LIMIT_EXCEEDED' });
});

test('standalone and embedded MCP schemas use the same closed connection contract', () => {
  const embedded = JSON.parse(readFileSync(new URL('../../../schemas/agent-guard-inventory-v1.schema.json', import.meta.url), 'utf8'));
  const standalone = JSON.parse(readFileSync(new URL('../../../schemas/agent-guard-mcp-inventory-v1.schema.json', import.meta.url), 'utf8'));
  for (const [name, value] of Object.entries(standalone.$defs)) assert.deepEqual(value, embedded.$defs[name]);
  assert.equal(standalone.$defs.mcpConnection.additionalProperties, false);
});
