import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection } from '../dist/index.js';

const identity = { serverId: 'documents', transportIdentity: 'https://user:TRANSPORT_SECRET@example.test/mcp?token=TRANSPORT_TOKEN', tenantId: 'acme', principalId: 'operator' };
const schema = { type: 'object', properties: { id: { type: 'string', description: 'SCHEMA_CANARY' } }, required: ['id'], additionalProperties: false };
const binding = { name: 'read', resolve: args => ({ resourceId: args.id, tenantId: 'acme' }) };
const plain = value => JSON.parse(JSON.stringify(value));

async function fixture(t, options = {}) {
  const calls = { authorize: 0, register: 0, resolve: 0, execute: 0, send: 0, nativeSession: 0 };
  const server = new McpServer({ name: 'documents', version: '1' });
  server.registerTool('read', { description: 'DESCRIPTOR_CANARY', inputSchema: fromJsonSchema(schema) }, () => {
    calls.execute++; return { content: [{ type: 'text', text: 'RESULT_CANARY' }] };
  });
  options.setup?.(server);
  const [transport, peer] = InMemoryTransport.createLinkedPair();
  const send = transport.send.bind(transport);
  transport.send = (...args) => { calls.send++; return send(...args); };
  await server.connect(peer);
  const guard = options.guard ?? new AgentGuard();
  const registerTool = guard.registerTool.bind(guard);
  const wrappedGuard = { registerTool(definition) { calls.register++; return registerTool(definition); } };
  let connection;
  t.after(async () => { await connection?.close(); await server.close(); });
  connection = await ManagedMcpConnection.connect({
    guard: wrappedGuard, identity, transport, authorize: () => { calls.authorize++; },
    tools: [{ ...binding, resolve(args) { calls.resolve++; return binding.resolve(args); } }],
    ...options.connection,
  });
  // A preexisting session ID changes the SDK's connection handshake. Install
  // the getter only after initialization to check inventory never reads it.
  Object.defineProperty(transport, 'sessionId', { get() { calls.nativeSession++; return 'NATIVE_HTTP_SESSION_CANARY'; } });
  return { connection, calls, guard, server, transport, peer };
}

test('inventory is a detached, deeply immutable allowlist with no callbacks or transport access', async t => {
  const f = await fixture(t);
  const before = { ...f.calls };
  const inventory = f.connection.inventory();
  const second = f.connection.inventory();
  assert.deepEqual(f.calls, before);
  assert.notEqual(second, inventory);
  assert.notEqual(second.identity, inventory.identity);
  assert.notEqual(second.operations, inventory.operations);
  assert.equal(second.revision, inventory.revision);
  assert.equal(inventory.revision, f.connection.inventoryRevision);
  assert.equal(inventory.authorizationEpoch, f.connection.revision);
  assert.deepEqual(Object.keys(inventory).sort(), ['authorizationEpoch', 'identity', 'metadataRevision', 'metadataState', 'observedAt', 'operations', 'revision', 'schemaVersion', 'sessionId', 'state']);
  assert.deepEqual(Object.keys(inventory.identity).sort(), ['principalId', 'serverId', 'tenantId', 'transportRef']);
  assert.deepEqual(Object.keys(inventory.operations[0]).sort(), ['fingerprint', 'kind', 'name']);
  assert.equal(inventory.schemaVersion, 1);
  assert.equal(inventory.state, 'ready');
  assert.equal(inventory.metadataState, 'current');
  assert.equal(inventory.metadataRevision, 1);
  assert.equal(inventory.operations[0].name, 'mcp:documents:read');
  assert.match(inventory.operations[0].fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(inventory.operations[0].fingerprint, f.connection.registrations[0].fingerprint.slice(7));
  assert.match(inventory.identity.transportRef, /^opaque:[a-f0-9]{64}$/);
  assert.equal(inventory.identity.transportRef, second.identity.transportRef);
  assert.equal(new Date(inventory.observedAt).toISOString(), inventory.observedAt);
  for (const value of [inventory, inventory.identity, inventory.operations, inventory.operations[0]]) assert.ok(Object.isFrozen(value));
  assert.throws(() => { inventory.identity.tenantId = 'other'; }, TypeError);
  assert.throws(() => inventory.operations.push({}), TypeError);
  assert.throws(() => { inventory.operations[0].name = 'other'; }, TypeError);
  const serialized = JSON.stringify(inventory);
  for (const secret of ['TRANSPORT_SECRET', 'TRANSPORT_TOKEN', 'NATIVE_HTTP_SESSION_CANARY', 'DESCRIPTOR_CANARY', 'SCHEMA_CANARY', 'RESULT_CANARY', 'inputSchema', 'remoteName', 'transportIdentity']) assert.equal(serialized.includes(secret), false, secret);
});

test('refresh hides stale operations and increments inventory revision without invalidating ready closures', async t => {
  const f = await fixture(t);
  const ready = f.connection.inventory();
  const pending = f.connection.refresh();
  const refreshing = f.connection.inventory();
  assert.equal(refreshing.state, 'refreshing');
  assert.equal(refreshing.metadataState, 'stale');
  assert.equal(refreshing.metadataRevision, ready.metadataRevision);
  assert.deepEqual(refreshing.operations, []);
  assert.ok(refreshing.revision > ready.revision);
  assert.ok(refreshing.authorizationEpoch > ready.authorizationEpoch);
  await pending;
  const current = f.connection.inventory();
  assert.ok(current.revision > refreshing.revision);
  assert.equal(current.authorizationEpoch, refreshing.authorizationEpoch);
  assert.equal(current.metadataRevision, ready.metadataRevision);
  assert.equal(current.state, 'ready');
  assert.notEqual(current.operations[0].fingerprint, ready.operations[0].fingerprint);
  const registered = f.connection.registrations[0];
  f.guard.approveTool(registered.name, registered.fingerprint);
  const task = f.guard.createTask({ id: 'inventory-refresh', principalId: 'operator', tenantId: 'acme', grants: [{ tool: registered.name, resources: ['report'] }], budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
  await f.guard.execute(await f.guard.prepare(task, { tool: registered.name, args: { id: 'report' } }));
  assert.equal(f.calls.execute, 1);
  assert.equal(ready.state, 'ready');
  assert.equal(ready.operations.length, 1);
});

test('metadata revision changes only when accepted descriptors change, including removal', async t => {
  const f = await fixture(t, {
    setup: server => server.registerTool('other', { inputSchema: fromJsonSchema({ type: 'object' }) }, () => ({ content: [] })),
    connection: { tools: [binding, { ...binding, name: 'other' }] },
  });
  const first = f.connection.inventory();
  const descriptors = f.connection.registrations.map(item => plain(item.descriptor));
  f.server.server.setRequestHandler('tools/list', () => ({ tools: [...descriptors].reverse() }));
  await f.connection.refresh();
  assert.equal(f.connection.inventory().metadataRevision, first.metadataRevision);
  descriptors[0].description = 'CHANGED_DESCRIPTOR_CANARY';
  f.server.server.setRequestHandler('tools/list', () => ({ tools: descriptors }));
  await f.connection.refresh();
  const changed = f.connection.inventory();
  assert.equal(changed.metadataRevision, first.metadataRevision + 1);
  assert.equal(JSON.stringify(changed).includes('CHANGED_DESCRIPTOR_CANARY'), false);
  await f.connection.refresh();
  assert.equal(f.connection.inventory().metadataRevision, changed.metadataRevision);
  f.server.server.setRequestHandler('tools/list', () => ({ tools: [] }));
  await f.connection.refresh();
  const removed = f.connection.inventory();
  assert.equal(removed.state, 'ready');
  assert.equal(removed.metadataState, 'current');
  assert.equal(removed.metadataRevision, changed.metadataRevision + 1);
  assert.deepEqual(removed.operations, []);
});

test('quarantine, rejected refresh and closure retain only the prior metadata revision', async t => {
  const f = await fixture(t);
  const ready = f.connection.inventory();
  await f.peer.send({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  const quarantined = f.connection.inventory();
  assert.equal(quarantined.state, 'quarantined');
  assert.equal(quarantined.metadataState, 'stale');
  assert.deepEqual(quarantined.operations, []);
  assert.equal(quarantined.metadataRevision, ready.metadataRevision);
  assert.ok(quarantined.revision > ready.revision);
  f.server.server.setRequestHandler('tools/list', () => ({ tools: [{ name: 'read', inputSchema: { $ref: 'file:///PRIVATE_SCHEMA_CANARY' } }] }));
  await assert.rejects(f.connection.refresh(), { code: 'REGISTRY_REJECTED' });
  const rejected = f.connection.inventory();
  assert.equal(rejected.state, 'quarantined');
  assert.deepEqual(rejected.operations, []);
  assert.equal(rejected.metadataRevision, ready.metadataRevision);
  assert.ok(rejected.revision > quarantined.revision);
  await f.connection.close();
  const closed = f.connection.inventory();
  assert.equal(closed.state, 'closed');
  assert.equal(closed.metadataState, 'stale');
  assert.deepEqual(closed.operations, []);
  assert.ok(closed.revision > rejected.revision);
  assert.equal(closed.identity.transportRef, ready.identity.transportRef);
  await f.connection.close();
  assert.equal(f.connection.inventory().revision, closed.revision);
});

test('a transport closure is observable and a reconnect has independent session and transport references', async t => {
  const previous = await fixture(t);
  const before = previous.connection.inventory();
  await previous.peer.close();
  const closed = previous.connection.inventory();
  assert.equal(closed.state, 'closed');
  assert.deepEqual(closed.operations, []);
  const next = await fixture(t, { guard: previous.guard });
  const current = next.connection.inventory();
  assert.notEqual(current.sessionId, before.sessionId);
  assert.notEqual(current.identity.transportRef, before.identity.transportRef);
  assert.notEqual(current.operations[0].fingerprint, before.operations[0].fingerprint);
  assert.equal(current.metadataRevision, 1);
  assert.equal(previous.connection.inventory().sessionId, before.sessionId);
  assert.equal(previous.connection.inventory().revision, closed.revision);
});

test('resource and prompt projections expose guarded operation names without remote URIs or descriptors', async t => {
  const uri = 'report://PRIVATE_RESOURCE_URI';
  const f = await fixture(t, {
    setup(server) {
      server.registerResource('REMOTE_RESOURCE_NAME', uri, { description: 'RESOURCE_DESCRIPTOR_CANARY' }, () => ({ contents: [] }));
      server.registerPrompt('summary', { description: 'PROMPT_DESCRIPTOR_CANARY' }, () => ({ messages: [] }));
    },
    connection: { resources: [{ ...binding, name: 'report', uri }], prompts: [{ ...binding, name: 'summary' }] },
  });
  const inventory = f.connection.inventory();
  assert.deepEqual(inventory.operations.map(({ kind, name }) => ({ kind, name })), [
    { kind: 'prompt', name: 'mcp-prompt:documents:summary' },
    { kind: 'resource', name: 'mcp-resource:documents:report' },
    { kind: 'tool', name: 'mcp:documents:read' },
  ]);
  for (const secret of [uri, 'REMOTE_RESOURCE_NAME', 'RESOURCE_DESCRIPTOR_CANARY', 'PROMPT_DESCRIPTOR_CANARY']) assert.equal(JSON.stringify(inventory).includes(secret), false);
});

test('initial connecting state is unobserved and malformed inventory identifiers fail safely', async t => {
  // JavaScript can construct the TypeScript-private class to inspect the otherwise
  // internal connecting state; the public async factory returns only after refresh.
  for (const principalId of ['operator', 'PRIVATE\0IDENTITY', '\ud800', '\u0085', '\u001c']) {
    const [transport] = InMemoryTransport.createLinkedPair();
    const connection = new ManagedMcpConnection({ guard: new AgentGuard(), identity: { ...identity, principalId }, transport });
    t.after(() => connection.close());
    if (principalId !== 'operator') {
      assert.throws(() => connection.inventory(), { code: 'MCP_INVENTORY_INVALID', message: 'MCP_INVENTORY_INVALID' });
      continue;
    }
    const inventory = connection.inventory();
    assert.equal(inventory.state, 'connecting');
    assert.equal(inventory.metadataState, 'unobserved');
    assert.equal(inventory.metadataRevision, 0);
    assert.equal(inventory.revision, 0);
    assert.equal(inventory.authorizationEpoch, 0);
    assert.deepEqual(inventory.operations, []);
    await connection.close();
    assert.equal(connection.inventory().metadataState, 'unobserved');
  }
});

test('invalid observation clocks and fingerprint values fail with stable, sanitized errors', async t => {
  const f = await fixture(t);
  const previousRevision = f.connection.inventoryRevision;
  const originalNow = Date.now;
  try {
    for (const value of [NaN, Infinity, -1, 0.5, 253_402_300_800_000]) {
      Date.now = () => value;
      assert.throws(() => f.connection.inventory(), { code: 'MCP_INVENTORY_CLOCK_INVALID', message: 'MCP_INVENTORY_CLOCK_INVALID' });
    }
  } finally { Date.now = originalNow; }
  assert.equal(f.connection.inventoryRevision, previousRevision);
  const invalid = await fixture(t, { connection: { guard: { registerTool: () => 'PRIVATE_FINGERPRINT_CANARY' } } });
  assert.throws(() => invalid.connection.inventory(), { code: 'MCP_INVENTORY_INVALID', message: 'MCP_INVENTORY_INVALID' });
});

test('a close during host registration cannot publish ready metadata or stale operations', async t => {
  const guard = new AgentGuard();
  let connection; let armed = false;
  const registerTool = guard.registerTool.bind(guard);
  guard.registerTool = definition => {
    const fingerprint = registerTool(definition);
    if (armed) { armed = false; void connection.close(); }
    return fingerprint;
  };
  const f = await fixture(t, { guard }); connection = f.connection;
  const ready = connection.inventory();
  // Arm only after refresh's synchronous unavailable registration completes;
  // the accepted descriptor registration then reenters through a host callback.
  const refresh = connection.refresh(); armed = true;
  await assert.rejects(refresh, { code: 'REGISTRY_REJECTED' });
  const closed = connection.inventory();
  assert.equal(closed.state, 'closed');
  assert.equal(closed.metadataRevision, ready.metadataRevision);
  assert.deepEqual(closed.operations, []);
});
