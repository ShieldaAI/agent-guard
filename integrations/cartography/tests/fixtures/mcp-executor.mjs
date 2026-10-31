// Real executor -> managed MCP -> observer -> Python consumer contract fixture.
// All state, credentials and remote descriptors are disposable synthetic values.
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { ManagedMcpConnection } from '../../../../packages/mcp/dist/index.js';
import { DurableExecutor, composeInventorySnapshot, composeMcpInventorySnapshot,
  createInventoryObserverToken, startInventoryServer } from '../../../../packages/executor/dist/index.js';

const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-mcp-contract-')));
const callbacks = { authorize: 0, register: 0, resolve: 0, execute: 0, send: 0, nativeSession: 0, foreignRead: 0 };
const observationCallbacks = Object.fromEntries(Object.keys(callbacks).map(key => [key, 0]));
let executor, connection, server, observer;
try {
  executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 9),
    clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'mcp-executor', enrollmentGeneration: 'generation' } });
  server = new McpServer({ name: 'documents', version: '1' });
  const schema = { type: 'object', properties: { id: { type: 'string', description: 'private-schema-canary' } }, required: ['id'], additionalProperties: false };
  server.registerTool('read', { description: 'private-descriptor-canary', inputSchema: fromJsonSchema(schema) }, () => {
    callbacks.execute++; throw new Error('Inventory dispatched a remote operation');
  });
  const [transport, peer] = InMemoryTransport.createLinkedPair();
  const originalSend = transport.send.bind(transport);
  transport.send = (...args) => { callbacks.send++; return originalSend(...args); };
  await server.connect(peer);
  connection = await ManagedMcpConnection.connect({
    guard: { registerTool(definition) { callbacks.register++; return executor.registerTool(definition); } },
    identity: { serverId: 'documents', transportIdentity: 'https://user:private-transport-password@private.invalid/mcp?token=private-transport-token', principalId: 'worker', tenantId: 'alpha' },
    transport, authorize: () => { callbacks.authorize++; },
    tools: [{ name: 'read', requiresApproval: true,
      resolve() { callbacks.resolve++; throw new Error('Inventory called an authorization resolver'); } }],
  });
  // Setting this before connect makes the SDK resume an existing HTTP session.
  // After initialization it is a canary for accidental transport/session reads.
  Object.defineProperty(transport, 'sessionId', { get() { callbacks.nativeSession++; return 'private-native-session-canary'; } });
  const registration = connection.registrations[0];
  executor.approveTool(registration.name, registration.fingerprint);
  const root = executor.createTask({ id: 'mcp-task', principalId: 'worker', tenantId: 'alpha',
    grants: [{ tool: registration.name, resources: ['https://user:private-resource-password@private.invalid/report'] }],
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: 100_000 } });
  executor.createTask({ id: 'private-beta-task', principalId: 'private-beta-principal', tenantId: 'beta',
    grants: [{ tool: 'private-beta-tool', resources: ['private-beta-resource'] }],
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: 100_000 } });
  const core = executor.inventorySnapshot({ tenantId: 'alpha' });
  const manifest = {
    schemaVersion: 1, evidenceKind: 'host_asserted', source: { ...core.source },
    manifestId: 'mcp-manifest', revision: 1, observedAt: '2026-10-30T00:00:00Z',
    agents: [{ id: 'research-agent', name: 'Research worker', ownerId: null, teamId: 'research-team' }],
    deployments: [{ id: 'research-deployment', agentId: 'research-agent', environment: 'test' }],
    taskBindings: [{ taskId: 'mcp-task', deploymentId: 'research-deployment' }],
    resourceBindings: [],
    executionBindings: [{ id: 'mcp-execution', tool: registration.name, deploymentId: 'research-deployment',
      connectionId: 'documents-mcp', identitySelection: 'static',
      identity: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
        arn: 'arn:aws:iam::111122223333:role/McpReader' } }],
  };
  const sources = [
    { tenantId: 'alpha', connectionId: 'documents-mcp', source: connection },
    { tenantId: 'beta', connectionId: 'documents-mcp', source: { inventory() { callbacks.foreignRead++; throw new Error('Cross-tenant inventory read'); } } },
    { tenantId: 'alpha', connectionId: 'unbound-connection', source: { inventory() { callbacks.foreignRead++; throw new Error('Unbound inventory read'); } } },
  ];
  function observe(operation) {
    const before = { ...callbacks };
    const value = operation();
    for (const name of Object.keys(callbacks)) observationCallbacks[name] += callbacks[name] - before[name];
    assert.deepEqual(callbacks, before, 'Observation invoked a managed callback');
    return value;
  }
  const capture = (bindings = sources) => observe(() => composeMcpInventorySnapshot(
    composeInventorySnapshot(executor.inventorySnapshot({ tenantId: 'alpha' }), manifest), bindings));
  const standalone = observe(() => connection.inventory());
  const ready = capture();
  assert.equal(Object.isFrozen(ready.mcp.connections[0].inventory.operations[0]), true);
  assert.throws(() => { ready.mcp.connections[0].inventory.identity.tenantId = 'beta'; }, TypeError);
  for (const field of ['tasks', 'tools', 'ledgerRevision', 'policyEpoch']) assert.deepEqual(ready[field], core[field]);
  const missing = capture([]);
  assert.deepEqual({ ...missing.mcp.connections[0] }, { connectionId: 'documents-mcp', status: 'unavailable', reason: 'missing' });

  const mcpToken = createInventoryObserverToken(), coreToken = createInventoryObserverToken();
  observer = await startInventoryServer({ executor, manifests: [manifest], mcpSources: sources, observers: [
    { token: mcpToken, tenantIds: ['alpha'], profile: 'host-mcp' },
    { token: coreToken, tenantIds: ['alpha'], profile: 'core' },
  ] });
  const request = async (token, input) => {
    const response = await fetch(`${observer.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(input), signal: AbortSignal.timeout(5000) });
    const bytes = Buffer.from(await response.arrayBuffer());
    return { status: response.status, cacheControl: response.headers.get('cache-control'),
      contentLength: response.headers.get('content-length'), byteLength: bytes.byteLength,
      body: JSON.parse(bytes.toString('utf8')) };
  };
  const beforeHttp = { ...callbacks };
  const observedMcp = await request(mcpToken, { tenantId: 'alpha' });
  const observedCore = await request(coreToken, { tenantId: 'alpha' });
  const forbidden = await request(mcpToken, { tenantId: 'beta' });
  const override = await request(coreToken, { tenantId: 'alpha', profile: 'host-mcp' });
  assert.deepEqual(callbacks, beforeHttp, 'Observer invoked a managed callback');
  assert.equal(observedMcp.status, 200);
  const after = executor.inventorySnapshot({ tenantId: 'alpha' });
  for (const field of ['tasks', 'tools', 'ledgerRevision', 'policyEpoch']) assert.deepEqual(after[field], core[field]);

  await peer.send({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  const quarantined = capture();
  const changedDescriptor = { ...registration.descriptor, description: 'private-changed-descriptor-canary' };
  server.server.setRequestHandler('tools/list', () => ({ tools: [changedDescriptor] }));
  await connection.refresh();
  const refreshed = capture();
  server.server.setRequestHandler('tools/list', () => ({ tools: [] }));
  await connection.refresh();
  const removed = capture();
  await connection.close();
  const closed = capture();
  assert.equal(callbacks.resolve, 0); assert.equal(callbacks.execute, 0); assert.equal(callbacks.foreignRead, 0);
  const output = JSON.stringify({ core, standalone, ready, quarantined, refreshed, removed, closed, missing,
    observedMcp, observedCore, forbidden, override, after, observationCallbacks });
  for (const secret of [root.token, mcpToken, coreToken, 'private-', 'transportIdentity', 'remoteName', 'inputSchema']) {
    assert.equal(output.includes(secret), false, 'Private metadata reached MCP inventory output');
  }
  process.stdout.write(output);

} finally {
  try { await observer?.close(); }
  finally {
    try { await connection?.close(); await server?.close(); }
    finally { executor?.close(); rmSync(directory, { recursive: true, force: true }); }
  }
}
