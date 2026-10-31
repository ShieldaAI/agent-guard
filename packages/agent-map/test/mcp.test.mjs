import assert from 'node:assert/strict';
import test from 'node:test';
import { Client, InMemoryTransport, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { MAP_OPERATIONS, MapService, createMapMcpServer, createMapToken, startMapServer } from '../dist/index.js';

const scope = { subject: 'reference-client', companyId: 'acme', tenantIds: ['one'], teamIds: ['blue'], allTeams: false };
test('official MCP client receives the same scoped evidence as HTTP', async t => {
  const calls = [];
  const service = new MapService({ read: async value => { calls.push(value); return { sources: [] }; } }, { clock: () => 1000 });
  const token = createMapToken();
  const http = await startMapServer({ service, credentials: [{ token, scope }] });
  const client = new Client({ name: 'map-test', version: '1' });
  t.after(async () => { await client.close(); await http.close(); });
  const transport = new StreamableHTTPClientTransport(new URL(http.url + '/mcp'), {
    requestInit: { headers: { Authorization: `Bearer ${token}` }, redirect: 'error' },
  });
  await client.connect(transport);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name).sort(), [...MAP_OPERATIONS].sort());
  for (const tool of listed.tools) {
    assert.equal(tool.annotations.readOnlyHint, true); assert.equal(tool.annotations.destructiveHint, false);
    assert.equal(tool.inputSchema.additionalProperties, false);
    assert.equal(tool.inputSchema.properties.scope, undefined);
  }
  const mcp = await client.callTool({ name: 'list_agents', arguments: {} });
  const rest = await fetch(http.url + '/v1/query', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ operation: 'list_agents', args: {} }) });
  assert.equal(rest.status, 200); assert.equal(mcp.isError, undefined);
  assert.deepEqual(JSON.parse(mcp.content[0].text), await rest.json());
  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [scope, scope]);
  const invalid = await client.callTool({ name: 'list_agents', arguments: { scope: { allTeams: true } } });
  assert.equal(invalid.isError, true); assert.equal(calls.length, 2);
  const missing = await client.callTool({ name: 'get_agent_access', arguments: { sourceId: 'hidden', agentId: 'hidden' } });
  assert.equal(missing.isError, true); assert.equal(missing.content[0].text, '{"error":"MAP_NOT_FOUND"}');
});
test('read-only MCP factory binds a detached scope and sanitizes backend exceptions', async t => {
  const copy = structuredClone(scope); const received = [];
  const service = new MapService({ read: async value => { received.push(value); throw new Error('private database details'); } });
  const server = createMapMcpServer(service, copy); copy.tenantIds.push('forbidden');
  const client = new Client({ name: 'map-memory', version: '1' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(b); await client.connect(a);
  const result = await client.callTool({ name: 'get_inventory_health', arguments: {} });
  assert.equal(result.isError, true); assert.equal(result.content[0].text, '{"error":"MAP_UNAVAILABLE"}');
  assert.deepEqual(JSON.parse(JSON.stringify(received)), [scope]);
});
test('MCP HTTP denies arbitrary methods, unauthenticated discovery and protocol batches', async t => {
  let reads = 0; const token = createMapToken();
  const http = await startMapServer({ service: new MapService({ read: async () => { reads++; return { sources: [] }; } }), credentials: [{ token, scope }] });
  t.after(() => http.close());
  for (const method of ['resources/read', 'tools/execute', 'sampling/createMessage', 'run_cypher', 'notifications/cancelled']) {
    const response = await fetch(http.url + '/mcp', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: {} }) });
    assert.equal(response.status, 403);
  }
  const denied = await fetch(http.url + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
  assert.equal(denied.status, 401);
  const batch = await fetch(http.url + '/mcp', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: '[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]' });
  assert.equal(batch.status, 400); assert.equal(reads, 0);
});
test('MCP scopes are selected anew for each authenticated request despite a reused session header', async t => {
  const calls = [], tokenA = createMapToken(), tokenB = createMapToken();
  const second = { ...scope, subject: 'other-reader', companyId: 'other-company', tenantIds: ['two'], teamIds: ['red'] };
  const service = new MapService({ read: async value => { calls.push(value); return { sources: [] }; } });
  const http = await startMapServer({ service, credentials: [{ token: tokenA, scope }, { token: tokenB, scope: second }] });
  t.after(() => http.close());
  for (const token of [tokenA, tokenB, tokenA]) {
    const response = await fetch(http.url + '/mcp', { method: 'POST', headers: { Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json', 'Mcp-Session-Id': 'same-client-session', 'Mcp-Protocol-Version': '2025-06-18' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_agents', arguments: {},
        _meta: { companyId: 'attempted-override', scope: { allTeams: true } } } }) });
    assert.equal(response.status, 200);
    const wire = await response.text();
    const message = response.headers.get('content-type')?.includes('text/event-stream')
      ? JSON.parse(wire.split('\n').find(line => line.startsWith('data: ')).slice(6)) : JSON.parse(wire);
    assert.equal(message.result.isError, undefined);
  }
  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [scope, second, scope]);
});

test('HTTP and official MCP clients receive identical bounded policy evidence and safe failures', async t => {
  const now = Date.parse('2026-10-30T00:00:00Z');
  const nodes = [
    ['agent', 'GuardAgent', { agent_id: 'reader', name: 'Reader', team_id: 'blue' }],
    ['deployment', 'GuardDeployment', { deployment_id: 'deployment' }],
    ['task', 'GuardTask', { task_id: 'task', revoked: false }],
    ['grant', 'GuardGrant', { task_id: 'task', tool: 'reports.read', resources: ['report'] }],
    ['tool', 'GuardTool', { name: 'reports.read', known_metadata: true, registered: true, approved: true }],
    ['resource', 'GuardResource', { resource_id: 'report', tool: 'reports.read' }],
    ['binding', 'GuardResourceBinding', { binding_id: 'binding', tool: 'reports.read', resource_ref: 'report', actions: ['s3:GetObject'], scope: 'exact' }],
    ['execution', 'GuardExecutionBinding', { binding_id: 'execution', tool: 'reports.read', identity_selection: 'static' }],
    ['identity', 'GuardExternalIdentity', { arn: 'arn:aws:iam::111122223333:role/Reader' }],
    ['external', 'GuardExternalResource', { arn: 'arn:aws:s3:::reports/one.txt', kind: 'object' }],
  ].map(([id, label, properties]) => ({ id, entityId: `e:${id}`, label, sourceId: 'source', projectionId: 'projection', properties }));
  const edges = [
    ['deployment', 'agent', 'G_INSTANCE_OF'], ['task', 'deployment', 'G_ASSIGNED_TO'],
    ['task', 'grant', 'G_HAS_GRANT'], ['grant', 'tool', 'G_FOR_TOOL'], ['grant', 'resource', 'G_TARGETS'],
    ['binding', 'resource', 'G_BINDS_SELECTOR'], ['binding', 'external', 'G_MAPS_TO'],
    ['execution', 'deployment', 'G_EXECUTES_FOR'], ['execution', 'tool', 'G_EXECUTES_TOOL'], ['execution', 'identity', 'G_USES_IDENTITY'],
  ].map(([source, target, kind]) => ({ source, target, kind }));
  const record = { taskId: 'e:task', deploymentId: 'e:deployment', executionBindingId: 'e:execution', resourceBindingId: 'e:binding',
    identityId: 'e:identity', resourceId: 'e:external', action: 's3:GetObject', status: 'complete', reason: null,
    observedAt: new Date(now).toISOString(), assessment: 'unknown',
    candidates: [{ relationship: 'CAN_READ', hasCondition: true, conditionKeys: ['aws:PrincipalTag/team'], resourceScope: 'bucket_summary' }] };
  const current = { id: 'projection', snapshotId: 'snapshot', generatedAt: new Date(now).toISOString(), status: 'published',
    nodes, edges, coverage: {}, policyEvidence: [record] };
  const scopes = [];
  const service = new MapService({ async read(value) { scopes.push(value); return { sources: [{ id: 'source', sourceId: 'installation',
    tenantId: 'one', profile: 'host', current, previous: null }] }; } }, { clock: () => now });
  const token = createMapToken(), http = await startMapServer({ service, credentials: [{ token, scope }] });
  const client = new Client({ name: 'policy-map-test', version: '1' });
  t.after(async () => { await client.close(); await http.close(); });
  await client.connect(new StreamableHTTPClientTransport(new URL(http.url + '/mcp'), {
    requestInit: { headers: { Authorization: `Bearer ${token}` }, redirect: 'error' },
  }));
  const rest = async (operation, args) => fetch(http.url + '/v1/query', { method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ operation, args }) });
  for (const [status, reason] of [['complete', null], ['unavailable', 'stale'], ['not_collected', 'disabled']]) {
    current.policyEvidence = [{ ...record, status, reason, candidates: status === 'complete' ? record.candidates : [],
      observedAt: status === 'not_collected' ? null : record.observedAt }];
    for (const [operation, args] of [['get_agent_access', { sourceId: 'source', agentId: 'reader' }],
      ['explain_access', { sourceId: 'source', taskId: 'task', tool: 'reports.read', resourceId: 'report' }]]) {
      const response = await rest(operation, args), mcp = await client.callTool({ name: operation, arguments: args });
      assert.equal(response.status, 200); assert.equal(mcp.isError, undefined);
      const value = await response.json();
      assert.deepEqual(JSON.parse(mcp.content[0].text), value);
      const evidence = operation === 'get_agent_access' ? value.data.policyEvidence : value.data.externalEvidence.policyEvidence;
      assert.equal(evidence[0].status, status); assert.equal(evidence[0].assessment, 'unknown');
      assert.equal(value.data.assessment, 'unknown');
    }
  }
  current.policyEvidence[0].rawPolicy = 'private-policy-canary';
  const args = { sourceId: 'source', agentId: 'reader' };
  const failed = await rest('get_agent_access', args), mcp = await client.callTool({ name: 'get_agent_access', arguments: args });
  assert.equal(failed.status, 503); assert.equal(await failed.text(), '{"error":"MAP_UNAVAILABLE"}');
  assert.equal(mcp.isError, true); assert.equal(mcp.content[0].text, '{"error":"MAP_UNAVAILABLE"}');
  assert.ok(scopes.length >= 14);
  for (const received of scopes) assert.deepEqual(JSON.parse(JSON.stringify(received)), scope);
});
