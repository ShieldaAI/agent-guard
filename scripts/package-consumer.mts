import assert from 'node:assert/strict';
import { MapService, createMapMcpServer, createMapToken, startMapServer, startMapIdentityServer,
  validateReadScope, type MapStore, type MapPolicyEvidence, type MapProjection,
  type MapNode, type MapEdge, type MapIdentityServerOptions, type MapIdentityServer, type MapOidcOptions } from '@shieldaai/agent-map';
import { AgentGuard, GuardError, GuardErrorCode, type GuardOptions, type Json } from '@shieldaai/agent-guard';
import { ManagedMcpConnection, registerMcpTool, type McpToolClient, type McpConnectionInventory } from '@shieldaai/agent-guard-mcp';
import { runConformance, scenarioCatalog, type GuardLike } from '@shieldaai/agent-guard-scenarios';
import { ArtifactBroker, DurableExecutor, createRestrictedFetch, createModelTool, validateSandboxProfile, createSandboxTool,
  createInventoryObserverToken, startInventoryServer,
  validateInventoryManifest, composeInventorySnapshot,
  validateMcpConnectionInventory, validateMcpInventorySources, composeMcpInventorySnapshot, type McpInventorySnapshot,
  type InventoryManifest, type HostInventorySnapshot, type InventoryOptions, type InventorySnapshot,
  type InventoryTask, type InventoryServerOptions } from '@shieldaai/agent-guard-executor';

const calls: Array<{ name: string; arguments: Record<string, Json> }> = [];
const client: McpToolClient = {
  async callTool(request, { signal }) {
    assert.equal(signal.aborted, false);
    calls.push(request);
    return { content: [{ type: 'text', text: 'Public report' }] };
  },
};
const guard = new AgentGuard();
const registered = registerMcpTool(guard, {
  serverId: 'packed-documents',
  tool: { name: 'read', inputSchema: { type: 'object' } },
  client,
  resolve(args) {
    assert.equal(typeof args.id, 'string');
    return { resourceId: args.id as string, tenantId: 'pack-test' };
  },
});
guard.approveTool(registered.name, registered.fingerprint);
const task = guard.createTask({
  id: 'packed-consumer', principalId: 'host', tenantId: 'pack-test',
  grants: [{ tool: registered.name, resources: ['public-report'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
await assert.rejects(
  guard.prepare(task, { tool: registered.name, args: { id: 'private-report' } }),
  error => error instanceof GuardError && error.code === GuardErrorCode.GRANT_DENIED,
);
assert.equal(calls.length, 0);
const args = { id: 'public-report' };
const prepared = await guard.prepare(task, { tool: registered.name, args });
args.id = 'private-report';
assert.deepEqual(JSON.parse(JSON.stringify(await guard.execute(prepared))), { content: [{ type: 'text', text: 'Public report' }] });
assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ name: 'read', arguments: { id: 'public-report' } }]);
assert.equal(Object.isFrozen(calls[0]?.arguments), true);

const createGuard = (options: GuardOptions): GuardLike => new AgentGuard(options);
const report = await runConformance({ createGuard });
assert.equal(report.passed, true, JSON.stringify(report));
assert.equal(report.scenarioCount, scenarioCatalog.length);
assert.equal(report.caseCount, scenarioCatalog.length * 2);
console.log('Packed declarations and README examples compiled; MCP dispatch and all conformance scenarios passed.');

const inventory: InventoryOptions = { companyId: 'pack-test', sourceId: 'installed-consumer', enrollmentGeneration: 'one' };
const durable = new DurableExecutor({ database: ':memory:', encryptionKey: new Uint8Array(32), inventory });
const model = createModelTool({ name: 'model', model: 'fixture', tenantId: 'pack-test', recipient: 'fixture-provider',
  maxCost: 2, maxOutputTokens: 10, complete: async () => ({ response: { text: 'accepted' }, actualCost: 1 }) });
durable.approveTool('model', durable.registerTool(model));
const scoped = durable.createTask({ id: 'durable-consumer', principalId: 'host', tenantId: 'pack-test',
  grants: [{ tool: 'model', resources: ['fixture'] }], allowedRecipients: ['fixture-provider'],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 2, deadline: Date.now() + 60_000 } });
assert.equal(durable.authenticate(scoped.token), scoped.taskId);
const modelAction = await durable.prepare(scoped.taskId, { tool: 'model', args: { prompt: 'public', maxOutputTokens: 10 } });
assert.equal((await durable.execute(scoped.taskId, modelAction.id) as {text: string}).text, 'accepted');
assert.equal(durable.snapshot(scoped.taskId).spent, 1);
const inventorySnapshot: InventorySnapshot = durable.inventorySnapshot({ tenantId: 'pack-test' });
const inventoryTask: InventoryTask = inventorySnapshot.tasks[0]!;
assert.equal(inventorySnapshot.schemaVersion, 1);
assert.equal(inventoryTask.id, scoped.taskId);
assert.equal(inventoryTask.usage.spent, 1);
assert.match(inventoryTask.grants[0]!.resources[0]!, /^opaque:[a-f0-9]{64}$/);
assert.equal(Object.isFrozen(inventoryTask), true);
const manifest: InventoryManifest = validateInventoryManifest({ schemaVersion: 1, evidenceKind: 'host_asserted',
  source: inventorySnapshot.source, manifestId: 'consumer-manifest', revision: 1, observedAt: inventorySnapshot.generatedAt,
  agents: [{ id: 'consumer-agent', name: 'Installed consumer', ownerId: null, teamId: null }],
  deployments: [{ id: 'consumer-deployment', agentId: 'consumer-agent', environment: 'test' }],
  taskBindings: [{ taskId: inventoryTask.id, deploymentId: 'consumer-deployment' }], resourceBindings: [], executionBindings: [] });
const composed: HostInventorySnapshot = composeInventorySnapshot(inventorySnapshot, manifest);
assert.equal(composed.profile, 'host');
assert.deepEqual(composed.tasks, inventorySnapshot.tasks);
assert.equal(Object.isFrozen(composed.manifest.agents), true);
assert.equal(typeof ManagedMcpConnection.prototype.inventory, 'function');
const connection: McpConnectionInventory = { schemaVersion: 1,
  identity: { serverId: 'consumer', transportRef: `opaque:${'a'.repeat(64)}`, principalId: 'host', tenantId: 'pack-test' },
  sessionId: 'consumer-session', revision: 1, authorizationEpoch: 1, metadataRevision: 0,
  state: 'closed', metadataState: 'unobserved', observedAt: inventorySnapshot.generatedAt, operations: [] };
assert.equal(validateMcpConnectionInventory(connection).state, 'closed');
const mcpSources = validateMcpInventorySources([{ tenantId: 'pack-test', connectionId: 'consumer',
  source: { inventory: () => connection } }]);
const mcpComposed: McpInventorySnapshot = composeMcpInventorySnapshot(composed, mcpSources);
assert.equal(mcpComposed.profile, 'host-mcp');
assert.equal(mcpComposed.coverage.mcp.status, 'complete');
assert.equal(mcpComposed.mcp.connections.length, 0);
const observerToken = createInventoryObserverToken();
const hostToken = createInventoryObserverToken();
const mcpToken = createInventoryObserverToken();
const observerOptions: InventoryServerOptions = { executor: durable,
  observers: [{ token: observerToken, tenantIds: ['pack-test'], profile: 'core' },
    { token: hostToken, tenantIds: ['pack-test'], profile: 'host' },
    { token: mcpToken, tenantIds: ['pack-test'], profile: 'host-mcp' }], manifests: [manifest], mcpSources };
const observer = await startInventoryServer(observerOptions);
try {
  const response = await fetch(`${observer.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${observerToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'pack-test' }) });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const observed = await response.json() as InventorySnapshot;
  assert.equal(observed.source.inventoryInstanceId, inventorySnapshot.source.inventoryInstanceId);
  assert.equal(observed.ledgerRevision, inventorySnapshot.ledgerRevision);
  const hostResponse = await fetch(`${observer.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${hostToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'pack-test' }) });
  assert.equal(hostResponse.status, 200);
  const hostInventory = await hostResponse.json() as HostInventorySnapshot;
  assert.equal(hostInventory.profile, 'host');
  assert.equal(hostInventory.manifest.manifestId, manifest.manifestId);
  assert.equal(hostInventory.ledgerRevision, observed.ledgerRevision);
  const mcpResponse = await fetch(`${observer.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${mcpToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'pack-test' }) });
  assert.equal(mcpResponse.status, 200);
  const mcpInventory = await mcpResponse.json() as McpInventorySnapshot;
  assert.equal(mcpInventory.profile, 'host-mcp');
  assert.equal(mcpInventory.coverage.mcp.status, 'complete');
} finally { await observer.close(); }
assert.equal(typeof createRestrictedFetch({ allowedOrigins: [] }), 'function');
assert.throws(() => validateSandboxProfile({ image: 'unreviewed:latest' }));
durable.close();
const artifacts = new ArtifactBroker({ key: new Uint8Array(32), keyId: 'consumer' });
const bytes = new TextEncoder().encode('fixture');
const receipt = artifacts.classifyArtifact({ content: bytes, path: 'fixture.txt', tenantId: 'pack-test', origin: 'consumer' });
assert.equal(artifacts.verifyArtifact(receipt, bytes, 'pack-test').sensitivity, 'sensitive');
assert.equal(typeof createSandboxTool, 'function');
artifacts.close();
const mapStore: MapStore = { async read(scope) { assert.equal(scope.companyId, 'pack-test'); return { sources: [] }; } };
const mapService = new MapService(mapStore);
const mapScope = validateReadScope({ subject: 'consumer', companyId: 'pack-test', tenantIds: ['pack-test'], teamIds: ['platform'], allTeams: false });
const mapToken = createMapToken();
const mapServer = await startMapServer({ service: mapService, credentials: [{ token: mapToken, scope: mapScope }] });
try {
  const response = await fetch(`${mapServer.url}/v1/query`, { method: 'POST',
    headers: { authorization: `Bearer ${mapToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ operation: 'list_agents', args: {} }) });
  assert.equal(response.status, 200);
  assert.equal((await response.json() as { operation: string }).operation, 'list_agents');
} finally { await mapServer.close(); }
const mapMcp = createMapMcpServer(mapService, mapScope); await mapMcp.close();
const policyEvidence: MapPolicyEvidence = { taskId: 'task', deploymentId: 'deployment',
  executionBindingId: 'execution', resourceBindingId: 'binding', identityId: 'identity', resourceId: 'external',
  action: 's3:GetObject', status: 'complete', reason: null, observedAt: new Date().toISOString(),
  assessment: 'unknown', candidates: [{ relationship: 'CAN_READ', hasCondition: true,
    conditionKeys: ['aws:PrincipalTag/team'], resourceScope: 'bucket_summary' }] };
const policyNode = (id: string, label: MapNode['label'], properties: MapNode['properties']): MapNode =>
  ({ id, entityId: id, label, sourceId: 'source', projectionId: 'projection', properties });
const policyEdge = (source: string, target: string, kind: MapEdge['kind']): MapEdge => ({ source, target, kind });
const policyProjection: MapProjection = { id: 'projection', snapshotId: 'snapshot',
  generatedAt: policyEvidence.observedAt!, status: 'published', coverage: {}, policyEvidence: [policyEvidence],
  nodes: [policyNode('agent', 'GuardAgent', { agent_id: 'agent', team_id: 'platform' }),
    policyNode('deployment', 'GuardDeployment', { deployment_id: 'deployment' }),
    policyNode('task', 'GuardTask', { task_id: 'task' }),
    policyNode('grant', 'GuardGrant', { task_id: 'task', tool: 'read', resources: ['report'] }),
    policyNode('tool', 'GuardTool', { name: 'read' }),
    policyNode('resource', 'GuardResource', { resource_id: 'report', tool: 'read' }),
    policyNode('binding', 'GuardResourceBinding', { binding_id: 'binding', tool: 'read', resource_ref: 'report', actions: ['s3:GetObject'], scope: 'exact' }),
    policyNode('execution', 'GuardExecutionBinding', { binding_id: 'execution', tool: 'read', identity_selection: 'static' }),
    policyNode('identity', 'GuardExternalIdentity', { arn: 'arn:aws:iam::111122223333:role/Reader' }),
    policyNode('external', 'GuardExternalResource', { arn: 'arn:aws:s3:::reports/one.txt', kind: 'object' })],
  edges: [policyEdge('deployment', 'agent', 'G_INSTANCE_OF'), policyEdge('task', 'deployment', 'G_ASSIGNED_TO'),
    policyEdge('task', 'grant', 'G_HAS_GRANT'), policyEdge('grant', 'tool', 'G_FOR_TOOL'),
    policyEdge('grant', 'resource', 'G_TARGETS'), policyEdge('binding', 'resource', 'G_BINDS_SELECTOR'),
    policyEdge('binding', 'external', 'G_MAPS_TO'), policyEdge('execution', 'deployment', 'G_EXECUTES_FOR'),
    policyEdge('execution', 'tool', 'G_EXECUTES_TOOL'), policyEdge('execution', 'identity', 'G_USES_IDENTITY')] };
const policyService = new MapService({ async read() { return { sources: [{ id: 'source', sourceId: 'installation',
  tenantId: 'pack-test', profile: 'host', current: policyProjection, previous: null }] }; } });
const policyResult = await policyService.query(mapScope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
assert.deepEqual(JSON.parse(JSON.stringify(policyResult.data.policyEvidence)), [policyEvidence]);
assert.equal(policyResult.data.assessment, 'unknown');
const identityFactory: (options: MapIdentityServerOptions) => Promise<MapIdentityServer> = startMapIdentityServer;
const provider: MapOidcOptions = { issuer: 'https://identity.example', clientId: 'map', clientSecret: 'test-only',
  redirectUri: 'https://map.example/auth/callback' };
assert.equal(typeof identityFactory, 'function');
assert.equal(provider.redirectUri, 'https://map.example/auth/callback');
console.log('Packed executor admission, model adapter, observer HTTP transport and public exports passed.');
console.log('Packed reference service, scoped HTTP/MCP and policy-evidence contract passed.');
