import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService, MAP_OPERATIONS, MAP_INPUT_SCHEMAS, validateQueryArguments } from '../dist/service.js';
import { MapQueryError } from '../dist/types.js';

const NOW = Date.parse('2030-01-02T00:00:00Z');
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['alpha'], teamIds: ['team-one'], allTeams: false };
const plain = value => JSON.parse(JSON.stringify(value));
function fixture() {
  const nodes = [];
  const node = (id, label, properties) => { nodes.push({ id, entityId: `entity:${id}`, label, sourceId: 'source', projectionId: 'current', properties }); return id; };
  node('agent', 'GuardAgent', { agent_id: 'reader-agent', name: '<script>private()</script>', team_id: 'team-one', owner_id: 'owner' });
  node('deployment', 'GuardDeployment', { deployment_id: 'reader-prod', environment: 'production' });
  const task = { principal_id: 'application', revoked: false, sensitive: false, allow_control_plane: false,
    max_calls: 10, max_concurrent: 2, max_cost: 100, deadline: NOW + 60_000, calls: 1, concurrent: 0, spent: 5, reserved: 0 };
  node('task', 'GuardTask', { ...task, task_id: 'reader-task' });
  node('parent', 'GuardTask', { ...task, task_id: 'reader-parent' });
  node('provenance', 'GuardTask', { ...task, task_id: 'provenance-only', revoked: true });
  node('principal', 'GuardPrincipal', { principal_id: 'application' });
  node('tool', 'GuardTool', { name: 'reports.read', fingerprint: 'a'.repeat(64), revision: 1,
    known_metadata: true, registered: true, approved: true, requires_approval: true, control_plane: false, max_cost: 2 });
  node('grant', 'GuardGrant', { task_id: 'reader-task', tool: 'reports.read', resources: ['report'] });
  node('parent-grant', 'GuardGrant', { task_id: 'reader-parent', tool: 'reports.read', resources: ['report'] });
  node('resource', 'GuardResource', { resource_id: 'report', tool: 'reports.read', selector_kind: 'exact' });
  node('resource-binding', 'GuardResourceBinding', { binding_id: 'object-binding', tool: 'reports.read',
    resource_ref: 'report', actions: ['s3:GetObject'], scope: 'exact' });
  node('external-resource', 'GuardExternalResource', { provider: 'aws', account_id: '111122223333', partition: 'aws',
    arn: 'arn:aws:s3:::reports/one.txt', kind: 'object', region: '', cloud_match_kind: 'containment', cloud_status: 'resolved' });
  node('execution', 'GuardExecutionBinding', { binding_id: 'execution-one', tool: 'reports.read', connection_id: 'documents', identity_selection: 'static' });
  node('identity', 'GuardExternalIdentity', { arn: 'arn:aws:iam::111122223333:role/Reader', account_id: '111122223333', partition: 'aws', provider: 'aws', region: '' });
  node('connection', 'GuardMcpConnection', { connection_id: 'documents', state: 'ready', capture_status: 'observed', metadata_state: 'current' });
  node('operation', 'GuardMcpOperation', { name: 'reports.read', kind: 'tool', fingerprint: 'a'.repeat(64) });
  node('other-agent', 'GuardAgent', { agent_id: 'writer-agent', name: 'Writer', team_id: 'team-one', owner_id: 'second-owner' });
  node('other-deployment', 'GuardDeployment', { deployment_id: 'writer-dev', environment: 'development' });
  node('other-execution', 'GuardExecutionBinding', { binding_id: 'execution-two', tool: 'reports.read', connection_id: null, identity_selection: 'static' });
  node('other-identity', 'GuardExternalIdentity', { arn: 'other-execution-identity-canary' });
  const edges = [];
  const edge = (source, target, kind) => edges.push({ source, target, kind });
  edge('deployment', 'agent', 'G_INSTANCE_OF');
  edge('task', 'deployment', 'G_ASSIGNED_TO'); edge('parent', 'deployment', 'G_ASSIGNED_TO');
  edge('task', 'principal', 'G_ACTS_AS'); edge('parent', 'principal', 'G_ACTS_AS');
  edge('task', 'parent', 'G_DELEGATED_FROM'); edge('task', 'provenance', 'G_DERIVED_FROM');
  edge('task', 'grant', 'G_HAS_GRANT'); edge('parent', 'parent-grant', 'G_HAS_GRANT');
  for (const id of ['grant', 'parent-grant']) { edge(id, 'tool', 'G_FOR_TOOL'); edge(id, 'resource', 'G_TARGETS'); }
  edge('resource-binding', 'resource', 'G_BINDS_SELECTOR'); edge('resource-binding', 'external-resource', 'G_MAPS_TO');
  edge('execution', 'deployment', 'G_EXECUTES_FOR'); edge('execution', 'tool', 'G_EXECUTES_TOOL');
  edge('execution', 'identity', 'G_USES_IDENTITY'); edge('execution', 'connection', 'G_VIA_CONNECTION');
  edge('connection', 'operation', 'G_EXPOSES_OPERATION'); edge('operation', 'tool', 'G_OPERATION_TOOL');
  edge('other-deployment', 'other-agent', 'G_INSTANCE_OF'); edge('other-execution', 'other-deployment', 'G_EXECUTES_FOR');
  edge('other-execution', 'tool', 'G_EXECUTES_TOOL'); edge('other-execution', 'other-identity', 'G_USES_IDENTITY');
  const current = { id: 'current', snapshotId: 'snapshot-current', generatedAt: new Date(NOW - 10_000).toISOString(),
    status: 'published', nodes, edges, coverage: { tasks: { status: 'visible_scope' }, mcp: { status: 'observed' } } };
  const previous = structuredClone(current);
  previous.id = 'previous'; previous.snapshotId = 'snapshot-previous'; previous.generatedAt = new Date(NOW - 60_000).toISOString();
  previous.nodes.forEach(node => { node.id = `old:${node.id}`; node.projectionId = 'previous'; });
  previous.edges.forEach(edge => { edge.source = `old:${edge.source}`; edge.target = `old:${edge.target}`; });
  const source = { id: 'source', sourceId: 'executor-one', tenantId: 'alpha', profile: 'host-mcp', current, previous };
  const reads = [];
  const store = { async read(receivedScope, request) { reads.push({ scope: receivedScope, request });
    return { sources: request?.sourceId && request.sourceId !== source.id ? [] : [source] }; } };
  const service = new MapService(store, { clock: () => NOW });
  return { source, nodes, edges, reads, store, service };
}
const explainArgs = { sourceId: 'source', taskId: 'reader-task', tool: 'reports.read', resourceId: 'report' };

test('one closed input schema defines each HTTP/MCP operation', () => {
  assert.deepEqual(Object.keys(MAP_INPUT_SCHEMAS), MAP_OPERATIONS);
  for (const operation of MAP_OPERATIONS) {
    assert.equal(MAP_INPUT_SCHEMAS[operation].additionalProperties, false);
    assert.equal(Object.isFrozen(MAP_INPUT_SCHEMAS[operation]), true);
  }
  assert.deepEqual(plain(validateQueryArguments('get_inventory_health', {})), {});
  const action = 'execute-api:Invoke';
  assert.equal(validateQueryArguments('find_agents_with_access', { resourceRef: 'api', action }).action, action);
  assert.match(action, new RegExp(MAP_INPUT_SCHEMAS.find_agents_with_access.properties.action.pattern));
});

test('search and filters operate only on the authorized view, with explicit result limits', async () => {
  const { service, reads } = fixture();
  const result = await service.query(scope, 'list_agents', { environment: 'production', ownerId: 'owner', search: 'script', limit: 1 });
  assert.equal(result.data.agents.length, 1);
  assert.equal(result.data.agents[0].name, '<script>private()</script>');
  assert.equal(result.data.agents[0].id, 'entity:agent');
  assert.equal(result.data.agents[0].sourceId, 'source');
  assert.equal(result.data.truncated, false);
  assert.equal((await service.query(scope, 'list_agents', { limit: 1 })).data.truncated, true);
  assert.equal(Object.isFrozen(reads[0].scope), true);
  assert.deepEqual(plain(reads[0].scope), scope);
  assert.equal(Object.hasOwn(result, 'scope'), false);
});

test('focused graph never expands through shared tools to another execution identity', async () => {
  const { service, reads } = fixture();
  const result = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'entity:agent' });
  assert.equal(result.data.agent.agentId, 'reader-agent');
  assert.deepEqual(result.data.tasks.map(task => task.taskId), ['reader-task', 'reader-parent']);
  assert.equal(result.data.grants[0].resources[0], 'report');
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('other-execution-identity-canary'), false);
  assert.equal(serialized.includes('writer-agent'), false);
  assert.equal(serialized.includes('provenance-only'), false);
  assert.deepEqual(reads[0].request, { sourceId: 'source', agentId: 'entity:agent' });
  assert.ok(Object.isFrozen(result.graph.nodes[0].properties));
  assert.throws(() => { result.data.agent.name = 'changed'; }, TypeError);
});

test('explanation preserves unknown checks and never infers a grant from provenance', async () => {
  const { service } = fixture();
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.equal(result.data.assessment, 'unknown');
  assert.deepEqual(result.data.blockers, []);
  assert.equal(result.data.delegation.length, 2);
  assert.ok(result.data.unknownChecks.includes('ancestor_evidence_outside_visible_scope'));
  assert.ok(result.data.unknownChecks.includes('action_approval'));
  assert.ok(result.data.unknownChecks.includes('custom_policy'));
  assert.equal(JSON.stringify(result).includes('provenance-only'), false);
  assert.equal(result.data.matchedGrants.length, 2);
});

for (const [label, mutate, blocker] of [
  ['revoked', (task) => { task.revoked = true; }, 'task_revoked'],
  ['expired', (task) => { task.deadline = NOW; }, 'deadline_expired'],
  ['calls', (task) => { task.calls = task.max_calls; }, 'call_budget_exhausted'],
  ['concurrent', (task) => { task.concurrent = task.max_concurrent; }, 'concurrency_full_at_capture'],
  ['cost', (task) => { task.spent = 99; }, 'cost_budget_exceeded'],
]) test(`visible ancestor ${label} blocks the declared path`, async () => {
  const { service, nodes } = fixture();
  mutate(nodes.find(node => node.id === 'parent').properties);
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.equal(result.data.assessment, 'blocked');
  assert.ok(result.data.blockers.includes(blocker));
});

test('zero cost budget does not block a zero cost tool; unknown flags stay unknown', async () => {
  const { service, nodes } = fixture();
  for (const node of nodes.filter(node => node.label === 'GuardTask')) Object.assign(node.properties, { max_cost: 0, spent: 0, reserved: 0 });
  const tool = nodes.find(node => node.id === 'tool');
  Object.assign(tool.properties, { max_cost: 0, registered: null, approved: null });
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.equal(result.data.assessment, 'unknown');
  assert.ok(result.data.unknownChecks.includes('tool_registration'));
  assert.ok(result.data.unknownChecks.includes('tool_metadata_approval'));
});

test('metadata and control-plane blockers remain distinct from exact action approval', async () => {
  const { service, nodes } = fixture();
  Object.assign(nodes.find(node => node.id === 'tool').properties, { approved: false, control_plane: true });
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.ok(result.data.blockers.includes('tool_metadata_unapproved'));
  assert.ok(result.data.blockers.includes('control_plane_disabled'));
  assert.ok(result.data.unknownChecks.includes('action_approval'));
});

test('literal wildcard remains a declared selector without synthesizing cloud access', async () => {
  const { service, nodes } = fixture();
  nodes.find(node => node.id === 'grant').properties.resources = ['*'];
  nodes.find(node => node.id === 'parent-grant').properties.resources = ['*'];
  const result = await service.query(scope, 'explain_access', { ...explainArgs, resourceId: 'unmapped-object' });
  assert.equal(result.data.assessment, 'unknown');
  assert.equal(result.data.matchedGrants[0].resources[0], '*');
  assert.equal(Object.hasOwn(result.data, 'cloudPermission'), false);
});

test('parent grant is mandatory and provenance never supplies missing grants', async () => {
  const { service, nodes } = fixture();
  nodes.find(node => node.id === 'parent-grant').properties.resources = ['different'];
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.ok(result.data.blockers.includes('ancestor_declared_grant_missing'));
  assert.equal(result.data.assessment, 'blocked');
});

test('cycles and overlong delegation cannot create an unbounded explanation', async () => {
  const { service, edges } = fixture();
  edges.push({ source: 'parent', target: 'task', kind: 'G_DELEGATED_FROM' });
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.equal(result.data.delegation.length, 2);
  assert.ok(result.data.unknownChecks.includes('delegation_depth_or_cycle'));
});

test('potential access matches exact host action/resource evidence and keeps containment scope', async () => {
  const { service } = fixture();
  const result = await service.query(scope, 'find_agents_with_access', { resourceRef: 'arn:aws:s3:::reports/one.txt', action: 's3:GetObject' });
  assert.equal(result.data.candidates.length, 1);
  const candidate = result.data.candidates[0];
  assert.equal(candidate.assessment, 'unknown');
  assert.equal(candidate.evidence[0].scope, 'exact');
  assert.equal(candidate.evidence[0].externalResource.kind, 'object');
  assert.equal(candidate.evidence[0].externalResource.cloud_match_kind, 'containment');
  assert.equal(JSON.stringify(candidate).includes('other-execution-identity-canary'), false);
  for (const resourceRef of ['arn:aws:s3:::reports', 'arn:aws:s3:::reports/two.txt', 'arn:aws:s3:::reports/*']) {
    assert.deepEqual((await service.query(scope, 'find_agents_with_access', { resourceRef, action: 's3:GetObject' })).data.candidates, []);
  }
  assert.deepEqual((await service.query(scope, 'find_agents_with_access', { resourceRef: 'report', action: 's3:PutObject' })).data.candidates, []);
});

test('dynamic execution identity remains unknown and does not borrow another binding identity', async () => {
  const { service, nodes, edges } = fixture();
  nodes.find(node => node.id === 'execution').properties.identity_selection = 'dynamic';
  edges.splice(edges.findIndex(edge => edge.source === 'execution' && edge.kind === 'G_USES_IDENTITY'), 1);
  const result = await service.query(scope, 'find_agents_with_access', { resourceRef: 'report', action: 's3:GetObject' });
  assert.deepEqual(result.data.candidates[0].evidence[0].executionBindings[0].identities, []);
});

test('explanation associates cloud evidence with the task deployment and exact selector', async () => {
  const { service } = fixture();
  const result = await service.query(scope, 'explain_access', explainArgs);
  const evidence = result.data.externalEvidence;
  assert.equal(evidence.assessment, 'unknown');
  assert.equal(evidence.executionBindings[0].identities[0].arn, 'arn:aws:iam::111122223333:role/Reader');
  assert.equal(evidence.resourceBindings[0].scope, 'exact');
  assert.equal(evidence.resourceBindings[0].targets[0].kind, 'object');
  assert.equal(evidence.resourceBindings[0].targets[0].cloud_match_kind, 'containment');
  assert.equal(JSON.stringify(evidence).includes('other-execution-identity-canary'), false);
  const unmatched = await service.query(scope, 'explain_access', { ...explainArgs, resourceId: 'arn:aws:s3:::reports' });
  assert.deepEqual(unmatched.data.externalEvidence.resourceBindings, []);
});

test('changes compare stable visible entities and omit capture-only changes', async () => {
  const { service, source } = fixture();
  let result = await service.query(scope, 'get_changes', { sourceId: 'source' });
  assert.deepEqual(plain(result.data.changes), { added: [], removed: [], changed: [] });
  source.current.nodes.find(node => node.id === 'task').properties.revoked = true;
  source.current.nodes.find(node => node.id === 'agent').properties.manifest_observed_at = '2030-01-02T00:00:00Z';
  result = await service.query(scope, 'get_changes', { sourceId: 'source', since: 'snapshot-previous' });
  assert.deepEqual(result.data.changes.changed.map(node => node.entityId), ['entity:task']);
  assert.equal(result.data.coverageGap, false);
  const same = await service.query(scope, 'get_changes', { sourceId: 'source', since: 'current' });
  assert.deepEqual(plain(same.data.changes), { added: [], removed: [], changed: [] });
});

test('retention gaps and unknown historical identifiers reveal no unpublished evidence', async () => {
  const { service } = fixture();
  const results = [];
  for (const since of ['hidden-snapshot', 'absent-snapshot']) {
    results.push(await service.query(scope, 'get_changes', { sourceId: 'source', since }));
  }
  assert.deepEqual(plain(results[0]), plain(results[1]));
  assert.equal(results[0].data.coverageGap, true);
  assert.equal(results[0].data.from, null);
});

test('hidden and absent source/agent/task identifiers have the same error', async () => {
  const { service } = fixture();
  for (const id of ['hidden', 'absent']) {
    await assert.rejects(service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: id }), { code: 'MAP_NOT_FOUND', message: 'MAP_NOT_FOUND' });
    await assert.rejects(service.query(scope, 'explain_access', { ...explainArgs, taskId: id }), { code: 'MAP_NOT_FOUND', message: 'MAP_NOT_FOUND' });
    await assert.rejects(service.query(scope, 'get_changes', { sourceId: id }), { code: 'MAP_NOT_FOUND', message: 'MAP_NOT_FOUND' });
  }
});

test('health exposes authorized receipt freshness without global counts or revisions', async () => {
  const { service, source } = fixture();
  const result = await service.query(scope, 'get_inventory_health', {});
  assert.equal(result.data.sources[0].stale, false);
  assert.equal(result.data.visibility, 'visible_agent_sources');
  for (const key of ['ledgerRevision', 'manifestRevision', 'taskCount', 'agentCount']) assert.equal(JSON.stringify(result).includes(key), false);
  source.current.generatedAt = new Date(NOW - 901_000).toISOString();
  assert.equal((await service.query(scope, 'get_inventory_health', {})).data.sources[0].stale, true);
  source.current.generatedAt = new Date(NOW + 61_000).toISOString();
  assert.equal((await service.query(scope, 'get_inventory_health', {})).data.sources[0].stale, true);
});

test('health evaluates each component capture independently and never freshens missing timestamps', async () => {
  const { service, source } = fixture();
  source.current.coverage = {
    tasks: { status: 'complete', observedAt: new Date(NOW - 10_000).toISOString() },
    manifest: { status: 'complete', observedAt: new Date(NOW - 3_600_000).toISOString() },
    mcp: { status: 'unavailable', observedAt: 'invalid' },
    cloud: { status: 'not_collected' },
    future: { status: 'complete', observedAt: new Date(NOW + 61_000).toISOString() },
  };
  const { sources } = (await service.query(scope, 'get_inventory_health', {})).data;
  assert.equal(sources[0].stale, false);
  assert.equal(sources[0].coverage.tasks.stale, false);
  assert.equal(sources[0].coverage.tasks.ageSeconds, 10);
  assert.equal(sources[0].coverage.manifest.stale, true);
  assert.equal(sources[0].coverage.manifest.ageSeconds, 3600);
  assert.equal(sources[0].coverage.manifest.observedAt, source.current.coverage.manifest.observedAt);
  for (const component of ['mcp', 'cloud']) {
    assert.equal(sources[0].coverage[component].stale, true);
    assert.equal(sources[0].coverage[component].ageSeconds, null);
  }
  assert.equal(sources[0].coverage.future.stale, true);
  assert.ok(Object.isFrozen(sources[0].coverage.manifest));
});

test('candidate limit checks one extra authorized match without returning its evidence', async () => {
  const { service, nodes, edges } = fixture();
  nodes.push({ id: 'other-task', entityId: 'entity:other-task', label: 'GuardTask', sourceId: 'source', projectionId: 'current', properties: { task_id: 'other-task' } });
  nodes.push({ id: 'other-grant', entityId: 'entity:other-grant', label: 'GuardGrant', sourceId: 'source', projectionId: 'current', properties: { task_id: 'other-task', tool: 'reports.read', resources: ['report'] } });
  edges.push({ source: 'other-task', target: 'other-deployment', kind: 'G_ASSIGNED_TO' },
    { source: 'other-task', target: 'other-grant', kind: 'G_HAS_GRANT' },
    { source: 'other-grant', target: 'resource', kind: 'G_TARGETS' },
    { source: 'other-grant', target: 'tool', kind: 'G_FOR_TOOL' });
  const result = await service.query(scope, 'find_agents_with_access', { resourceRef: 'report', action: 's3:GetObject', limit: 1 });
  assert.equal(result.data.candidates.length, 1);
  assert.equal(result.data.truncated, true);
  assert.equal(JSON.stringify(result).includes('other-task'), false);
  assert.equal(JSON.stringify(result).includes('other-execution-identity-canary'), false);
});

test('whole-query monotonic deadline catches synchronous work before an event-loop timer can run', async () => {
  const service = new MapService({ read: async () => {
    const end = performance.now() + 25;
    while (performance.now() < end) { /* Simulate synchronous adapter/projection work. */ }
    return { sources: [] };
  } }, { queryTimeoutMs: 10 });
  await assert.rejects(service.query(scope, 'get_inventory_health', {}), /MAP_TIMEOUT/);
});

test('shared selectors cannot amplify candidate evidence beyond bounded processing', async () => {
  const nodes = [], edges = [];
  const node = (id, label, properties) => nodes.push({ id, entityId: id, label, sourceId: 's', projectionId: 'p', properties });
  const edge = (source, target, kind) => edges.push({ source, target, kind });
  node('a', 'GuardAgent', { agent_id: 'a', name: 'A', team_id: 'team-one' });
  node('d', 'GuardDeployment', { deployment_id: 'd' }); edge('d', 'a', 'G_INSTANCE_OF');
  node('tool', 'GuardTool', { name: 'read', registered: true, approved: true, known_metadata: true });
  node('external', 'GuardExternalResource', { arn: 'arn:aws:s3:::shared/object', kind: 'object' });
  const resources = Array.from({ length: 40 }, (_, i) => `r${i}`);
  for (const resource of resources) {
    node(resource, 'GuardResource', { resource_id: resource });
    node(`b${resource}`, 'GuardResourceBinding', { tool: 'read', resource_ref: resource, actions: ['s3:GetObject'], scope: 'exact' });
    edge(`b${resource}`, resource, 'G_BINDS_SELECTOR'); edge(`b${resource}`, 'external', 'G_MAPS_TO');
  }
  for (let i = 0; i < 100; i++) {
    node(`t${i}`, 'GuardTask', { task_id: `t${i}` });
    node(`g${i}`, 'GuardGrant', { task_id: `t${i}`, tool: 'read', resources });
    edge(`t${i}`, 'd', 'G_ASSIGNED_TO'); edge(`t${i}`, `g${i}`, 'G_HAS_GRANT'); edge(`g${i}`, 'tool', 'G_FOR_TOOL');
    for (const resource of resources) edge(`g${i}`, resource, 'G_TARGETS');
  }
  const view = { sources: [{ id: 's', sourceId: 'native', tenantId: 'alpha', profile: 'host', previous: null,
    current: { id: 'p', snapshotId: 'snap', generatedAt: new Date(NOW).toISOString(), status: 'published', nodes, edges, coverage: {} } }] };
  assert.ok(nodes.length < 2000 && edges.length < 5000 && Buffer.byteLength(JSON.stringify(view)) < 4 * 1024 * 1024);
  const service = new MapService({ read: async () => view }, { clock: () => NOW, maxResponseBytes: 8 * 1024 * 1024 });
  await assert.rejects(service.query(scope, 'find_agents_with_access', { resourceRef: 'arn:aws:s3:::shared/object', action: 's3:GetObject', limit: 1 }), /MAP_LIMIT_EXCEEDED/);
});

for (const [operation, args] of [
  ['cypher', { query: 'MATCH (n) RETURN n' }], ['get_inventory_health', { companyId: 'foreign' }],
  ['list_agents', { tenantIds: ['foreign'] }], ['list_agents', { limit: 0 }], ['list_agents', { limit: 101 }],
  ['list_agents', { limit: 1.5 }], ['list_agents', { search: 'a'.repeat(257) }],
  ['get_agent_access', { sourceId: 'source' }], ['get_agent_access', { sourceId: '', agentId: 'agent' }],
  ['explain_access', { ...explainArgs, args: { token: 'private-token' } }],
  ['find_agents_with_access', { resourceRef: 'report', action: '*' }],
  ['get_changes', { sourceId: 'source', since: null }], ['get_inventory_health', []],
]) test(`rejects invalid operation/argument shape ${operation} ${JSON.stringify(args).slice(0, 80)}`, async () => {
  const { service, reads } = fixture();
  await assert.rejects(service.query(scope, operation, args), { code: 'MAP_REQUEST_INVALID', message: 'MAP_REQUEST_INVALID' });
  assert.equal(reads.length, 0);
});

test('request accessors and serialization hooks are not invoked', async () => {
  const { service, reads } = fixture();
  let invoked = 0;
  await assert.rejects(service.query(scope, 'list_agents', { get search() { invoked++; return 'test'; } }), { code: 'MAP_REQUEST_INVALID' });
  await assert.rejects(service.query(scope, 'list_agents', { toJSON() { invoked++; return {}; } }), { code: 'MAP_REQUEST_INVALID' });
  assert.equal(invoked, 0); assert.equal(reads.length, 0);
});

test('invalid trusted scopes never reach the store', async () => {
  const { service, reads } = fixture();
  for (const invalid of [{ ...scope, allTeams: 'yes' }, { ...scope, teamIds: [] }, { ...scope, extra: 'foreign' }]) {
    await assert.rejects(service.query(invalid, 'get_inventory_health', {}), { code: 'MAP_SCOPE_INVALID' });
  }
  assert.equal(reads.length, 0);
});

test('response and graph overflow fail without partial or truncated data', async () => {
  const { store } = fixture();
  const args = { sourceId: 'source', agentId: 'reader-agent' };
  for (const options of [{ maxResponseBytes: 128 }, { maxGraphNodes: 1 }, { maxGraphEdges: 1 }]) {
    await assert.rejects(new MapService(store, { clock: () => NOW, ...options }).query(scope, 'get_agent_access', args), { code: 'MAP_LIMIT_EXCEEDED' });
  }
});

test('timeout and store failures expose stable codes without private backend details', async () => {
  const stalled = new MapService({ read: () => new Promise(() => {}) }, { queryTimeoutMs: 10 });
  await assert.rejects(stalled.query(scope, 'get_inventory_health', {}), { code: 'MAP_TIMEOUT' });
  for (const error of [new Error('private-backend-canary'), new MapQueryError('private-backend-canary')]) {
    const failed = new MapService({ async read() { throw error; } });
    await assert.rejects(failed.query(scope, 'get_inventory_health', {}), { code: 'MAP_UNAVAILABLE', message: 'MAP_UNAVAILABLE' });
  }
});

test('invalid or failing observation clocks return stable errors before reading', async () => {
  const { store, reads } = fixture();
  for (const clock of [() => NaN, () => -1, () => { throw new Error('private-clock-canary'); }]) {
    await assert.rejects(new MapService(store, { clock }).query(scope, 'get_inventory_health', {}),
      { code: 'MAP_UNAVAILABLE', message: 'MAP_UNAVAILABLE' });
  }
  assert.equal(reads.length, 0);
});

function policyRecord(overrides = {}) {
  return {
    taskId: 'entity:task', deploymentId: 'entity:deployment', executionBindingId: 'entity:execution',
    resourceBindingId: 'entity:resource-binding', identityId: 'entity:identity', resourceId: 'entity:external-resource',
    action: 's3:GetObject', status: 'complete', reason: null, observedAt: new Date(NOW - 10_000).toISOString(), assessment: 'unknown',
    candidates: [{ relationship: 'CAN_READ', hasCondition: true, conditionKeys: ['aws:PrincipalTag/team'], resourceScope: 'bucket_summary' }],
    ...overrides,
  };
}
function policyFixture() {
  const value = fixture();
  value.source.current.policyEvidence = [policyRecord()];
  return value;
}

test('policy candidates preserve exact binding scope, conditions and unknown assessments', async () => {
  const { service } = policyFixture();
  const access = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'reader-agent' });
  assert.deepEqual(plain(access.data.policyEvidence), [policyRecord()]);
  assert.deepEqual(plain(access.data.policyCoverage), { status: 'complete', observedAt: new Date(NOW - 10_000).toISOString(), assessment: 'unknown' });
  assert.equal(access.data.assessment, 'unknown');
  const resource = access.graph.nodes.find(node => node.label === 'GuardExternalResource');
  assert.equal(resource.properties.arn, 'arn:aws:s3:::reports/one.txt');
  assert.equal(access.data.policyEvidence[0].candidates[0].resourceScope, 'bucket_summary');
  const explanation = await service.query(scope, 'explain_access', explainArgs);
  assert.deepEqual(plain(explanation.data.externalEvidence.policyEvidence), [policyRecord()]);
  assert.equal(explanation.data.externalEvidence.assessment, 'unknown');
  assert.ok(Object.isFrozen(explanation.data.externalEvidence.policyEvidence[0].candidates[0].conditionKeys));
});

test('policy results never borrow a sibling task observation or another deployment identity', async () => {
  const { source, service } = policyFixture();
  source.current.policyEvidence.push(policyRecord({ taskId: 'entity:parent', candidates: [{ relationship: 'CAN_READ', hasCondition: true,
    conditionKeys: ['sibling-task-canary'], resourceScope: 'bucket_summary' }] }));
  const explanation = await service.query(scope, 'explain_access', explainArgs);
  assert.equal(explanation.data.externalEvidence.policyEvidence.length, 1);
  assert.doesNotMatch(JSON.stringify(explanation), /sibling-task-canary/);
  source.current.policyEvidence = [policyRecord({ executionBindingId: 'entity:other-execution', identityId: 'entity:other-identity' })];
  await assert.rejects(service.query(scope, 'explain_access', explainArgs), { code: 'MAP_UNAVAILABLE' });
});

test('selected agent policy excludes valid records belonging to a second visible agent', async () => {
  const { source, service, nodes, edges } = policyFixture();
  const task = nodes.find(node => node.id === 'task');
  nodes.push({ ...task, id: 'other-task', entityId: 'entity:other-task', properties: { ...task.properties, task_id: 'other-task' } });
  nodes.push({ ...nodes.find(node => node.id === 'grant'), id: 'other-grant', entityId: 'entity:other-grant',
    properties: { task_id: 'other-task', tool: 'reports.read', resources: ['report'] } });
  edges.push({ source: 'other-task', target: 'other-deployment', kind: 'G_ASSIGNED_TO' },
    { source: 'other-task', target: 'other-grant', kind: 'G_HAS_GRANT' },
    { source: 'other-grant', target: 'tool', kind: 'G_FOR_TOOL' },
    { source: 'other-grant', target: 'resource', kind: 'G_TARGETS' });
  source.current.policyEvidence.push(policyRecord({ taskId: 'entity:other-task', deploymentId: 'entity:other-deployment',
    executionBindingId: 'entity:other-execution', identityId: 'entity:other-identity', candidates: [{ relationship: 'CAN_READ',
      hasCondition: true, conditionKeys: ['other-agent-policy-canary'], resourceScope: 'bucket_summary' }] }));
  const access = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'reader-agent' });
  assert.equal(access.data.policyEvidence.length, 1);
  assert.doesNotMatch(JSON.stringify(access), /other-agent-policy-canary|other-execution-identity-canary/);
});

test('resource lookup restricts both top-level and nested policy evidence to requested action', async () => {
  const { source, nodes, service } = policyFixture();
  nodes.find(node => node.id === 'resource-binding').properties.actions.push('s3:PutObject');
  source.current.policyEvidence.push(policyRecord({ action: 's3:PutObject', candidates: [{ relationship: 'CAN_WRITE', hasCondition: true,
    conditionKeys: ['unrequested-write-canary'], resourceScope: 'bucket_summary' }] }));
  const result = await service.query(scope, 'find_agents_with_access', { resourceRef: 'report', action: 's3:GetObject' });
  const record = result.data.candidates[0].evidence.find(item => item.taskId === 'reader-task');
  assert.deepEqual(plain(record.policyEvidence), [policyRecord()]);
  assert.deepEqual(plain(record.explanation.externalEvidence.policyEvidence), [policyRecord()]);
  assert.doesNotMatch(JSON.stringify(result), /unrequested-write-canary/);
});

for (const [status, reason] of [['complete', 'no_candidate'], ['unavailable', 'boundary_unresolved'],
  ['unavailable', 'unsupported_policy'], ['unavailable', 'stale'], ['unavailable', 'changed'],
  ['not_collected', 'disabled'], ['not_collected', 'collection_missing']]) {
  test(`policy ${status}/${reason} remains explicit and never becomes a denial`, async () => {
    const { source, service } = policyFixture();
    source.current.policyEvidence = [policyRecord({ status, reason, candidates: [], ...(status === 'not_collected' ? { observedAt: null } : {}) })];
    const response = await service.query(scope, 'explain_access', explainArgs);
    assert.equal(response.data.assessment, 'unknown');
    const external = response.data.externalEvidence;
    assert.equal(external.policyEvidence[0].reason, reason);
    assert.equal(external.policyEvidence[0].assessment, 'unknown');
    assert.deepEqual(plain(external.policyEvidence[0].candidates), []);
    assert.equal(external.policyCoverage.status, status);
  });
}

test('policy health uses its independent validated age and history never invents policy changes', async () => {
  const { source, service } = policyFixture();
  source.current.policyEvidence[0].observedAt = new Date(NOW - 3_600_000).toISOString();
  const health = await service.query(scope, 'get_inventory_health', {});
  assert.equal(health.data.sources[0].coverage.policy.status, 'complete');
  assert.equal(health.data.sources[0].coverage.policy.observedAt, new Date(NOW - 3_600_000).toISOString());
  assert.equal(health.data.sources[0].coverage.policy.stale, undefined);
  source.previous.policyEvidence = [policyRecord({ policyHash: 'old-private-hash-canary' })];
  const changes = await service.query(scope, 'get_changes', { sourceId: 'source' });
  assert.equal(changes.data.policyHistory, 'not_collected');
  assert.doesNotMatch(JSON.stringify(changes), /old-private-hash-canary|CAN_READ/);
});

test('custom stores without policy collection retain compatible explicit coverage', async () => {
  const { service } = fixture();
  const response = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'reader-agent' });
  assert.deepEqual(plain(response.data.policyEvidence), []);
  assert.deepEqual(plain(response.data.policyCoverage), { status: 'not_collected', observedAt: null, assessment: 'unknown' });
});

for (const [name, mutate] of [
  ['raw policy field', record => { record.policyHash = 'private-policy-canary'; }],
  ['raw condition values', record => { record.candidates[0].conditions = 'private-condition-canary'; }],
  ['effective allow', record => { record.assessment = 'allowed'; }],
  ['exact scope claim', record => { record.candidates[0].resourceScope = 'exact'; }],
  ['wrong mapping', record => { record.candidates[0].relationship = 'CAN_WRITE'; }],
  ['duplicate condition key', record => { record.candidates[0].conditionKeys.push(record.candidates[0].conditionKeys[0]); }],
  ['unbounded condition key', record => { record.candidates[0].conditionKeys = ['x'.repeat(257)]; }],
  ['missing endpoint', record => { record.resourceId = 'hidden-resource-canary'; }],
  ['false complete with no timestamp', record => { record.observedAt = null; }],
  ['unknown reason', record => { record.reason = 'private-diagnostic-canary'; }],
  ['candidate on unavailable', record => { record.status = 'unavailable'; record.reason = 'stale'; }],
]) test(`policy boundary rejects ${name} without exposing data`, async () => {
  const { source, service } = policyFixture();
  mutate(source.current.policyEvidence[0]);
  await assert.rejects(service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'reader-agent' }),
    { code: 'MAP_UNAVAILABLE', message: 'MAP_UNAVAILABLE' });
});

test('policy response bounds and malformed accessors fail without partial output', async () => {
  const { source, service } = policyFixture();
  source.current.policyEvidence = Array.from({ length: 513 }, () => policyRecord());
  await assert.rejects(service.query(scope, 'get_inventory_health', {}), { code: 'MAP_LIMIT_EXCEEDED' });
  let calls = 0;
  const record = policyRecord();
  Object.defineProperty(record, 'candidates', { enumerable: true, get() { calls++; return []; } });
  source.current.policyEvidence = [record];
  await assert.rejects(service.query(scope, 'get_inventory_health', {}), { code: 'MAP_UNAVAILABLE' });
  assert.equal(calls, 0);
});

for (const relation of ['G_ASSIGNED_TO', 'G_EXECUTES_FOR', 'G_EXECUTES_TOOL', 'G_USES_IDENTITY', 'G_MAPS_TO', 'G_BINDS_SELECTOR',
  'G_INSTANCE_OF', 'G_FOR_TOOL', 'G_HAS_GRANT', 'G_TARGETS']) {
  test(`complete policy rejects ambiguous ${relation} relationships`, async () => {
    const { service, edges } = policyFixture();
    edges.push({ ...edges.find(edge => edge.kind === relation) });
    await assert.rejects(service.query(scope, 'get_inventory_health', {}), { code: 'MAP_UNAVAILABLE' });
  });
}

for (const relation of ['G_INSTANCE_OF', 'G_FOR_TOOL']) {
  test(`complete policy rejects an extra wrong-label ${relation} target`, async () => {
    const { service, edges } = policyFixture();
    edges.push({ ...edges.find(edge => edge.kind === relation), target: 'identity' });
    await assert.rejects(service.query(scope, 'get_inventory_health', {}), { code: 'MAP_UNAVAILABLE' });
  });
}

test('complete policy requires one owning agent for its deployment', async () => {
  const { service, edges } = policyFixture();
  edges.splice(edges.findIndex(edge => edge.source === 'deployment' && edge.kind === 'G_INSTANCE_OF'), 1);
  await assert.rejects(service.query(scope, 'get_inventory_health', {}), { code: 'MAP_UNAVAILABLE' });
});

test('complete policy accepts distinct valid grants and additional resource selectors', async () => {
  const { service, nodes, edges } = policyFixture();
  const grant = nodes.find(node => node.id === 'grant');
  nodes.push({ ...grant, id: 'another-grant', entityId: 'entity:another-grant', properties: { ...grant.properties } });
  edges.push({ source: 'task', target: 'another-grant', kind: 'G_HAS_GRANT' },
    { source: 'another-grant', target: 'tool', kind: 'G_FOR_TOOL' },
    { source: 'another-grant', target: 'resource', kind: 'G_TARGETS' });
  const selector = { ...nodes.find(node => node.id === 'resource'), id: 'another-selector', entityId: 'entity:another-selector',
    properties: { resource_id: 'another-report', tool: 'reports.read', selector_kind: 'exact' } };
  nodes.push(selector);
  grant.properties.resources.push('another-report');
  edges.push({ source: 'grant', target: selector.id, kind: 'G_TARGETS' });
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.deepEqual(plain(result.data.externalEvidence.policyEvidence), [policyRecord()]);
});

test('explicit unavailable evidence survives ambiguous owning-agent and grant paths', async () => {
  const { service, source, edges } = policyFixture();
  for (const relation of ['G_INSTANCE_OF', 'G_FOR_TOOL', 'G_HAS_GRANT', 'G_TARGETS']) {
    edges.push({ ...edges.find(edge => edge.kind === relation) });
  }
  source.current.policyEvidence = [policyRecord({ status: 'unavailable', reason: 'binding_ambiguous', candidates: [] })];
  const result = await service.query(scope, 'explain_access', explainArgs);
  assert.deepEqual(plain(result.data.externalEvidence.policyEvidence), source.current.policyEvidence);
  assert.equal(result.data.externalEvidence.policyCoverage.status, 'unavailable');
});

test('policy cannot use a forged resource edge absent from the task declared grant', async () => {
  const { source, service, nodes } = policyFixture();
  nodes.find(node => node.id === 'grant').properties.resources = ['somewhere-else'];
  assert.equal(source.current.policyEvidence.length, 1);
  await assert.rejects(service.query(scope, 'explain_access', explainArgs), { code: 'MAP_UNAVAILABLE' });
});

test('policy condition keys retain Python Unicode codepoint order for astral characters', async () => {
  const { source, service } = policyFixture();
  const keys = ['aws:PrincipalTag/\ue000', 'aws:PrincipalTag/😀'];
  source.current.policyEvidence[0].candidates[0].conditionKeys = keys;
  const response = await service.query(scope, 'explain_access', explainArgs);
  assert.deepEqual(plain(response.data.externalEvidence.policyEvidence[0].candidates[0].conditionKeys), keys);
});

test('long valid host action remains explicit unsupported evidence without widening query inputs', async () => {
  const { source, nodes, service } = policyFixture();
  const action = 'custom:' + 'A'.repeat(4089);
  nodes.find(node => node.id === 'resource-binding').properties.actions = [action];
  source.current.policyEvidence = [policyRecord({ action, status: 'not_collected', reason: 'unsupported_action', observedAt: null, candidates: [] })];
  const result = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'reader-agent' });
  assert.equal(result.data.policyEvidence[0].action, action);
  assert.equal(result.data.policyEvidence[0].reason, 'unsupported_action');
  await assert.rejects(service.query(scope, 'find_agents_with_access', { resourceRef: 'report', action }), { code: 'MAP_REQUEST_INVALID' });
});
