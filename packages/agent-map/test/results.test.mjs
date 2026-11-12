import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService, MAP_INPUT_SCHEMAS } from '../dist/service.js';

const NOW = Date.parse('2030-01-02T00:00:00Z');
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['alpha'], teamIds: [], allTeams: true };
const plain = value => JSON.parse(JSON.stringify(value));
/** A small graph builder in the store's output shape. `prefix` keeps node ids distinct per projection. */
function graph(projectionId = 'current', prefix = '') {
  const nodes = [],
    edges = [];
  return {
    nodes,
    edges,
    node(id, label, properties = {}) {
      nodes.push({ id: prefix + id, entityId: `e:${id}`, label, sourceId: 'source', projectionId, properties });
    },
    edge(source, target, kind) {
      edges.push({ source: prefix + source, target: prefix + target, kind });
    },
    projection(extra = {}) {
      return {
        id: projectionId,
        snapshotId: `snapshot-${projectionId}`,
        generatedAt: new Date(NOW - 10_000).toISOString(),
        status: 'published',
        nodes,
        edges,
        coverage: {},
        ...extra,
      };
    },
  };
}
const sourceOf = (current, previous = null) => ({
  id: 'source',
  sourceId: 'native',
  tenantId: 'alpha',
  profile: 'host',
  current,
  previous,
});
const serviceOf = (source, options = {}) =>
  new MapService({ read: async () => ({ sources: [source] }) }, { clock: () => NOW, ...options });
/** One agent with `tasks` tasks, each granted `reports.read` on `report`. */
function addAgent(g, index, { tasks = 1, name = `Agent ${index}` } = {}) {
  g.node(`agent:${index}`, 'GuardAgent', { agent_id: `agent-${index}`, name, team_id: 'team', owner_id: 'owner' });
  g.node(`deployment:${index}`, 'GuardDeployment', { deployment_id: `deployment-${index}` });
  g.edge(`deployment:${index}`, `agent:${index}`, 'G_INSTANCE_OF');
  g.node(`execution:${index}`, 'GuardExecutionBinding', {
    binding_id: `x${index}`,
    tool: 'reports.read',
    identity_selection: 'static',
  });
  g.edge(`execution:${index}`, `deployment:${index}`, 'G_EXECUTES_FOR');
  g.edge(`execution:${index}`, 'tool', 'G_EXECUTES_TOOL');
  for (let task = 0; task < tasks; task++) {
    const id = `${index}:${task}`;
    g.node(`task:${id}`, 'GuardTask', { task_id: `task-${id}`, revoked: false });
    g.node(`grant:${id}`, 'GuardGrant', { task_id: `task-${id}`, tool: 'reports.read', resources: ['report'] });
    g.edge(`task:${id}`, `deployment:${index}`, 'G_ASSIGNED_TO');
    g.edge(`task:${id}`, `grant:${id}`, 'G_HAS_GRANT');
    g.edge(`grant:${id}`, 'tool', 'G_FOR_TOOL');
    g.edge(`grant:${id}`, 'selector', 'G_TARGETS');
  }
}
function shared(g) {
  g.node('tool', 'GuardTool', { name: 'reports.read', registered: true, approved: true, known_metadata: true });
  g.node('selector', 'GuardResource', { resource_id: 'report', tool: 'reports.read' });
  g.node('binding', 'GuardResourceBinding', {
    binding_id: 'report-binding',
    tool: 'reports.read',
    resource_ref: 'report',
    actions: ['s3:GetObject'],
    scope: 'exact',
  });
  g.edge('binding', 'selector', 'G_BINDS_SELECTOR');
}

test('find_agents_with_access reaches its documented limit of 100 on a projection at the node cap', async () => {
  const g = graph();
  shared(g);
  for (let index = 0; index < 150; index++) addAgent(g, index);
  // Unrelated nodes up to the store's default cap: they must not be scanned once per evidence row.
  for (let index = 0; g.nodes.length < 2000; index++) g.node(`principal:${index}`, 'GuardPrincipal', {});
  assert.equal(g.nodes.length, 2000);
  const result = await serviceOf(sourceOf(g.projection())).query(scope, 'find_agents_with_access', {
    resourceRef: 'report',
    action: 's3:GetObject',
    limit: 100,
  });
  assert.equal(result.data.candidates.length, 100);
  // More agents match than the limit: said through the existing flag, with no error.
  assert.equal(result.data.truncated, true);
  assert.equal(result.data.truncatedReason, undefined);
  assert.equal(result.data.candidates[0].evidence[0].explanation.taskId, 'task-0:0');
});

test('find_agents_with_access that runs out of budget returns the candidates it completed, marked truncated', async () => {
  const g = graph();
  shared(g);
  // 60 agents x 20 tasks = 1,200 evidence rows, past the 1,000 one answer may hold.
  for (let index = 0; index < 60; index++) addAgent(g, index, { tasks: 20 });
  const source = sourceOf(g.projection());
  const result = await serviceOf(source, { maxResponseBytes: 8 * 1024 * 1024 }).query(
    scope,
    'find_agents_with_access',
    { resourceRef: 'report', action: 's3:GetObject', limit: 100 },
  );
  assert.equal(result.data.truncated, true);
  assert.equal(result.data.truncatedReason, 'work_limit');
  // Only complete candidates: fifty agents with all twenty rows each, never a partial one.
  assert.equal(result.data.candidates.length, 50);
  assert.ok(result.data.candidates.every(candidate => candidate.evidence.length === 20));
  // With not even one candidate complete there is nothing honest to return.
  const single = graph();
  shared(single);
  addAgent(single, 0, { tasks: 1001 });
  await assert.rejects(
    serviceOf(sourceOf(single.projection()), { maxResponseBytes: 8 * 1024 * 1024 }).query(
      scope,
      'find_agents_with_access',
      { resourceRef: 'report', action: 's3:GetObject' },
    ),
    { code: 'MAP_LIMIT_EXCEEDED' },
  );
});

test('names sort in code-point order with a stable id tiebreak, so a prefix comes first', async () => {
  const g = graph();
  shared(g);
  const names = ['Reader 2', 'Reader', 'Reader-1', 'reader', 'Reader', 'Écrivain', null, 'Reader\u{1F600}', 'Reader�'];
  names.forEach((name, index) => {
    addAgent(g, index, { name });
    g.node(`owner:${index}`, 'GuardOwner', { owner_id: `owner-${index}`, name: name ?? '', kind: 'team' });
  });
  const service = serviceOf(sourceOf(g.projection()));
  const agents = (await service.query(scope, 'list_agents', {})).data.agents;
  assert.deepEqual(
    agents.map(agent => [agent.name, agent.id]),
    [
      ['Reader', 'e:agent:1'],
      ['Reader', 'e:agent:4'],
      ['Reader 2', 'e:agent:0'],
      ['Reader-1', 'e:agent:2'],
      // Code points, not UTF-16 units: U+FFFD sorts before the astral U+1F600.
      ['Reader�', 'e:agent:8'],
      ['Reader\u{1F600}', 'e:agent:7'],
      ['reader', 'e:agent:3'],
      ['Écrivain', 'e:agent:5'],
      // Unnamed agents last.
      [null, 'e:agent:6'],
    ],
  );
  const owners = (await service.query(scope, 'list_owners', {})).data.owners.map(owner => owner.name);
  assert.deepEqual(owners.slice(0, 4), ['', 'Reader', 'Reader', 'Reader 2']);
  // Paging follows the same order.
  const page = (await service.query(scope, 'list_agents', { offset: 2, limit: 2 })).data.agents;
  assert.deepEqual(
    page.map(agent => agent.name),
    ['Reader 2', 'Reader-1'],
  );
});

test('every change category can be requested, and a renamed agent appears under its current name', async () => {
  assert.deepEqual(plain(MAP_INPUT_SCHEMAS.get_changes.properties.changeKind.enum), [
    'all',
    'permissions',
    'ownership',
    'bindings',
    'outside_guard',
    'inventory',
  ]);
  const before = graph('previous', 'old:'),
    after = graph();
  for (const [g, name] of [
    [before, 'Old name'],
    [after, 'New name'],
  ]) {
    shared(g);
    addAgent(g, 0, { name });
  }
  // A task of the renamed agent changes too, so the agent is an affected agent of another row.
  after.nodes.find(node => node.id === 'task:0:0').properties.revoked = true;
  const service = serviceOf(sourceOf(after.projection(), before.projection()));
  const changes = (await service.query(scope, 'get_changes', { sourceId: 'source' })).data;
  const emitted = new Set(changes.details.flatMap(item => item.categories));
  for (const category of emitted)
    assert.ok(MAP_INPUT_SCHEMAS.get_changes.properties.changeKind.enum.includes(category), category);
  assert.ok(emitted.has('inventory'));
  const renamed = (await service.query(scope, 'get_changes', { sourceId: 'source', changeKind: 'inventory' })).data;
  assert.deepEqual(
    renamed.details.map(item => [item.label, item.name, item.changedFields]),
    [['GuardAgent', 'New name', ['name']]],
  );
  for (const list of [changes.affectedAgents, ...changes.details.map(item => item.affectedAgents)])
    assert.deepEqual(
      list.map(agent => agent.name),
      ['New name'],
    );
});

test('owner counts appear only where they cover the whole scoped projection', async () => {
  const g = graph();
  shared(g);
  g.node('owner', 'GuardOwner', { owner_id: 'owner', name: 'Platform', kind: 'team' });
  g.edge('binding', 'owner', 'G_RESOURCE_OWNED_BY');
  for (let index = 0; index < 3; index++) {
    addAgent(g, index);
    g.edge(`agent:${index}`, 'owner', 'G_OWNED_BY');
  }
  const service = serviceOf(sourceOf(g.projection()));
  const listed = (await service.query(scope, 'list_owners', {})).data.owners[0];
  assert.equal(listed.agentCount, 3);
  assert.equal(listed.resourceCount, 1);
  const inventory = await service.query(scope, 'get_agent_inventory', {
    sourceId: 'source',
    agentId: 'agent-0',
    section: 'owners',
  });
  // One agent's neighborhood cannot count an owner's agents: no figure rather than "1".
  assert.deepEqual(plain(inventory.data.items), [
    {
      id: 'e:owner',
      ownerId: 'owner',
      name: 'Platform',
      kind: 'team',
      sourceId: 'source',
      authorityId: null,
      manifestId: null,
      manifestRevision: null,
      observedAt: null,
    },
  ]);
});

test('evidence rows and the response graph carry allowlisted properties only', async () => {
  const g = graph();
  shared(g);
  addAgent(g, 0);
  g.node('identity', 'GuardExternalIdentity', { provider: 'aws', arn: 'arn:aws:iam::111122223333:role/Reader' });
  g.node('external', 'GuardExternalResource', { provider: 'aws', arn: 'arn:aws:s3:::reports', kind: 'bucket' });
  g.node('connection', 'GuardMcpConnection', { connection_id: 'documents', state: 'ready' });
  g.edge('execution:0', 'identity', 'G_USES_IDENTITY');
  g.edge('execution:0', 'connection', 'G_VIA_CONNECTION');
  g.edge('binding', 'external', 'G_MAPS_TO');
  // A host-provided store that returns more than the projection contract allows.
  for (const node of g.nodes) node.properties.unlisted_canary = `canary-${node.id}`;
  const service = serviceOf(sourceOf(g.projection()));
  for (const [operation, args] of [
    ['get_agent_access', { sourceId: 'source', agentId: 'agent-0' }],
    ['explain_access', { sourceId: 'source', taskId: 'task-0:0', tool: 'reports.read', resourceId: 'report' }],
    ['find_agents_with_access', { resourceRef: 'report', action: 's3:GetObject' }],
    ['get_agent_inventory', { sourceId: 'source', agentId: 'agent-0', section: 'bindings' }],
    ['list_resources', {}],
  ]) {
    const result = await service.query(scope, operation, args);
    assert.equal(JSON.stringify(result).includes('canary'), false, operation);
  }
  // The allowlisted fields themselves are still there.
  const access = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent-0' });
  assert.equal(access.graph.nodes.find(node => node.label === 'GuardMcpConnection').properties.state, 'ready');
  assert.equal(access.data.connections[0].connection_id, 'documents');
  const found = await service.query(scope, 'find_agents_with_access', {
    resourceRef: 'report',
    action: 's3:GetObject',
  });
  const row = found.data.candidates[0].evidence[0];
  assert.equal(row.externalResource.arn, 'arn:aws:s3:::reports');
  assert.equal(row.executionBindings[0].identities[0].arn, 'arn:aws:iam::111122223333:role/Reader');
});

test('the service asks the store only for the policy evidence each operation returns', async () => {
  const requests = [];
  const g = graph();
  shared(g);
  addAgent(g, 0);
  const source = sourceOf(g.projection());
  const service = new MapService(
    {
      read: async (_scope, request) => {
        requests.push(plain(request));
        return { sources: [source] };
      },
    },
    { clock: () => NOW },
  );
  await service.query(scope, 'list_owners', { sourceId: 'source' });
  await service.query(scope, 'list_resources', {});
  await service.query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'report-binding' });
  await service.query(scope, 'explain_access', {
    sourceId: 'source',
    taskId: 'task-0:0',
    tool: 'reports.read',
    resourceId: 'report',
  });
  await service.query(scope, 'find_agents_with_access', { resourceRef: 'report', action: 's3:GetObject' });
  await service.query(scope, 'get_inventory_health', {});
  await service.query(scope, 'get_agent_inventory', { sourceId: 'source', agentId: 'agent-0' });
  assert.deepEqual(requests, [
    { sourceId: 'source', owners: true },
    { outsideGuard: true, policy: false },
    { sourceId: 'source', outsideGuard: true, policy: false },
    { sourceId: 'source', policy: { taskId: 'task-0:0', tool: 'reports.read', resourceRef: 'report' } },
    { policy: { resourceRef: 'report', action: 's3:GetObject', optional: true } },
    { policy: { optional: true } },
    // Health's second, optional read for undeclared activity.
    { undeclared: true },
    // One agent's own evidence: every pair of that agent; past the pair limit it reads unknown.
    { sourceId: 'source', agentId: 'agent-0', policy: { optional: true } },
  ]);
});

test('one agent with more policy pairs than a read evaluates still answers, with policy evidence unknown', async () => {
  const g = graph();
  shared(g);
  addAgent(g, 0);
  const source = sourceOf(g.projection());
  // What the store returns for an optional policy read past its 512-pair limit: no evidence
  // and the marker. A read that did not ask for `optional` fails, as the store does.
  const service = new MapService(
    {
      read: async (_scope, request) => {
        if (request.policy?.optional !== true)
          throw Object.assign(new (await import('../dist/types.js')).MapQueryError('MAP_LIMIT_EXCEEDED'));
        const { policyEvidence: _dropped, ...current } = source.current;
        return { sources: [{ ...source, current: { ...current, policyEvidenceNotLoaded: true } }] };
      },
    },
    { clock: () => NOW },
  );
  const unknown = { status: 'unknown', reason: 'limit_exceeded', observedAt: null, assessment: 'unknown' };
  const access = await service.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent-0' });
  assert.deepEqual(plain(access.data.policyCoverage), unknown);
  assert.deepEqual(plain(access.data.policyEvidence), []);
  // The rest of the answer is unaffected.
  assert.equal(access.data.graphStatus, 'included');
  assert.ok(access.data.tasks.length > 0 && access.data.grants.length > 0);
  assert.equal(access.data.boundaryFlags.length, 1);
  for (const section of ['overview', 'policies', 'permissions']) {
    const inventory = await service.query(scope, 'get_agent_inventory', {
      sourceId: 'source',
      agentId: 'agent-0',
      section,
    });
    assert.deepEqual(plain(inventory.data.policyCoverage), unknown);
    assert.deepEqual(plain(inventory.data.policyEvidence), []);
    // Not evaluated has no size: null, never a zero that reads as "no policy".
    assert.equal(inventory.data.counts.policies, null);
    assert.ok(inventory.data.counts.permissions > 0);
    // Only the section that was not evaluated loses its total.
    if (section === 'policies') assert.equal(inventory.data.total, null);
    else assert.equal(Number.isSafeInteger(inventory.data.total), true, section);
    assert.equal(inventory.data.truncated, false);
  }
});
