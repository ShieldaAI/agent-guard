import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService, validateQueryArguments, createMapToken, startMapServer } from '../dist/index.js';

const now = Date.parse('2030-01-02T00:00:00Z');
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['blue'], allTeams: false };
const opaque = char => `opaque:${char.repeat(64)}`;
const plain = value => JSON.parse(JSON.stringify(value));
function fixture(id = 'source') {
  const nodes = [],
    edges = [];
  const node = (key, label, properties) =>
    nodes.push({ id: `${id}:${key}`, entityId: `e:${key}`, sourceId: id, projectionId: 'current', label, properties });
  const edge = (a, b, kind) => edges.push({ source: `${id}:${a}`, target: `${id}:${b}`, kind });
  node('owner', 'GuardOwner', { owner_id: 'owner', name: 'Accountable team', kind: 'team' });
  node('other-owner', 'GuardOwner', { owner_id: 'other-owner', name: 'Service owner', kind: 'service' });
  node('credential', 'GuardCredentialReference', {
    credential_id: opaque('a'),
    name: 'Host credential',
    issuer_ref: opaque('b'),
    audience_refs: [opaque('c')],
    recipient_refs: [opaque('d')],
    lifecycle_state: 'rotating',
    expires_at: null,
    rotation_status: 'due',
    token: 'private-canary',
  });
  node('tool', 'GuardTool', {
    name: 'records.read',
    fingerprint: 'a'.repeat(64),
    revision: 3,
    registered: true,
    approved: true,
  });
  for (const suffix of ['', '-two']) {
    node(`agent${suffix}`, 'GuardAgent', {
      agent_id: `agent${suffix}`,
      name: `Agent${suffix}`,
      team_id: 'blue',
      owner_id: suffix ? null : 'owner',
      purpose: 'Read reviewed records',
      lifecycle_state: 'active',
      ownership_status: suffix ? 'unassigned' : 'assigned',
      ownership_source: 'Company catalog',
      authority_id: 'host-authority',
    });
    node(`deployment${suffix}`, 'GuardDeployment', {
      deployment_id: `deployment${suffix}`,
      environment: 'production',
      runtime_ref: opaque('e'),
      build_ref: opaque('f'),
      workload_generation: '3',
      binding_authority: 'host-authority',
    });
    node(`task${suffix}`, 'GuardTask', { task_id: `task${suffix}`, revoked: false, max_calls: 10, calls: 0 });
    node(`grant${suffix}`, 'GuardGrant', {
      task_id: `task${suffix}`,
      tool: 'records.read',
      resources: [`record${suffix}`],
    });
    node(`selector${suffix}`, 'GuardResource', {
      resource_id: `record${suffix}`,
      tool: 'records.read',
      selector_kind: 'exact',
    });
    node(`resource${suffix}`, 'GuardResourceBinding', {
      binding_id: `resource${suffix}`,
      resource_ref: `record${suffix}`,
      tool: 'records.read',
      display_name: `Records${suffix}`,
      actions: ['read-record'],
      scope: suffix ? 'prefix' : 'exact',
      owner_id: suffix ? 'other-owner' : 'owner',
      ownership_status: 'assigned',
      ownership_source: 'Catalog',
      sensitivity: suffix ? 'restricted' : 'internal',
      approved_destinations: [opaque('d')],
      depends_on: ['hidden-binding-canary'],
      authority_id: 'host-authority',
    });
    node(`external${suffix}`, 'GuardExternalResource', {
      provider: 'host',
      host_resource_id: opaque(suffix ? '2' : '1'),
      name: `Repository${suffix}`,
      kind: 'repository',
    });
    edge(`deployment${suffix}`, `agent${suffix}`, 'G_INSTANCE_OF');
    edge(`task${suffix}`, `deployment${suffix}`, 'G_ASSIGNED_TO');
    edge(`task${suffix}`, `grant${suffix}`, 'G_HAS_GRANT');
    edge(`grant${suffix}`, 'tool', 'G_FOR_TOOL');
    edge(`grant${suffix}`, `selector${suffix}`, 'G_TARGETS');
    edge(`resource${suffix}`, `selector${suffix}`, 'G_BINDS_SELECTOR');
    edge(`resource${suffix}`, `external${suffix}`, 'G_MAPS_TO');
    edge(`resource${suffix}`, suffix ? 'other-owner' : 'owner', 'G_RESOURCE_OWNED_BY');
  }
  edge('agent', 'owner', 'G_OWNED_BY');
  edge('deployment', 'credential', 'G_USES_CREDENTIAL');
  edge('resource', 'resource-two', 'G_DEPENDS_ON');
  const current = {
    id: 'current',
    snapshotId: 'snapshot-current',
    generatedAt: new Date(now).toISOString(),
    status: 'published',
    nodes,
    edges,
    coverage: {},
  };
  const previous = structuredClone(current);
  previous.id = 'previous';
  previous.snapshotId = 'snapshot-previous';
  for (const node of previous.nodes) {
    node.id = `old:${node.id}`;
    node.projectionId = previous.id;
  }
  for (const edge of previous.edges) {
    edge.source = `old:${edge.source}`;
    edge.target = `old:${edge.target}`;
  }
  return { id, sourceId: id, tenantId: 'tenant', profile: 'host', current, previous };
}
function service(sources, options = {}) {
  return new MapService(
    {
      read: async (receivedScope, request) => {
        assert.deepEqual(plain(receivedScope), scope);
        return { sources: sources.filter(source => !request.sourceId || source.id === request.sourceId) };
      },
    },
    { clock: () => now, ...options },
  );
}

test('indexes have stable authorized totals and source-bound repeated native IDs', async () => {
  const map = service([fixture('source-two'), fixture('source-one')]);
  const first = await map.query(scope, 'list_agents', { ownerId: 'owner', limit: 1 });
  const next = await map.query(scope, 'list_agents', { ownerId: 'owner', limit: 1, offset: 1 });
  assert.equal(first.data.total, 2);
  assert.equal(first.data.truncated, true);
  assert.equal(next.data.truncated, false);
  assert.notEqual(first.data.agents[0].sourceId, next.data.agents[0].sourceId);
  const owners = await map.query(scope, 'list_owners', { sourceId: 'source-one', kind: 'team' });
  assert.equal(owners.data.total, 1);
  assert.equal(owners.data.owners[0].agentCount, 1);
  assert.equal(owners.data.owners[0].resourceCount, 1);
  const unassigned = await map.query(scope, 'list_agents', { sourceId: 'source-one', ownershipStatus: 'unassigned' });
  assert.equal(unassigned.data.total, 1);
  assert.equal(unassigned.data.agents[0].ownerName, null);
  assert.equal((await map.query(scope, 'list_agents', { teamId: 'hidden' })).data.total, 0);
  assert.equal((await map.query(scope, 'list_owners', { offset: 100_000 })).data.owners.length, 0);
});

test('v1 missing metadata stays unknown, not unassigned, and known owner IDs remain compatible', async () => {
  const source = fixture();
  source.current.nodes = source.current.nodes.filter(
    n => !['GuardOwner', 'GuardCredentialReference'].includes(n.label),
  );
  source.current.edges = source.current.edges.filter(
    e => source.current.nodes.some(n => n.id === e.source) && source.current.nodes.some(n => n.id === e.target),
  );
  for (const agent of source.current.nodes.filter(n => n.label === 'GuardAgent'))
    for (const key of ['purpose', 'lifecycle_state', 'ownership_status', 'ownership_source'])
      delete agent.properties[key];
  const result = await service([source]).query(scope, 'list_agents', { ownerId: 'owner' });
  assert.equal(result.data.agents[0].ownerId, 'owner');
  assert.equal(result.data.agents[0].ownerName, null);
  assert.equal(result.data.agents[0].ownershipStatus, 'unknown');
  assert.equal(result.data.agents[0].lifecycleState, 'unknown');
});

test('generic resources navigate only exact declared bindings and preserve object/prefix boundaries', async () => {
  const map = service([fixture()]);
  const result = await map.query(scope, 'list_resources', { ownerId: 'owner', sensitivity: 'internal' });
  assert.equal(result.data.total, 1);
  const resource = result.data.resources[0];
  assert.equal(resource.scope, 'exact');
  assert.equal(resource.targets[0].provider, 'host');
  assert.equal(resource.targets[0].host_resource_id, opaque('1'));
  assert.equal(resource.dependencies[0].id, 'e:resource-two');
  assert.equal(JSON.stringify(result).includes('hidden-binding-canary'), false);
  const access = await map.query(scope, 'get_resource_access', { sourceId: 'source', resourceId: resource.id });
  assert.deepEqual(
    access.data.agents.map(a => a.agentId),
    ['agent'],
  );
  assert.equal(access.data.assessment, 'unknown');
  assert.equal(access.data.collection.backendReceipts, 'not_collected');
  for (const resourceId of ['hidden', 'absent', 'resource-prefix-child'])
    await assert.rejects(map.query(scope, 'get_resource_access', { sourceId: 'source', resourceId }), {
      code: 'MAP_NOT_FOUND',
    });
});

test('paged sections remain usable beyond graph display caps without leaking shared neighborhoods', async () => {
  const map = service([fixture()], { maxGraphNodes: 1 });
  // Past the display cap the graph is left out; the evidence itself still answers.
  const access = await map.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  assert.equal(access.graph, undefined);
  assert.equal(access.data.graphStatus, 'too_large');
  for (const section of [
    'overview',
    'owners',
    'deployments',
    'tasks',
    'permissions',
    'resources',
    'credentials',
    'relationships',
    'tools',
    'bindings',
    'identities',
    'connections',
    'policies',
  ]) {
    const result = await map.query(scope, 'get_agent_inventory', {
      sourceId: 'source',
      agentId: 'agent',
      section,
      limit: 1,
    });
    assert.equal(result.data.section, section);
    assert.ok(result.data.items.length <= 1);
    assert.equal(result.graph, undefined);
    assert.equal(result.data.graphStatus, 'not_requested');
    assert.equal(result.data.collection.approvals, 'not_collected');
    assert.equal(result.data.policyCoverage.status, 'not_collected');
    const json = JSON.stringify(result);
    assert.equal(json.includes('private-canary'), false);
    assert.equal(json.includes('hidden-binding-canary'), false);
    assert.equal(json.includes('e:agent-two'), false);
    assert.equal(json.includes('e:resource-two'), false);
  }
  const credential = (
    await map.query(scope, 'get_agent_inventory', { sourceId: 'source', agentId: 'agent', section: 'credentials' })
  ).data.items[0];
  assert.equal(credential.credentialId, opaque('a'));
  assert.equal(credential.lifecycleState, 'rotating');
  assert.equal(Object.isFrozen(credential), true);
});

test('retained changes show safe before/after and affected agents for ownership and relationship-only changes', async () => {
  const source = fixture();
  source.previous.edges = source.previous.edges.filter(e => e.kind !== 'G_DEPENDS_ON' && e.kind !== 'G_OWNED_BY');
  const previousOwner = source.previous.nodes.find(n => n.entityId === 'e:owner');
  previousOwner.properties.name = 'Previous team';
  previousOwner.properties.secret = 'private-before-canary';
  const map = service([source]);
  const ownership = await map.query(scope, 'get_changes', { sourceId: 'source', changeKind: 'ownership' });
  const owner = ownership.data.details.find(d => d.entityId === 'e:owner');
  assert.equal(owner.before.properties.name, 'Previous team');
  assert.equal(owner.after.properties.name, 'Accountable team');
  assert.ok(owner.changedFields.includes('name'));
  assert.ok(owner.affectedAgents.some(a => a.agentId === 'agent'));
  assert.equal(JSON.stringify(ownership).includes('private-before-canary'), false);
  assert.ok(ownership.data.relationships.added.some(e => e.kind === 'G_OWNED_BY'));
  const binding = await map.query(scope, 'get_changes', {
    sourceId: 'source',
    resourceId: 'resource',
    changeKind: 'bindings',
    limit: 1,
  });
  assert.equal(binding.data.details[0].entityId, 'e:resource');
  assert.deepEqual(binding.data.details[0].changedFields, []);
  assert.ok(binding.data.relationships.added.some(e => e.kind === 'G_DEPENDS_ON'));
  assert.equal(binding.data.policyHistory, 'not_collected');
  assert.deepEqual(
    plain((await map.query(scope, 'get_changes', { sourceId: 'source', agentId: 'agent-two' })).data.details),
    [],
  );
});

test('permissions changes keep declared evidence separate, pagination and missing baseline honest', async () => {
  const source = fixture();
  source.previous.nodes.find(n => n.entityId === 'e:grant').properties.resources = ['old-selection'];
  const map = service([source]);
  const result = await map.query(scope, 'get_changes', {
    sourceId: 'source',
    changeKind: 'permissions',
    agentId: 'agent',
    limit: 1,
  });
  assert.equal(result.data.total, 1);
  assert.equal(result.data.details[0].entityId, 'e:grant');
  assert.deepEqual(result.data.details[0].changedFields, ['resources']);
  assert.equal(result.data.collection.requestTimeDecisions, 'not_collected');
  const gap = await map.query(scope, 'get_changes', { sourceId: 'source', since: 'unretained' });
  assert.equal(gap.data.coverageGap, true);
  assert.equal(gap.data.from, null);
  assert.equal(gap.data.total, 0);
  for (const agentId of ['hidden', 'absent'])
    await assert.rejects(map.query(scope, 'get_changes', { sourceId: 'source', agentId }), { code: 'MAP_NOT_FOUND' });
});

test('new input schemas reject scope injection, invalid paging and arbitrary sections before reads', () => {
  for (const [operation, args] of [
    ['list_owners', { companyId: 'other' }],
    ['list_resources', { offset: -1 }],
    ['list_agents', { offset: 0.5 }],
    ['list_resources', { sensitivity: 'secret' }],
    ['list_agents', { ownershipStatus: 'allowed' }],
    ['get_agent_inventory', { sourceId: 'source', agentId: 'agent', section: 'raw_secrets' }],
    ['get_changes', { sourceId: 'source', changeKind: 'effective_permissions' }],
  ])
    assert.throws(() => validateQueryArguments(operation, args), { code: 'MAP_REQUEST_INVALID' });
});

test('HTTP exposes the same paged new APIs and rejects caller scope overrides', async t => {
  const map = service([fixture()]),
    token = createMapToken();
  const server = await startMapServer({ service: map, credentials: [{ token, scope }] });
  t.after(() => server.close());
  const query = async (operation, args) =>
    fetch(server.url + '/v1/query', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ operation, args }),
    });
  const response = await query('list_resources', { limit: 1 });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), plain(await map.query(scope, 'list_resources', { limit: 1 })));
  assert.equal((await query('list_owners', { tenantIds: ['hidden'] })).status, 400);
});

test('relationship names are readable while endpoint renames never manufacture edge changes', async () => {
  const source = fixture();
  source.previous.nodes.find(n => n.entityId === 'e:owner').properties.name = 'Old owner';
  const map = service([source]);
  const rows = (
    await map.query(scope, 'get_agent_inventory', { sourceId: 'source', agentId: 'agent', section: 'relationships' })
  ).data.items;
  const edge = rows.find(e => e.kind === 'G_OWNED_BY');
  assert.equal(edge.sourceName, 'Agent');
  assert.equal(edge.targetName, 'Accountable team');
  assert.equal(edge.sourceLabel, 'GuardAgent');
  assert.equal(edge.targetLabel, 'GuardOwner');
  const changes = (await map.query(scope, 'get_changes', { sourceId: 'source' })).data;
  assert.deepEqual(plain(changes.relationships), { added: [], removed: [] });
  assert.deepEqual(
    changes.details.map(d => d.entityId),
    ['e:owner'],
  );
});

test('explicit change pages bound companions and align relationship deltas with their page', async () => {
  const source = fixture();
  for (let i = 0; i < 80; i++) {
    const node = {
      ...source.current.nodes.find(n => n.entityId === 'e:resource'),
      id: `source:extra${i}`,
      entityId: `e:extra${i}`,
      properties: {
        binding_id: `extra${i}`,
        display_name: `Binding ${String(i).padStart(2, '0')}`,
        tool: 'records.read',
        resource_ref: 'record',
      },
    };
    source.current.nodes.push(node);
    source.previous.nodes.push({
      ...structuredClone(node),
      id: `old:${node.id}`,
      projectionId: 'previous',
      properties: { ...node.properties, display_name: `Previous ${i}` },
    });
    for (const [projection, prefix] of [
      [source.current, ''],
      [source.previous, 'old:'],
    ])
      projection.edges.push({
        source: `${prefix}${node.id}`,
        target: `${prefix}source:selector`,
        kind: 'G_BINDS_SELECTOR',
      });
    source.current.edges.push({ source: node.id, target: 'source:external', kind: 'G_MAPS_TO' });
  }
  const map = service([source], { maxResponseBytes: 24_000 });
  const first = (await map.query(scope, 'get_changes', { sourceId: 'source', limit: 2 })).data;
  const next = (await map.query(scope, 'get_changes', { sourceId: 'source', offset: 2, limit: 2 })).data;
  assert.equal(first.total, 80);
  assert.equal(first.changeSummaryScope, 'page');
  assert.equal(first.details.length, 2);
  assert.equal(first.changes.changed.length, 2);
  assert.equal(first.relationships.added.length, 2);
  assert.ok(first.relationships.added.every(e => first.details.some(d => d.entityId === e.source)));
  assert.ok(next.details.every(d => !first.details.some(previous => previous.entityId === d.entityId)));
  assert.ok(Buffer.byteLength(JSON.stringify(first)) < 24_000);
  await assert.rejects(map.query(scope, 'get_changes', { sourceId: 'source' }), { code: 'MAP_LIMIT_EXCEEDED' });
  const retained = (await service([source]).query(scope, 'get_changes', { sourceId: 'source' })).data;
  assert.equal(retained.changeSummaryScope, 'retained');
  assert.equal(retained.changes.changed.length, 80);
});

test('shared owner changes bound affected-agent lists and expose authorized total plus navigation', async () => {
  const source = fixture();
  source.current.nodes = source.current.nodes.filter(n => n.entityId === 'e:owner');
  source.current.edges = [];
  for (let i = 0; i < 130; i++) {
    source.current.nodes.push({
      id: `agent-${i}`,
      entityId: `e:agent-${i}`,
      label: 'GuardAgent',
      sourceId: source.id,
      projectionId: 'current',
      properties: { agent_id: `agent-${i}`, name: `Agent ${i}`, owner_id: 'owner' },
    });
    source.current.edges.push({ source: `agent-${i}`, target: 'source:owner', kind: 'G_OWNED_BY' });
  }
  source.previous = structuredClone(source.current);
  source.previous.id = 'previous';
  source.previous.snapshotId = 'previous';
  source.previous.nodes[0].properties.name = 'Previous team';
  const result = (await service([source]).query(scope, 'get_changes', { sourceId: 'source', limit: 1 })).data;
  const change = result.details[0];
  assert.equal(change.affectedAgents.length, 100);
  assert.equal(change.affectedAgentsTotal, 130);
  assert.equal(change.affectedAgentsTruncated, true);
  assert.equal(result.affectedAgents.length, 100);
  assert.equal(result.affectedAgentsTotal, 130);
  assert.deepEqual(plain(change.affectedAgentNavigation), {
    operation: 'list_agents',
    args: { sourceId: 'source', ownerId: 'owner' },
    scope: 'direct_current_ownership',
    limitation: 'Lists agents directly owned now; excludes indirect impact through resource ownership.',
  });
});

test('host assertion provenance is retained while manifest refresh alone is not a semantic change', async () => {
  const source = fixture();
  for (const [projection, revision] of [
    [source.current, 4],
    [source.previous, 3],
  ]) {
    for (const node of projection.nodes.filter(n =>
      ['GuardAgent', 'GuardOwner', 'GuardCredentialReference', 'GuardDeployment', 'GuardResourceBinding'].includes(
        n.label,
      ),
    )) {
      Object.assign(node.properties, {
        manifest_id: 'host-manifest',
        manifest_revision: revision,
        manifest_observed_at: `2030-01-0${revision}T00:00:00Z`,
        authority_id: 'catalog-authority',
      });
    }
  }
  const map = service([source]);
  const agent = (await map.query(scope, 'list_agents', { sourceId: source.id })).data.agents[0];
  assert.equal(agent.manifestId, 'host-manifest');
  assert.equal(agent.manifestRevision, 4);
  assert.equal(agent.authorityId, 'catalog-authority');
  for (const section of ['owners', 'deployments', 'resources', 'credentials']) {
    const row = (await map.query(scope, 'get_agent_inventory', { sourceId: source.id, agentId: 'agent', section })).data
      .items[0];
    assert.equal(row.manifestId, 'host-manifest');
    assert.equal(row.manifestRevision, 4);
  }
  assert.equal((await map.query(scope, 'get_changes', { sourceId: source.id })).data.total, 0);
});
