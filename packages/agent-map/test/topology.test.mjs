import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { MapService, MAP_OPERATIONS, MAP_INPUT_SCHEMAS, validateQueryArguments } from '../dist/service.js';

const now = Date.parse('2030-01-02T00:00:00Z');
const all = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: [], allTeams: true };
const team = teamIds => ({ ...all, teamIds, allTeams: false });
const plain = value => JSON.parse(JSON.stringify(value));

/**
 * One projection of one source. Node keys are stable across projections (the entity id), the
 * projection id is part of the node id, as in a real snapshot.
 */
function projection(sourceId, projectionId, fill) {
  const nodes = [],
    edges = [];
  const id = key => `${projectionId}:${sourceId}:${key}`;
  const api = {
    node(key, label, properties) {
      if (nodes.some(item => item.id === id(key))) return;
      nodes.push({ id: id(key), entityId: `${sourceId}:${key}`, sourceId, projectionId, label, properties });
    },
    edge(a, b, kind) {
      edges.push({ source: id(a), target: id(b), kind });
    },
    /** An agent with one deployment and one task that acts as `principal`. */
    agent(key, options = {}) {
      api.node(key, 'GuardAgent', {
        agent_id: key,
        name: options.name ?? key,
        team_id: options.team ?? 'blue',
        owner_id: options.owner ?? 'owner',
        purpose: options.purpose ?? 'Work',
        lifecycle_state: 'active',
      });
      api.node(`dep-${key}`, 'GuardDeployment', {
        deployment_id: `dep-${key}`,
        environment: options.environment ?? 'production',
        ...(options.directAccessStatus ? { direct_access_status: options.directAccessStatus } : {}),
        ...options.deployment,
      });
      api.edge(`dep-${key}`, key, 'G_INSTANCE_OF');
      api.task(key, key, options.task);
    },
    task(agent, taskKey, properties = {}) {
      api.node(`task-${taskKey}`, 'GuardTask', {
        task_id: `task-${taskKey}`,
        principal_id: `p-${taskKey}`,
        revoked: false,
        ...properties,
      });
      api.edge(`task-${taskKey}`, `dep-${agent}`, 'G_ASSIGNED_TO');
    },
    execution(agent) {
      api.node(`exec-${agent}`, 'GuardExecutionBinding', {
        binding_id: `exec-${agent}`,
        tool: 'any',
        identity_selection: 'static',
      });
      api.edge(`exec-${agent}`, `dep-${agent}`, 'G_EXECUTES_FOR');
    },
    /** A separately declared MCP connection of the agent. */
    connection(agent, key, serverId) {
      api.execution(agent);
      api.node(key, 'GuardMcpConnection', {
        connection_id: key,
        ...(serverId === undefined ? {} : { server_id: serverId }),
        state: 'ready',
      });
      api.edge(`exec-${agent}`, key, 'G_VIA_CONNECTION');
    },
    identity(agent, key, arn = `arn:aws:iam::111122223333:role/${key}`) {
      api.execution(agent);
      api.node(key, 'GuardExternalIdentity', { arn, account_id: '111122223333', provider: 'aws' });
      api.edge(`exec-${agent}`, key, 'G_USES_IDENTITY');
    },
    credential(agent, key) {
      api.node(key, 'GuardCredentialReference', { credential_id: key, name: `Credential ${key}` });
      api.edge(`dep-${agent}`, key, 'G_USES_CREDENTIAL');
    },
    /** A resource binding reached through the agent's task by its own grant and selector. */
    binding(agent, key, properties = {}) {
      api.node(key, 'GuardResourceBinding', {
        binding_id: key,
        tool: 'records.read',
        resource_ref: key,
        display_name: `Resource ${key}`,
        sensitivity: 'internal',
        ...properties,
      });
      api.node(`grant-${agent}-${key}`, 'GuardGrant', { task_id: `task-${agent}`, tool: 'records.read' });
      api.node(`selector-${agent}-${key}`, 'GuardResource', { resource_id: key, tool: 'records.read' });
      api.edge(`task-${agent}`, `grant-${agent}-${key}`, 'G_HAS_GRANT');
      api.edge(`grant-${agent}-${key}`, `selector-${agent}-${key}`, 'G_TARGETS');
      api.edge(key, `selector-${agent}-${key}`, 'G_BINDS_SELECTOR');
    },
    tool(agent, name, properties = {}) {
      api.execution(agent);
      api.node(`tool-${agent}-${name}`, 'GuardTool', { name, registered: true, approved: true, ...properties });
      api.edge(`exec-${agent}`, `tool-${agent}-${name}`, 'G_EXECUTES_TOOL');
    },
    direct(agent, key) {
      api.node(key, 'GuardDirectAccess', {
        access_id: key,
        deployment_id: `dep-${agent}`,
        kind: 'shell',
        target_ref: null,
        description: 'Ops shell',
      });
      api.edge(key, `dep-${agent}`, 'G_DIRECT_ACCESS_FOR');
    },
  };
  fill(api);
  return {
    id: projectionId,
    snapshotId: `snapshot-${projectionId}`,
    generatedAt: new Date(now - (projectionId === 'previous' ? 60_000 : 0)).toISOString(),
    status: 'published',
    nodes,
    edges,
    // Every layer collected unless a test says otherwise: dedicated and none_declared need it.
    coverage: {
      tasks: { status: 'complete' },
      tools: { status: 'complete' },
      manifest: { status: 'complete' },
      mcp: { status: 'complete' },
    },
  };
}
/** A source; `previous` is a fill function, or null for a source with one snapshot only. */
const source = (id, current, previous = null) => ({
  id,
  sourceId: id,
  tenantId: 'tenant',
  profile: 'host',
  current: projection(id, 'current', current),
  previous: previous ? projection(id, 'previous', previous) : null,
});
/**
 * A store that, like a real one, returns only what the reader's scope allows: `build` receives
 * the scope and leaves out the agents of other teams.
 */
const service = build =>
  new MapService(
    {
      read: async (scope, request) => ({
        sources: build(scope).filter(item => !request.sourceId || item.id === request.sourceId),
      }),
    },
    { clock: () => now },
  );
const fixed = (...sources) => service(() => sources);
const topology = async (map, args = {}, scope = all) => (await map.query(scope, 'get_agent_topology', args)).data;
const agentKey = (sourceId, agent) => JSON.stringify([sourceId, `${sourceId}:${agent}`]);
const byName = (data, name) => data.agents.find(agent => agent.name === name);
const hubOf = (data, kind) => data.hubs.filter(hub => hub.kind === kind);

test('get_agent_topology is registered with a closed schema', () => {
  assert.equal(MAP_OPERATIONS.length, 13);
  assert.ok(MAP_OPERATIONS.includes('get_agent_topology'));
  const schema = MAP_INPUT_SCHEMAS.get_agent_topology;
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(Object.keys(schema.properties).sort(), ['environment', 'sourceId', 'teamId']);
  assert.deepEqual(plain(validateQueryArguments('get_agent_topology', {})), {});
});

test('arguments are validated: unknown, empty and mistyped ones are rejected', async () => {
  const map = fixed(source('s', api => api.agent('a')));
  for (const args of [{ limit: 5 }, { agentId: 'a' }, { teamId: '' }, { environment: 3 }, { sourceId: ['s'] }])
    await assert.rejects(topology(map, args), { code: 'MAP_REQUEST_INVALID' }, JSON.stringify(args));
  await assert.rejects(topology(map, { sourceId: 'missing' }), { code: 'MAP_NOT_FOUND' });
});

test('a node held by one agent is not a hub; two or more visible agents make one', async () => {
  const map = fixed(
    source('s', api => {
      for (const name of ['a', 'b', 'c']) api.agent(name);
      api.credential('a', 'cred-shared');
      api.credential('b', 'cred-shared');
      api.credential('c', 'cred-own');
      api.identity('a', 'role-shared');
      api.identity('b', 'role-shared');
      api.binding('a', 'records', { sensitivity: 'restricted' });
      api.binding('b', 'records');
      api.binding('c', 'solo');
    }),
  );
  const data = await topology(map);
  assert.deepEqual(data.hubs.map(hub => hub.kind).sort(), ['cloud_identity', 'credential', 'resource']);
  assert.equal(data.hubsTotal, 3);
  assert.equal(data.hubsTruncated, false);
  for (const hub of data.hubs) assert.equal(hub.agentCount, 2);
  assert.equal(hubOf(data, 'credential')[0].name, 'Credential cred-shared');
  assert.equal(hubOf(data, 'resource')[0].sensitivity, 'restricted', 'the first holder declares it');
  const links = data.links.filter(link => link.toKind === 'hub');
  assert.equal(links.length, 6);
  assert.deepEqual([...new Set(links.map(link => link.kind))].sort(), [
    'uses_cloud_identity',
    'uses_credential',
    'uses_resource',
  ]);
  assert.equal(data.linksTotal, 6);
  const c = byName(data, 'c');
  assert.deepEqual(plain(c.isolation.credential), { status: 'dedicated', total: 1, shared: 0 });
  assert.deepEqual(plain(c.isolation.resource), { status: 'dedicated', total: 1, shared: 0 });
  assert.deepEqual(plain(c.isolation.cloud_identity), { status: 'none_declared', total: 0, shared: 0 });
  assert.deepEqual(plain(byName(data, 'a').isolation.credential), { status: 'shared', total: 1, shared: 1 });
  assert.deepEqual(plain(byName(data, 'a').isolation.mcp_server), { status: 'none_declared', total: 0, shared: 0 });
  // No manifest v4 declaration: the network is unknown, never isolated.
  assert.equal(byName(data, 'a').isolation.network.status, 'unknown');
  assert.equal(data.evidenceKind, 'declared');
  assert.equal(data.assessment, 'unknown');
  assert.equal(data.collection.networkIsolation, 'host_declared');
});

test('separately declared MCP connections to one server_id share one hub', async () => {
  const map = fixed(
    source('s', api => {
      for (const name of ['a', 'b', 'c']) api.agent(name);
      api.connection('a', 'conn-a', 'github');
      api.connection('b', 'conn-b', 'github');
      api.connection('c', 'conn-c', 'other');
    }),
  );
  const data = await topology(map);
  const hubs = hubOf(data, 'mcp_server');
  assert.equal(hubs.length, 1);
  assert.equal(hubs[0].name, 'github');
  assert.equal(hubs[0].agentCount, 2);
  assert.deepEqual(
    data.links.filter(link => link.kind === 'uses_mcp_server').map(link => link.to),
    [hubs[0].id, hubs[0].id],
  );
  assert.equal(byName(data, 'a').isolation.mcp_server.status, 'shared');
  assert.equal(byName(data, 'c').isolation.mcp_server.status, 'dedicated');
});

test('one connection node used by two agents is a hub, and a connection without server_id groups by itself', async () => {
  const map = fixed(
    source('s', api => {
      for (const name of ['a', 'b', 'c', 'd']) api.agent(name);
      api.connection('a', 'conn-one');
      api.connection('b', 'conn-one');
      api.connection('c', 'conn-c');
      api.connection('d', 'conn-d');
    }),
  );
  const hubs = hubOf(await topology(map), 'mcp_server');
  assert.equal(hubs.length, 1);
  assert.equal(hubs[0].name, 'conn-one');
});

test('hubs never join two sources, even with equal names and server ids (a cloud identity aside)', async () => {
  const fill = api => {
    api.agent('a');
    api.connection('a', 'conn', 'github');
    api.credential('a', 'cred');
  };
  const data = await topology(fixed(source('one', fill), source('two', fill)));
  assert.equal(data.agents.length, 2);
  assert.deepEqual(data.hubs, []);
  assert.deepEqual(data.links, []);
  assert.equal(byName(data, 'a') !== undefined, true);
  for (const agent of data.agents) assert.equal(agent.isolation.mcp_server.status, 'dedicated');
  // Within each source a second holder still makes a hub of that source only.
  const shared = await topology(
    fixed(
      source('one', api => {
        fill(api);
        api.agent('b');
        api.connection('b', 'conn-b', 'github');
      }),
      source('two', fill),
    ),
  );
  assert.equal(shared.hubs.length, 1);
  assert.equal(shared.hubs[0].sourceId, 'one');
  assert.equal(shared.hubs[0].agentCount, 2);
});

test('tasks that call as one principal share a principal hub with no entity id', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a', { task: { principal_id: 'svc' } });
      api.agent('b', { task: { principal_id: 'svc' } });
      api.agent('c');
    }),
  );
  const data = await topology(map);
  const hubs = hubOf(data, 'principal');
  assert.equal(hubs.length, 1);
  assert.equal(hubs[0].name, 'svc');
  assert.equal(hubs[0].entityId, null);
  assert.equal(byName(data, 'c').isolation.principal.status, 'dedicated');
});

test('a team reader gets nothing from teams outside its scope and sees own_teams visibility', async () => {
  const build = reader => [
    source('s', api => {
      const visible = name => reader.allTeams || reader.teamIds.includes(name);
      const agents = [
        ['a', 'blue'],
        ['b', 'blue'],
        ['x', 'red'],
      ].filter(([, owner]) => visible(owner));
      for (const [name, owner] of agents) {
        api.agent(name, { team: owner, name: `agent-${name}` });
        api.connection(name, `conn-${name}`, 'github');
        api.credential(name, 'cred-common');
      }
      api.binding('a', 'records');
      if (visible('red')) api.binding('x', 'records');
    }),
  ];
  const map = service(build);
  const everyone = await topology(map, {}, all);
  assert.equal(everyone.visibility, 'all_teams');
  assert.equal(everyone.agents.length, 3);
  assert.equal(hubOf(everyone, 'mcp_server')[0].agentCount, 3);
  const blue = await topology(map, {}, team(['blue']));
  assert.equal(blue.visibility, 'own_teams');
  assert.deepEqual(blue.agents.map(agent => agent.name).sort(), ['agent-a', 'agent-b']);
  assert.equal(hubOf(blue, 'mcp_server')[0].agentCount, 2);
  assert.equal(hubOf(blue, 'resource').length, 0, 'a binding shared only with a hidden team is dedicated');
  // Dedicated only within the team reader's view: an agent outside it may hold the binding too.
  assert.equal(byName(blue, 'agent-a').isolation.resource.status, 'dedicated_in_view');
  assert.equal(JSON.stringify(blue).includes('agent-x'), false);
  assert.equal(JSON.stringify(blue).includes('"red"'), false);
  const red = await topology(map, {}, team(['red']));
  assert.deepEqual(
    red.agents.map(agent => agent.name),
    ['agent-x'],
  );
  assert.deepEqual(red.hubs, []);
  assert.deepEqual(red.links, []);
  const none = await topology(map, {}, team(['green']));
  assert.deepEqual([none.agents, none.hubs, none.links], [[], [], []]);
  assert.equal(none.visibility, 'own_teams');
});

test('delegation and handoff across agents become directed links; the same agent makes none', async () => {
  const map = fixed(
    source('s', api => {
      for (const name of ['boss', 'worker', 'writer']) api.agent(name);
      api.task('worker', 'worker-sub', {});
      api.task('boss', 'boss-sub', {});
      api.edge('task-worker', 'task-boss', 'G_DELEGATED_FROM');
      api.edge('task-writer', 'task-boss', 'G_DERIVED_FROM');
      // Both tasks belong to the same agent: not a link between agents.
      api.edge('task-boss-sub', 'task-boss', 'G_DELEGATED_FROM');
      api.edge('task-worker-sub', 'task-worker', 'G_DERIVED_FROM');
    }),
  );
  const data = await topology(map);
  const boss = agentKey('s', 'boss'),
    worker = agentKey('s', 'worker'),
    writer = agentKey('s', 'writer');
  const direct = data.links.filter(link => link.toKind === 'agent');
  assert.deepEqual(
    direct.map(link => [link.kind, link.from, link.to]),
    [
      ['delegates_to', boss, worker],
      ['hands_off_to', boss, writer],
    ],
  );
  assert.ok(direct.every(link => link.directed === true));
  assert.deepEqual(plain(direct[0].via), [{ label: 'GuardTask', entityId: 's:task-worker', name: 'task-worker' }]);
  assert.equal(direct[0].viaTotal, 1);
  assert.equal(data.linksTotal, 2);
  for (const agent of data.agents) assert.equal(agent.delegationParentsNotShown, 0);
});

test('a delegated task whose parent is outside the view is counted and reveals no identity', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('child', { task: { delegated: true } });
      api.agent('alone');
      // A parent task that no visible agent owns, such as one of a hidden team's agent.
      api.node('task-hidden', 'GuardTask', { task_id: 'secret-parent-task', principal_id: 'p-hidden', revoked: false });
      api.edge('task-child', 'task-hidden', 'G_DELEGATED_FROM');
    }),
  );
  const data = await topology(map);
  assert.deepEqual(data.links, []);
  assert.equal(byName(data, 'child').delegationParentsNotShown, 1);
  assert.equal(byName(data, 'alone').delegationParentsNotShown, 0);
  assert.equal(JSON.stringify(data).includes('secret-parent-task'), false);
  assert.equal(JSON.stringify(data).includes('p-hidden'), false);
  // With no parent node in the projection at all, the delegated flag alone is counted.
  const flagged = await topology(fixed(source('s', api => api.agent('child', { task: { delegated: true } }))));
  assert.equal(byName(flagged, 'child').delegationParentsNotShown, 1);
  const handoff = await topology(fixed(source('s', api => api.agent('child', { task: { derived: true } }))));
  assert.equal(byName(handoff, 'child').delegationParentsNotShown, 1);
});

test('can_send_to needs a recipient that is another agent task principal in the same source', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('sender', { task: { allowed_recipients: ['p-receiver', 'p-sender', 'stranger@example.com'] } });
      api.agent('receiver');
      api.agent('bystander');
    }),
    source('t', api => {
      api.agent('sender', { task: { allowed_recipients: ['p-receiver'] } });
      api.agent('other');
    }),
  );
  const data = await topology(map);
  const sends = data.links.filter(link => link.kind === 'can_send_to');
  assert.deepEqual(
    sends.map(link => [link.from, link.to]),
    [[agentKey('s', 'sender'), agentKey('s', 'receiver')]],
  );
  assert.equal(sends[0].directed, true);
  const none = await topology(
    fixed(
      source('s', api => {
        api.agent('sender', { task: { allowed_recipients: ['p-sender', 'someone'] } });
        api.agent('receiver');
      }),
    ),
  );
  assert.deepEqual(none.links, []);
});

test('depends_on links agents whose resource bindings depend on each other', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('app');
      api.agent('db');
      api.agent('lone');
      api.binding('app', 'app-data');
      api.binding('db', 'db-data');
      api.binding('lone', 'lone-data');
      api.edge('app-data', 'db-data', 'G_DEPENDS_ON');
      // A dependency inside one agent is not a link between agents.
      api.binding('app', 'app-cache');
      api.edge('app-data', 'app-cache', 'G_DEPENDS_ON');
    }),
  );
  const data = await topology(map);
  const links = data.links.filter(link => link.kind === 'depends_on');
  assert.deepEqual(
    links.map(link => [link.from, link.to]),
    [[agentKey('s', 'app'), agentKey('s', 'db')]],
  );
  assert.equal(links[0].via[0].name, 'Resource app-data');
  assert.equal(data.hubs.length, 0);
});

test('lastChange: no previous snapshot, added, unchanged and changed', async () => {
  const before = api => {
    api.agent('stays', { purpose: 'Reads' });
    api.agent('edited', { purpose: 'Reads' });
    api.agent('still', { purpose: 'Reads' });
  };
  const after = api => {
    api.agent('stays', { purpose: 'Reads' });
    api.agent('edited', { purpose: 'Reads and writes' });
    api.connection('edited', 'conn-new', 'github');
    api.agent('still', { purpose: 'Reads' });
    api.agent('fresh');
  };
  const first = await topology(fixed(source('s', after)));
  for (const agent of first.agents) {
    assert.equal(agent.lastChange.status, 'no_previous_snapshot');
    assert.equal(agent.lastChange.from, null);
    assert.equal(agent.lastChange.total, 0);
  }
  const data = await topology(fixed(source('s', after, before)));
  assert.equal(byName(data, 'fresh').lastChange.status, 'added');
  assert.equal(byName(data, 'stays').lastChange.status, 'unchanged');
  assert.equal(byName(data, 'still').lastChange.status, 'unchanged');
  const edited = byName(data, 'edited').lastChange;
  assert.equal(edited.status, 'changed');
  assert.ok(edited.total >= 2);
  assert.ok(edited.items.length <= 5);
  assert.equal(edited.from, new Date(now - 60_000).toISOString());
  assert.equal(edited.to, new Date(now).toISOString());
  assert.ok(edited.items.some(item => item.kind === 'added' && item.label === 'GuardMcpConnection'));
  assert.ok(edited.items.some(item => item.kind === 'changed' && item.label === 'GuardAgent'));
  // The categories are the ones get_changes reports for the same agent.
  const map = fixed(source('s', after, before));
  const changes = (await map.query(all, 'get_changes', { sourceId: 's', agentId: 'edited' })).data;
  const expected = [...new Set(changes.details.flatMap(item => item.categories))].sort();
  assert.deepEqual(plain(edited.categories), expected);
  assert.deepEqual(Object.keys(edited.counts).sort(), expected);
  assert.ok(expected.includes('inventory'));
  assert.equal(
    Object.values(edited.counts).every(count => count >= 1),
    true,
  );
});

test('lastChange categories for a relationship-only change match get_changes', async () => {
  const before = api => {
    api.agent('a');
    api.agent('b');
    api.binding('a', 'records');
    api.binding('b', 'other');
  };
  const after = api => {
    before(api);
    api.edge('records', 'other', 'G_DEPENDS_ON');
    api.tool('a', 'mail.send', { sends_external: true });
  };
  const map = fixed(source('s', after, before));
  const data = await topology(map);
  const changes = (await map.query(all, 'get_changes', { sourceId: 's', agentId: 'a' })).data;
  const expected = [...new Set(changes.details.flatMap(item => item.categories))].sort();
  const a = byName(data, 'a').lastChange;
  assert.equal(a.status, 'changed');
  assert.deepEqual(plain(a.categories), expected);
});

test('teamId and environment filters narrow the drawn agents but never turn a shared item dedicated', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a', { team: 'blue', environment: 'production' });
      api.agent('b', { team: 'blue', environment: 'development' });
      api.agent('c', { team: 'red', environment: 'production' });
      for (const name of ['a', 'b', 'c']) api.connection(name, `conn-${name}`, 'github');
    }),
    source('t', api => api.agent('d', { team: 'blue', environment: 'production' })),
  );
  const names = data => data.agents.map(agent => agent.name).sort();
  assert.deepEqual(names(await topology(map)), ['a', 'b', 'c', 'd']);
  const blue = await topology(map, { teamId: 'blue' });
  assert.deepEqual(names(blue), ['a', 'b', 'd']);
  // Agent c is filtered out but still holds the server: three holders, one not drawn.
  assert.deepEqual([hubOf(blue, 'mcp_server')[0].agentCount, hubOf(blue, 'mcp_server')[0].agentsNotDrawn], [3, 1]);
  const production = await topology(map, { environment: 'production' });
  assert.deepEqual(names(production), ['a', 'c', 'd']);
  assert.deepEqual(
    [hubOf(production, 'mcp_server')[0].agentCount, hubOf(production, 'mcp_server')[0].agentsNotDrawn],
    [3, 1],
  );
  const narrow = await topology(map, { teamId: 'blue', environment: 'production', sourceId: 's' });
  assert.deepEqual(names(narrow), ['a']);
  assert.deepEqual(plain(narrow.hubs.map(hub => [hub.agentCount, hub.agentsNotDrawn])), [[3, 2]]);
  assert.equal(byName(narrow, 'a').isolation.mcp_server.status, 'shared');
  // sourceId is a draw filter too: every visible source still counts toward sharing.
  assert.equal(narrow.agentsInView, 4);
  assert.deepEqual((await topology(map, { teamId: 'nobody' })).agents, []);
  assert.deepEqual(names(await topology(map, { sourceId: 't' })), ['d']);
});

test('egress status reports allowlisted, refused, none_declared and unknown sending', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('sends', { task: { allowed_recipients: ['ops@example.com', 'ops@example.com', 'p-relay'] } });
      api.tool('sends', 'mail.send', { sends_external: true, requires_approval: false });
      api.tool('sends', 'mail.draft', { sends_external: false });
      api.agent('relay');
      api.agent('quiet');
      api.tool('quiet', 'records.read', { sends_external: false });
      api.agent('undeclared');
      api.tool('undeclared', 'records.read');
      api.agent('toolless');
      api.agent('approved', { task: { allowed_recipients: [] } });
      api.tool('approved', 'mail.send', { sends_external: true, requires_approval: true });
    }),
  );
  const data = await topology(map);
  const egress = name => byName(data, name).isolation.egress;
  assert.equal(egress('sends').status, 'allowlisted');
  assert.deepEqual(plain(egress('sends').sendingTools), ['mail.send']);
  assert.equal(egress('sends').sendingToolsWithoutApproval, 1);
  assert.deepEqual(plain(egress('sends').recipients), ['ops@example.com', 'p-relay']);
  assert.equal(egress('sends').recipientsTotal, 2);
  assert.equal(egress('approved').sendingToolsWithoutApproval, 0);
  // A sending tool but no recipient listed anywhere: the executor refuses every external send.
  assert.equal(egress('approved').status, 'refused');
  assert.equal(egress('quiet').status, 'none_declared');
  assert.equal(egress('toolless').reason, 'no_tools');
  assert.equal(egress('undeclared').status, 'unknown');
  assert.equal(egress('undeclared').toolsWithUndeclaredSending, 1);
  assert.equal(egress('toolless').status, 'unknown');
});

test('direct access is found, none_declared or unknown from the deployment declaration', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('found', { directAccessStatus: 'found' });
      api.direct('found', 'shell');
      api.agent('declared', { directAccessStatus: 'none_declared' });
      api.agent('silent');
    }),
  );
  const data = await topology(map);
  const egress = name => byName(data, name).isolation.egress;
  assert.equal(egress('found').directAccess, 'found');
  assert.equal(egress('found').directAccessPaths, 1);
  assert.equal(egress('declared').directAccess, 'none_declared');
  assert.equal(egress('declared').directAccessPaths, 0);
  assert.equal(egress('silent').directAccess, 'unknown');
});

test('agents carry identity fields, sort by name and expose the declared limits', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('z', { name: 'Zed' });
      api.agent('a', { name: 'Alpha', environment: 'staging' });
    }),
  );
  const data = await topology(map);
  assert.deepEqual(
    data.agents.map(agent => agent.name),
    ['Alpha', 'Zed'],
  );
  const alpha = data.agents[0];
  assert.equal(alpha.key, agentKey('s', 'a'));
  assert.equal(alpha.agentId, 'a');
  assert.equal(alpha.sourceId, 's');
  assert.equal(alpha.teamId, 'blue');
  assert.equal(alpha.lifecycleState, 'active');
  assert.deepEqual(plain(alpha.environments), ['staging']);
  assert.equal(typeof alpha.dangerousThree, 'string');
  assert.equal(data.limitations.length, 6);
  assert.equal(data.sources[0].previousGeneratedAt, null);
  assert.equal(data.linksTruncated, false);
});

test('a layer whose collection is incomplete reads not_collected or unknown, never dedicated or none', async () => {
  const withCoverage = (coverage, fill) => {
    const item = source('s', fill);
    return { ...item, current: { ...item.current, coverage } };
  };
  const fill = api => {
    api.agent('a');
    api.connection('a', 'conn-a', 'github');
  };
  const core = await topology(fixed(withCoverage({ tasks: { status: 'complete' } }, fill)));
  const a = byName(core, 'a').isolation;
  // A connection is recorded but MCP collection is not reported: unknown, not "not collected".
  assert.equal(a.mcp_server.status, 'unknown');
  assert.equal(a.credential.status, 'not_collected');
  assert.equal(a.resource.status, 'not_collected');
  assert.equal(a.principal.status, 'dedicated');
  const partial = await topology(
    fixed(
      withCoverage(
        { tasks: { status: 'complete' }, manifest: { status: 'partial' }, mcp: { status: 'partial' } },
        fill,
      ),
    ),
  );
  assert.equal(byName(partial, 'a').isolation.mcp_server.status, 'unknown');
  assert.equal(byName(partial, 'a').isolation.credential.status, 'unknown');
  // Shared is positive evidence and stands even when collection is partial.
  const both = await topology(
    fixed(
      withCoverage({ mcp: { status: 'partial' } }, api => {
        fill(api);
        api.agent('b');
        api.connection('b', 'conn-b', 'github');
      }),
    ),
  );
  assert.equal(byName(both, 'a').isolation.mcp_server.status, 'shared');
});

test('MCP connections with one server id but different transports are two servers', async () => {
  const map = fixed(
    source('s', api => {
      for (const [agent, transport] of [
        ['a', 'opaque:1'],
        ['b', 'opaque:2'],
      ]) {
        api.agent(agent);
        api.execution(agent);
        api.node(`conn-${agent}`, 'GuardMcpConnection', {
          connection_id: `conn-${agent}`,
          server_id: 'github',
          transport_ref: transport,
        });
        api.edge(`exec-${agent}`, `conn-${agent}`, 'G_VIA_CONNECTION');
      }
    }),
  );
  const data = await topology(map);
  assert.equal(hubOf(data, 'mcp_server').length, 0);
  assert.equal(byName(data, 'a').isolation.mcp_server.status, 'dedicated');
});

test('lastChange does not call a node added when it already existed and is only newly reachable', async () => {
  const before = api => {
    api.agent('a');
    api.agent('b');
    api.node('owner-1', 'GuardOwner', { owner_id: 'o1', name: 'Owner one' });
    api.binding('b', 'records');
    api.edge('records', 'owner-1', 'G_RESOURCE_OWNED_BY');
  };
  const after = api => {
    before(api);
    // Agent a gains its own grant to b's existing binding.
    api.binding('a', 'records');
  };
  const map = fixed(source('s', after, before));
  const change = byName(await topology(map), 'a').lastChange;
  const changes = (await map.query(all, 'get_changes', { sourceId: 's', agentId: 'a' })).data;
  assert.equal(change.status, 'changed');
  assert.deepEqual(plain(change.categories), [...new Set(changes.details.flatMap(item => item.categories))].sort());
  // The binding and its owner existed before: the binding changed (a new selector), the owner did not.
  const binding = change.items.find(item => item.label === 'GuardResourceBinding');
  assert.equal(binding.kind, 'changed');
  assert.ok(!change.items.some(item => item.label === 'GuardOwner'));
  assert.ok(!change.categories.includes('ownership'));
});

test('a revoked task does not widen the recipient list, and depends_on skips a dependency the agent also holds', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a', { task: { allowed_recipients: ['live@example.com'] } });
      api.task('a', 'old', { revoked: true, allowed_recipients: ['old@example.com'] });
      api.tool('a', 'mail.send', { sends_external: true });
      api.agent('b');
      api.binding('a', 'mine');
      api.binding('a', 'common');
      api.binding('b', 'common');
      api.edge('mine', 'common', 'G_DEPENDS_ON');
    }),
  );
  const data = await topology(map);
  assert.deepEqual(plain(byName(data, 'a').isolation.egress.recipients), ['live@example.com']);
  assert.equal(data.links.filter(link => link.kind === 'depends_on').length, 0);
});

test('agent-to-agent links are counted apart from shared-item links and listed first', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a');
      api.agent('b', { task: { allowed_recipients: ['p-a'] } });
      for (const name of ['a', 'b']) api.connection(name, `conn-${name}`, 'github');
    }),
  );
  const data = await topology(map);
  assert.equal(data.links[0].kind, 'can_send_to');
  assert.equal(data.links[0].via[0].match, 'recipient_equals_principal');
  assert.equal(data.agentLinksTotal, 1);
  assert.equal(data.linksTotal, 3);
});

test('a sending agent whose tasks do not record recipients is unknown, not refused', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a');
      api.node('task-a', 'GuardTask', { task_id: 'task-a', principal_id: 'p-a', revoked: false });
      api.tool('a', 'mail.send', { sends_external: true });
      api.agent('b', { task: { allowed_recipients: ['x@example.com'], deadline: now - 1 } });
      api.tool('b', 'mail.send', { sends_external: true });
    }),
  );
  const data = await topology(map);
  const a = byName(data, 'a').isolation.egress;
  assert.deepEqual([a.status, a.reason], ['unknown', 'recipients_not_recorded']);
  // An expired task's list does not count; b's only live list is empty, so every send is refused.
  assert.equal(byName(data, 'b').isolation.egress.status, 'refused');
});

test('network: a shared segment is a hub; open egress and a missing sandbox are positive evidence', async () => {
  const map = fixed(
    source('s', api => {
      for (const [agent, network] of [
        [
          'a',
          {
            network_status: 'declared',
            network_segment: 'seg-1',
            network_egress: 'allowlist',
            network_egress_targets: ['opaque:t1'],
            sandbox_kind: 'container',
          },
        ],
        [
          'b',
          {
            network_status: 'declared',
            network_segment: 'seg-1',
            network_egress: 'open',
            network_egress_targets: [],
            sandbox_kind: 'none',
          },
        ],
        [
          'c',
          {
            network_status: 'declared',
            network_segment: null,
            network_egress: 'none',
            network_egress_targets: [],
            sandbox_kind: 'vm',
          },
        ],
        ['d', { network_status: 'not_declared' }],
        ['e', {}],
      ])
        api.agent(agent, { deployment: network });
    }),
  );
  const data = await topology(map);
  const net = name => byName(data, name).isolation.network;
  assert.deepEqual(plain(hubOf(data, 'network_segment').map(hub => [hub.name, hub.agentCount])), [['seg-1', 2]]);
  assert.deepEqual(
    plain([net('a').status, net('a').segment.status, net('a').egress, net('a').sandbox, net('a').egressTargets]),
    ['declared', 'shared', 'allowlist', 'container', ['opaque:t1']],
  );
  assert.deepEqual(plain([net('b').egress, net('b').sandbox]), ['open', 'none']);
  // d and e did not declare, so c cannot be shown alone on the network; its own policy still stands.
  assert.deepEqual(plain([net('c').segment.status, net('c').egress, net('c').sandbox]), ['unknown', 'none', 'vm']);
  assert.deepEqual(plain([net('d').status, net('d').segment.status, net('d').egress, net('d').sandbox]), [
    'not_declared',
    'unknown',
    'unknown',
    'unknown',
  ]);
  assert.equal(net('e').status, 'unknown');
  assert.equal(data.links.filter(link => link.kind === 'uses_network_segment').length, 2);
});

test('network: one undeclared deployment keeps the agent partial; open egress on another still stands', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a', {
        deployment: {
          network_status: 'declared',
          network_segment: 'seg',
          network_egress: 'open',
          network_egress_targets: [],
          sandbox_kind: 'vm',
        },
      });
      api.node('dep-a2', 'GuardDeployment', { deployment_id: 'dep-a2', environment: 'production' });
      api.edge('dep-a2', 'a', 'G_INSTANCE_OF');
    }),
  );
  const net = byName(await topology(map), 'a').isolation.network;
  assert.deepEqual(plain([net.status, net.egress, net.sandbox, net.segment.status]), [
    'partial',
    'open',
    'unknown',
    'unknown',
  ]);
  assert.deepEqual([net.deploymentsDeclared, net.deployments], [1, 2]);
});

test('one IAM ARN used from two sources is one cloud identity hub outside both sources', async () => {
  const fill = api => {
    api.agent('a');
    api.identity('a', 'role', 'arn:aws:iam::111122223333:role/shared');
  };
  const data = await topology(fixed(source('one', fill), source('two', fill)));
  const [hub] = hubOf(data, 'cloud_identity');
  assert.deepEqual(plain([hub.sourceId, hub.sourceIds, hub.agentCount]), [null, ['one', 'two'], 2]);
  for (const agent of data.agents) assert.equal(agent.isolation.cloud_identity.status, 'shared');
});

test('a revoked or expired task links nothing and calls as no principal', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a');
      api.agent('b', { task: { revoked: true, allowed_recipients: ['p-a'], principal_id: 'p-shared' } });
      api.agent('c', { task: { deadline: now - 1, principal_id: 'p-shared' } });
      api.task('b', 'child', { revoked: true });
      api.edge('task-child', 'task-a', 'G_DELEGATED_FROM');
    }),
  );
  const data = await topology(map);
  assert.deepEqual(
    data.links.filter(link => link.toKind === 'agent'),
    [],
  );
  assert.deepEqual(hubOf(data, 'principal'), []);
});

test('agents gone since the previous snapshot are listed, filters applied', async () => {
  const before = api => {
    api.agent('a', { team: 'blue' });
    api.agent('gone', { team: 'blue' });
    api.agent('other', { team: 'red' });
  };
  const map = fixed(source('s', api => api.agent('a', { team: 'blue' }), before));
  const data = await topology(map);
  assert.deepEqual(plain(data.removedAgents.map(agent => agent.name)), ['gone', 'other']);
  assert.equal(data.removedAgentsTotal, 2);
  assert.deepEqual(plain((await topology(map, { teamId: 'blue' })).removedAgents.map(agent => agent.name)), ['gone']);
});

test('a fleet too large for the full answer answers compact: every status and count, no detail lists', async () => {
  const fill = api => {
    for (let index = 0; index < 60; index++) {
      const name = `agent-${String(index).padStart(3, '0')}`;
      api.agent(name, {
        task: { allowed_recipients: Array.from({ length: 10 }, (_, item) => `r-${index}-${item}@example.com`) },
      });
      api.tool(name, 'mail.send', { sends_external: true });
      api.connection(name, `conn-${name}`, 'github');
    }
  };
  const full = await topology(fixed(source('s', fill)));
  assert.equal(full.compact, undefined);
  const size = Buffer.byteLength(JSON.stringify(full));
  const small = new MapService(
    { read: async () => ({ sources: [source('s', fill)] }) },
    { clock: () => now, maxResponseBytes: Math.floor(size * 0.95) },
  );
  const compact = (await small.query(all, 'get_agent_topology', {})).data;
  assert.equal(compact.compact, true);
  assert.equal(compact.agents.length, 60);
  assert.ok(
    compact.agents.every(
      agent => agent.isolation.egress.recipients.length === 0 && agent.isolation.egress.recipientsTotal === 10,
    ),
  );
  assert.equal(compact.hubs.length, full.hubs.length);
});

test('sourceId only chooses what is drawn: an IAM identity shared with another source stays shared', async () => {
  const fill = api => {
    api.agent('a');
    api.identity('a', 'role', 'arn:aws:iam::111122223333:role/x');
  };
  const data = await topology(fixed(source('one', fill), source('two', fill)), { sourceId: 'one' });
  assert.deepEqual(
    data.agents.map(agent => agent.sourceId),
    ['one'],
  );
  assert.equal(data.agents[0].isolation.cloud_identity.status, 'shared');
  assert.deepEqual(plain(hubOf(data, 'cloud_identity').map(hub => [hub.agentCount, hub.agentsNotDrawn])), [[2, 1]]);
  assert.equal(data.agentsInView, 2);
});

test('a segment no one else is seen on is dedicated only when every deployment of the source declared', async () => {
  const declared = {
    network_status: 'declared',
    network_segment: 'seg',
    network_egress: 'none',
    network_egress_targets: [],
    sandbox_kind: 'vm',
  };
  const both = await topology(
    fixed(
      source('s', api => {
        api.agent('a', { deployment: declared });
        api.agent('b', { deployment: { ...declared, network_segment: 'other' } });
      }),
    ),
  );
  assert.equal(byName(both, 'a').isolation.network.segment.status, 'dedicated');
  for (const other of [{ network_status: 'not_declared' }, {}]) {
    const partial = await topology(
      fixed(
        source('s', api => {
          api.agent('a', { deployment: declared });
          api.agent('b', { deployment: other });
        }),
      ),
    );
    assert.equal(byName(partial, 'a').isolation.network.segment.status, 'unknown', JSON.stringify(other));
    // Its own egress and sandbox are still its own declaration.
    assert.deepEqual(
      plain([byName(partial, 'a').isolation.network.egress, byName(partial, 'a').isolation.network.sandbox]),
      ['none', 'vm'],
    );
  }
});

test('a declared value outside the vocabulary makes that part unknown, and a segment hub names no node', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a', {
        deployment: {
          network_status: 'declared',
          network_segment: 'seg',
          network_egress: 'none',
          network_egress_targets: [],
          sandbox_kind: 'vm',
        },
      });
      api.node('dep-a2', 'GuardDeployment', {
        deployment_id: 'dep-a2',
        environment: 'production',
        network_status: 'declared',
        network_segment: 'seg',
        network_egress: 'weird',
        sandbox_kind: 'odd',
      });
      api.edge('dep-a2', 'a', 'G_INSTANCE_OF');
      api.agent('b', {
        deployment: {
          network_status: 'declared',
          network_segment: 'seg',
          network_egress: 'none',
          network_egress_targets: [],
          sandbox_kind: 'vm',
        },
      });
    }),
  );
  const data = await topology(map);
  const net = byName(data, 'a').isolation.network;
  assert.deepEqual(plain([net.egress, net.sandbox]), ['unknown', 'unknown']);
  assert.equal(hubOf(data, 'network_segment')[0].entityId, null);
});

test('recipients recorded on only some live tasks give allowlisted with a reason', async () => {
  const map = fixed(
    source('s', api => {
      api.agent('a', { task: { allowed_recipients: ['x@example.com'] } });
      api.node('task-a2', 'GuardTask', { task_id: 'task-a2', principal_id: 'p-a2', revoked: false });
      api.edge('task-a2', 'dep-a', 'G_ASSIGNED_TO');
      api.tool('a', 'mail.send', { sends_external: true });
    }),
  );
  const egress = byName(await topology(map), 'a').isolation.egress;
  assert.deepEqual(plain([egress.status, egress.reason]), ['allowlisted', 'recipients_partly_recorded']);
});

test('when even the compact answer does not fit, links to shared items are left out and agent links stay', async () => {
  const fill = api => {
    for (let index = 0; index < 40; index++) {
      const name = `agent-${String(index).padStart(3, '0')}`;
      api.agent(name, { task: { allowed_recipients: index ? ['p-agent-000'] : [] } });
      for (const server of ['github', 'slack', 'jira', 'docs']) api.connection(name, `conn-${name}-${server}`, server);
      api.credential(name, 'shared-credential');
    }
  };
  const full = await topology(fixed(source('s', fill)));
  const agentOnly = { ...full, links: full.links.filter(link => link.toKind === 'agent') };
  const compactSize = Buffer.byteLength(JSON.stringify(agentOnly));
  const small = new MapService(
    { read: async () => ({ sources: [source('s', fill)] }) },
    { clock: () => now, maxResponseBytes: Math.ceil((compactSize + 4000) / 0.9) },
  );
  const data = (await small.query(all, 'get_agent_topology', {})).data;
  assert.deepEqual([data.compact, data.hubLinksOmitted], [true, true]);
  assert.ok(data.links.length > 0 && data.links.every(link => link.toKind === 'agent'));
  assert.equal(data.hubs.length, full.hubs.length);
  assert.equal(data.linksTotal, full.linksTotal);
});
