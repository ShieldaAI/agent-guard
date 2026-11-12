import test from 'node:test';
import assert from 'node:assert/strict';
import { Neo4jMapStore, createNeo4jMapStore } from '../dist/store.js';
import { MapService } from '../dist/service.js';
import { validateReadScope } from '../dist/types.js';

const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false };
const captures = (tasks, tools = tasks) =>
  JSON.stringify({
    tasks: { status: 'complete', observedAt: tasks },
    tools: { status: 'complete', observedAt: tools },
  });
const source = {
  id: 'source',
  tenantId: 'tenant',
  nativeSourceId: 'installation',
  profile: 'host',
  currentId: 'projection',
  currentSnapshotId: 'receipt',
  currentGeneratedAt: '2026-10-30T00:00:00Z',
  currentCoverage: captures('2026-10-30T00:00:00Z'),
  previousId: null,
};
const agent = {
  id: 'agent-node',
  entity_id: 'agent-entity',
  source_id: 'source',
  projection_id: 'projection',
  agent_id: 'agent',
  name: 'Visible agent',
  team_id: 'team',
  owner_id: null,
  metadata: 'private-canary',
};
const records = values => values.map(value => ({ get: name => value[name] }));
function fake(options = {}) {
  const calls = [];
  let sourceReads = 0,
    rolledBack = 0,
    closed = 0;
  const tx = {
    isOpen: () => true,
    rollback: async () => {
      rolledBack++;
    },
    run: async function* (query, params) {
      calls.push({ query, params });
      if (options.run) {
        yield* records(await options.run(query, params, calls.length));
        return;
      }
      if (query.startsWith('MATCH (s:GuardSource)')) {
        sourceReads++;
        if (options.supersedeSource && sourceReads > 1) return;
        yield* records(
          options.sources ?? [
            { ...source, ...(options.changePointer && sourceReads > 1 ? { currentId: 'newer' } : {}) },
          ],
        );
        return;
      }
      if (query.includes(' AS node')) {
        const label = query.match(/RETURN '(\w+)' AS label/)[1];
        yield* records(
          (options.nodes ?? [{ label: 'GuardAgent', node: agent }]).filter(
            item => item.label === label || item.label === 'AWSRole',
          ),
        );
        return;
      }
      yield* records(options.edges ?? []);
    },
  };
  return {
    calls,
    status: () => ({ rolledBack, closed }),
    driver: {
      session(config) {
        assert.equal(config.defaultAccessMode, 'READ');
        return {
          beginTransaction(config) {
            assert.ok(config.timeout <= 5000);
            return tx;
          },
          close: async () => {
            closed++;
          },
        };
      },
      close: async () => {},
    },
  };
}

test('read scope is a detached closed allowlist and never invokes accessors', () => {
  const input = structuredClone(scope),
    result = validateReadScope(input);
  input.tenantIds.push('foreign');
  assert.deepEqual(result.tenantIds, ['tenant']);
  assert.equal(Object.isFrozen(result), true);
  let called = false;
  assert.throws(
    () =>
      validateReadScope({
        ...scope,
        get subject() {
          called = true;
          return 'x';
        },
      }),
    { code: 'MAP_SCOPE_INVALID' },
  );
  assert.equal(called, false);
  for (const value of [
    { ...scope, roles: ['admin'] },
    { ...scope, tenantIds: [] },
    { ...scope, teamIds: [] },
    { ...scope, tenantIds: ['tenant', 'tenant'] },
  ]) {
    assert.throws(() => validateReadScope(value), { code: 'MAP_SCOPE_INVALID' });
  }
});

test('store binds trusted scope into fixed read templates and strips arbitrary graph properties', async () => {
  const backend = fake();
  const store = new Neo4jMapStore(backend.driver);
  const result = await store.read(scope, { sourceId: "id' MATCH (n) DETACH DELETE n //" });
  assert.equal(result.sources[0].current.nodes[0].properties.name, 'Visible agent');
  assert.equal(JSON.stringify(result).includes('private-canary'), false);
  assert.equal(Object.isFrozen(result.sources[0].current.nodes), true);
  assert.equal(backend.calls[0].params.sourceId, "id' MATCH (n) DETACH DELETE n //");
  assert.equal(backend.calls[0].params.companyId, 'company');
  assert.deepEqual(backend.calls[0].params.tenantIds, ['tenant']);
  assert.deepEqual(backend.calls[0].params.teamIds, ['team']);
  for (const { query } of backend.calls) {
    assert.equal(/\b(CREATE|MERGE|DELETE|SET|REMOVE|CALL|LOAD\s+CSV)\b/.test(query), false);
    assert.equal(query.includes("id' MATCH"), false);
    assert.equal(query.includes('properties('), false);
  }
  assert.deepEqual(backend.status(), { rolledBack: 1, closed: 1 });
});

test('publication pointer changes reject the whole view', async () => {
  const backend = fake({ changePointer: true });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_UNAVAILABLE' });
});

test('source supersession is filtered on selection and the final recheck', async () => {
  const backend = fake({ supersedeSource: true });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_UNAVAILABLE' });
  const selections = backend.calls.filter(call => call.query.startsWith('MATCH (s:GuardSource)'));
  assert.equal(selections.length, 2);
  for (const { query } of selections) assert.match(query, /coalesce\(s\.lifecycle_status,'active'\)='active'/);
  assert.deepEqual(backend.status(), { rolledBack: 1, closed: 1 });
});

test('agent summaries read only the authorized agent deployment and ownership index', async () => {
  const backend = fake();
  const result = await new Neo4jMapStore(backend.driver, { maxNodes: 1 }).read(scope, { summary: true });
  assert.equal(result.sources[0].current.nodes.length, 1);
  assert.equal(result.sources[0].current.coverage.tasks.status, 'not_collected');
  assert.equal(backend.calls.filter(call => call.query.includes(' AS node')).length, 3);
  assert.equal(
    backend.calls.some(call => call.query.includes("RETURN 'GuardTask' AS label")),
    false,
  );
});

test('source, node and edge limits reject complete views without truncation', async () => {
  for (const [options, limits] of [
    [{ sources: [source, source] }, { maxSources: 1 }],
    [
      {
        nodes: [
          { label: 'GuardAgent', node: agent },
          { label: 'GuardAgent', node: { ...agent, id: 'other' } },
        ],
      },
      { maxNodes: 1 },
    ],
    [
      {
        edges: [
          { source: agent.id, target: agent.id, kind: 'G_INSTANCE_OF' },
          { source: agent.id, target: agent.id, kind: 'G_INSTANCE_OF' },
        ],
      },
      { maxEdges: 1 },
    ],
  ])
    await assert.rejects(new Neo4jMapStore(fake(options).driver, limits).read(scope), { code: 'MAP_LIMIT_EXCEEDED' });
});

test('cumulative byte bounds stop streamed materialization before later graph queries', async () => {
  const backend = fake({
    nodes: Array.from({ length: 12 }, (_, i) => ({
      label: 'GuardAgent',
      node: { ...agent, id: `node-${i}`, name: 'x'.repeat(480_000) },
    })),
  });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_LIMIT_EXCEEDED' });
  assert.equal(backend.calls.length, 2);
  assert.deepEqual(backend.status(), { rolledBack: 1, closed: 1 });
});

test('component capture timestamps remain independent of the core publication timestamp', async () => {
  const backend = fake({
    sources: [{ ...source, profile: 'host-mcp' }],
    nodes: [
      { label: 'GuardAgent', node: { ...agent, manifest_observed_at: '2026-10-20T01:00:00Z' } },
      {
        label: 'GuardMcpConnection',
        node: {
          ...agent,
          id: 'connection',
          entity_id: 'connection-entity',
          capture_status: 'observed',
          capture_observed_at: '2026-10-21T02:00:00Z',
          observed_at: '2026-10-21T02:00:00Z',
        },
      },
      {
        label: 'GuardExternalResource',
        node: {
          ...agent,
          id: 'external',
          entity_id: 'external-entity',
          cloud_status: 'resolved',
          cloud_observed_at: Date.parse('2026-10-22T03:00:00Z') / 1000,
        },
      },
    ],
  });
  const result = await new Neo4jMapStore(backend.driver).read(scope);
  const coverage = result.sources[0].current.coverage;
  assert.equal(coverage.tasks.observedAt, source.currentGeneratedAt);
  assert.equal(coverage.manifest.observedAt, '2026-10-20T01:00:00.000Z');
  assert.equal(coverage.mcp.observedAt, '2026-10-21T02:00:00.000Z');
  assert.equal(coverage.cloud.observedAt, '2026-10-22T03:00:00.000Z');
  const edgeQuery = backend.calls.find(call => call.query.includes('RETURN n.id AS source'));
  assert.equal(edgeQuery.params.tenantId, 'tenant');
  assert.match(edgeQuery.query, /n\.tenant_id=\$tenantId AND m\.tenant_id=\$tenantId/);
});

test('recomposition cannot renew original task, tool or MCP observation freshness', async () => {
  const old = '2026-10-01T00:00:00Z',
    toolTime = '2026-10-02T00:00:00Z';
  const now = Date.parse(source.currentGeneratedAt);
  const backend = fake({
    sources: [{ ...source, profile: 'host-mcp', currentCoverage: captures(old, toolTime) }],
    nodes: [
      { label: 'GuardAgent', node: agent },
      {
        label: 'GuardMcpConnection',
        node: {
          ...agent,
          id: 'connection',
          entity_id: 'connection-entity',
          capture_status: 'observed',
          capture_observed_at: source.currentGeneratedAt,
          observed_at: old,
        },
      },
    ],
  });
  const result = await new MapService(new Neo4jMapStore(backend.driver, { clock: () => now }), {
    clock: () => now,
  }).query(scope, 'get_inventory_health', {});
  const health = result.data.sources[0];
  assert.equal(health.stale, false);
  assert.equal(health.coverage.tasks.observedAt, old);
  assert.equal(health.coverage.tools.observedAt, toolTime);
  assert.equal(health.coverage.mcp.observedAt, '2026-10-01T00:00:00.000Z');
  for (const component of ['tasks', 'tools', 'mcp']) {
    assert.equal(health.coverage[component].stale, true);
    assert.ok(health.coverage[component].ageSeconds > 86_400);
  }
  assert.match(backend.calls[0].query, /substring\(p\.coverage_json,0,4097\) AS currentCoverage/);
});

test('missing original core coverage stays unknown instead of inheriting generation time', async () => {
  for (const currentCoverage of [undefined, null]) {
    const backend = fake({ sources: [{ ...source, currentCoverage }] });
    const result = await new MapService(new Neo4jMapStore(backend.driver), {
      clock: () => Date.parse(source.currentGeneratedAt),
    }).query(scope, 'get_inventory_health', {});
    for (const component of ['tasks', 'tools'])
      assert.deepEqual(
        { ...result.data.sources[0].coverage[component] },
        { status: 'complete', stale: true, ageSeconds: null },
      );
  }
});

test('malformed or oversized original coverage never supplies fresh component evidence', async () => {
  for (const currentCoverage of [
    '{',
    '[]',
    '{}',
    'x'.repeat(4097),
    captures('2026-02-30T00:00:00Z'),
    captures('2026-10-30T00:00:00Z\n'),
    JSON.stringify({
      tasks: { status: 'partial', observedAt: source.currentGeneratedAt },
      tools: { status: 'complete', observedAt: source.currentGeneratedAt },
    }),
  ]) {
    await assert.rejects(new Neo4jMapStore(fake({ sources: [{ ...source, currentCoverage }] }).driver).read(scope), {
      code: 'MAP_UNAVAILABLE',
    });
  }
});

test('an unknown observed MCP timestamp cannot be hidden behind a fresh sibling or capture', async () => {
  const now = Date.parse(source.currentGeneratedAt);
  const connection = {
    ...agent,
    id: 'connection',
    entity_id: 'connection-entity',
    capture_status: 'observed',
    capture_observed_at: source.currentGeneratedAt,
    observed_at: source.currentGeneratedAt,
  };
  for (const observed_at of [undefined, null, 'malformed', '2026-02-30T00:00:00Z', '2026-11-01T00:00:00Z']) {
    const unknown = { ...connection, id: 'unknown-connection', entity_id: 'unknown-entity', observed_at };
    if (observed_at === undefined) delete unknown.observed_at;
    const backend = fake({
      sources: [{ ...source, profile: 'host-mcp' }],
      nodes: [
        { label: 'GuardMcpConnection', node: connection },
        { label: 'GuardMcpConnection', node: unknown },
      ],
    });
    const result = await new MapService(new Neo4jMapStore(backend.driver, { clock: () => now }), {
      clock: () => now,
    }).query(scope, 'get_inventory_health', {});
    assert.deepEqual({ ...result.data.sources[0].coverage.mcp }, { status: 'complete', stale: true, ageSeconds: null });
  }
  const unavailable = fake({
    sources: [{ ...source, profile: 'host-mcp' }],
    nodes: [{ label: 'GuardMcpConnection', node: { ...connection, capture_status: 'unavailable', observed_at: null } }],
  });
  const result = await new Neo4jMapStore(unavailable.driver, { clock: () => now }).read(scope);
  assert.deepEqual(
    { ...result.sources[0].current.coverage.mcp },
    { status: 'unavailable', observedAt: '2026-10-30T00:00:00.000Z' },
  );
});

test('previous and current projections retain their own original capture timestamps', async () => {
  const old = '2026-10-01T00:00:00Z';
  const backend = fake({
    run: async (query, params) => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [{ ...source, previousId: 'previous' }];
      if (query.startsWith('MATCH (p:GuardSnapshot') && !query.includes(' AS node')) {
        return [
          { id: 'previous', snapshotId: 'old-receipt', generatedAt: '2026-10-29T00:00:00Z', coverage: captures(old) },
        ];
      }
      return [];
    },
  });
  const result = await new Neo4jMapStore(backend.driver).read(scope, { history: true });
  assert.equal(result.sources[0].current.coverage.tasks.observedAt, source.currentGeneratedAt);
  assert.equal(result.sources[0].previous.coverage.tasks.observedAt, old);
  assert.equal(result.sources[0].previous.coverage.tools.observedAt, old);
  assert.ok(backend.calls.some(call => /substring\(p\.coverage_json,0,4097\) AS coverage/.test(call.query)));
});

for (const allTeams of [false, true])
  for (const agentSelected of [false, true]) {
    test(`fixed query modes preserve team/history fences (allTeams=${allTeams}, selected=${agentSelected})`, async () => {
      const backend = fake({
        run: async (query, params) => {
          if (query.startsWith('MATCH (s:GuardSource)')) return [{ ...source, previousId: 'previous' }];
          if (query.startsWith('MATCH (p:GuardSnapshot') && !query.includes(' AS node')) {
            return [
              {
                id: 'previous',
                snapshotId: 'old',
                generatedAt: source.currentGeneratedAt,
                coverage: source.currentCoverage,
              },
            ];
          }
          if (query.includes("RETURN 'GuardAgent' AS label"))
            return [
              {
                label: 'GuardAgent',
                node: { ...agent, id: `${params.projectionId}-agent`, projection_id: params.projectionId },
              },
            ];
          return [];
        },
      });
      await new Neo4jMapStore(backend.driver).read(
        { ...scope, allTeams },
        {
          sourceId: 'source',
          history: true,
          ...(agentSelected ? { agentId: 'agent' } : {}),
        },
      );
      const sources = backend.calls.filter(call => call.query.startsWith('MATCH (s:GuardSource)'));
      assert.equal(sources.length, 2);
      assert.equal(sources[0].query, sources[1].query, 'publication recheck uses the same authorized source template');
      for (const { query } of sources) {
        assert.match(query, /s\.company_id=\$companyId AND s\.tenant_id IN \$tenantIds AND s\.id=\$sourceId/);
        assert.equal(query.includes('a.team_id IN $teamIds'), !allTeams);
        assert.equal(query.includes('a.agent_id IN $agentIds OR a.entity_id IN $agentIds'), agentSelected);
        assert.equal(query.includes('EXISTS'), !allTeams || agentSelected);
        assert.equal(query.includes('$allTeams'), false);
      }
      for (const label of ['GuardAgent', 'GuardTask'])
        for (const projectionId of ['projection', 'previous']) {
          const call = backend.calls.find(
            item => item.query.includes(`RETURN '${label}' AS label`) && item.params.projectionId === projectionId,
          );
          assert.ok(call);
          assert.match(
            call.query,
            /n\.source_id=\$sourceId AND n\.projection_id=\$projectionId AND n\.tenant_id=\$tenantId/,
          );
          assert.match(call.query, /size\(\[label IN labels\(n\) WHERE label IN \$labels\]\)=1/);
          const fenced = projectionId === 'previous' && !allTeams;
          assert.equal(call.query.includes('NOT EXISTS'), fenced);
          assert.equal(call.query.includes('$allTeams'), false);
          if (fenced) {
            assert.match(call.query, /current\.source_id=\$sourceId/);
            assert.match(call.query, /current\.projection_id=\$currentId AND current\.tenant_id=\$tenantId/);
          }
          if (label === 'GuardAgent') {
            assert.equal(call.query.includes('n.team_id IN $teamIds'), !allTeams);
            assert.equal(call.query.includes('n.agent_id IN $agentIds OR n.entity_id IN $agentIds'), agentSelected);
          } else assert.equal(call.query.includes('G_ASSIGNED_TO'), !allTeams || agentSelected);
        }
    });
  }

test('unselected source template retains company and tenant bounds without nullable identity branches', async () => {
  const backend = fake();
  await new Neo4jMapStore(backend.driver).read(scope);
  const sources = backend.calls.filter(call => call.query.startsWith('MATCH (s:GuardSource)'));
  assert.equal(sources.length, 2);
  for (const { query, params } of sources) {
    assert.match(query, /s\.company_id=\$companyId AND s\.tenant_id IN \$tenantIds/);
    assert.equal(query.includes('s.id=$sourceId'), false);
    assert.equal(query.includes('$agentId'), false);
    assert.equal(params.companyId, scope.companyId);
    assert.deepEqual(params.tenantIds, scope.tenantIds);
  }
});

test('original coverage changes during a read reject the complete view', async () => {
  let reads = 0;
  const backend = fake({
    run: async query =>
      query.startsWith('MATCH (s:GuardSource)')
        ? [{ ...source, currentCoverage: ++reads > 1 ? captures('2026-10-01T00:00:00Z') : source.currentCoverage }]
        : [],
  });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_UNAVAILABLE' });
});

test('unexpected scoped graph endpoints and tenants never become partial evidence', async () => {
  for (const options of [
    { sources: [{ ...source, tenantId: 'foreign' }] },
    { nodes: [{ label: 'GuardAgent', node: { ...agent, source_id: 'foreign' } }] },
    { nodes: [{ label: 'AWSRole', node: agent }] },
    { edges: [{ source: agent.id, target: 'hidden-canary', kind: 'G_INSTANCE_OF' }] },
  ])
    await assert.rejects(new Neo4jMapStore(fake(options).driver).read(scope), { code: 'MAP_UNAVAILABLE' });
});

test('absolute timeout returns a stable error and requests rollback', async () => {
  let completed = false;
  const backend = fake({
    run: async () => {
      await new Promise(resolve => setTimeout(resolve, 60));
      completed = true;
      return [];
    },
  });
  await assert.rejects(new Neo4jMapStore(backend.driver, { timeoutMs: 5 }).read(scope), { code: 'MAP_TIMEOUT' });
  assert.equal(completed, false);
  assert.ok(backend.status().rolledBack >= 1);
  await new Promise(resolve => setTimeout(resolve, 70));
  assert.equal(backend.status().closed, 1);
});

test('unknown query arguments and invalid source credentials fail before driver access', async () => {
  const store = new Neo4jMapStore(fake().driver);
  for (const query of [{ cypher: 'MATCH (n) RETURN n' }, { history: 'all' }, { summary: 'all' }, { sourceId: '' }]) {
    await assert.rejects(store.read(scope, query), { code: 'MAP_REQUEST_INVALID' });
  }
  for (const uri of [
    'bolt://db.example.com',
    'neo4j://127.0.0.1',
    'bolt+ssc://127.0.0.1',
    'https://example.com',
    'bolt://u:p@127.0.0.1',
    'bolt://127.0.0.1/?query=secret',
  ]) {
    assert.throws(() => createNeo4jMapStore({ uri, username: 'u', password: 'private-canary' }), {
      code: 'MAP_CONFIG_INVALID',
    });
  }
});

test('v2 owners and credentials use authorized attachment paths and exclude raw relationship metadata', async () => {
  const opaque = `opaque:${'a'.repeat(64)}`;
  const rows = [
    { label: 'GuardAgent', node: agent },
    {
      label: 'GuardOwner',
      node: { ...agent, id: 'owner', entity_id: 'owner-entity', owner_id: 'owner', name: 'Owner', kind: 'team' },
    },
    {
      label: 'GuardCredentialReference',
      node: {
        ...agent,
        id: 'credential',
        entity_id: 'credential-entity',
        credential_id: opaque,
        issuer_ref: null,
        audience_refs: [opaque],
        recipient_refs: [],
        lifecycle_state: 'active',
        rotation_status: 'current',
        token: 'private-token-canary',
      },
    },
    {
      label: 'GuardDeployment',
      node: {
        ...agent,
        id: 'deployment',
        entity_id: 'deployment-entity',
        runtime_ref: opaque,
        build_ref: null,
        credential_refs: ['hidden-credential-canary'],
      },
    },
    {
      label: 'GuardResourceBinding',
      node: {
        ...agent,
        id: 'binding',
        entity_id: 'binding-entity',
        approved_destinations: [opaque],
        depends_on: ['hidden-binding-canary'],
      },
    },
    {
      label: 'GuardExternalResource',
      node: {
        ...agent,
        id: 'external',
        entity_id: 'external-entity',
        provider: 'host',
        kind: 'database',
        host_resource_id: opaque,
        arn: 'private-aws-canary',
        cloud_provider_id: 'private-cloud-canary',
        cloud_status: 'not_collected',
        cloud_reason: 'unsupported_provider',
      },
    },
  ];
  const backend = fake({ nodes: rows });
  const result = await new Neo4jMapStore(backend.driver).read(scope);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private-token-canary|hidden-credential-canary|hidden-binding-canary|private-aws-canary|private-cloud-canary/,
  );
  const owner = backend.calls.find(c => c.query.includes("RETURN 'GuardOwner' AS label"));
  assert.match(owner.query, /G_OWNED_BY/);
  assert.match(owner.query, /G_RESOURCE_OWNED_BY/);
  const credential = backend.calls.find(c => c.query.includes("RETURN 'GuardCredentialReference' AS label"));
  assert.match(credential.query, /G_USES_CREDENTIAL/);
  assert.match(credential.query, /visible.id IN \$GuardDeploymentIds/);
  assert.deepEqual(credential.params.GuardDeploymentIds, ['deployment']);
  assert.match(backend.calls.find(c => c.query.includes("RETURN 'GuardDeployment' AS label")).query, /G_INSTANCE_OF/);
  assert.deepEqual(owner.params.teamIds, ['team']);
  assert.deepEqual(credential.params.teamIds, ['team']);
  for (const call of backend.calls.filter(c => c.query.includes(' AS node')))
    assert.doesNotMatch(call.query, /G_DEPENDS_ON/);
});

test('opaque references reject terminal newlines, duplicates and malformed credential metadata', async () => {
  const opaque = `opaque:${'a'.repeat(64)}`;
  const credential = {
    ...agent,
    id: 'credential',
    entity_id: 'credential-entity',
    credential_id: opaque,
    issuer_ref: null,
    audience_refs: [],
    recipient_refs: [],
    lifecycle_state: 'active',
    rotation_status: 'current',
  };
  for (const [label, properties] of [
    ['GuardCredentialReference', { ...credential, credential_id: `${opaque}\n` }],
    ['GuardCredentialReference', { ...credential, issuer_ref: `${opaque}\n` }],
    ['GuardCredentialReference', { ...credential, audience_refs: [`${opaque}\n`] }],
    ['GuardCredentialReference', { ...credential, recipient_refs: [opaque, opaque] }],
    ['GuardDeployment', { ...agent, runtime_ref: `${opaque}\n` }],
    ['GuardExternalResource', { ...agent, provider: 'host', kind: 'database', host_resource_id: `${opaque}\n` }],
    ['GuardResourceBinding', { ...agent, approved_destinations: [`${opaque}\n`] }],
  ])
    await assert.rejects(new Neo4jMapStore(fake({ nodes: [{ label, node: properties }] }).driver).read(scope), {
      code: 'MAP_UNAVAILABLE',
    });
});

test('duplicate stable entity identities fail before scoped relationships can be conflated', async () => {
  const backend = fake({
    nodes: [
      { label: 'GuardAgent', node: agent },
      { label: 'GuardAgent', node: { ...agent, id: 'other-node' } },
    ],
  });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_UNAVAILABLE' });
});

test('declared direct access attaches only through an authorized deployment and is validated', async () => {
  const opaque = `opaque:${'a'.repeat(64)}`;
  const entry = {
    ...agent,
    id: 'direct',
    entity_id: 'direct-entity',
    access_id: opaque,
    deployment_id: 'deployment',
    kind: 'shell',
    target_ref: null,
    description: 'Ops shell',
    command: 'private-command-canary',
  };
  const backend = fake({
    nodes: [
      { label: 'GuardAgent', node: agent },
      {
        label: 'GuardDeployment',
        node: { ...agent, id: 'deployment', entity_id: 'deployment-entity', direct_access_status: 'found' },
      },
      { label: 'GuardDirectAccess', node: entry },
    ],
  });
  const result = await new Neo4jMapStore(backend.driver).read(scope);
  assert.doesNotMatch(JSON.stringify(result), /private-command-canary/);
  const direct = backend.calls.find(c => c.query.includes("RETURN 'GuardDirectAccess' AS label"));
  assert.match(direct.query, /G_DIRECT_ACCESS_FOR/);
  assert.deepEqual(direct.params.GuardDeploymentIds, ['deployment']);
  for (const [label, properties] of [
    ['GuardDirectAccess', { ...entry, access_id: 'raw-name' }],
    ['GuardDirectAccess', { ...entry, target_ref: 'db.internal' }],
    ['GuardDirectAccess', { ...entry, kind: 'ssh' }],
    ['GuardDirectAccess', { ...entry, description: 'x'.repeat(1025) }],
    ['GuardDeployment', { ...agent, direct_access_status: 'safe' }],
  ])
    await assert.rejects(new Neo4jMapStore(fake({ nodes: [{ label, node: properties }] }).driver).read(scope), {
      code: 'MAP_UNAVAILABLE',
    });
});

test('a one-agent read finds delegation ancestors from its own tasks, after its own nodes', async () => {
  const backend = fake();
  await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: true });
  const ancestors = backend.calls.find(call => call.query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16'));
  assert.ok(ancestors, 'the ancestor query runs');
  assert.match(ancestors.query, /^MATCH path=\(visible:GuardDeployment\)<-\[:G_ASSIGNED_TO\]-\(child:GuardTask\)/);
  assert.match(ancestors.query, /ALL\(t IN nodes\(path\)\[2\.\.\] WHERE /, 'every ancestor on the path is checked');
  assert.match(ancestors.query, /size\(\[label IN labels\(t\) WHERE label IN \$labels\]\)=1/);
  assert.match(ancestors.query, /size\(\[label IN labels\(d\) WHERE label IN \$labels\]\)=1/);
  assert.match(ancestors.query, /ag\.team_id IN \$teamIds/);
  const order = backend.calls.map(call => call.query);
  assert.ok(
    order.findIndex(query => query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16')) >
      order.findIndex(query => query.includes("RETURN 'GuardMcpOperation' AS label")),
    'ancestors are read after every label of the agent',
  );
  const tasks = backend.calls.find(call => call.query.includes("RETURN 'GuardTask' AS label"));
  assert.doesNotMatch(tasks.query, /G_DELEGATED_FROM\*|ancestorTaskIds/, 'no per-task descendant expansion');
  const plain = fake();
  await new Neo4jMapStore(plain.driver).read(scope);
  assert.equal(
    plain.calls.some(call => call.query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16')),
    false,
    'team-wide reads see ancestors directly',
  );
});

test('ancestors that do not fit the remaining node budget are left out, not fatal', async () => {
  const node = (label, key, extra = {}) => ({
    label,
    node: { ...agent, id: key, entity_id: `${key}-entity`, ...extra },
  });
  const own = [
    node('GuardAgent', 'agent'),
    node('GuardDeployment', 'deployment', { deployment_id: 'deployment' }),
    ...[1, 2, 3, 4].map(index => node('GuardTask', `task-${index}`, { task_id: `task-${index}`, delegated: true })),
  ];
  const backend = fake({
    run: async query => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [source];
      const label = /RETURN '(\w+)' AS label/.exec(query)?.[1];
      if (label && query.includes(' AS node') && !query.includes('$ancestorTaskIds'))
        return own.filter(item => item.label === label);
      if (query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16'))
        return Array.from({ length: 8 }, (_, index) => ({ id: `ancestor-${index}` }));
      return [];
    },
  });
  const view = await new Neo4jMapStore(backend.driver, { maxNodes: 10 }).read(scope, {
    agentId: 'agent',
    boundary: true,
  });
  const current = view.sources[0].current;
  assert.equal(current.ancestorsNotLoaded, true);
  assert.equal(current.nodes.filter(item => item.label === 'GuardTask').length, 4, 'own tasks kept');
  assert.equal(
    backend.calls.some(call => call.query.includes('$ancestorTaskIds')),
    false,
  );
});

test('read modes cannot be combined', async () => {
  const store = new Neo4jMapStore(fake().driver);
  for (const request of [
    { summary: true, flags: true },
    { history: true, flags: true },
    { flags: true, outsideGuard: true },
    { outsideGuard: true, agentId: 'agent' },
    { agentIds: ['agent'] },
    { flags: true, agentIds: [] },
  ])
    await assert.rejects(store.read(scope, request), { code: 'MAP_REQUEST_INVALID' }, JSON.stringify(request));
});

test('a boundary read asks only for sensitive in-scope bindings of *-granted tools, not every binding', async () => {
  const grant = {
    ...agent,
    id: 'grant',
    entity_id: 'grant-entity',
    task_id: 'task',
    tool: 's3.read',
    resources: ['*'],
  };
  const backend = fake({
    run: async query => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [source];
      if (query.includes("RETURN 'GuardGrant' AS label")) return [{ label: 'GuardGrant', node: grant }];
      if (query.includes("RETURN 'GuardAgent' AS label")) return [{ label: 'GuardAgent', node: agent }];
      if (query.includes('$wildcardTools'))
        return [{ tool: 's3.read', bindings: [{ id: 'binding-entity', sensitivity: 'restricted' }] }];
      return [];
    },
  });
  const view = await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: true });
  const wildcard = backend.calls.find(call => call.query.includes('$wildcardTools'));
  assert.deepEqual(wildcard.params.wildcardTools, ['s3.read']);
  assert.match(wildcard.query, /a\.team_id IN \$teamIds/, 'only bindings in the team scope');
  assert.match(wildcard.query, /LIMIT 5/);
  assert.deepEqual(JSON.parse(JSON.stringify(view.sources[0].current.wildcardSensitivity)), {
    's3.read': [{ id: 'binding-entity', sensitivity: 'restricted' }],
  });
  const bindings = backend.calls.find(call => call.query.includes("RETURN 'GuardResourceBinding' AS label"));
  assert.doesNotMatch(bindings.query, /resource_id:'\*'/, 'no node read of every binding of the tool');
  const inventory = fake();
  await new Neo4jMapStore(inventory.driver).read(scope, { agentId: 'agent' });
  assert.equal(
    inventory.calls.some(call => call.query.includes('$wildcardTools')),
    false,
  );
});

/** A store over one or two sources, each with an agent, a deployment, delegated tasks and ancestors. */
function ancestorBackend({ sources = ['source'], ancestors = 1, ownEdges = [] } = {}) {
  const node = (sourceId, label, key, extra = {}) => ({
    label,
    node: {
      ...agent,
      id: `${sourceId}:${key}`,
      entity_id: `${sourceId}:${key}-entity`,
      source_id: sourceId,
      ...extra,
    },
  });
  const own = sourceId => [
    node(sourceId, 'GuardAgent', 'agent'),
    node(sourceId, 'GuardDeployment', 'deployment', { deployment_id: 'deployment' }),
    node(sourceId, 'GuardTask', 'task', { task_id: 'task', delegated: true }),
  ];
  const ancestorIds = sourceId => Array.from({ length: ancestors }, (_, index) => `${sourceId}:ancestor-${index}`);
  return fake({
    run: async (query, params) => {
      if (query.startsWith('MATCH (s:GuardSource)')) return sources.map(id => ({ ...source, id }));
      if (query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16'))
        return ancestorIds(params.sourceId).map(id => ({ id }));
      if (query.includes('$ancestorTaskIds'))
        return params.ancestorTaskIds.map(id => node(params.sourceId, 'GuardTask', id.split(':')[1], { task_id: id }));
      const label = /RETURN '(\w+)' AS label/.exec(query)?.[1];
      if (label && query.includes(' AS node')) return own(params.sourceId).filter(item => item.label === label);
      if (query.includes('$relationships') && params.relationships.length === 2)
        return ancestorIds(params.sourceId)
          .slice(0, 1)
          .map(target => ({ source: `${params.sourceId}:task`, target, kind: 'G_DELEGATED_FROM' }));
      if (query.includes('$relationships'))
        return ownEdges.map(edge => ({
          ...edge,
          source: `${params.sourceId}:${edge.source}`,
          target: `${params.sourceId}:${edge.target}`,
        }));
      return [];
    },
  });
}

test('ancestors that fit are added with their delegation edges', async () => {
  const backend = ancestorBackend();
  const view = await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: true });
  const current = view.sources[0].current;
  assert.equal(current.ancestorsNotLoaded, undefined);
  assert.ok(current.nodes.some(item => item.id === 'source:ancestor-0'));
  assert.deepEqual(
    current.edges.filter(edge => edge.kind === 'G_DELEGATED_FROM').map(edge => [edge.source, edge.target]),
    [['source:task', 'source:ancestor-0']],
  );
});

test('ancestors without room for their edges are left out and the read still answers', async () => {
  const backend = ancestorBackend({ ownEdges: [{ source: 'deployment', target: 'agent', kind: 'G_INSTANCE_OF' }] });
  const view = await new Neo4jMapStore(backend.driver, { maxEdges: 1 }).read(scope, {
    agentId: 'agent',
    boundary: true,
  });
  const current = view.sources[0].current;
  assert.equal(current.ancestorsNotLoaded, true);
  assert.equal(
    current.nodes.some(item => item.id.includes('ancestor')),
    false,
  );
});

test("one source's ancestors never crowd out another source's own nodes", async () => {
  // Six own nodes in all; source one's four ancestors would fit alone but not beside source two.
  const backend = ancestorBackend({ sources: ['one', 'two'], ancestors: 4 });
  const view = await new Neo4jMapStore(backend.driver, { maxNodes: 9 }).read(scope, {
    flags: true,
    agentIds: ['agent'],
  });
  assert.deepEqual(
    view.sources.map(item => [item.id, item.current.nodes.length, item.current.ancestorsNotLoaded ?? false]),
    [
      ['one', 3, true],
      ['two', 3, true],
    ],
  );
});

test('duplicate ancestor ids are read once, and a second record for one id fails the read', async () => {
  let requested;
  const duplicateIds = fake({
    run: async (query, params) => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [source];
      if (query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16')) return [{ id: 'source:a' }, { id: 'source:a' }];
      if (query.includes('$ancestorTaskIds')) {
        requested = params.ancestorTaskIds;
        const record = { ...agent, id: 'source:a', entity_id: 'a-1', task_id: 'a' };
        return [
          { label: 'GuardTask', node: record },
          { label: 'GuardTask', node: { ...record, entity_id: 'a-2' } },
        ];
      }
      const label = /RETURN '(\w+)' AS label/.exec(query)?.[1];
      if (label === 'GuardAgent' && query.includes(' AS node')) return [{ label, node: agent }];
      if (label === 'GuardDeployment' && query.includes(' AS node'))
        return [{ label, node: { ...agent, id: 'deployment', entity_id: 'deployment-entity' } }];
      return [];
    },
  });
  await assert.rejects(new Neo4jMapStore(duplicateIds.driver).read(scope, { agentId: 'agent', boundary: true }), {
    code: 'MAP_UNAVAILABLE',
  });
  // Checked outside the fake, where the store cannot turn a failed assertion into the rejection.
  assert.deepEqual(requested, ['source:a'], 'ancestor ids are deduplicated');
});

test('the wildcard query checks every node on its path', async () => {
  const grant = {
    ...agent,
    id: 'grant',
    entity_id: 'grant-entity',
    task_id: 'task',
    tool: 's3.read',
    resources: ['*'],
  };
  const backend = fake({
    run: async query => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [source];
      if (query.includes("RETURN 'GuardGrant' AS label")) return [{ label: 'GuardGrant', node: grant }];
      if (query.includes("RETURN 'GuardAgent' AS label")) return [{ label: 'GuardAgent', node: agent }];
      return [];
    },
  });
  await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: true });
  const wildcard = backend.calls.find(call => call.query.includes('$wildcardTools')).query;
  for (const variable of ['rb', 'r', 'g', 't', 'd', 'a'])
    assert.ok(wildcard.includes(`size([label IN labels(${variable}) WHERE label IN $labels])=1`), variable);
});

test('identity scope that needs more work than allowed is left out; the read still answers', async () => {
  // One static AWS identity and 1,900 tasks in one delegation chain: within the node and edge
  // limits, but the per-task liveness walks exceed the identity plan's work budget.
  const node = (label, key, extra = {}) => ({
    label,
    node: { ...agent, id: key, entity_id: `${key}-entity`, ...extra },
  });
  const tasks = Array.from({ length: 1900 }, (_, index) =>
    node('GuardTask', `task-${index}`, {
      task_id: `task-${index}`,
      revoked: false,
      deadline: 4_102_444_800_000,
      delegated: index > 0,
      derived: false,
    }),
  );
  const nodes = [
    node('GuardAgent', 'agent-node'),
    node('GuardDeployment', 'deployment', { deployment_id: 'deployment' }),
    node('GuardExecutionBinding', 'execution', { binding_id: 'execution', tool: 't', identity_selection: 'static' }),
    node('GuardTool', 'tool', { name: 't', registered: true }),
    node('GuardExternalIdentity', 'identity', {
      provider: 'aws',
      partition: 'aws',
      account_id: '111122223333',
      region: '',
      arn: 'arn:aws:iam::111122223333:role/Worker',
      cloud_status: 'resolved',
    }),
    ...tasks,
  ];
  const edges = [
    { source: 'deployment', target: 'agent-node', kind: 'G_INSTANCE_OF' },
    { source: 'execution', target: 'deployment', kind: 'G_EXECUTES_FOR' },
    { source: 'execution', target: 'tool', kind: 'G_EXECUTES_TOOL' },
    { source: 'execution', target: 'identity', kind: 'G_USES_IDENTITY' },
    ...tasks.flatMap((task, index) => [
      { source: task.node.id, target: 'deployment', kind: 'G_ASSIGNED_TO' },
      ...(index ? [{ source: task.node.id, target: `task-${index - 1}`, kind: 'G_DELEGATED_FROM' }] : []),
    ]),
  ];
  const backend = fake({
    run: async query => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [source];
      const label = /RETURN '(\w+)' AS label/.exec(query)?.[1];
      if (label && query.includes(' AS node') && !query.includes('$ancestorTaskIds'))
        return nodes.filter(item => item.label === label);
      if (query.includes('$relationships') && query.includes('AS kind')) return edges;
      return [];
    },
  });
  const view = await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: true });
  const current = view.sources[0].current;
  assert.equal(current.nodes.filter(item => item.label === 'GuardTask').length, 1900);
  assert.equal(current.identityScope, undefined, 'identity scope was not evaluated');
  assert.equal(
    backend.calls.some(call => call.query.includes('$scopePairs')),
    false,
    'no identity query ran',
  );
});

test('a * grant on a tool named __proto__ is answered like any other tool', async () => {
  const grant = {
    ...agent,
    id: 'grant',
    entity_id: 'grant-entity',
    task_id: 'task',
    tool: '__proto__',
    resources: ['*'],
  };
  const backend = fake({
    run: async query => {
      if (query.startsWith('MATCH (s:GuardSource)')) return [source];
      if (query.includes("RETURN 'GuardGrant' AS label")) return [{ label: 'GuardGrant', node: grant }];
      if (query.includes("RETURN 'GuardAgent' AS label")) return [{ label: 'GuardAgent', node: agent }];
      if (query.includes('$wildcardTools'))
        return [{ tool: '__proto__', bindings: [{ id: 'binding-entity', sensitivity: 'restricted' }] }];
      return [];
    },
  });
  const view = await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: true });
  const answers = view.sources[0].current.wildcardSensitivity;
  assert.ok(Object.hasOwn(answers, '__proto__'));
  assert.equal(answers.__proto__[0].sensitivity, 'restricted');
});

test('boundary is a read mode like the others, and false means not set', async () => {
  const store = new Neo4jMapStore(fake().driver);
  for (const request of [
    { agentId: 'agent', boundary: true, summary: true },
    { agentId: 'agent', boundary: true, history: true },
    { boundary: true },
    { agentId: 'agent', boundary: 'yes' },
  ])
    await assert.rejects(store.read(scope, request), { code: 'MAP_REQUEST_INVALID' }, JSON.stringify(request));
  const backend = fake();
  await new Neo4jMapStore(backend.driver).read(scope, { agentId: 'agent', boundary: false });
  assert.equal(
    backend.calls.some(call => call.query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16')),
    false,
    'boundary: false reads like an inventory read',
  );
});

/** One agent with one static, resolved AWS execution identity and no grants: a scope-only read. */
function scopeOnlyBackend({ coverage, scopeRows = [] } = {}) {
  const node = (label, key, extra = {}) => ({
    label,
    node: { ...agent, id: key, entity_id: `${key}-entity`, ...extra },
  });
  const nodes = [
    node('GuardAgent', 'agent-node'),
    node('GuardDeployment', 'deployment', { deployment_id: 'deployment' }),
    node('GuardExecutionBinding', 'execution', { binding_id: 'execution', tool: 't', identity_selection: 'static' }),
    node('GuardTool', 'tool', { name: 't', registered: true }),
    node('GuardExternalIdentity', 'identity', {
      provider: 'aws',
      partition: 'aws',
      account_id: '111122223333',
      region: '',
      arn: 'arn:aws:iam::111122223333:role/Worker',
      cloud_status: 'resolved',
    }),
  ];
  const edges = [
    { source: 'deployment', target: 'agent-node', kind: 'G_INSTANCE_OF' },
    { source: 'execution', target: 'deployment', kind: 'G_EXECUTES_FOR' },
    { source: 'execution', target: 'tool', kind: 'G_EXECUTES_TOOL' },
    { source: 'execution', target: 'identity', kind: 'G_USES_IDENTITY' },
  ];
  return fake({
    run: async query => {
      if (query.startsWith('MATCH (s:GuardSource)'))
        return [{ ...source, ...(coverage === undefined ? {} : { policyCoverage: coverage }) }];
      if (query.includes('$scopePairs')) return scopeRows;
      const label = /RETURN '(\w+)' AS label/.exec(query)?.[1];
      if (label && query.includes(' AS node') && !query.includes('$ancestorTaskIds'))
        return nodes.filter(item => item.label === label);
      if (query.includes('$relationships') && query.includes('AS kind')) return edges;
      return [];
    },
  });
}

test('a scope-only read with an unreadable age bound or a row fan-out answers without identity scope', async () => {
  const healthy = scopeOnlyBackend();
  const view = await new Neo4jMapStore(healthy.driver).read(scope, { agentId: 'agent', boundary: true });
  assert.equal(view.sources[0].current.identityScope.length, 1, 'the identity is evaluated when it can be');
  assert.ok(healthy.calls.some(call => call.query.includes('$scopePairs')));

  const unreadable = scopeOnlyBackend({ coverage: '{not json' });
  const skipped = await new Neo4jMapStore(unreadable.driver).read(scope, { agentId: 'agent', boundary: true });
  assert.equal(skipped.sources[0].current.identityScope, undefined);
  assert.equal(skipped.sources[0].current.nodes.length, 5, 'the rest of the read stands');

  const fanOut = scopeOnlyBackend({ scopeRows: Array.from({ length: 9 }, () => ({ key: 0 })) });
  const degraded = await new Neo4jMapStore(fanOut.driver).read(scope, { agentId: 'agent', boundary: true });
  assert.equal(degraded.sources[0].current.identityScope, undefined);
});
