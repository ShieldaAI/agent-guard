import test from 'node:test';
import assert from 'node:assert/strict';
import { Neo4jMapStore, createNeo4jMapStore } from '../dist/store.js';
import { MapService } from '../dist/service.js';
import { validateReadScope } from '../dist/types.js';

const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false };
const captures = (tasks, tools = tasks) => JSON.stringify({
  tasks: { status: 'complete', observedAt: tasks }, tools: { status: 'complete', observedAt: tools },
});
const source = { id: 'source', tenantId: 'tenant', nativeSourceId: 'installation', profile: 'host',
  currentId: 'projection', currentSnapshotId: 'receipt', currentGeneratedAt: '2026-10-30T00:00:00Z',
  currentCoverage: captures('2026-10-30T00:00:00Z'), previousId: null };
const agent = { id: 'agent-node', entity_id: 'agent-entity', source_id: 'source', projection_id: 'projection',
  agent_id: 'agent', name: 'Visible agent', team_id: 'team', owner_id: null, metadata: 'private-canary' };
const records = values => values.map(value => ({ get: name => value[name] }));
function fake(options = {}) {
  const calls = []; let sourceReads = 0, rolledBack = 0, closed = 0;
  const tx = { isOpen: () => true, rollback: async () => { rolledBack++; }, run: async function* (query, params) {
    calls.push({ query, params });
    if (options.run) { yield* records(await options.run(query, params, calls.length)); return; }
    if (query.startsWith('MATCH (s:GuardSource)')) {
      sourceReads++;
      if (options.supersedeSource && sourceReads > 1) return;
      yield* records(options.sources ?? [{ ...source, ...(options.changePointer && sourceReads > 1 ? { currentId: 'newer' } : {}) }]); return;
    }
    if (query.includes(' AS node')) {
      const label = query.match(/RETURN '(\w+)' AS label/)[1];
      yield* records((options.nodes ?? [{ label: 'GuardAgent', node: agent }]).filter(item => item.label === label || item.label === 'AWSRole'));
      return;
    }
    yield* records(options.edges ?? []);
  } };
  return { calls, status: () => ({ rolledBack, closed }), driver: {
    session(config) { assert.equal(config.defaultAccessMode, 'READ'); return {
      beginTransaction(config) { assert.ok(config.timeout <= 5000); return tx; },
      close: async () => { closed++; },
    }; }, close: async () => {},
  } };
}

test('read scope is a detached closed allowlist and never invokes accessors', () => {
  const input = structuredClone(scope), result = validateReadScope(input);
  input.tenantIds.push('foreign');
  assert.deepEqual(result.tenantIds, ['tenant']);
  assert.equal(Object.isFrozen(result), true);
  let called = false;
  assert.throws(() => validateReadScope({ ...scope, get subject() { called = true; return 'x'; } }), { code: 'MAP_SCOPE_INVALID' });
  assert.equal(called, false);
  for (const value of [{ ...scope, roles: ['admin'] }, { ...scope, tenantIds: [] }, { ...scope, teamIds: [] }, { ...scope, tenantIds: ['tenant', 'tenant'] }]) {
    assert.throws(() => validateReadScope(value), { code: 'MAP_SCOPE_INVALID' });
  }
});

test('store binds trusted scope into fixed read templates and strips arbitrary graph properties', async () => {
  const backend = fake(); const store = new Neo4jMapStore(backend.driver);
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

test('agent summaries read only the authorized agent and deployment index', async () => {
  const backend = fake();
  const result = await new Neo4jMapStore(backend.driver, { maxNodes: 1 }).read(scope, { summary: true });
  assert.equal(result.sources[0].current.nodes.length, 1);
  assert.equal(result.sources[0].current.coverage.tasks.status, 'not_collected');
  assert.equal(backend.calls.filter(call => call.query.includes(' AS node')).length, 2);
  assert.equal(backend.calls.some(call => call.query.includes("RETURN 'GuardTask' AS label")), false);
});

test('source, node and edge limits reject complete views without truncation', async () => {
  for (const [options, limits] of [
    [{ sources: [source, source] }, { maxSources: 1 }],
    [{ nodes: [{ label: 'GuardAgent', node: agent }, { label: 'GuardAgent', node: { ...agent, id: 'other' } }] }, { maxNodes: 1 }],
    [{ edges: [{ source: agent.id, target: agent.id, kind: 'G_INSTANCE_OF' }, { source: agent.id, target: agent.id, kind: 'G_INSTANCE_OF' }] }, { maxEdges: 1 }],
  ]) await assert.rejects(new Neo4jMapStore(fake(options).driver, limits).read(scope), { code: 'MAP_LIMIT_EXCEEDED' });
});

test('cumulative byte bounds stop streamed materialization before later graph queries', async () => {
  const backend = fake({ nodes: Array.from({ length: 12 }, (_, i) => ({ label: 'GuardAgent',
    node: { ...agent, id: `node-${i}`, name: 'x'.repeat(480_000) } })) });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_LIMIT_EXCEEDED' });
  assert.equal(backend.calls.length, 2);
  assert.deepEqual(backend.status(), { rolledBack: 1, closed: 1 });
});

test('component capture timestamps remain independent of the core publication timestamp', async () => {
  const backend = fake({ sources: [{ ...source, profile: 'host-mcp' }], nodes: [
    { label: 'GuardAgent', node: { ...agent, manifest_observed_at: '2026-10-20T01:00:00Z' } },
    { label: 'GuardMcpConnection', node: { ...agent, id: 'connection', capture_status: 'observed', capture_observed_at: '2026-10-21T02:00:00Z', observed_at: '2026-10-21T02:00:00Z' } },
    { label: 'GuardExternalResource', node: { ...agent, id: 'external', cloud_status: 'resolved', cloud_observed_at: Date.parse('2026-10-22T03:00:00Z') / 1000 } },
  ] });
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
  const old = '2026-10-01T00:00:00Z', toolTime = '2026-10-02T00:00:00Z';
  const now = Date.parse(source.currentGeneratedAt);
  const backend = fake({ sources: [{ ...source, profile: 'host-mcp', currentCoverage: captures(old, toolTime) }], nodes: [
    { label: 'GuardAgent', node: agent },
    { label: 'GuardMcpConnection', node: { ...agent, id: 'connection', capture_status: 'observed',
      capture_observed_at: source.currentGeneratedAt, observed_at: old } },
  ] });
  const result = await new MapService(new Neo4jMapStore(backend.driver, { clock: () => now }),
    { clock: () => now }).query(scope, 'get_inventory_health', {});
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
    const result = await new MapService(new Neo4jMapStore(backend.driver),
      { clock: () => Date.parse(source.currentGeneratedAt) }).query(scope, 'get_inventory_health', {});
    for (const component of ['tasks', 'tools']) assert.deepEqual({ ...result.data.sources[0].coverage[component] },
      { status: 'complete', stale: true, ageSeconds: null });
  }
});

test('malformed or oversized original coverage never supplies fresh component evidence', async () => {
  for (const currentCoverage of ['{', '[]', '{}', 'x'.repeat(4097),
    captures('2026-02-30T00:00:00Z'), captures('2026-10-30T00:00:00Z\n'),
    JSON.stringify({ tasks: { status: 'partial', observedAt: source.currentGeneratedAt },
      tools: { status: 'complete', observedAt: source.currentGeneratedAt } })]) {
    await assert.rejects(new Neo4jMapStore(fake({ sources: [{ ...source, currentCoverage }] }).driver).read(scope),
      { code: 'MAP_UNAVAILABLE' });
  }
});

test('an unknown observed MCP timestamp cannot be hidden behind a fresh sibling or capture', async () => {
  const now = Date.parse(source.currentGeneratedAt);
  const connection = { ...agent, id: 'connection', capture_status: 'observed',
    capture_observed_at: source.currentGeneratedAt, observed_at: source.currentGeneratedAt };
  for (const observed_at of [undefined, null, 'malformed', '2026-02-30T00:00:00Z', '2026-11-01T00:00:00Z']) {
    const unknown = { ...connection, id: 'unknown-connection', observed_at };
    if (observed_at === undefined) delete unknown.observed_at;
    const backend = fake({ sources: [{ ...source, profile: 'host-mcp' }], nodes: [
      { label: 'GuardMcpConnection', node: connection },
      { label: 'GuardMcpConnection', node: unknown },
    ] });
    const result = await new MapService(new Neo4jMapStore(backend.driver, { clock: () => now }),
      { clock: () => now }).query(scope, 'get_inventory_health', {});
    assert.deepEqual({ ...result.data.sources[0].coverage.mcp }, { status: 'complete', stale: true, ageSeconds: null });
  }
  const unavailable = fake({ sources: [{ ...source, profile: 'host-mcp' }], nodes: [
    { label: 'GuardMcpConnection', node: { ...connection, capture_status: 'unavailable', observed_at: null } },
  ] });
  const result = await new Neo4jMapStore(unavailable.driver, { clock: () => now }).read(scope);
  assert.deepEqual({ ...result.sources[0].current.coverage.mcp },
    { status: 'unavailable', observedAt: '2026-10-30T00:00:00.000Z' });
});

test('previous and current projections retain their own original capture timestamps', async () => {
  const old = '2026-10-01T00:00:00Z';
  const backend = fake({ run: async (query, params) => {
    if (query.startsWith('MATCH (s:GuardSource)')) return [{ ...source, previousId: 'previous' }];
    if (query.startsWith('MATCH (p:GuardSnapshot') && !query.includes(' AS node')) {
      return [{ id: 'previous', snapshotId: 'old-receipt', generatedAt: '2026-10-29T00:00:00Z', coverage: captures(old) }];
    }
    return [];
  } });
  const result = await new Neo4jMapStore(backend.driver).read(scope, { history: true });
  assert.equal(result.sources[0].current.coverage.tasks.observedAt, source.currentGeneratedAt);
  assert.equal(result.sources[0].previous.coverage.tasks.observedAt, old);
  assert.equal(result.sources[0].previous.coverage.tools.observedAt, old);
  assert.ok(backend.calls.some(call => /substring\(p\.coverage_json,0,4097\) AS coverage/.test(call.query)));
});

test('original coverage changes during a read reject the complete view', async () => {
  let reads = 0;
  const backend = fake({ run: async query => query.startsWith('MATCH (s:GuardSource)')
    ? [{ ...source, currentCoverage: ++reads > 1 ? captures('2026-10-01T00:00:00Z') : source.currentCoverage }]
    : [] });
  await assert.rejects(new Neo4jMapStore(backend.driver).read(scope), { code: 'MAP_UNAVAILABLE' });
});

test('unexpected scoped graph endpoints and tenants never become partial evidence', async () => {
  for (const options of [
    { sources: [{ ...source, tenantId: 'foreign' }] },
    { nodes: [{ label: 'GuardAgent', node: { ...agent, source_id: 'foreign' } }] },
    { nodes: [{ label: 'AWSRole', node: agent }] },
    { edges: [{ source: agent.id, target: 'hidden-canary', kind: 'G_INSTANCE_OF' }] },
  ]) await assert.rejects(new Neo4jMapStore(fake(options).driver).read(scope), { code: 'MAP_UNAVAILABLE' });
});

test('absolute timeout returns a stable error and requests rollback', async () => {
  let completed = false;
  const backend = fake({ run: async () => { await new Promise(resolve => setTimeout(resolve, 60)); completed = true; return []; } });
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
  for (const uri of ['bolt://db.example.com', 'neo4j://127.0.0.1', 'bolt+ssc://127.0.0.1', 'https://example.com', 'bolt://u:p@127.0.0.1', 'bolt://127.0.0.1/?query=secret']) {
    assert.throws(() => createNeo4jMapStore({ uri, username: 'u', password: 'private-canary' }), { code: 'MAP_REQUEST_INVALID' });
  }
});
