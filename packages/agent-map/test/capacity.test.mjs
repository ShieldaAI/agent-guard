import test from 'node:test';
import assert from 'node:assert/strict';
import { Neo4jMapStore } from '../dist/store.js';
import { MapService } from '../dist/service.js';
import { policyPlan } from '../dist/policy-reader.js';

// Capacity: what one reader can list once a source holds more than a few dozen agents.
const NOW = Date.parse('2026-10-30T00:00:10Z');
const all = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: [], allTeams: true };
const team = { ...all, teamIds: ['team'], allTeams: false };
const plain = value => JSON.parse(JSON.stringify(value));
const ACTIONS = ['s3:GetObject', 's3:PutObject', 's3:ListBucket'];
const BUCKETS = 3;
const sourceRow = {
  id: 'source',
  tenantId: 'tenant',
  nativeSourceId: 'installation',
  profile: 'host',
  currentId: 'projection',
  currentSnapshotId: 'receipt',
  currentGeneratedAt: '2026-10-30T00:00:00Z',
  currentCoverage: JSON.stringify({
    tasks: { status: 'complete', observedAt: '2026-10-30T00:00:00Z' },
    tools: { status: 'complete', observedAt: '2026-10-30T00:00:00Z' },
  }),
  previousId: null,
};

/** A fleet in the graph's own shape: every agent's one task is granted three buckets with three actions each. */
function fleet(agents, { filler = 0, padding = '' } = {}) {
  const rows = [],
    edges = [];
  const node = (id, label, properties) =>
    rows.push({
      label,
      node: { id, entity_id: `e:${id}`, source_id: 'source', projection_id: 'projection', ...properties },
    });
  const edge = (source, target, kind) => edges.push({ source, target, kind });
  node('tool', 'GuardTool', { name: 'reports.read', registered: true, approved: true, known_metadata: true });
  node('identity', 'GuardExternalIdentity', {
    provider: 'aws',
    partition: 'aws',
    account_id: '111122223333',
    arn: 'arn:aws:iam::111122223333:role/Reader',
  });
  node('owner', 'GuardOwner', { owner_id: 'owner', name: 'Platform', kind: 'team' });
  for (let bucket = 0; bucket < BUCKETS; bucket++) {
    node(`selector:${bucket}`, 'GuardResource', {
      resource_id: `r${bucket}`,
      tool: 'reports.read',
      selector_kind: 'exact',
    });
    node(`binding:${bucket}`, 'GuardResourceBinding', {
      binding_id: `b${bucket}`,
      tool: 'reports.read',
      resource_ref: `r${bucket}`,
      actions: ACTIONS,
      scope: 'exact',
      owner_id: 'owner',
    });
    node(`external:${bucket}`, 'GuardExternalResource', {
      provider: 'aws',
      partition: 'aws',
      account_id: '111122223333',
      arn: `arn:aws:s3:::bucket-${bucket}`,
      kind: 'bucket',
    });
    edge(`binding:${bucket}`, `selector:${bucket}`, 'G_BINDS_SELECTOR');
    edge(`binding:${bucket}`, `external:${bucket}`, 'G_MAPS_TO');
    edge(`binding:${bucket}`, 'owner', 'G_RESOURCE_OWNED_BY');
  }
  for (let index = 0; index < agents; index++) {
    node(`agent:${index}`, 'GuardAgent', {
      agent_id: `agent-${index}`,
      name: `Agent ${String(index).padStart(4, '0')}`,
      team_id: 'team',
      owner_id: 'owner',
      purpose: padding,
    });
    node(`deployment:${index}`, 'GuardDeployment', {
      deployment_id: `deployment-${index}`,
      environment: 'production',
      direct_access_status: 'none_declared',
    });
    node(`task:${index}`, 'GuardTask', { task_id: `task-${index}`, revoked: false, sensitive: false });
    node(`grant:${index}`, 'GuardGrant', {
      task_id: `task-${index}`,
      tool: 'reports.read',
      resources: Array.from({ length: BUCKETS }, (_, bucket) => `r${bucket}`),
    });
    node(`execution:${index}`, 'GuardExecutionBinding', {
      binding_id: `x${index}`,
      tool: 'reports.read',
      identity_selection: 'static',
    });
    edge(`agent:${index}`, 'owner', 'G_OWNED_BY');
    edge(`deployment:${index}`, `agent:${index}`, 'G_INSTANCE_OF');
    edge(`task:${index}`, `deployment:${index}`, 'G_ASSIGNED_TO');
    edge(`task:${index}`, `grant:${index}`, 'G_HAS_GRANT');
    edge(`grant:${index}`, 'tool', 'G_FOR_TOOL');
    for (let bucket = 0; bucket < BUCKETS; bucket++) edge(`grant:${index}`, `selector:${bucket}`, 'G_TARGETS');
    edge(`execution:${index}`, `deployment:${index}`, 'G_EXECUTES_FOR');
    edge(`execution:${index}`, 'tool', 'G_EXECUTES_TOOL');
    edge(`execution:${index}`, 'identity', 'G_USES_IDENTITY');
  }
  for (let index = 0; index < filler; index++)
    node(`principal:${index}`, 'GuardPrincipal', { principal_id: `p${index}` });
  return { rows, edges };
}
/** A driver over one fleet: fixed templates in, the rows a published projection would return out. */
function driver({ rows, edges }) {
  const calls = [];
  const records = values => values.map(value => ({ get: name => value[name] }));
  const tx = {
    isOpen: () => true,
    rollback: async () => {},
    run: async function* (query, params) {
      calls.push({ query, params });
      if (query.startsWith('MATCH (s:GuardSource)')) yield* records([sourceRow]);
      else if (query.includes(' AS node')) {
        const label = query.match(/RETURN '(\w+)' AS label/)[1];
        yield* records(rows.filter(item => item.label === label).slice(0, Number(params.nodeLimit)));
      } else if (query.includes('type(r) AS kind')) {
        const ids = new Set(params.nodeIds);
        yield* records(edges.filter(item => ids.has(item.source) && ids.has(item.target)));
      } else if (query.includes('AS hidden')) yield* records([{ hidden: false }]);
      // Policy, identity-scope and discovery templates find nothing collected in this fixture.
    },
  };
  return {
    calls,
    labels: () => calls.flatMap(call => call.query.match(/RETURN '(\w+)' AS label/)?.[1] ?? []),
    driver: {
      session: () => ({ beginTransaction: () => tx, close: async () => {} }),
      close: async () => {},
    },
  };
}
const store = (graph, options) => new Neo4jMapStore(driver(graph).driver, { clock: () => NOW, ...options });

test('a read that shows no policy evidence is not bound by the 512-pair policy limit', async () => {
  // 58 agents x 3 buckets x 3 actions = 522 task/binding/action pairs.
  const graph = fleet(58);
  // Unchanged default for a caller that wants every pair: over the limit, no partial evidence.
  await assert.rejects(store(graph).read(all, {}), { code: 'MAP_LIMIT_EXCEEDED' });
  for (const request of [{ policy: false }, { outsideGuard: true, policy: false }, { owners: true }]) {
    const backend = driver(graph);
    const view = await new Neo4jMapStore(backend.driver, { clock: () => NOW }).read(all, request);
    assert.equal(view.sources[0].current.policyEvidence, undefined, JSON.stringify(request));
    assert.equal(view.sources[0].current.policyEvidenceNotLoaded, undefined);
    assert.equal(
      backend.calls.some(call => call.query.includes('$policyPairs')),
      false,
    );
  }
  // Health asks for the pairs but can do without them: it is told, never handed a partial list.
  const optional = (await store(graph).read(all, { policy: { optional: true } })).sources[0].current;
  assert.equal(optional.policyEvidenceNotLoaded, true);
  assert.equal(optional.policyEvidence, undefined);
  // Under the limit the same optional read carries complete evidence.
  const small = (await store(fleet(5)).read(all, { policy: { optional: true } })).sources[0].current;
  assert.equal(small.policyEvidenceNotLoaded, undefined);
  assert.equal(small.policyEvidence.length, 5 * BUCKETS * ACTIONS.length);
});

test('a lookup narrows the policy pairs to its own task, tool, resource and action', async () => {
  const graph = fleet(58);
  const evidence = async policy => (await store(graph).read(all, { policy })).sources[0].current.policyEvidence;
  const byResource = await evidence({ resourceRef: 'r0', action: 's3:GetObject' });
  assert.equal(byResource.length, 58);
  assert.ok(byResource.every(item => item.action === 's3:GetObject' && item.resourceBindingId === 'e:binding:0'));
  // The mapped ARN selects the same binding as its host reference.
  assert.equal((await evidence({ resourceRef: 'arn:aws:s3:::bucket-0', action: 's3:GetObject' })).length, 58);
  for (const taskId of ['task-7', 'e:task:7']) {
    const byTask = await evidence({ taskId, tool: 'reports.read', resourceRef: 'r1' });
    assert.equal(byTask.length, ACTIONS.length);
    assert.ok(byTask.every(item => item.taskId === 'e:task:7' && item.resourceBindingId === 'e:binding:1'));
  }
  assert.deepEqual(plain(await evidence({ tool: 'another.tool' })), []);
  // A selection that still matches more than 512 pairs fails as before.
  await assert.rejects(store(graph).read(all, { policy: { tool: 'reports.read' } }), { code: 'MAP_LIMIT_EXCEEDED' });
  // The planner itself: the same records as the unfiltered plan, filtered.
  const view = await store(fleet(4)).read(all, { policy: false });
  const { nodes, edges } = view.sources[0].current;
  const whole = policyPlan('company', 'tenant', nodes, edges, 512).records;
  const narrowed = policyPlan('company', 'tenant', nodes, edges, 512, { taskId: 'task-2', action: 's3:PutObject' });
  assert.deepEqual(
    plain(narrowed.records),
    plain(whole.filter(item => item.taskId === 'e:task:2' && item.action === 's3:PutObject')),
  );
});

test('policy selection and the owner index are closed request shapes', async () => {
  const graph = fleet(1);
  for (const request of [
    { policy: true },
    { policy: 'all' },
    { policy: [] },
    { policy: { cypher: 'MATCH (n) RETURN n' } },
    { policy: { optional: 'yes' } },
    { policy: { taskId: '' } },
    { policy: { action: 5 } },
    { owners: 'yes' },
    { owners: true, summary: true },
    { owners: true, outsideGuard: true },
    { owners: true, agentId: 'agent-0' },
  ])
    await assert.rejects(store(graph).read(all, request), { code: 'MAP_REQUEST_INVALID' }, JSON.stringify(request));
});

test('every listing answers for a fleet past the policy pair limit, for both kinds of reader', async () => {
  const graph = fleet(58);
  for (const scope of [all, team]) {
    const map = new MapService(store(graph), { clock: () => NOW });
    const owners = await map.query(scope, 'list_owners', {});
    assert.deepEqual(
      plain(owners.data.owners).map(item => [item.name, item.agentCount, item.resourceCount]),
      [['Platform', 58, BUCKETS]],
    );
    const resources = await map.query(scope, 'list_resources', {});
    assert.equal(resources.data.total, BUCKETS);
    const access = await map.query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'b0', limit: 100 });
    assert.equal(access.data.total, 58);
    const found = await map.query(scope, 'find_agents_with_access', {
      resourceRef: 'r0',
      action: 's3:GetObject',
      limit: 100,
    });
    assert.equal(found.data.candidates.length, 58);
    assert.equal(found.data.truncated, false);
    // Narrowed to the lookup, the evidence is still there: one record per candidate task.
    assert.ok(found.data.candidates.every(item => item.evidence[0].policyEvidence.length === 1));
    const explained = await map.query(scope, 'explain_access', {
      sourceId: 'source',
      taskId: 'task-9',
      tool: 'reports.read',
      resourceId: 'r2',
    });
    assert.equal(explained.data.externalEvidence.policyEvidence.length, ACTIONS.length);
    // Health still answers; policy coverage for more pairs than one read evaluates is unknown.
    const health = await map.query(scope, 'get_inventory_health', {});
    assert.deepEqual(plain(health.data.sources[0].coverage.policy), {
      status: 'unknown',
      reason: 'limit_exceeded',
      observedAt: null,
      assessment: 'unknown',
    });
    assert.equal((await map.query(scope, 'list_agents', { limit: 100 })).data.total, 58);
  }
});

test('the owner index reads only the labels that decide its rows', async () => {
  const graph = fleet(3);
  const whole = new MapService(
    // The same question answered from a read of the whole graph.
    { read: scope => store(graph).read(scope, { policy: false }) },
    { clock: () => NOW },
  );
  for (const [scope, labels] of [
    [all, ['GuardAgent', 'GuardResourceBinding', 'GuardOwner']],
    // A team reader's bindings are visible through its agents' grants, so that chain is read too.
    [
      team,
      [
        'GuardAgent',
        'GuardDeployment',
        'GuardTask',
        'GuardGrant',
        'GuardResource',
        'GuardResourceBinding',
        'GuardOwner',
      ],
    ],
  ]) {
    const backend = driver(graph);
    const map = new MapService(new Neo4jMapStore(backend.driver, { clock: () => NOW }), { clock: () => NOW });
    const listed = await map.query(scope, 'list_owners', {});
    assert.deepEqual(backend.labels(), labels);
    // The same rows and counts as a read of the whole graph.
    assert.deepEqual(plain(listed.data), plain((await whole.query(scope, 'list_owners', {})).data));
  }
});

test('store read limits are configurable up to hard maximums and refuse anything else as configuration', async () => {
  const many = fleet(0, { filler: 2500 });
  await assert.rejects(store(many).read(all, { policy: false }), { code: 'MAP_LIMIT_EXCEEDED' });
  const raised = await store(many, { maxNodes: 4000 }).read(all, { policy: false });
  assert.equal(raised.sources[0].current.nodes.length, 2500 + 3 + 3 * BUCKETS);
  // The byte budget is separate: nodes that fit the count can still exceed it, until it is raised.
  const heavy = fleet(1500, { padding: 'x'.repeat(3000) });
  const limits = { maxNodes: 10_000, maxEdges: 25_000 };
  await assert.rejects(store(heavy, limits).read(all, { summary: true }), { code: 'MAP_LIMIT_EXCEEDED' });
  const roomy = await store(heavy, { ...limits, maxBytes: 16 * 1024 * 1024 }).read(all, { summary: true });
  assert.equal(roomy.sources[0].current.nodes.filter(node => node.label === 'GuardAgent').length, 1500);
  for (const options of [
    { maxNodes: 10_001 },
    { maxEdges: 25_001 },
    { maxBytes: 16 * 1024 * 1024 + 1 },
    { maxNodes: 0 },
    { maxBytes: '4MiB' },
    { timeoutMs: 5001 },
    { database: '' },
    { clock: 5 },
  ])
    assert.throws(() => new Neo4jMapStore(driver(many).driver, options), { code: 'MAP_CONFIG_INVALID' });
});

test('a fleet at the raised store maximum still lists within the service work budget', async () => {
  // 800 agents with about a dozen nodes each: the practical ceiling of the raised limits.
  const graph = fleet(800, { filler: 5000 });
  const limits = { maxNodes: 10_000, maxEdges: 25_000, maxBytes: 16 * 1024 * 1024 };
  await assert.rejects(store(graph).read(all, { policy: false }), { code: 'MAP_LIMIT_EXCEEDED' });
  const map = new MapService(store(graph, limits), { clock: () => NOW });
  assert.equal((await map.query(all, 'list_agents', { limit: 100 })).data.total, 800);
  assert.equal((await map.query(all, 'list_owners', {})).data.owners[0].agentCount, 800);
  assert.equal((await map.query(all, 'list_resources', {})).data.total, BUCKETS);
  const access = await map.query(all, 'get_resource_access', { sourceId: 'source', resourceId: 'b0' });
  assert.equal(access.data.total, 800);
  // 800 tasks reach this bucket: more pairs than one read evaluates. The documented 100
  // candidates are still listed, and their policy coverage reads unknown, not "not collected".
  const found = await map.query(all, 'find_agents_with_access', {
    resourceRef: 'r0',
    action: 's3:GetObject',
    limit: 100,
  });
  assert.equal(found.data.candidates.length, 100);
  assert.equal(found.data.truncated, true);
  assert.equal(found.data.truncatedReason, undefined);
  for (const candidate of found.data.candidates) {
    assert.deepEqual(plain(candidate.evidence[0].policyEvidence), []);
    assert.equal(candidate.evidence[0].policyCoverage.status, 'unknown');
    assert.equal(candidate.evidence[0].policyCoverage.reason, 'limit_exceeded');
    assert.equal(candidate.evidence[0].explanation.externalEvidence.policyCoverage.reason, 'limit_exceeded');
  }
  const health = await map.query(all, 'get_inventory_health', {});
  assert.equal(health.data.sources[0].coverage.policy.status, 'unknown');
});

test('policy evidence that was not loaded has no size: null counts and totals, never an empty complete list', async () => {
  const args = { sourceId: 'source', agentId: 'agent-3' };
  const unknown = { status: 'unknown', reason: 'limit_exceeded', observedAt: null, assessment: 'unknown' };
  for (const scope of [all, team]) {
    // 522 task/binding/action pairs: the optional read loads no policy evidence and says so.
    const map = new MapService(store(fleet(58)), { clock: () => NOW });
    const overview = (await map.query(scope, 'get_agent_inventory', args)).data;
    assert.equal(overview.counts.policies, null);
    assert.deepEqual(plain(overview.policyCoverage), unknown);
    // Every other section was read and keeps its size.
    for (const [section, size] of Object.entries(overview.counts))
      if (section !== 'policies') assert.equal(Number.isSafeInteger(size), true, section);
    assert.equal(overview.total, 1);
    const policies = (await map.query(scope, 'get_agent_inventory', { ...args, section: 'policies' })).data;
    assert.deepEqual(plain([policies.items, policies.total, policies.truncated]), [[], null, false]);
    assert.equal(policies.counts.policies, null);
    assert.deepEqual(plain(policies.policyCoverage), unknown);
    // A section that was read still reports its own total while the policy count is null.
    const tasks = (await map.query(scope, 'get_agent_inventory', { ...args, section: 'tasks' })).data;
    assert.equal(tasks.total, tasks.counts.tasks);
    assert.equal(tasks.counts.policies, null);
    // get_agent_access states no size; its empty list is marked by the coverage beside it.
    const access = (await map.query(scope, 'get_agent_access', args)).data;
    assert.deepEqual(plain([access.policyEvidence, access.policyCoverage]), [[], unknown]);
    // Under the limit the same agent has evidence, a count and a total.
    const small = new MapService(store(fleet(5)), { clock: () => NOW });
    const loaded = (await small.query(scope, 'get_agent_inventory', { ...args, section: 'policies' })).data;
    assert.equal(loaded.counts.policies, BUCKETS * ACTIONS.length);
    assert.deepEqual(
      [loaded.total, loaded.items.length, loaded.truncated],
      [loaded.counts.policies, loaded.total, false],
    );
    assert.notEqual(loaded.policyCoverage.status, 'unknown');
  }
});
