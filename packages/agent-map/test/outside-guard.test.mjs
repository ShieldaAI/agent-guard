import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService } from '../dist/index.js';

const now = Date.parse('2030-01-02T00:00:00Z');
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['blue'], allTeams: false };
const opaque = char => `opaque:${char.repeat(64)}`;
const plain = value => JSON.parse(JSON.stringify(value));

/** Two bindings: an S3 bucket (`reports`) and a host database (opaque('d')). */
function build({
  status = 'none_declared',
  direct = false,
  untargeted = false,
  reach = [],
  reachMissing = false,
  hiddenScope = false,
  execution = true,
  unresolved = false,
  collected = true,
} = {}) {
  const nodes = [],
    edges = [];
  const node = (key, label, properties) =>
    nodes.push({
      id: `n:${key}`,
      entityId: `e:${key}`,
      sourceId: 'source',
      projectionId: 'current',
      label,
      properties,
    });
  const edge = (a, b, kind) => edges.push({ source: `n:${a}`, target: `n:${b}`, kind });
  node('agent', 'GuardAgent', { agent_id: 'agent', name: 'Agent', team_id: 'blue' });
  node('deployment', 'GuardDeployment', {
    deployment_id: 'deployment',
    ...(status ? { direct_access_status: direct ? 'found' : status } : {}),
  });
  edge('deployment', 'agent', 'G_INSTANCE_OF');
  node('task', 'GuardTask', { task_id: 'task', revoked: false, deadline: now + 60_000 });
  edge('task', 'deployment', 'G_ASSIGNED_TO');
  if (execution) {
    node('execution', 'GuardExecutionBinding', { binding_id: 'execution', tool: 'read', identity_selection: 'static' });
    edge('execution', 'deployment', 'G_EXECUTES_FOR');
  }
  if (unresolved) {
    node('elsewhere', 'GuardDirectAccess', {
      access_id: opaque('c'),
      deployment_id: 'deployment',
      kind: 'database',
      target_ref: opaque('e'),
      description: 'Another team database',
    });
    edge('elsewhere', 'deployment', 'G_DIRECT_ACCESS_FOR');
  }
  if (untargeted) {
    node('shell', 'GuardDirectAccess', {
      access_id: opaque('b'),
      deployment_id: 'deployment',
      kind: 'shell',
      target_ref: null,
      description: 'Ops shell',
    });
    edge('shell', 'deployment', 'G_DIRECT_ACCESS_FOR');
  }
  for (const [name, target] of [
    [
      'reports',
      {
        provider: 'aws',
        partition: 'aws',
        account_id: '111122223333',
        arn: 'arn:aws:s3:::reports/data/',
        kind: 'prefix',
        cloud_status: collected ? 'resolved' : 'unresolved',
      },
    ],
    ['database', { provider: 'host', host_resource_id: opaque('d'), name: 'Records', kind: 'database' }],
  ]) {
    node(`grant-${name}`, 'GuardGrant', { task_id: 'task', tool: 'read', resources: [name] });
    node(`selector-${name}`, 'GuardResource', { resource_id: name, tool: 'read' });
    node(`binding-${name}`, 'GuardResourceBinding', {
      binding_id: name,
      tool: 'read',
      resource_ref: name,
      display_name: name,
    });
    node(`target-${name}`, 'GuardExternalResource', target);
    edge('task', `grant-${name}`, 'G_HAS_GRANT');
    edge(`grant-${name}`, `selector-${name}`, 'G_TARGETS');
    edge(`binding-${name}`, `selector-${name}`, 'G_BINDS_SELECTOR');
    edge(`binding-${name}`, `target-${name}`, 'G_MAPS_TO');
  }
  if (direct) {
    node('direct', 'GuardDirectAccess', {
      access_id: opaque('a'),
      deployment_id: 'deployment',
      kind: 'database',
      target_ref: opaque('d'),
      description: 'Reporting job connects directly',
    });
    edge('direct', 'deployment', 'G_DIRECT_ACCESS_FOR');
  }
  const current = {
    id: 'current',
    snapshotId: 'snapshot',
    generatedAt: new Date(now).toISOString(),
    status: 'published',
    nodes,
    edges,
    coverage: {},
    ...(reachMissing ? {} : { identityReach: reach }),
    outsideVisibleScope: hiddenScope,
  };
  return { id: 'source', sourceId: 'source', tenantId: 'tenant', profile: 'host', current, previous: null };
}
const record = (status, extras = [], accountId = '111122223333') => ({
  executionBindingId: 'e:execution',
  accountId,
  deploymentId: 'e:deployment',
  tool: 'write',
  identityId: 'e:identity',
  status,
  reason: status === 'unknown' ? 'stale' : null,
  observedAt: null,
  boundBuckets: [],
  extraResources: extras.map(bucket => ({
    resourceId: `arn:aws:s3:::${bucket}`,
    bucketName: bucket,
    relationship: 'CAN_READ',
    hasCondition: false,
    conditionKeys: [],
  })),
  truncated: false,
  evidenceKind: 'iam_identity_policy_candidate',
  assessment: 'unknown',
});
const map = source => new MapService({ read: async () => ({ sources: [source] }) }, { clock: () => now });
async function column(options) {
  const response = await map(build(options)).query(scope, 'list_resources', {});
  return Object.fromEntries(response.data.resources.map(item => [item.bindingId, item.outsideGuard]));
}

test('list_resources reports yes, none_found or unknown per resource', async () => {
  assert.deepEqual(await column({ reach: [record('matches_grants')] }), {
    reports: 'none_found',
    database: 'unknown',
  });
  assert.deepEqual(await column({ reach: [record('broader_than_grants', ['reports'])] }), {
    reports: 'yes',
    database: 'unknown',
  });
  assert.deepEqual(await column({ direct: true, reach: [record('matches_grants')] }), {
    reports: 'none_found',
    database: 'yes',
  });
  assert.deepEqual(await column({ status: null, reach: [record('matches_grants')] }), {
    reports: 'unknown',
    database: 'unknown',
  });
  assert.deepEqual(await column({ reach: [record('unknown')] }), { reports: 'unknown', database: 'unknown' });
  assert.deepEqual(await column({ reachMissing: true }), { reports: 'unknown', database: 'unknown' });
  assert.deepEqual(
    await column({ collected: false, reach: [record('matches_grants')] }),
    { reports: 'unknown', database: 'unknown' },
    'a bucket the AWS collection never resolved was never compared',
  );
  assert.deepEqual(
    await column({ reach: [] }),
    { reports: 'unknown', database: 'unknown' },
    'an execution binding with no reach record was not evaluated',
  );
});

test('anything that could reach a resource unseen keeps the column unknown, never none_found', async () => {
  const none = { reports: 'unknown', database: 'unknown' };
  assert.deepEqual(
    await column({ untargeted: true, reach: [record('matches_grants')] }),
    none,
    'a shell can touch any resource',
  );
  assert.deepEqual(await column({ execution: false, reach: [] }), none, 'a tool with no declared identity');
  assert.deepEqual(
    await column({ hiddenScope: true, reach: [record('matches_grants')] }),
    none,
    'deployments outside your scope',
  );
  const found = build({ reach: [record('matches_grants')] });
  found.current.nodes.find(item => item.label === 'GuardDeployment').properties.direct_access_status = 'found';
  const inconsistent = await map(found).query(scope, 'list_resources', {});
  assert.equal(
    inconsistent.data.resources.find(item => item.bindingId === 'reports').outsideGuard,
    'unknown',
    'found with no entry in the read is not a declaration',
  );
  assert.deepEqual(
    await column({ reach: [record('matches_grants', [], '222222222222')] }),
    none,
    'an identity in another account was never compared with this bucket',
  );
  assert.deepEqual(
    await column({ unresolved: true, reach: [record('matches_grants')] }),
    none,
    'a path to a resource the read cannot match may be any resource',
  );
  const response = await map(build({ hiddenScope: true, reach: [record('matches_grants')] })).query(
    scope,
    'get_resource_access',
    {
      sourceId: 'source',
      resourceId: 'reports',
    },
  );
  assert.deepEqual(plain(response.data.outsideGuard.unknownReasons), ['outside_visible_scope']);
  const all = await map(build({ hiddenScope: true, reach: [record('matches_grants')] })).query(
    { ...scope, allTeams: true },
    'list_resources',
    {},
  );
  assert.equal(
    all.data.resources.find(item => item.bindingId === 'reports').outsideGuard,
    'none_found',
    'an all-teams reader sees every deployment',
  );
});

test('get_resource_access lists the identities and declared paths that reach a resource', async () => {
  const source = build({ direct: true, reach: [record('broader_than_grants', ['reports'])] });
  const reports = plain(
    (await map(source).query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'reports' })).data,
  );
  assert.equal(reports.outsideGuard.status, 'yes');
  assert.deepEqual(
    reports.outsideGuard.identities.map(item => [item.tool, item.relationship, item.executionBindingId]),
    [['write', 'CAN_READ', 'e:execution']],
  );
  assert.deepEqual(reports.outsideGuard.directAccess, []);
  assert.match(reports.limitations.join(' '), /within your visible scope/);
  const database = plain(
    (await map(source).query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'database' })).data,
  );
  assert.equal(database.outsideGuard.status, 'yes');
  assert.deepEqual(
    database.outsideGuard.directAccess.map(item => [item.kind, item.deploymentId, item.evidenceKind]),
    [['database', 'deployment', 'declared']],
  );
  const undeclared = plain(
    (
      await map(build({ status: null, reach: [record('matches_grants')] })).query(scope, 'get_resource_access', {
        sourceId: 'source',
        resourceId: 'reports',
      })
    ).data,
  );
  assert.deepEqual(undeclared.outsideGuard.unknownReasons, ['direct_access_undeclared']);
});

test('get_changes labels added and removed declared paths as outside_guard and declared', async () => {
  const before = build({ reach: [] }).current;
  const after = build({ direct: true, reach: [] }).current;
  const previous = {
    ...before,
    id: 'previous',
    snapshotId: 'old',
    nodes: before.nodes.map(item => ({ ...item, id: `old:${item.id}`, projectionId: 'previous' })),
    edges: before.edges.map(item => ({ ...item, source: `old:${item.source}`, target: `old:${item.target}` })),
  };
  const source = { id: 'source', sourceId: 'source', tenantId: 'tenant', profile: 'host', current: after, previous };
  const changes = plain(
    (await map(source).query(scope, 'get_changes', { sourceId: 'source', changeKind: 'outside_guard' })).data,
  );
  const labels = changes.details.map(item => [item.label, item.kind, item.evidenceKind]).sort();
  assert.deepEqual(labels, [
    ['GuardDeployment', 'changed', 'declared'],
    ['GuardDirectAccess', 'added', 'declared'],
  ]);
  // A target outside the reader's scope is never shown, before or after.
  const hidden = build({ direct: true, reach: [] }).current;
  hidden.nodes.find(item => item.label === 'GuardDirectAccess').properties.target_ref = opaque('e');
  const withheld = plain(
    (
      await map({ ...source, current: hidden }).query(scope, 'get_changes', {
        sourceId: 'source',
        changeKind: 'outside_guard',
      })
    ).data,
  );
  const added = withheld.details.find(item => item.label === 'GuardDirectAccess');
  assert.equal('target_ref' in added.after.properties, false);
  assert.doesNotMatch(JSON.stringify(withheld), new RegExp(opaque('e').slice(7)));
  const deployment = changes.details.find(item => item.label === 'GuardDeployment');
  assert.deepEqual(deployment.changedFields, ['direct_access_status']);
  const permissions = plain(
    (await map(source).query(scope, 'get_changes', { sourceId: 'source', changeKind: 'bindings' })).data,
  );
  assert.ok(
    permissions.details.every(item => item.label !== 'GuardDirectAccess'),
    'declared paths are their own category',
  );
});

test('a reach record whose list was cut keeps resources unknown, never none_found', async () => {
  const cut = { ...record('broader_than_grants', ['other']), truncated: true, notes: ['bucket_list_shortened'] };
  assert.deepEqual(await column({ reach: [cut] }), { reports: 'unknown', database: 'unknown' });
  const naming = { ...record('broader_than_grants', ['reports']), truncated: true };
  assert.equal((await column({ reach: [naming] })).reports, 'yes', 'a bucket it still names is reached');
});

test('get_resource_access lists at most 100 reaching identities and says when it cut the list', async () => {
  // 150 tools on one broad role all reach the same bucket.
  const reach = Array.from({ length: 150 }, (_, index) => ({
    ...record('broader_than_grants', ['reports']),
    executionBindingId: `e:execution-${String(index).padStart(3, '0')}`,
    tool: `tool-${index}`,
  }));
  const source = build({ reach });
  const { nodes, edges } = source.current;
  for (let index = 0; index < 150; index++) {
    nodes.push({
      id: `n:execution-${index}`,
      entityId: `e:execution-${String(index).padStart(3, '0')}`,
      sourceId: 'source',
      projectionId: 'current',
      label: 'GuardExecutionBinding',
      properties: { binding_id: `execution-${index}`, tool: `tool-${index}`, identity_selection: 'static' },
    });
    edges.push({ source: `n:execution-${index}`, target: 'n:deployment', kind: 'G_EXECUTES_FOR' });
  }
  const detail = plain(
    (await map(source).query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'reports' })).data,
  );
  assert.equal(detail.outsideGuard.status, 'yes');
  assert.equal(detail.outsideGuard.identities.length, 100);
  assert.equal(detail.outsideGuard.identitiesTruncated, true);
  assert.equal(detail.outsideGuard.directAccessTruncated, false);
  assert.equal(detail.outsideGuard.identities[0].executionBindingId, 'e:execution-000', 'a stable order');
  const listing = await map(source).query(scope, 'list_resources', {});
  assert.equal(listing.data.resources.find(item => item.bindingId === 'reports').outsideGuard, 'yes');
});

test('a deployment with many tasks and many execution bindings is judged within the work budget', async () => {
  // 1,000 granted tasks and 250 execution bindings on one deployment: each deployment's
  // executed tools are read once, not once per task.
  const source = build({ reach: [record('matches_grants')] });
  const { nodes, edges } = source.current;
  const add = (key, label, properties) =>
    nodes.push({
      id: `n:${key}`,
      entityId: `e:${key}`,
      sourceId: 'source',
      projectionId: 'current',
      label,
      properties,
    });
  for (let index = 0; index < 250; index++) {
    add(`bulk-execution-${index}`, 'GuardExecutionBinding', { tool: `tool-${index}`, identity_selection: 'static' });
    edges.push({ source: `n:bulk-execution-${index}`, target: 'n:deployment', kind: 'G_EXECUTES_FOR' });
  }
  for (let index = 0; index < 1000; index++) {
    add(`bulk-task-${index}`, 'GuardTask', { task_id: `bulk-${index}`, revoked: false, deadline: now + 60_000 });
    add(`bulk-grant-${index}`, 'GuardGrant', {
      task_id: `bulk-${index}`,
      tool: `tool-${index % 250}`,
      resources: ['x'],
    });
    edges.push(
      { source: `n:bulk-task-${index}`, target: 'n:deployment', kind: 'G_ASSIGNED_TO' },
      { source: `n:bulk-task-${index}`, target: `n:bulk-grant-${index}`, kind: 'G_HAS_GRANT' },
    );
  }
  const listing = await map(source).query(scope, 'list_resources', {});
  assert.equal(listing.data.resources.length, 2);
  const detail = await map(source).query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'reports' });
  // Every granted tool has an execution binding, so none is undeclared; the bulk bindings
  // have no reach record, which is the only reason left.
  assert.equal(detail.data.outsideGuard.status, 'unknown');
  assert.deepEqual(plain(detail.data.outsideGuard.unknownReasons), ['identity_scope_unknown']);
});

test('reach that needs more work than allowed reads unknown; the listing still answers', async () => {
  // Reach work alone over its budget: 2,100 reach records of 100 buckets each.
  const wide = record(
    'broader_than_grants',
    Array.from({ length: 100 }, (_, index) => `bucket-${index}`),
  );
  const source = build({ reach: Array.from({ length: 2100 }, () => wide) });
  const listing = await map(source).query(scope, 'list_resources', {});
  assert.deepEqual(Object.fromEntries(listing.data.resources.map(item => [item.bindingId, item.outsideGuard])), {
    reports: 'unknown',
    database: 'unknown',
  });
  const detail = await map(source).query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'reports' });
  assert.deepEqual(plain(detail.data.outsideGuard.unknownReasons), ['reach_not_evaluated']);
  assert.equal(detail.data.outsideGuard.status, 'unknown');
});

test('a reach record with an unrecognised status never lets none_found stand', async () => {
  const odd = { ...record('matches_grants'), status: 'fine' };
  assert.deepEqual(await column({ reach: [odd] }), { reports: 'unknown', database: 'unknown' });
});

test('a task on two deployments needs an execution binding for its tools on both', async () => {
  const second = bound => {
    const source = build({
      reach: [record('matches_grants'), { ...record('matches_grants'), executionBindingId: 'e:execution-b' }],
    });
    const { nodes, edges } = source.current;
    const add = (key, label, properties) =>
      nodes.push({
        id: `n:${key}`,
        entityId: `e:${key}`,
        sourceId: 'source',
        projectionId: 'current',
        label,
        properties,
      });
    add('deployment-b', 'GuardDeployment', { deployment_id: 'deployment-b', direct_access_status: 'none_declared' });
    edges.push(
      { source: 'n:deployment-b', target: 'n:agent', kind: 'G_INSTANCE_OF' },
      { source: 'n:task', target: 'n:deployment-b', kind: 'G_ASSIGNED_TO' },
    );
    if (bound) {
      add('execution-b', 'GuardExecutionBinding', {
        binding_id: 'execution-b',
        tool: 'read',
        identity_selection: 'static',
      });
      edges.push({ source: 'n:execution-b', target: 'n:deployment-b', kind: 'G_EXECUTES_FOR' });
    }
    return source;
  };
  const detail = async source =>
    (await map(source).query(scope, 'get_resource_access', { sourceId: 'source', resourceId: 'reports' })).data
      .outsideGuard;
  const both = await detail(second(true));
  assert.equal(both.status, 'none_found');
  const one = await detail(second(false));
  assert.equal(one.status, 'unknown');
  assert.deepEqual(plain(one.unknownReasons), ['execution_identity_undeclared']);
});
