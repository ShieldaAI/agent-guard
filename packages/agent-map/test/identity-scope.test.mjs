import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IDENTITY_SCOPE_BUCKETS,
  IDENTITY_SCOPE_CANDIDATE_LIMIT,
  IDENTITY_SCOPE_QUERY,
  identityScopeEvidence,
  identityScopePlan,
} from '../dist/policy-reader.js';
import { MapService } from '../dist/service.js';

const now = 10000,
  captureTime = 9800,
  maximumAge = 7200;
const account = '111122223333',
  principalArn = `arn:aws:iam::${account}:role/Worker`;
const stamp = {
  cloud_status: 'resolved',
  cloud_assessment: 'unknown',
  cloud_observed_at: 9900,
  cloud_node_updated: captureTime,
  cloud_ownership_updated: captureTime,
  cloud_account_updated: captureTime,
};
const node = (id, label, properties) => ({
  id,
  entityId: `${id}-entity`,
  label,
  sourceId: 'source',
  projectionId: 'projection',
  properties,
});

/** One deployment, two tools sharing one role: `read` binds `reports`, `write` binds `archive`. */
function fixture() {
  const nodes = [
    node('agent', 'GuardAgent', { agent_id: 'agent', team_id: 'team' }),
    node('deployment', 'GuardDeployment', { deployment_id: 'deployment' }),
    node('task', 'GuardTask', {
      task_id: 'task',
      revoked: false,
      deadline: now * 1000 + 60_000,
      delegated: false,
      derived: false,
    }),
    node('identity', 'GuardExternalIdentity', {
      provider: 'aws',
      partition: 'aws',
      account_id: account,
      region: '',
      arn: principalArn,
      ...stamp,
      cloud_provider_id: principalArn,
      cloud_provider_label: 'AWSRole',
      cloud_match_kind: 'exact',
    }),
  ];
  const edges = [
    ['deployment', 'agent', 'G_INSTANCE_OF'],
    ['task', 'deployment', 'G_ASSIGNED_TO'],
  ];
  for (const [tool, bucket] of [
    ['read', 'reports'],
    ['write', 'archive'],
  ]) {
    nodes.push(
      node(`execution-${tool}`, 'GuardExecutionBinding', { tool, identity_selection: 'static' }),
      node(`tool-${tool}`, 'GuardTool', { name: tool }),
      node(`grant-${tool}`, 'GuardGrant', { tool, resources: [bucket] }),
      node(`selector-${tool}`, 'GuardResource', { tool, resource_id: bucket }),
      node(`binding-${tool}`, 'GuardResourceBinding', { tool, resource_ref: bucket, actions: ['s3:GetObject'] }),
      node(`resource-${tool}`, 'GuardExternalResource', {
        provider: 'aws',
        partition: 'aws',
        account_id: account,
        // `read` binds its whole bucket; `write` binds only a prefix of its bucket.
        arn: tool === 'read' ? `arn:aws:s3:::${bucket}` : `arn:aws:s3:::${bucket}/data/`,
        kind: tool === 'read' ? 'bucket' : 'prefix',
      }),
    );
    edges.push(
      [`execution-${tool}`, 'deployment', 'G_EXECUTES_FOR'],
      [`execution-${tool}`, 'identity', 'G_USES_IDENTITY'],
      [`execution-${tool}`, `tool-${tool}`, 'G_EXECUTES_TOOL'],
      ['task', `grant-${tool}`, 'G_HAS_GRANT'],
      [`grant-${tool}`, `tool-${tool}`, 'G_FOR_TOOL'],
      [`grant-${tool}`, `selector-${tool}`, 'G_TARGETS'],
      [`binding-${tool}`, `selector-${tool}`, 'G_BINDS_SELECTOR'],
      [`binding-${tool}`, `resource-${tool}`, 'G_MAPS_TO'],
    );
  }
  return { nodes, edges: edges.map(([source, target, kind]) => ({ source, target, kind })) };
}
const candidate = (bucket, relationship = 'CAN_READ', keys = []) => ({
  bucket,
  relationship,
  has_condition: keys.length > 0,
  condition_keys: keys,
  condition_key_count: keys.length,
  condition_key_lengths: keys.map(key => [...key].length),
  consistent: true,
});
function row(probe, candidates) {
  const reference = item => ({ id: item.id, entity_id: item.entityId, ...item.properties });
  return {
    key: probe.key,
    executionProof: true,
    identity: reference(probe.identity),
    identityLink: {
      eid: 'link',
      kind: 'G_CLOUD_MATCH',
      evidence_kind: 'provider_inventory',
      assessment: 'unknown',
      observed_at: 9900,
    },
    principal: {
      eid: 'principal',
      id: principalArn,
      arn: principalArn,
      lastupdated: captureTime,
      principal: true,
      role: true,
      user: false,
    },
    principalAccount: { eid: 'account', id: account, lastupdated: captureTime },
    principalOwnership: { eid: 'ownership', lastupdated: captureTime },
    collection: {
      eid: 'collection',
      id: probe.collectionId,
      schema_version: 1,
      status: 'complete',
      captured_at: captureTime,
      content_hash: 'a'.repeat(64),
      policy_status: 'complete',
      policy_hash: 'b'.repeat(64),
      policy_mapping_version: 's3-identity-policy-v1',
    },
    principalMember: {
      eid: 'member',
      captured_at: captureTime,
      capture_hash: 'a'.repeat(64),
      policy_status: 'mapped',
      policy_boundary_present: false,
      policy_hash: 'b'.repeat(64),
      policy_mapping_version: 's3-identity-policy-v1',
      policy_assessment: 'unknown',
    },
    candidates,
  };
}
const SHARED = [
  candidate('archive'),
  candidate('reports'),
  candidate('reports', 'CAN_LIST'),
  candidate('secrets', 'CAN_READ', ['aws:SourceVpc']),
];
function evaluate(candidates = SHARED, mutate = () => {}, value = fixture()) {
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  const rows = plan.probes.map(probe => {
    const item = row(probe, typeof candidates === 'function' ? candidates(probe) : candidates);
    mutate(item, probe);
    return item;
  });
  const byTool = Object.fromEntries(identityScopeEvidence(plan, rows, now, maximumAge).map(item => [item.tool, item]));
  return { plan, byTool };
}
const extras = item => item.extraResources.map(extra => `${extra.bucketName}:${extra.relationship}`);

test('each tool is compared with its own bindings only, even when the identity is shared', () => {
  const { plan, byTool } = evaluate();
  assert.equal(plan.probes.length, 1, 'one probe per distinct identity, shared by both tools');
  assert.equal(plan.links.length, 2);
  assert.deepEqual(byTool.read.boundBuckets, ['reports']);
  assert.equal(byTool.read.status, 'broader_than_grants');
  assert.deepEqual(extras(byTool.read), ['archive:CAN_READ', 'secrets:CAN_READ']);
  assert.equal(byTool.write.status, 'broader_than_grants');
  assert.deepEqual(extras(byTool.write), ['reports:CAN_LIST', 'reports:CAN_READ', 'secrets:CAN_READ']);
  assert.equal(byTool.read.observedAt, new Date(captureTime * 1000).toISOString());
  assert.equal(byTool.read.evidenceKind, 'iam_identity_policy_candidate');
});

test('a bucket bound only as a prefix is not covered by a bucket-level candidate', () => {
  const { byTool } = evaluate([candidate('archive')]);
  assert.deepEqual(
    [byTool.write.status, byTool.write.reason, byTool.write.extraResources],
    ['unknown', 'binding_narrower_than_candidate', []],
  );
  assert.equal(byTool.read.status, 'broader_than_grants', 'archive is not bound by read at all');
});

test('a revoked parent unbinds the task; a parent outside the read leaves its grants unknown', () => {
  const withParent = (properties, visible) => {
    const value = fixture();
    Object.assign(value.nodes.find(item => item.id === 'task').properties, { delegated: true });
    if (visible) {
      value.nodes.push(
        node('parent', 'GuardTask', {
          task_id: 'parent',
          deadline: now * 1000 + 60_000,
          delegated: false,
          derived: false,
          ...properties,
        }),
      );
      value.edges.push({ source: 'task', target: 'parent', kind: 'G_DELEGATED_FROM' });
    }
    return identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  };
  const revoked = withParent({ revoked: true }, true);
  assert.deepEqual(
    revoked.records.map(item => item.boundBuckets),
    [[], []],
    'the executor refuses a task whose parent is revoked',
  );
  const live = withParent({ revoked: false }, true);
  assert.deepEqual(live.records.find(item => item.tool === 'read').boundBuckets, ['reports']);
  // A parent that does not say whether it is revoked proves nothing about the task.
  const unverified = withParent({}, true);
  assert.deepEqual(
    unverified.records.map(item => item.reason),
    ['grant_lineage_unknown', 'grant_lineage_unknown'],
  );
  const noClock = identityScopePlan('company', 'tenant', fixture().nodes, fixture().edges, 128, null, Number.NaN);
  assert.deepEqual(
    noClock.records.map(item => item.reason),
    ['grant_lineage_unknown', 'grant_lineage_unknown'],
    'a snapshot time that does not parse leaves expiry unknown',
  );
  const hidden = withParent({ revoked: false }, false);
  assert.deepEqual(
    hidden.records.map(item => [item.status, item.reason]),
    [
      ['unknown', 'grant_lineage_unknown'],
      ['unknown', 'grant_lineage_unknown'],
    ],
  );
});

test('grants on revoked or expired tasks do not count as bound', () => {
  for (const properties of [{ revoked: true }, { deadline: now * 1000 - 1 }]) {
    const value = fixture();
    Object.assign(value.nodes.find(item => item.id === 'task').properties, properties);
    const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
    assert.deepEqual(
      plan.records.map(item => item.boundBuckets),
      [[], []],
    );
  }
});

test('a bound bucket is never listed and a conditional candidate keeps its condition keys', () => {
  const { byTool } = evaluate([candidate('reports'), candidate('secrets', 'CAN_READ', ['aws:SourceVpc'])]);
  const [secret] = byTool.read.extraResources;
  assert.deepEqual(secret, {
    resourceId: 'arn:aws:s3:::secrets',
    bucketName: 'secrets',
    relationship: 'CAN_READ',
    hasCondition: true,
    conditionKeys: ['aws:SourceVpc'],
  });
  assert.equal(byTool.read.extraResources.length, 1);
});

test('only bound buckets, or none at all, match the grants', () => {
  assert.equal(evaluate([candidate('reports')]).byTool.read.status, 'matches_grants');
  const { byTool } = evaluate([]);
  assert.deepEqual([byTool.read.status, byTool.read.reason, byTool.read.extraResources], ['matches_grants', null, []]);
});

test('a list of more than 100 buckets is cut, and the status from the full comparison stands', () => {
  const buckets = Array.from({ length: 101 }, (_, index) => `extra-${String(index).padStart(3, '0')}`);
  const { byTool } = evaluate(buckets.map(bucket => candidate(bucket)));
  assert.deepEqual(
    [byTool.read.status, byTool.read.reason, byTool.read.truncated, byTool.read.notes],
    ['broader_than_grants', null, true, ['bucket_list_shortened']],
  );
  assert.equal(byTool.read.extraResources.length, 100);
  const exactly = evaluate(buckets.slice(0, 100).map(bucket => candidate(bucket)));
  assert.deepEqual([exactly.byTool.read.status, exactly.byTool.read.truncated], ['broader_than_grants', false]);
});

test('the list limit counts buckets, not bucket-relationship entries', () => {
  // A role with read, write and list on 34 buckets: 102 entries, 34 buckets, nothing cut.
  const relationships = ['CAN_LIST', 'CAN_READ', 'CAN_WRITE'];
  const full = Array.from({ length: 34 }, (_, index) => `full-${String(index).padStart(3, '0')}`).flatMap(bucket =>
    relationships.map(relationship => candidate(bucket, relationship)),
  );
  const { byTool } = evaluate(full);
  assert.deepEqual([byTool.read.status, byTool.read.truncated], ['broader_than_grants', false]);
  assert.equal(byTool.read.extraResources.length, 102);
  assert.equal(new Set(byTool.read.extraResources.map(extra => extra.bucketName)).size, 34);
});

test('more than 500 buckets is truncated and unknown', () => {
  const buckets = Array.from(
    { length: IDENTITY_SCOPE_BUCKETS + 1 },
    (_, index) => `bucket-${String(index).padStart(4, '0')}`,
  );
  const { byTool } = evaluate(buckets.map(bucket => candidate(bucket)));
  assert.deepEqual([byTool.read.status, byTool.read.reason, byTool.read.truncated], ['unknown', 'truncated', true]);
  assert.equal(byTool.read.extraResources.length, 100, 'the per-binding list stays short');
  // At exactly 500 the identity's list is complete; whether the record is cut then depends
  // only on the per-binding cap, tested separately.
  const value = fixture();
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  const full = plan.probes.map(probe =>
    row(
      probe,
      buckets.slice(0, IDENTITY_SCOPE_BUCKETS).map(bucket => candidate(bucket)),
    ),
  );
  const over = plan.probes.map(probe =>
    row(
      probe,
      buckets.map(bucket => candidate(bucket)),
    ),
  );
  // The read tool binds no candidate bucket, so it lists the first 100 either way.
  assert.equal(identityScopeEvidence(plan, full, now, maximumAge)[0].extraResources.length, 100);
  assert.equal(identityScopeEvidence(plan, over, now, maximumAge)[0].extraResources[0].bucketName, 'bucket-0000');
  assert.equal(IDENTITY_SCOPE_CANDIDATE_LIMIT, IDENTITY_SCOPE_BUCKETS * 3 + 1);
});

test('malformed, stale or missing evidence is unknown with a reason, never a match', () => {
  const cases = [
    [item => (item.executionProof = false), 'changed'],
    [item => (item.principal = null), 'provider_missing'],
    [item => (item.principal.arn = 'arn:aws:iam::111122223333:role/Other'), 'evidence_invalid'],
    [item => (item.collection = null), 'collection_missing'],
    [item => (item.collection.status = 'partial'), 'collection_invalid'],
    [item => (item.collection.captured_at = now - maximumAge - 1), 'stale'],
    [item => (item.collection.policy_status = 'disabled'), 'disabled'],
    [
      item =>
        Object.assign(item.principalMember, { policy_status: 'boundary_unresolved', policy_boundary_present: true }),
      'boundary_unresolved',
    ],
    [item => (item.principalMember.policy_status = 'unsupported'), 'unsupported_policy'],
    [item => (item.candidates[0].consistent = false), 'evidence_invalid'],
    [item => item.candidates.push(item.candidates[0]), 'evidence_invalid'],
    [item => (item.candidates[0].relationship = 'CAN_DELETE'), 'evidence_invalid'],
    [item => (item.candidates[0].bucket = 'Not_A_Bucket'), 'evidence_invalid'],
    [item => (item.candidates[3].condition_keys = []), 'evidence_invalid'],
  ];
  for (const [mutate, reason] of cases) {
    const { byTool } = evaluate(
      () => structuredClone(SHARED),
      (item, probe) => probe.key === 0 && mutate(item),
    );
    const read = Object.values(byTool).find(item => item.executionBindingId === 'execution-read-entity');
    assert.deepEqual([read.status, read.reason, read.extraResources], ['unknown', reason, []], reason);
  }
});

test('non-static, ambiguous, non-AWS and unresolved identities are not probed', () => {
  const cases = [
    [
      value => (value.nodes.find(n => n.id === 'execution-read').properties.identity_selection = 'dynamic'),
      'identity_not_static',
    ],
    [
      value => value.edges.push({ source: 'execution-read', target: 'deployment', kind: 'G_EXECUTES_FOR' }),
      'binding_ambiguous',
    ],
    [value => (value.nodes.find(n => n.id === 'identity').properties.provider = 'gcp'), 'unsupported_identity'],
    [value => (value.nodes.find(n => n.id === 'identity').properties.cloud_status = null), 'cloud_not_collected'],
    [value => (value.nodes.find(n => n.id === 'identity').properties.cloud_status = 'missing'), 'cloud_unresolved'],
  ];
  for (const [mutate, reason] of cases) {
    const value = fixture();
    mutate(value);
    const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
    const read = plan.records.find(item => item.executionBindingId === 'execution-read-entity');
    assert.deepEqual([read.status, read.reason], ['unknown', reason], reason);
    assert.ok(plan.links.every(link => plan.records[link.record].executionBindingId !== 'execution-read-entity'));
  }
  const shared = identityScopePlan('company', 'tenant', fixture().nodes, fixture().edges, 1, null, now * 1000);
  assert.equal(shared.probes.length, 1, 'two tools on one role need one probe');
  assert.deepEqual(
    shared.records.map(item => item.reason),
    ['collection_missing', 'collection_missing'],
  );
  const capped = identityScopePlan('company', 'tenant', fixture().nodes, fixture().edges, 0, null, now * 1000);
  assert.deepEqual(
    capped.records.map(item => item.reason),
    ['not_evaluated', 'not_evaluated'],
    'past the cap the read continues',
  );
});

test('a binding with more than one target binds nothing and is ambiguous', () => {
  const value = fixture();
  value.edges.push({ source: 'binding-read', target: 'resource-write', kind: 'G_MAPS_TO' });
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  const read = plan.records.find(item => item.tool === 'read');
  assert.deepEqual([read.status, read.reason], ['unknown', 'binding_ambiguous']);
});

test('a * grant is its own reason and is not probed', () => {
  const value = fixture();
  value.nodes.find(item => item.id === 'grant-read').properties.resources = ['*'];
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  const read = plan.records.find(item => item.tool === 'read');
  assert.deepEqual([read.status, read.reason], ['unknown', 'wildcard_grant']);
  assert.equal(plan.probes.length, 1, 'only the write tool is probed');
});

test('a team reader sees only buckets an in-scope binding maps; the rest is a note without a count', () => {
  const value = fixture();
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  const rows = plan.probes.map(probe => row(probe, SHARED));
  const evaluate = readable =>
    identityScopeEvidence(plan, rows, now, maximumAge, readable).find(item => item.tool === 'read');
  const hidden = evaluate(new Set(['reports']));
  assert.equal(hidden.status, 'broader_than_grants', 'the identity still reaches beyond its grants');
  assert.deepEqual(hidden.extraResources, []);
  assert.deepEqual(hidden.notes, ['evidence_outside_visible_scope']);
  assert.doesNotMatch(JSON.stringify(hidden), /secrets|archive/);
  const partial = evaluate(new Set(['reports', 'archive']));
  assert.deepEqual(extras(partial), ['archive:CAN_READ'], 'a same-scope bucket is still listed');
  assert.deepEqual(partial.notes, ['evidence_outside_visible_scope']);
  const everyone = evaluate(null);
  assert.deepEqual(extras(everyone), ['archive:CAN_READ', 'secrets:CAN_READ']);
  assert.equal(everyone.notes, undefined);
});

test('rows for an unrequested probe fail the read', () => {
  const value = fixture();
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  assert.throws(() => identityScopeEvidence(plan, [{ ...row(plan.probes[0], []), key: 99 }], now, maximumAge), {
    code: 'MAP_UNAVAILABLE',
  });
});

test('the reverse query is bounded, scoped, and re-proves team visibility', () => {
  assert.match(IDENTITY_SCOPE_QUERY, /LIMIT \$candidateLimit/);
  assert.match(IDENTITY_SCOPE_QUERY, /LIMIT \$scopeRowLimit/);
  assert.match(IDENTITY_SCOPE_QUERY, /\$allTeams OR agent\.team_id IN \$teamIds/);
  assert.match(IDENTITY_SCOPE_QUERY, /collection_id:c\.id/);
  assert.doesNotMatch(IDENTITY_SCOPE_QUERY, /policy_hash:substring\(candidate/, 'no per-candidate hashes on the wire');
});

test('get_agent_access reports identityScope only for execution bindings in the agent focus', async () => {
  const value = fixture();
  const { plan, byTool } = evaluate();
  assert.equal(plan.records.length, 2);
  value.nodes.push(
    node('other-agent', 'GuardAgent', { agent_id: 'other', team_id: 'team' }),
    node('other-deployment', 'GuardDeployment', { deployment_id: 'other-deployment' }),
    node('other-execution', 'GuardExecutionBinding', { tool: 'read', identity_selection: 'static' }),
  );
  value.edges.push(
    { source: 'other-deployment', target: 'other-agent', kind: 'G_INSTANCE_OF' },
    { source: 'other-execution', target: 'other-deployment', kind: 'G_EXECUTES_FOR' },
  );
  const projection = {
    id: 'projection',
    snapshotId: 'snapshot',
    generatedAt: new Date(now * 1000).toISOString(),
    status: 'published',
    ...value,
    coverage: {},
    policyEvidence: [],
    identityScope: [
      byTool.read,
      byTool.write,
      {
        ...byTool.read,
        executionBindingId: 'other-execution-entity',
        extraResources: [{ bucketName: 'hidden-canary' }],
      },
    ],
  };
  const source = {
    id: 'source',
    sourceId: 'source',
    tenantId: 'tenant',
    profile: 'host',
    current: projection,
    previous: null,
  };
  const map = new MapService({ read: async () => ({ sources: [source] }) }, { clock: () => now * 1000 });
  const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false };
  const response = await map.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const scoped = response.data.outsideGuard.identityScope;
  assert.deepEqual(scoped.map(item => [item.tool, item.status]).sort(), [
    ['read', 'broader_than_grants'],
    ['write', 'broader_than_grants'],
  ]);
  assert.doesNotMatch(JSON.stringify(response), /hidden-canary/);
  const bare = new MapService(
    { read: async () => ({ sources: [{ ...source, current: { ...projection, identityScope: undefined } }] }) },
    { clock: () => now * 1000 },
  );
  const unknown = (await bare.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' })).data
    .outsideGuard.identityScope;
  assert.ok(unknown.length === 2 && unknown.every(item => item.status === 'unknown'));
  assert.ok(
    unknown.every(item => item.reason === 'not_evaluated'),
    'a store that skipped identity scope says so',
  );
});

test('a large deployment with many tools on one role plans within budget', () => {
  // 60 tools sharing one resolved role, 600 tasks with two grants each: one index per deployment.
  const value = fixture();
  for (let tool = 0; tool < 60; tool++) {
    value.nodes.push(
      node(`execution-t${tool}`, 'GuardExecutionBinding', { tool: `t${tool}`, identity_selection: 'static' }),
      node(`tool-t${tool}`, 'GuardTool', { name: `t${tool}` }),
    );
    value.edges.push(
      { source: `execution-t${tool}`, target: 'deployment', kind: 'G_EXECUTES_FOR' },
      { source: `execution-t${tool}`, target: 'identity', kind: 'G_USES_IDENTITY' },
      { source: `execution-t${tool}`, target: `tool-t${tool}`, kind: 'G_EXECUTES_TOOL' },
    );
  }
  for (let task = 0; task < 600; task++) {
    value.nodes.push(
      node(`bulk-${task}`, 'GuardTask', {
        task_id: `bulk-${task}`,
        revoked: false,
        deadline: now * 1000 + 60_000,
        delegated: false,
        derived: false,
      }),
    );
    value.edges.push({ source: `bulk-${task}`, target: 'deployment', kind: 'G_ASSIGNED_TO' });
    for (const grant of [0, 1]) {
      const tool = `t${(task + grant) % 60}`;
      value.nodes.push(node(`bulk-${task}-${grant}`, 'GuardGrant', { tool, resources: ['none'] }));
      value.edges.push({ source: `bulk-${task}`, target: `bulk-${task}-${grant}`, kind: 'G_HAS_GRANT' });
    }
  }
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 8, null, now * 1000);
  assert.equal(plan.records.length, 62);
  assert.equal(plan.probes.length, 1, 'one shared role, one probe');
});

test('a response too large with full bucket lists is answered with shortened, truncated lists', async () => {
  // 80 execution bindings on one broad role, 100 extra buckets each: well over the 1 MiB
  // default response limit with full lists, far under it with short ones.
  const value = fixture();
  const records = [];
  for (let index = 0; index < 80; index++) {
    value.nodes.push(
      node(`wide-${index}`, 'GuardExecutionBinding', { tool: `wide-${index}`, identity_selection: 'static' }),
    );
    value.edges.push({ source: `wide-${index}`, target: 'deployment', kind: 'G_EXECUTES_FOR' });
    records.push({
      executionBindingId: `wide-${index}-entity`,
      deploymentId: 'deployment-entity',
      tool: `wide-${index}`,
      identityId: 'identity-entity',
      accountId: account,
      status: 'broader_than_grants',
      reason: null,
      observedAt: new Date(captureTime * 1000).toISOString(),
      boundBuckets: [],
      extraResources: Array.from({ length: 100 }, (_, bucket) => ({
        resourceId: `arn:aws:s3:::company-data-bucket-number-${String(bucket).padStart(4, '0')}`,
        bucketName: `company-data-bucket-number-${String(bucket).padStart(4, '0')}`,
        relationship: 'CAN_READ',
        hasCondition: false,
        conditionKeys: [],
      })),
      truncated: false,
      evidenceKind: 'iam_identity_policy_candidate',
      assessment: 'unknown',
    });
  }
  assert.ok(Buffer.byteLength(JSON.stringify(records)) > 1024 * 1024, 'the full lists alone exceed the limit');
  const projection = {
    id: 'projection',
    snapshotId: 'snapshot',
    generatedAt: new Date(now * 1000).toISOString(),
    status: 'published',
    ...value,
    coverage: {},
    policyEvidence: [],
    identityScope: records,
  };
  const source = {
    id: 'source',
    sourceId: 'source',
    tenantId: 'tenant',
    profile: 'host',
    current: projection,
    previous: null,
  };
  const map = new MapService({ read: async () => ({ sources: [source] }) }, { clock: () => now * 1000 });
  const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false };
  const response = await map.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const wide = response.data.outsideGuard.identityScope.filter(item => item.tool.startsWith('wide-'));
  assert.equal(wide.length, 80);
  // Only the lists are cut: each record keeps the status of its full comparison.
  assert.ok(wide.every(item => item.status === 'broader_than_grants' && item.truncated === true));
  assert.ok(wide.every(item => item.notes.includes('bucket_list_shortened')));
  assert.ok(wide.every(item => item.extraResources.length <= 25));
  assert.ok(Buffer.byteLength(JSON.stringify(response)) <= 1024 * 1024);
  assert.equal(response.data.agent.agentId, 'agent', 'the rest of the response is intact');
});

test('an identity row too large to keep reads truncated, and says so', () => {
  const value = fixture();
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128, null, now * 1000);
  const rows = plan.probes.map(probe => ({ key: probe.key, oversized: true }));
  const records = identityScopeEvidence(plan, rows, now, maximumAge);
  assert.ok(records.length === 2);
  assert.ok(records.every(item => item.status === 'unknown' && item.reason === 'truncated' && item.truncated === true));
});
