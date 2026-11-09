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
    node('task', 'GuardTask', { task_id: 'task' }),
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
        arn: `arn:aws:s3:::${bucket}/data/`,
        kind: 'prefix',
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
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128);
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
  assert.equal(plan.probes.length, 2, 'one probe per execution binding');
  assert.deepEqual(byTool.read.boundBuckets, ['reports']);
  assert.equal(byTool.read.status, 'broader_than_grants');
  assert.deepEqual(extras(byTool.read), ['archive:CAN_READ', 'secrets:CAN_READ']);
  assert.equal(byTool.write.status, 'broader_than_grants');
  assert.deepEqual(extras(byTool.write), ['reports:CAN_LIST', 'reports:CAN_READ', 'secrets:CAN_READ']);
  assert.equal(byTool.read.observedAt, new Date(captureTime * 1000).toISOString());
  assert.equal(byTool.read.evidenceKind, 'iam_identity_policy_candidate');
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

test('more than 500 buckets is truncated and unknown', () => {
  const buckets = Array.from(
    { length: IDENTITY_SCOPE_BUCKETS + 1 },
    (_, index) => `bucket-${String(index).padStart(4, '0')}`,
  );
  const { byTool } = evaluate(buckets.map(bucket => candidate(bucket)));
  assert.deepEqual([byTool.read.status, byTool.read.reason, byTool.read.truncated], ['unknown', 'truncated', true]);
  assert.equal(byTool.read.extraResources.length, IDENTITY_SCOPE_BUCKETS, 'the first 500 buckets are still listed');
  const exactly = evaluate(buckets.slice(0, IDENTITY_SCOPE_BUCKETS).map(bucket => candidate(bucket)));
  assert.equal(exactly.byTool.read.truncated, false);
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
    const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128);
    const read = plan.records.find(item => item.executionBindingId === 'execution-read-entity');
    assert.deepEqual([read.status, read.reason], ['unknown', reason], reason);
    assert.ok(plan.probes.every(probe => plan.records[probe.key].executionBindingId !== 'execution-read-entity'));
  }
  assert.throws(() => identityScopePlan('company', 'tenant', fixture().nodes, fixture().edges, 1), {
    code: 'MAP_LIMIT_EXCEEDED',
  });
});

test('rows for an unrequested probe fail the read', () => {
  const value = fixture();
  const plan = identityScopePlan('company', 'tenant', value.nodes, value.edges, 128);
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
});
