import test from 'node:test';
import assert from 'node:assert/strict';
import { policyPlan, policyEvidence, policyParameters, safePolicyRow, POLICY_QUERY } from '../dist/policy-reader.js';
import { Neo4jMapStore } from '../dist/store.js';

const now = 10000, captureTime = 9800;
const account = '111122223333', principalArn = `arn:aws:iam::${account}:role/Reader`, bucketArn = 'arn:aws:s3:::reports';
const stamp = { cloud_status: 'resolved', cloud_assessment: 'unknown', cloud_observed_at: 9900,
  cloud_node_updated: captureTime, cloud_ownership_updated: captureTime, cloud_account_updated: captureTime };
function fixture() {
  const node = (id, label, properties) => ({ id, entityId: `${id}-entity`, label, sourceId: 'source', projectionId: 'projection', properties });
  const nodes = [
    node('agent', 'GuardAgent', { agent_id: 'agent', team_id: 'team' }),
    node('task', 'GuardTask', { task_id: 'task' }), node('deployment', 'GuardDeployment', {}),
    node('execution', 'GuardExecutionBinding', { tool: 'read', identity_selection: 'static' }),
    node('tool', 'GuardTool', { name: 'read' }),
    node('grant', 'GuardGrant', { tool: 'read', resources: ['report'] }),
    node('selector', 'GuardResource', { tool: 'read', resource_id: 'report' }),
    node('binding', 'GuardResourceBinding', { tool: 'read', resource_ref: 'report', actions: ['s3:GetObject'], scope: 'exact' }),
    node('identity', 'GuardExternalIdentity', { provider: 'aws', partition: 'aws', account_id: account, region: '', arn: principalArn,
      ...stamp, cloud_provider_id: principalArn, cloud_provider_label: 'AWSRole', cloud_match_kind: 'exact' }),
    node('resource', 'GuardExternalResource', { provider: 'aws', partition: 'aws', account_id: account, region: '',
      arn: `${bucketArn}/reports/one.txt`, kind: 'object', ...stamp, cloud_provider_id: 'reports', cloud_provider_label: 'AWSS3Bucket', cloud_match_kind: 'containment' }),
  ];
  const edges = [
    ['deployment', 'agent', 'G_INSTANCE_OF'],
    ['task', 'deployment', 'G_ASSIGNED_TO'], ['execution', 'deployment', 'G_EXECUTES_FOR'],
    ['execution', 'identity', 'G_USES_IDENTITY'], ['task', 'grant', 'G_HAS_GRANT'],
    ['execution', 'tool', 'G_EXECUTES_TOOL'], ['grant', 'tool', 'G_FOR_TOOL'],
    ['grant', 'selector', 'G_TARGETS'], ['binding', 'selector', 'G_BINDS_SELECTOR'], ['binding', 'resource', 'G_MAPS_TO'],
  ].map(([source, target, kind]) => ({ source, target, kind }));
  return { nodes, edges };
}
function prepare(value = fixture(), company = 'company') {
  const plan = policyPlan(company, 'tenant', value.nodes, value.edges, 512);
  const probe = plan.probes[0];
  if (!probe) return { ...value, plan, row: null };
  const reference = node => ({ id: node.id, entity_id: node.entityId, ...node.properties });
  const row = { key: 0, bindingProof: true, identity: reference(probe.identity), resource: reference(probe.resource),
    identityLink: { eid: 'identity-link', kind: 'G_CLOUD_MATCH', evidence_kind: 'provider_inventory', assessment: 'unknown', observed_at: 9900 },
    resourceLink: { eid: 'resource-link', kind: 'G_CLOUD_CONTAINER', evidence_kind: 'provider_inventory', assessment: 'unknown', observed_at: 9900 },
    principal: { eid: 'principal', id: principalArn, arn: principalArn, lastupdated: captureTime, principal: true, role: true, user: false },
    bucket: { eid: 'bucket', id: 'reports', arn: bucketArn, lastupdated: captureTime, region: 'us-east-1', bucket: true },
    principalAccount: { eid: 'account', id: account, lastupdated: captureTime },
    bucketAccount: { eid: 'account', id: account, lastupdated: captureTime },
    principalOwnership: { eid: 'principal-ownership', lastupdated: captureTime }, bucketOwnership: { eid: 'bucket-ownership', lastupdated: captureTime },
    collection: { eid: 'collection', id: probe.collectionId, schema_version: 1, status: 'complete', captured_at: captureTime,
      content_hash: 'a'.repeat(64), policy_status: 'complete', policy_hash: 'b'.repeat(64), policy_mapping_version: 's3-identity-policy-v1' },
    principalMember: { eid: 'principal-member', captured_at: captureTime, capture_hash: 'a'.repeat(64), policy_status: 'mapped',
      policy_boundary_present: false, policy_hash: 'b'.repeat(64), policy_mapping_version: 's3-identity-policy-v1', policy_assessment: 'unknown' },
    bucketMember: { eid: 'bucket-member', captured_at: captureTime, capture_hash: 'a'.repeat(64), region: 'us-east-1' },
    candidate: { eid: 'candidate', collection_id: probe.collectionId, capture_hash: 'a'.repeat(64), captured_at: captureTime,
      policy_hash: 'b'.repeat(64), mapping_version: 's3-identity-policy-v1', relationship: 'CAN_READ', has_condition: true,
      condition_keys: ['aws:SecureTransport'], condition_key_count: 1, condition_key_lengths: [19],
      resource_scope: 'bucket_summary', assessment: 'unknown', evidence_kind: 'iam_identity_policy_candidate' } };
  return { ...value, plan, row };
}
const evaluate = value => policyEvidence(value.plan, value.row ? [value.row] : [], now, 7200);

test('policy projection preserves binding/task/resource identity and emits only minimized unknown candidates', () => {
  const value = prepare();
  const [result] = evaluate(value);
  assert.equal(result.status, 'complete');
  assert.equal(result.reason, null);
  assert.equal(result.taskId, 'task-entity');
  assert.equal(result.deploymentId, 'deployment-entity');
  assert.equal(result.resourceId, 'resource-entity');
  assert.deepEqual(result.candidates, [{ relationship: 'CAN_READ', hasCondition: true, conditionKeys: ['aws:SecureTransport'], resourceScope: 'bucket_summary' }]);
  assert.equal(result.assessment, 'unknown');
  const text = JSON.stringify(result);
  for (const forbidden of ['collection', 'policy_hash', 'capture_hash', '111122223333', 'arn:', 'condition_key_lengths']) assert.equal(text.includes(forbidden), false);
  assert.equal(policyParameters(value.plan)[0].identityNodeId, 'identity');
  assert.equal(value.nodes.find(node => node.id === 'resource').properties.arn, `${bucketArn}/reports/one.txt`);
});

test('pairs never borrow an execution identity from another deployment or a binding for another tool', () => {
  const value = fixture();
  value.nodes.push({ id: 'other', entityId: 'other-entity', label: 'GuardDeployment', sourceId: 'source', projectionId: 'projection', properties: {} });
  value.edges.find(edge => edge.kind === 'G_EXECUTES_FOR').target = 'other';
  assert.deepEqual(prepare(value).plan.records, []);
  const mismatch = fixture(); mismatch.nodes.find(node => node.id === 'binding').properties.tool = 'delete';
  assert.deepEqual(prepare(mismatch).plan.records, []);
});

test('ambiguous assignment and missing identities remain explicit unknown evidence', () => {
  const value = fixture(); value.edges.push({ ...value.edges.find(edge => edge.kind === 'G_ASSIGNED_TO') });
  assert.equal(evaluate(prepare(value))[0].reason, 'binding_ambiguous');
  const missing = fixture(); missing.edges = missing.edges.filter(edge => edge.kind !== 'G_USES_IDENTITY');
  const [row] = evaluate(prepare(missing));
  assert.equal(row.identityId, null); assert.equal(row.reason, 'binding_ambiguous');
});

for (const relation of ['G_FOR_TOOL', 'G_EXECUTES_TOOL', 'G_EXECUTES_FOR', 'G_BINDS_SELECTOR']) {
  test(`ambiguous ${relation} cannot produce direct-store policy candidates`, () => {
    const value = fixture(); value.edges.push({ ...value.edges.find(edge => edge.kind === relation) });
    const prepared = prepare(value);
    assert.equal(prepared.plan.probes.length, 0);
    assert.equal(evaluate(prepared)[0].reason, 'binding_ambiguous');
  });
}

for (const relation of ['G_INSTANCE_OF', 'G_ASSIGNED_TO', 'G_FOR_TOOL', 'G_EXECUTES_TOOL', 'G_EXECUTES_FOR', 'G_BINDS_SELECTOR', 'G_USES_IDENTITY', 'G_MAPS_TO']) {
  test(`wrong-label extra ${relation} is ambiguous even when the valid endpoint is visible`, () => {
    const value = fixture();
    const edge = value.edges.find(item => item.kind === relation);
    value.edges.push({ ...edge, target: 'task' });
    const prepared = prepare(value);
    assert.equal(prepared.plan.probes.length, 0);
    assert.equal(evaluate(prepared)[0].reason, 'binding_ambiguous');
  });
}

test('mismatched real tool endpoint cannot borrow a matching tool-name property', () => {
  const value = fixture();
  value.nodes.push({ ...value.nodes.find(node => node.id === 'tool'), id: 'wrong-tool', entityId: 'wrong-tool-entity', properties: { name: 'read' } });
  value.edges.find(edge => edge.kind === 'G_EXECUTES_TOOL').target = 'wrong-tool';
  assert.equal(evaluate(prepare(value))[0].reason, 'binding_ambiguous');
});

test('an unbound deployment has no candidate probe even when all its other bindings are visible', () => {
  const value = fixture(); value.edges = value.edges.filter(edge => edge.kind !== 'G_INSTANCE_OF');
  const prepared = prepare(value);
  assert.equal(prepared.plan.probes.length, 0);
  assert.equal(evaluate(prepared)[0].reason, 'binding_ambiguous');
});

for (const [name, mutate, expected] of [
  ['unsupported action', value => { value.nodes.find(n => n.id === 'binding').properties.actions = ['s3:DeleteObject']; }, 'unsupported_action'],
  ['dynamic identity', value => { value.nodes.find(n => n.id === 'execution').properties.identity_selection = 'dynamic'; }, 'identity_not_static'],
  ['foreign account', value => { value.nodes.find(n => n.id === 'resource').properties.account_id = '999988887777'; }, 'unsupported_binding'],
  ['missing cloud collection', value => { delete value.nodes.find(n => n.id === 'identity').properties.cloud_status; }, 'cloud_not_collected'],
  ['unresolved cloud', value => { value.nodes.find(n => n.id === 'identity').properties.cloud_status = 'unresolved'; }, 'cloud_unresolved'],
]) test(`${name} creates no provider probe or candidate`, () => {
  const value = fixture(); mutate(value); const prepared = prepare(value);
  assert.equal(prepared.plan.probes.length, 0); assert.equal(evaluate(prepared)[0].reason, expected);
  assert.deepEqual(evaluate(prepared)[0].candidates, []);
});

for (const [name, mutate] of [
  ['candidate hash', row => { row.candidate.capture_hash = 'c'.repeat(64); }],
  ['policy hash', row => { row.candidate.policy_hash = 'c'.repeat(64); }],
  ['candidate assessment', row => { row.candidate.assessment = 'allowed'; }],
  ['candidate scope', row => { row.candidate.resource_scope = 'exact'; }],
  ['conditional flag', row => { row.candidate.has_condition = false; }],
  ['condition key count', row => { row.candidate.condition_key_count = 129; }],
  ['condition string truncation', row => { row.candidate.condition_key_lengths = [257]; }],
  ['condition duplicate', row => { row.candidate.condition_keys.push(row.candidate.condition_keys[0]); row.candidate.condition_key_count++; row.candidate.condition_key_lengths.push(19); }],
  ['foreign collection', row => { row.collection.id = 'c'.repeat(64); }],
  ['malformed collection', row => { row.collection.schema_version = 2; }],
  ['future collection', row => { row.collection.captured_at = now + 1; }],
  ['provider refresh', row => { row.principal.lastupdated++; }],
  ['account refresh', row => { row.principalAccount.lastupdated++; }],
  ['ownership refresh', row => { row.bucketOwnership.lastupdated++; }],
  ['membership hash', row => { row.principalMember.capture_hash = 'c'.repeat(64); }],
  ['bucket region drift', row => { row.bucket.region = 'us-west-2'; }],
  ['mismatched provider identity', row => { row.principal.id = 'wrong'; }],
  ['foreign ownership', row => { row.bucketAccount.id = '999988887777'; }],
  ['wrong provider labels', row => { row.principal.user = true; }],
  ['wrong cloud relationship', row => { row.resourceLink.kind = 'G_CLOUD_MATCH'; }],
  ['cloud link changed', row => { row.identityLink.observed_at++; }],
  ['reference changed after visibility read', row => { row.resource.arn = `${bucketArn}/other`; }],
  ['binding path changed after visibility read', row => { row.bindingProof = false; }],
]) test(`${name} suppresses positive candidates`, () => {
  const value = prepare(); mutate(value.row); const [result] = evaluate(value);
  assert.equal(result.status, 'unavailable'); assert.deepEqual(result.candidates, []);
});

test('complete missing candidate never claims a denial', () => {
  const value = prepare(); value.row.candidate = null;
  const [result] = evaluate(value);
  assert.equal(result.status, 'complete'); assert.equal(result.reason, 'no_candidate'); assert.equal(result.assessment, 'unknown');
});

test('old or disabled collection and boundary/unsupported coverage stay distinct', () => {
  const value = prepare();
  assert.equal(policyEvidence(value.plan, [value.row], now, 120)[0].reason, 'stale');
  value.row.collection.policy_status = 'disabled';
  assert.equal(evaluate(value)[0].reason, 'disabled');
  value.row.collection.policy_status = 'complete';
  value.row.principalMember.policy_status = 'boundary_unresolved'; value.row.principalMember.policy_boundary_present = true;
  assert.equal(evaluate(value)[0].reason, 'boundary_unresolved');
  value.row.principalMember.policy_status = 'unsupported'; value.row.principalMember.policy_boundary_present = false;
  assert.equal(evaluate(value)[0].reason, 'unsupported_policy');
  value.row.collection = null; assert.equal(evaluate(value)[0].reason, 'collection_missing');
});

test('duplicate candidate and ambiguous provider ownership never become a partial positive graph', () => {
  const value = prepare();
  assert.equal(policyEvidence(value.plan, [value.row, structuredClone(value.row)], now, 7200)[0].reason, 'evidence_invalid');
  const duplicate = structuredClone(value.row); duplicate.principalOwnership.eid = 'other';
  assert.equal(policyEvidence(value.plan, [value.row, duplicate], now, 7200)[0].reason, 'evidence_invalid');
});

test('Unicode condition keys retain Python codepoint order and UTF-8 bounds', () => {
  const value = prepare();
  value.row.candidate.condition_keys = ['tag:\ue000', 'tag:😀'];
  value.row.candidate.condition_key_count = 2; value.row.candidate.condition_key_lengths = [5, 5];
  assert.equal(evaluate(value)[0].status, 'complete');
  value.row.candidate.condition_keys = ['é'.repeat(129)]; value.row.candidate.condition_key_count = 1; value.row.candidate.condition_key_lengths = [129];
  assert.equal(evaluate(value)[0].reason, 'evidence_invalid');
});

test('record, graph-work and raw materialization caps fail the complete read', () => {
  const value = fixture();
  assert.throws(() => policyPlan('company', 'tenant', value.nodes, value.edges, 0), { code: 'MAP_LIMIT_EXCEEDED' });
  assert.throws(() => safePolicyRow({ huge: 'x'.repeat(128 * 1024) }), { code: 'MAP_LIMIT_EXCEEDED' });
  assert.throws(() => policyEvidence(prepare().plan, [{ key: 512 }], now, 7200), { code: 'MAP_UNAVAILABLE' });
});

test('fixed policy query projects only allowlisted fields and limits without an unbounded sort', () => {
  assert.equal(/\b(CREATE|MERGE|DELETE|SET|REMOVE|CALL|ORDER\s+BY)\b/.test(POLICY_QUERY), false);
  assert.equal(POLICY_QUERY.includes('properties('), false);
  assert.match(POLICY_QUERY, /LIMIT \$policyRowLimit/);
  assert.match(POLICY_QUERY, /condition_keys\[\.\.129\]/);
  for (const options of [{ policyMaxAgeSeconds: 0 }, { policyMaxAgeSeconds: 86401 }, { clock: 5 }]) {
    assert.throws(() => new Neo4jMapStore({}, options), { code: 'MAP_REQUEST_INVALID' });
  }
});

const readScope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false };
function backend(value, options = {}) {
  let policyReads = 0, rowsYielded = 0, sourceReads = 0;
  const record = data => ({ get: name => data[name] });
  const source = { id: 'source', tenantId: 'tenant', nativeSourceId: 'installation', profile: 'host', currentId: 'projection',
    currentSnapshotId: 'receipt', currentGeneratedAt: new Date(now * 1000).toISOString(), previousId: null,
    policyCoverage: JSON.stringify({ maxAgeSeconds: options.enrolledAge ?? 7200 }) };
  const tx = { isOpen: () => true, rollback: async () => {}, run: async function* (query, params) {
    if (query.startsWith('MATCH (s:GuardSource)')) { sourceReads++; yield record(source); return; }
    if (query.includes(' AS node')) {
      const label = query.match(/RETURN '(\w+)' AS label/)[1];
      for (const node of value.nodes.filter(node => node.label === label)) yield record({ label, node: {
        id: node.id, entity_id: node.entityId, source_id: 'source', projection_id: 'projection', ...node.properties,
      } });
      return;
    }
    if (query === POLICY_QUERY) {
      policyReads++;
      const rows = options.rows ? options.rows(policyReads, params) : [value.row];
      for (const row of rows) { rowsYielded++; yield record(row); }
      return;
    }
    for (const edge of value.edges) yield record(edge);
  } };
  return { stats: () => ({ policyReads, rowsYielded, sourceReads }), driver: { session: () => ({
    beginTransaction: () => tx, close: async () => {},
  }), close: async () => {} } };
}

test('store reads and rechecks policy provenance after source pointers without exposing internal hashes', async () => {
  const value = prepare(), fake = backend(value);
  const view = await new Neo4jMapStore(fake.driver, { clock: () => now * 1000 }).read(readScope);
  assert.equal(view.sources[0].current.policyEvidence[0].status, 'complete');
  assert.deepEqual(fake.stats(), { policyReads: 2, rowsYielded: 2, sourceReads: 2 });
  assert.equal(JSON.stringify(view).includes(value.row.collection.policy_hash), false);
  assert.equal(Object.isFrozen(view.sources[0].current.policyEvidence[0].candidates), true);
});

test('managed candidate edits during the read reject the whole response', async () => {
  const value = prepare(), fake = backend(value, { rows: count => {
    const row = structuredClone(value.row); if (count === 2) row.candidate.condition_keys = ['changed-key']; return [row];
  } });
  await assert.rejects(new Neo4jMapStore(fake.driver, { clock: () => now * 1000 }).read(readScope), { code: 'MAP_UNAVAILABLE' });
});

test('binding proof changed during the read rejects the whole response', async () => {
  const value = prepare(), fake = backend(value, { rows: count => {
    const row = structuredClone(value.row); if (count === 2) row.bindingProof = false; return [row];
  } });
  await assert.rejects(new Neo4jMapStore(fake.driver, { clock: () => now * 1000 }).read(readScope), { code: 'MAP_UNAVAILABLE' });
  const probe = policyParameters(value.plan)[0];
  assert.equal(probe.taskNodeId, 'task'); assert.equal(probe.executionNodeId, 'execution');
  assert.equal(probe.resourceRef, 'report'); assert.equal(probe.action, 's3:GetObject');
  assert.equal(probe.agentNodeId, 'agent'); assert.equal(probe.agentEntityId, 'agent-entity'); assert.equal(probe.agentTeamId, 'team');
  assert.match(POLICY_QUERY, /\$allTeams OR agent\.team_id IN \$teamIds/);
  assert.match(POLICY_QUERY, /agent\.team_id=pair\.agentTeamId/);
  assert.match(POLICY_QUERY, /NOT EXISTS \{ MATCH \(deployment\)-\[other:G_INSTANCE_OF\]/);
});

test('candidate freshness is bounded by both host and enrolled scope, and rechecked before return', async () => {
  for (const [enrolledAge, hostAge] of [[120, 7200], [7200, 120]]) {
    const value = prepare(), fake = backend(value, { enrolledAge });
    const view = await new Neo4jMapStore(fake.driver, { policyMaxAgeSeconds: hostAge, clock: () => now * 1000 }).read(readScope);
    assert.equal(view.sources[0].current.policyEvidence[0].reason, 'stale');
  }
  const value = prepare(); let current = now;
  const fake = backend(value, { enrolledAge: 200, rows: count => {
    // Advance on the actual policy recheck, independently of how often other
    // components read the clock. The initially complete candidate then expires.
    if (count === 2) current = now + 1;
    return [value.row];
  } });
  await assert.rejects(new Neo4jMapStore(fake.driver, { clock: () => current * 1000 }).read(readScope), { code: 'MAP_UNAVAILABLE' });
  assert.equal(fake.stats().policyReads, 2);
});

test('history reads omit live policy evidence entirely', async () => {
  const value = prepare(), fake = backend(value);
  const view = await new Neo4jMapStore(fake.driver, { clock: () => now * 1000 }).read(readScope, { history: true });
  assert.equal(view.sources[0].current.policyEvidence, undefined);
  assert.equal(fake.stats().policyReads, 0);
});

test('recheck byte cap stops concurrent policy growth before collecting an oversized second result', async () => {
  const value = fixture(), originalTask = value.nodes.find(node => node.id === 'task');
  for (let index = 1; index < 128; index++) {
    const id = `task-${index}`;
    value.nodes.push({ ...originalTask, id, entityId: `${id}-entity` });
    value.edges.push({ source: id, target: 'deployment', kind: 'G_ASSIGNED_TO' }, { source: id, target: 'grant', kind: 'G_HAS_GRANT' });
  }
  const prepared = prepare(value);
  const keys = Array.from({ length: 128 }, (_, index) => `key${String(index).padStart(3, '0')}:${'x'.repeat(249)}`);
  const fake = backend(prepared, { rows: count => prepared.plan.probes.map(probe => {
    const row = structuredClone(prepared.row); row.key = probe.key;
    if (count === 2) {
      row.candidate.condition_keys = keys; row.candidate.condition_key_count = keys.length;
      row.candidate.condition_key_lengths = keys.map(key => key.length);
    }
    return row;
  }) });
  await assert.rejects(new Neo4jMapStore(fake.driver, { clock: () => now * 1000 }).read(readScope), { code: 'MAP_LIMIT_EXCEEDED' });
  assert.equal(fake.stats().policyReads, 2);
  assert.ok(fake.stats().rowsYielded < 256);
});
