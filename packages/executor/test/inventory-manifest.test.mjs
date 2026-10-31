import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { composeInventorySnapshot, validateInventoryManifest } from '../dist/inventory-manifest.js';
import { projectInventory } from '../dist/inventory.js';

const fixture = JSON.parse(readFileSync(new URL('fixtures/inventory-manifest.json', import.meta.url), 'utf8'));
const plain = value => JSON.parse(JSON.stringify(value));
const manifest = () => plain(fixture);
function core() {
  const { source } = fixture;
  const task = { options: { id: 'task', tenantId: source.tenantId, principalId: 'caller',
    grants: [{ tool: 'read', resources: ['item'] }], budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100_000.5 } },
    parent: null, family: 'task', tokenHash: 'private-token-hash', revoked: true,
    calls: 2, concurrent: 1, spent: 3, reserved: 5 };
  return projectInventory({ schema: 1, revision: 7, epoch: 3, lastClock: 1000,
    inventoryInstanceId: source.inventoryInstanceId, tasks: { task }, families: { task: { sensitive: true } },
    tools: { read: { fingerprint: 'a'.repeat(64), revision: 1, approved: false } },
    actions: {}, approvals: {}, audit: [], memory: {} }, new Map(), {
    companyId: source.companyId, sourceId: source.sourceId, enrollmentGeneration: source.enrollmentGeneration,
  }, { tenantId: source.tenantId }, Date.UTC(2026, 9, 29));
}

test('manifest validation returns a detached immutable host assertion', () => {
  const input = manifest();
  const validated = validateInventoryManifest(input);
  assert.deepEqual(plain(validated), input);
  assert.notEqual(validated, input);
  assert.equal(Object.isFrozen(validated.resourceBindings[0].actions), true);
  input.agents[0].name = 'changed';
  assert.equal(validated.agents[0].name, fixture.agents[0].name);
  assert.throws(() => { validated.executionBindings[0].identity.accountId = '000000000000'; }, TypeError);
});

test('composition preserves every authority field and independent capture time', () => {
  const snapshot = core(); const before = plain(snapshot);
  const value = manifest();
  const composed = composeInventorySnapshot(snapshot, value);
  assert.equal(composed.profile, 'host'); assert.notEqual(composed.snapshotId, snapshot.snapshotId);
  assert.deepEqual(composed.tasks, snapshot.tasks); assert.deepEqual(composed.tools, snapshot.tools);
  assert.deepEqual(composed.source, snapshot.source);
  assert.equal(composed.ledgerRevision, snapshot.ledgerRevision); assert.equal(composed.policyEpoch, snapshot.policyEpoch);
  assert.deepEqual(composed.coverage.tasks, snapshot.coverage.tasks); assert.deepEqual(composed.coverage.tools, snapshot.coverage.tools);
  assert.deepEqual(plain(composed.coverage.manifest), { status: 'complete', observedAt: value.observedAt });
  assert.equal(composed.coverage.mcp.status, 'not_collected'); assert.equal(composed.coverage.cloud.status, 'not_collected');
  assert.notEqual(composed.coverage.tasks.observedAt, composed.coverage.manifest.observedAt);
  assert.equal(composed.manifest.revision, 4);
  assert.deepEqual(plain(snapshot), before);
  assert.deepEqual(value, fixture);
  assert.equal(Object.isFrozen(composed.manifest.resourceBindings[0].target), true);
  const another = composeInventorySnapshot(snapshot, value);
  assert.notEqual(another.snapshotId, composed.snapshotId);
});

test('unassigned tasks remain visible and metadata cannot replace caller identity', () => {
  const snapshot = plain(core());
  snapshot.tasks.push({ ...plain(snapshot.tasks[0]), id: 'unassigned' });
  const composed = composeInventorySnapshot(snapshot, manifest());
  assert.equal(composed.tasks.length, 2);
  assert.equal(composed.tasks[1].id, 'unassigned'); assert.equal(composed.tasks[0].principalId, 'caller');
  assert.equal(composed.manifest.executionBindings[0].identity.arn, 'arn:aws:iam::123456789012:role/reporter');
  assert.equal(composed.tasks[0].revoked, true); assert.equal(composed.tasks[0].sensitive, true);
});

test('empty host metadata composes with a complete empty tenant', () => {
  const snapshot = plain(core()); snapshot.tasks = []; snapshot.tools = [];
  const value = manifest();
  for (const field of ['agents', 'deployments', 'taskBindings', 'resourceBindings', 'executionBindings']) value[field] = [];
  const composed = composeInventorySnapshot(snapshot, value);
  assert.deepEqual(composed.tasks, []); assert.deepEqual(composed.manifest.agents, []);
  assert.equal(composed.coverage.tasks.status, 'complete');
});

test('resource bindings match exact exported opaque references and preserve prefix scopes', () => {
  const snapshot = plain(core());
  snapshot.tasks[0].grants[0].resources = ['opaque:' + 'b'.repeat(64)];
  const value = manifest(); value.resourceBindings[0].resourceRef = snapshot.tasks[0].grants[0].resources[0];
  value.resourceBindings[0].target.arn = 'arn:aws:s3:::reports/selected/prefix/';
  value.resourceBindings[0].target.kind = 'prefix'; value.resourceBindings[0].scope = 'prefix';
  const composed = composeInventorySnapshot(snapshot, value);
  assert.deepEqual(plain(composed.tasks[0].grants), snapshot.tasks[0].grants);
  assert.equal(composed.manifest.resourceBindings[0].target.kind, 'prefix');
  value.resourceBindings[0].resourceRef = 'raw-private-resource';
  assert.throws(() => composeInventorySnapshot(snapshot, value), { code: 'INVENTORY_MANIFEST_REFERENCE_INVALID' });
});

test('dynamic and unknown execution identities stay unresolved and may name an opaque connection', () => {
  for (const identitySelection of ['dynamic', 'unknown']) {
    const value = manifest();
    Object.assign(value.executionBindings[0], { identitySelection, identity: null, connectionId: 'connection-1' });
    const composed = composeInventorySnapshot(core(), value);
    assert.equal(composed.manifest.executionBindings[0].identity, null);
    assert.equal(composed.coverage.mcp.status, 'not_collected');
  }
});

test('AWS references preserve the exact partition, asserted account and regional identity', () => {
  const value = manifest();
  value.resourceBindings[0].target = { provider: 'aws', partition: 'aws-cn', accountId: '111122223333', region: 'cn-north-1',
    arn: 'arn:aws-cn:lambda:cn-north-1:111122223333:function:reports', kind: 'resource' };
  value.resourceBindings[0].actions = ['lambda:InvokeFunction'];
  value.executionBindings[0].identity = { provider: 'aws', partition: 'aws-cn', accountId: '111122223333', region: '',
    arn: 'arn:aws-cn:sts::111122223333:assumed-role/reporter/session' };
  assert.deepEqual(plain(validateInventoryManifest(value)), value);
});

for (const field of ['companyId', 'sourceId', 'enrollmentGeneration', 'inventoryInstanceId', 'tenantId']) {
  test(`composition rejects a different ${field} without exposing either source`, () => {
    const value = manifest(); value.source[field] = 'private-source-canary';
    assert.throws(() => composeInventorySnapshot(core(), value), {
      code: 'INVENTORY_MANIFEST_SOURCE_MISMATCH', message: 'INVENTORY_MANIFEST_SOURCE_MISMATCH',
    });
  });
}

for (const [name, change] of [
  ['task', value => { value.taskBindings[0].taskId = 'unknown'; }],
  ['execution tool', value => { value.executionBindings[0].tool = 'unknown'; }],
  ['resource tool', value => { value.resourceBindings[0].tool = 'unknown'; }],
  ['resource reference', value => { value.resourceBindings[0].resourceRef = 'unknown'; }],
]) test(`composition rejects an unresolved local ${name} binding`, () => {
  const value = manifest(); change(value);
  assert.throws(() => composeInventorySnapshot(core(), value), { code: 'INVENTORY_MANIFEST_REFERENCE_INVALID' });
});

for (const [name, change] of [
  ['extra credential field', value => { value.credentials = 'private-canary'; }],
  ['nested arbitrary metadata', value => { value.agents[0].metadata = { secret: 'private-canary' }; }],
  ['authority injection', value => { value.taskBindings[0].grants = [{ tool: 'admin', resources: ['*'] }]; }],
  ['missing required null field', value => { delete value.agents[0].ownerId; }],
  ['wrong evidence kind', value => { value.evidenceKind = 'verified_permission'; }],
  ['unsafe revision', value => { value.revision = Number.MAX_SAFE_INTEGER + 1; }],
  ['impossible date', value => { value.observedAt = '2026-02-30T01:00:00Z'; }],
  ['year zero', value => { value.observedAt = '0000-01-01T00:00:00Z'; }],
  ['blank unicode identifier', value => { value.agents[0].name = '\u0085'; }],
  ['unpaired unicode', value => { value.agents[0].name = '\ud800'; }],
  ['duplicate agent ID', value => { value.agents.push(plain(value.agents[0])); }],
  ['duplicate deployment ID', value => { value.deployments.push(plain(value.deployments[0])); }],
  ['duplicate task assignment', value => { value.taskBindings.push(plain(value.taskBindings[0])); }],
  ['duplicate resource pair', value => { value.resourceBindings.push({ ...plain(value.resourceBindings[0]), id: 'another' }); }],
  ['duplicate execution pair', value => { value.executionBindings.push({ ...plain(value.executionBindings[0]), id: 'another' }); }],
  ['wildcard selector expansion', value => { value.resourceBindings[0].resourceRef = '*'; }],
  ['wildcard AWS action', value => { value.resourceBindings[0].actions = ['s3:*']; }],
  ['unrelated AWS action service', value => { value.resourceBindings[0].actions = ['iam:GetUser']; }],
  ['duplicate AWS actions', value => { value.resourceBindings[0].actions = ['s3:GetObject', 's3:GetObject']; }],
  ['empty actions', value => { value.resourceBindings[0].actions = []; }],
  ['credential URL', value => { value.resourceBindings[0].target.arn = 'https://user:private-canary@service.invalid'; }],
  ['ARN partition mismatch', value => { value.resourceBindings[0].target.partition = 'aws-cn'; }],
  ['object-valued ARN partition', value => { value.resourceBindings[0].target.partition = { toString: 'private-canary' }; }],
  ['ARN region mismatch', value => { value.resourceBindings[0].target.region = 'eu-west-1'; }],
  ['S3 ARN account present', value => { value.resourceBindings[0].target.arn = 'arn:aws:s3::123456789012:reports/report.txt'; }],
  ['ARN wildcard', value => { value.resourceBindings[0].target.arn = 'arn:aws:s3:::reports/*'; }],
  ['object claimed as bucket', value => { value.resourceBindings[0].target.kind = 'bucket'; }],
  ['S3 generic scope', value => { value.resourceBindings[0].target.kind = 'resource'; }],
  ['prefix without trailing delimiter', value => { value.resourceBindings[0].target.kind = 'prefix'; value.resourceBindings[0].scope = 'prefix'; }],
  ['prefix expansion of object', value => { value.resourceBindings[0].scope = 'prefix'; }],
  ['static identity missing', value => { value.executionBindings[0].identity = null; }],
  ['dynamic identity guessed', value => { value.executionBindings[0].identitySelection = 'dynamic'; }],
  ['object-valued identity selection', value => { value.executionBindings[0].identitySelection = {}; }],
  ['array-valued identity selection', value => { value.executionBindings[0].identitySelection = []; }],
  ['null identity selection', value => { value.executionBindings[0].identitySelection = null; }],
  ['identity account mismatch', value => { value.executionBindings[0].identity.accountId = '000000000000'; }],
  ['IAM identity empty final segment', value => { value.executionBindings[0].identity.arn = 'arn:aws:iam::123456789012:role/path/'; }],
  ['IAM identity empty middle segment', value => { value.executionBindings[0].identity.arn = 'arn:aws:iam::123456789012:role//reporter'; }],
  ['regional STS identity', value => { value.executionBindings[0].identity.region = 'eu-west-1'; value.executionBindings[0].identity.arn = 'arn:aws:sts:eu-west-1:123456789012:assumed-role/reporter/session'; }],
  ['identity resource not principal', value => { value.executionBindings[0].identity.arn = 'arn:aws:s3:::reports'; }],
]) test(`manifest rejects ${name}`, () => {
  const value = manifest(); change(value);
  assert.throws(() => validateInventoryManifest(value), { code: 'INVENTORY_MANIFEST_INVALID', message: 'INVENTORY_MANIFEST_INVALID' });
});

for (const [name, change] of [
  ['deployment agent', value => { value.deployments[0].agentId = 'missing'; }],
  ['task deployment', value => { value.taskBindings[0].deploymentId = 'missing'; }],
  ['execution deployment', value => { value.executionBindings[0].deploymentId = 'missing'; }],
]) test(`manifest rejects dangling ${name}`, () => {
  const value = manifest(); change(value);
  assert.throws(() => validateInventoryManifest(value), { code: 'INVENTORY_MANIFEST_REFERENCE_INVALID' });
});

test('validation and composition do not invoke accessors or custom serialization', () => {
  let invoked = false;
  const value = manifest(); Object.defineProperty(value.agents[0], 'name', { get() { invoked = true; return 'private-canary'; } });
  assert.throws(() => validateInventoryManifest(value), { code: 'INVENTORY_MANIFEST_INVALID' });
  const snapshot = plain(core()); Object.defineProperty(snapshot.tasks[0], 'budget', { get() { invoked = true; return {}; } });
  assert.throws(() => composeInventorySnapshot(snapshot, manifest()), { code: 'INVENTORY_SNAPSHOT_INVALID' });
  const custom = manifest(); custom.toJSON = () => { invoked = true; return fixture; };
  assert.throws(() => validateInventoryManifest(custom), { code: 'INVENTORY_MANIFEST_INVALID' });
  assert.equal(invoked, false);
});

for (const [name, change] of [
  ['extra property', value => { value.raw = 'private-canary'; }],
  ['task extra field', value => { value.tasks[0].token = 'private-canary'; }],
  ['wrong tenant', value => { value.tasks[0].tenantId = 'foreign'; }],
  ['missing lineage', value => { value.tasks[0].parentTaskId = 'missing'; }],
  ['lineage cycle', value => { value.tasks[0].sourceTaskId = 'task'; }],
  ['duplicate grants', value => { value.tasks[0].grants.push(plain(value.tasks[0].grants[0])); }],
  ['invalid counter', value => { value.tasks[0].usage.calls = -1; }],
  ['fabricated availability', value => { value.tools[0].requiresApproval = false; }],
]) test(`composition rejects a malformed core snapshot: ${name}`, () => {
  const snapshot = plain(core()); change(snapshot);
  assert.throws(() => composeInventorySnapshot(snapshot, manifest()), { code: 'INVENTORY_SNAPSHOT_INVALID' });
});

test('manifest and composed-output limits reject complete payloads without truncation', () => {
  const tooMany = manifest();
  tooMany.agents = Array.from({ length: 1001 }, (_, i) => ({ ...fixture.agents[0], id: `agent-${i}` }));
  assert.throws(() => validateInventoryManifest(tooMany), { code: 'INVENTORY_MANIFEST_LIMIT_EXCEEDED' });
  const large = manifest();
  large.agents = Array.from({ length: 600 }, (_, i) => ({ ...fixture.agents[0], id: i === 0 ? 'agent' : `agent-${i}`, name: 'x'.repeat(4000) }));
  assert.throws(() => validateInventoryManifest(large), { code: 'INVENTORY_MANIFEST_LIMIT_EXCEEDED' });
  const snapshot = plain(core());
  for (let i = 0; i < 2; i++) snapshot.tasks.push({ ...plain(snapshot.tasks[0]), id: `large-${i}`,
    grants: [{ tool: 'read', resources: Array.from({ length: 950 }, (_, j) => `${j}:${'x'.repeat(4000)}`) }] });
  const bounded = manifest();
  bounded.agents = Array.from({ length: 300 }, (_, i) => ({ ...fixture.agents[0], id: i === 0 ? 'agent' : `agent-${i}`, name: 'x'.repeat(4000) }));
  validateInventoryManifest(bounded);
  assert.ok(Buffer.byteLength(JSON.stringify(snapshot)) < 8 * 1024 * 1024);
  assert.throws(() => composeInventorySnapshot(snapshot, bounded), { code: 'INVENTORY_LIMIT_EXCEEDED' });
});
