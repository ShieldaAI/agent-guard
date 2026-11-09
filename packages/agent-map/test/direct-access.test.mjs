import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService } from '../dist/index.js';

const now = Date.parse('2030-01-02T00:00:00Z');
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['blue'], allTeams: false };
const opaque = char => `opaque:${char.repeat(64)}`;

/** Three deployments: one declared path, one declared none (v3), one from a v2 manifest. */
function fixture() {
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
  for (const [suffix, status] of [
    ['found', 'found'],
    ['none', 'none_declared'],
    ['old', undefined],
  ]) {
    node(`agent-${suffix}`, 'GuardAgent', { agent_id: `agent-${suffix}`, name: `Agent ${suffix}`, team_id: 'blue' });
    node(`deployment-${suffix}`, 'GuardDeployment', {
      deployment_id: `deployment-${suffix}`,
      environment: 'production',
      ...(status ? { direct_access_status: status } : {}),
    });
    edge(`deployment-${suffix}`, `agent-${suffix}`, 'G_INSTANCE_OF');
  }
  node('shell', 'GuardDirectAccess', {
    access_id: opaque('a'),
    deployment_id: 'deployment-found',
    kind: 'shell',
    target_ref: null,
    description: 'Ops shell for debugging',
    evidence_kind: 'host_asserted',
  });
  node('database', 'GuardDirectAccess', {
    access_id: opaque('b'),
    deployment_id: 'deployment-found',
    kind: 'database',
    target_ref: opaque('c'),
    description: 'Reporting job reads the records database directly',
    evidence_kind: 'host_asserted',
  });
  edge('shell', 'deployment-found', 'G_DIRECT_ACCESS_FOR');
  edge('database', 'deployment-found', 'G_DIRECT_ACCESS_FOR');
  const current = {
    id: 'current',
    snapshotId: 'snapshot',
    generatedAt: new Date(now).toISOString(),
    status: 'published',
    nodes,
    edges,
    coverage: {},
  };
  return { id: 'source', sourceId: 'source', tenantId: 'tenant', profile: 'host', current, previous: null };
}
const map = new MapService({ read: async () => ({ sources: [fixture()] }) }, { clock: () => now });
const access = async agentId =>
  (await map.query(scope, 'get_agent_access', { sourceId: 'source', agentId })).data.outsideGuard.directAccess;

test('declared paths are listed per deployment with status found', async () => {
  const [deployment] = await access('agent-found');
  assert.equal(deployment.deploymentId, 'deployment-found');
  assert.equal(deployment.status, 'found');
  assert.equal(deployment.evidenceKind, 'declared');
  assert.deepEqual(deployment.entries.map(entry => [entry.kind, entry.targetRef]).sort(), [
    ['database', opaque('c')],
    ['shell', null],
  ]);
});

test('an empty v3 declaration reads as none_declared', async () => {
  const [deployment] = await access('agent-none');
  assert.deepEqual([deployment.status, deployment.entries], ['none_declared', []]);
});

test('a v2 manifest without directAccess reads as unknown, never none_declared', async () => {
  const [deployment] = await access('agent-old');
  assert.deepEqual([deployment.status, deployment.entries], ['unknown', []]);
});

test('another agent never sees a declared path of a deployment outside its focus', async () => {
  const result = await map.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent-none' });
  assert.doesNotMatch(JSON.stringify(result), /Ops shell|records database/);
  assert.match(result.data.limitations.join(' '), /Only S3 identity policies and host declarations are checked/);
});

test('the inventory deployments section carries the same status', async () => {
  const status = async agentId =>
    (await map.query(scope, 'get_agent_inventory', { sourceId: 'source', agentId, section: 'deployments' })).data
      .items[0].directAccessStatus;
  assert.deepEqual(
    [await status('agent-found'), await status('agent-none'), await status('agent-old')],
    ['found', 'none_declared', 'unknown'],
  );
});
