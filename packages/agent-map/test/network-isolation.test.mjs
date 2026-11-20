import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService } from '../dist/index.js';
import { MAP_PROPERTIES } from '../dist/projection-fields.js';
import { IGNORE_DIFF } from '../dist/service/changes.js';

const now = Date.parse('2030-01-02T00:00:00Z');
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['blue'], allTeams: false };
const opaque = char => `opaque:${char.repeat(64)}`;
const plain = value => JSON.parse(JSON.stringify(value));
const FIELDS = ['network_status', 'network_segment', 'network_egress', 'network_egress_targets', 'sandbox_kind'];

/** One agent and its deployment with the given network properties, as one projection. */
function projection(id, network) {
  const prefix = id === 'current' ? '' : `${id}:`;
  return {
    id,
    snapshotId: `${id}-snapshot`,
    generatedAt: new Date(now).toISOString(),
    status: 'published',
    nodes: [
      {
        id: `${prefix}n:agent`,
        entityId: 'e:agent',
        sourceId: 'source',
        projectionId: id,
        label: 'GuardAgent',
        properties: { agent_id: 'agent', name: 'Agent', team_id: 'blue' },
      },
      {
        id: `${prefix}n:deployment`,
        entityId: 'e:deployment',
        sourceId: 'source',
        projectionId: id,
        label: 'GuardDeployment',
        properties: { deployment_id: 'deployment', direct_access_status: 'none_declared', ...network },
      },
    ],
    edges: [{ source: `${prefix}n:deployment`, target: `${prefix}n:agent`, kind: 'G_INSTANCE_OF' }],
    coverage: {},
  };
}
const declared = {
  network_status: 'declared',
  network_segment: opaque('a'),
  network_egress: 'allowlist',
  network_egress_targets: [opaque('b')],
  sandbox_kind: 'container',
};
async function changes(before, after, args = {}) {
  const source = {
    id: 'source',
    sourceId: 'source',
    tenantId: 'tenant',
    profile: 'host',
    current: projection('current', after),
    previous: projection('previous', before),
  };
  const service = new MapService({ read: async () => ({ sources: [source] }) }, { clock: () => now });
  const response = await service.query(scope, 'get_changes', { sourceId: 'source', ...args });
  return plain(response.data).details;
}

test('the five network fields are map properties of a deployment and are never ignored as noise', () => {
  for (const field of FIELDS) {
    assert.ok(MAP_PROPERTIES.GuardDeployment.includes(field), field);
    assert.equal(IGNORE_DIFF.has(field), false, field);
  }
});

test('get_changes reports a new network declaration under bindings, with before and after', async () => {
  // A host moving from manifest v3 (absent: unknown) to v4.
  const [detail] = await changes({}, declared);
  assert.equal(detail.label, 'GuardDeployment');
  assert.equal(detail.kind, 'changed');
  assert.ok(detail.categories.includes('bindings'), detail.categories.join());
  assert.deepEqual([...detail.changedFields].sort(), [...FIELDS].sort());
  for (const field of FIELDS) assert.equal(field in detail.before.properties, false, field);
  assert.deepEqual(
    Object.fromEntries(FIELDS.map(field => [field, detail.after.properties[field]])),
    declared,
    'the declared values are shown',
  );
  const filtered = await changes({}, declared, { changeKind: 'bindings' });
  assert.equal(filtered.length, 1);
});

test('get_changes reports each changed network field, and nothing when the declaration is unchanged', async () => {
  const opened = { ...declared, network_egress: 'open', network_egress_targets: [] };
  const [egress] = await changes(declared, opened);
  assert.deepEqual([...egress.changedFields].sort(), ['network_egress', 'network_egress_targets']);
  const [sandbox] = await changes(declared, { ...declared, sandbox_kind: 'vm' });
  assert.deepEqual(sandbox.changedFields, ['sandbox_kind']);
  const [withdrawn] = await changes(declared, { network_status: 'not_declared' });
  assert.deepEqual([...withdrawn.changedFields].sort(), [...FIELDS].sort());
  assert.equal(withdrawn.after.properties.network_status, 'not_declared');
  assert.deepEqual(await changes(declared, declared), []);
});
