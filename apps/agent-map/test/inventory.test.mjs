import test from 'node:test';
import assert from 'node:assert/strict';
import {
  defaultSource,
  ownershipLabel,
  pageInfo,
  relationshipLabel,
  shownValue,
  sourceOptionLabel,
} from '../src/inventory-model.mjs';
import { graphElements, OPERATIONS } from '../src/view-model.mjs';

test('legacy missing ownership remains unknown rather than unassigned or an invented owner', () => {
  assert.equal(ownershipLabel({ ownerId: 'legacy-id' }), 'Ownership unknown');
  assert.equal(ownershipLabel({ ownershipStatus: 'unknown' }), 'Ownership unknown');
  assert.equal(ownershipLabel({ ownershipStatus: 'unassigned' }), 'Unassigned owner');
  assert.equal(
    ownershipLabel({ ownershipStatus: 'assigned', ownerId: 'id', ownerName: 'Team <admin>' }),
    'Team <admin>',
  );
});
test('authorized pagination reaches later rows without turning a bounded unknown count into a total', () => {
  assert.deepEqual(pageInfo({ offset: 20, limit: 20, total: 41, truncated: true }, 20), {
    offset: 20,
    limit: 20,
    total: 41,
    previous: 0,
    next: 40,
    label: '21–40 of 41',
    incomplete: false,
  });
  assert.equal(pageInfo({ offset: 40, limit: 20, total: 41 }, 1).next, null);
  const legacy = pageInfo({ truncated: true }, 100);
  assert.equal(legacy.total, null);
  assert.equal(legacy.next, null);
  assert.equal(legacy.incomplete, true);
  assert.equal(pageInfo({ total: 0, limit: 20 }, 0).label, '0 of 0');
});
test('empty collected arrays, unknown scalar values and false values are distinct', () => {
  assert.equal(shownValue([]), 'None recorded');
  assert.equal(shownValue(null), 'Unknown');
  // A boolean is never shown as `true` / `false`.
  assert.equal(shownValue(false), 'No');
  assert.equal(shownValue(true), 'Yes');
  assert.equal(shownValue(0), '0');
  assert.equal(relationshipLabel('G_USES_CREDENTIAL'), 'uses credential reference');
  assert.equal(relationshipLabel('G_RESOURCE_OWNED_BY'), 'resource is owned by');
});
test('source dropdown uses compact Unicode labels without changing full lookup identifiers', () => {
  const source = { id: 'a'.repeat(64), tenantId: '😀'.repeat(40) };
  assert.equal(sourceOptionLabel(source, 0), `${'😀'.repeat(16)}… · 1`);
  assert.equal(source.id.length, 64);
  assert.equal(sourceOptionLabel({ id: 'source', tenantId: 'Company' }, 1), 'Company · 2');
});
test('new read-only query operations and graph reference labels remain explicit', () => {
  for (const operation of ['list_owners', 'list_resources', 'get_resource_access', 'get_agent_inventory'])
    assert.ok(OPERATIONS.includes(operation));
  assert.equal(OPERATIONS.includes('approve'), false);
  const graph = {
    nodes: [
      { id: 'a', entityId: 'a', label: 'GuardAgent', properties: { name: 'Agent' } },
      { id: 'owner', entityId: 'o', label: 'GuardOwner', properties: { name: 'Owner' } },
      {
        id: 'credential',
        entityId: 'c',
        label: 'GuardCredentialReference',
        properties: { name: 'Service reference', credential_id: `opaque:${'a'.repeat(64)}` },
      },
    ],
    edges: [
      { source: 'a', target: 'owner', kind: 'G_OWNED_BY' },
      { source: 'a', target: 'credential', kind: 'G_USES_CREDENTIAL' },
    ],
  };
  const elements = graphElements(graph);
  assert.equal(elements.length, 5);
  assert.equal(elements[2].data.fullLabel, 'Service reference');
});

test('a view starts on the first listed source, and stays on it while the service still lists it', () => {
  const sources = [{ id: 'one' }, { id: 'two' }];
  assert.equal(defaultSource('', []), '');
  assert.equal(defaultSource('', sources), 'one');
  assert.equal(defaultSource('two', sources), 'two');
  assert.equal(defaultSource('gone', sources), 'one');
  assert.equal(defaultSource('one', []), '');
  for (const list of [undefined, null, 'one', [null], [{}]]) assert.equal(defaultSource('one', list), '');
});
