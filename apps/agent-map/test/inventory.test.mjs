import test from 'node:test';
import assert from 'node:assert/strict';
import { ownershipLabel, pageInfo, relationshipLabel, shownValue, sourceOptionLabel } from '../src/inventory-model.mjs';
import { graphElements, OPERATIONS } from '../src/view-model.mjs';
import { queryDemo } from '../src/demo.mjs';

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
  assert.equal(shownValue(false), 'false');
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
test('synthetic directory and structured sections preserve page counts, source, collection gaps and detached data', async () => {
  const first = (await queryDemo('list_agents', { limit: 1 })).data;
  const second = (await queryDemo('list_agents', { limit: 1, offset: 1 })).data;
  assert.equal(first.total, 3);
  assert.equal(first.agents.length, 1);
  assert.equal(first.truncated, true);
  assert.notEqual(first.agents[0].id, second.agents[0].id);
  const agent = first.agents[0];
  for (const section of [
    'overview',
    'deployments',
    'tasks',
    'permissions',
    'resources',
    'connections',
    'credentials',
    'relationships',
    'tools',
    'bindings',
    'identities',
    'policies',
  ]) {
    const result = (
      await queryDemo('get_agent_inventory', { sourceId: agent.sourceId, agentId: agent.id, section, limit: 1 })
    ).data;
    assert.equal(result.section, section);
    assert.ok(result.items.length <= 1);
    assert.equal(result.assessment, 'unknown');
    assert.deepEqual(Object.values(result.collection), [
      'not_collected',
      'not_collected',
      'not_collected',
      'not_collected',
    ]);
    assert.equal(result.policyEvidence.length, section === 'policies' ? 1 : 0);
  }
  const owners = (await queryDemo('list_owners', { limit: 1 })).data;
  assert.equal(owners.total, 2);
  assert.equal(owners.owners[0].sourceId, agent.sourceId);
  const resource = (await queryDemo('list_resources')).data.resources[0];
  const linked = (
    await queryDemo('get_resource_access', {
      sourceId: resource.sourceId,
      resourceId: resource.id,
      offset: 1,
      limit: 1,
    })
  ).data;
  assert.equal(linked.total, 3);
  assert.equal(linked.agents.length, 1);
  linked.resource.displayName = 'mutated';
  assert.equal((await queryDemo('list_resources')).data.resources[0].displayName, 'Quarterly report');
  assert.equal((await queryDemo('list_resources')).data.resourceCoverage, 'host_bound_resources');
  assert.equal((await queryDemo('list_resources', { sourceId: 'other-source' })).data.total, 0);
  assert.equal((await queryDemo('list_owners', { sourceId: 'other-source' })).data.total, 0);
  const relationship = (
    await queryDemo('get_agent_inventory', { sourceId: agent.sourceId, agentId: agent.id, section: 'relationships' })
  ).data.items[0];
  assert.equal(relationship.targetName, agent.name);
  assert.equal(relationship.targetLabel, 'GuardAgent');
});
test('change evidence shows exact ownership before/after without claiming effective permission gain', async () => {
  const data = (await queryDemo('get_changes', { changeKind: 'ownership' })).data;
  assert.equal(data.details.length, 1);
  assert.equal(data.details[0].before.properties.owner_id, 'sam.rivera');
  assert.equal(data.details[0].after.properties.owner_id, 'alex.chen');
  assert.equal(data.details[0].affectedAgents[0].name, 'Research assistant');
  assert.equal(data.policyHistory, 'not_collected');
  assert.equal((await queryDemo('get_changes', { agentId: 'invisible-agent' })).data.details.length, 0);
});
