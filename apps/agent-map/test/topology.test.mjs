import { test } from 'node:test';
import assert from 'node:assert/strict';
import { queryDemo } from '../src/demo.mjs';
import {
  LINK_GROUPS,
  egressText,
  isolationText,
  lastChangeText,
  linkRows,
  networkText,
  permissionsChanged,
  topologyElements,
  topologySummary,
} from '../src/topology-model.mjs';

const topology = async () => (await queryDemo('get_agent_topology', {})).data;

test('the demo topology links the three agents through a handoff, a recipient and four shared items', async () => {
  const data = await topology();
  assert.deepEqual(
    data.agents.map(agent => agent.name),
    ['Finance reviewer', 'Release assistant', 'Research assistant'],
  );
  const name = key => data.agents.find(agent => agent.key === key)?.name;
  assert.deepEqual(
    data.links.filter(link => link.toKind === 'agent').map(link => [name(link.from), link.kind, name(link.to)]),
    [
      ['Release assistant', 'can_send_to', 'Finance reviewer'],
      ['Research assistant', 'hands_off_to', 'Finance reviewer'],
    ],
  );
  assert.deepEqual(data.hubs.map(hub => [hub.kind, hub.name, hub.agentCount]).sort(), [
    ['credential', 'Documents service identity', 3],
    ['mcp_server', 'documents', 3],
    ['network_segment', `opaque:${'c'.repeat(64)}`, 2],
    ['resource', 'Quarterly report', 3],
  ]);
  assert.deepEqual(
    data.removedAgents.map(agent => agent.name),
    ['Legacy exporter'],
  );
  assert.equal(data.collection.networkIsolation, 'host_declared');
  const summary = topologySummary(data);
  assert.deepEqual(summary, {
    agents: 3,
    agentLinks: 2,
    sharedHubs: 4,
    sharedIdentity: 3,
    permissionChanges: 3,
    newAgents: 0,
    outsideGuard: 1,
    openEgress: 1,
    networkUnknown: 1,
    removedAgents: 1,
  });
});

test('isolation, egress, network and last change read in plain words', async () => {
  const data = await topology();
  assert.equal(
    networkText(data.agents.find(agent => agent.name === 'Research assistant').isolation.network),
    'Open egress · Container sandbox · shares a segment (1)',
  );
  assert.equal(
    networkText(data.agents.find(agent => agent.name === 'Finance reviewer').isolation.network),
    'Allowlisted egress (1) · VM sandbox · shares a segment (1)',
  );
  assert.equal(
    networkText(data.agents.find(agent => agent.name === 'Release assistant').isolation.network),
    'Not declared by the host',
  );
  const [finance, release, research] = data.agents;
  // The demo's mail capture is partial, so MCP isolation cannot be called dedicated; shared still stands.
  assert.equal(isolationText(research.isolation.cloud_identity), 'Dedicated (1)');
  assert.equal(isolationText(research.isolation.credential), 'Shared: 1 of 1');
  assert.equal(isolationText(finance.isolation.principal), 'Dedicated (1)');
  assert.equal(isolationText({ status: 'dedicated_in_view', total: 2 }), 'Dedicated in your view (2)');
  assert.equal(isolationText({ status: 'not_collected' }), 'Not collected');
  assert.equal(lastChangeText({ status: 'surprise' }), 'Unknown');
  assert.equal(egressText({ status: 'allowlisted' }), 'Allowlisted recipients (?) · 0 sending tools');
  assert.equal(egressText(release.isolation.egress), 'Allowlisted recipients (2) · 1 sending tool');
  assert.equal(egressText(finance.isolation.egress), 'Unknown: a tool does not declare whether it sends');
  assert.equal(lastChangeText(release.lastChange), 'Changed: Permissions (1)');
  assert.ok(permissionsChanged(release.lastChange));
  assert.equal(lastChangeText({ status: 'no_previous_snapshot' }), 'No earlier snapshot to compare');
  assert.equal(lastChangeText({ status: 'unchanged' }), 'No change since the previous snapshot');
  assert.equal(isolationText(undefined), 'Unknown');
});

test('graph elements: boxes per source and environment, fixed positions, and switchable link groups', async () => {
  const data = await topology();
  const elements = topologyElements(data);
  const boxes = elements.filter(element => String(element.classes).includes('box ')).map(box => box.data.label);
  assert.equal(boxes.filter(label => label.startsWith('Source')).length, 1);
  assert.deepEqual(boxes.filter(label => label.startsWith('Environment')).sort(), [
    'Environment · production',
    'Environment · staging',
  ]);
  const leaves = elements.filter(element => element.group === 'nodes' && element.data.kind);
  assert.equal(leaves.length, 7);
  assert.ok(leaves.every(node => Number.isFinite(node.position?.x) && Number.isFinite(node.position?.y)));
  // No two leaves share a position.
  assert.equal(new Set(leaves.map(node => `${node.position.x}:${node.position.y}`)).size, leaves.length);
  // The same answer always draws the same picture.
  assert.deepEqual(topologyElements(data), elements);
  const agentsOnly = topologyElements(data, { groups: ['agents'] });
  assert.equal(agentsOnly.filter(element => element.data.kind === 'hub').length, 0);
  assert.equal(agentsOnly.filter(element => element.group === 'edges').length, 2);
  assert.equal(LINK_GROUPS.length, 5);
  assert.throws(() => topologyElements({ agents: [] }), /topology_invalid/);
});

test('the links table names both ends instead of showing keys', async () => {
  const rows = linkRows(await topology());
  assert.ok(
    rows.some(row => row.from === 'Release assistant' && row.kind === 'May send to' && row.to === 'Finance reviewer'),
  );
  assert.ok(rows.some(row => row.to === 'MCP server · documents'));
  assert.ok(rows.every(row => !row.from.startsWith('[') && !row.to.startsWith('[')));
});

test('an answer without hub links still draws every shared item of a switched-on kind', async () => {
  const data = await topology();
  const reduced = { ...data, links: data.links.filter(link => link.toKind === 'agent'), hubLinksOmitted: true };
  const hubs = topologyElements(reduced).filter(element => element.data.kind === 'hub');
  assert.equal(hubs.length, data.hubs.length);
  assert.ok(hubs.every(hub => Number.isFinite(hub.position?.x)));
  // Switched-off kinds stay hidden.
  const agentsOnly = topologyElements(reduced, { groups: ['agents', 'network'] }).filter(
    element => element.data.kind === 'hub',
  );
  assert.deepEqual(
    agentsOnly.map(hub => hub.classes.split(' ')[1]),
    ['hub-network_segment'],
  );
});
