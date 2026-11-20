// The fleet topology view: get_agent_topology's answer as Cytoscape elements and plain-language
// labels. Pure functions, so the browser view and the tests read the same words.
import { FLAG_NAME } from './boundary-model.mjs';

export const HUB_KIND_NAME = Object.freeze({
  mcp_server: 'MCP server',
  cloud_identity: 'Cloud identity',
  principal: 'Caller principal',
  credential: 'Credential',
  resource: 'Resource',
  network_segment: 'Network segment',
});
export const LINK_KIND_NAME = Object.freeze({
  delegates_to: 'Delegates to',
  hands_off_to: 'Hands off to',
  depends_on: 'Depends on',
  can_send_to: 'May send to',
  uses_mcp_server: 'Uses MCP server',
  uses_cloud_identity: 'Uses cloud identity',
  uses_principal: 'Calls as',
  uses_credential: 'Uses credential',
  uses_resource: 'Granted resource',
  uses_network_segment: 'On network segment',
});
/** The link groups a reader can switch on and off. */
export const LINK_GROUPS = Object.freeze([
  ['agents', 'Agent to agent', ['delegates_to', 'hands_off_to', 'depends_on', 'can_send_to']],
  ['mcp_server', 'Shared MCP servers', ['uses_mcp_server']],
  ['identity', 'Shared identities and credentials', ['uses_cloud_identity', 'uses_principal', 'uses_credential']],
  ['resource', 'Shared resources', ['uses_resource']],
  ['network', 'Shared network segments', ['uses_network_segment']],
]);
const ISOLATION_NAME = Object.freeze({
  dedicated: 'Dedicated',
  dedicated_in_view: 'Dedicated in your view',
  shared: 'Shared',
  none_declared: 'None declared',
  not_collected: 'Not collected',
  unknown: 'Unknown',
});
export const isolationLabel = value => ISOLATION_NAME[value?.status] ?? 'Unknown';
export function isolationText(value) {
  if (!value || typeof value !== 'object') return 'Unknown';
  if (value.status === 'shared') return `Shared: ${value.shared} of ${value.total}`;
  if (value.status === 'dedicated') return `Dedicated (${value.total})`;
  if (value.status === 'dedicated_in_view') return `Dedicated in your view (${value.total})`;
  if (value.status === 'none_declared') return 'None declared';
  if (value.status === 'not_collected') return 'Not collected';
  return 'Unknown: collection incomplete';
}
const EGRESS_NAME = Object.freeze({
  allowlisted: 'Allowlisted recipients',
  refused: 'Every external send refused (no recipient listed)',
  none_declared: 'No tool declares sending out',
});
export function egressText(egress) {
  if (!egress || typeof egress !== 'object') return 'Unknown';
  if (egress.status === 'unknown')
    return egress.reason === 'no_tools'
      ? 'Unknown: no tool is recorded for this agent'
      : egress.reason === 'recipients_not_recorded'
        ? 'Unknown: allowed recipients are not recorded'
        : 'Unknown: a tool does not declare whether it sends';
  const base = EGRESS_NAME[egress.status] ?? 'Unknown';
  const tools = Array.isArray(egress.sendingTools) ? egress.sendingTools.length : 0;
  return egress.status === 'allowlisted'
    ? `${base} (${egress.recipientsTotal ?? '?'}) · ${tools} sending tool${tools === 1 ? '' : 's'}`
    : base;
}
const DIRECT_NAME = Object.freeze({
  found: 'Paths around the guard declared',
  none_declared: 'None declared (host claim)',
  unknown: 'Unknown: the host has not said',
});
export const directAccessText = egress => DIRECT_NAME[egress?.directAccess] ?? 'Unknown';
const CATEGORY_NAME = Object.freeze({
  permissions: 'Permissions',
  ownership: 'Ownership',
  bindings: 'Bindings and connections',
  outside_guard: 'Outside-guard paths',
  inventory: 'Other details',
});
export const changeCategoryName = value => CATEGORY_NAME[value] ?? 'Other details';
/** The last change in one line: what kind, and between which captures. */
export function lastChangeText(change) {
  if (!change || typeof change !== 'object') return 'Unknown';
  if (change.status === 'no_previous_snapshot') return 'No earlier snapshot to compare';
  if (change.status === 'added') return 'New since the previous snapshot';
  if (change.status === 'unchanged') return 'No change since the previous snapshot';
  if (change.status !== 'changed') return 'Unknown';
  const parts = (change.categories ?? []).map(
    category => `${changeCategoryName(category)} (${change.counts?.[category] ?? 0})`,
  );
  return `Changed: ${parts.join(', ')}`;
}
/** Declared permissions changed between the two snapshots; a new agent counts separately. */
export const permissionsChanged = change =>
  change?.status === 'changed' && (change.categories ?? []).includes('permissions');

const FLAG_CLASS = Object.freeze({ exposed: 'flag-exposed', mitigated: 'flag-mitigated', unknown: 'flag-unknown' });
const short = (value, size = 28) => {
  const text = String(value ?? '');
  return [...text].length > size ? `${[...text].slice(0, size - 1).join('')}…` : text;
};
/** Where an agent sits: its source, then its environments (several are one group of their own). */
export function agentGroup(agent) {
  const environments = Array.isArray(agent.environments) && agent.environments.length ? agent.environments : null;
  return environments ? environments.join(' + ') : 'No environment declared';
}
/**
 * Cytoscape elements: one box per source and, inside it, one per environment group; agents in
 * those boxes; shared hubs inside their source; links between them. `groups` keeps only links
 * whose kind belongs to a switched-on group.
 */
export function topologyElements(data, { groups = LINK_GROUPS.map(([id]) => id), sourceNames = {} } = {}) {
  if (!data || !Array.isArray(data.agents) || !Array.isArray(data.hubs) || !Array.isArray(data.links))
    throw new Error('topology_invalid');
  const kinds = new Set(LINK_GROUPS.filter(([id]) => groups.includes(id)).flatMap(([, , items]) => items));
  const links = data.links.filter(link => kinds.has(link.kind));
  const elements = [];
  const boxes = new Set();
  const box = (id, label, parent, kind) => {
    if (boxes.has(id)) return;
    boxes.add(id);
    elements.push({ group: 'nodes', data: { id, label, ...(parent ? { parent } : {}) }, classes: `box box-${kind}` });
  };
  const sourceBox = sourceId => {
    const id = `source:${sourceId}`;
    box(id, `Source · ${sourceNames[sourceId] ?? short(sourceId, 16)}`, null, 'source');
    return id;
  };
  for (const agent of data.agents) {
    const parent = sourceBox(agent.sourceId);
    const group = `group:${agent.sourceId}:${agentGroup(agent)}`;
    box(group, `Environment · ${agentGroup(agent)}`, parent, 'environment');
    const flag = FLAG_CLASS[agent.dangerousThree];
    const changed = permissionsChanged(agent.lastChange);
    elements.push({
      group: 'nodes',
      data: {
        id: agent.key,
        parent: group,
        kind: 'agent',
        label: `${short(agent.name ?? agent.agentId ?? 'Unnamed agent')}${flag ? `\n${FLAG_NAME}: ${agent.dangerousThree}` : ''}`,
      },
      classes: ['agent', flag, changed ? 'changed' : ''].filter(Boolean).join(' '),
    });
  }
  const used = new Set(links.map(link => link.to));
  // Which kinds of shared item the switched-on groups show, for an answer without hub links.
  const hubKinds = new Set([...kinds].filter(kind => kind.startsWith('uses_')).map(kind => kind.slice(5)));
  for (const hub of data.hubs) {
    // A hub whose links are all switched off is not drawn. An answer that left the links to
    // shared items out still draws every hub of a switched-on kind, unlinked.
    if (data.hubLinksOmitted ? !hubKinds.has(hub.kind) : !used.has(hub.id)) continue;
    elements.push({
      group: 'nodes',
      data: {
        id: hub.id,
        // A cloud identity used from several sources sits below them all, in no source box.
        ...(hub.sourceId ? { parent: sourceBox(hub.sourceId) } : {}),
        kind: 'hub',
        label: `${HUB_KIND_NAME[hub.kind] ?? 'Shared'} · ${short(hub.name, 24)}\n${hub.agentCount} agents${
          hub.agentsNotDrawn ? ` (${hub.agentsNotDrawn} filtered out)` : ''
        }`,
      },
      classes: `hub hub-${hub.kind}${hub.sensitivity === 'confidential' || hub.sensitivity === 'restricted' ? ' sensitive' : ''}`,
    });
  }
  placeTopology(elements);
  const ids = new Set(elements.map(element => element.data.id));
  links.forEach((link, index) => {
    if (!ids.has(link.from) || !ids.has(link.to)) return;
    elements.push({
      group: 'edges',
      data: {
        id: `link:${index}`,
        source: link.from,
        target: link.to,
        label: LINK_KIND_NAME[link.kind] ?? link.kind,
      },
      classes: `${link.toKind === 'agent' ? 'agent-link' : 'hub-link'} link-${link.kind}${link.directed ? ' directed' : ''}`,
    });
  });
  return elements;
}
// Layout grid, in graph pixels: an agent cell, a hub cell and the gaps between boxes.
const AGENT_CELL = { w: 230, h: 150 },
  HUB_CELL = { w: 200, h: 120 },
  BOX_GAP = 90,
  SOURCE_GAP = 170;
/**
 * A fixed layout, so the same answer always draws the same picture: sources stacked, each
 * source's environment boxes side by side with their agents in a small grid, and the items the
 * source's agents share in rows below them. Sets `position` on every leaf node.
 */
export function placeTopology(elements) {
  const nodes = elements.filter(element => element.group === 'nodes');
  const parentOf = new Map(nodes.map(node => [node.data.id, node.data.parent ?? null]));
  const sources = nodes.filter(node => node.classes.includes('box-source'));
  let top = 0;
  for (const source of sources) {
    const environments = nodes.filter(
      node => node.data.parent === source.data.id && node.classes.includes('box-environment'),
    );
    let left = 0,
      height = 0;
    for (const environment of environments) {
      const agents = nodes.filter(node => parentOf.get(node.data.id) === environment.data.id);
      const columns = Math.max(1, Math.ceil(Math.sqrt(agents.length)));
      agents.forEach((agent, index) => {
        agent.position = {
          x: left + (index % columns) * AGENT_CELL.w,
          y: top + Math.floor(index / columns) * AGENT_CELL.h,
        };
      });
      left += columns * AGENT_CELL.w + BOX_GAP;
      height = Math.max(height, Math.ceil(agents.length / columns) * AGENT_CELL.h);
    }
    const width = Math.max(AGENT_CELL.w, left - BOX_GAP);
    const hubs = nodes.filter(node => node.data.parent === source.data.id && node.data.kind === 'hub');
    const perRow = Math.max(1, Math.floor(width / HUB_CELL.w));
    const hubTop = top + height + 70;
    hubs.forEach((hub, index) => {
      const row = Math.floor(index / perRow),
        inRow = Math.min(perRow, hubs.length - row * perRow);
      const start = (width - AGENT_CELL.w) / 2 - ((inRow - 1) * HUB_CELL.w) / 2;
      hub.position = { x: start + (index % perRow) * HUB_CELL.w, y: hubTop + row * HUB_CELL.h };
    });
    top = hubTop + Math.ceil(hubs.length / perRow) * HUB_CELL.h + SOURCE_GAP;
  }
  // Items shared across sources: one row under every source.
  const across = nodes.filter(node => node.data.kind === 'hub' && !node.data.parent);
  across.forEach((hub, index) => {
    hub.position = { x: index * HUB_CELL.w, y: top };
  });
  return elements;
}
/** Readable rows for the links table: names in place of keys. */
export function linkRows(data) {
  const agents = new Map((data?.agents ?? []).map(agent => [agent.key, agent]));
  const hubs = new Map((data?.hubs ?? []).map(hub => [hub.id, hub]));
  const name = key =>
    agents.has(key)
      ? (agents.get(key).name ?? agents.get(key).agentId)
      : hubs.has(key)
        ? `${HUB_KIND_NAME[hubs.get(key).kind]} · ${hubs.get(key).name}`
        : key;
  return (data?.links ?? []).map((link, index) => ({
    id: `link:${index}`,
    kind: LINK_KIND_NAME[link.kind] ?? link.kind,
    from: name(link.from),
    to: name(link.to),
    via: (link.via ?? []).map(item => item.name ?? item.entityId).join(', '),
    viaTotal: link.viaTotal ?? null,
    raw: link,
  }));
}
/** Counts for the summary strip above the graph. */
export function topologySummary(data) {
  const agents = data?.agents ?? [];
  return {
    agents: agents.length,
    agentLinks: data?.agentLinksTotal ?? (data?.links ?? []).filter(link => link.toKind === 'agent').length,
    sharedHubs: data?.hubsTotal ?? (data?.hubs ?? []).length,
    sharedIdentity: agents.filter(agent =>
      ['cloud_identity', 'principal', 'credential'].some(kind => agent.isolation?.[kind]?.status === 'shared'),
    ).length,
    permissionChanges: agents.filter(agent => permissionsChanged(agent.lastChange)).length,
    newAgents: agents.filter(agent => agent.lastChange?.status === 'added').length,
    outsideGuard: agents.filter(agent => agent.isolation?.egress?.directAccess === 'found').length,
    openEgress: agents.filter(agent => agent.isolation?.network?.egress === 'open').length,
    networkUnknown: agents.filter(agent => !['declared'].includes(agent.isolation?.network?.status)).length,
    removedAgents: data?.removedAgentsTotal ?? 0,
  };
}

const NETWORK_STATUS = Object.freeze({
  declared: 'Declared',
  partial: 'Partly declared',
  not_declared: 'Not declared by the host',
  unknown: 'Unknown: not declared for every deployment',
});
const EGRESS_POLICY = Object.freeze({
  none: 'No egress',
  allowlist: 'Allowlisted egress',
  open: 'Open egress',
  unknown: 'Egress unknown',
});
const SANDBOX = Object.freeze({
  vm: 'VM sandbox',
  container: 'Container sandbox',
  process: 'Process sandbox',
  none: 'No sandbox',
  unknown: 'Sandbox unknown',
});
/** The host-declared network isolation of one agent in one line. */
export function networkText(network) {
  if (!network || typeof network !== 'object') return 'Unknown';
  if (network.status === 'not_declared' || network.status === 'unknown' || !network.segment)
    return NETWORK_STATUS[network.status] ?? 'Unknown';
  const segment =
    network.segment.status === 'shared'
      ? `shares a segment (${network.segment.shared})`
      : network.segment.status === 'none_declared'
        ? 'no shared segment'
        : network.segment.status === 'unknown'
          ? 'segment unknown'
          : network.segment.status === 'dedicated_in_view'
            ? 'own segment in your view'
            : 'own segment';
  const egress = EGRESS_POLICY[network.egress] ?? 'Egress unknown';
  const targets = network.egress === 'allowlist' ? ` (${network.egressTargetsTotal ?? 0})` : '';
  const prefix = network.status === 'partial' ? 'Partly declared: ' : '';
  return `${prefix}${egress}${targets} · ${SANDBOX[network.sandbox] ?? 'Sandbox unknown'} · ${segment}`;
}
