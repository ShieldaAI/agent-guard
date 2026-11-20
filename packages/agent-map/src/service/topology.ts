import type { Json } from '@shieldaai/agent-guard';
import { canonicalJson } from '@shieldaai/agent-guard/internal';
import { safeProperties } from '../projection-fields.js';
import {
  MapQueryError,
  type JsonObject,
  type MapNode,
  type MapProjection,
  type MapSource,
  type ReadScope,
} from '../types.js';
import { changeCategories, IGNORE_DIFF, nodeState } from './changes.js';
import { agentFlags } from './flags.js';
import { agentSortKey, compare, sortedBy } from './ordering.js';
import { agentSummary, changeSummary, deployments, focus, receipt } from './summaries.js';
import { connected, QueryWork, string, strings } from './work.js';

/** The node kinds that more than one agent can hold, drawn as a shared hub between them. */
export const TOPOLOGY_HUB_KINDS = [
  'mcp_server',
  'cloud_identity',
  'principal',
  'credential',
  'resource',
  'network_segment',
] as const;
export type TopologyHubKind = (typeof TOPOLOGY_HUB_KINDS)[number];
/** Agent-to-agent relationships the graph declares directly. */
export const TOPOLOGY_LINK_KINDS = ['delegates_to', 'hands_off_to', 'depends_on', 'can_send_to'] as const;
export type TopologyLinkKind = (typeof TOPOLOGY_LINK_KINDS)[number];

const HUB_LABEL: Readonly<Partial<Record<MapNode['label'], TopologyHubKind>>> = Object.freeze({
  GuardDeployment: 'network_segment',
  GuardTask: 'principal',
  GuardMcpConnection: 'mcp_server',
  GuardExternalIdentity: 'cloud_identity',
  GuardCredentialReference: 'credential',
  GuardResourceBinding: 'resource',
});
/** At most this many shared hubs, links and change items are returned; the rest is counted. */
export const TOPOLOGY_LIMITS = Object.freeze({
  hubs: 1000,
  agentLinks: 2000,
  hubLinks: 2000,
  via: 5,
  changeItems: 5,
  recipients: 10,
});
/** The coverage component each layer comes from: an incomplete one cannot show a layer is dedicated or empty. */
const LAYER_COVERAGE: Readonly<Record<TopologyHubKind, string>> = Object.freeze({
  mcp_server: 'mcp',
  cloud_identity: 'manifest',
  principal: 'tasks',
  credential: 'manifest',
  resource: 'manifest',
  network_segment: 'manifest',
});
/** The isolation layers judged by `layerStatus`; the network has its own summary. */
const LAYER_KINDS = TOPOLOGY_HUB_KINDS.filter(kind => kind !== 'network_segment');
const EGRESS_RANK = Object.freeze({ none: 0, allowlist: 1, open: 2 }) as Readonly<Record<string, number>>;
const SANDBOX_RANK = Object.freeze({ vm: 3, container: 2, process: 1, none: 0 }) as Readonly<Record<string, number>>;
/** At most this many removed agents are listed per answer; the rest is counted. */
const REMOVED_LIMIT = 100;

export const TOPOLOGY_LIMITATIONS = Object.freeze([
  'Built from declared manifests and executor inventory: a link or a shared hub is evidence that two agents could exchange data, not that they did.',
  'Only agents you may see are compared. For a team reader, dedicated_in_view means no other agent in your view holds the item; an agent outside your view may.',
  'A layer whose collection is incomplete reads unknown or not_collected, never dedicated or none_declared.',
  'Network isolation is what hosts declare in manifest v4 (segment, egress policy, sandbox); it is not observed on the network, and older manifests leave it unknown.',
  'Links and caller principals use live tasks only: a revoked task, or one past its deadline at capture, links nothing.',
  'The last change compares the two retained snapshots of a source. Changes between them, and their exact time, are not recorded.',
]);

interface AgentEntry {
  readonly source: MapSource;
  readonly node: MapNode;
  readonly nodes: readonly MapNode[];
}
/**
 * Hub key. MCP connections to the same server over the same transport share one hub even when
 * declared separately; the executor tells servers apart by both. Hubs never cross sources: two
 * sources are two executors, even with equal names.
 */
function hubId(source: MapSource, node: MapNode, kind: TopologyHubKind): string {
  // Tasks of two agents that call as one principal share that caller identity.
  if (kind === 'principal') return JSON.stringify([source.id, kind, string(node, 'principal_id')]);
  // Deployments the host put on one network segment can reach each other on the network.
  if (kind === 'network_segment') return JSON.stringify([source.id, kind, string(node, 'network_segment')]);
  // An IAM ARN names one identity in every source, so it is the one hub that can join sources.
  const arn = kind === 'cloud_identity' ? string(node, 'arn') : null;
  if (arn !== null) return JSON.stringify([null, kind, arn]);
  const server = kind === 'mcp_server' ? string(node, 'server_id') : null;
  return JSON.stringify([
    source.id,
    kind,
    server === null ? node.entityId : `server:${server}`,
    ...(server === null ? [] : [string(node, 'transport_ref')]),
  ]);
}
/** Nodes that do not stand for a hub of their kind: dead tasks, deployments without a declared segment. */
function holds(node: MapNode, kind: TopologyHubKind, projection: MapProjection): boolean {
  if (kind === 'principal') return string(node, 'principal_id') !== null && liveTask(node, projection);
  if (kind === 'network_segment')
    return string(node, 'network_status') === 'declared' && string(node, 'network_segment') !== null;
  return true;
}
/** Not revoked and not past its deadline at capture, as the boundary flags judge a task. */
function liveTask(node: MapNode, projection: MapProjection): boolean {
  const deadline = node.properties.deadline;
  return (
    node.properties.revoked !== true &&
    !(typeof deadline === 'number' && deadline <= Date.parse(projection.generatedAt))
  );
}
function hubName(node: MapNode, kind: TopologyHubKind): string {
  if (kind === 'network_segment') return string(node, 'network_segment')!;
  if (kind === 'mcp_server') return string(node, 'server_id') ?? string(node, 'connection_id') ?? node.entityId;
  if (kind === 'cloud_identity') return string(node, 'arn') ?? node.entityId;
  if (kind === 'principal') return string(node, 'principal_id')!;
  if (kind === 'credential') return string(node, 'name') ?? string(node, 'credential_id') ?? node.entityId;
  return string(node, 'display_name') ?? string(node, 'resource_ref') ?? string(node, 'binding_id') ?? node.entityId;
}
/**
 * Shared is positive evidence and always stands. Dedicated and none_declared need the layer's
 * collection to be complete; a team reader sees dedicated only within its own view.
 */
function layerStatus(total: number, shared: number, coverage: string | undefined, allTeams: boolean): string {
  if (shared > 0) return 'shared';
  // Items exist but the layer's collection is not reported: unknown, not "not collected".
  if (coverage === undefined || coverage === 'not_collected') return total > 0 ? 'unknown' : 'not_collected';
  if (coverage !== 'complete') return 'unknown';
  return total === 0 ? 'none_declared' : allTeams ? 'dedicated' : 'dedicated_in_view';
}

/**
 * Per-agent net change between the previous and current snapshot: the agent's own neighborhood
 * in each, compared node by node with the same rules as get_changes.
 */
function lastChange(entry: AgentEntry, work: QueryWork, previousAgents: ReadonlyMap<string, MapNode>): JsonObject {
  const { source } = entry;
  const previous = source.previous;
  const window = {
    from: previous ? previous.generatedAt : null,
    to: source.current.generatedAt,
  };
  if (!previous) return { status: 'no_previous_snapshot', categories: [], counts: {}, items: [], total: 0, ...window };
  const before = previousAgents.get(entry.node.entityId);
  if (!before) return { status: 'added', categories: [], counts: {}, items: [], total: 0, ...window };
  // Which nodes to compare: the agent's neighborhood in either snapshot. How each one changed is
  // judged against the whole other snapshot, as get_changes does, so a node that is only newly
  // reachable (another agent's binding, a shared owner) is not reported as added.
  const ids = new Set([
    ...focus(previous, before, work).nodes.map(node => node.entityId),
    ...entry.nodes.map(node => node.entityId),
  ]);
  const oldIndex = work.index(previous),
    newIndex = work.index(source.current);
  const byEntity = (projection: MapProjection, index: typeof oldIndex): Map<string, MapNode> =>
    work.cached(projection, 'topology:entities', () => {
      work.step(projection.nodes.length);
      return new Map([...index.nodes.values()].map(node => [node.entityId, node]));
    });
  const old = byEntity(previous, oldIndex),
    now = byEntity(source.current, newIndex);
  const counts: Record<string, number> = Object.create(null);
  const items: JsonObject[] = [];
  let total = 0;
  for (const id of [...ids].sort(compare)) {
    work.step();
    const a = old.get(id),
      b = now.get(id);
    if (a && b && nodeState(a, previous, work) === nodeState(b, source.current, work)) continue;
    const display = (b ?? a)!;
    const fields =
      a && b
        ? [...new Set([...Object.keys(safeProperties(a)), ...Object.keys(safeProperties(b))])].filter(
            key =>
              !IGNORE_DIFF.has(key) &&
              canonicalJson((safeProperties(a)[key] ?? null) as Json) !==
                canonicalJson((safeProperties(b)[key] ?? null) as Json),
          )
        : [];
    const edgeKinds = changedEdgeKinds(a, previous, b, source.current, work);
    const categories = changeCategories(display.label, fields, edgeKinds);
    for (const category of categories) counts[category] = (counts[category] ?? 0) + 1;
    total++;
    if (items.length < TOPOLOGY_LIMITS.changeItems)
      items.push({ ...changeSummary(display), kind: !a ? 'added' : !b ? 'removed' : 'changed', categories });
  }
  return {
    status: total ? 'changed' : 'unchanged',
    categories: Object.keys(counts).sort(compare),
    counts,
    items,
    total,
    ...window,
  };
}
/** Outgoing edge kinds added or removed; an added or removed node counts all of its own. */
function changedEdgeKinds(
  a: MapNode | undefined,
  before: MapProjection,
  b: MapNode | undefined,
  after: MapProjection,
  work: QueryWork,
): string[] {
  const edges = (node: MapNode | undefined, projection: MapProjection): Set<string> => {
    if (!node) return new Set();
    const index = work.index(projection);
    const result = new Set<string>();
    for (const [kind, targets] of index.outgoing.get(node.id)?.entries() ?? []) {
      work.step(targets.length);
      for (const target of targets) result.add(JSON.stringify([kind, index.nodes.get(target)?.entityId ?? null]));
    }
    return result;
  };
  const old = edges(a, before),
    now = edges(b, after);
  return [
    ...new Set(
      [...[...old].filter(edge => !now.has(edge)), ...[...now].filter(edge => !old.has(edge))].map(
        edge => JSON.parse(edge)[0] as string,
      ),
    ),
  ];
}

/** What crosses the agent's boundary: sending tools, recipients and declared paths around the guard. */
function egress(entry: AgentEntry, work: QueryWork): JsonObject {
  const projection = entry.source.current;
  const tools = entry.nodes.filter(node => node.label === 'GuardTool');
  const sending = tools.filter(node => node.properties.sends_external === true);
  const undeclared = tools.filter(node => typeof node.properties.sends_external !== 'boolean');
  // Live tasks only: not revoked and not past their deadline at capture. The executor also
  // intersects the list with every delegation ancestor's, so this union is an upper bound of
  // where a send may go, never a narrower claim.
  const live = entry.nodes.filter(node => node.label === 'GuardTask' && liveTask(node, projection));
  // An older inventory may not record the list; then no send can be called refused.
  const unrecorded = live.some(node => !Array.isArray(node.properties.allowed_recipients));
  const recipients = [...new Set(live.flatMap(node => strings(node, 'allowed_recipients')))].sort(compare);
  const destinations = [
    ...new Set(
      entry.nodes
        .filter(node => node.label === 'GuardResourceBinding')
        .flatMap(node => strings(node, 'approved_destinations')),
    ),
  ].sort(compare);
  const deployed = deployments(projection, entry.node, work);
  const paths = connected(projection, new Set(deployed.map(node => node.id)), 'G_DIRECT_ACCESS_FOR', work, true);
  const directAccess = paths.length
    ? 'found'
    : deployed.length && deployed.every(node => string(node, 'direct_access_status') === 'none_declared')
      ? 'none_declared'
      : 'unknown';
  return {
    // The executor refuses an external send to a recipient no task lists, so the list is the
    // allowlist for sends through the guard (empty: every external send is refused). Paths
    // around the guard are not limited by it.
    status: sending.length
      ? recipients.length
        ? 'allowlisted'
        : unrecorded
          ? 'unknown'
          : 'refused'
      : undeclared.length || !tools.length
        ? 'unknown'
        : 'none_declared',
    ...(!tools.length
      ? { reason: 'no_tools' }
      : sending.length && unrecorded
        ? // Some live task has no recorded list: the allowlist shown may be incomplete.
          { reason: recipients.length ? 'recipients_partly_recorded' : 'recipients_not_recorded' }
        : {}),
    sendingTools: sending
      .map(node => string(node, 'name'))
      .filter((name): name is string => name !== null)
      .sort(compare),
    sendingToolsWithoutApproval: sending.filter(node => node.properties.requires_approval !== true).length,
    toolsWithUndeclaredSending: undeclared.length,
    recipients: recipients.slice(0, TOPOLOGY_LIMITS.recipients),
    recipientsTotal: recipients.length,
    approvedDestinations: destinations.slice(0, TOPOLOGY_LIMITS.recipients),
    approvedDestinationsTotal: destinations.length,
    directAccess,
    directAccessPaths: paths.length,
  };
}

/**
 * What the host declared about the agent's network (manifest v4): the segments its deployments
 * sit on, the widest egress policy and the weakest sandbox among them. Positive evidence (a
 * shared segment, open egress, no sandbox) stands even when some deployments declared nothing.
 */
function network(
  entry: AgentEntry,
  work: QueryWork,
  sharedKeys: ReadonlySet<string>,
  allTeams: boolean,
  sourceDeclared: boolean,
): JsonObject {
  const deployed = deployments(entry.source.current, entry.node, work);
  const declared = deployed.filter(node => string(node, 'network_status') === 'declared');
  const notDeclared = deployed.filter(node => string(node, 'network_status') === 'not_declared');
  const status = !deployed.length
    ? 'unknown'
    : declared.length === deployed.length
      ? 'declared'
      : declared.length
        ? 'partial'
        : notDeclared.length === deployed.length
          ? 'not_declared'
          : 'unknown';
  // A declared value outside the closed vocabulary (a custom store) makes that part unknown.
  const unranked = (key: string, ranks: Readonly<Record<string, number>>): boolean =>
    declared.some(node => {
      const value = string(node, key);
      return value === null || !Object.hasOwn(ranks, value);
    });
  const complete = status === 'declared';
  const segments = [
    ...new Set(
      declared
        .filter(node => string(node, 'network_segment') !== null)
        .map(node => hubId(entry.source, node, 'network_segment')),
    ),
  ];
  const sharedSegments = segments.filter(hub => sharedKeys.has(hub)).length;
  const egressValues = declared
    .map(node => string(node, 'network_egress'))
    .filter(value => value !== null && Object.hasOwn(EGRESS_RANK, value)) as string[];
  const widest = egressValues.sort((a, b) => EGRESS_RANK[b]! - EGRESS_RANK[a]!)[0];
  const sandboxes = declared
    .map(node => string(node, 'sandbox_kind'))
    .filter(value => value !== null && Object.hasOwn(SANDBOX_RANK, value)) as string[];
  const weakest = sandboxes.sort((a, b) => SANDBOX_RANK[a]! - SANDBOX_RANK[b]!)[0];
  const targets = [...new Set(declared.flatMap(node => strings(node, 'network_egress_targets')))].sort(compare);
  return {
    status,
    deploymentsDeclared: declared.length,
    deployments: deployed.length,
    segment: {
      status:
        sharedSegments > 0
          ? 'shared'
          : // Dedicated needs every deployment of the source declared: an undeclared one may sit on it.
            !complete || !sourceDeclared
            ? 'unknown'
            : segments.length === 0
              ? 'none_declared'
              : allTeams
                ? 'dedicated'
                : 'dedicated_in_view',
      total: segments.length,
      shared: sharedSegments,
    },
    // The widest policy wins: one open deployment makes the agent open.
    egress:
      widest === 'open' ? 'open' : complete && widest && !unranked('network_egress', EGRESS_RANK) ? widest : 'unknown',
    egressTargets: targets.slice(0, TOPOLOGY_LIMITS.recipients),
    egressTargetsTotal: targets.length,
    // The weakest boundary wins: one deployment without a sandbox makes the agent unsandboxed.
    sandbox:
      weakest === 'none'
        ? 'none'
        : complete && weakest && !unranked('sandbox_kind', SANDBOX_RANK)
          ? weakest
          : 'unknown',
    evidenceKind: 'declared',
  };
}

export interface TopologyFilters {
  readonly sourceId?: string;
  readonly teamId?: string;
  readonly environment?: string;
}
/**
 * The fleet as one graph: each visible agent with its isolation summary and last change, the
 * nodes two or more of them share (hubs), and the agent-to-agent relationships declared between
 * them. Everything comes from the reader's own scoped view.
 */
export function agentTopology(
  sources: readonly MapSource[],
  filters: TopologyFilters,
  scope: ReadScope,
  work: QueryWork,
  maxBytes: number,
): JsonObject {
  // Every agent in the reader's view takes part in sharing; the filters only choose which are drawn,
  // so filtering never turns a shared item into a dedicated one.
  const entries: AgentEntry[] = [];
  const drawn = new Set<string>();
  const summaries = new Map<string, JsonObject>();
  for (const source of sources) {
    work.step(source.current.nodes.length);
    for (const node of source.current.nodes) {
      if (node.label !== 'GuardAgent') continue;
      const summary = agentSummary(source, source.current, node, work);
      const key = agentKey(source, node);
      entries.push({ source, node, nodes: focus(source.current, node, work).nodes });
      summaries.set(key, summary);
      if (
        (filters.sourceId === undefined || source.id === filters.sourceId) &&
        (filters.teamId === undefined || summary.teamId === filters.teamId) &&
        (filters.environment === undefined || (summary.environments as readonly string[]).includes(filters.environment))
      )
        drawn.add(key);
    }
  }
  const shown = entries.filter(entry => drawn.has(agentKey(entry.source, entry.node)));
  // Which agents hold each node; a node held by two or more becomes a hub or a link end.
  const holders = new Map<string, Set<string>>();
  const hubNodes = new Map<string, { kind: TopologyHubKind; node: MapNode; source: MapSource }>();
  const taskOwners = new Map<string, string>();
  const bindingOwners = new Map<string, Set<string>>();
  const principalOwners = new Map<string, Set<string>>();
  for (const entry of entries) {
    const key = agentKey(entry.source, entry.node);
    for (const node of entry.nodes) {
      work.step();
      const scoped = `${entry.source.id}\u0000${node.id}`;
      if (node.label === 'GuardTask' && liveTask(node, entry.source.current)) {
        taskOwners.set(scoped, key);
        const principal = string(node, 'principal_id');
        const caller = `${entry.source.id}\u0000${principal}`;
        if (principal !== null) principalOwners.set(caller, (principalOwners.get(caller) ?? new Set()).add(key));
      }
      if (node.label === 'GuardResourceBinding')
        bindingOwners.set(scoped, (bindingOwners.get(scoped) ?? new Set()).add(key));
      const kind = HUB_LABEL[node.label];
      if (!kind || !holds(node, kind, entry.source.current)) continue;
      const hub = hubId(entry.source, node, kind);
      if (!hubNodes.has(hub)) hubNodes.set(hub, { kind, node, source: entry.source });
      holders.set(hub, (holders.get(hub) ?? new Set()).add(key));
    }
  }
  const shared = [...holders].filter(([, agents]) => agents.size > 1);
  const sharedKeys = new Set(shared.map(([hub]) => hub));
  // A shared item is drawn when at least one of its holders is drawn.
  const drawnHubs = shared
    .filter(([, agents]) => [...agents].some(agent => drawn.has(agent)))
    .sort(([a], [b]) => compare(a, b));
  const hubs: JsonObject[] = [];
  const hubLinks: JsonObject[] = [];
  let hubLinksTotal = 0;
  for (const [hub, agents] of drawnHubs) {
    const { kind, node, source } = hubNodes.get(hub)!;
    const drawnHolders = [...agents].filter(agent => drawn.has(agent)).sort(compare);
    // Past the hub cap, links are still counted so linksTotal and linksTruncated stay true.
    if (hubs.length >= TOPOLOGY_LIMITS.hubs) {
      work.step(drawnHolders.length);
      hubLinksTotal += drawnHolders.length;
      continue;
    }
    // A cloud identity used from two sources sits outside both source boxes.
    const holderSources = new Set([...agents].map(agent => JSON.parse(agent)[0] as string));
    hubs.push({
      id: hub,
      kind,
      sourceId: holderSources.size === 1 ? source.id : null,
      ...(holderSources.size > 1 ? { sourceIds: [...holderSources].sort(compare) } : {}),
      // A principal is a caller id and a segment a declared name: neither is one node.
      entityId: kind === 'principal' || kind === 'network_segment' ? null : node.entityId,
      name: hubName(node, kind),
      agentCount: agents.size,
      // Holders the filters leave out; they still make the item shared.
      agentsNotDrawn: agents.size - drawnHolders.length,
      ...(kind === 'resource' ? { sensitivity: string(node, 'sensitivity') ?? 'unknown' } : {}),
      evidenceKind: 'declared',
    });
    for (const agent of drawnHolders) {
      hubLinksTotal++;
      if (hubLinks.length < TOPOLOGY_LIMITS.hubLinks)
        hubLinks.push({ kind: `uses_${kind}`, from: agent, to: hub, toKind: 'hub', directed: false });
    }
  }
  const hubsTotal = drawnHubs.length;
  // Agent-to-agent links, deduplicated by kind and direction, with the evidence behind each.
  const direct = new Map<
    string,
    { kind: TopologyLinkKind; from: string; to: string; via: JsonObject[]; total: number }
  >();
  const addLink = (kind: TopologyLinkKind, from: string, to: string, via: JsonObject): void => {
    if (from === to) return;
    const id = JSON.stringify([kind, from, to]);
    const link = direct.get(id) ?? { kind, from, to, via: [], total: 0 };
    link.total++;
    if (link.via.length < TOPOLOGY_LIMITS.via) link.via.push(via);
    direct.set(id, link);
  };
  // Delegation or handoff parents that are not a drawn agent's task: outside the reader's view,
  // undeclared, or left out by the filters. Counted, never named.
  const parentsNotShown = new Map<string, number>();
  for (const entry of shown) {
    const key = agentKey(entry.source, entry.node);
    const projection = entry.source.current;
    for (const task of entry.nodes.filter(node => node.label === 'GuardTask' && liveTask(node, projection))) {
      for (const [relation, kind] of [
        ['G_DELEGATED_FROM', 'delegates_to'],
        ['G_DERIVED_FROM', 'hands_off_to'],
      ] as const) {
        const parents = connected(projection, new Set([task.id]), relation, work);
        for (const parent of parents) {
          const owner = taskOwners.get(`${entry.source.id}\u0000${parent.id}`);
          if (owner && drawn.has(owner))
            addLink(kind, owner, key, { label: 'GuardTask', entityId: task.entityId, name: string(task, 'task_id') });
          else if (owner !== key) parentsNotShown.set(key, (parentsNotShown.get(key) ?? 0) + 1);
        }
        // Marked delegated or derived, but no parent in this view.
        const flag = relation === 'G_DELEGATED_FROM' ? 'delegated' : 'derived';
        if (!parents.length && task.properties[flag] === true)
          parentsNotShown.set(key, (parentsNotShown.get(key) ?? 0) + 1);
      }
      for (const recipient of strings(task, 'allowed_recipients'))
        for (const owner of principalOwners.get(`${entry.source.id}\u0000${recipient}`) ?? [])
          if (drawn.has(owner))
            // Inferred: a recipient string equal to another agent's caller principal.
            addLink('can_send_to', key, owner, {
              label: 'GuardTask',
              entityId: task.entityId,
              name: string(task, 'task_id'),
              match: 'recipient_equals_principal',
            });
    }
    for (const binding of entry.nodes.filter(node => node.label === 'GuardResourceBinding'))
      for (const dependency of connected(projection, new Set([binding.id]), 'G_DEPENDS_ON', work))
        for (const owner of bindingOwners.get(`${entry.source.id}\u0000${dependency.id}`) ?? [])
          // An agent that holds the dependency itself does not depend on another agent for it.
          if (drawn.has(owner) && !bindingOwners.get(`${entry.source.id}\u0000${dependency.id}`)!.has(key))
            addLink('depends_on', key, owner, {
              label: 'GuardResourceBinding',
              entityId: binding.entityId,
              name: string(binding, 'display_name') ?? string(binding, 'binding_id'),
            });
  }
  // Agent-to-agent links come first and have their own cap, so shared items never crowd them out.
  const agentLinks: JsonObject[] = [];
  const directLinks = [...direct.values()].sort((a, b) =>
    compare(JSON.stringify([a.kind, a.from, a.to]), JSON.stringify([b.kind, b.from, b.to])),
  );
  for (const link of directLinks.slice(0, TOPOLOGY_LIMITS.agentLinks)) {
    agentLinks.push({
      kind: link.kind,
      from: link.from,
      to: link.to,
      toKind: 'agent',
      directed: true,
      via: link.via,
      viaTotal: link.total,
    });
  }
  const links = [...agentLinks, ...hubLinks];
  const linksTotal = directLinks.length + hubLinksTotal;
  // Boundary flags with their own budget (as list_agents does), degraded together to unknown when
  // the fleet is too large to evaluate in time; the rest of the answer still has its own.
  let flagsUnavailable: string | null = null;
  const flags = new Map<string, string>();
  try {
    const flagWork = new QueryWork(Math.max(1, Math.floor(work.remaining() / 2)), maxBytes);
    for (const entry of shown)
      flags.set(
        agentKey(entry.source, entry.node),
        agentFlags(entry.source.current, entry.node, scope, flagWork).status,
      );
  } catch (error) {
    const code = error instanceof MapQueryError ? error.code : '';
    if (code !== 'MAP_LIMIT_EXCEEDED' && code !== 'MAP_TIMEOUT') throw error;
    flags.clear();
    flagsUnavailable = code === 'MAP_TIMEOUT' ? 'flags_timeout' : 'flags_limit_exceeded';
  }
  const previousAgents = new Map<string, Map<string, MapNode>>();
  for (const source of sources)
    if (source.previous) {
      work.step(source.previous.nodes.length);
      previousAgents.set(
        source.id,
        new Map(source.previous.nodes.filter(node => node.label === 'GuardAgent').map(node => [node.entityId, node])),
      );
    }
  // Whether every deployment in view of each source declared its network: only then can a
  // segment no one else is seen on be called dedicated.
  const sourceDeclared = new Map<string, boolean>();
  for (const source of sources) {
    work.step(source.current.nodes.length);
    const deployed = source.current.nodes.filter(node => node.label === 'GuardDeployment');
    sourceDeclared.set(
      source.id,
      deployed.every(node => string(node, 'network_status') === 'declared'),
    );
  }
  const agents = shown.map(entry => {
    const key = agentKey(entry.source, entry.node);
    const held = (kind: TopologyHubKind): { total: number; shared: number } => {
      let total = 0,
        sharedCount = 0;
      const seen = new Set<string>();
      for (const node of entry.nodes) {
        if (HUB_LABEL[node.label] !== kind || !holds(node, kind, entry.source.current)) continue;
        const hub = hubId(entry.source, node, kind);
        if (seen.has(hub)) continue;
        seen.add(hub);
        total++;
        if (sharedKeys.has(hub)) sharedCount++;
      }
      return { total, shared: sharedCount };
    };
    const isolation: Record<string, JsonObject> = {};
    for (const kind of LAYER_KINDS) {
      const { total, shared: count } = held(kind);
      const coverage = entry.source.current.coverage[LAYER_COVERAGE[kind]]?.status;
      isolation[kind] = { status: layerStatus(total, count, coverage, scope.allTeams), total, shared: count };
    }
    const summary = summaries.get(key)!;
    return {
      key,
      id: summary.id,
      agentId: summary.agentId,
      sourceId: summary.sourceId,
      name: summary.name,
      teamId: summary.teamId,
      ownerId: summary.ownerId,
      ownerName: summary.ownerName,
      lifecycleState: summary.lifecycleState,
      environments: summary.environments,
      dangerousThree: flags.get(key) ?? 'unknown',
      isolation: {
        ...isolation,
        egress: egress(entry, work),
        network: network(entry, work, sharedKeys, scope.allTeams, sourceDeclared.get(entry.source.id) === true),
      },
      delegationParentsNotShown: parentsNotShown.get(key) ?? 0,
      lastChange: lastChange(entry, work, previousAgents.get(entry.source.id) ?? new Map()),
    } as JsonObject;
  });
  sortedBy(agents, agentSortKey);
  // Agents in a source's previous snapshot and not in its current one, under the same filters.
  const removed: JsonObject[] = [];
  for (const source of sources) {
    if (!source.previous) continue;
    const current = new Set(
      source.current.nodes.filter(node => node.label === 'GuardAgent').map(node => node.entityId),
    );
    for (const node of previousAgents.get(source.id)?.values() ?? []) {
      work.step();
      if (current.has(node.entityId)) continue;
      const summary = agentSummary(source, source.previous, node, work);
      if (filters.sourceId !== undefined && source.id !== filters.sourceId) continue;
      if (filters.teamId !== undefined && summary.teamId !== filters.teamId) continue;
      if (
        filters.environment !== undefined &&
        !(summary.environments as readonly string[]).includes(filters.environment)
      )
        continue;
      removed.push({
        id: summary.id!,
        agentId: summary.agentId ?? null,
        sourceId: source.id,
        name: summary.name ?? null,
        teamId: summary.teamId ?? null,
        from: source.previous.generatedAt,
        to: source.current.generatedAt,
      });
    }
  }
  sortedBy(removed, agentSortKey);
  return {
    sources: sources.map(source => ({
      ...receipt(source),
      previousGeneratedAt: source.previous?.generatedAt ?? null,
    })),
    agents,
    hubs,
    hubsTotal,
    hubsTruncated: hubsTotal > hubs.length,
    links,
    linksTotal,
    linksTruncated: linksTotal > links.length,
    agentLinksTotal: directLinks.length,
    agentsInView: entries.length,
    removedAgents: removed.slice(0, REMOVED_LIMIT),
    removedAgentsTotal: removed.length,
    ...(flagsUnavailable ? { flagsUnavailable } : {}),
    visibility: scope.allTeams ? 'all_teams' : 'own_teams',
    collection: { networkIsolation: 'host_declared', permissionHistory: 'two_snapshots' },
    evidenceKind: 'declared',
    assessment: 'unknown',
    limitations: TOPOLOGY_LIMITATIONS,
  };
}
const agentKey = (source: MapSource, node: MapNode): string => JSON.stringify([source.id, node.entityId]);

/**
 * The same answer without its optional detail lists (change items, recipients, destinations,
 * egress targets, link evidence), for a fleet whose full answer does not fit the response
 * limit. Every status, count and total stays; `compact: true` says the lists were left out.
 */
export function compactTopology(data: JsonObject): JsonObject {
  const agents = (data.agents as readonly JsonObject[]).map(agent => {
    const isolation = agent.isolation as JsonObject;
    const egress = isolation.egress as JsonObject;
    const net = isolation.network as JsonObject;
    return {
      ...agent,
      isolation: {
        ...isolation,
        egress: { ...egress, recipients: [], approvedDestinations: [] },
        network: { ...net, egressTargets: [] },
      },
      lastChange: { ...(agent.lastChange as JsonObject), items: [] },
    };
  });
  const links = (data.links as readonly JsonObject[]).map(link => (link.via ? { ...link, via: [] } : link));
  return { ...data, agents, links, compact: true };
}
/**
 * The second step for a fleet the compact answer still does not fit: agent-to-agent links stay,
 * the links from agents to shared items are left out (`hubLinksOmitted: true`). Each hub keeps
 * its `agentCount`, and each agent's isolation still says what it shares.
 */
export function withoutHubLinks(data: JsonObject): JsonObject {
  const links = (data.links as readonly JsonObject[]).filter(link => link.toKind === 'agent');
  return { ...data, links, hubLinksOmitted: true };
}
