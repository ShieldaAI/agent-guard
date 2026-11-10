// Presentation logic for boundary flags ("dangerous three") and outside-guard access.
// Pure functions only, so they are testable without a browser. Every status is declared
// or candidate evidence: no label here may read as "safe" or "confirmed".

/** Badges for `boundaryFlags.dangerousThree`. `absent` has no badge; anything unrecognized reads as unknown. */
export const FLAG_BADGES = Object.freeze({
  exposed: Object.freeze({ status: 'exposed', tone: 'exposed', label: 'Exposed' }),
  mitigated: Object.freeze({ status: 'mitigated', tone: 'mitigated', label: 'Mitigated' }),
  unknown: Object.freeze({ status: 'unknown', tone: 'unknown', label: 'Unknown' }),
});
export function flagBadge(value) {
  // A row without `boundaryFlags` was listed without flags; there is nothing to show.
  const status = value && typeof value === 'object' ? value.dangerousThree : value;
  if (status === undefined || status === null || status === 'absent') return null;
  return Object.hasOwn(FLAG_BADGES, status) ? FLAG_BADGES[status] : FLAG_BADGES.unknown;
}

/** The list filter maps to `flag` / `flagStatus`; every listing also asks for the flags themselves. */
export const FLAG_FILTERS = Object.freeze([
  ['', 'All agents'],
  ['flagged', 'Flagged (exposed, mitigated or unknown)'],
  ['exposed', 'Exposed'],
  ['mitigated', 'Mitigated'],
  ['unknown', 'Unknown'],
  ['absent', 'No flag (a leg is known absent)'],
]);
export function flagFilterArgs(value) {
  if (value === 'flagged') return { includeFlags: true, flag: 'dangerous_three' };
  if (['exposed', 'mitigated', 'unknown', 'absent'].includes(value)) return { includeFlags: true, flagStatus: value };
  return { includeFlags: true };
}

export const LEG_LABELS = Object.freeze({
  privateData: 'Private data',
  outsideContent: 'Outside content',
  externalSend: 'Can send out',
});
const LEG_STATES = Object.freeze({ present: 'Present', absent: 'Absent', unknown: 'Unknown' });
const REASONS = Object.freeze({
  binding_restricted: 'Resource binding labelled restricted',
  binding_confidential: 'Resource binding labelled confidential',
  task_sensitive: 'Task marked sensitive',
  tool_reads_untrusted: 'Tool declares it reads untrusted content',
  task_untrusted: 'Task marked untrusted',
  tool_sends_external: 'Tool declares it sends externally',
  no_effective_recipients: 'No effective recipients across the task lineage',
  sensitive_egress_denied: 'Task is sensitive, so declared external sends are refused',
  untrusted_context_require_approval: 'Sending tool requires approval with untrusted context',
  untrusted_context_deny: 'Sending tool is denied with untrusted context',
});
const NOTES = Object.freeze({
  no_live_tasks: 'No live tasks in this snapshot.',
  ancestor_evidence_outside_visible_scope: 'A delegating ancestor task is outside your visible scope.',
  delegation_not_recorded: 'This snapshot predates delegation data; republishing the source restores it.',
  delegation_depth_exceeded: 'A recorded parent or handoff source lies more than 16 links away.',
  delegation_ancestors_not_loaded: 'Ancestor and handoff source tasks were too many to load in this view.',
  flags_limit_exceeded: 'The flag needed more work than this view allows.',
  flags_timeout: 'Evaluating the flag took too long.',
  delegation_parent_missing: 'A recorded parent or handoff source task is missing from this snapshot.',
  delegation_evidence_ambiguous: 'A task has more than one parent or handoff source.',
  task_liveness_unverified: 'A task does not say whether it is revoked or when it expires.',
});
const words = value => String(value).replaceAll('_', ' ');
// Own keys only: a value such as "constructor" must not pick up an inherited member.
const lookup = (table, value, fallback) =>
  typeof value === 'string' ? (Object.hasOwn(table, value) ? table[value] : words(value)) : fallback;
export const reasonLabel = value => lookup(REASONS, value, 'Unknown reason');
export const noteLabel = value => lookup(NOTES, value, 'Unknown note');
const textOrNull = value => (typeof value === 'string' && value ? value : null);
const strings = value => (Array.isArray(value) ? value.filter(item => typeof item === 'string') : []);

function evidenceRow(item) {
  return {
    leg: item.leg,
    taskId: textOrNull(item.taskId),
    tool: textOrNull(item.tool),
    resourceBindingId: textOrNull(item.resourceBindingId),
    reason: textOrNull(item.reason),
    reasonLabel: reasonLabel(item.reason),
  };
}
/** One row per leg in a fixed order, with its evidence; mitigation evidence is listed separately. */
export function boundaryFlagRows(flags) {
  const flag = (Array.isArray(flags) ? flags : []).find(item => item?.kind === 'dangerous_three');
  if (!flag) return null;
  const evidence = (Array.isArray(flag.evidence) ? flag.evidence : []).filter(item => item && typeof item === 'object');
  const legs = flag.legs && typeof flag.legs === 'object' ? flag.legs : {};
  // A missing or unrecognised status reads as unknown, never as no flag.
  const status = Object.hasOwn(FLAG_BADGES, flag.status) || flag.status === 'absent' ? flag.status : 'unknown';
  return {
    status,
    badge: flagBadge(status),
    statusLabel: status === 'absent' ? 'No flag: at least one leg is known absent' : flagBadge(status).label,
    legs: Object.entries(LEG_LABELS).map(([leg, label]) => {
      const state = Object.hasOwn(LEG_STATES, legs[leg]) ? legs[leg] : 'unknown';
      return {
        leg,
        label,
        state,
        stateLabel: LEG_STATES[state],
        evidence: evidence.filter(item => item.leg === leg).map(evidenceRow),
      };
    }),
    mitigation: evidence.filter(item => item.leg === 'mitigation').map(evidenceRow),
    // The service lists a few items per leg; say so when it left some out.
    evidenceTruncated: flag.evidenceTruncated === true,
    notes: strings(flag.notes).map(noteLabel),
    limitations: strings(flag.limitations),
    liveTasks: Number.isSafeInteger(flag.liveTasks) && flag.liveTasks >= 0 ? flag.liveTasks : null,
    evidenceKind: 'declared',
  };
}

const DIRECT_STATUS = Object.freeze({
  found: 'Direct paths declared',
  none_declared: 'None declared (host claim, not checked)',
  unknown: 'Unknown: the host has not declared direct paths',
});
const SCOPE_STATUS = Object.freeze({
  broader_than_grants: 'Broader than grants (candidate)',
  matches_grants: 'Matches grants for checked identity policies',
  unknown: 'Unknown',
});
const RELATIONSHIPS = Object.freeze({ CAN_READ: 'Can read', CAN_WRITE: 'Can write', CAN_LIST: 'Can list' });
export const relationshipName = value =>
  typeof value === 'string' ? (Object.hasOwn(RELATIONSHIPS, value) ? RELATIONSHIPS[value] : value) : 'Unknown';
export const DIRECT_KINDS = Object.freeze(['shell', 'database', 'network', 'sdk', 'mcp', 'other']);

function extraRow(extra) {
  const conditionKeys = strings(extra?.conditionKeys);
  return {
    resourceId: textOrNull(extra?.resourceId),
    bucketName: textOrNull(extra?.bucketName) ?? textOrNull(extra?.resourceId) ?? 'Unknown bucket',
    relationship: textOrNull(extra?.relationship),
    relationshipLabel: relationshipName(extra?.relationship),
    hasCondition: extra?.hasCondition === true || conditionKeys.length > 0,
    conditionKeys,
  };
}
/** Declared direct paths (C1) and tool identity scope (C2), kept in separate lists. */
export function outsideGuardRows(outsideGuard) {
  const value = outsideGuard && typeof outsideGuard === 'object' ? outsideGuard : {};
  const directAccess = (Array.isArray(value.directAccess) ? value.directAccess : []).map(deployment => {
    const status = Object.hasOwn(DIRECT_STATUS, deployment?.status) ? deployment.status : 'unknown';
    return {
      id: textOrNull(deployment?.id),
      deploymentId: textOrNull(deployment?.deploymentId) ?? textOrNull(deployment?.id) ?? 'Unknown deployment',
      status,
      statusLabel: DIRECT_STATUS[status],
      entries: (Array.isArray(deployment?.entries) ? deployment.entries : []).map(entry => ({
        id: textOrNull(entry?.id),
        accessId: textOrNull(entry?.accessId),
        kind: DIRECT_KINDS.includes(entry?.kind) ? entry.kind : 'other',
        targetRef: textOrNull(entry?.targetRef),
        // `outside_visible_scope`: the host named a target this reader cannot see; it is withheld.
        targetWithheld: entry?.targetStatus === 'outside_visible_scope',
        description: textOrNull(entry?.description),
      })),
    };
  });
  const identityScope = (Array.isArray(value.identityScope) ? value.identityScope : []).map(item => {
    const status = Object.hasOwn(SCOPE_STATUS, item?.status) ? item.status : 'unknown';
    return {
      id: textOrNull(item?.id),
      executionBindingId: textOrNull(item?.executionBindingId) ?? textOrNull(item?.id),
      deploymentId: textOrNull(item?.deploymentId),
      tool: textOrNull(item?.tool),
      identityId: textOrNull(item?.identityId),
      status,
      statusLabel: SCOPE_STATUS[status],
      reason: textOrNull(item?.reason),
      observedAt: textOrNull(item?.observedAt),
      boundBuckets: strings(item?.boundBuckets),
      extraResources: (Array.isArray(item?.extraResources) ? item.extraResources : []).map(extraRow),
      truncated: item?.truncated === true,
      // Some buckets belong to bindings outside the reader's scope; the API names none of them.
      withheld: strings(item?.notes).includes('evidence_outside_visible_scope'),
    };
  });
  return { directAccess, identityScope };
}

/** `list_resources` / `get_resource_access` reach: yes | none_found | unknown. */
const REACH = Object.freeze({ yes: 'Yes', none_found: 'None found', unknown: 'Unknown' });
export const outsideGuardLabel = value => (Object.hasOwn(REACH, value) ? REACH[value] : REACH.unknown);
const UNKNOWN_REASONS = Object.freeze({
  direct_access_undeclared: 'A visible deployment has not declared its direct paths',
  resource_not_collected: 'The AWS collection has not resolved this bucket',
  binding_ambiguous: 'The binding does not map to exactly one resource',
  identity_scope_not_collected_for_resource: 'No collected S3 bucket maps to this resource',
  identity_scope_not_collected: 'Tool identity scope was not collected',
  identity_scope_unknown: 'A visible tool identity could not be evaluated',
  identity_scope_other_account: 'A tool identity is in another AWS account and was never compared with this bucket',
  direct_access_untargeted: 'A declared direct path has no target, so it may reach any resource',
  direct_access_target_unresolved: 'A declared direct path names a resource this view cannot match',
  execution_identity_undeclared: 'A granted tool has no declared execution identity',
  outside_visible_scope: 'Deployments or tasks outside your scope may reach it',
  reach_not_evaluated: 'This source is too large to judge reach in one read',
});
export const unknownReasonLabel = value => lookup(UNKNOWN_REASONS, value, 'Unknown reason');

/** A change row about a declared direct path carries the `outside_guard` category or `declared` kind. */
export const changeIsDeclared = item =>
  item?.evidenceKind === 'declared' || (Array.isArray(item?.categories) && item.categories.includes('outside_guard'));

// Graph: classes and synthetic elements for outside-guard edges and compound boxes.

export const OUTSIDE_EDGE_CLASSES = Object.freeze(['outside-guard', 'identity-reach']);
const CLOUD_LABELS = new Set(['GuardExternalIdentity', 'GuardExternalResource']);
const hasClass = (element, name) => ` ${element.classes ?? ''} `.includes(` ${name} `);
// Node data also carries `source` (the evidence node), so only `target` marks an edge.
const isEdge = element => typeof element?.data?.target === 'string';
export const isOutsideGuardEdge = element =>
  isEdge(element) && OUTSIDE_EDGE_CLASSES.some(name => hasClass(element, name));

/**
 * Synthetic nodes and edges for outside-guard evidence the focused graph does not already
 * contain: declared direct paths missing from the graph, their targets, and buckets a tool's
 * identity reaches beyond its grants. Endpoints resolve by entity ID; unresolved ones are skipped.
 */
/** Buckets drawn per execution binding, and in all, before the graph summarises the rest. */
export const GRAPH_BUCKETS_PER_BINDING = 8;
export const GRAPH_BUCKET_EDGES = 300;
export function outsideGuardElements(outsideGuard, graphNodes, { label = value => value } = {}) {
  const rows = outsideGuardRows(outsideGuard);
  const byEntity = new Map(),
    byHostResource = new Map(),
    ids = new Set();
  for (const node of graphNodes) {
    ids.add(node.id);
    if (typeof node.entityId === 'string') byEntity.set(node.entityId, node);
    const host = node.properties?.host_resource_id;
    if (typeof host === 'string' && !byHostResource.has(host)) byHostResource.set(host, node);
  }
  const resolve = entityId =>
    entityId === null ? null : (byEntity.get(entityId) ?? (ids.has(entityId) ? { id: entityId } : null));
  const nodes = [],
    edges = [],
    added = new Set(),
    edgeKeys = new Set();
  const addNode = (id, name, kind, synthetic, properties) => {
    if (added.has(id) || ids.has(id)) return;
    added.add(id);
    nodes.push({
      data: { id, label: label(name), fullLabel: name, kind, source: { id, label: synthetic, properties } },
      classes: `${synthetic === 'OutsideGuardBucket' ? 'resource' : 'evidence'} synthetic outside-node`,
    });
  };
  const addEdge = (source, target, text, classes) => {
    const key = JSON.stringify([source, target, text]);
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ data: { id: `outside-edge-${edgeKeys.size}`, source, target, label: text }, classes });
  };
  for (const deployment of rows.directAccess) {
    const deploymentNode = resolve(deployment.id);
    for (const entry of deployment.entries) {
      let accessNode = resolve(entry.id);
      if (!accessNode && deploymentNode && entry.id) {
        const id = `outside-access:${entry.id}`;
        addNode(
          id,
          entry.description ?? entry.accessId ?? entry.id,
          'Direct access (outside guard)',
          'OutsideGuardAccess',
          {
            access_id: entry.accessId,
            kind: entry.kind,
            target_ref: entry.targetRef,
            description: entry.description,
            evidence_kind: 'declared',
          },
        );
        accessNode = { id };
        addEdge(id, deploymentNode.id, `outside guard · ${entry.kind}`, 'outside-guard');
      }
      if (!accessNode || entry.targetRef === null) continue;
      const known = byHostResource.get(entry.targetRef);
      const targetId = known?.id ?? `outside-target:${entry.targetRef}`;
      if (!known)
        addNode(targetId, entry.targetRef, 'Direct path target', 'OutsideGuardTarget', {
          target_ref: entry.targetRef,
          evidence_kind: 'declared',
        });
      addEdge(accessNode.id, targetId, 'outside guard · declared target', 'outside-guard');
    }
  }
  // A broad role can reach hundreds of buckets from every tool. The tables list them all; the
  // graph draws a few per execution binding and one "more" node for the rest, so it stays readable.
  let drawn = 0;
  for (const record of rows.identityScope) {
    const execution = resolve(record.executionBindingId);
    if (!execution) continue;
    // Whole buckets (with every relationship) are drawn until the per-binding or overall limit.
    const bucketKey = extra => extra.resourceId ?? extra.bucketName;
    const byBucket = new Map();
    for (const extra of record.extraResources) {
      const entries = byBucket.get(bucketKey(extra));
      if (entries) entries.push(extra);
      else byBucket.set(bucketKey(extra), [extra]);
    }
    const shown = [];
    let buckets = 0;
    for (const entries of byBucket.values()) {
      if (buckets >= GRAPH_BUCKETS_PER_BINDING || drawn + entries.length > GRAPH_BUCKET_EDGES) break;
      shown.push(...entries);
      drawn += entries.length;
      buckets++;
    }
    const rest = byBucket.size - buckets;
    if (rest > 0 || record.truncated) {
      const id = `outside-more:${execution.id}`;
      const text =
        rest > 0
          ? `+${rest} more bucket${rest === 1 ? '' : 's'} (listed in the table)${record.truncated ? ', and others not listed' : ''}`
          : 'More buckets, not listed';
      addNode(id, text, 'More buckets reached by tool identity (candidates)', 'OutsideGuardBucket', {
        undrawn: rest,
        list_shortened: record.truncated,
        evidence_kind: 'iam_identity_policy_candidate',
        assessment: 'unknown',
      });
      addEdge(execution.id, id, 'tool identity reaches this · more candidates', 'identity-reach');
    }
    for (const extra of shown) {
      const id = `outside-bucket:${extra.resourceId ?? extra.bucketName}`;
      addNode(id, extra.bucketName, 'Bucket reached by tool identity (candidate)', 'OutsideGuardBucket', {
        resource_id: extra.resourceId,
        bucket_name: extra.bucketName,
        evidence_kind: 'iam_identity_policy_candidate',
        assessment: 'unknown',
      });
      addEdge(
        execution.id,
        id,
        `tool identity reaches this · ${extra.relationship ?? 'unknown'}${extra.hasCondition ? ' · condition unresolved' : ''}`,
        'identity-reach',
      );
    }
  }
  return { nodes, edges };
}

/**
 * Compound boxes: one per tenant and, inside it, one per agent team. Host nodes join the team
 * box of their nearest agent, along paths that do not pass through provider nodes; a node equally
 * near to several teams (or reached by none) sits in the tenant box. Provider (cloud) nodes and synthetic buckets
 * or targets sit outside every box. Returns the parents and a node-id → parent-id map.
 */
export function assignBoxes(graphNodes, graphEdges, { tenantId = null, outside = [] } = {}) {
  const tenant = typeof tenantId === 'string' && tenantId ? tenantId : null;
  const tenantBox = `box:tenant:${tenant ?? 'unknown'}`;
  const parents = [{ id: tenantBox, label: `Tenant · ${tenant ?? 'unknown'}`, kind: 'tenant', parent: null }];
  const outsideIds = new Set(outside);
  const host = new Map();
  for (const node of graphNodes) if (!CLOUD_LABELS.has(node.label) && !outsideIds.has(node.id)) host.set(node.id, node);
  const neighbors = new Map([...host.keys()].map(id => [id, []]));
  for (const edge of graphEdges)
    if (host.has(edge.source) && host.has(edge.target)) {
      neighbors.get(edge.source).push(edge.target);
      neighbors.get(edge.target).push(edge.source);
    }
  // Multi-source breadth-first search: each host node joins the team of its nearest agent.
  // A tie between teams (a hub shared by several teams) or no path at all leaves it in the tenant box.
  const nearest = new Map();
  let frontier = [];
  for (const node of host.values()) {
    if (node.label !== 'GuardAgent') continue;
    const team =
      typeof node.properties?.team_id === 'string' && node.properties.team_id ? node.properties.team_id : null;
    const box = `box:team:${tenant ?? 'unknown'}:${team ?? 'unknown'}`;
    if (!parents.some(parent => parent.id === box))
      parents.push({ id: box, label: `Team · ${team ?? 'unknown'}`, kind: 'team', parent: tenantBox });
    if (!nearest.has(node.id)) nearest.set(node.id, new Set());
    nearest.get(node.id).add(box);
    frontier.push(node.id);
  }
  const reached = new Set(frontier);
  while (frontier.length) {
    const next = new Map();
    for (const id of frontier)
      for (const neighbor of neighbors.get(id) ?? []) {
        if (reached.has(neighbor)) continue;
        if (!next.has(neighbor)) next.set(neighbor, new Set());
        for (const box of nearest.get(id)) next.get(neighbor).add(box);
      }
    for (const [id, boxes] of next) {
      reached.add(id);
      nearest.set(id, boxes);
    }
    frontier = [...next.keys()];
  }
  const assignment = new Map();
  for (const id of host.keys()) {
    const boxes = nearest.get(id);
    assignment.set(id, boxes?.size === 1 ? [...boxes][0] : tenantBox);
  }
  return { parents, assignment };
}
/** The chain of boxes a node sits in, innermost first; an empty list is outside every box. */
function boxChain(id, assignment, parents) {
  const byId = new Map(parents.map(parent => [parent.id, parent])),
    chain = [];
  for (let box = assignment.get(id) ?? null; box !== null && chain.length < 8; box = byId.get(box)?.parent ?? null)
    chain.push(box);
  return chain;
}
/**
 * null when both ends share the same innermost box, or when one end sits outside every box
 * (a provider or candidate node, which belongs to no tenant or team); otherwise which border
 * the edge crosses.
 */
export function boxCrossing(source, target, assignment, parents) {
  const a = boxChain(source, assignment, parents),
    b = boxChain(target, assignment, parents);
  if (!a.length || !b.length || a[0] === b[0]) return null;
  const tenant = chain => chain.find(id => id.startsWith('box:tenant:')) ?? null;
  return tenant(a) === tenant(b) ? 'team' : 'tenant';
}

/** The "outside-guard only" toggle: outside-guard edges, their endpoints and the boxes around them. */
export function onlyOutsideGuard(elements) {
  const edges = elements.filter(isOutsideGuardEdge);
  const keep = new Set(edges.flatMap(edge => [edge.data.source, edge.data.target]));
  const byId = new Map(elements.filter(element => !isEdge(element)).map(element => [element.data.id, element]));
  for (const id of [...keep])
    for (let parent = byId.get(id)?.data.parent; parent && !keep.has(parent); parent = byId.get(parent)?.data.parent)
      keep.add(parent);
  return [...elements.filter(element => !isEdge(element) && keep.has(element.data.id)), ...edges];
}

/** Why the page's flags read as unknown when the service could not compute them. */
export function flagsUnavailableLabel(value) {
  const reason =
    value === 'flags_limit_exceeded'
      ? 'this page is too large to evaluate'
      : value === 'flags_timeout'
        ? 'evaluating them took too long'
        : 'the evaluation was unavailable';
  return `Boundary flags show Unknown on this page because ${reason}. Open an agent for its own flags.`;
}
