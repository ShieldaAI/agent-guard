// Presentation logic for boundary flags ("dangerous three") and outside-guard access.
// Pure functions only, so they are testable without a browser. Every status is declared
// or candidate evidence: no label here may read as "safe" or "confirmed". The words themselves
// live in labels.mjs; this module shapes rows.
import { LABELS, fieldValue, hasLabel, label } from './labels.mjs';

/** Badges for `boundaryFlags.dangerousThree`. `absent` has no badge; anything unrecognized reads as unknown. */
export const FLAG_NAME = 'Dangerous three';
export const FLAG_BADGES = Object.freeze(
  Object.fromEntries(
    Object.entries(LABELS.flagStatus).map(([status, word]) => [
      status,
      Object.freeze({ status, tone: status, word, label: `${FLAG_NAME}: ${word}` }),
    ]),
  ),
);
export function flagBadge(value) {
  // A row without `boundaryFlags` was listed without flags; there is nothing to show.
  const status = value && typeof value === 'object' ? value.dangerousThree : value;
  if (status === undefined || status === null || status === 'absent') return null;
  return Object.hasOwn(FLAG_BADGES, status) ? FLAG_BADGES[status] : FLAG_BADGES.unknown;
}

/** The list filter maps to `flag` / `flagStatus`; every listing also asks for the flags themselves. */
export const FLAG_FILTERS = Object.freeze([
  ['', 'All agents'],
  ['flagged', 'Any flag (exposed, mitigated or unknown)'],
  ...Object.entries(LABELS.flagStatus),
  ['absent', 'No flag (one of the three is known not to apply)'],
]);
export function flagFilterArgs(value) {
  if (value === 'flagged') return { includeFlags: true, flag: 'dangerous_three' };
  if (['exposed', 'mitigated', 'unknown', 'absent'].includes(value)) return { includeFlags: true, flagStatus: value };
  return { includeFlags: true };
}

export const LEG_LABELS = LABELS.flagLeg;
export const reasonLabel = value => label('flagReason', value, 'Unknown reason');
export const noteLabel = value => label('flagNote', value, 'Unknown note');
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
    statusLabel:
      status === 'absent' ? 'No flag: at least one of the three is known not to apply' : flagBadge(status).label,
    legs: Object.entries(LEG_LABELS).map(([leg, label]) => {
      const state = hasLabel('legState', legs[leg]) ? legs[leg] : 'unknown';
      return {
        leg,
        label,
        state,
        stateLabel: LABELS.legState[state],
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

export const relationshipName = value => label('policyRelationship', value);
export const DIRECT_KINDS = Object.freeze(Object.keys(LABELS.directAccessKind));

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
    const status = hasLabel('directAccessStatus', deployment?.status) ? deployment.status : 'unknown';
    return {
      id: textOrNull(deployment?.id),
      deploymentId: textOrNull(deployment?.deploymentId) ?? textOrNull(deployment?.id) ?? 'Unknown deployment',
      status,
      statusLabel: LABELS.directAccessStatus[status],
      entries: (Array.isArray(deployment?.entries) ? deployment.entries : []).map(entry => ({
        id: textOrNull(entry?.id),
        accessId: textOrNull(entry?.accessId),
        kind: DIRECT_KINDS.includes(entry?.kind) ? entry.kind : 'other',
        kindLabel: label('directAccessKind', DIRECT_KINDS.includes(entry?.kind) ? entry.kind : 'other'),
        targetRef: textOrNull(entry?.targetRef),
        // `outside_visible_scope`: the host named a target this reader cannot see; it is withheld.
        targetWithheld: entry?.targetStatus === 'outside_visible_scope',
        description: textOrNull(entry?.description),
      })),
    };
  });
  const identityScope = (Array.isArray(value.identityScope) ? value.identityScope : []).map(item => {
    const status = hasLabel('identityScopeStatus', item?.status) ? item.status : 'unknown';
    return {
      id: textOrNull(item?.id),
      executionBindingId: textOrNull(item?.executionBindingId) ?? textOrNull(item?.id),
      deploymentId: textOrNull(item?.deploymentId),
      tool: textOrNull(item?.tool),
      identityId: textOrNull(item?.identityId),
      status,
      statusLabel: LABELS.identityScopeStatus[status],
      reason: textOrNull(item?.reason),
      reasonLabel: textOrNull(item?.reason) ? label('identityScopeReason', item.reason) : null,
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
export const outsideGuardLabel = value => (hasLabel('reach', value) ? LABELS.reach[value] : LABELS.reach.unknown);
/** True when reach was never judged, so its empty lists say nothing about the resource. */
export const reachNotEvaluated = value =>
  Array.isArray(value?.unknownReasons) && value.unknownReasons.includes('reach_not_evaluated');
export const unknownReasonLabel = value => label('reachUnknownReason', value, 'Unknown reason');

/** get_changes categories and kinds in words; the service's codes are never shown raw. */
export const CHANGE_FILTERS = Object.freeze([['all', 'All changes'], ...Object.entries(LABELS.changeCategory)]);
export const changeCategoryLabel = value => label('changeCategory', value);
export const changeKindLabel = value => label('changeKind', value);
/** A changed field's value, in words where the field holds a status code or a yes/no value. */
export const changeValueLabel = (field, value) => fieldValue(field, value);

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
        addEdge(id, deploymentNode.id, `outside guard · ${entry.kindLabel.toLowerCase()}`, 'outside-guard');
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
        `tool identity reaches this · ${extra.relationshipLabel.toLowerCase()}${extra.hasCondition ? ' · condition unresolved' : ''}`,
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
  const reason = hasLabel('flagsUnavailable', value)
    ? LABELS.flagsUnavailable[value]
    : 'the evaluation was unavailable';
  return `Boundary flags show Unknown on this page because ${reason}. Open an agent for its own flags.`;
}
