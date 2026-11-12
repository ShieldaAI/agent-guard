import { assignBoxes, boxCrossing, flagBadge, outsideGuardElements } from './boundary-model.mjs';
import { LABELS, hasLabel, label } from './labels.mjs';

export const OPERATIONS = Object.freeze([
  'list_agents',
  'list_owners',
  'list_resources',
  'get_agent_inventory',
  'get_resource_access',
  'get_agent_access',
  'explain_access',
  'find_agents_with_access',
  'get_changes',
  'get_inventory_health',
  'list_undeclared_activity',
  'list_unclaimed_identities',
]);
// The labels a focused graph may carry. The viewer's own outside-guard nodes have names too,
// but are never accepted as graph input.
const GRAPH_LABELS = new Set(Object.keys(LABELS.nodeKind).filter(name => name.startsWith('Guard')));

export const kindName = value => (hasLabel('nodeKind', value) ? LABELS.nodeKind[value] : 'Evidence');
/** The table that names a node's lifecycle value, by the property that carries it. */
const LIFECYCLE_TABLES = Object.freeze({
  state: 'connectionState',
  cloud_status: 'cloudStatus',
  capture_status: 'captureStatus',
});
export function evidenceState(node) {
  const p = node?.properties ?? {};
  if (p.revoked === true) return { kind: 'blocked', label: 'Revoked at capture' };
  const field = ['state', 'cloud_status', 'capture_status'].find(name => p[name] !== undefined && p[name] !== null);
  const lifecycle = field ? p[field] : undefined;
  const words = field ? label(LIFECYCLE_TABLES[field], lifecycle) : null;
  if (p.cloud_reason === 'stale' || lifecycle === 'stale') return { kind: 'unavailable', label: 'Stale evidence' };
  if (['quarantined', 'closed', 'refreshing', 'connecting', 'unavailable', 'unresolved'].includes(lifecycle))
    return { kind: 'unavailable', label: words };
  if (p.requires_approval === true) return { kind: 'conditional', label: 'Conditional · approval required' };
  if (p.assessment === 'unknown' || p.cloud_assessment === 'unknown')
    return { kind: 'unknown', label: words ? `${words} · access unknown` : 'Access unknown' };
  return { kind: 'observed', label: words ?? 'Observed evidence' };
}
export function nodeName(node) {
  const p = node.properties ?? {};
  if (node.label === 'GuardDirectAccess' && (typeof p.description === 'string' || typeof p.access_id === 'string'))
    return p.description ?? p.access_id;
  const value =
    p.name ??
    p.agent_id ??
    p.deployment_id ??
    p.task_id ??
    p.principal_id ??
    p.connection_id ??
    p.resource_id ??
    p.arn ??
    p.display_name ??
    p.owner_id ??
    p.credential_id ??
    p.binding_id ??
    p.tool ??
    kindName(node.label);
  return typeof value === 'string' ? value : kindName(node.label);
}
export function graphLabel(value) {
  const characters = Array.from(value);
  return characters.length <= 24 ? value : `${characters.slice(0, 16).join('')}…${characters.slice(-7).join('')}`;
}
/**
 * Cytoscape elements for a focused graph. Options add the agent's boundary-flag badge,
 * outside-guard edges (declared direct paths and tool-identity reach) and tenant/team boxes.
 */
export function graphElements(graph, policyEvidence = [], options = {}) {
  if (
    !graph ||
    !Array.isArray(graph.nodes) ||
    !Array.isArray(graph.edges) ||
    graph.nodes.length > 2000 ||
    graph.edges.length > 5000
  )
    throw new Error('VIEWER_GRAPH_INVALID');
  const { flagStatus = null, outsideGuard = null, tenantId = null, boxes = false } = options;
  const badge = flagStatus === null ? null : flagBadge(flagStatus);
  const ids = new Set();
  const nodes = graph.nodes.map(node => {
    if (!node || typeof node.id !== 'string' || !node.id || ids.has(node.id) || !GRAPH_LABELS.has(node.label))
      throw new Error('VIEWER_GRAPH_INVALID');
    ids.add(node.id);
    const state = evidenceState(node);
    const kind =
      node.label === 'GuardAgent'
        ? 'agent'
        : node.label === 'GuardTask'
          ? 'task'
          : node.label === 'GuardDirectAccess'
            ? 'direct-access'
            : node.label.includes('Mcp')
              ? 'mcp'
              : node.label.includes('Resource')
                ? 'resource'
                : node.label.includes('Identity') || node.label === 'GuardPrincipal'
                  ? 'identity'
                  : 'evidence';
    const flagged = badge && node.label === 'GuardAgent';
    return {
      data: {
        id: node.id,
        label: `${graphLabel(nodeName(node))}${flagged ? `\n${badge.label}` : ''}`,
        fullLabel: nodeName(node),
        kind: kindName(node.label),
        source: node,
      },
      classes: `${kind} ${state.kind}${flagged ? ` flag-${badge.status}` : ''}`,
    };
  });
  const byId = new Map(graph.nodes.map(node => [node.id, node]));
  const states = new Map(graph.nodes.map(node => [node.id, evidenceState(node)]));
  const edges = graph.edges.map((edge, index) => {
    if (!edge || !ids.has(edge.source) || !ids.has(edge.target) || typeof edge.kind !== 'string')
      throw new Error('VIEWER_GRAPH_INVALID');
    if (edge.kind === 'G_DIRECT_ACCESS_FOR') {
      // A host-declared path that acts without the guard: never styled as a guarded relationship.
      const kind = byId.get(edge.source)?.properties?.kind;
      return {
        data: {
          id: `edge-${index}`,
          source: edge.source,
          target: edge.target,
          label: `outside guard${typeof kind === 'string' ? ` · ${kind}` : ''}`,
        },
        classes: 'outside-guard',
      };
    }
    const adjacent = [states.get(edge.source), states.get(edge.target)];
    const unavailable = adjacent.find(state => state.kind === 'unavailable');
    const conditional = adjacent.some(state => state.kind === 'conditional');
    const association = edge.kind.includes('CLOUD') || edge.kind.includes('MAPS');
    const status = unavailable?.label ?? (conditional ? 'approval required' : association ? 'access unknown' : '');
    return {
      data: {
        id: `edge-${index}`,
        source: edge.source,
        target: edge.target,
        label: `${edge.kind.replace(/^G_/, '').replaceAll('_', ' ').toLowerCase()}${status ? ` · ${status}` : ''}`,
      },
      classes: `${association ? 'association' : 'declared'}${unavailable ? ' unavailable' : conditional ? ' conditional' : ''}`,
    };
  });
  const policies = policyEvidenceRows(policyEvidence, graph);
  const seen = new Set();
  for (const row of policies)
    for (const candidate of row.candidates) {
      if (row.status !== 'complete' || !row.identityNode || !row.resourceNode) continue;
      const key = JSON.stringify([row.identityNode.id, row.resourceNode.id, row.action, candidate.hasCondition]);
      if (seen.has(key)) continue;
      seen.add(key);
      if (edges.length >= 5000) throw new Error('VIEWER_GRAPH_INVALID');
      edges.push({
        data: {
          id: `policy-edge-${seen.size}`,
          source: row.identityNode.id,
          target: row.resourceNode.id,
          label: `${row.action} · policy candidate${candidate.hasCondition ? ' · condition unresolved' : ''}`,
        },
        classes: 'policy-candidate',
      });
    }
  const extra = outsideGuard ? outsideGuardElements(outsideGuard, graph.nodes, { label: graphLabel }) : null;
  if (extra) {
    if (nodes.length + extra.nodes.length > 2000 || edges.length + extra.edges.length > 5000)
      throw new Error('VIEWER_GRAPH_INVALID');
    nodes.push(...extra.nodes);
    edges.push(...extra.edges);
  }
  if (!boxes) return [...nodes, ...edges];
  const { parents, assignment } = assignBoxes(
    nodes.map(node => ({ ...node.data.source, id: node.data.id })),
    edges.map(edge => edge.data),
    {
      tenantId,
      outside: nodes
        .filter(node => ['OutsideGuardBucket', 'OutsideGuardTarget'].includes(node.data.source.label))
        .map(node => node.data.id),
    },
  );
  if (parents.some(parent => ids.has(parent.id))) throw new Error('VIEWER_GRAPH_INVALID');
  for (const node of nodes) {
    const parent = assignment.get(node.data.id);
    if (parent) node.data.parent = parent;
  }
  for (const edge of edges) {
    const crossing = boxCrossing(edge.data.source, edge.data.target, assignment, parents);
    if (!crossing) continue;
    edge.classes += ' crosses-box';
    edge.data.label += ` · crosses ${crossing} border`;
  }
  // Only boxes that hold something; an empty compound node would draw as a stray node.
  const used = new Set(assignment.values());
  for (const parent of parents) if (used.has(parent.id) && parent.parent) used.add(parent.parent);
  const boxElements = parents
    .filter(parent => used.has(parent.id))
    .map(parent => ({
      data: {
        id: parent.id,
        label: parent.label,
        kind: parent.kind === 'tenant' ? 'Tenant' : 'Team',
        ...(parent.parent ? { parent: parent.parent } : {}),
      },
      classes: `box box-${parent.kind}`,
    }));
  return [...boxElements, ...nodes, ...edges];
}

const POLICY_ACTIONS = Object.freeze({
  CAN_READ: 's3:GetObject',
  CAN_WRITE: 's3:PutObject',
  CAN_LIST: 's3:ListBucket',
});
const policyText = value =>
  typeof value === 'string' &&
  value.length > 0 &&
  Array.from(value).length <= 4096 &&
  !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
/** Minimized presentation data; never display unrecognized provider properties. */
export function policyEvidenceRows(records = [], graph = null) {
  if (!Array.isArray(records) || records.length > 512) throw new Error('VIEWER_POLICY_INVALID');
  const byEntity = new Map(),
    byId = new Map(),
    links = new Set(),
    outgoing = new Map();
  if (graph) {
    if (
      !Array.isArray(graph.nodes) ||
      !Array.isArray(graph.edges) ||
      graph.nodes.length > 2000 ||
      graph.edges.length > 5000
    )
      throw new Error('VIEWER_POLICY_INVALID');
    for (const node of graph.nodes) {
      byId.set(node.id, node);
      if (typeof node.entityId !== 'string') continue;
      if (byEntity.has(node.entityId)) throw new Error('VIEWER_POLICY_INVALID');
      byEntity.set(node.entityId, node);
    }
    for (const edge of graph.edges) {
      links.add(JSON.stringify([edge.source, edge.target, edge.kind]));
      const key = JSON.stringify([edge.source, edge.kind]);
      if (!outgoing.has(key)) outgoing.set(key, []);
      outgoing.get(key).push(edge.target);
    }
  }
  const linked = (source, target, kind) => links.has(JSON.stringify([source?.id, target?.id, kind]));
  const targets = (source, kind) => (outgoing.get(JSON.stringify([source?.id, kind])) ?? []).map(id => byId.get(id));
  const rows = [];
  for (const record of records) {
    if (
      !record ||
      typeof record !== 'object' ||
      record.assessment !== 'unknown' ||
      !['complete', 'unavailable', 'not_collected'].includes(record.status) ||
      !['taskId', 'deploymentId', 'executionBindingId', 'resourceBindingId', 'action'].every(key =>
        policyText(record[key]),
      ) ||
      ![record.identityId, record.resourceId].every(value => value === null || policyText(value)) ||
      !(record.reason === null || policyText(record.reason)) ||
      !(
        record.observedAt === null ||
        (typeof record.observedAt === 'string' && Number.isFinite(Date.parse(record.observedAt)))
      ) ||
      !Array.isArray(record.candidates) ||
      record.candidates.length > 1 ||
      (record.status !== 'complete' && record.candidates.length) ||
      (record.status === 'complete' &&
        (record.observedAt === null || record.reason !== (record.candidates.length ? null : 'no_candidate')))
    )
      throw new Error('VIEWER_POLICY_INVALID');
    const candidates = record.candidates.map(candidate => {
      if (
        !candidate ||
        POLICY_ACTIONS[candidate.relationship] !== record.action ||
        typeof candidate.hasCondition !== 'boolean' ||
        candidate.resourceScope !== 'bucket_summary' ||
        !Array.isArray(candidate.conditionKeys) ||
        candidate.conditionKeys.length > 128 ||
        candidate.conditionKeys.some(
          key => typeof key !== 'string' || !key || new TextEncoder().encode(key).byteLength > 256,
        ) ||
        candidate.hasCondition !== Boolean(candidate.conditionKeys.length)
      )
        throw new Error('VIEWER_POLICY_INVALID');
      return {
        relationship: candidate.relationship,
        hasCondition: candidate.hasCondition,
        conditionKeys: [...candidate.conditionKeys],
        resourceScope: 'bucket_summary',
      };
    });
    const task = byEntity.get(record.taskId),
      deployment = byEntity.get(record.deploymentId),
      execution = byEntity.get(record.executionBindingId),
      binding = byEntity.get(record.resourceBindingId),
      identity = byEntity.get(record.identityId),
      resource = byEntity.get(record.resourceId);
    if (
      graph &&
      (task?.label !== 'GuardTask' ||
        deployment?.label !== 'GuardDeployment' ||
        execution?.label !== 'GuardExecutionBinding' ||
        binding?.label !== 'GuardResourceBinding' ||
        (record.identityId !== null && identity?.label !== 'GuardExternalIdentity') ||
        (record.resourceId !== null && resource?.label !== 'GuardExternalResource') ||
        !linked(task, deployment, 'G_ASSIGNED_TO') ||
        !linked(execution, deployment, 'G_EXECUTES_FOR') ||
        (identity && !linked(execution, identity, 'G_USES_IDENTITY')) ||
        (resource && !linked(binding, resource, 'G_MAPS_TO')))
    )
      continue;
    if (
      graph &&
      !targets(task, 'G_HAS_GRANT').some(
        grant =>
          grant?.label === 'GuardGrant' &&
          targets(grant, 'G_FOR_TOOL').some(
            tool =>
              tool?.label === 'GuardTool' &&
              linked(execution, tool, 'G_EXECUTES_TOOL') &&
              execution.properties?.tool === tool.properties?.name &&
              binding.properties?.tool === tool.properties?.name,
          ) &&
          targets(grant, 'G_TARGETS').some(
            selector => selector?.label === 'GuardResource' && linked(binding, selector, 'G_BINDS_SELECTOR'),
          ),
      )
    )
      continue;
    if (graph && (!Array.isArray(binding.properties?.actions) || !binding.properties.actions.includes(record.action)))
      continue;
    const candidate = candidates[0];
    rows.push({
      taskId: record.taskId,
      deploymentId: record.deploymentId,
      executionBindingId: record.executionBindingId,
      resourceBindingId: record.resourceBindingId,
      action: record.action,
      status: record.status,
      assessment: 'unknown',
      observedAt: record.observedAt,
      label:
        record.status === 'complete'
          ? candidate
            ? candidate.hasCondition
              ? 'Conditional policy candidate'
              : 'Policy candidate'
            : 'No policy candidate observed'
          : hasLabel('policyReason', record.reason)
            ? LABELS.policyReason[record.reason]
            : record.status === 'not_collected'
              ? 'Policy evidence not collected'
              : 'Policy evidence unavailable',
      candidates,
      identityNode: identity ?? null,
      resourceNode: resource ?? null,
      task: task ? nodeName(task) : record.taskId,
      deployment: deployment ? nodeName(deployment) : record.deploymentId,
      execution: execution ? nodeName(execution) : record.executionBindingId,
      target: resource ? nodeName(resource) : (record.resourceId ?? 'Target not resolved'),
      bindingScope: label('matchScope', binding?.properties.scope),
      resourceKind: label('kind', resource?.properties.kind),
    });
  }
  return rows;
}
/**
 * Owner ids and environments named by the agents loaded so far, for the sidebar pickers.
 * `known` carries the choices of earlier pages, so a picker never loses an option it offered.
 */
export function agentOptions(agents, known = { owners: [], environments: [] }) {
  const owners = new Set(known.owners),
    environments = new Set(known.environments);
  for (const agent of agents) {
    if (typeof agent.ownerId === 'string') owners.add(agent.ownerId);
    for (const environment of agent.environments ?? [])
      if (typeof environment === 'string') environments.add(environment);
  }
  return { owners: [...owners].sort(), environments: [...environments].sort() };
}
/** How many sidebar filters are set; the search box is not one of them. */
export const activeFilterCount = filters =>
  ['owner', 'environment', 'ownership', 'lifecycle', 'flag'].filter(name => Boolean(filters?.[name])).length;
export function initialExplanation(access) {
  const task = access.tasks?.[0];
  const grant = access.grants?.find(item => item.taskId === task?.taskId) ?? access.grants?.[0];
  return { taskId: task?.taskId ?? '', tool: grant?.tool ?? '', resourceId: grant?.resources?.[0] ?? '' };
}
/** Identifiers longer than this are shown shortened, with the full value one click away. */
export const IDENTIFIER_LIMIT = 24;
/** `first 10 … last 6` for a long identifier (opaque references, source ids, ARNs); null when it is short enough. */
export function shortIdentifier(value) {
  if (typeof value !== 'string') return null;
  const characters = Array.from(value);
  return characters.length > IDENTIFIER_LIMIT
    ? `${characters.slice(0, 10).join('')}…${characters.slice(-6).join('')}`
    : null;
}
export function displayTime(value) {
  // A numeric deadline can be beyond the Date range; toISOString() would throw during render.
  const timestamp =
    typeof value === 'number' ? new Date(value < 1e12 ? value * 1000 : value).getTime() : Date.parse(value);
  return Number.isFinite(timestamp)
    ? new Date(timestamp).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
      })
    : 'Not observed';
}
/** Component freshness never inherits the enclosing snapshot's capture time. */
export function componentHealth(coverage) {
  const value = coverage && typeof coverage === 'object' ? coverage : {};
  const status = typeof coverage === 'string' ? coverage : typeof value.status === 'string' ? value.status : 'unknown';
  const captured = typeof value.observedAt === 'string' && Number.isFinite(Date.parse(value.observedAt));
  const recent = captured && value.stale === false;
  const age = captured && Number.isFinite(value.ageSeconds) && value.ageSeconds >= 0 ? value.ageSeconds : null;
  return {
    status: label('coverageStatus', status),
    // The policy component can read unknown because one read had too many pairs to evaluate.
    reason: hasLabel('coverageReason', value.reason) ? LABELS.coverageReason[value.reason] : null,
    observedAt: captured ? value.observedAt : null,
    observedLabel: captured ? displayTime(value.observedAt) : 'Capture time unknown',
    freshness: !captured
      ? 'Timestamp unknown'
      : value.stale === true
        ? 'Stale capture'
        : recent
          ? 'Recent capture'
          : 'Freshness unknown',
    tone: recent ? 'green' : 'amber',
    ageLabel:
      age === null
        ? null
        : age < 60
          ? `${Math.floor(age)} sec old at query`
          : age < 3600
            ? `${Math.floor(age / 60)} min old at query`
            : `${Math.floor(age / 3600)} hr old at query`,
  };
}
/** The service found more task/binding pairs than one read evaluates and loaded no policy evidence. */
export const policyNotEvaluated = coverage => coverage?.status === 'unknown' && coverage?.reason === 'limit_exceeded';
/**
 * A `get_agent_inventory` answer whose policy evidence was not loaded: the coverage says so, or
 * the count of the policies section (or the total of that section itself) is null. Its empty
 * list means "not evaluated", never "none".
 */
export const policySectionNotEvaluated = data =>
  policyNotEvaluated(data?.policyCoverage) ||
  data?.counts?.policies === null ||
  (data?.section === 'policies' && data?.total === null);
/** get_agent_access left the graph out because it exceeds the display cap; its evidence still stands. */
export const graphTooLarge = response => response?.data?.graphStatus === 'too_large' && response.graph === undefined;
/**
 * Health is optional to the workspace: a failed read resolves to `unavailable` (with the error,
 * so the caller can end a rejected session) instead of rejecting.
 */
export async function readInventoryHealth(query, options) {
  try {
    const result = await query('get_inventory_health', {}, options);
    return { status: 'ready', sources: Array.isArray(result?.data?.sources) ? result.data.sources : [] };
  } catch (error) {
    return { status: 'unavailable', message: errorMessage(error), error };
  }
}
export class ViewerError extends Error {
  constructor(code, status = 0) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
/** Two reads at a time leave gateway capacity for sign-out and other clients. */
export function createQuerySession(invoke) {
  const controller = new AbortController(),
    pending = [];
  let running = 0;
  const ended = () => new ViewerError('VIEWER_SESSION_ENDED');
  const cancelled = () => new ViewerError('VIEWER_REQUEST_CANCELLED');
  function drain() {
    while (!controller.signal.aborted && running < 2 && pending.length) {
      const item = pending.shift();
      item.started = true;
      running++;
      void (async () => {
        try {
          const result = await invoke(item.operation, item.args, { signal: controller.signal });
          if (controller.signal.aborted) throw ended();
          if (item.signal?.aborted) throw cancelled();
          item.resolve(result);
        } catch (error) {
          item.reject(controller.signal.aborted ? ended() : item.signal?.aborted ? cancelled() : error);
        } finally {
          item.signal?.removeEventListener('abort', item.cancel);
          running--;
          drain();
        }
      })();
    }
  }
  return Object.freeze({
    close() {
      controller.abort();
      for (const item of pending.splice(0)) {
        item.signal?.removeEventListener('abort', item.cancel);
        item.reject(ended());
      }
    },
    query(operation, args = {}, { signal } = {}) {
      if (controller.signal.aborted) return Promise.reject(ended());
      if (signal?.aborted) return Promise.reject(cancelled());
      return new Promise((resolve, reject) => {
        const item = { operation, args, signal, resolve, reject, started: false };
        item.cancel = () => {
          // A started read keeps its slot until the response settles. Aborting
          // fetch alone does not establish that the backend query has stopped.
          if (item.started) return;
          const index = pending.indexOf(item);
          if (index !== -1) pending.splice(index, 1);
          signal?.removeEventListener('abort', item.cancel);
          reject(cancelled());
        };
        signal?.addEventListener('abort', item.cancel, { once: true });
        pending.push(item);
        drain();
      });
    },
  });
}
/** The error's code when it is a string; a DOMException carries a numeric one. */
export const errorCode = error => (typeof error?.code === 'string' ? error.code : '');
export function errorMessage(error) {
  if (error?.status === 401)
    return 'Your reference credential was not accepted. Connect again with a valid credential.';
  if (error?.status === 403) return 'This reference operation is outside your authorized scope.';
  // A timeout rejects with a DOMException whose `code` is a number, so only string codes are read.
  const code = errorCode(error);
  if (error?.name === 'AbortError' || code.includes('TIMEOUT'))
    return 'The reference service took too long. Try again shortly.';
  if (code.includes('NOT_FOUND')) return 'That item is unavailable in your authorized inventory.';
  if (error?.status === 429 || code === 'MAP_RATE_LIMITED') return 'Too many requests. Wait a moment, then try again.';
  if (code.includes('LIMIT') || error?.status === 413)
    return 'This view is too large. Narrow the source or agent selection and try again.';
  return 'The reference service could not complete this request. Try again shortly.';
}
const CSRF = /^agm_csrf_v1\.[A-Za-z0-9_-]{43}$/;
function csrfHeaders(token) {
  if (typeof token !== 'string' || !CSRF.test(token)) throw new ViewerError('VIEWER_CSRF_INVALID', 401);
  return { 'Content-Type': 'application/json', 'X-CSRF-Token': token };
}
function exactObject(value, names) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === names.length &&
    names.every(name => Object.hasOwn(value, name))
  );
}
async function requestJSON(path, request, maximum, { fetchImpl = fetch, timeoutMs = 12000, signal } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000)
    throw new ViewerError('VIEWER_REQUEST_INVALID');
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    if (controller.signal.aborted) throw new DOMException('aborted', 'AbortError');
    const response = await fetchImpl(path, {
      ...request,
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    // A known authentication denial ends the session even when its body is invalid or never finishes.
    if (response.status === 401 || response.status === 403) {
      void response.body?.cancel().catch(() => {});
      throw new ViewerError('REFERENCE_UNAVAILABLE', response.status);
    }
    const declared = response.headers.get('content-length');
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum))
      throw new ViewerError('VIEWER_RESPONSE_LIMIT');
    if (
      response.redirected ||
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '') ||
      !response.body
    )
      throw new ViewerError('VIEWER_RESPONSE_INVALID');
    const chunks = [];
    let length = 0;
    const reader = response.body.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > maximum) {
          await reader.cancel();
          throw new ViewerError('VIEWER_RESPONSE_LIMIT');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const joined = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let body;
    try {
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(joined));
    } catch {
      throw new ViewerError('VIEWER_RESPONSE_INVALID');
    }
    if (!response.ok)
      throw new ViewerError(
        typeof body?.error === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(body.error)
          ? body.error
          : 'REFERENCE_UNAVAILABLE',
        response.status,
      );
    return body;
  } finally {
    clearTimeout(timer);
    controller.abort();
    signal?.removeEventListener('abort', cancel);
  }
}
function queryResult(body, operation) {
  if (!body || body.operation !== operation || !body.data || typeof body.data !== 'object' || Array.isArray(body.data))
    throw new ViewerError('VIEWER_RESPONSE_INVALID');
  return body;
}
export async function queryReference(token, operation, args = {}, options = {}) {
  if (!OPERATIONS.includes(operation)) throw new ViewerError('VIEWER_OPERATION_INVALID');
  if (typeof token !== 'string' || !/^agm_v1\.[A-Za-z0-9_-]{43}$/.test(token))
    throw new ViewerError('VIEWER_CREDENTIAL_INVALID', 401);
  return queryResult(
    await requestJSON(
      '/v1/query',
      {
        method: 'POST',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ operation, args }),
      },
      4 * 1024 * 1024,
      options,
    ),
    operation,
  );
}
export async function queryCompanySession(csrfToken, operation, args = {}, options = {}) {
  if (!OPERATIONS.includes(operation)) throw new ViewerError('VIEWER_OPERATION_INVALID');
  return queryResult(
    await requestJSON(
      '/v1/query',
      {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfHeaders(csrfToken),
        body: JSON.stringify({ operation, args }),
      },
      4 * 1024 * 1024,
      options,
    ),
    operation,
  );
}
export async function readCompanySession({ now = Date.now, ...options } = {}) {
  const value = await requestJSON('/auth/session', { method: 'GET', credentials: 'same-origin' }, 16 * 1024, options);
  if (exactObject(value, ['mode']) && value.mode === 'bearer') return Object.freeze({ mode: 'bearer' });
  if (
    !exactObject(value, ['mode', 'authenticated', 'csrfToken', 'expiresAt']) ||
    value.mode !== 'oidc' ||
    typeof value.authenticated !== 'boolean' ||
    typeof value.csrfToken !== 'string' ||
    !CSRF.test(value.csrfToken) ||
    typeof value.expiresAt !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value.expiresAt) ||
    !Number.isFinite(Date.parse(value.expiresAt))
  )
    throw new ViewerError('VIEWER_SESSION_INVALID');
  if (Date.parse(value.expiresAt) <= now()) throw new ViewerError('VIEWER_SESSION_EXPIRED', 401);
  return Object.freeze({
    mode: 'oidc',
    authenticated: value.authenticated,
    csrfToken: value.csrfToken,
    expiresAt: value.expiresAt,
  });
}
export async function startCompanyLogin(csrfToken, options = {}) {
  const value = await requestJSON(
    '/auth/login',
    { method: 'POST', credentials: 'same-origin', headers: csrfHeaders(csrfToken), body: '{}' },
    16 * 1024,
    options,
  );
  if (
    !exactObject(value, ['authorizationUrl']) ||
    typeof value.authorizationUrl !== 'string' ||
    value.authorizationUrl.length > 8192
  )
    throw new ViewerError('VIEWER_SESSION_INVALID');
  let url;
  try {
    url = new URL(value.authorizationUrl);
  } catch {
    throw new ViewerError('VIEWER_SESSION_INVALID');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href !== value.authorizationUrl)
    throw new ViewerError('VIEWER_SESSION_INVALID');
  return url.href;
}
export async function endCompanySession(csrfToken, options = {}) {
  const value = await requestJSON(
    '/auth/logout',
    { method: 'POST', credentials: 'same-origin', headers: csrfHeaders(csrfToken), body: '{}' },
    16 * 1024,
    options,
  );
  if (!exactObject(value, ['ok']) || value.ok !== true) throw new ViewerError('VIEWER_SESSION_INVALID');
}
/** An explicit retry can confirm a lost logout response without reopening inventory. */
export async function retryCompanyLogout(options = {}) {
  let value = await readCompanySession(options);
  if (value.mode !== 'oidc') throw new ViewerError('VIEWER_SESSION_INVALID');
  if (value.authenticated) {
    await endCompanySession(value.csrfToken, options);
    value = await readCompanySession(options);
  }
  if (value.mode !== 'oidc' || value.authenticated) throw new ViewerError('VIEWER_LOGOUT_UNCONFIRMED');
  return value;
}
/** Authentication loss aborts sibling requests before their results can reach the page. */
function createAuthenticatedQuerySession(invoke, { onEnded = () => {}, ...options }) {
  let ended = false;
  const session = createQuerySession(async (operation, args, { signal }) => {
    try {
      return await invoke(operation, args, { ...options, signal });
    } catch (error) {
      if ([401, 403].includes(error?.status) && !ended) {
        ended = true;
        session.close();
        onEnded();
      }
      throw error;
    }
  });
  return Object.freeze({
    close() {
      ended = true;
      session.close();
    },
    query: session.query,
  });
}
export function createBearerQuerySession(token, options = {}) {
  return createAuthenticatedQuerySession((...args) => queryReference(token, ...args), options);
}
export function createCompanyQuerySession(csrfToken, options = {}) {
  return createAuthenticatedQuerySession((...args) => queryCompanySession(csrfToken, ...args), options);
}
/** How long before a company session ends the viewer says so. */
export const SESSION_WARNING_MS = 60_000;
/**
 * Watches one company session. Hiding the page unloads nothing (`onAway` lets the caller cover
 * the evidence meanwhile); coming back to it (or being restored from the back/forward cache)
 * asks the caller to check the session again before the evidence is shown
 * (`onRevalidate('hidden' | 'restored')`). `onExpiring` fires once, a minute
 * before `expiresAt`. At expiry the evidence is dropped (`onInvalidate('expired')`) and the
 * session is checked (`onRevalidate('expired')`). Returns a function that stops the watch.
 */
export function watchCompanySession({
  expiresAt,
  onInvalidate,
  onRevalidate,
  onExpiring = () => {},
  onAway = () => {},
  warnMs = SESSION_WARNING_MS,
  windowImpl = window,
  documentImpl = document,
  now = Date.now,
  schedule = setTimeout,
  cancel = clearTimeout,
}) {
  let ended = false,
    away = false,
    warned = false,
    revalidating = false,
    timer;
  const revalidate = reason => {
    if (!ended && !revalidating) {
      revalidating = true;
      onRevalidate(reason);
    }
  };
  const visibility = () => {
    if (documentImpl.visibilityState === 'hidden') {
      away = true;
      if (!ended && !revalidating) onAway();
    } else if (away) revalidate('hidden');
  };
  const pageshow = event => {
    if (event.persisted) revalidate('restored');
  };
  const arm = () => {
    const remaining = Date.parse(expiresAt) - now();
    if (!warned && remaining > 0 && remaining <= warnMs) {
      warned = true;
      onExpiring();
    }
    // Wake for the warning first, then for the expiry itself.
    const wait = warned ? remaining : remaining - warnMs;
    timer = schedule(
      () => {
        if (ended) return;
        if (Date.parse(expiresAt) <= now()) {
          if (!revalidating) onInvalidate('expired');
          revalidate('expired');
        } else arm();
      },
      Math.max(0, Math.min(wait, 2147483647)),
    );
  };
  if (!Number.isFinite(Date.parse(expiresAt))) throw new ViewerError('VIEWER_SESSION_INVALID');
  documentImpl.addEventListener('visibilitychange', visibility);
  windowImpl.addEventListener('pageshow', pageshow);
  arm();
  visibility();
  return () => {
    ended = true;
    cancel(timer);
    documentImpl.removeEventListener('visibilitychange', visibility);
    windowImpl.removeEventListener('pageshow', pageshow);
  };
}
