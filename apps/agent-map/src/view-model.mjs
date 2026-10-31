export const OPERATIONS = Object.freeze(['list_agents', 'get_agent_access', 'explain_access',
  'find_agents_with_access', 'get_changes', 'get_inventory_health']);
const LABELS = Object.freeze({ GuardAgent: 'Agent', GuardDeployment: 'Deployment', GuardTask: 'Task',
  GuardPrincipal: 'Principal', GuardTool: 'Tool', GuardGrant: 'Declared grant', GuardResource: 'Resource',
  GuardResourceBinding: 'Resource binding', GuardExecutionBinding: 'Execution binding',
  GuardExternalIdentity: 'Cloud identity', GuardExternalResource: 'Cloud resource',
  GuardMcpConnection: 'MCP connection', GuardMcpOperation: 'MCP operation' });

export const kindName = label => LABELS[label] ?? 'Evidence';
export function evidenceState(node) {
  const p = node?.properties ?? {};
  if (p.revoked === true) return { kind: 'blocked', label: 'Revoked at capture' };
  const lifecycle = p.state ?? p.cloud_status ?? p.capture_status;
  if (p.cloud_reason === 'stale' || lifecycle === 'stale') return { kind: 'unavailable', label: 'Stale evidence' };
  if (['quarantined', 'closed', 'refreshing', 'connecting', 'unavailable', 'unresolved'].includes(lifecycle))
    return { kind: 'unavailable', label: String(lifecycle).replaceAll('_', ' ') };
  if (p.requires_approval === true) return { kind: 'conditional', label: 'Conditional · approval required' };
  if (p.assessment === 'unknown' || p.cloud_assessment === 'unknown') return { kind: 'unknown', label: lifecycle ? `${lifecycle} · access unknown` : 'Access unknown' };
  return { kind: 'observed', label: lifecycle ?? 'Observed evidence' };
}
export function nodeName(node) {
  const p = node.properties ?? {};
  const value = p.name ?? p.agent_id ?? p.deployment_id ?? p.task_id ?? p.principal_id ??
    p.connection_id ?? p.resource_id ?? p.arn ?? p.binding_id ?? p.tool ?? kindName(node.label);
  return typeof value === 'string' ? value : kindName(node.label);
}
export function graphElements(graph, policyEvidence = []) {
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || graph.nodes.length > 2000 || graph.edges.length > 5000) throw new Error('VIEWER_GRAPH_INVALID');
  const ids = new Set();
  const nodes = graph.nodes.map(node => {
    if (!node || typeof node.id !== 'string' || !node.id || ids.has(node.id) || !Object.hasOwn(LABELS, node.label)) throw new Error('VIEWER_GRAPH_INVALID');
    ids.add(node.id);
    const state = evidenceState(node);
    const kind = node.label === 'GuardAgent' ? 'agent' : node.label === 'GuardTask' ? 'task' :
      node.label.includes('Mcp') ? 'mcp' : node.label.includes('Resource') ? 'resource' :
      node.label.includes('Identity') || node.label === 'GuardPrincipal' ? 'identity' : 'evidence';
    return { data: { id: node.id, label: nodeName(node).slice(0, 88), kind: kindName(node.label), source: node },
      classes: `${kind} ${state.kind}` };
  });
  const states = new Map(graph.nodes.map(node => [node.id, evidenceState(node)]));
  const edges = graph.edges.map((edge, index) => {
    if (!edge || !ids.has(edge.source) || !ids.has(edge.target) || typeof edge.kind !== 'string') throw new Error('VIEWER_GRAPH_INVALID');
    const adjacent = [states.get(edge.source), states.get(edge.target)];
    const unavailable = adjacent.find(state => state.kind === 'unavailable');
    const conditional = adjacent.some(state => state.kind === 'conditional');
    const association = edge.kind.includes('CLOUD') || edge.kind.includes('MAPS');
    const status = unavailable?.label ?? (conditional ? 'approval required' : association ? 'access unknown' : '');
    return { data: { id: `edge-${index}`, source: edge.source, target: edge.target,
      label: `${edge.kind.replace(/^G_/, '').replaceAll('_', ' ').toLowerCase()}${status ? ` · ${status}` : ''}` },
      classes: `${association ? 'association' : 'declared'}${unavailable ? ' unavailable' : conditional ? ' conditional' : ''}` };
  });
  const policies = policyEvidenceRows(policyEvidence, graph);
  const seen = new Set();
  for (const row of policies) for (const candidate of row.candidates) {
    if (row.status !== 'complete' || !row.identityNode || !row.resourceNode) continue;
    const key = JSON.stringify([row.identityNode.id, row.resourceNode.id, row.action, candidate.hasCondition]);
    if (seen.has(key)) continue;
    seen.add(key);
    if (edges.length >= 5000) throw new Error('VIEWER_GRAPH_INVALID');
    edges.push({ data: { id: `policy-edge-${seen.size}`, source: row.identityNode.id, target: row.resourceNode.id,
      label: `${row.action} · policy candidate${candidate.hasCondition ? ' · condition unresolved' : ''}` }, classes: 'policy-candidate' });
  }
  return [...nodes, ...edges];
}

const POLICY_ACTIONS = Object.freeze({ CAN_READ: 's3:GetObject', CAN_WRITE: 's3:PutObject', CAN_LIST: 's3:ListBucket' });
const POLICY_REASONS = Object.freeze({
  no_candidate: 'No policy candidate observed', boundary_unresolved: 'Permissions boundary unresolved',
  unsupported: 'Unsupported policy expression', unsupported_policy: 'Unsupported policy expression', unsupported_action: 'Action outside collected policy mappings',
  stale: 'Policy evidence is stale', changed: 'Provider evidence changed',
  disabled: 'Policy collection disabled', collection_missing: 'Policy collection unavailable',
  identity_unresolved: 'Execution identity unresolved', identity_not_static: 'Execution identity is selected at runtime',
  cloud_unresolved: 'Cloud association unresolved', cloud_not_collected: 'Cloud inventory not collected',
  binding_ambiguous: 'Binding evidence is ambiguous', unsupported_binding: 'Binding is outside collected policy mappings',
  provider_missing: 'Provider evidence unavailable', collection_invalid: 'Policy collection could not be verified',
  evidence_invalid: 'Policy evidence could not be verified',
  ambiguous: 'Ambiguous policy evidence', malformed: 'Policy evidence unavailable',
  missing: 'Policy evidence unavailable', history_not_collected: 'Policy history not collected',
});
const policyText = value => typeof value === 'string' && value.length > 0 && value.length <= 4096;
/** Minimized presentation data; never display unrecognized provider properties. */
export function policyEvidenceRows(records = [], graph = null) {
  if (!Array.isArray(records) || records.length > 512) throw new Error('VIEWER_POLICY_INVALID');
  const byEntity = new Map(), byId = new Map(), links = new Set(), outgoing = new Map();
  if (graph) {
    if (!Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || graph.nodes.length > 2000 || graph.edges.length > 5000)
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
    if (!record || typeof record !== 'object' || record.assessment !== 'unknown' ||
        !['complete', 'unavailable', 'not_collected'].includes(record.status) ||
        !['taskId', 'deploymentId', 'executionBindingId', 'resourceBindingId', 'action'].every(key => policyText(record[key])) ||
        ![record.identityId, record.resourceId].every(value => value === null || policyText(value)) ||
        !(record.reason === null || policyText(record.reason)) ||
        !(record.observedAt === null || typeof record.observedAt === 'string' && Number.isFinite(Date.parse(record.observedAt))) ||
        !Array.isArray(record.candidates) || record.candidates.length > 1 ||
        record.status !== 'complete' && record.candidates.length ||
        record.status === 'complete' && (record.observedAt === null || record.reason !== (record.candidates.length ? null : 'no_candidate')))
      throw new Error('VIEWER_POLICY_INVALID');
    const candidates = record.candidates.map(candidate => {
      if (!candidate || POLICY_ACTIONS[candidate.relationship] !== record.action ||
          typeof candidate.hasCondition !== 'boolean' || candidate.resourceScope !== 'bucket_summary' ||
          !Array.isArray(candidate.conditionKeys) || candidate.conditionKeys.length > 128 ||
          candidate.conditionKeys.some(key => typeof key !== 'string' || !key || new TextEncoder().encode(key).byteLength > 256) ||
          candidate.hasCondition !== Boolean(candidate.conditionKeys.length)) throw new Error('VIEWER_POLICY_INVALID');
      return { relationship: candidate.relationship, hasCondition: candidate.hasCondition,
        conditionKeys: [...candidate.conditionKeys], resourceScope: 'bucket_summary' };
    });
    const task = byEntity.get(record.taskId), deployment = byEntity.get(record.deploymentId),
      execution = byEntity.get(record.executionBindingId), binding = byEntity.get(record.resourceBindingId),
      identity = byEntity.get(record.identityId), resource = byEntity.get(record.resourceId);
    if (graph && (task?.label !== 'GuardTask' || deployment?.label !== 'GuardDeployment' ||
        execution?.label !== 'GuardExecutionBinding' || binding?.label !== 'GuardResourceBinding' ||
        record.identityId !== null && identity?.label !== 'GuardExternalIdentity' ||
        record.resourceId !== null && resource?.label !== 'GuardExternalResource' ||
        !linked(task, deployment, 'G_ASSIGNED_TO') || !linked(execution, deployment, 'G_EXECUTES_FOR') ||
        identity && !linked(execution, identity, 'G_USES_IDENTITY') || resource && !linked(binding, resource, 'G_MAPS_TO'))) continue;
    if (graph && !targets(task, 'G_HAS_GRANT').some(grant => grant?.label === 'GuardGrant' &&
      targets(grant, 'G_FOR_TOOL').some(tool => tool?.label === 'GuardTool' && linked(execution, tool, 'G_EXECUTES_TOOL') &&
        execution.properties?.tool === tool.properties?.name && binding.properties?.tool === tool.properties?.name) &&
      targets(grant, 'G_TARGETS').some(selector => selector?.label === 'GuardResource' && linked(binding, selector, 'G_BINDS_SELECTOR')))) continue;
    if (graph && (!Array.isArray(binding.properties?.actions) || !binding.properties.actions.includes(record.action))) continue;
    const candidate = candidates[0];
    rows.push({ taskId: record.taskId, deploymentId: record.deploymentId,
      executionBindingId: record.executionBindingId, resourceBindingId: record.resourceBindingId,
      action: record.action, status: record.status, assessment: 'unknown', observedAt: record.observedAt,
      label: record.status === 'complete' ? candidate ? candidate.hasCondition ? 'Conditional policy candidate' : 'Policy candidate' : 'No policy candidate observed' :
        POLICY_REASONS[record.reason] ?? (record.status === 'not_collected' ? 'Policy evidence not collected' : 'Policy evidence unavailable'),
      candidates, identityNode: identity ?? null, resourceNode: resource ?? null,
      task: task ? nodeName(task) : record.taskId, deployment: deployment ? nodeName(deployment) : record.deploymentId,
      execution: execution ? nodeName(execution) : record.executionBindingId,
      target: resource ? nodeName(resource) : 'Target not resolved',
      bindingScope: typeof binding?.properties.scope === 'string' ? binding.properties.scope : 'Unknown',
      resourceKind: typeof resource?.properties.kind === 'string' ? resource.properties.kind : 'Unknown',
    });
  }
  return rows;
}
export function agentOptions(agents) {
  const owners = new Set(), environments = new Set();
  for (const agent of agents) {
    if (typeof agent.ownerId === 'string') owners.add(agent.ownerId);
    for (const environment of agent.environments ?? []) if (typeof environment === 'string') environments.add(environment);
  }
  return { owners: [...owners].sort(), environments: [...environments].sort() };
}
export function initialExplanation(access) {
  const task = access.tasks?.[0];
  const grant = access.grants?.find(item => item.taskId === task?.taskId || item.task_id === task?.taskId) ?? access.grants?.[0];
  return { taskId: task?.taskId ?? '', tool: grant?.tool ?? '', resourceId: grant?.resources?.[0] ?? '' };
}
export function shortReference(value) {
  return typeof value === 'string' && value.length > 25 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value ?? 'Unknown';
}
export function displayTime(value) {
  if (typeof value === 'number') value = new Date(value < 1e12 ? value * 1000 : value).toISOString();
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }) : 'Not observed';
}
/** Component freshness never inherits the enclosing snapshot's capture time. */
export function componentHealth(coverage) {
  const value = coverage && typeof coverage === 'object' ? coverage : {};
  const status = typeof coverage === 'string' ? coverage : typeof value.status === 'string' ? value.status : 'unknown';
  const captured = typeof value.observedAt === 'string' && Number.isFinite(Date.parse(value.observedAt));
  const recent = captured && value.stale === false;
  const age = captured && Number.isFinite(value.ageSeconds) && value.ageSeconds >= 0 ? value.ageSeconds : null;
  return {
    status: status.replaceAll('_', ' '),
    observedAt: captured ? value.observedAt : null,
    observedLabel: captured ? displayTime(value.observedAt) : 'Capture time unknown',
    freshness: !captured ? 'Timestamp unknown' : value.stale === true ? 'Stale capture' : recent ? 'Recent capture' : 'Freshness unknown',
    tone: recent ? 'green' : 'amber',
    ageLabel: age === null ? null : age < 60 ? `${Math.floor(age)} sec old at query` : age < 3600 ? `${Math.floor(age / 60)} min old at query` : `${Math.floor(age / 3600)} hr old at query`,
  };
}
export class ReferenceError extends Error {
  constructor(code, status = 0) { super(code); this.code = code; this.status = status; }
}
/** Ending a page session aborts transport and discards even an already-queued result. */
export function createQuerySession(invoke) {
  const controller = new AbortController();
  const ended = () => new ReferenceError('VIEWER_SESSION_ENDED');
  return Object.freeze({
    close: () => controller.abort(),
    async query(operation, args = {}) {
      if (controller.signal.aborted) throw ended();
      try {
        const result = await invoke(operation, args, { signal: controller.signal });
        if (controller.signal.aborted) throw ended();
        return result;
      } catch (error) {
        if (controller.signal.aborted) throw ended();
        throw error;
      }
    },
  });
}
export function errorMessage(error) {
  if (error?.status === 401) return 'Your reference credential was not accepted. Connect again with a valid credential.';
  if (error?.status === 403) return 'This reference operation is outside your authorized scope.';
  if (error?.code?.includes('NOT_FOUND')) return 'That item is unavailable in your authorized inventory.';
  if (error?.code?.includes('LIMIT') || error?.status === 413) return 'This view is too large. Narrow the source or agent selection and try again.';
  if (error?.name === 'AbortError' || error?.code?.includes('TIMEOUT')) return 'The reference service took too long. Try again shortly.';
  return 'The reference service could not complete this request. Try again shortly.';
}
const CSRF = /^agm_csrf_v1\.[A-Za-z0-9_-]{43}$/;
function csrfHeaders(token) {
  if (typeof token !== 'string' || !CSRF.test(token)) throw new ReferenceError('VIEWER_CSRF_INVALID', 401);
  return { 'Content-Type': 'application/json', 'X-CSRF-Token': token };
}
function exactObject(value, names) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
}
async function requestJSON(path, request, maximum, { fetchImpl = fetch, timeoutMs = 12000, signal } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new ReferenceError('VIEWER_REQUEST_INVALID');
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    if (controller.signal.aborted) throw new DOMException('aborted', 'AbortError');
    const response = await fetchImpl(path, { ...request, cache: 'no-store', redirect: 'error',
      referrerPolicy: 'no-referrer', signal: controller.signal });
    // A known authentication denial ends the session even when its body is invalid or never finishes.
    if (response.status === 401 || response.status === 403) {
      void response.body?.cancel().catch(() => {});
      throw new ReferenceError('REFERENCE_UNAVAILABLE', response.status);
    }
    const declared = response.headers.get('content-length');
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) throw new ReferenceError('VIEWER_RESPONSE_LIMIT');
    if (response.redirected || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '') ||
        !response.body) throw new ReferenceError('VIEWER_RESPONSE_INVALID');
    const chunks = []; let length = 0;
    const reader = response.body.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > maximum) { await reader.cancel(); throw new ReferenceError('VIEWER_RESPONSE_LIMIT'); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const joined = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
    let body;
    try { body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(joined)); }
    catch { throw new ReferenceError('VIEWER_RESPONSE_INVALID'); }
    if (!response.ok) throw new ReferenceError(typeof body?.error === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(body.error) ? body.error : 'REFERENCE_UNAVAILABLE', response.status);
    return body;
  } finally { clearTimeout(timer); controller.abort(); signal?.removeEventListener('abort', cancel); }
}
function queryResult(body, operation) {
  if (!body || body.operation !== operation || !body.data || typeof body.data !== 'object' || Array.isArray(body.data)) throw new ReferenceError('VIEWER_RESPONSE_INVALID');
  return body;
}
export async function queryReference(token, operation, args = {}, options = {}) {
  if (!OPERATIONS.includes(operation)) throw new ReferenceError('VIEWER_OPERATION_INVALID');
  if (typeof token !== 'string' || !/^agm_v1\.[A-Za-z0-9_-]{43}$/.test(token)) throw new ReferenceError('VIEWER_CREDENTIAL_INVALID', 401);
  return queryResult(await requestJSON('/v1/query', { method: 'POST', credentials: 'omit',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ operation, args }) }, 4 * 1024 * 1024, options), operation);
}
export async function queryCompanySession(csrfToken, operation, args = {}, options = {}) {
  if (!OPERATIONS.includes(operation)) throw new ReferenceError('VIEWER_OPERATION_INVALID');
  return queryResult(await requestJSON('/v1/query', { method: 'POST', credentials: 'same-origin',
    headers: csrfHeaders(csrfToken), body: JSON.stringify({ operation, args }) }, 4 * 1024 * 1024, options), operation);
}
export async function readCompanySession({ now = Date.now, ...options } = {}) {
  const value = await requestJSON('/auth/session', { method: 'GET', credentials: 'same-origin' }, 16 * 1024, options);
  if (exactObject(value, ['mode']) && value.mode === 'bearer') return Object.freeze({ mode: 'bearer' });
  if (!exactObject(value, ['mode', 'authenticated', 'csrfToken', 'expiresAt']) || value.mode !== 'oidc' ||
      typeof value.authenticated !== 'boolean' || typeof value.csrfToken !== 'string' || !CSRF.test(value.csrfToken) || typeof value.expiresAt !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value.expiresAt) || !Number.isFinite(Date.parse(value.expiresAt)))
    throw new ReferenceError('VIEWER_SESSION_INVALID');
  if (Date.parse(value.expiresAt) <= now()) throw new ReferenceError('VIEWER_SESSION_EXPIRED', 401);
  return Object.freeze({ mode: 'oidc', authenticated: value.authenticated, csrfToken: value.csrfToken, expiresAt: value.expiresAt });
}
export async function startCompanyLogin(csrfToken, options = {}) {
  const value = await requestJSON('/auth/login', { method: 'POST', credentials: 'same-origin',
    headers: csrfHeaders(csrfToken), body: '{}' }, 16 * 1024, options);
  if (!exactObject(value, ['authorizationUrl']) || typeof value.authorizationUrl !== 'string' || value.authorizationUrl.length > 8192)
    throw new ReferenceError('VIEWER_SESSION_INVALID');
  let url;
  try { url = new URL(value.authorizationUrl); } catch { throw new ReferenceError('VIEWER_SESSION_INVALID'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href !== value.authorizationUrl)
    throw new ReferenceError('VIEWER_SESSION_INVALID');
  return url.href;
}
export async function endCompanySession(csrfToken, options = {}) {
  const value = await requestJSON('/auth/logout', { method: 'POST', credentials: 'same-origin',
    headers: csrfHeaders(csrfToken), body: '{}' }, 16 * 1024, options);
  if (!exactObject(value, ['ok']) || value.ok !== true) throw new ReferenceError('VIEWER_SESSION_INVALID');
}
/** An explicit retry can confirm a lost logout response without reopening inventory. */
export async function retryCompanyLogout(options = {}) {
  let value = await readCompanySession(options);
  if (value.mode !== 'oidc') throw new ReferenceError('VIEWER_SESSION_INVALID');
  if (value.authenticated) {
    await endCompanySession(value.csrfToken, options);
    value = await readCompanySession(options);
  }
  if (value.mode !== 'oidc' || value.authenticated) throw new ReferenceError('VIEWER_LOGOUT_UNCONFIRMED');
  return value;
}
/** Authentication loss aborts sibling requests before their results can reach the page. */
export function createCompanyQuerySession(csrfToken, { onEnded = () => {}, ...options } = {}) {
  let ended = false;
  const session = createQuerySession(async (operation, args, { signal }) => {
    try { return await queryCompanySession(csrfToken, operation, args, { ...options, signal }); }
    catch (error) {
      if ([401, 403].includes(error?.status) && !ended) { ended = true; session.close(); onEnded(); }
      throw error;
    }
  });
  return Object.freeze({ close() { ended = true; session.close(); }, query: session.query });
}
/** Returning to a company workspace always revalidates before showing its cached data. */
export function watchCompanySession({ expiresAt, onInvalidate, onRevalidate, windowImpl = window,
  documentImpl = document, now = Date.now, schedule = setTimeout, cancel = clearTimeout }) {
  let ended = false, invalidated = false, revalidating = false, reason, timer;
  const invalidate = value => { if (!ended && !invalidated) { invalidated = true; reason = value; onInvalidate(value); } };
  const revalidate = () => { if (!ended && !revalidating) { revalidating = true; onRevalidate(reason); } };
  const visibility = () => {
    if (documentImpl.visibilityState === 'hidden') invalidate('hidden');
    else if (invalidated) revalidate();
  };
  const pageshow = event => { if (event.persisted) { invalidate('restored'); revalidate(); } };
  const arm = () => {
    const remaining = Date.parse(expiresAt) - now();
    timer = schedule(() => {
      if (ended) return;
      if (Date.parse(expiresAt) <= now()) { invalidate('expired'); revalidate(); } else arm();
    }, Math.max(0, Math.min(remaining, 2147483647)));
  };
  if (!Number.isFinite(Date.parse(expiresAt))) throw new ReferenceError('VIEWER_SESSION_INVALID');
  documentImpl.addEventListener('visibilitychange', visibility); windowImpl.addEventListener('pageshow', pageshow);
  arm(); visibility();
  return () => { ended = true; cancel(timer); documentImpl.removeEventListener('visibilitychange', visibility); windowImpl.removeEventListener('pageshow', pageshow); };
}
