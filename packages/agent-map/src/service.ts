import { canonicalJson, immutableJson, type Json } from '@shieldaai/agent-guard';
import { MapQueryError, mapIdentifier, validateReadScope, type JsonObject, type JsonValue,
  type MapEdge, type MapNode, type MapPolicyEvidence, type MapProjection, type MapSource, type MapStore,
  type MapView, type ReadScope } from './types.js';

export const MAP_OPERATIONS = ['list_agents', 'get_agent_access', 'explain_access',
  'find_agents_with_access', 'get_changes', 'get_inventory_health'] as const;
export type MapOperation = typeof MAP_OPERATIONS[number];
const idSchema = { type: 'string', minLength: 1, maxLength: 4096 };
const limitSchema = { type: 'integer', minimum: 1, maximum: 100 };
const schema = (properties: Record<string, unknown>, required: readonly string[] = []): JsonObject =>
  immutableJson({ type: 'object', additionalProperties: false, properties, required }) as JsonObject;
export const MAP_INPUT_SCHEMAS: Readonly<Record<MapOperation, JsonObject>> = Object.freeze({
  list_agents: schema({ search: { type: 'string', maxLength: 256 }, sourceId: idSchema,
    ownerId: idSchema, environment: idSchema, limit: limitSchema }),
  get_agent_access: schema({ sourceId: idSchema, agentId: idSchema }, ['sourceId', 'agentId']),
  explain_access: schema({ sourceId: idSchema, taskId: idSchema, tool: idSchema, resourceId: idSchema },
    ['sourceId', 'taskId', 'tool', 'resourceId']),
  find_agents_with_access: schema({ resourceRef: idSchema,
    action: { type: 'string', minLength: 3, maxLength: 256, pattern: '^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$' },
    sourceId: idSchema, limit: limitSchema }, ['resourceRef', 'action']),
  get_changes: schema({ sourceId: idSchema, since: idSchema }, ['sourceId']),
  get_inventory_health: schema({ sourceId: idSchema }),
});

export interface MapResponse {
  readonly operation: MapOperation;
  readonly observedAt: string;
  readonly data: JsonObject;
  readonly graph?: { readonly nodes: readonly MapNode[]; readonly edges: readonly MapEdge[] };
}
export interface MapServiceOptions {
  readonly clock?: () => number;
  readonly maxResponseBytes?: number;
  readonly maxGraphNodes?: number;
  readonly maxGraphEdges?: number;
  readonly queryTimeoutMs?: number;
  readonly staleAfterSeconds?: number;
}

function fail(code = 'MAP_REQUEST_INVALID'): never { throw new MapQueryError(code); }
function integer(value: unknown, fallback: number, maximum: number, minimum = 1): number {
  const chosen = value === undefined ? fallback : value;
  if (typeof chosen !== 'number' || !Number.isSafeInteger(chosen) || chosen < minimum || chosen > maximum) fail('MAP_CONFIG_INVALID');
  return chosen;
}
export function validateQueryArguments(operation: unknown, value: unknown): Readonly<Record<string, JsonValue>> {
  if (typeof operation !== 'string' || !(MAP_OPERATIONS as readonly string[]).includes(operation)) fail();
  let copied: Json;
  try { copied = immutableJson(value, 4, 512, 64 * 1024); }
  catch { return fail(); }
  if (!copied || typeof copied !== 'object' || Array.isArray(copied)) fail();
  const args = copied as Record<string, JsonValue>;
  const definition = MAP_INPUT_SCHEMAS[operation as MapOperation];
  const properties = definition.properties as JsonObject;
  const required = definition.required as readonly string[];
  if (Object.keys(args).some(key => !Object.hasOwn(properties, key)) || required.some(key => !Object.hasOwn(args, key))) fail();
  for (const [key, item] of Object.entries(args)) {
    if (key === 'limit') {
      if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 1 || item > 100) fail();
    } else if (key === 'search') {
      if (typeof item !== 'string' || [...item].length > 256 || item.includes('\0') ||
          /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(item)) fail();
    } else {
      mapIdentifier(item);
      if (key === 'action' && (typeof item !== 'string' || item.length > 256 || !/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(item))) fail();
    }
  }
  return args;
}

const string = (node: MapNode, key: string): string | null => typeof node.properties[key] === 'string' ? node.properties[key] as string : null;
const number = (node: MapNode, key: string): number | null => typeof node.properties[key] === 'number' ? node.properties[key] as number : null;
const strings = (node: MapNode, key: string): readonly string[] => Array.isArray(node.properties[key]) ? (node.properties[key] as readonly JsonValue[]).filter((v): v is string => typeof v === 'string') : [];
const matching = (node: MapNode, id: string, native: string): boolean => node.entityId === id || string(node, native) === id;
const unique = <T>(values: readonly T[]): T[] => [...new Set(values)];
interface GraphIndex {
  nodes: Map<string, MapNode>;
  outgoing: Map<string, Map<MapEdge['kind'], string[]>>;
  incoming: Map<string, Map<MapEdge['kind'], string[]>>;
}
/** Count authorized work and elapsed monotonic time, including synchronous projection. */
class QueryWork {
  readonly #deadline: number;
  readonly #indices = new WeakMap<MapProjection, GraphIndex>();
  readonly #policy = new WeakMap<MapProjection, readonly MapPolicyEvidence[]>();
  #remaining = 200_000;
  #evidenceBytes: number;
  #evidenceCount = 0;
  constructor(timeout: number, maxBytes: number) { this.#deadline = performance.now() + timeout; this.#evidenceBytes = maxBytes; }
  step(amount = 1): void {
    if (performance.now() >= this.#deadline) fail('MAP_TIMEOUT');
    this.#remaining -= amount;
    if (this.#remaining < 0) fail('MAP_LIMIT_EXCEEDED');
  }
  index(projection: MapProjection): GraphIndex {
    this.step();
    const existing = this.#indices.get(projection); if (existing) return existing;
    this.step(projection.nodes.length + projection.edges.length);
    const result: GraphIndex = { nodes: new Map(), outgoing: new Map(), incoming: new Map() };
    for (const node of projection.nodes) result.nodes.set(node.id, node);
    const add = (map: GraphIndex['outgoing'], from: string, kind: MapEdge['kind'], to: string): void => {
      let kinds = map.get(from); if (!kinds) { kinds = new Map(); map.set(from, kinds); }
      const items = kinds.get(kind); if (items) items.push(to); else kinds.set(kind, [to]);
    };
    for (const edge of projection.edges) { add(result.outgoing, edge.source, edge.kind, edge.target); add(result.incoming, edge.target, edge.kind, edge.source); }
    this.#indices.set(projection, result); this.step(); return result;
  }
  evidence(value: JsonObject): JsonObject {
    this.step();
    if (++this.#evidenceCount > 1000) fail('MAP_LIMIT_EXCEEDED');
    let copy: JsonObject;
    try { copy = immutableJson(value, 24, 25_000, this.#evidenceBytes) as JsonObject; }
    catch { return fail('MAP_LIMIT_EXCEEDED'); }
    this.#evidenceBytes -= Buffer.byteLength(JSON.stringify(copy));
    this.step(); return copy;
  }
  policy(projection: MapProjection): readonly MapPolicyEvidence[] {
    const existing = this.#policy.get(projection); if (existing) return existing;
    const result = validatedPolicyEvidence(projection, this);
    this.#policy.set(projection, result); return result;
  }
}
function connected(projection: MapProjection, ids: Set<string>, kind: MapEdge['kind'], work: QueryWork, reverse = false): MapNode[] {
  const index = work.index(projection), selected = new Set<string>();
  work.step(ids.size);
  for (const id of ids) {
    const targets = (reverse ? index.incoming : index.outgoing).get(id)?.get(kind) ?? [];
    work.step(targets.length); for (const target of targets) selected.add(target);
  }
  return [...selected].flatMap(id => index.nodes.get(id) ? [index.nodes.get(id)!] : []);
}
const nodeIds = (nodes: readonly MapNode[]): Set<string> => new Set(nodes.map(node => node.id));
function deployments(projection: MapProjection, agent: MapNode, work: QueryWork): MapNode[] {
  return connected(projection, new Set([agent.id]), 'G_INSTANCE_OF', work, true).filter(node => node.label === 'GuardDeployment');
}
function agentSummary(source: MapSource, projection: MapProjection, agent: MapNode, work: QueryWork): JsonObject {
  const items = deployments(projection, agent, work).map(node => ({ id: node.entityId,
    deploymentId: string(node, 'deployment_id'), environment: string(node, 'environment') }));
  return { id: agent.entityId, agentId: string(agent, 'agent_id'), sourceId: source.id,
    name: string(agent, 'name'), ownerId: string(agent, 'owner_id'), teamId: string(agent, 'team_id'),
    environments: unique(items.map(item => item.environment).filter((item): item is string => item !== null)).sort(),
    deployments: items };
}
function taskSummary(node: MapNode): JsonObject {
  return { id: node.entityId, taskId: string(node, 'task_id'), principalId: string(node, 'principal_id'),
    revoked: node.properties.revoked ?? null, sensitive: node.properties.sensitive ?? null,
    usage: { calls: number(node, 'calls'), concurrent: number(node, 'concurrent'), spent: number(node, 'spent'), reserved: number(node, 'reserved') },
    budget: { maxCalls: number(node, 'max_calls'), maxConcurrent: number(node, 'max_concurrent'), maxCost: number(node, 'max_cost'), deadline: number(node, 'deadline') } };
}
function grantSummary(node: MapNode): JsonObject {
  return { id: node.entityId, taskId: string(node, 'task_id'), tool: string(node, 'tool'),
    resources: strings(node, 'resources'), evidenceKind: 'declared', assessment: 'unknown' };
}
function receipt(source: MapSource, projection = source.current): JsonObject {
  return { sourceId: source.id, tenantId: source.tenantId, profile: source.profile,
    projectionId: projection.id, snapshotId: projection.snapshotId, generatedAt: projection.generatedAt,
    coverage: projection.coverage as unknown as JsonObject };
}
function findSource(view: MapView, id: string): MapSource {
  const source = view.sources.find(item => item.id === id);
  if (!source) fail('MAP_NOT_FOUND');
  return source;
}
function findAgent(projection: MapProjection, id: string): MapNode {
  const agent = projection.nodes.find(node => node.label === 'GuardAgent' && matching(node, id, 'agent_id'));
  if (!agent) fail('MAP_NOT_FOUND');
  return agent;
}

/** Keep the selected agent's neighborhood explicit; never expand through shared tools to other agents. */
function focus(projection: MapProjection, agent: MapNode, work: QueryWork): { nodes: MapNode[]; edges: MapEdge[] } {
  const deployment = deployments(projection, agent, work);
  const tasks = connected(projection, nodeIds(deployment), 'G_ASSIGNED_TO', work, true);
  const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true);
  const grants = connected(projection, nodeIds(tasks), 'G_HAS_GRANT', work);
  const resources = connected(projection, nodeIds(grants), 'G_TARGETS', work);
  const resourceBindings = connected(projection, nodeIds(resources), 'G_BINDS_SELECTOR', work, true);
  const tools = [...connected(projection, nodeIds(grants), 'G_FOR_TOOL', work), ...connected(projection, nodeIds(executions), 'G_EXECUTES_TOOL', work)];
  const connections = connected(projection, nodeIds(executions), 'G_VIA_CONNECTION', work), toolIds = nodeIds(tools);
  const operations = connected(projection, nodeIds(connections), 'G_EXPOSES_OPERATION', work).filter(operation =>
    connected(projection, new Set([operation.id]), 'G_OPERATION_TOOL', work).some(tool => toolIds.has(tool.id)));
  const selected = nodeIds([agent, ...deployment, ...tasks, ...executions, ...grants, ...resources, ...resourceBindings,
    ...tools, ...connections, ...operations, ...connected(projection, nodeIds(tasks), 'G_ACTS_AS', work),
    ...connected(projection, nodeIds(executions), 'G_USES_IDENTITY', work), ...connected(projection, nodeIds(resourceBindings), 'G_MAPS_TO', work)]);
  work.step(projection.nodes.length + projection.edges.length);
  return { nodes: projection.nodes.filter(node => selected.has(node.id)),
    edges: projection.edges.filter(edge => selected.has(edge.source) && selected.has(edge.target)) };
}

const POLICY_ACTIONS: Readonly<Record<string, string>> = Object.freeze({
  's3:GetObject': 'CAN_READ', 's3:PutObject': 'CAN_WRITE', 's3:ListBucket': 'CAN_LIST',
});
const POLICY_REASONS = Object.freeze({
  unavailable: ['binding_ambiguous', 'cloud_unresolved', 'provider_missing', 'collection_invalid',
    'stale', 'changed', 'boundary_unresolved', 'unsupported_policy', 'evidence_invalid'],
  not_collected: ['unsupported_action', 'identity_not_static', 'unsupported_binding',
    'cloud_not_collected', 'collection_missing', 'disabled'],
});
const POLICY_FIELDS = ['taskId', 'deploymentId', 'executionBindingId', 'resourceBindingId',
  'identityId', 'resourceId', 'action', 'status', 'reason', 'observedAt', 'assessment', 'candidates'].sort().join(',');
function policyObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function policyTime(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const instant = Date.parse(value);
  return Number.isFinite(instant) && instant >= 0 && instant <= 253_402_300_799_999 && new Date(instant).toISOString() === value;
}
function comparePolicyKeys(a: string, b: string): number {
  let left = 0, right = 0;
  while (left < a.length && right < b.length) {
    const ac = a.codePointAt(left)!, bc = b.codePointAt(right)!;
    if (ac !== bc) return ac - bc;
    left += ac > 0xffff ? 2 : 1; right += bc > 0xffff ? 2 : 1;
  }
  return (a.length - left) - (b.length - right);
}
/** Custom stores receive the same closed output contract and binding-path checks. */
function validatedPolicyEvidence(projection: MapProjection, work: QueryWork): readonly MapPolicyEvidence[] {
  const rawInput = projection.policyEvidence;
  if (rawInput === undefined) return [];
  if (!Array.isArray(rawInput)) fail('MAP_UNAVAILABLE');
  if (rawInput.length > 512) fail('MAP_LIMIT_EXCEEDED');
  let input: readonly MapPolicyEvidence[];
  try { input = immutableJson(rawInput, 8, 100_000, 4 * 1024 * 1024) as unknown as readonly MapPolicyEvidence[]; }
  catch { return fail('MAP_UNAVAILABLE'); }
  work.step(projection.nodes.length);
  const entities = new Map(projection.nodes.map(node => [node.entityId, node]));
  if (input.length && entities.size !== projection.nodes.length) fail('MAP_UNAVAILABLE');
  const seen = new Set<string>(), result: MapPolicyEvidence[] = [];
  let materializedBytes = 0;
  const link = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length); return targets.includes(target.id);
  };
  const exactLink = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length); return targets.length === 1 && targets[0] === target.id;
  };
  // Tasks may have several grants and grants several selectors, but the
  // particular pair proving this record must not have duplicate relationships.
  const uniqueLink = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length); return targets.filter(id => id === target.id).length === 1;
  };
  const endpoint = (id: unknown, label: MapNode['label']): MapNode => {
    mapIdentifier(id, 'MAP_UNAVAILABLE'); const node = entities.get(id as string);
    if (!node || node.label !== label) fail('MAP_UNAVAILABLE'); return node;
  };
  for (const raw of input) {
    work.step();
    if (!policyObject(raw) || Object.keys(raw).sort().join(',') !== POLICY_FIELDS ||
        raw.assessment !== 'unknown' || typeof raw.action !== 'string' || raw.action.length > 4096 ||
        !/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(raw.action) ||
        (raw.observedAt !== null && !policyTime(raw.observedAt))) fail('MAP_UNAVAILABLE');
    if (!Array.isArray(raw.candidates) || raw.candidates.length > 1) fail('MAP_UNAVAILABLE');
    if (raw.status === 'complete') {
      if (!policyTime(raw.observedAt) || !POLICY_ACTIONS[raw.action] ||
          raw.reason !== (raw.candidates.length ? null : 'no_candidate')) fail('MAP_UNAVAILABLE');
    } else if ((raw.status !== 'unavailable' && raw.status !== 'not_collected') ||
        !POLICY_REASONS[raw.status].includes(raw.reason as string) || raw.candidates.length) fail('MAP_UNAVAILABLE');
    for (const candidate of raw.candidates) {
      if (!policyObject(candidate) || Object.keys(candidate).sort().join(',') !== 'conditionKeys,hasCondition,relationship,resourceScope' ||
          candidate.relationship !== POLICY_ACTIONS[raw.action] || candidate.resourceScope !== 'bucket_summary' ||
          typeof candidate.hasCondition !== 'boolean' || !Array.isArray(candidate.conditionKeys) || candidate.conditionKeys.length > 128) fail('MAP_UNAVAILABLE');
      for (const key of candidate.conditionKeys) {
        work.step(); mapIdentifier(key, 'MAP_UNAVAILABLE');
        if (Buffer.byteLength(key as string, 'utf8') > 256 || /[\u0000-\u001f]/.test(key as string)) fail('MAP_UNAVAILABLE');
      }
      if (candidate.hasCondition !== !!candidate.conditionKeys.length ||
          JSON.stringify(candidate.conditionKeys) !== JSON.stringify([...new Set(candidate.conditionKeys as string[])].sort(comparePolicyKeys))) fail('MAP_UNAVAILABLE');
    }
    const task = endpoint(raw.taskId, 'GuardTask'), deployment = endpoint(raw.deploymentId, 'GuardDeployment');
    const execution = endpoint(raw.executionBindingId, 'GuardExecutionBinding'), resource = endpoint(raw.resourceBindingId, 'GuardResourceBinding');
    const tool = string(execution, 'tool');
    if (!tool || string(resource, 'tool') !== tool || !strings(resource, 'actions').includes(raw.action) ||
        !link(task, deployment, 'G_ASSIGNED_TO') || !link(execution, deployment, 'G_EXECUTES_FOR')) fail('MAP_UNAVAILABLE');
    const tools = connected(projection, new Set([execution.id]), 'G_EXECUTES_TOOL', work).filter(node => node.label === 'GuardTool' && string(node, 'name') === tool);
    const grants = connected(projection, new Set([task.id]), 'G_HAS_GRANT', work).filter(node => node.label === 'GuardGrant' && string(node, 'tool') === tool);
    const selectors = connected(projection, new Set([resource.id]), 'G_BINDS_SELECTOR', work).filter(node =>
      node.label === 'GuardResource' && string(node, 'tool') === tool && string(node, 'resource_id') === string(resource, 'resource_ref'));
    if (!grants.some(grant => strings(grant, 'resources').includes(string(resource, 'resource_ref') ?? '') &&
        (raw.status !== 'complete' || uniqueLink(task, grant, 'G_HAS_GRANT')) &&
        tools.some(toolNode => (raw.status === 'complete' ? exactLink : link)(grant, toolNode, 'G_FOR_TOOL')) &&
        selectors.some(selector => (raw.status === 'complete' ? uniqueLink : link)(grant, selector, 'G_TARGETS')))) fail('MAP_UNAVAILABLE');
    for (const [key, label, relation, owner] of [
      ['identityId', 'GuardExternalIdentity', 'G_USES_IDENTITY', execution],
      ['resourceId', 'GuardExternalResource', 'G_MAPS_TO', resource],
    ] as const) {
      if (raw[key] === null) { if (raw.status === 'complete') fail('MAP_UNAVAILABLE'); continue; }
      const target = endpoint(raw[key], label);
      if (!(raw.status === 'complete' ? exactLink(owner, target, relation) : link(owner, target, relation))) fail('MAP_UNAVAILABLE');
    }
    if (raw.status === 'complete') {
      const agents = connected(projection, new Set([deployment.id]), 'G_INSTANCE_OF', work).filter(node => node.label === 'GuardAgent');
      if (agents.length !== 1 || !exactLink(deployment, agents[0]!, 'G_INSTANCE_OF') ||
          string(execution, 'identity_selection') !== 'static' ||
          !exactLink(task, deployment, 'G_ASSIGNED_TO') || !exactLink(execution, deployment, 'G_EXECUTES_FOR') ||
          tools.length !== 1 || !exactLink(execution, tools[0]!, 'G_EXECUTES_TOOL') || selectors.length !== 1 ||
          !exactLink(resource, selectors[0]!, 'G_BINDS_SELECTOR')) fail('MAP_UNAVAILABLE');
    }
    const identity = JSON.stringify([raw.taskId, raw.deploymentId, raw.executionBindingId, raw.resourceBindingId, raw.action]);
    if (seen.has(identity)) fail('MAP_UNAVAILABLE'); seen.add(identity);
    try {
      const copy = immutableJson(raw, 6, 1024, 64 * 1024) as unknown as MapPolicyEvidence;
      materializedBytes += Buffer.byteLength(JSON.stringify(copy));
      if (materializedBytes > 4 * 1024 * 1024) fail('MAP_LIMIT_EXCEEDED');
      result.push(copy);
    }
    catch { fail('MAP_LIMIT_EXCEEDED'); }
  }
  return result;
}
function policyCoverage(records: readonly MapPolicyEvidence[]): JsonObject {
  const complete = records.filter(item => item.status === 'complete').length;
  const observed = records.flatMap(item => item.observedAt === null ? [] : [item.observedAt]).sort();
  return { status: !records.length || records.every(item => item.status === 'not_collected') ? 'not_collected' :
    complete === records.length ? 'complete' : complete ? 'partial' : 'unavailable',
    observedAt: observed[0] ?? null, assessment: 'unknown' };
}
function selectedPolicy(projection: MapProjection, work: QueryWork, options: {
  nodes?: readonly MapNode[]; task?: MapNode; executions?: readonly MapNode[]; resources?: readonly MapNode[]; action?: string;
} = {}): readonly MapPolicyEvidence[] {
  const ids = options.nodes ? new Set(options.nodes.map(node => node.entityId)) : undefined;
  const executions = options.executions ? new Set(options.executions.map(node => node.entityId)) : undefined;
  const resources = options.resources ? new Set(options.resources.map(node => node.entityId)) : undefined;
  return work.policy(projection).filter(record => {
    work.step(); return (!ids || [record.taskId, record.deploymentId, record.executionBindingId, record.resourceBindingId,
      record.identityId, record.resourceId].every(id => id === null || ids.has(id))) &&
      (!options.task || record.taskId === options.task.entityId) && (!executions || executions.has(record.executionBindingId)) &&
      (!resources || resources.has(record.resourceBindingId)) && (!options.action || record.action === options.action);
  });
}

function knownBlockers(task: MapNode, tool: MapNode | undefined, now: number): string[] {
  const blockers: string[] = [];
  if (task.properties.revoked === true) blockers.push('task_revoked');
  const deadline = number(task, 'deadline');
  if (deadline !== null && now >= deadline) blockers.push('deadline_expired');
  const calls = number(task, 'calls'), maxCalls = number(task, 'max_calls');
  if (calls !== null && maxCalls !== null && calls >= maxCalls) blockers.push('call_budget_exhausted');
  const concurrent = number(task, 'concurrent'), maxConcurrent = number(task, 'max_concurrent');
  if (concurrent !== null && maxConcurrent !== null && concurrent >= maxConcurrent) blockers.push('concurrency_full_at_capture');
  const spent = number(task, 'spent'), reserved = number(task, 'reserved'), maxCost = number(task, 'max_cost');
  const cost = tool ? number(tool, 'max_cost') : null;
  if (spent !== null && reserved !== null && maxCost !== null && cost !== null && spent + reserved + cost > maxCost) blockers.push('cost_budget_exceeded');
  if (tool?.properties.control_plane === true && task.properties.allow_control_plane === false) blockers.push('control_plane_disabled');
  return blockers;
}
function externalEvidence(projection: MapProjection, task: MapNode, toolName: string, resourceId: string, work: QueryWork,
  policySelection: { action?: string; resourceBindingId?: string } = {}): JsonObject {
  const deployment = connected(projection, new Set([task.id]), 'G_ASSIGNED_TO', work);
  const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true)
    .filter(node => string(node, 'tool') === toolName);
  work.step(projection.nodes.length);
  const resources = projection.nodes.filter(node => node.label === 'GuardResourceBinding' &&
    string(node, 'tool') === toolName && string(node, 'resource_ref') === resourceId &&
    (!policySelection.resourceBindingId || node.entityId === policySelection.resourceBindingId));
  const policy = selectedPolicy(projection, work, { task, executions, resources,
    ...(policySelection.action ? { action: policySelection.action } : {}) });
  return {
    executionBindings: executions.map(node => ({ id: node.entityId, ...node.properties,
      identities: connected(projection, new Set([node.id]), 'G_USES_IDENTITY', work).map(identity => ({ ...identity.properties })),
      connections: connected(projection, new Set([node.id]), 'G_VIA_CONNECTION', work).map(connection => ({ ...connection.properties })) })),
    resourceBindings: resources.map(node => ({ id: node.entityId, ...node.properties,
      targets: connected(projection, new Set([node.id]), 'G_MAPS_TO', work).map(target => ({ ...target.properties })) })),
    policyEvidence: policy as unknown as readonly JsonObject[], policyCoverage: policyCoverage(policy),
    assessment: 'unknown',
    limitations: ['Host bindings and provider inventory are evidence, not effective cloud permissions.',
      'Container matches do not establish exact object or prefix access; missing evidence does not establish denial.'],
  };
}
const COMMON_UNKNOWN = ['live_authorization', 'request_arguments_and_resolution', 'custom_policy', 'backend_authorization', 'action_approval'];
function explain(projection: MapProjection, scope: ReadScope, task: MapNode, toolName: string, resourceId: string, now: number, work: QueryWork,
  policySelection: { action?: string; resourceBindingId?: string } = {}): JsonObject {
  const index = work.index(projection), nodes = index.nodes;
  work.step(projection.nodes.length);
  const tool = projection.nodes.find(node => node.label === 'GuardTool' && string(node, 'name') === toolName);
  const blockers: string[] = [], matched: JsonObject[] = [], chain: JsonObject[] = [];
  const unknown = [...COMMON_UNKNOWN];
  if (!scope.allTeams) unknown.push('ancestor_evidence_outside_visible_scope');
  if (!tool || tool.properties.known_metadata === false || tool.properties.registered === false) blockers.push('tool_unregistered_at_capture');
  else if (tool.properties.registered !== true) unknown.push('tool_registration');
  if (tool?.properties.approved === false) blockers.push('tool_metadata_unapproved');
  else if (tool?.properties.approved !== true) unknown.push('tool_metadata_approval');
  const visited = new Set<string>();
  let current: MapNode | undefined = task;
  for (let depth = 0; current; depth++) {
    work.step();
    if (depth >= 16 || visited.has(current.id)) { unknown.push('delegation_depth_or_cycle'); break; }
    visited.add(current.id);
    chain.push({ id: current.entityId, taskId: string(current, 'task_id') });
    blockers.push(...knownBlockers(current, tool, now));
    const grants = connected(projection, new Set([current.id]), 'G_HAS_GRANT', work).filter(node =>
      node.label === 'GuardGrant' && string(node, 'tool') === toolName &&
      strings(node, 'resources').some(resource => resource === resourceId || resource === '*'));
    if (!grants.length) blockers.push(current.id === task.id ? 'declared_grant_missing' : 'ancestor_declared_grant_missing');
    matched.push(...grants.map(grantSummary));
    const parents: readonly string[] = index.outgoing.get(current.id)?.get('G_DELEGATED_FROM') ?? [];
    work.step(parents.length);
    if (parents.length > 1) { unknown.push('delegation_evidence_ambiguous'); break; }
    current = parents[0] ? nodes.get(parents[0]) : undefined;
  }
  if (task.properties.sensitive === true) unknown.push('sensitive_egress_and_recipient_checks');
  return { taskId: string(task, 'task_id'), tool: toolName, resourceId,
    assessment: blockers.length ? 'blocked' : 'unknown', evidenceKind: 'declared_and_observed',
    blockers: unique(blockers), unknownChecks: unique(unknown), delegation: chain, matchedGrants: matched,
    externalEvidence: externalEvidence(projection, task, toolName, resourceId, work, policySelection),
    limitations: ['Explanation only; no action was prepared or executed.', 'A clear exported gate does not establish effective permission.'] };
}

const IGNORE_DIFF = new Set(['lastupdated', 'manifest_observed_at', 'manifest_revision', 'observed_at', 'capture_observed_at', 'cloud_observed_at']);
function nodeState(node: MapNode, projection: MapProjection, work: QueryWork): string {
  const index = work.index(projection);
  const properties = Object.fromEntries(Object.entries(node.properties).filter(([key]) => !IGNORE_DIFF.has(key)));
  const edges = [...(index.outgoing.get(node.id)?.entries() ?? [])].flatMap(([kind, targets]) => {
    work.step(targets.length); return targets.map(target => ({ kind, target: index.nodes.get(target)?.entityId ?? null }));
  })
    .sort((a, b) => `${a.kind}:${a.target}`.localeCompare(`${b.kind}:${b.target}`));
  return canonicalJson({ properties, edges } as Json);
}
function freshness(observedAt: unknown, now: number, staleSeconds: number): JsonObject {
  const captured = typeof observedAt === 'string' ? Date.parse(observedAt) : NaN, age = now - captured;
  return { stale: !Number.isFinite(captured) || age < -60_000 || age > staleSeconds * 1000,
    ageSeconds: Number.isFinite(captured) ? Math.max(0, Math.floor(age / 1000)) : null };
}
function changeSummary(node: MapNode): JsonObject {
  return { entityId: node.entityId, label: node.label,
    name: string(node, 'name') ?? string(node, 'task_id') ?? string(node, 'agent_id') ?? string(node, 'deployment_id') ?? string(node, 'tool') ?? string(node, 'binding_id') ?? string(node, 'connection_id') ?? node.entityId };
}

/** One read-only evidence layer shared by HTTP, MCP and the browser. */
export class MapService {
  readonly #store: MapStore;
  readonly #clock: () => number;
  readonly #maxBytes: number;
  readonly #maxNodes: number;
  readonly #maxEdges: number;
  readonly #timeout: number;
  readonly #staleSeconds: number;
  constructor(store: MapStore, options: MapServiceOptions = {}) {
    if (!store || typeof store.read !== 'function' || (options.clock !== undefined && typeof options.clock !== 'function')) fail('MAP_CONFIG_INVALID');
    this.#store = store; this.#clock = options.clock ?? Date.now;
    this.#maxBytes = integer(options.maxResponseBytes, 1024 * 1024, 8 * 1024 * 1024, 128);
    this.#maxNodes = integer(options.maxGraphNodes, 500, 2000);
    this.#maxEdges = integer(options.maxGraphEdges, 1000, 5000);
    this.#timeout = integer(options.queryTimeoutMs, 5000, 10_000, 10);
    this.#staleSeconds = integer(options.staleAfterSeconds, 900, 86400);
  }

  async query(inputScope: ReadScope, inputOperation: unknown, inputArgs: unknown): Promise<MapResponse> {
    const scope = validateReadScope(inputScope);
    const args = validateQueryArguments(inputOperation, inputArgs);
    const operation = inputOperation as MapOperation;
    const work = new QueryWork(this.#timeout, this.#maxBytes);
    let now: number;
    try { now = this.#clock(); } catch { return fail('MAP_UNAVAILABLE'); }
    if (!Number.isSafeInteger(now) || now < 0 || now > 253_402_300_799_999) fail('MAP_UNAVAILABLE');
    const request = { ...(args.sourceId ? { sourceId: args.sourceId as string } : {}),
      ...(operation === 'list_agents' ? { summary: true } : {}),
      ...(operation === 'get_agent_access' ? { agentId: args.agentId as string } : {}),
      ...(operation === 'get_changes' ? { history: true } : {}) };
    let timer: ReturnType<typeof setTimeout> | undefined;
    let view: MapView;
    try {
      view = await Promise.race([this.#store.read(scope, request), new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new MapQueryError('MAP_TIMEOUT')), this.#timeout);
      })]);
    } catch (error) {
      if (error instanceof MapQueryError && ['MAP_NOT_FOUND', 'MAP_LIMIT_EXCEEDED', 'MAP_UNAVAILABLE', 'MAP_TIMEOUT', 'MAP_SCOPE_INVALID'].includes(error.code)) throw error;
      return fail('MAP_UNAVAILABLE');
    } finally { if (timer) clearTimeout(timer); }
    work.step(view.sources.length);
    let data: JsonObject;
    let graph: { nodes: MapNode[]; edges: MapEdge[] } | undefined;
    if (operation === 'list_agents') {
      const search = typeof args.search === 'string' ? args.search.toLocaleLowerCase('en-US') : '';
      const agents = view.sources.flatMap(source => {
        work.step(source.current.nodes.length);
        return source.current.nodes.filter(node => node.label === 'GuardAgent').map(agent => agentSummary(source, source.current, agent, work));
      })
        .filter(agent => (!search || [agent.name, agent.agentId].some(value => typeof value === 'string' && value.toLocaleLowerCase('en-US').includes(search))) &&
          (args.ownerId === undefined || agent.ownerId === args.ownerId) &&
          (args.environment === undefined || (agent.environments as readonly string[]).includes(args.environment as string)))
        .sort((a, b) => `${a.name}:${a.sourceId}:${a.id}`.localeCompare(`${b.name}:${b.sourceId}:${b.id}`));
      const limit = args.limit as number | undefined ?? 50;
      data = { agents: agents.slice(0, limit), truncated: agents.length > limit };
    } else if (operation === 'get_agent_access') {
      const source = findSource(view, args.sourceId as string), projection = source.current;
      const agent = findAgent(projection, args.agentId as string);
      graph = focus(projection, agent, work);
      const policy = selectedPolicy(projection, work, { nodes: graph.nodes });
      data = { agent: agentSummary(source, projection, agent, work),
        deployments: graph.nodes.filter(node => node.label === 'GuardDeployment').map(node => ({ id: node.entityId, deploymentId: string(node, 'deployment_id'), environment: string(node, 'environment') })),
        tasks: graph.nodes.filter(node => node.label === 'GuardTask').map(taskSummary),
        grants: graph.nodes.filter(node => node.label === 'GuardGrant').map(grantSummary),
        connections: graph.nodes.filter(node => node.label === 'GuardMcpConnection').map(node => ({ id: node.entityId, ...node.properties })),
        bindings: graph.nodes.filter(node => ['GuardExecutionBinding', 'GuardResourceBinding'].includes(node.label)).map(node => ({ id: node.entityId, kind: node.label, ...node.properties })),
        policyEvidence: policy as unknown as readonly JsonObject[], policyCoverage: policyCoverage(policy),
        receipt: receipt(source), assessment: 'unknown',
        limitations: ['Declared and observed evidence only; current executor admission is required.', 'External object and prefix bindings retain their original scope.'] };
    } else if (operation === 'explain_access') {
      const source = findSource(view, args.sourceId as string);
      const task = source.current.nodes.find(node => node.label === 'GuardTask' && matching(node, args.taskId as string, 'task_id'));
      if (!task) fail('MAP_NOT_FOUND');
      data = { ...explain(source.current, scope, task, args.tool as string, args.resourceId as string, now, work), receipt: receipt(source) };
    } else if (operation === 'find_agents_with_access') {
      const candidates: JsonObject[] = [];
      const limit = args.limit as number | undefined ?? 50;
      let truncated = false;
      candidateSearch: for (const source of view.sources) for (const agent of source.current.nodes.filter(node => node.label === 'GuardAgent')) {
        work.step();
        const selected = focus(source.current, agent, work), selectedProjection = { ...source.current, ...selected };
        const bindings = selected.nodes.filter(node => node.label === 'GuardResourceBinding' && strings(node, 'actions').includes(args.action as string));
        const evidence: JsonObject[] = [];
        for (const binding of bindings) {
          work.step();
          const external = connected(selectedProjection, new Set([binding.id]), 'G_MAPS_TO', work)[0];
          if (string(binding, 'resource_ref') !== args.resourceRef && (!external || string(external, 'arn') !== args.resourceRef)) continue;
          const toolName = string(binding, 'tool'), resource = string(binding, 'resource_ref');
          if (!toolName || !resource) continue;
          for (const task of selected.nodes.filter(node => node.label === 'GuardTask')) {
            work.step();
            if (!connected(selectedProjection, new Set([task.id]), 'G_HAS_GRANT', work).some(grant => string(grant, 'tool') === toolName && strings(grant, 'resources').some(item => item === '*' || item === resource))) continue;
            if (candidates.length >= limit) { truncated = true; break candidateSearch; }
            const deployment = connected(selectedProjection, new Set([task.id]), 'G_ASSIGNED_TO', work);
            const executions = connected(selectedProjection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true).filter(node => string(node, 'tool') === toolName);
            const policy = selectedPolicy(source.current, work, { task, executions, resources: [binding], action: args.action as string });
            evidence.push(work.evidence({ taskId: string(task, 'task_id'), tool: toolName, resourceRef: resource, action: args.action!,
              scope: string(binding, 'scope'), externalResource: external ? { ...external.properties } : null,
              executionBindings: executions.map(node => ({ id: node.entityId, ...node.properties,
                identities: connected(selectedProjection, new Set([node.id]), 'G_USES_IDENTITY', work).map(identity => ({ ...identity.properties })) })),
              policyEvidence: policy as unknown as readonly JsonObject[], policyCoverage: policyCoverage(policy),
              explanation: explain(source.current, scope, task, toolName, resource, now, work,
                { action: args.action as string, resourceBindingId: binding.entityId }) }));
          }
        }
        if (evidence.length) candidates.push({ agent: agentSummary(source, source.current, agent, work), evidence,
          assessment: 'unknown', limitations: ['Potential access candidates; no effective permission decision.', 'Cloud containment is not exact object authorization.'] });
      }
      data = { candidates, truncated };
    } else if (operation === 'get_changes') {
      const source = findSource(view, args.sourceId as string), current = source.current;
      const since = args.since ?? 'previous';
      const previous = [current.id, current.snapshotId].includes(since as string) ? current :
        source.previous && (since === 'previous' || [source.previous.id, source.previous.snapshotId].includes(since as string)) ? source.previous : null;
      const added: JsonObject[] = [], removed: JsonObject[] = [], changed: JsonObject[] = [];
      if (previous) {
        const before = new Map(previous.nodes.map(node => [node.entityId, node])), after = new Map(current.nodes.map(node => [node.entityId, node]));
        for (const [id, node] of after) {
          work.step();
          if (!before.has(id)) added.push(changeSummary(node));
          else if (nodeState(node, current, work) !== nodeState(before.get(id)!, previous, work)) changed.push(changeSummary(node));
        }
        for (const [id, node] of before) if (!after.has(id)) removed.push(changeSummary(node));
      }
      data = { sourceId: source.id, from: previous ? receipt(source, previous) : null, to: receipt(source),
        changes: { added, removed, changed }, coverageGap: previous === null, policyHistory: 'not_collected',
        limitations: ['Net changes in authorized retained snapshots only; not an invocation or intermediate-event log.',
          'Current IAM policy observations are separate from retained Guard snapshots; policy history is not collected.'] };
    } else {
      data = { sources: view.sources.map(source => {
        work.step();
        return { id: source.id, sourceId: source.sourceId, tenantId: source.tenantId, profile: source.profile,
          generatedAt: source.current.generatedAt, snapshotId: source.current.snapshotId, projectionId: source.current.id,
          ...freshness(source.current.generatedAt, now, this.#staleSeconds),
          coverage: { ...Object.fromEntries(Object.entries(source.current.coverage).filter(([component]) => component !== 'policy').map(([component, status]) => {
            work.step(); return [component, { ...status, ...freshness(status.observedAt, now, this.#staleSeconds) }];
          })), policy: policyCoverage(work.policy(source.current)) } };
      }), visibility: scope.allTeams ? 'enrolled_sources' : 'visible_agent_sources',
      limitations: ['Collection freshness is separate from current execution authority.'] };
    }
    if (graph && (graph.nodes.length > this.#maxNodes || graph.edges.length > this.#maxEdges)) fail('MAP_LIMIT_EXCEEDED');
    work.step();
    const result = { operation, observedAt: new Date(now).toISOString(), data, ...(graph ? { graph } : {}) };
    let copied: MapResponse;
    try { copied = immutableJson(result, 32, 100_000, this.#maxBytes) as unknown as MapResponse; }
    catch { return fail('MAP_LIMIT_EXCEEDED'); }
    work.step(); return copied;
  }
}
