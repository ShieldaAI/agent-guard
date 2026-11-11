import { type Json } from '@shieldaai/agent-guard';
import { canonicalJson, immutableJson } from '@shieldaai/agent-guard/internal';
import { safeProperties } from './projection-fields.js';
import { shortenScopeList } from './policy-reader.js';
import {
  DANGEROUS_THREE_LIMITATIONS,
  dangerousThree,
  type DangerousThreeStatus,
  type FlagGraph,
} from './boundary-flags.js';
import {
  MapQueryError,
  mapIdentifier,
  validateReadScope,
  type JsonObject,
  type JsonValue,
  type MapEdge,
  type MapIdentityExtraResource,
  type MapIdentityScope,
  type MapNode,
  type MapPolicyEvidence,
  type MapProjection,
  type MapReadRequest,
  type MapSource,
  type MapStore,
  type MapUndeclaredActivity,
  type MapView,
  type ReadScope,
} from './types.js';

export const MAP_OPERATIONS = [
  'list_agents',
  'get_agent_access',
  'explain_access',
  'find_agents_with_access',
  'get_changes',
  'get_inventory_health',
  'list_owners',
  'list_resources',
  'get_resource_access',
  'get_agent_inventory',
  'list_undeclared_activity',
  'list_unclaimed_identities',
] as const;
export type MapOperation = (typeof MAP_OPERATIONS)[number];
const idSchema = { type: 'string', minLength: 1, maxLength: 4096 };
const limitSchema = { type: 'integer', minimum: 1, maximum: 100 };
const offsetSchema = { type: 'integer', minimum: 0, maximum: 100_000 };
const choice = (...values: string[]) => ({ type: 'string', enum: values });
const ownershipSchema = choice('assigned', 'unassigned', 'unknown');
const lifecycleSchema = choice('active', 'inactive', 'retired', 'unknown');
const sections = [
  'overview',
  'owners',
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
] as const;
const schema = (properties: Record<string, unknown>, required: readonly string[] = []): JsonObject =>
  immutableJson({ type: 'object', additionalProperties: false, properties, required }) as JsonObject;
export const MAP_INPUT_SCHEMAS: Readonly<Record<MapOperation, JsonObject>> = Object.freeze({
  list_agents: schema({
    search: { type: 'string', maxLength: 256 },
    sourceId: idSchema,
    ownerId: idSchema,
    teamId: idSchema,
    environment: idSchema,
    ownershipStatus: ownershipSchema,
    lifecycleState: lifecycleSchema,
    /** Only agents with this boundary flag (not `absent`), optionally one status. */
    flag: choice('dangerous_three'),
    flagStatus: choice('exposed', 'mitigated', 'unknown', 'absent'),
    /** Add `boundaryFlags` to every agent; reads tasks, so it costs more than the plain index. */
    includeFlags: { type: 'boolean' },
    limit: limitSchema,
    offset: offsetSchema,
  }),
  get_agent_access: schema({ sourceId: idSchema, agentId: idSchema }, ['sourceId', 'agentId']),
  explain_access: schema({ sourceId: idSchema, taskId: idSchema, tool: idSchema, resourceId: idSchema }, [
    'sourceId',
    'taskId',
    'tool',
    'resourceId',
  ]),
  find_agents_with_access: schema(
    {
      resourceRef: idSchema,
      action: { type: 'string', minLength: 3, maxLength: 256, pattern: '^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$' },
      sourceId: idSchema,
      limit: limitSchema,
    },
    ['resourceRef', 'action'],
  ),
  get_changes: schema(
    {
      sourceId: idSchema,
      since: idSchema,
      agentId: idSchema,
      resourceId: idSchema,
      changeKind: choice('all', 'permissions', 'ownership', 'bindings', 'outside_guard'),
      offset: offsetSchema,
      limit: limitSchema,
    },
    ['sourceId'],
  ),
  get_inventory_health: schema({ sourceId: idSchema }),
  list_owners: schema({
    sourceId: idSchema,
    search: { type: 'string', maxLength: 256 },
    kind: choice('person', 'team', 'service'),
    offset: offsetSchema,
    limit: limitSchema,
  }),
  list_resources: schema({
    sourceId: idSchema,
    search: { type: 'string', maxLength: 256 },
    ownerId: idSchema,
    sensitivity: choice('public', 'internal', 'confidential', 'restricted', 'unknown'),
    offset: offsetSchema,
    limit: limitSchema,
  }),
  get_resource_access: schema({ sourceId: idSchema, resourceId: idSchema, offset: offsetSchema, limit: limitSchema }, [
    'sourceId',
    'resourceId',
  ]),
  get_agent_inventory: schema(
    { sourceId: idSchema, agentId: idSchema, section: choice(...sections), offset: offsetSchema, limit: limitSchema },
    ['sourceId', 'agentId'],
  ),
  /** Tasks or caller principals of one source that no declared agent accounts for; all-teams readers. */
  list_undeclared_activity: schema(
    { sourceId: idSchema, kind: choice('tasks', 'principals'), offset: offsetSchema, limit: limitSchema },
    ['sourceId'],
  ),
  /** IAM roles and users of the enrolled AWS accounts that no declared agent names; all-teams readers. */
  list_unclaimed_identities: schema({ offset: offsetSchema, limit: limitSchema }),
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

function fail(code = 'MAP_REQUEST_INVALID'): never {
  throw new MapQueryError(code);
}
function integer(value: unknown, fallback: number, maximum: number, minimum = 1): number {
  const chosen = value === undefined ? fallback : value;
  if (typeof chosen !== 'number' || !Number.isSafeInteger(chosen) || chosen < minimum || chosen > maximum)
    fail('MAP_CONFIG_INVALID');
  return chosen;
}
export function validateQueryArguments(operation: unknown, value: unknown): Readonly<Record<string, JsonValue>> {
  if (typeof operation !== 'string' || !(MAP_OPERATIONS as readonly string[]).includes(operation)) fail();
  let copied: Json;
  try {
    copied = immutableJson(value, 4, 512, 64 * 1024);
  } catch {
    return fail();
  }
  if (!copied || typeof copied !== 'object' || Array.isArray(copied)) fail();
  const args = copied as Record<string, JsonValue>;
  const definition = MAP_INPUT_SCHEMAS[operation as MapOperation];
  const properties = definition.properties as JsonObject;
  const required = definition.required as readonly string[];
  if (Object.keys(args).some(key => !Object.hasOwn(properties, key)) || required.some(key => !Object.hasOwn(args, key)))
    fail();
  for (const [key, item] of Object.entries(args)) {
    if (key === 'limit' || key === 'offset') {
      if (
        typeof item !== 'number' ||
        !Number.isSafeInteger(item) ||
        item < (key === 'offset' ? 0 : 1) ||
        item > (key === 'offset' ? 100_000 : 100)
      )
        fail();
    } else if ((properties[key] as JsonObject).type === 'boolean') {
      if (typeof item !== 'boolean') fail();
    } else if (key === 'search') {
      if (
        typeof item !== 'string' ||
        [...item].length > 256 ||
        item.includes('\0') ||
        /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(item)
      )
        fail();
    } else {
      mapIdentifier(item);
      const allowed = (properties[key] as JsonObject).enum;
      if (Array.isArray(allowed) && !allowed.includes(item)) fail();
      if (
        key === 'action' &&
        (typeof item !== 'string' || item.length > 256 || !/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(item))
      )
        fail();
    }
  }
  return args;
}

const string = (node: MapNode, key: string): string | null =>
  typeof node.properties[key] === 'string' ? (node.properties[key] as string) : null;
const number = (node: MapNode, key: string): number | null =>
  typeof node.properties[key] === 'number' ? (node.properties[key] as number) : null;
const strings = (node: MapNode, key: string): readonly string[] =>
  Array.isArray(node.properties[key])
    ? (node.properties[key] as readonly JsonValue[]).filter((v): v is string => typeof v === 'string')
    : [];
const matching = (node: MapNode, id: string, native: string): boolean =>
  node.entityId === id || string(node, native) === id;
const unique = <T>(values: readonly T[]): T[] => [...new Set(values)];
interface GraphIndex {
  nodes: Map<string, MapNode>;
  /** Positions of each node ID in projection.nodes, so subgraphs keep projection order. */
  nodePositions: Map<string, number[]>;
  /** Positions of each source's edges in projection.edges. */
  edgesFrom: Map<string, number[]>;
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
  constructor(timeout: number, maxBytes: number) {
    this.#deadline = performance.now() + timeout;
    this.#evidenceBytes = maxBytes;
  }
  /** Milliseconds left before this query's deadline. */
  remaining(): number {
    return Math.max(0, this.#deadline - performance.now());
  }
  step(amount = 1): void {
    if (performance.now() >= this.#deadline) fail('MAP_TIMEOUT');
    this.#remaining -= amount;
    if (this.#remaining < 0) fail('MAP_LIMIT_EXCEEDED');
  }
  index(projection: MapProjection): GraphIndex {
    this.step();
    const existing = this.#indices.get(projection);
    if (existing) return existing;
    this.step(projection.nodes.length + projection.edges.length);
    const result: GraphIndex = {
      nodes: new Map(),
      nodePositions: new Map(),
      edgesFrom: new Map(),
      outgoing: new Map(),
      incoming: new Map(),
    };
    const push = (map: Map<string, number[]>, key: string, position: number): void => {
      const list = map.get(key);
      if (list) list.push(position);
      else map.set(key, [position]);
    };
    projection.nodes.forEach((node, position) => {
      result.nodes.set(node.id, node);
      push(result.nodePositions, node.id, position);
    });
    projection.edges.forEach((edge, position) => push(result.edgesFrom, edge.source, position));
    const add = (map: GraphIndex['outgoing'], from: string, kind: MapEdge['kind'], to: string): void => {
      let kinds = map.get(from);
      if (!kinds) {
        kinds = new Map();
        map.set(from, kinds);
      }
      const items = kinds.get(kind);
      if (items) items.push(to);
      else kinds.set(kind, [to]);
    };
    for (const edge of projection.edges) {
      add(result.outgoing, edge.source, edge.kind, edge.target);
      add(result.incoming, edge.target, edge.kind, edge.source);
    }
    this.#indices.set(projection, result);
    this.step();
    return result;
  }
  evidence(value: JsonObject): JsonObject {
    this.step();
    if (++this.#evidenceCount > 1000) fail('MAP_LIMIT_EXCEEDED');
    let copy: JsonObject;
    try {
      copy = immutableJson(value, 24, 25_000, this.#evidenceBytes) as JsonObject;
    } catch {
      return fail('MAP_LIMIT_EXCEEDED');
    }
    this.#evidenceBytes -= Buffer.byteLength(JSON.stringify(copy));
    this.step();
    return copy;
  }
  policy(projection: MapProjection): readonly MapPolicyEvidence[] {
    const existing = this.#policy.get(projection);
    if (existing) return existing;
    const result = validatedPolicyEvidence(projection, this);
    this.#policy.set(projection, result);
    return result;
  }
}
function connected(
  projection: MapProjection,
  ids: Set<string>,
  kind: MapEdge['kind'],
  work: QueryWork,
  reverse = false,
): MapNode[] {
  const index = work.index(projection),
    selected = new Set<string>();
  work.step(ids.size);
  for (const id of ids) {
    const targets = (reverse ? index.incoming : index.outgoing).get(id)?.get(kind) ?? [];
    work.step(targets.length);
    for (const target of targets) selected.add(target);
  }
  return [...selected].flatMap(id => (index.nodes.get(id) ? [index.nodes.get(id)!] : []));
}
const nodeIds = (nodes: readonly MapNode[]): Set<string> => new Set(nodes.map(node => node.id));
function hostObservation(node: MapNode): JsonObject {
  return {
    authorityId: string(node, 'authority_id'),
    manifestId: string(node, 'manifest_id'),
    manifestRevision: number(node, 'manifest_revision'),
    observedAt: string(node, 'manifest_observed_at'),
  };
}
function deployments(projection: MapProjection, agent: MapNode, work: QueryWork): MapNode[] {
  return connected(projection, new Set([agent.id]), 'G_INSTANCE_OF', work, true).filter(
    node => node.label === 'GuardDeployment',
  );
}
function agentSummary(source: MapSource, projection: MapProjection, agent: MapNode, work: QueryWork): JsonObject {
  const items = deployments(projection, agent, work).map(node => ({
    id: node.entityId,
    deploymentId: string(node, 'deployment_id'),
    environment: string(node, 'environment'),
  }));
  return {
    id: agent.entityId,
    agentId: string(agent, 'agent_id'),
    sourceId: source.id,
    name: string(agent, 'name'),
    ownerId: string(agent, 'owner_id'),
    teamId: string(agent, 'team_id'),
    purpose: string(agent, 'purpose'),
    lifecycleState: string(agent, 'lifecycle_state') ?? 'unknown',
    ownershipStatus: string(agent, 'ownership_status') ?? 'unknown',
    ownershipSource: string(agent, 'ownership_source'),
    ownerName:
      connected(projection, new Set([agent.id]), 'G_OWNED_BY', work)
        .filter(n => n.label === 'GuardOwner')
        .map(n => string(n, 'name'))[0] ?? null,
    ownershipObservedAt: string(agent, 'manifest_observed_at'),
    ...hostObservation(agent),
    environments: unique(items.map(item => item.environment).filter((item): item is string => item !== null)).sort(),
    deployments: items,
  };
}
function taskSummary(node: MapNode): JsonObject {
  return {
    id: node.entityId,
    taskId: string(node, 'task_id'),
    principalId: string(node, 'principal_id'),
    revoked: node.properties.revoked ?? null,
    sensitive: node.properties.sensitive ?? null,
    usage: {
      calls: number(node, 'calls'),
      concurrent: number(node, 'concurrent'),
      spent: number(node, 'spent'),
      reserved: number(node, 'reserved'),
    },
    budget: {
      maxCalls: number(node, 'max_calls'),
      maxConcurrent: number(node, 'max_concurrent'),
      maxCost: number(node, 'max_cost'),
      deadline: number(node, 'deadline'),
    },
  };
}
function grantSummary(node: MapNode): JsonObject {
  return {
    id: node.entityId,
    taskId: string(node, 'task_id'),
    tool: string(node, 'tool'),
    resources: strings(node, 'resources'),
    evidenceKind: 'declared',
    assessment: 'unknown',
  };
}
function receipt(source: MapSource, projection = source.current): JsonObject {
  return {
    sourceId: source.id,
    tenantId: source.tenantId,
    profile: source.profile,
    projectionId: projection.id,
    snapshotId: projection.snapshotId,
    generatedAt: projection.generatedAt,
    coverage: projection.coverage as unknown as JsonObject,
  };
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
  const tools = [
    ...connected(projection, nodeIds(grants), 'G_FOR_TOOL', work),
    ...connected(projection, nodeIds(executions), 'G_EXECUTES_TOOL', work),
  ];
  const connections = connected(projection, nodeIds(executions), 'G_VIA_CONNECTION', work),
    toolIds = nodeIds(tools);
  const operations = connected(projection, nodeIds(connections), 'G_EXPOSES_OPERATION', work).filter(operation =>
    connected(projection, new Set([operation.id]), 'G_OPERATION_TOOL', work).some(tool => toolIds.has(tool.id)),
  );
  const selected = nodeIds([
    agent,
    ...deployment,
    ...tasks,
    ...executions,
    ...grants,
    ...resources,
    ...resourceBindings,
    ...tools,
    ...connections,
    ...operations,
    ...connected(projection, nodeIds(tasks), 'G_ACTS_AS', work),
    ...connected(projection, new Set([agent.id]), 'G_OWNED_BY', work),
    ...connected(projection, nodeIds(resourceBindings), 'G_RESOURCE_OWNED_BY', work),
    ...connected(projection, nodeIds(deployment), 'G_USES_CREDENTIAL', work),
    ...connected(projection, nodeIds(deployment), 'G_DIRECT_ACCESS_FOR', work, true),
    ...connected(projection, nodeIds(executions), 'G_USES_IDENTITY', work),
    ...connected(projection, nodeIds(resourceBindings), 'G_MAPS_TO', work),
  ]);
  // Build the subgraph from the index instead of scanning the whole projection per agent:
  // the same nodes and edges in projection order, at a cost proportional to this subgraph.
  const index = work.index(projection),
    nodePositions: number[] = [],
    edgePositions: number[] = [];
  for (const id of selected) {
    nodePositions.push(...(index.nodePositions.get(id) ?? []));
    const outgoing = index.edgesFrom.get(id) ?? [];
    work.step(1 + outgoing.length);
    for (const position of outgoing) if (selected.has(projection.edges[position]!.target)) edgePositions.push(position);
  }
  nodePositions.sort((a, b) => a - b);
  edgePositions.sort((a, b) => a - b);
  return {
    nodes: nodePositions.map(position => projection.nodes[position]!),
    edges: edgePositions.map(position => projection.edges[position]!),
  };
}

/**
 * Host-declared paths that act without the guard, per deployment in the agent's focus.
 * Manifest v3 sets `direct_access_status`; older manifests leave it absent, which reads as
 * `unknown` and never as `none_declared`.
 */
/** A declared target names a host resource; name it only when that resource is in the reader's scope. */
function targetVisibility(projection: MapProjection, scope: ReadScope, work: QueryWork): (target: string) => boolean {
  if (scope.allTeams) return () => true;
  work.step(projection.nodes.length);
  const visible = new Set([
    ...projection.nodes
      .filter(node => node.label === 'GuardExternalResource')
      .map(node => string(node, 'host_resource_id'))
      .filter((id): id is string => id !== null),
    ...(projection.inScopeTargets ?? []),
  ]);
  return target => visible.has(target);
}
function directAccess(
  projection: MapProjection,
  graph: { nodes: MapNode[]; edges: MapEdge[] },
  scope: ReadScope,
  work: QueryWork,
): JsonObject[] {
  const visibleTarget = targetVisibility(projection, scope, work);
  return ordered(
    graph.nodes
      .filter(node => node.label === 'GuardDeployment')
      .map(deployment => {
        const entries = connected(projection, new Set([deployment.id]), 'G_DIRECT_ACCESS_FOR', work, true);
        const declared = string(deployment, 'direct_access_status');
        // An entry without the v3 status would be inconsistent; report what was found.
        const status = entries.length ? 'found' : declared === 'none_declared' ? 'none_declared' : 'unknown';
        return {
          id: deployment.entityId,
          deploymentId: string(deployment, 'deployment_id'),
          status,
          evidenceKind: 'declared',
          entries: ordered(
            entries.map(entry => {
              const target = string(entry, 'target_ref');
              const targetStatus =
                target === null ? 'none' : visibleTarget(target) ? 'visible' : 'outside_visible_scope';
              return {
                id: entry.entityId,
                accessId: string(entry, 'access_id'),
                kind: string(entry, 'kind'),
                targetRef: targetStatus === 'visible' ? target : null,
                targetStatus,
                description: string(entry, 'description'),
              };
            }),
          ),
        };
      }),
  );
}

/**
 * The bounded, read-only graph view the boundary flags use. Sensitive bindings for `*` grants
 * come from the store's wildcard read when it ran (one-agent boundary reads); a team-wide read
 * already holds every in-scope binding, indexed once per projection.
 */
const sensitiveIndex = new WeakMap<MapProjection, Map<string, { id: string; sensitivity: string }[]>>();
function flagGraph(projection: MapProjection, work: QueryWork): FlagGraph {
  return {
    linked: (node, kind, reverse = false) => connected(projection, new Set([node.id]), kind, work, reverse),
    sensitiveBindings: tool => {
      if (projection.wildcardSensitivity)
        return Object.hasOwn(projection.wildcardSensitivity, tool) ? projection.wildcardSensitivity[tool]! : [];
      let index = sensitiveIndex.get(projection);
      if (!index) {
        work.step(projection.nodes.length);
        index = new Map();
        for (const node of projection.nodes) {
          const name = string(node, 'tool'),
            sensitivity = string(node, 'sensitivity');
          if (node.label !== 'GuardResourceBinding' || name === null) continue;
          if (sensitivity !== 'confidential' && sensitivity !== 'restricted') continue;
          const items = index.get(name) ?? [];
          items.push({ id: node.entityId, sensitivity });
          index.set(name, items);
        }
        for (const [name, items] of index)
          index.set(name, items.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).slice(0, 5));
        sensitiveIndex.set(projection, index);
      }
      return index.get(tool) ?? [];
    },
    step: amount => work.step(amount),
  };
}
/** Task expiry is judged at the snapshot's own capture time, so list and detail agree. */
function agentFlags(projection: MapProjection, agent: MapNode, scope: ReadScope, work: QueryWork) {
  return dangerousThree(
    flagGraph(projection, work),
    agent,
    Date.parse(projection.generatedAt),
    scope.allTeams,
    projection.ancestorsNotLoaded === true,
  );
}

/**
 * The detail flag with its own work budget: a very large lineage degrades the flag to
 * `unknown`, it never fails the rest of get_agent_access.
 */
function detailFlags(
  projection: MapProjection,
  agent: MapNode,
  scope: ReadScope,
  remaining: number,
  maxBytes: number,
): JsonObject {
  try {
    return agentFlags(
      projection,
      agent,
      scope,
      new QueryWork(Math.max(1, remaining - 25), maxBytes),
    ) as unknown as JsonObject;
  } catch (error) {
    const code = error instanceof MapQueryError ? error.code : '';
    if (code !== 'MAP_LIMIT_EXCEEDED' && code !== 'MAP_TIMEOUT') throw error;
    return {
      kind: 'dangerous_three',
      status: 'unknown',
      taskId: null,
      legs: { privateData: 'unknown', outsideContent: 'unknown', externalSend: 'unknown' },
      evidence: [],
      evidenceTruncated: false,
      notes: [code === 'MAP_TIMEOUT' ? 'flags_timeout' : 'flags_limit_exceeded'],
      liveTasks: 0,
      evidenceKind: 'declared',
      assessment: 'unknown',
      limitations: DANGEROUS_THREE_LIMITATIONS,
    } as unknown as JsonObject;
  }
}

/** `data` with each identity-scope list cut to `keep` entries, or null if nothing would change. */
function shortenIdentityScope(data: JsonObject, keep: number): JsonObject | null {
  const outside = data.outsideGuard as JsonObject | undefined;
  const records = outside?.identityScope as readonly MapIdentityScope[] | undefined;
  if (!Array.isArray(records)) return null;
  const shortened = records.map(record => shortenScopeList(record, keep));
  if (shortened.every((record, index) => record === records[index])) return null;
  return { ...data, outsideGuard: { ...outside, identityScope: shortened as unknown as JsonValue } };
}

type Reach = 'yes' | 'none_found' | 'unknown';
interface ReachIndex {
  readonly undeclaredDeployments: number;
  /** Declared paths without a target, such as a shell, can touch any resource. */
  readonly untargetedPaths: number;
  /** Declared paths whose target matches no resource in this read (perhaps another team's). */
  readonly unresolvedPaths: number;
  /** Visible granted tools with no declared execution identity (ambient or unknown). */
  readonly undeclaredIdentities: number;
  readonly directByTarget: Map<string, MapNode[]>;
  readonly identitiesByBucket: Map<string, { record: MapIdentityScope; extra: MapIdentityExtraResource }[]>;
  readonly identityUnknown: number;
  readonly identityCollected: boolean;
  /** AWS accounts of the evaluated identities; a bucket elsewhere was never compared. */
  readonly identityAccounts: ReadonlySet<string | null>;
}
const reachIndex = new WeakMap<MapProjection, ReachIndex>();
/**
 * Outside-guard reach over the whole visible projection: any declared direct path or any
 * evaluated tool identity can touch any resource, so `none_found` needs every visible
 * deployment to have declared its paths and every visible identity to be evaluated.
 */
function outsideGuardIndex(projection: MapProjection, work: QueryWork): ReachIndex {
  const existing = reachIndex.get(projection);
  if (existing) return existing;
  work.step(projection.nodes.length);
  let undeclaredDeployments = 0,
    untargetedPaths = 0,
    undeclaredIdentities = 0;
  const identityAccounts = new Set<string | null>();
  const directByTarget = new Map<string, MapNode[]>();
  // The tools each deployment has an execution binding for, read once per deployment.
  const executed = new Map<string, Set<string | null>>();
  const executedTools = (deployment: MapNode): Set<string | null> => {
    let tools = executed.get(deployment.id);
    if (!tools) {
      tools = new Set(
        connected(projection, new Set([deployment.id]), 'G_EXECUTES_FOR', work, true).map(item => string(item, 'tool')),
      );
      executed.set(deployment.id, tools);
    }
    return tools;
  };
  for (const node of projection.nodes) {
    if (node.label === 'GuardDeployment') {
      const status = string(node, 'direct_access_status');
      // `found` with no entry in the read is inconsistent, so it is not a declaration either.
      const entries = connected(projection, new Set([node.id]), 'G_DIRECT_ACCESS_FOR', work, true).length;
      if (!(status === 'none_declared' || (status === 'found' && entries > 0))) undeclaredDeployments++;
    }
    if (node.label === 'GuardDirectAccess') {
      const target = string(node, 'target_ref');
      if (target === null) untargetedPaths++;
      else {
        const paths = directByTarget.get(target);
        if (paths) paths.push(node);
        else directByTarget.set(target, [node]);
      }
    }
    if (node.label === 'GuardTask') {
      // A granted tool runs under some identity on every deployment the task is assigned to;
      // a deployment without an execution binding for it leaves that identity undeclared.
      const granted = new Set(
        connected(projection, new Set([node.id]), 'G_HAS_GRANT', work).map(item => string(item, 'tool')),
      );
      if (granted.size) {
        const deployments = connected(projection, new Set([node.id]), 'G_ASSIGNED_TO', work);
        work.step(granted.size * deployments.length);
        if (!deployments.length || deployments.some(item => [...granted].some(tool => !executedTools(item).has(tool))))
          undeclaredIdentities++;
      }
    }
  }
  const identitiesByBucket: ReachIndex['identitiesByBucket'] = new Map();
  let identityUnknown = 0;
  // A visible execution binding the reach read never reported on was not evaluated.
  if (projection.identityReach !== undefined) {
    const reported = new Set(projection.identityReach.map(record => record.executionBindingId));
    for (const node of projection.nodes)
      if (node.label === 'GuardExecutionBinding' && !reported.has(node.entityId)) identityUnknown++;
  }
  // A target the read cannot match may be any resource, so it counts like no target.
  const hostIds = new Set(
    projection.nodes
      .filter(node => node.label === 'GuardExternalResource')
      .map(node => string(node, 'host_resource_id'))
      .filter((id): id is string => id !== null),
  );
  let unresolvedPaths = 0;
  for (const [target, paths] of directByTarget) if (!hostIds.has(target)) unresolvedPaths += paths.length;
  for (const record of projection.identityReach ?? []) {
    work.step(1 + record.extraResources.length);
    // Only a complete comparison counts: any other status, or a record whose list was cut
    // (it may reach buckets it no longer names), leaves reach unknown.
    if (!(record.status === 'matches_grants' || record.status === 'broader_than_grants') || record.truncated)
      identityUnknown++;
    identityAccounts.add(record.accountId ?? null);
    for (const extra of record.extraResources) {
      const reached = identitiesByBucket.get(extra.bucketName);
      if (reached) reached.push({ record, extra });
      else identitiesByBucket.set(extra.bucketName, [{ record, extra }]);
    }
  }
  const result = {
    undeclaredDeployments,
    untargetedPaths,
    unresolvedPaths,
    undeclaredIdentities,
    directByTarget,
    identitiesByBucket,
    identityUnknown,
    identityCollected: projection.identityReach !== undefined,
    identityAccounts,
  };
  reachIndex.set(projection, result);
  return result;
}
/** Entries listed per resource in get_resource_access before the list is marked truncated. */
const REACH_LIST_LIMIT = 100;
interface ReachResult {
  status: Reach;
  unknownReasons: string[];
  directAccess: JsonObject[];
  directAccessTruncated: boolean;
  identities: JsonObject[];
  identitiesTruncated: boolean;
}
/**
 * `detail` builds the (bounded) lists for one resource; the listing only needs the status,
 * which comes from index lookups.
 */
function outsideGuardReach(
  projection: MapProjection,
  resource: MapNode,
  scope: ReadScope,
  work: QueryWork,
  detail = false,
): ReachResult {
  const index = outsideGuardIndex(projection, work);
  const targets = connected(projection, new Set([resource.id]), 'G_MAPS_TO', work);
  // The collector writes one target per binding; anything else is malformed and never none_found.
  const malformed = targets.length !== 1;
  const hosts = targets.map(node => string(node, 'host_resource_id')).filter((id): id is string => id !== null);
  const accounts = new Set(
    targets.filter(node => string(node, 'provider') === 'aws').map(node => string(node, 'account_id')),
  );
  const buckets = targets
    .filter(node => string(node, 'provider') === 'aws')
    .map(node => /^arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:\/.*)?$/.exec(string(node, 'arn') ?? '')?.[1])
    .filter((name): name is string => name !== undefined);
  work.step(1 + hosts.length + buckets.length);
  const reached =
    hosts.some(id => index.directByTarget.has(id)) || buckets.some(name => index.identitiesByBucket.has(name));
  let directAccess: JsonObject[] = [],
    identities: JsonObject[] = [],
    directAccessTruncated = false,
    identitiesTruncated = false;
  if (detail) {
    const paths = hosts
      .flatMap(id => index.directByTarget.get(id) ?? [])
      .sort((a, b) => compare(a.entityId, b.entityId));
    const reaching = buckets
      .flatMap(name => index.identitiesByBucket.get(name) ?? [])
      .sort(
        (a, b) =>
          compare(a.record.executionBindingId, b.record.executionBindingId) ||
          compare(a.extra.bucketName, b.extra.bucketName) ||
          compare(a.extra.relationship, b.extra.relationship),
      );
    work.step(paths.length + reaching.length);
    directAccessTruncated = paths.length > REACH_LIST_LIMIT;
    identitiesTruncated = reaching.length > REACH_LIST_LIMIT;
    directAccess = paths.slice(0, REACH_LIST_LIMIT).map(node => ({
      id: node.entityId,
      accessId: string(node, 'access_id'),
      deploymentId: string(node, 'deployment_id'),
      kind: string(node, 'kind'),
      description: string(node, 'description'),
      evidenceKind: 'declared',
    }));
    identities = reaching.slice(0, REACH_LIST_LIMIT).map(
      ({ record, extra }) =>
        ({
          id: record.executionBindingId,
          executionBindingId: record.executionBindingId,
          deploymentId: record.deploymentId,
          tool: record.tool,
          identityId: record.identityId,
          relationship: extra.relationship,
          hasCondition: extra.hasCondition,
          conditionKeys: extra.conditionKeys,
          evidenceKind: 'iam_identity_policy_candidate',
        }) as unknown as JsonObject,
    );
  }
  const unknownReasons: string[] = [];
  if (malformed) unknownReasons.push('binding_ambiguous');
  // Candidates exist only for buckets the AWS collection observed; an unresolved bucket was
  // never compared with any identity.
  if (targets.some(node => string(node, 'provider') === 'aws' && string(node, 'cloud_status') !== 'resolved'))
    unknownReasons.push('resource_not_collected');
  if (index.undeclaredDeployments) unknownReasons.push('direct_access_undeclared');
  if (index.untargetedPaths) unknownReasons.push('direct_access_untargeted');
  if (index.unresolvedPaths) unknownReasons.push('direct_access_target_unresolved');
  if (!buckets.length) unknownReasons.push('identity_scope_not_collected_for_resource');
  else if (!index.identityCollected) unknownReasons.push('identity_scope_not_collected');
  else {
    if (index.identityUnknown) unknownReasons.push('identity_scope_unknown');
    // Candidates are collected per account: an identity elsewhere was never compared with
    // this bucket, and a cross-account bucket policy can still let it in.
    if ([...index.identityAccounts].some(account => account === null || !accounts.has(account)) || accounts.has(null))
      unknownReasons.push('identity_scope_other_account');
    if (index.undeclaredIdentities) unknownReasons.push('execution_identity_undeclared');
  }
  // Paths and identities of teams this reader cannot see may reach the resource too.
  if (!scope.allTeams && projection.outsideVisibleScope !== false) unknownReasons.push('outside_visible_scope');
  const status: Reach = reached ? 'yes' : unknownReasons.length ? 'unknown' : 'none_found';
  return { status, unknownReasons, directAccess, directAccessTruncated, identities, identitiesTruncated };
}
/**
 * Reach with its own work budget, shared by every row of one response: if it runs out, that
 * row and every later one read `unknown` (`reach_not_evaluated`) and the response still
 * answers. Rows judged before that keep their status: each used a complete index.
 */
function boundedReach(remaining: number, maxBytes: number) {
  const work = new QueryWork(Math.max(1, remaining - 25), maxBytes);
  let exhausted = false;
  return (projection: MapProjection, resource: MapNode, scope: ReadScope, detail = false): ReachResult => {
    if (!exhausted)
      try {
        return outsideGuardReach(projection, resource, scope, work, detail);
      } catch (error) {
        const code = error instanceof MapQueryError ? error.code : '';
        if (code !== 'MAP_LIMIT_EXCEEDED' && code !== 'MAP_TIMEOUT') throw error;
        exhausted = true;
      }
    return {
      status: 'unknown',
      unknownReasons: ['reach_not_evaluated'],
      directAccess: [],
      directAccessTruncated: false,
      identities: [],
      identitiesTruncated: false,
    };
  };
}
const OUTSIDE_GUARD_LIMITATION =
  'Only S3 identity policies and host declarations of this source are checked, within your visible scope; none_found is not proof that no path exists.';

/**
 * C2 per execution binding in the agent's focus. A store that did not run the reverse identity
 * read reports every binding as `unknown` rather than leaving it out.
 */
function identityScope(projection: MapProjection, graph: { nodes: MapNode[] }): JsonObject[] {
  const executions = graph.nodes.filter(node => node.label === 'GuardExecutionBinding');
  const known = new Map((projection.identityScope ?? []).map(item => [item.executionBindingId, item]));
  return ordered(
    executions.map(execution => {
      const item = known.get(execution.entityId);
      return {
        id: execution.entityId,
        ...(item ?? {
          executionBindingId: execution.entityId,
          deploymentId: null,
          tool: string(execution, 'tool'),
          identityId: null,
          accountId: null,
          status: 'unknown',
          // The store did not evaluate this binding (not run, or more work than allowed).
          reason: 'not_evaluated',
          observedAt: null,
          boundBuckets: [],
          extraResources: [],
          truncated: false,
          evidenceKind: 'iam_identity_policy_candidate',
          assessment: 'unknown',
        }),
      } as unknown as JsonObject;
    }),
  );
}

const POLICY_ACTIONS: Readonly<Record<string, string>> = Object.freeze({
  's3:GetObject': 'CAN_READ',
  's3:PutObject': 'CAN_WRITE',
  's3:ListBucket': 'CAN_LIST',
});
const POLICY_REASONS = Object.freeze({
  unavailable: [
    'binding_ambiguous',
    'cloud_unresolved',
    'provider_missing',
    'collection_invalid',
    'stale',
    'changed',
    'boundary_unresolved',
    'unsupported_policy',
    'evidence_invalid',
  ],
  not_collected: [
    'unsupported_action',
    'identity_not_static',
    'unsupported_binding',
    'cloud_not_collected',
    'collection_missing',
    'disabled',
  ],
});
const POLICY_FIELDS = [
  'taskId',
  'deploymentId',
  'executionBindingId',
  'resourceBindingId',
  'identityId',
  'resourceId',
  'action',
  'status',
  'reason',
  'observedAt',
  'assessment',
  'candidates',
]
  .sort()
  .join(',');
function policyObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function policyTime(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const instant = Date.parse(value);
  return (
    Number.isFinite(instant) &&
    instant >= 0 &&
    instant <= 253_402_300_799_999 &&
    new Date(instant).toISOString() === value
  );
}
function comparePolicyKeys(a: string, b: string): number {
  let left = 0,
    right = 0;
  while (left < a.length && right < b.length) {
    const ac = a.codePointAt(left)!,
      bc = b.codePointAt(right)!;
    if (ac !== bc) return ac - bc;
    left += ac > 0xffff ? 2 : 1;
    right += bc > 0xffff ? 2 : 1;
  }
  return a.length - left - (b.length - right);
}
/** Custom stores receive the same closed output contract and binding-path checks. */
function validatedPolicyEvidence(projection: MapProjection, work: QueryWork): readonly MapPolicyEvidence[] {
  const rawInput = projection.policyEvidence;
  if (rawInput === undefined) return [];
  if (!Array.isArray(rawInput)) fail('MAP_UNAVAILABLE');
  if (rawInput.length > 512) fail('MAP_LIMIT_EXCEEDED');
  let input: readonly MapPolicyEvidence[];
  try {
    input = immutableJson(rawInput, 8, 100_000, 4 * 1024 * 1024) as unknown as readonly MapPolicyEvidence[];
  } catch {
    return fail('MAP_UNAVAILABLE');
  }
  work.step(projection.nodes.length);
  const entities = new Map(projection.nodes.map(node => [node.entityId, node]));
  if (input.length && entities.size !== projection.nodes.length) fail('MAP_UNAVAILABLE');
  const seen = new Set<string>(),
    result: MapPolicyEvidence[] = [];
  let materializedBytes = 0;
  const link = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length);
    return targets.includes(target.id);
  };
  const exactLink = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length);
    return targets.length === 1 && targets[0] === target.id;
  };
  // Tasks may have several grants and grants several selectors, but the
  // particular pair proving this record must not have duplicate relationships.
  const uniqueLink = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length);
    return targets.filter(id => id === target.id).length === 1;
  };
  const endpoint = (id: unknown, label: MapNode['label']): MapNode => {
    mapIdentifier(id, 'MAP_UNAVAILABLE');
    const node = entities.get(id as string);
    if (!node || node.label !== label) fail('MAP_UNAVAILABLE');
    return node;
  };
  for (const raw of input) {
    work.step();
    if (
      !policyObject(raw) ||
      Object.keys(raw).sort().join(',') !== POLICY_FIELDS ||
      raw.assessment !== 'unknown' ||
      typeof raw.action !== 'string' ||
      (raw.observedAt !== null && !policyTime(raw.observedAt))
    )
      fail('MAP_UNAVAILABLE');
    mapIdentifier(raw.action, 'MAP_UNAVAILABLE');
    // Generic host actions carry no cloud-policy inference. Keep their explicit
    // unsupported observation readable without admitting a cloud candidate.
    const genericAction = !/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(raw.action);
    if (genericAction) {
      if (raw.status !== 'not_collected' || raw.reason !== 'unsupported_action') fail('MAP_UNAVAILABLE');
    }
    if (!Array.isArray(raw.candidates) || raw.candidates.length > 1) fail('MAP_UNAVAILABLE');
    if (raw.status === 'complete') {
      if (
        !policyTime(raw.observedAt) ||
        !POLICY_ACTIONS[raw.action] ||
        raw.reason !== (raw.candidates.length ? null : 'no_candidate')
      )
        fail('MAP_UNAVAILABLE');
    } else if (
      (raw.status !== 'unavailable' && raw.status !== 'not_collected') ||
      !POLICY_REASONS[raw.status].includes(raw.reason as string) ||
      raw.candidates.length
    )
      fail('MAP_UNAVAILABLE');
    for (const candidate of raw.candidates) {
      if (
        !policyObject(candidate) ||
        Object.keys(candidate).sort().join(',') !== 'conditionKeys,hasCondition,relationship,resourceScope' ||
        candidate.relationship !== POLICY_ACTIONS[raw.action] ||
        candidate.resourceScope !== 'bucket_summary' ||
        typeof candidate.hasCondition !== 'boolean' ||
        !Array.isArray(candidate.conditionKeys) ||
        candidate.conditionKeys.length > 128
      )
        fail('MAP_UNAVAILABLE');
      for (const key of candidate.conditionKeys) {
        work.step();
        mapIdentifier(key, 'MAP_UNAVAILABLE');
        if (Buffer.byteLength(key as string, 'utf8') > 256 || /[\u0000-\u001f]/.test(key as string))
          fail('MAP_UNAVAILABLE');
      }
      if (
        candidate.hasCondition !== !!candidate.conditionKeys.length ||
        JSON.stringify(candidate.conditionKeys) !==
          JSON.stringify([...new Set(candidate.conditionKeys as string[])].sort(comparePolicyKeys))
      )
        fail('MAP_UNAVAILABLE');
    }
    const task = endpoint(raw.taskId, 'GuardTask'),
      deployment = endpoint(raw.deploymentId, 'GuardDeployment');
    const execution = endpoint(raw.executionBindingId, 'GuardExecutionBinding'),
      resource = endpoint(raw.resourceBindingId, 'GuardResourceBinding');
    const tool = string(execution, 'tool');
    if (
      !tool ||
      string(resource, 'tool') !== tool ||
      !strings(resource, 'actions').includes(raw.action) ||
      !link(task, deployment, 'G_ASSIGNED_TO') ||
      !link(execution, deployment, 'G_EXECUTES_FOR')
    )
      fail('MAP_UNAVAILABLE');
    const tools = connected(projection, new Set([execution.id]), 'G_EXECUTES_TOOL', work).filter(
      node => node.label === 'GuardTool' && string(node, 'name') === tool,
    );
    const grants = connected(projection, new Set([task.id]), 'G_HAS_GRANT', work).filter(
      node => node.label === 'GuardGrant' && string(node, 'tool') === tool,
    );
    const selectors = connected(projection, new Set([resource.id]), 'G_BINDS_SELECTOR', work).filter(
      node =>
        node.label === 'GuardResource' &&
        string(node, 'tool') === tool &&
        string(node, 'resource_id') === string(resource, 'resource_ref'),
    );
    if (
      !grants.some(
        grant =>
          strings(grant, 'resources').includes(string(resource, 'resource_ref') ?? '') &&
          (raw.status !== 'complete' || uniqueLink(task, grant, 'G_HAS_GRANT')) &&
          tools.some(toolNode => (raw.status === 'complete' ? exactLink : link)(grant, toolNode, 'G_FOR_TOOL')) &&
          selectors.some(selector => (raw.status === 'complete' ? uniqueLink : link)(grant, selector, 'G_TARGETS')),
      )
    )
      fail('MAP_UNAVAILABLE');
    for (const [key, label, relation, owner] of [
      ['identityId', 'GuardExternalIdentity', 'G_USES_IDENTITY', execution],
      ['resourceId', 'GuardExternalResource', 'G_MAPS_TO', resource],
    ] as const) {
      if (raw[key] === null) {
        if (raw.status === 'complete') fail('MAP_UNAVAILABLE');
        continue;
      }
      const target = endpoint(raw[key], label);
      if (!(raw.status === 'complete' ? exactLink(owner, target, relation) : link(owner, target, relation)))
        fail('MAP_UNAVAILABLE');
    }
    if (
      genericAction &&
      (raw.resourceId === null || string(endpoint(raw.resourceId, 'GuardExternalResource'), 'provider') !== 'host')
    )
      fail('MAP_UNAVAILABLE');
    if (raw.status === 'complete') {
      const agents = connected(projection, new Set([deployment.id]), 'G_INSTANCE_OF', work).filter(
        node => node.label === 'GuardAgent',
      );
      if (
        agents.length !== 1 ||
        !exactLink(deployment, agents[0]!, 'G_INSTANCE_OF') ||
        string(execution, 'identity_selection') !== 'static' ||
        !exactLink(task, deployment, 'G_ASSIGNED_TO') ||
        !exactLink(execution, deployment, 'G_EXECUTES_FOR') ||
        tools.length !== 1 ||
        !exactLink(execution, tools[0]!, 'G_EXECUTES_TOOL') ||
        selectors.length !== 1 ||
        !exactLink(resource, selectors[0]!, 'G_BINDS_SELECTOR')
      )
        fail('MAP_UNAVAILABLE');
    }
    const identity = JSON.stringify([
      raw.taskId,
      raw.deploymentId,
      raw.executionBindingId,
      raw.resourceBindingId,
      raw.action,
    ]);
    if (seen.has(identity)) fail('MAP_UNAVAILABLE');
    seen.add(identity);
    try {
      const copy = immutableJson(raw, 6, 1024, 64 * 1024) as unknown as MapPolicyEvidence;
      materializedBytes += Buffer.byteLength(JSON.stringify(copy));
      if (materializedBytes > 4 * 1024 * 1024) fail('MAP_LIMIT_EXCEEDED');
      result.push(copy);
    } catch {
      fail('MAP_LIMIT_EXCEEDED');
    }
  }
  return result;
}
function policyCoverage(records: readonly MapPolicyEvidence[]): JsonObject {
  const complete = records.filter(item => item.status === 'complete').length;
  const observed = records.flatMap(item => (item.observedAt === null ? [] : [item.observedAt])).sort();
  return {
    status:
      !records.length || records.every(item => item.status === 'not_collected')
        ? 'not_collected'
        : complete === records.length
          ? 'complete'
          : complete
            ? 'partial'
            : 'unavailable',
    observedAt: observed[0] ?? null,
    assessment: 'unknown',
  };
}
function selectedPolicy(
  projection: MapProjection,
  work: QueryWork,
  options: {
    nodes?: readonly MapNode[];
    task?: MapNode;
    executions?: readonly MapNode[];
    resources?: readonly MapNode[];
    action?: string;
  } = {},
): readonly MapPolicyEvidence[] {
  const ids = options.nodes ? new Set(options.nodes.map(node => node.entityId)) : undefined;
  const executions = options.executions ? new Set(options.executions.map(node => node.entityId)) : undefined;
  const resources = options.resources ? new Set(options.resources.map(node => node.entityId)) : undefined;
  return work.policy(projection).filter(record => {
    work.step();
    return (
      (!ids ||
        [
          record.taskId,
          record.deploymentId,
          record.executionBindingId,
          record.resourceBindingId,
          record.identityId,
          record.resourceId,
        ].every(id => id === null || ids.has(id))) &&
      (!options.task || record.taskId === options.task.entityId) &&
      (!executions || executions.has(record.executionBindingId)) &&
      (!resources || resources.has(record.resourceBindingId)) &&
      (!options.action || record.action === options.action)
    );
  });
}

function knownBlockers(task: MapNode, tool: MapNode | undefined, now: number): string[] {
  const blockers: string[] = [];
  if (task.properties.revoked === true) blockers.push('task_revoked');
  const deadline = number(task, 'deadline');
  if (deadline !== null && now >= deadline) blockers.push('deadline_expired');
  const calls = number(task, 'calls'),
    maxCalls = number(task, 'max_calls');
  if (calls !== null && maxCalls !== null && calls >= maxCalls) blockers.push('call_budget_exhausted');
  const concurrent = number(task, 'concurrent'),
    maxConcurrent = number(task, 'max_concurrent');
  if (concurrent !== null && maxConcurrent !== null && concurrent >= maxConcurrent)
    blockers.push('concurrency_full_at_capture');
  const spent = number(task, 'spent'),
    reserved = number(task, 'reserved'),
    maxCost = number(task, 'max_cost');
  const cost = tool ? number(tool, 'max_cost') : null;
  if (spent !== null && reserved !== null && maxCost !== null && cost !== null && spent + reserved + cost > maxCost)
    blockers.push('cost_budget_exceeded');
  if (tool?.properties.control_plane === true && task.properties.allow_control_plane === false)
    blockers.push('control_plane_disabled');
  return blockers;
}
function externalEvidence(
  projection: MapProjection,
  task: MapNode,
  toolName: string,
  resourceId: string,
  work: QueryWork,
  policySelection: { action?: string; resourceBindingId?: string } = {},
): JsonObject {
  const deployment = connected(projection, new Set([task.id]), 'G_ASSIGNED_TO', work);
  const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true).filter(
    node => string(node, 'tool') === toolName,
  );
  work.step(projection.nodes.length);
  const resources = projection.nodes.filter(
    node =>
      node.label === 'GuardResourceBinding' &&
      string(node, 'tool') === toolName &&
      string(node, 'resource_ref') === resourceId &&
      (!policySelection.resourceBindingId || node.entityId === policySelection.resourceBindingId),
  );
  const policy = selectedPolicy(projection, work, {
    task,
    executions,
    resources,
    ...(policySelection.action ? { action: policySelection.action } : {}),
  });
  return {
    executionBindings: executions.map(node => ({
      id: node.entityId,
      ...node.properties,
      identities: connected(projection, new Set([node.id]), 'G_USES_IDENTITY', work).map(identity => ({
        ...identity.properties,
      })),
      connections: connected(projection, new Set([node.id]), 'G_VIA_CONNECTION', work).map(connection => ({
        ...connection.properties,
      })),
    })),
    resourceBindings: resources.map(node => ({
      id: node.entityId,
      ...node.properties,
      targets: connected(projection, new Set([node.id]), 'G_MAPS_TO', work).map(target => ({ ...target.properties })),
    })),
    policyEvidence: policy as unknown as readonly JsonObject[],
    policyCoverage: policyCoverage(policy),
    assessment: 'unknown',
    limitations: [
      'Host bindings and provider inventory are evidence, not effective cloud permissions.',
      'Container matches do not establish exact object or prefix access; missing evidence does not establish denial.',
    ],
  };
}
const COMMON_UNKNOWN = [
  'live_authorization',
  'request_arguments_and_resolution',
  'custom_policy',
  'backend_authorization',
  'action_approval',
];
function explain(
  projection: MapProjection,
  scope: ReadScope,
  task: MapNode,
  toolName: string,
  resourceId: string,
  now: number,
  work: QueryWork,
  policySelection: { action?: string; resourceBindingId?: string } = {},
): JsonObject {
  const index = work.index(projection),
    nodes = index.nodes;
  work.step(projection.nodes.length);
  const tool = projection.nodes.find(node => node.label === 'GuardTool' && string(node, 'name') === toolName);
  const blockers: string[] = [],
    matched: JsonObject[] = [],
    chain: JsonObject[] = [];
  const unknown = [...COMMON_UNKNOWN];
  if (!scope.allTeams) unknown.push('ancestor_evidence_outside_visible_scope');
  if (!tool || tool.properties.known_metadata === false || tool.properties.registered === false)
    blockers.push('tool_unregistered_at_capture');
  else if (tool.properties.registered !== true) unknown.push('tool_registration');
  if (tool?.properties.approved === false) blockers.push('tool_metadata_unapproved');
  else if (tool?.properties.approved !== true) unknown.push('tool_metadata_approval');
  const visited = new Set<string>();
  let current: MapNode | undefined = task;
  for (let depth = 0; current; depth++) {
    work.step();
    if (depth >= 16 || visited.has(current.id)) {
      unknown.push('delegation_depth_or_cycle');
      break;
    }
    visited.add(current.id);
    chain.push({ id: current.entityId, taskId: string(current, 'task_id') });
    blockers.push(...knownBlockers(current, tool, now));
    const grants = connected(projection, new Set([current.id]), 'G_HAS_GRANT', work).filter(
      node =>
        node.label === 'GuardGrant' &&
        string(node, 'tool') === toolName &&
        strings(node, 'resources').some(resource => resource === resourceId || resource === '*'),
    );
    if (!grants.length)
      blockers.push(current.id === task.id ? 'declared_grant_missing' : 'ancestor_declared_grant_missing');
    matched.push(...grants.map(grantSummary));
    const parents: readonly string[] = index.outgoing.get(current.id)?.get('G_DELEGATED_FROM') ?? [];
    work.step(parents.length);
    if (parents.length > 1) {
      unknown.push('delegation_evidence_ambiguous');
      break;
    }
    current = parents[0] ? nodes.get(parents[0]) : undefined;
  }
  if (task.properties.sensitive === true) unknown.push('sensitive_egress_and_recipient_checks');
  return {
    taskId: string(task, 'task_id'),
    tool: toolName,
    resourceId,
    assessment: blockers.length ? 'blocked' : 'unknown',
    evidenceKind: 'declared_and_observed',
    blockers: unique(blockers),
    unknownChecks: unique(unknown),
    delegation: chain,
    matchedGrants: matched,
    externalEvidence: externalEvidence(projection, task, toolName, resourceId, work, policySelection),
    limitations: [
      'Explanation only; no action was prepared or executed.',
      'A clear exported gate does not establish effective permission.',
    ],
  };
}

const IGNORE_DIFF = new Set([
  'lastupdated',
  'manifest_observed_at',
  'manifest_revision',
  'observed_at',
  'capture_observed_at',
  'cloud_observed_at',
  // Recorded since 0.2.0; they cannot change for a task, so they are never a change.
  'delegated',
  'derived',
]);
function nodeState(node: MapNode, projection: MapProjection, work: QueryWork): string {
  const index = work.index(projection);
  const properties = Object.fromEntries(Object.entries(safeProperties(node)).filter(([key]) => !IGNORE_DIFF.has(key)));
  const edges = [...(index.outgoing.get(node.id)?.entries() ?? [])]
    .flatMap(([kind, targets]) => {
      work.step(targets.length);
      return targets.map(target => ({ kind, target: index.nodes.get(target)?.entityId ?? null }));
    })
    .sort((a, b) => compare(`${a.kind}:${a.target}`, `${b.kind}:${b.target}`));
  return canonicalJson({ properties, edges } as Json);
}
function freshness(observedAt: unknown, now: number, staleSeconds: number): JsonObject {
  const captured = typeof observedAt === 'string' ? Date.parse(observedAt) : NaN,
    age = now - captured;
  return {
    stale: !Number.isFinite(captured) || age < -60_000 || age > staleSeconds * 1000,
    ageSeconds: Number.isFinite(captured) ? Math.max(0, Math.floor(age / 1000)) : null,
  };
}
function changeSummary(node: MapNode): JsonObject {
  return {
    entityId: node.entityId,
    label: node.label,
    name:
      string(node, 'name') ??
      string(node, 'display_name') ??
      string(node, 'description') ??
      string(node, 'task_id') ??
      string(node, 'agent_id') ??
      string(node, 'deployment_id') ??
      string(node, 'binding_id') ??
      string(node, 'connection_id') ??
      string(node, 'resource_id') ??
      string(node, 'tool') ??
      node.entityId,
  };
}

const collection = Object.freeze({
  approvals: 'not_collected',
  requestTimeDecisions: 'not_collected',
  backendReceipts: 'not_collected',
  externalPolicyHistory: 'not_collected',
});
// Discovery views list what belongs to no team, so only an all-teams reader sees them. A
// team-scoped reader gets this fixed answer without any read: no names, no counts, and the
// same words whether or not anything would be listed.
const ALL_TEAMS_NOTE =
  'Shown only to readers with all-teams visibility, because what it lists belongs to no team. This note is the same whether or not anything would be listed.';
const notVisible = (): JsonObject => ({
  visibility: 'all_teams_required',
  status: 'not_visible',
  note: ALL_TEAMS_NOTE,
});
function undeclaredCounts(source: MapSource, activity: MapUndeclaredActivity): JsonObject {
  return {
    // Counting stops at 10,000: a minimum is partial, not complete.
    status: activity.tasksCapped || activity.principalsCapped ? 'partial' : 'complete',
    tasks: activity.tasks,
    tasksIsMinimum: activity.tasksCapped,
    principals: activity.principals,
    principalsIsMinimum: activity.principalsCapped,
    // Without a manifest no agent can be declared, so everything the executor saw counts.
    manifest: source.profile === 'core' ? 'not_collected' : 'collected',
  };
}
const UNDECLARED_LIMITATIONS = [
  'Only activity that ran through an enrolled executor is seen. An agent that does not use the guard leaves nothing here.',
  'A task is undeclared when no manifest task binding assigns it to a deployment of a declared agent. parentDeclared marks a task whose direct parent is assigned: usually a sub-task that only lacks its own binding.',
  'A lead to follow up, not a finding. Listing grants or blocks nothing.',
];
const UNCLAIMED_LIMITATIONS = [
  'Candidates to review, not findings: most IAM roles and users are not agents, and the map cannot tell which are.',
  'An identity is claimed when a declared execution binding names its exact ARN in a current snapshot you can read. Role assumption, instance profiles and federation are not followed.',
  'Only IAM roles and users of an enrolled AWS account are collected. An account that is missing, stale or inconsistent reads unknown, and its identities are not listed. Listing grants or blocks nothing.',
];
const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const agentSortKey = (agent: JsonObject): string =>
  JSON.stringify([
    agent.name === null || agent.name === undefined ? 1 : 0,
    agent.name ?? '',
    agent.sourceId ?? '',
    agent.id ?? '',
  ]);
function ordered(items: JsonObject[]): JsonObject[] {
  return items.sort((a, b) =>
    compare(
      JSON.stringify([
        a.name ?? a.displayName ?? '',
        a.sourceId ?? '',
        a.id ?? a.entityId ?? '',
        a.source ?? '',
        a.target ?? '',
        a.kind ?? '',
      ]),
      JSON.stringify([
        b.name ?? b.displayName ?? '',
        b.sourceId ?? '',
        b.id ?? b.entityId ?? '',
        b.source ?? '',
        b.target ?? '',
        b.kind ?? '',
      ]),
    ),
  );
}
function page(items: readonly JsonObject[], args: Readonly<Record<string, JsonValue>>): JsonObject {
  const offset = (args.offset as number | undefined) ?? 0,
    limit = (args.limit as number | undefined) ?? 50;
  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    offset,
    limit,
    truncated: offset + limit < items.length,
  };
}
function ownerSummary(source: MapSource, projection: MapProjection, node: MapNode, work: QueryWork): JsonObject {
  return {
    id: node.entityId,
    ownerId: string(node, 'owner_id'),
    name: string(node, 'name'),
    kind: string(node, 'kind'),
    sourceId: source.id,
    ...hostObservation(node),
    agentCount: connected(projection, new Set([node.id]), 'G_OWNED_BY', work, true).filter(
      n => n.label === 'GuardAgent',
    ).length,
    resourceCount: connected(projection, new Set([node.id]), 'G_RESOURCE_OWNED_BY', work, true).filter(
      n => n.label === 'GuardResourceBinding',
    ).length,
  };
}
function resourceSummary(source: MapSource, projection: MapProjection, node: MapNode, work: QueryWork): JsonObject {
  return {
    id: node.entityId,
    bindingId: string(node, 'binding_id'),
    sourceId: source.id,
    displayName: string(node, 'display_name') ?? string(node, 'resource_ref'),
    tool: string(node, 'tool'),
    resourceRef: string(node, 'resource_ref'),
    scope: string(node, 'scope'),
    actions: strings(node, 'actions'),
    ownerId: string(node, 'owner_id'),
    ownerName:
      connected(projection, new Set([node.id]), 'G_RESOURCE_OWNED_BY', work)
        .filter(n => n.label === 'GuardOwner')
        .map(n => string(n, 'name'))[0] ?? null,
    ownershipStatus: string(node, 'ownership_status') ?? 'unknown',
    ownershipSource: string(node, 'ownership_source'),
    sensitivity: string(node, 'sensitivity') ?? 'unknown',
    approvedDestinations: strings(node, 'approved_destinations'),
    targets: connected(projection, new Set([node.id]), 'G_MAPS_TO', work)
      .filter(n => n.label === 'GuardExternalResource')
      .map(n => ({ id: n.entityId, ...safeProperties(n) })),
    dependencies: connected(projection, new Set([node.id]), 'G_DEPENDS_ON', work)
      .filter(n => n.label === 'GuardResourceBinding')
      .map(n => ({
        id: n.entityId,
        bindingId: string(n, 'binding_id'),
        displayName: string(n, 'display_name') ?? string(n, 'resource_ref'),
      })),
    ...hostObservation(node),
  };
}
function relationshipRows(projection: MapProjection, work: QueryWork): JsonObject[] {
  const index = work.index(projection);
  work.step(projection.edges.length);
  return ordered(
    projection.edges.flatMap(edge => {
      const source = index.nodes.get(edge.source),
        target = index.nodes.get(edge.target);
      return source && target
        ? [
            {
              source: source.entityId,
              target: target.entityId,
              kind: edge.kind,
              sourceName: changeSummary(source).name!,
              sourceLabel: source.label,
              targetName: changeSummary(target).name!,
              targetLabel: target.label,
            },
          ]
        : [];
    }),
  );
}
function inventorySections(
  source: MapSource,
  projection: MapProjection,
  agent: MapNode,
  work: QueryWork,
): Record<(typeof sections)[number], JsonObject[]> {
  const byLabel = (label: MapNode['label']): MapNode[] => projection.nodes.filter(node => node.label === label);
  const described = (label: MapNode['label']): JsonObject[] =>
    byLabel(label).map(node => ({ id: node.entityId, ...safeProperties(node) }));
  const summary = agentSummary(source, projection, agent, work);
  return {
    overview: [
      {
        purpose: summary.purpose!,
        lifecycleState: summary.lifecycleState!,
        ownershipStatus: summary.ownershipStatus!,
        ownershipSource: summary.ownershipSource!,
        ownerName: summary.ownerName!,
        ...hostObservation(agent),
      },
    ],
    owners: ordered(byLabel('GuardOwner').map(node => ownerSummary(source, projection, node, work))),
    deployments: ordered(
      byLabel('GuardDeployment').map(node => ({
        id: node.entityId,
        deploymentId: string(node, 'deployment_id'),
        environment: string(node, 'environment'),
        runtimeRef: string(node, 'runtime_ref'),
        workloadGeneration: string(node, 'workload_generation'),
        buildRef: string(node, 'build_ref'),
        bindingAuthority: string(node, 'binding_authority'),
        // The same rule as get_agent_access: `found` needs an entry in the read.
        directAccessStatus: connected(projection, new Set([node.id]), 'G_DIRECT_ACCESS_FOR', work, true).length
          ? 'found'
          : string(node, 'direct_access_status') === 'none_declared'
            ? 'none_declared'
            : 'unknown',
        ...hostObservation(node),
      })),
    ),
    tasks: ordered(byLabel('GuardTask').map(taskSummary)),
    permissions: ordered(byLabel('GuardGrant').map(grantSummary)),
    resources: ordered(byLabel('GuardResourceBinding').map(node => resourceSummary(source, projection, node, work))),
    connections: ordered(described('GuardMcpConnection')),
    credentials: ordered(
      byLabel('GuardCredentialReference').map(node => ({
        id: node.entityId,
        credentialId: string(node, 'credential_id'),
        name: string(node, 'name'),
        issuerRef: string(node, 'issuer_ref'),
        audienceRefs: strings(node, 'audience_refs'),
        recipientRefs: strings(node, 'recipient_refs'),
        lifecycleState: string(node, 'lifecycle_state') ?? 'unknown',
        expiresAt: string(node, 'expires_at'),
        rotationStatus: string(node, 'rotation_status') ?? 'unknown',
        ...hostObservation(node),
      })),
    ),
    relationships: relationshipRows(projection, work),
    tools: ordered(described('GuardTool')),
    bindings: ordered(
      projection.nodes
        .filter(node => ['GuardExecutionBinding', 'GuardResourceBinding'].includes(node.label))
        .map(node => ({ id: node.entityId, kind: node.label, ...safeProperties(node) })),
    ),
    identities: ordered(described('GuardExternalIdentity')),
    policies: [],
  };
}

function retainedChanges(
  source: MapSource,
  args: Readonly<Record<string, JsonValue>>,
  scope: ReadScope,
  work: QueryWork,
): JsonObject {
  const current = source.current,
    since = args.since ?? 'previous';
  const previous = [current.id, current.snapshotId].includes(since as string)
    ? current
    : source.previous &&
        (since === 'previous' || [source.previous.id, source.previous.snapshotId].includes(since as string))
      ? source.previous
      : null;
  const projections = previous && previous !== current ? [current, previous] : [current];
  const related = new Map<MapProjection, Map<string, JsonObject[]>>();
  for (const projection of projections) {
    const impacted = new Map<string, JsonObject[]>();
    for (const agent of projection.nodes.filter(node => node.label === 'GuardAgent')) {
      const brief = {
        id: agent.entityId,
        agentId: string(agent, 'agent_id'),
        name: string(agent, 'name'),
        sourceId: source.id,
      };
      for (const node of focus(projection, agent, work).nodes) {
        const owners = impacted.get(node.entityId) ?? [];
        owners.push(brief);
        impacted.set(node.entityId, owners);
      }
    }
    related.set(projection, impacted);
  }
  const selectedAgents = new Set<string>(),
    selectedResources = new Set<string>();
  for (const projection of projections) {
    for (const node of projection.nodes) {
      work.step();
      if (args.agentId && node.label === 'GuardAgent' && matching(node, args.agentId as string, 'agent_id'))
        selectedAgents.add(node.entityId);
      if (
        args.resourceId &&
        node.label === 'GuardResourceBinding' &&
        matching(node, args.resourceId as string, 'binding_id')
      ) {
        const selectors = connected(projection, new Set([node.id]), 'G_BINDS_SELECTOR', work);
        const grants = connected(projection, nodeIds(selectors), 'G_TARGETS', work, true);
        const tasks = connected(projection, nodeIds(grants), 'G_HAS_GRANT', work, true);
        const deployment = connected(projection, nodeIds(tasks), 'G_ASSIGNED_TO', work);
        const tools = connected(projection, nodeIds(grants), 'G_FOR_TOOL', work);
        const toolIds = nodeIds(tools);
        const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true).filter(execution =>
          connected(projection, new Set([execution.id]), 'G_EXECUTES_TOOL', work).some(tool => toolIds.has(tool.id)),
        );
        for (const item of [
          node,
          ...selectors,
          ...grants,
          ...tasks,
          ...deployment,
          ...tools,
          ...executions,
          ...connected(projection, new Set([node.id]), 'G_MAPS_TO', work),
          ...connected(projection, new Set([node.id]), 'G_RESOURCE_OWNED_BY', work),
          ...connected(projection, nodeIds(executions), 'G_USES_IDENTITY', work),
        ])
          selectedResources.add(item.entityId);
      }
    }
  }
  if ((args.agentId && !selectedAgents.size) || (args.resourceId && !selectedResources.size)) fail('MAP_NOT_FOUND');
  const uniqueAgents = (items: JsonObject[]): JsonObject[] =>
    ordered([...new Map(items.map(item => [item.id, item])).values()]);
  const before = new Map(previous?.nodes.map(node => [node.entityId, node]) ?? []),
    after = new Map(current.nodes.map(node => [node.entityId, node]));
  const beforeEdges = previous ? relationshipRows(previous, work) : [],
    afterEdges = relationshipRows(current, work);
  const edgeKey = (edge: JsonObject): string => JSON.stringify([edge.source, edge.target, edge.kind]);
  const oldEdges = new Set(beforeEdges.map(edgeKey)),
    newEdges = new Set(afterEdges.map(edgeKey));
  const relationships = {
    added: previous ? afterEdges.filter(edge => !oldEdges.has(edgeKey(edge))) : [],
    removed: previous ? beforeEdges.filter(edge => !newEdges.has(edgeKey(edge))) : [],
  };
  const outgoing = (edges: JsonObject[]): Map<string, JsonObject[]> => {
    const result = new Map<string, JsonObject[]>();
    for (const edge of edges) {
      const list = result.get(edge.source as string) ?? [];
      list.push(edge);
      result.set(edge.source as string, list);
    }
    return result;
  };
  const oldOutgoing = outgoing(beforeEdges),
    newOutgoing = outgoing(afterEdges),
    changedOutgoing = outgoing([...relationships.added, ...relationships.removed]);
  // A declared path's target is shown only when that resource is in the reader's scope.
  const visibleNow = targetVisibility(current, scope, work),
    visibleBefore = previous ? targetVisibility(previous, scope, work) : visibleNow;
  const state = (
    node: MapNode | undefined,
    edges: Map<string, JsonObject[]>,
    visible: (target: string) => boolean,
  ): JsonObject | null =>
    node
      ? {
          properties: Object.fromEntries(
            Object.entries(safeProperties(node)).filter(
              ([key, value]) =>
                !IGNORE_DIFF.has(key) &&
                !(
                  node.label === 'GuardDirectAccess' &&
                  key === 'target_ref' &&
                  typeof value === 'string' &&
                  !visible(value)
                ),
            ),
          ),
          relationships: edges.get(node.entityId) ?? [],
        }
      : null;
  const details: JsonObject[] = [];
  if (previous)
    for (const id of new Set([...after.keys(), ...before.keys()])) {
      work.step();
      const old = before.get(id),
        node = after.get(id),
        display = node ?? old!;
      if (node && old && nodeState(node, current, work) === nodeState(old, previous, work)) continue;
      const oldState = state(old, oldOutgoing, visibleBefore),
        newState = state(node, newOutgoing, visibleNow);
      const oldProps = oldState?.properties as JsonObject | undefined,
        newProps = newState?.properties as JsonObject | undefined;
      const fields = [...new Set([...Object.keys(oldProps ?? {}), ...Object.keys(newProps ?? {})])]
        .filter(
          key => canonicalJson((oldProps?.[key] ?? null) as Json) !== canonicalJson((newProps?.[key] ?? null) as Json),
        )
        .sort();
      const edgeChanges = changedOutgoing.get(id) ?? [];
      const categories: string[] = [];
      if (
        display.label === 'GuardOwner' ||
        fields.some(field => ['owner_id', 'team_id', 'ownership_status', 'ownership_source'].includes(field)) ||
        edgeChanges.some(edge => ['G_OWNED_BY', 'G_RESOURCE_OWNED_BY'].includes(edge.kind as string))
      )
        categories.push('ownership');
      if (
        ['GuardGrant', 'GuardTool', 'GuardTask'].includes(display.label) ||
        edgeChanges.some(edge => ['G_HAS_GRANT', 'G_FOR_TOOL', 'G_TARGETS'].includes(edge.kind as string))
      )
        categories.push('permissions');
      if (
        [
          'GuardDeployment',
          'GuardResourceBinding',
          'GuardExecutionBinding',
          'GuardExternalResource',
          'GuardExternalIdentity',
          'GuardCredentialReference',
          'GuardMcpConnection',
          'GuardMcpOperation',
        ].includes(display.label) ||
        edgeChanges.some(
          edge =>
            ![
              'G_OWNED_BY',
              'G_RESOURCE_OWNED_BY',
              'G_HAS_GRANT',
              'G_FOR_TOOL',
              'G_TARGETS',
              'G_DIRECT_ACCESS_FOR',
            ].includes(edge.kind as string),
        )
      )
        categories.push('bindings');
      // Host-declared paths around the guard, and a deployment's declaration status.
      const outsideGuard =
        display.label === 'GuardDirectAccess' ||
        fields.includes('direct_access_status') ||
        edgeChanges.some(edge => edge.kind === 'G_DIRECT_ACCESS_FOR');
      if (outsideGuard) categories.push('outside_guard');
      if (!categories.length) categories.push('inventory');
      const affected = uniqueAgents([
        ...(related.get(current)?.get(id) ?? []),
        ...(related.get(previous)?.get(id) ?? []),
      ]);
      if (args.agentId && !affected.some(agent => selectedAgents.has(agent.id as string))) continue;
      if (args.resourceId && !selectedResources.has(id)) continue;
      if (args.changeKind && args.changeKind !== 'all' && !categories.includes(args.changeKind as string)) continue;
      const navigation =
        display.label === 'GuardOwner' && string(display, 'owner_id')
          ? {
              operation: 'list_agents',
              args: { sourceId: source.id, ownerId: string(display, 'owner_id') },
              scope: 'direct_current_ownership',
              limitation: 'Lists agents directly owned now; excludes indirect impact through resource ownership.',
            }
          : display.label === 'GuardResourceBinding' && node
            ? {
                operation: 'get_resource_access',
                args: { sourceId: source.id, resourceId: node.entityId },
                scope: 'current_observations',
              }
            : null;
      details.push({
        ...changeSummary(display),
        kind: !old ? 'added' : !node ? 'removed' : 'changed',
        categories,
        ...(outsideGuard ? { evidenceKind: 'declared' } : {}),
        changedFields: fields,
        before: oldState,
        after: newState,
        affectedAgents: affected.slice(0, 100),
        affectedAgentsTotal: affected.length,
        affectedAgentsTruncated: affected.length > 100,
        affectedAgentNavigation: navigation,
      });
    }
  ordered(details);
  const { items, ...pagination } = page(details, args);
  const explicitlyPaged = args.offset !== undefined || args.limit !== undefined;
  const companion = explicitlyPaged ? (items as JsonObject[]) : details;
  const changedIds = new Set(companion.map(item => item.entityId));
  const relevantEdge = (edge: JsonObject): boolean => changedIds.has(edge.source);
  const affected = uniqueAgents(
    companion.flatMap(item => [
      ...(related.get(current)?.get(item.entityId as string) ?? []),
      ...(previous ? (related.get(previous)?.get(item.entityId as string) ?? []) : []),
    ]),
  );
  return {
    sourceId: source.id,
    from: previous ? receipt(source, previous) : null,
    to: receipt(source),
    changes: Object.fromEntries(
      ['added', 'removed', 'changed'].map(kind => [
        kind,
        companion
          .filter(item => item.kind === kind)
          .map(item => ({ entityId: item.entityId!, label: item.label!, name: item.name! })),
      ]),
    ),
    details: items!,
    ...pagination,
    relationships: {
      added: relationships.added.filter(relevantEdge),
      removed: relationships.removed.filter(relevantEdge),
    },
    changeSummaryScope: explicitlyPaged ? 'page' : 'retained',
    affectedAgents: affected.slice(0, 100),
    affectedAgentsTotal: affected.length,
    affectedAgentsTruncated: affected.length > 100,
    coverageGap: previous === null,
    policyHistory: 'not_collected',
    collection,
    limitations: [
      'Net changes in authorized retained snapshots only; not an invocation or intermediate-event log.',
      'Declared permission and binding changes do not establish effective access gain or loss.',
      'Current IAM policy observations are separate from retained Guard snapshots; policy history is not collected.',
    ],
  };
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
    if (
      !store ||
      typeof store.read !== 'function' ||
      (options.clock !== undefined && typeof options.clock !== 'function')
    )
      fail('MAP_CONFIG_INVALID');
    this.#store = store;
    this.#clock = options.clock ?? Date.now;
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
    try {
      now = this.#clock();
    } catch {
      return fail('MAP_UNAVAILABLE');
    }
    if (!Number.isSafeInteger(now) || now < 0 || now > 253_402_300_799_999) fail('MAP_UNAVAILABLE');
    const request = {
      ...(args.sourceId ? { sourceId: args.sourceId as string } : {}),
      // Filtering by flag needs every agent's flags; showing them needs only the page's.
      ...(operation === 'list_agents'
        ? args.flag !== undefined || args.flagStatus !== undefined
          ? { flags: true }
          : { summary: true }
        : {}),
      ...(['list_resources', 'get_resource_access'].includes(operation) ? { outsideGuard: true } : {}),
      ...(['get_agent_access', 'get_agent_inventory'].includes(operation) ? { agentId: args.agentId as string } : {}),
      // Boundary evidence (ancestors, `*` bindings, identity scope) only where it is shown.
      ...(operation === 'get_agent_access' ? { boundary: true } : {}),
      ...(operation === 'get_changes' ? { history: true } : {}),
    };
    const read = async (input: MapReadRequest, timeout = this.#timeout): Promise<MapView> => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          this.#store.read(scope, input),
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => reject(new MapQueryError('MAP_TIMEOUT')), timeout);
          }),
        ]);
      } catch (error) {
        if (
          error instanceof MapQueryError &&
          ['MAP_NOT_FOUND', 'MAP_LIMIT_EXCEEDED', 'MAP_UNAVAILABLE', 'MAP_TIMEOUT', 'MAP_SCOPE_INVALID'].includes(
            error.code,
          )
        )
          throw error;
        return fail('MAP_UNAVAILABLE');
      } finally {
        if (timer) clearTimeout(timer);
      }
    };
    // `flag` lists flagged agents; asking it for the absent ones is a contradiction.
    if (operation === 'list_agents' && args.flag !== undefined && args.flagStatus === 'absent')
      fail('MAP_REQUEST_INVALID');
    // Discovery operations use their own bounded reads, and none at all for a team-scoped reader.
    const discovery = operation === 'list_undeclared_activity' || operation === 'list_unclaimed_identities';
    const view: MapView = discovery ? { sources: [] } : await read(request);
    work.step(view.sources.length);
    let data: JsonObject;
    let graph: { nodes: MapNode[]; edges: MapEdge[] } | undefined;
    if (discovery && !scope.allTeams) {
      data = notVisible();
    } else if (operation === 'list_undeclared_activity') {
      const kind = (args.kind ?? 'tasks') as 'tasks' | 'principals';
      const offset = (args.offset as number | undefined) ?? 0,
        limit = (args.limit as number | undefined) ?? 50;
      const found = await read({ sourceId: args.sourceId as string, undeclared: true, page: { kind, offset, limit } });
      const source = findSource(found, args.sourceId as string);
      const activity = source.current.undeclared;
      if (!activity || activity.page?.kind !== kind) fail('MAP_UNAVAILABLE');
      work.step(activity.page.items.length);
      const total = kind === 'tasks' ? activity.tasks : activity.principals;
      const minimum = kind === 'tasks' ? activity.tasksCapped : activity.principalsCapped;
      data = {
        visibility: 'all_teams',
        kind,
        items: activity.page.items.map(item => ({ ...item, evidenceKind: 'observed', assessment: 'unknown' })),
        total,
        totalIsMinimum: minimum,
        offset,
        limit,
        truncated: minimum || offset + limit < total,
        counts: undeclaredCounts(source, activity),
        receipt: receipt(source),
        assessment: 'unknown',
        limitations: UNDECLARED_LIMITATIONS,
      };
    } else if (operation === 'list_unclaimed_identities') {
      const offset = (args.offset as number | undefined) ?? 0,
        limit = (args.limit as number | undefined) ?? 50;
      const found = await read({ unclaimedIdentities: true, page: { offset, limit } });
      const result = found.unclaimedIdentities;
      if (!result) fail('MAP_UNAVAILABLE');
      work.step(result.accounts.length + result.identities.length + found.sources.length);
      const complete = result.accounts.filter(account => account.status === 'complete').length;
      // No usable collection: nothing is known, so no total and no list. Some unusable: the
      // total and the list cover the complete accounts only.
      const status = !complete ? 'unknown' : complete === result.accounts.length ? 'complete' : 'partial';
      data = {
        visibility: 'all_teams',
        status,
        reason: result.accounts.length ? null : 'cloud_not_collected',
        identities: result.identities.map(identity => ({
          ...identity,
          candidate: true,
          evidenceKind: 'provider_inventory',
          assessment: 'unknown',
        })),
        total: status === 'unknown' ? null : result.total,
        offset,
        limit,
        truncated: status !== 'unknown' && offset + limit < result.total,
        accounts: result.accounts.map(account => ({
          ...account,
          ...(account.observedAt ? freshness(account.observedAt, now, this.#staleSeconds) : {}),
        })),
        bindingsWithoutIdentity: result.bindingsWithoutIdentity,
        // The snapshots whose declared bindings decided what counts as claimed.
        declaredFrom: found.sources.map(source => ({
          sourceId: source.id,
          tenantId: source.tenantId,
          snapshotId: source.current.snapshotId,
          generatedAt: source.current.generatedAt,
        })),
        assessment: 'unknown',
        limitations: UNCLAIMED_LIMITATIONS,
      };
    } else if (operation === 'list_agents') {
      const search = typeof args.search === 'string' ? args.search.toLocaleLowerCase('en-US') : '';
      const filtered = args.flag !== undefined || args.flagStatus !== undefined;
      const statuses: readonly DangerousThreeStatus[] =
        args.flagStatus !== undefined
          ? [args.flagStatus as DangerousThreeStatus]
          : args.flag !== undefined
            ? ['exposed', 'mitigated', 'unknown']
            : ['exposed', 'mitigated', 'unknown', 'absent'];
      const agents = view.sources
        .flatMap(source => {
          work.step(source.current.nodes.length);
          return source.current.nodes
            .filter(node => node.label === 'GuardAgent')
            .flatMap(agent => {
              const summary = agentSummary(source, source.current, agent, work);
              if (!filtered) return [summary];
              const status = agentFlags(source.current, agent, scope, work).status;
              return statuses.includes(status) ? [{ ...summary, boundaryFlags: { dangerousThree: status } }] : [];
            });
        })
        .filter(
          agent =>
            (!search ||
              [agent.name, agent.agentId].some(
                value => typeof value === 'string' && value.toLocaleLowerCase('en-US').includes(search),
              )) &&
            (args.ownerId === undefined || agent.ownerId === args.ownerId) &&
            (args.teamId === undefined || agent.teamId === args.teamId) &&
            (args.ownershipStatus === undefined || agent.ownershipStatus === args.ownershipStatus) &&
            (args.lifecycleState === undefined || agent.lifecycleState === args.lifecycleState) &&
            (args.environment === undefined ||
              (agent.environments as readonly string[]).includes(args.environment as string)),
        )
        // Unnamed agents sort last; code-unit order keeps paging identical on every host and locale.
        .sort((a, b) => compare(agentSortKey(a), agentSortKey(b)));
      const { items, ...pagination } = page(agents, args);
      let rows = items as JsonObject[];
      let flagsUnavailable: string | null = null;
      if (args.includeFlags === true && !filtered && rows.length) {
        // Flags for this page only: one read of these agents under the one-agent rules, so a
        // badge here matches get_agent_access and the work follows the page, not the fleet.
        // If that read is too large or fails, the listing still answers, with every flag unknown.
        // The page flags get what is left of this query's time, keep a margin for the answer,
        // and count their work separately: running out degrades flags, not the listing.
        const budget = work.remaining() - 50;
        const statuses = new Map<JsonObject, DangerousThreeStatus>();
        try {
          if (budget <= 0) fail('MAP_TIMEOUT');
          const flagged = await read(
            {
              ...(args.sourceId ? { sourceId: args.sourceId as string } : {}),
              flags: true,
              agentIds: rows.map(agent => agent.id as string),
            },
            budget,
          );
          const flagWork = new QueryWork(Math.max(1, work.remaining() - 25), this.#maxBytes);
          for (const agent of rows) {
            const source = flagged.sources.find(item => item.id === agent.sourceId);
            const node = source?.current.nodes.find(item => item.label === 'GuardAgent' && item.entityId === agent.id);
            // An agent gone between the two reads has no evidence now.
            if (source && node) statuses.set(agent, agentFlags(source.current, node, scope, flagWork).status);
          }
        } catch (error) {
          const code = error instanceof MapQueryError ? error.code : 'MAP_UNAVAILABLE';
          if (!['MAP_LIMIT_EXCEEDED', 'MAP_TIMEOUT', 'MAP_UNAVAILABLE'].includes(code)) throw error;
          statuses.clear();
          flagsUnavailable =
            code === 'MAP_LIMIT_EXCEEDED'
              ? 'flags_limit_exceeded'
              : code === 'MAP_TIMEOUT'
                ? 'flags_timeout'
                : 'flags_read_unavailable';
        }
        rows = rows.map(agent => ({ ...agent, boundaryFlags: { dangerousThree: statuses.get(agent) ?? 'unknown' } }));
      }
      data = { agents: rows, ...pagination, ...(flagsUnavailable ? { flagsUnavailable } : {}) };
    } else if (operation === 'list_owners' || operation === 'list_resources') {
      const search = typeof args.search === 'string' ? args.search.toLocaleLowerCase('en-US') : '';
      const ownerIndex = operation === 'list_owners';
      // Where each resource row came from, so reach can be judged after paging.
      const origins = new Map<JsonObject, { projection: MapProjection; node: MapNode }>();
      const rows = ordered(
        view.sources
          .flatMap(source => {
            work.step(source.current.nodes.length);
            return source.current.nodes
              .filter(node => node.label === (ownerIndex ? 'GuardOwner' : 'GuardResourceBinding'))
              .map(node => {
                if (ownerIndex) return ownerSummary(source, source.current, node, work);
                const summary = resourceSummary(source, source.current, node, work);
                origins.set(summary, { projection: source.current, node });
                return summary;
              });
          })
          .filter(
            item =>
              (!search ||
                [item.name, item.displayName, item.ownerId, item.bindingId, item.resourceRef].some(
                  value => typeof value === 'string' && value.toLocaleLowerCase('en-US').includes(search),
                )) &&
              (args.kind === undefined || item.kind === args.kind) &&
              (args.ownerId === undefined || item.ownerId === args.ownerId) &&
              (args.sensitivity === undefined || item.sensitivity === args.sensitivity),
          ),
      );
      const { items, ...pagination } = page(rows, args);
      // Reach is judged for the returned page only: its budget is never spent on rows the
      // caller does not see, and a filter or a later page costs no more than its own rows.
      const reach = ownerIndex ? null : boundedReach(work.remaining(), this.#maxBytes);
      const listed = ownerIndex
        ? items!
        : (items as JsonObject[]).map(item => {
            const origin = origins.get(item)!;
            return { ...item, outsideGuard: reach!(origin.projection, origin.node, scope).status };
          });
      data = {
        [ownerIndex ? 'owners' : 'resources']: listed,
        ...pagination,
        ...(!ownerIndex
          ? {
              resourceCoverage: 'host_bound_resources',
              limitations: [
                'Declared selectors without a host resource binding are not included; see agent permissions.',
                OUTSIDE_GUARD_LIMITATION,
              ],
            }
          : {}),
      };
    } else if (operation === 'get_agent_inventory') {
      const source = findSource(view, args.sourceId as string),
        agent = findAgent(source.current, args.agentId as string);
      const selected = { ...source.current, ...focus(source.current, agent, work) };
      const groups = inventorySections(source, selected, agent, work),
        section = (args.section ?? 'overview') as (typeof sections)[number];
      const policy = selectedPolicy(source.current, work, { nodes: selected.nodes });
      groups.policies = policy as unknown as JsonObject[];
      data = {
        agent: agentSummary(source, selected, agent, work),
        section,
        ...page(groups[section], args),
        counts: Object.fromEntries(
          Object.entries(groups)
            .filter(([key]) => key !== 'overview')
            .map(([key, value]) => [key, value.length]),
        ),
        policyEvidence: section === 'policies' ? page(groups.policies, args).items! : [],
        policyCoverage: policyCoverage(policy),
        receipt: receipt(source),
        assessment: 'unknown',
        graphStatus: 'not_requested',
        collection,
        limitations: ['Read-only host observations and declared grants; current execution still requires admission.'],
      };
    } else if (operation === 'get_resource_access') {
      const source = findSource(view, args.sourceId as string),
        projection = source.current;
      const resource = projection.nodes.find(
        node => node.label === 'GuardResourceBinding' && matching(node, args.resourceId as string, 'binding_id'),
      );
      if (!resource) fail('MAP_NOT_FOUND');
      const agents = ordered(
        projection.nodes
          .filter(node => node.label === 'GuardAgent')
          .filter(agent => {
            work.step();
            return focus(projection, agent, work).nodes.some(node => node.id === resource.id);
          })
          .map(agent => agentSummary(source, projection, agent, work)),
      );
      const { items, ...pagination } = page(agents, args);
      const reach = boundedReach(work.remaining(), this.#maxBytes)(projection, resource, scope, true);
      data = {
        resource: resourceSummary(source, projection, resource, work),
        agents: items!,
        ...pagination,
        outsideGuard: {
          status: reach.status,
          directAccess: reach.directAccess,
          directAccessTruncated: reach.directAccessTruncated,
          identities: reach.identities,
          identitiesTruncated: reach.identitiesTruncated,
          unknownReasons: reach.unknownReasons,
          evidenceKind: 'declared',
        },
        receipt: receipt(source),
        assessment: 'unknown',
        collection,
        limitations: [
          'Agents have a declared selector mapped to this resource; this is not proof of current effective access.',
          OUTSIDE_GUARD_LIMITATION,
        ],
      };
    } else if (operation === 'get_agent_access') {
      const source = findSource(view, args.sourceId as string),
        projection = source.current;
      const agent = findAgent(projection, args.agentId as string);
      graph = focus(projection, agent, work);
      // The response graph carries node properties too: withhold out-of-scope targets there.
      const visibleTarget = targetVisibility(projection, scope, work);
      graph = {
        ...graph,
        nodes: graph.nodes.map(node => {
          const target = node.label === 'GuardDirectAccess' ? string(node, 'target_ref') : null;
          if (target === null || visibleTarget(target)) return node;
          const { target_ref: _withheld, ...properties } = node.properties;
          return { ...node, properties };
        }),
      };
      const policy = selectedPolicy(projection, work, { nodes: graph.nodes });
      data = {
        agent: agentSummary(source, projection, agent, work),
        deployments: graph.nodes
          .filter(node => node.label === 'GuardDeployment')
          .map(node => ({
            id: node.entityId,
            deploymentId: string(node, 'deployment_id'),
            environment: string(node, 'environment'),
          })),
        tasks: graph.nodes.filter(node => node.label === 'GuardTask').map(taskSummary),
        grants: graph.nodes.filter(node => node.label === 'GuardGrant').map(grantSummary),
        connections: graph.nodes
          .filter(node => node.label === 'GuardMcpConnection')
          .map(node => ({ id: node.entityId, ...node.properties })),
        bindings: graph.nodes
          .filter(node => ['GuardExecutionBinding', 'GuardResourceBinding'].includes(node.label))
          .map(node => ({ id: node.entityId, kind: node.label, ...node.properties })),
        policyEvidence: policy as unknown as readonly JsonObject[],
        policyCoverage: policyCoverage(policy),
        outsideGuard: {
          directAccess: directAccess(projection, graph, scope, work),
          identityScope: identityScope(projection, graph),
        },
        boundaryFlags: [detailFlags(projection, agent, scope, work.remaining(), this.#maxBytes)],
        receipt: receipt(source),
        assessment: 'unknown',
        limitations: [
          'Declared and observed evidence only; current executor admission is required.',
          'External object and prefix bindings retain their original scope.',
          'Only S3 identity policies and host declarations are checked. Bucket policies, SCPs and permission boundaries are not, so identity-scope buckets are candidates and a deny elsewhere can remove the access. none_declared is the host claim, not a check, and no status means safe.',
        ],
      };
    } else if (operation === 'explain_access') {
      const source = findSource(view, args.sourceId as string);
      const task = source.current.nodes.find(
        node => node.label === 'GuardTask' && matching(node, args.taskId as string, 'task_id'),
      );
      if (!task) fail('MAP_NOT_FOUND');
      data = {
        ...explain(source.current, scope, task, args.tool as string, args.resourceId as string, now, work),
        receipt: receipt(source),
      };
    } else if (operation === 'find_agents_with_access') {
      const candidates: JsonObject[] = [];
      const limit = (args.limit as number | undefined) ?? 50;
      let truncated = false;
      candidateSearch: for (const source of view.sources) {
        // A binding enters an agent's focus only via deployment -> agent <- task -> grant -> resource
        // <- binding. Walking that chain backwards from the matching bindings yields exactly the
        // agents that can have evidence; the full per-agent check below still runs unchanged.
        const projection = source.current;
        const matches = projection.nodes.filter(node => {
          work.step();
          return (
            node.label === 'GuardResourceBinding' &&
            strings(node, 'actions').includes(args.action as string) &&
            (string(node, 'resource_ref') === args.resourceRef ||
              connected(projection, new Set([node.id]), 'G_MAPS_TO', work).some(
                external => string(external, 'arn') === args.resourceRef,
              ))
          );
        });
        if (!matches.length) continue;
        const resources = nodeIds(connected(projection, nodeIds(matches), 'G_BINDS_SELECTOR', work));
        const grants = nodeIds(connected(projection, resources, 'G_TARGETS', work, true));
        const tasks = nodeIds(connected(projection, grants, 'G_HAS_GRANT', work, true));
        const deploymentIds = nodeIds(
          connected(projection, tasks, 'G_ASSIGNED_TO', work).filter(node => node.label === 'GuardDeployment'),
        );
        const reachable = nodeIds(connected(projection, deploymentIds, 'G_INSTANCE_OF', work));
        for (const agent of projection.nodes.filter(node => node.label === 'GuardAgent' && reachable.has(node.id))) {
          work.step();
          const selected = focus(source.current, agent, work),
            selectedProjection = { ...source.current, ...selected };
          const bindings = selected.nodes.filter(
            node => node.label === 'GuardResourceBinding' && strings(node, 'actions').includes(args.action as string),
          );
          const evidence: JsonObject[] = [];
          for (const binding of bindings) {
            work.step();
            const external = connected(selectedProjection, new Set([binding.id]), 'G_MAPS_TO', work)[0];
            if (
              string(binding, 'resource_ref') !== args.resourceRef &&
              (!external || string(external, 'arn') !== args.resourceRef)
            )
              continue;
            const toolName = string(binding, 'tool'),
              resource = string(binding, 'resource_ref');
            if (!toolName || !resource) continue;
            for (const task of selected.nodes.filter(node => node.label === 'GuardTask')) {
              work.step();
              if (
                !connected(selectedProjection, new Set([task.id]), 'G_HAS_GRANT', work).some(
                  grant =>
                    string(grant, 'tool') === toolName &&
                    strings(grant, 'resources').some(item => item === '*' || item === resource),
                )
              )
                continue;
              if (candidates.length >= limit) {
                truncated = true;
                break candidateSearch;
              }
              const deployment = connected(selectedProjection, new Set([task.id]), 'G_ASSIGNED_TO', work);
              const executions = connected(
                selectedProjection,
                nodeIds(deployment),
                'G_EXECUTES_FOR',
                work,
                true,
              ).filter(node => string(node, 'tool') === toolName);
              const policy = selectedPolicy(source.current, work, {
                task,
                executions,
                resources: [binding],
                action: args.action as string,
              });
              evidence.push(
                work.evidence({
                  taskId: string(task, 'task_id'),
                  tool: toolName,
                  resourceRef: resource,
                  action: args.action!,
                  scope: string(binding, 'scope'),
                  externalResource: external ? { ...external.properties } : null,
                  executionBindings: executions.map(node => ({
                    id: node.entityId,
                    ...node.properties,
                    identities: connected(selectedProjection, new Set([node.id]), 'G_USES_IDENTITY', work).map(
                      identity => ({ ...identity.properties }),
                    ),
                  })),
                  policyEvidence: policy as unknown as readonly JsonObject[],
                  policyCoverage: policyCoverage(policy),
                  explanation: explain(source.current, scope, task, toolName, resource, now, work, {
                    action: args.action as string,
                    resourceBindingId: binding.entityId,
                  }),
                }),
              );
            }
          }
          if (evidence.length)
            candidates.push({
              agent: agentSummary(source, source.current, agent, work),
              evidence,
              assessment: 'unknown',
              limitations: [
                'Potential access candidates; no effective permission decision.',
                'Cloud containment is not exact object authorization.',
              ],
            });
        }
      }
      data = { candidates, truncated };
    } else if (operation === 'get_changes') {
      data = retainedChanges(findSource(view, args.sourceId as string), args, scope, work);
    } else {
      // Activity nobody declared, per source: a second, optional read. If it fails, is too
      // large or runs out of time, health still answers and the count reads unknown.
      const activity = new Map<string, MapSource>();
      let activityUnknown = 'not_reported';
      if (scope.allTeams && view.sources.length) {
        const budget = work.remaining() - 50;
        try {
          if (budget <= 0) fail('MAP_TIMEOUT');
          const found = await read(
            { ...(args.sourceId ? { sourceId: args.sourceId as string } : {}), undeclared: true },
            budget,
          );
          for (const source of found.sources) activity.set(source.id, source);
        } catch (error) {
          const code = error instanceof MapQueryError ? error.code : 'MAP_UNAVAILABLE';
          activityUnknown =
            code === 'MAP_TIMEOUT'
              ? 'read_timeout'
              : code === 'MAP_LIMIT_EXCEEDED'
                ? 'limit_exceeded'
                : 'read_unavailable';
        }
      }
      const undeclaredActivity = (source: MapSource): JsonObject => {
        if (!scope.allTeams) return { status: 'not_visible', reason: 'all_teams_required' };
        const counted = activity.get(source.id);
        if (!counted?.current.undeclared) return { status: 'unknown', reason: activityUnknown };
        // Counted against a newer publication than the one this response describes.
        if (counted.current.id !== source.current.id) return { status: 'unknown', reason: 'publication_changed' };
        return undeclaredCounts(source, counted.current.undeclared);
      };
      data = {
        sources: view.sources.map(source => {
          work.step();
          return {
            id: source.id,
            sourceId: source.sourceId,
            tenantId: source.tenantId,
            profile: source.profile,
            generatedAt: source.current.generatedAt,
            snapshotId: source.current.snapshotId,
            projectionId: source.current.id,
            ...freshness(source.current.generatedAt, now, this.#staleSeconds),
            coverage: {
              ...Object.fromEntries(
                Object.entries(source.current.coverage)
                  .filter(([component]) => component !== 'policy')
                  .map(([component, status]) => {
                    work.step();
                    return [component, { ...status, ...freshness(status.observedAt, now, this.#staleSeconds) }];
                  }),
              ),
              policy: policyCoverage(work.policy(source.current)),
            },
            undeclaredActivity: undeclaredActivity(source),
          };
        }),
        visibility: scope.allTeams ? 'enrolled_sources' : 'visible_agent_sources',
        limitations: [
          'Collection freshness is separate from current execution authority.',
          'undeclaredActivity counts tasks and caller principals that ran through this executor and belong to no declared agent. It is shown to all-teams readers only, and says nothing about agents that do not use the guard.',
        ],
      };
    }
    if (graph && (graph.nodes.length > this.#maxNodes || graph.edges.length > this.#maxEdges))
      fail('MAP_LIMIT_EXCEEDED');
    work.step();
    const observedAt = new Date(now).toISOString();
    const freeze = (payload: JsonObject): MapResponse | null => {
      try {
        const result = { operation, observedAt, data: payload, ...(graph ? { graph } : {}) };
        return immutableJson(result, 32, 100_000, this.#maxBytes) as unknown as MapResponse;
      } catch {
        return null;
      }
    };
    let copied = freeze(data);
    // The identity-scope bucket lists are optional detail. If the response does not fit with
    // them, shorten them (marked truncated) before giving up on the whole response.
    for (const keep of [25, 5, 0]) {
      if (copied) break;
      const shortened = shortenIdentityScope(data, keep);
      if (shortened) copied = freeze(shortened);
    }
    if (!copied) return fail('MAP_LIMIT_EXCEEDED');
    work.step();
    return copied;
  }
}
