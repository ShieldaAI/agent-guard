import { isIP } from 'node:net';
import neo4j, { type Driver, type Transaction, type Record as GraphRecord } from 'neo4j-driver';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import {
  MAP_LABELS,
  MAP_RELATIONSHIPS,
  MapQueryError,
  mapIdentifier,
  validateReadScope,
  type GuardLabel,
  type GuardRelation,
  type JsonObject,
  type MapCoverage,
  type MapEdge,
  type MapNode,
  type MapProjection,
  type MapReadRequest,
  type MapSource,
  type MapStore,
  type MapView,
  type ReadScope,
} from './types.js';
import {
  POLICY_COLUMNS,
  POLICY_QUERY,
  policyEvidence,
  policyParameters,
  policyPlan,
  safePolicyRow,
  type PolicyPlan,
} from './policy-reader.js';

import { MAP_PROPERTIES as FIELDS } from './projection-fields.js';

interface QueryAccess {
  readonly allTeams: boolean;
  readonly agentSelected: boolean;
}
const QUERY_ACCESS: readonly QueryAccess[] = Array.from({ length: 4 }, (_, mode) => ({
  allTeams: Boolean(mode & 2),
  agentSelected: Boolean(mode & 1),
}));
function agentPredicate(variable: string, access: QueryAccess): string {
  return (
    [
      !access.allTeams ? `${variable}.team_id IN $teamIds` : '',
      access.agentSelected ? `(${variable}.agent_id=$agentId OR ${variable}.entity_id=$agentId)` : '',
    ]
      .filter(Boolean)
      .join(' AND ') || 'true'
  );
}
// Only validated scope/selection flags choose these fixed templates. Avoid asking
// Neo4j to plan irrelevant administrative, selection and historical branches.
const SOURCES = QUERY_ACCESS.map(access =>
  [false, true].map(
    sourceSelected => `MATCH (s:GuardSource)
WHERE s.company_id=$companyId AND s.tenant_id IN $tenantIds ${sourceSelected ? 'AND s.id=$sourceId' : ''}
AND coalesce(s.lifecycle_status,'active')='active'
MATCH (p:GuardSnapshot {id:s.current_snapshot_id})
WHERE p.source_id=s.id AND p.status='published'
 ${
   access.allTeams && !access.agentSelected
     ? ''
     : `AND EXISTS {
   MATCH (a:GuardAgent)-[:G_IN_SNAPSHOT]->(p)
   WHERE a.source_id=s.id AND a.projection_id=p.id AND a.tenant_id=s.tenant_id
   AND ${agentPredicate('a', access)}
 }`
 }
RETURN s.id AS id,s.tenant_id AS tenantId,s.native_source_id AS nativeSourceId,s.profile AS profile,
 p.id AS currentId,p.snapshot_id AS currentSnapshotId,p.generated_at AS currentGeneratedAt,
 substring(p.coverage_json,0,4097) AS currentCoverage,
 s.previous_snapshot_id AS previousId,substring(p.cloud_coverage_json,0,16385) AS policyCoverage
ORDER BY s.id LIMIT $sourceLimit`,
  ),
);

const scoped = (variable: string): string =>
  `${variable}.source_id=$sourceId AND ${variable}.projection_id=$projectionId AND ${variable}.tenant_id=$tenantId`;
// Derive each next set only from previously authorized nodes, with bounds after every set.
const READ_ORDER: readonly GuardLabel[] = [
  'GuardAgent',
  'GuardDeployment',
  'GuardTask',
  'GuardPrincipal',
  'GuardGrant',
  'GuardExecutionBinding',
  'GuardTool',
  'GuardResource',
  'GuardResourceBinding',
  'GuardExternalResource',
  'GuardExternalIdentity',
  'GuardMcpConnection',
  'GuardMcpOperation',
  'GuardOwner',
  'GuardCredentialReference',
];
const historicalVisibility = (label: 'GuardAgent' | 'GuardTask', parameter: string): string =>
  `(n.entity_id IN $${parameter} OR NOT EXISTS {
    MATCH (current:${label})-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$currentId})
    WHERE current.entity_id=n.entity_id AND current.source_id=$sourceId
      AND current.projection_id=$currentId AND current.tenant_id=$tenantId
  })`;
function through(path: string, label: GuardLabel): string {
  return `EXISTS { MATCH ${path} WHERE ${scoped('visible')} AND visible.id IN $${label}Ids }`;
}
const predicates: Readonly<Record<Exclude<GuardLabel, 'GuardAgent'>, string>> = {
  GuardDeployment: through('(n)-[:G_INSTANCE_OF]->(visible:GuardAgent)', 'GuardAgent'),
  GuardTask: through('(n)-[:G_ASSIGNED_TO]->(visible:GuardDeployment)', 'GuardDeployment'),
  GuardPrincipal: through('(n)<-[:G_ACTS_AS]-(visible:GuardTask)', 'GuardTask'),
  GuardGrant: through('(n)<-[:G_HAS_GRANT]-(visible:GuardTask)', 'GuardTask'),
  GuardExecutionBinding: through('(n)-[:G_EXECUTES_FOR]->(visible:GuardDeployment)', 'GuardDeployment'),
  GuardTool: `(${through('(n)<-[:G_FOR_TOOL]-(visible:GuardGrant)', 'GuardGrant')} OR
    ${through('(n)<-[:G_EXECUTES_TOOL]-(visible:GuardExecutionBinding)', 'GuardExecutionBinding')})`,
  GuardResource: through('(n)<-[:G_TARGETS]-(visible:GuardGrant)', 'GuardGrant'),
  GuardResourceBinding: through('(n)-[:G_BINDS_SELECTOR]->(visible:GuardResource)', 'GuardResource'),
  GuardExternalResource: through('(n)<-[:G_MAPS_TO]-(visible:GuardResourceBinding)', 'GuardResourceBinding'),
  GuardExternalIdentity: through('(n)<-[:G_USES_IDENTITY]-(visible:GuardExecutionBinding)', 'GuardExecutionBinding'),
  GuardMcpConnection: through('(n)<-[:G_VIA_CONNECTION]-(visible:GuardExecutionBinding)', 'GuardExecutionBinding'),
  GuardOwner: `(${through('(n)<-[:G_OWNED_BY]-(visible:GuardAgent)', 'GuardAgent')} OR ${through('(n)<-[:G_RESOURCE_OWNED_BY]-(visible:GuardResourceBinding)', 'GuardResourceBinding')})`,
  GuardCredentialReference: through('(n)<-[:G_USES_CREDENTIAL]-(visible:GuardDeployment)', 'GuardDeployment'),
  GuardMcpOperation: `EXISTS {
    MATCH (n)<-[:G_EXPOSES_OPERATION]-(c:GuardMcpConnection)<-[:G_VIA_CONNECTION]-(b:GuardExecutionBinding)
    MATCH (b)-[:G_EXECUTES_TOOL]->(tool:GuardTool)<-[:G_OPERATION_TOOL]-(n)
    WHERE ${['c', 'b', 'tool'].map(scoped).join(' AND ')}
      AND c.id IN $GuardMcpConnectionIds AND b.id IN $GuardExecutionBindingIds AND tool.id IN $GuardToolIds
  }`,
};
function nodePredicate(label: GuardLabel, access: QueryAccess, historical: boolean): string {
  if (access.allTeams && !access.agentSelected) return 'true';
  const predicate = label === 'GuardAgent' ? agentPredicate('n', access) : predicates[label];
  // The historical fence remains mandatory for team-scoped previous projections.
  // A current projection (or an all-teams reader) bypassed it in the original query.
  if (historical && !access.allTeams && (label === 'GuardAgent' || label === 'GuardTask')) {
    return `(${predicate}) AND ${historicalVisibility(
      label,
      label === 'GuardAgent' ? 'currentAgentEntityIds' : 'currentTaskEntityIds',
    )}`;
  }
  return predicate;
}

// Labels/property names below are static source allowlists, never request-supplied strings.
// Separate bounded templates avoid the planner's combinatorial work for a large OR of paths.
const NODES = QUERY_ACCESS.map(access =>
  [false, true].map(
    historical =>
      Object.fromEntries(
        MAP_LABELS.map(label => [
          label,
          `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})
MATCH (n:${label})-[:G_IN_SNAPSHOT]->(p)
WHERE ${scoped('n')} AND size([label IN labels(n) WHERE label IN $labels])=1 AND
 (${nodePredicate(label, access, historical)})
RETURN '${label}' AS label,n { .id,.entity_id,.source_id,.projection_id,${FIELDS[label].map(field => `.${field}`).join(',')} } AS node
ORDER BY n.id LIMIT $nodeLimit`,
        ]),
      ) as Readonly<Record<GuardLabel, string>>,
  ),
);
const EDGES = `MATCH (n)-[r]->(m)
WHERE n.id IN $nodeIds AND m.id IN $nodeIds AND type(r) IN $relationships
 AND n.source_id=$sourceId AND m.source_id=$sourceId
 AND n.projection_id=$projectionId AND m.projection_id=$projectionId
 AND n.tenant_id=$tenantId AND m.tenant_id=$tenantId
RETURN n.id AS source,m.id AS target,type(r) AS kind ORDER BY source,target,kind LIMIT $edgeLimit`;
const PREVIOUS = `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})
RETURN p.id AS id,p.snapshot_id AS snapshotId,p.generated_at AS generatedAt,
 substring(p.coverage_json,0,4097) AS coverage LIMIT 1`;

export interface Neo4jMapStoreOptions {
  readonly database?: string;
  readonly timeoutMs?: number;
  readonly maxSources?: number;
  readonly maxNodes?: number;
  readonly maxEdges?: number;
  /** Host ceiling, also limited by the snapshot's enrolled cloud age limit. */
  readonly policyMaxAgeSeconds?: number;
  readonly clock?: () => number;
}
function bound(value: unknown, fallback: number, maximum: number): number {
  const number = value === undefined ? fallback : value;
  if (typeof number !== 'number' || !Number.isSafeInteger(number) || number < 1 || number > maximum)
    throw new MapQueryError('MAP_REQUEST_INVALID');
  return number;
}
function text(value: unknown): string {
  return mapIdentifier(value, 'MAP_UNAVAILABLE');
}
function converted(value: unknown): unknown {
  if (neo4j.isInt(value)) {
    if (!value.inSafeRange()) throw new MapQueryError('MAP_UNAVAILABLE');
    return value.toNumber();
  }
  if (Array.isArray(value)) return value.map(converted);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, converted(child)]));
  return value;
}
function safeNode(raw: unknown, label: unknown, sourceId: string, projectionId: string): MapNode {
  if (!MAP_LABELS.includes(label as GuardLabel) || !raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new MapQueryError('MAP_UNAVAILABLE');
  const data = raw as Record<string, unknown>;
  if (data.source_id !== sourceId || data.projection_id !== projectionId) throw new MapQueryError('MAP_UNAVAILABLE');
  const properties: Record<string, unknown> = {};
  for (const field of FIELDS[label as GuardLabel])
    if (Object.hasOwn(data, field)) properties[field] = converted(data[field]);
  const opaque = (value: unknown): boolean =>
    typeof value === 'string' && value.length === 71 && /^opaque:[a-f0-9]{64}$/.test(value);
  const optionalOpaque = (value: unknown): boolean => value == null || opaque(value);
  const opaqueArray = (value: unknown, maximum: number): boolean =>
    Array.isArray(value) && value.length <= maximum && new Set(value).size === value.length && value.every(opaque);
  if (
    label === 'GuardCredentialReference' &&
    (!opaque(properties.credential_id) ||
      !optionalOpaque(properties.issuer_ref) ||
      !opaqueArray(properties.audience_refs, 128) ||
      !opaqueArray(properties.recipient_refs, 128) ||
      !['active', 'rotating', 'revoked', 'expired', 'unknown'].includes(properties.lifecycle_state as string) ||
      !['current', 'due', 'overdue', 'unknown'].includes(properties.rotation_status as string))
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (label === 'GuardDeployment' && (!optionalOpaque(properties.runtime_ref) || !optionalOpaque(properties.build_ref)))
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (
    label === 'GuardResourceBinding' &&
    properties.approved_destinations != null &&
    !opaqueArray(properties.approved_destinations, 128)
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (label === 'GuardExternalResource' && properties.provider === 'host') {
    if (
      !opaque(properties.host_resource_id) ||
      !['service', 'repository', 'database', 'queue', 'storage', 'other'].includes(properties.kind as string)
    )
      throw new MapQueryError('MAP_UNAVAILABLE');
    // A host resource cannot acquire AWS identity through extra graph properties.
    for (const key of [
      'arn',
      'partition',
      'account_id',
      'region',
      'cloud_provider_label',
      'cloud_provider_id',
      'cloud_match_kind',
    ])
      delete properties[key];
  }
  return {
    id: text(data.id),
    entityId: text(data.entity_id),
    sourceId,
    projectionId,
    label: label as GuardLabel,
    properties: immutableJson(properties, 4, 50_000, 512 * 1024) as JsonObject,
  };
}
function observationTime(value: unknown): number | undefined {
  if (
    typeof value !== 'string' ||
    !/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/.test(value)
  )
    return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19) ? time : undefined;
}
function coreCaptureTimes(raw: unknown): Partial<Record<'tasks' | 'tools', string>> {
  // Older or incomplete graph metadata has unknown capture age. Recomposition
  // changes generated_at, so it is never a safe substitute for these timestamps.
  if (raw === null || raw === undefined) return {};
  try {
    if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 4096) throw new Error();
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    const result: Partial<Record<'tasks' | 'tools', string>> = {};
    for (const component of ['tasks', 'tools'] as const) {
      const item = (parsed as Record<string, unknown>)[component];
      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error();
      const record = item as Record<string, unknown>;
      if (
        Object.keys(record).sort().join(',') !== 'observedAt,status' ||
        record.status !== 'complete' ||
        observationTime(record.observedAt) === undefined
      )
        throw new Error();
      result[component] = record.observedAt as string;
    }
    return result;
  } catch {
    throw new MapQueryError('MAP_UNAVAILABLE');
  }
}
function coverage(
  nodes: readonly MapNode[],
  captures: Partial<Record<'tasks' | 'tools', string>>,
  profile: string,
  summary: boolean,
  now: number,
): MapCoverage {
  const connections = nodes.filter(node => node.label === 'GuardMcpConnection');
  const observed = connections.filter(node => node.properties.capture_status === 'observed').length;
  const references = nodes.filter(
    node =>
      (node.label === 'GuardExternalResource' || node.label === 'GuardExternalIdentity') &&
      node.properties.provider !== 'host',
  );
  const captured = references.filter(node => typeof node.properties.cloud_status === 'string');
  const resolved = captured.filter(node => node.properties.cloud_status === 'resolved').length;
  const at = (values: readonly unknown[]): { observedAt?: string } => {
    const times = values
      .map(value => (typeof value === 'number' ? value * 1000 : typeof value === 'string' ? Date.parse(value) : NaN))
      .filter(value => Number.isFinite(value) && value >= 0 && value <= 253_402_300_799_999);
    return times.length ? { observedAt: new Date(Math.min(...times)).toISOString() } : {};
  };
  // Aggregate only visible connections. A new composition cannot renew a cached
  // observation, and one missing/invalid/future timestamp must not disappear
  // behind another fresh connection. Unavailable records have only capture time.
  const mcpTimes = connections
    .flatMap(node =>
      node.properties.capture_status === 'observed'
        ? [node.properties.capture_observed_at, node.properties.observed_at]
        : [node.properties.capture_observed_at],
    )
    .map(observationTime);
  const mcpCapture =
    mcpTimes.length && mcpTimes.every(time => time !== undefined && time <= now + 60_000)
      ? { observedAt: new Date(Math.min(...(mcpTimes as number[]))).toISOString() }
      : {};
  return {
    tasks: summary
      ? { status: 'not_collected' }
      : { status: 'complete', ...(captures.tasks ? { observedAt: captures.tasks } : {}) },
    tools: summary
      ? { status: 'not_collected' }
      : { status: 'complete', ...(captures.tools ? { observedAt: captures.tools } : {}) },
    manifest:
      profile === 'core'
        ? { status: 'not_collected' }
        : { status: summary ? 'partial' : 'complete', ...at(nodes.map(node => node.properties.manifest_observed_at)) },
    mcp:
      summary || profile !== 'host-mcp'
        ? { status: 'not_collected' }
        : {
            status: observed === connections.length ? 'complete' : observed ? 'partial' : 'unavailable',
            ...mcpCapture,
          },
    cloud: !captured.length
      ? { status: 'not_collected' }
      : {
          status: resolved === references.length ? 'complete' : resolved ? 'partial' : 'unavailable',
          ...at(captured.map(node => node.properties.cloud_observed_at)),
        },
  };
}

export class Neo4jMapStore implements MapStore {
  readonly #driver: Driver;
  readonly #database: string;
  readonly #timeout: number;
  readonly #sources: number;
  readonly #nodes: number;
  readonly #edges: number;
  readonly #policyAge: number;
  readonly #clock: () => number;
  #active = 0;
  constructor(driver: Driver, options: Neo4jMapStoreOptions = {}) {
    this.#driver = driver;
    this.#database = mapIdentifier(options.database ?? 'neo4j');
    this.#timeout = bound(options.timeoutMs, 5000, 5000);
    this.#sources = bound(options.maxSources, 64, 64);
    this.#nodes = bound(options.maxNodes, 2000, 2000);
    this.#edges = bound(options.maxEdges, 5000, 5000);
    this.#policyAge = bound(options.policyMaxAgeSeconds, 7200, 86400);
    if (options.clock !== undefined && typeof options.clock !== 'function')
      throw new MapQueryError('MAP_REQUEST_INVALID');
    this.#clock = options.clock ?? Date.now;
  }
  async close(): Promise<void> {
    await this.#driver.close();
  }
  async read(input: ReadScope, request: MapReadRequest = {}): Promise<MapView> {
    const scope = validateReadScope(input);
    let selection: MapReadRequest;
    try {
      const copied = immutableJson(request, 2, 16, 32 * 1024) as unknown as Record<string, unknown>;
      if (
        !copied ||
        Array.isArray(copied) ||
        typeof copied !== 'object' ||
        Object.keys(copied).some(key => !['sourceId', 'agentId', 'history', 'summary'].includes(key))
      )
        throw new Error();
      if (copied.sourceId !== undefined) mapIdentifier(copied.sourceId);
      if (copied.agentId !== undefined) mapIdentifier(copied.agentId);
      if (copied.history !== undefined && typeof copied.history !== 'boolean') throw new Error();
      if (copied.summary !== undefined && typeof copied.summary !== 'boolean') throw new Error();
      selection = copied as MapReadRequest;
    } catch {
      throw new MapQueryError('MAP_REQUEST_INVALID');
    }
    const accessMode = (scope.allTeams ? 2 : 0) + (selection.agentId !== undefined ? 1 : 0);
    const sourceQuery = SOURCES[accessMode]![selection.sourceId !== undefined ? 1 : 0]!;
    if (this.#active >= 8) throw new MapQueryError('MAP_UNAVAILABLE');
    this.#active++;
    const deadline = Date.now() + this.#timeout;
    let cancel = (): void => {};
    const check = (): void => {
      if (Date.now() >= deadline) throw new MapQueryError('MAP_TIMEOUT');
    };
    const work = (async (): Promise<MapView> => {
      const session = this.#driver.session({
        database: this.#database,
        defaultAccessMode: neo4j.session.READ,
        fetchSize: 32,
      });
      let transaction: Transaction | undefined;
      try {
        transaction = session.beginTransaction({ timeout: this.#timeout });
        const tx = transaction;
        cancel = () => {
          void tx.rollback().catch(() => {});
        };
        const run = async (
          query: string,
          parameters: Record<string, unknown>,
          receive?: (record: GraphRecord) => void,
        ) => {
          check();
          const records: GraphRecord[] = [];
          for await (const record of tx.run(query, parameters)) {
            check();
            if (receive) receive(record);
            else records.push(record);
          }
          check();
          return records;
        };
        const common = {
          companyId: scope.companyId,
          tenantIds: [...scope.tenantIds],
          teamIds: [...scope.teamIds],
          allTeams: scope.allTeams,
          sourceId: selection.sourceId ?? null,
          agentId: selection.agentId ?? null,
          sourceLimit: neo4j.int(this.#sources + 1),
        };
        const selected = await run(sourceQuery, common);
        if (selected.length > this.#sources) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
        let nodeCount = 0;
        let edgeCount = 0;
        let materializedBytes = 0;
        const charge = (value: unknown): void => {
          materializedBytes += Buffer.byteLength(JSON.stringify(value), 'utf8');
          if (materializedBytes > 4 * 1024 * 1024) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
        };
        const now = (): number => {
          let stamp: number;
          try {
            stamp = this.#clock();
          } catch {
            throw new MapQueryError('MAP_UNAVAILABLE');
          }
          if (!Number.isSafeInteger(stamp) || stamp < 0 || stamp > 253_402_300_799_999)
            throw new MapQueryError('MAP_UNAVAILABLE');
          return Math.floor(stamp / 1000);
        };
        let policyPairCount = 0;
        const policyChecks: {
          plan: PolicyPlan;
          params: Record<string, unknown>;
          rows: JsonObject[];
          projection: MapProjection;
          maximumAge: number;
        }[] = [];
        const readPolicy = async (
          plan: PolicyPlan,
          params: Record<string, unknown>,
          chargeRows: boolean,
        ): Promise<JsonObject[]> => {
          if (!plan.probes.length) return [];
          const rows: JsonObject[] = [];
          let readBytes = 0;
          const pairs = policyParameters(plan);
          if (Buffer.byteLength(JSON.stringify(pairs), 'utf8') > 4 * 1024 * 1024)
            throw new MapQueryError('MAP_LIMIT_EXCEEDED');
          await run(
            POLICY_QUERY,
            { ...params, policyPairs: pairs, policyRowLimit: neo4j.int(plan.probes.length * 3 + 1) },
            item => {
              if (rows.length >= plan.probes.length * 3) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
              const raw = Object.fromEntries(POLICY_COLUMNS.map(column => [column, converted(item.get(column))]));
              const safe = safePolicyRow(raw);
              readBytes += Buffer.byteLength(JSON.stringify(safe), 'utf8');
              if (readBytes > 4 * 1024 * 1024) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
              if (chargeRows) charge(safe);
              rows.push(safe);
            },
          );
          // Sort only the bounded materialized rows. A server ORDER BY would
          // expand malformed relationship fan-out before applying its LIMIT.
          rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en-US'));
          return rows;
        };
        const sources: MapSource[] = [];
        for (const record of selected) {
          const sourceId = text(record.get('id'));
          const tenantId = text(record.get('tenantId'));
          const currentId = text(record.get('currentId'));
          const profile = record.get('profile');
          if (!scope.tenantIds.includes(tenantId) || !['core', 'host', 'host-mcp'].includes(profile))
            throw new MapQueryError('MAP_UNAVAILABLE');
          const readProjection = async (
            id: string,
            snapshotId: string,
            generatedAt: string,
            rawCoverage: unknown,
            currentNodes: readonly MapNode[] = [],
          ): Promise<MapProjection> => {
            const captures = coreCaptureTimes(rawCoverage);
            const params = {
              ...common,
              sourceId,
              tenantId,
              projectionId: id,
              currentId,
              labels: [...MAP_LABELS],
              currentAgentEntityIds: currentNodes
                .filter(node => node.label === 'GuardAgent')
                .map(node => node.entityId),
              currentTaskEntityIds: currentNodes.filter(node => node.label === 'GuardTask').map(node => node.entityId),
            };
            const nodes: MapNode[] = [];
            const nodeQueries = NODES[accessMode]![id === currentId ? 0 : 1]!;
            for (const label of selection.summary
              ? (['GuardAgent', 'GuardDeployment', 'GuardOwner'] as const)
              : READ_ORDER) {
              const authorized = Object.fromEntries(
                MAP_LABELS.map(kind => [`${kind}Ids`, nodes.filter(node => node.label === kind).map(node => node.id)]),
              );
              await run(
                nodeQueries[label],
                { ...params, ...authorized, nodeLimit: neo4j.int(this.#nodes - nodeCount + 1) },
                item => {
                  if (++nodeCount > this.#nodes) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
                  if (item.get('label') !== label) throw new MapQueryError('MAP_UNAVAILABLE');
                  const node = safeNode(item.get('node'), label, sourceId, id);
                  charge(node);
                  nodes.push(node);
                },
              );
            }
            const nodeIds = nodes.map(node => node.id);
            if (
              new Set(nodeIds).size !== nodes.length ||
              new Set(nodes.map(node => node.entityId)).size !== nodes.length
            )
              throw new MapQueryError('MAP_UNAVAILABLE');
            const ids = new Set(nodeIds);
            const edges: MapEdge[] = [];
            await run(
              EDGES,
              {
                ...params,
                nodeIds,
                relationships: [...MAP_RELATIONSHIPS],
                edgeLimit: neo4j.int(this.#edges - edgeCount + 1),
              },
              item => {
                if (++edgeCount > this.#edges) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
                const source = text(item.get('source')),
                  target = text(item.get('target')),
                  kind = item.get('kind');
                if (!ids.has(source) || !ids.has(target) || !MAP_RELATIONSHIPS.includes(kind))
                  throw new MapQueryError('MAP_UNAVAILABLE');
                const edge = { source, target, kind: kind as GuardRelation };
                charge(edge);
                edges.push(edge);
              },
            );
            const projection: MapProjection = {
              id,
              snapshotId,
              generatedAt,
              status: 'published',
              nodes,
              edges,
              coverage: coverage(nodes, captures, profile, selection.summary ?? false, now() * 1000),
            };
            if (!selection.summary && !selection.history && id === currentId) {
              const plan = policyPlan(scope.companyId, tenantId, nodes, edges, 512 - policyPairCount);
              policyPairCount += plan.records.length;
              let maximumAge = this.#policyAge;
              const enrolled = record.get('policyCoverage');
              if (enrolled !== null && enrolled !== undefined && plan.probes.length) {
                try {
                  if (typeof enrolled !== 'string' || enrolled.length > 16_384) throw new Error();
                  const parsed = JSON.parse(enrolled) as { maxAgeSeconds?: unknown };
                  if (
                    !parsed ||
                    typeof parsed !== 'object' ||
                    !Number.isSafeInteger(parsed.maxAgeSeconds) ||
                    (parsed.maxAgeSeconds as number) < 1 ||
                    (parsed.maxAgeSeconds as number) > 604800
                  )
                    throw new Error();
                  maximumAge = Math.min(maximumAge, parsed.maxAgeSeconds as number);
                } catch {
                  throw new MapQueryError('MAP_UNAVAILABLE');
                }
              }
              const rows = await readPolicy(plan, params, true);
              const evidence = policyEvidence(plan, rows, now(), maximumAge);
              for (const item of evidence) charge(item);
              const enriched = { ...projection, policyEvidence: evidence };
              policyChecks.push({ plan, params, rows, projection: enriched, maximumAge });
              return enriched;
            }
            return projection;
          };
          const current = await readProjection(
            currentId,
            text(record.get('currentSnapshotId')),
            text(record.get('currentGeneratedAt')),
            record.get('currentCoverage'),
          );
          let previous: MapProjection | null = null;
          if (selection.history && record.get('previousId')) {
            const previousId = text(record.get('previousId'));
            const previousRecords = await run(PREVIOUS, { sourceId, projectionId: previousId });
            if (previousRecords.length === 1) {
              const item = previousRecords[0]!;
              previous = await readProjection(
                previousId,
                text(item.get('snapshotId')),
                text(item.get('generatedAt')),
                item.get('coverage'),
                current.nodes,
              );
            }
          }
          sources.push({
            id: sourceId,
            tenantId,
            sourceId: text(record.get('nativeSourceId')),
            profile,
            current,
            previous,
          });
        }
        // Publication may advance while the read transaction is open. Never return mixed generations.
        const after = await run(sourceQuery, common);
        const pointers = (items: typeof selected): string =>
          JSON.stringify(
            items.map(record => [
              record.get('id'),
              record.get('currentId'),
              record.get('previousId'),
              record.get('currentCoverage'),
              record.get('policyCoverage'),
            ]),
          );
        if (pointers(selected) !== pointers(after)) throw new MapQueryError('MAP_UNAVAILABLE');
        for (const checked of policyChecks) {
          const rows = await readPolicy(checked.plan, checked.params, false);
          if (JSON.stringify(rows) !== JSON.stringify(checked.rows)) throw new MapQueryError('MAP_UNAVAILABLE');
          const refreshed = policyEvidence(checked.plan, rows, now(), checked.maximumAge);
          if (JSON.stringify(refreshed) !== JSON.stringify(checked.projection.policyEvidence))
            throw new MapQueryError('MAP_UNAVAILABLE');
        }
        try {
          return immutableJson({ sources }, 16, 200_000, 4 * 1024 * 1024) as unknown as MapView;
        } catch {
          throw new MapQueryError('MAP_LIMIT_EXCEEDED');
        }
      } catch (error) {
        if (error instanceof MapQueryError) throw error;
        const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
        throw new MapQueryError(/TimedOut|Timeout/.test(code) ? 'MAP_TIMEOUT' : 'MAP_UNAVAILABLE');
      } finally {
        if (transaction?.isOpen()) await transaction.rollback().catch(() => {});
        await session.close().catch(() => {});
      }
    })();
    void work
      .finally(() => {
        this.#active--;
      })
      .catch(() => {});
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        cancel();
        reject(new MapQueryError('MAP_TIMEOUT'));
      }, this.#timeout);
    });
    try {
      return await Promise.race([work, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

export interface Neo4jMapConnectionOptions extends Neo4jMapStoreOptions {
  readonly uri: string;
  readonly username: string;
  readonly password: string;
}
export function createNeo4jMapStore(options: Neo4jMapConnectionOptions): Neo4jMapStore {
  try {
    const uri = new URL(options.uri);
    const host = uri.hostname.replace(/^\[|\]$/g, '');
    const local = isIP(host) === 4 ? host.startsWith('127.') : host === '::1';
    if (
      !['bolt:', 'bolt+s:', 'neo4j+s:'].includes(uri.protocol) ||
      !host ||
      uri.username ||
      uri.password ||
      uri.pathname ||
      uri.search ||
      uri.hash ||
      (uri.port && (+uri.port < 1 || +uri.port > 65535)) ||
      (uri.protocol === 'bolt:' && !local)
    )
      throw new Error();
    mapIdentifier(options.username);
    if (typeof options.password !== 'string' || !options.password || options.password.length > 8192) throw new Error();
    const driver = neo4j.driver(options.uri, neo4j.auth.basic(options.username, options.password), {
      connectionTimeout: 5000,
      connectionAcquisitionTimeout: 5000,
      maxTransactionRetryTime: 0,
      maxConnectionPoolSize: 8,
    });
    return new Neo4jMapStore(driver, options);
  } catch {
    throw new MapQueryError('MAP_REQUEST_INVALID');
  }
}
