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
  type MapIdentityScope,
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
  IDENTITY_SCOPE_COLUMNS,
  IDENTITY_SCOPE_QUERY,
  identityScopeEvidence,
  identityScopeParameters,
  identityScopePlan,
  safeIdentityScopeRow,
  shortenScopeList,
  type IdentityScopePlan,
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
      access.agentSelected ? `(${variable}.agent_id IN $agentIds OR ${variable}.entity_id IN $agentIds)` : '',
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
  'GuardDirectAccess',
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
  GuardDirectAccess: through('(n)-[:G_DIRECT_ACCESS_FOR]->(visible:GuardDeployment)', 'GuardDeployment'),
  GuardMcpOperation: `EXISTS {
    MATCH (n)<-[:G_EXPOSES_OPERATION]-(c:GuardMcpConnection)<-[:G_VIA_CONNECTION]-(b:GuardExecutionBinding)
    MATCH (b)-[:G_EXECUTES_TOOL]->(tool:GuardTool)<-[:G_OPERATION_TOOL]-(n)
    WHERE ${['c', 'b', 'tool'].map(scoped).join(' AND ')}
      AND c.id IN $GuardMcpConnectionIds AND b.id IN $GuardExecutionBindingIds AND tool.id IN $GuardToolIds
  }`,
};
// A boundary read (get_agent_access, page flags) also needs what the team-wide read would
// show the flags: the in-scope delegation ancestors of the agent's tasks (recipients are
// checked against every ancestor; read after the agent's own nodes, within what is left of
// the budget) and, for `*` grants, whether an in-scope binding of the tool is sensitive.
// Both follow the team-wide visibility rules, so a flag is the same in either read.
// Templates stay specialized per scope mode: an all-teams reader needs no team check.
const SCOPE_RECORD_BYTES = 1024 * 1024;
const SCOPE_HEADROOM_BYTES = 64 * 1024;
/**
 * Tools sharing a role each list their own extras. Past the budget (1 MiB, or what is left of
 * the read's byte budget if that is less), keep every record but drop the lists and report
 * them truncated, rather than fail the read.
 */
/**
 * A stable order for bounded, already materialized rows. Each row is serialized once: the
 * comparator would otherwise re-serialize rows of up to 1 MiB on every comparison.
 */
function sortedBySerialization(rows: JsonObject[]): JsonObject[] {
  return rows
    .map(row => [JSON.stringify(row), row] as const)
    .sort((a, b) => a[0].localeCompare(b[0], 'en-US'))
    .map(entry => entry[1]);
}
function boundedRecords(
  records: readonly MapIdentityScope[],
  budget = SCOPE_RECORD_BYTES,
): readonly MapIdentityScope[] {
  if (Buffer.byteLength(JSON.stringify(records), 'utf8') <= budget) return records;
  return records.map(item => shortenScopeList(item, 0));
}
/** Stands in for a scope row that could not be kept; the classifier reads it as truncated. */
const oversized = (key: unknown): JsonObject =>
  immutableJson({ key: typeof key === 'number' ? key : -1, oversized: true }) as JsonObject;
const bucketName = (arn: unknown): string | null =>
  /^arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:\/.*)?$/.exec(typeof arn === 'string' ? arn : '')?.[1] ?? null;
/** S3 bucket names that visible host bindings map to; the outside-guard reach asks only about these. */
function boundBuckets(nodes: readonly MapNode[]): string[] {
  const names = new Set<string>();
  for (const node of nodes) {
    if (node.label !== 'GuardExternalResource' || node.properties.provider !== 'aws') continue;
    const name = bucketName(node.properties.arn);
    if (name !== null) names.add(name);
  }
  return [...names].sort();
}
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
// Delegation ancestors (at most 16 levels) of the selected agent's tasks. Anchored at the
// agent's deployments, so the work follows its own task chains, not every task in the graph.
// For a team reader every ancestor on the path must be in scope, so the walk stops at the
// first hidden one (where the flags stop too) and never counts tasks the reader can't see.
// Every node a boundary path passes through gets the same checks as the team-wide read:
// scoped to this source, projection and tenant, and carrying exactly one Map label.
const checked = (variable: string): string =>
  `${scoped(variable)} AND size([label IN labels(${variable}) WHERE label IN $labels])=1`;
// A binding reachable from an agent in the reader's teams, every hop checked.
const inScopeBinding = (binding: string): string => `EXISTS {
    MATCH (${binding})-[:G_BINDS_SELECTOR]->(r:GuardResource)<-[:G_TARGETS]-(g:GuardGrant)<-[:G_HAS_GRANT]-(t:GuardTask)
      -[:G_ASSIGNED_TO]->(d:GuardDeployment)-[:G_INSTANCE_OF]->(a:GuardAgent)
    WHERE ${['r', 'g', 't', 'd', 'a'].map(checked).join(' AND ')} AND a.team_id IN $teamIds
  }`;
const ancestorsQuery = (
  access: QueryAccess,
): string => `MATCH path=(visible:GuardDeployment)<-[:G_ASSIGNED_TO]-(child:GuardTask)-[:G_DELEGATED_FROM|G_DERIVED_FROM*1..16]->(a:GuardTask)
WHERE visible.id IN $GuardDeploymentIds AND ${checked('visible')} AND ${checked('child')}
 AND ALL(t IN nodes(path)[2..] WHERE ${checked('t')}${
   access.allTeams
     ? ''
     : ` AND EXISTS {
   MATCH (t)-[:G_ASSIGNED_TO]->(d:GuardDeployment)-[:G_INSTANCE_OF]->(ag:GuardAgent)
   WHERE ${checked('d')} AND ${checked('ag')} AND ag.team_id IN $teamIds
 }`
 })
RETURN DISTINCT a.id AS id LIMIT $nodeLimit`;
const ANCESTORS = QUERY_ACCESS.map(ancestorsQuery);
// The ancestor task records themselves, once their ids are known and fit the budget.
const ANCESTOR_TASKS = `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})
MATCH (n:GuardTask)-[:G_IN_SNAPSHOT]->(p)
WHERE ${scoped('n')} AND n.id IN $ancestorTaskIds AND size([label IN labels(n) WHERE label IN $labels])=1
RETURN 'GuardTask' AS label,n { .id,.entity_id,.source_id,.projection_id,${FIELDS.GuardTask.map(field => `.${field}`).join(',')} } AS node
ORDER BY n.id LIMIT $nodeLimit`;
// For each tool the agent holds a `*` grant on: up to five in-scope bindings of that tool
// marked confidential or restricted. Asked instead of loading every binding of the tool.
const wildcardQuery = (access: QueryAccess): string => `UNWIND $wildcardTools AS tool
CALL (tool) {
  MATCH (rb:GuardResourceBinding)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
  WHERE ${checked('rb')}
    AND rb.tool=tool AND rb.sensitivity IN ['confidential','restricted'] AND ${
      access.allTeams ? 'true' : inScopeBinding('rb')
    }
  WITH rb ORDER BY rb.entity_id LIMIT 5
  RETURN collect({id:substring(rb.entity_id,0,4097),sensitivity:rb.sensitivity}) AS bindings
}
RETURN tool, bindings ORDER BY tool`;
const WILDCARD = QUERY_ACCESS.map(wildcardQuery);
// For a team-scoped reader: the S3 buckets that bindings reachable from an in-scope agent
// map to. Identity scope names only these; any other bucket (another team's, or one no
// binding maps) becomes a note without a name or a count.
const IN_SCOPE_TARGETS = `MATCH (rb:GuardResourceBinding)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
WHERE ${checked('rb')} AND ${inScopeBinding('rb')}
MATCH (rb)-[:G_MAPS_TO]->(x:GuardExternalResource)
WHERE ${checked('x')}
  AND ((x.provider='host' AND x.host_resource_id IN $targetRefs) OR (x.provider='aws' AND x.arn STARTS WITH 'arn:aws:s3:::'))
RETURN DISTINCT substring(x.arn,0,2049) AS arn,substring(x.host_resource_id,0,72) AS host LIMIT 20001`;
// Whether any deployment or task lies outside the reader's read: a boolean, never a count.
const HIDDEN_SCOPE = `RETURN EXISTS {
  MATCH (n)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
  WHERE (n:GuardDeployment OR n:GuardTask) AND ${scoped('n')} AND NOT n.id IN $visibleIds
} AS hidden`;
// Start from the snapshot's unique id: an unlabelled `n.id IN $nodeIds` scans every node
// in the database, while snapshot membership bounds the work to this projection.
const EDGES = `MATCH (n)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
MATCH (n)-[r]->(m)
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
  if (
    label === 'GuardDeployment' &&
    (!optionalOpaque(properties.runtime_ref) ||
      !optionalOpaque(properties.build_ref) ||
      ![undefined, null, 'found', 'none_declared'].includes(properties.direct_access_status as string))
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  // Outside-content labels feed the boundary flags; a malformed value must not read as declared.
  const optionalFlag = (value: unknown): boolean => value === undefined || value === null || typeof value === 'boolean';
  const optionalMode = (value: unknown): boolean =>
    value === undefined || value === null || ['allow', 'require_approval', 'deny'].includes(value as string);
  if (
    label === 'GuardTool' &&
    (!optionalFlag(properties.reads_untrusted) ||
      !optionalFlag(properties.sends_external) ||
      !optionalMode(properties.untrusted_context) ||
      !optionalMode(properties.untrusted_context_default))
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (
    label === 'GuardTask' &&
    (!optionalFlag(properties.untrusted) || !optionalFlag(properties.delegated) || !optionalFlag(properties.derived))
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (
    label === 'GuardDirectAccess' &&
    (!opaque(properties.access_id) ||
      !optionalOpaque(properties.target_ref) ||
      !['shell', 'database', 'network', 'sdk', 'mcp', 'other'].includes(properties.kind as string) ||
      typeof properties.description !== 'string' ||
      // The same display rule as the manifest: not blank (including separators) and no NUL.
      /^[\s\u001c-\u001f\u0085\uFEFF]*$/.test(properties.description) ||
      properties.description.includes('\0') ||
      [...properties.description].length > 1024 ||
      typeof properties.deployment_id !== 'string' ||
      !properties.deployment_id ||
      [...properties.deployment_id].length > 4096)
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  // Fields the boundary flags read: a malformed value must not read as a known fact.
  if (
    label === 'GuardGrant' &&
    (typeof properties.tool !== 'string' ||
      !Array.isArray(properties.resources) ||
      properties.resources.some(item => typeof item !== 'string'))
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (
    label === 'GuardTask' &&
    (!optionalFlag(properties.revoked) ||
      !(properties.deadline == null || typeof properties.deadline === 'number') ||
      !(
        properties.allowed_recipients == null ||
        (Array.isArray(properties.allowed_recipients) &&
          properties.allowed_recipients.every(item => typeof item === 'string'))
      ))
  )
    throw new MapQueryError('MAP_UNAVAILABLE');
  if (
    label === 'GuardResourceBinding' &&
    properties.sensitivity != null &&
    !['public', 'internal', 'confidential', 'restricted', 'unknown'].includes(properties.sensitivity as string)
  )
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
      const copied = immutableJson(request, 3, 128, 64 * 1024) as unknown as Record<string, unknown>;
      if (
        !copied ||
        Array.isArray(copied) ||
        typeof copied !== 'object' ||
        Object.keys(copied).some(
          key =>
            !['sourceId', 'agentId', 'agentIds', 'boundary', 'history', 'summary', 'flags', 'outsideGuard'].includes(
              key,
            ),
        )
      )
        throw new Error();
      for (const key of ['flags', 'outsideGuard', 'boundary'])
        if (copied[key] !== undefined && typeof copied[key] !== 'boolean') throw new Error();
      // One read mode at a time: summary, history, flags and outside-guard reads differ in
      // what they load, and no caller needs two.
      if (['summary', 'history', 'flags', 'outsideGuard', 'boundary'].filter(key => copied[key] === true).length > 1)
        throw new Error();
      if (copied.outsideGuard === true && copied.agentId !== undefined) throw new Error();
      // A one-agent flags read must carry boundary evidence; the page read uses agentIds.
      if (copied.flags === true && copied.agentId !== undefined) throw new Error();
      if (copied.boundary === true && copied.agentId === undefined) throw new Error();
      if (copied.sourceId !== undefined) mapIdentifier(copied.sourceId);
      if (copied.agentId !== undefined) mapIdentifier(copied.agentId);
      // A page of agents for a flags read: one to 100 ids, never together with agentId.
      if (copied.agentIds !== undefined) {
        if (
          !Array.isArray(copied.agentIds) ||
          !copied.agentIds.length ||
          copied.agentIds.length > 100 ||
          copied.agentId !== undefined ||
          copied.flags !== true
        )
          throw new Error();
        for (const id of copied.agentIds) mapIdentifier(id);
      }
      if (copied.history !== undefined && typeof copied.history !== 'boolean') throw new Error();
      if (copied.summary !== undefined && typeof copied.summary !== 'boolean') throw new Error();
      selection = copied as MapReadRequest;
    } catch {
      throw new MapQueryError('MAP_REQUEST_INVALID');
    }
    const agentSelected = selection.agentId !== undefined || selection.agentIds !== undefined;
    // Boundary evidence (ancestors, `*` bindings, identity scope) for get_agent_access and the
    // page-of-agents flags read; get_agent_inventory keeps its earlier, cheaper read.
    const boundary = selection.agentIds !== undefined || selection.boundary === true;
    const accessMode = (scope.allTeams ? 2 : 0) + (agentSelected ? 1 : 0);
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
          agentIds: selection.agentIds ?? (selection.agentId !== undefined ? [selection.agentId] : null),
          boundary,
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
        let scopePairCount = 0;
        const ancestorJobs: { sourceId: string; params: Record<string, unknown> }[] = [];
        const policyChecks: {
          plan: PolicyPlan;
          scopePlan: IdentityScopePlan;
          params: Record<string, unknown>;
          rows: JsonObject[];
          scopeRows: JsonObject[];
          readable: ReadonlySet<string> | null;
          projection: MapProjection;
          maximumAge: number;
          scopeBudget: number;
        }[] = [];
        // Identity scope runs after the ancestor phase, so task liveness sees the ancestors.
        const scopeJobs: {
          sourceId: string;
          check: (typeof policyChecks)[number];
          reach: boolean;
          enrolled: unknown;
        }[] = [];
        /** The enrolled policy age bound, when a read has evidence to judge. */
        const maximumAgeFor = (enrolled: unknown): number => {
          if (enrolled === null || enrolled === undefined) return this.#policyAge;
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
            return Math.min(this.#policyAge, parsed.maxAgeSeconds as number);
          } catch {
            throw new MapQueryError('MAP_UNAVAILABLE');
          }
        };
        const readScope = async (
          plan: IdentityScopePlan,
          params: Record<string, unknown>,
          chargeRows: boolean,
        ): Promise<JsonObject[]> => {
          if (!plan.probes.length) return [];
          const rows: JsonObject[] = [];
          let readBytes = 0;
          await run(
            IDENTITY_SCOPE_QUERY,
            {
              ...params,
              scopePairs: identityScopeParameters(plan),
              candidateLimit: neo4j.int(plan.candidateLimit),
              buckets: plan.buckets,
              // A malformed fan-out repeats a probe's row; the classifier marks that one record
              // invalid, so only a much larger blow-up fails the whole read.
              scopeRowLimit: neo4j.int(plan.probes.length * 8 + 1),
            },
            item => {
              if (rows.length >= plan.probes.length * 8) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
              const raw = Object.fromEntries(
                IDENTITY_SCOPE_COLUMNS.map(column => [column, converted(item.get(column))]),
              );
              // An identity whose row is too large, or arrives after the read's byte budget, is
              // reported truncated for that identity only; the rest of the read stands.
              let safe: JsonObject;
              try {
                safe = safeIdentityScopeRow(raw);
              } catch {
                safe = oversized(raw.key);
              }
              const bytes = Buffer.byteLength(JSON.stringify(safe), 'utf8');
              if (readBytes + bytes > 4 * 1024 * 1024) safe = oversized(raw.key);
              else readBytes += bytes;
              if (chargeRows) charge(safe);
              rows.push(safe);
            },
          );
          return sortedBySerialization(rows);
        };
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
          return sortedBySerialization(rows);
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
            // Ids already loaded, by label: each label's query is limited to what earlier ones found.
            const idsByLabel = new Map<string, string[]>();
            const nodeQueries = NODES[accessMode]![id === currentId ? 0 : 1]!;
            for (const label of selection.summary
              ? (['GuardAgent', 'GuardDeployment', 'GuardOwner'] as const)
              : READ_ORDER) {
              const authorized: Record<string, unknown> = Object.fromEntries(
                MAP_LABELS.map(kind => [`${kind}Ids`, idsByLabel.get(kind) ?? []]),
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
                  const ids = idsByLabel.get(label);
                  if (ids) ids.push(node.id);
                  else idsByLabel.set(label, [node.id]);
                },
              );
            }
            // Delegation ancestors are read after every source's own nodes and edges (below).
            if (agentSelected && boundary && id === currentId) ancestorJobs.push({ sourceId, params });
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
            let projection: MapProjection = {
              id,
              snapshotId,
              generatedAt,
              status: 'published',
              nodes,
              edges,
              coverage: coverage(nodes, captures, profile, selection.summary ?? false, now() * 1000),
            };
            if (agentSelected && boundary && id === currentId) {
              // The agent's own `*` grants (ancestors' grants are not read).
              const wildcardTools = [
                ...new Set(
                  nodes
                    .filter(node => node.label === 'GuardGrant')
                    .filter(node => (node.properties.resources as readonly string[]).includes('*'))
                    .map(node => node.properties.tool as string),
                ),
              ].sort();
              // No prototype: a tool may be named like an Object.prototype member.
              const wildcardSensitivity: Record<string, { id: string; sensitivity: string }[]> = Object.create(null);
              if (wildcardTools.length)
                await run(WILDCARD[accessMode]!, { ...params, wildcardTools }, item => {
                  const tool = item.get('tool'),
                    bindings = converted(item.get('bindings'));
                  if (
                    typeof tool !== 'string' ||
                    !wildcardTools.includes(tool) ||
                    !Array.isArray(bindings) ||
                    bindings.length > 5 ||
                    Object.hasOwn(wildcardSensitivity, tool) ||
                    bindings.some(
                      binding =>
                        !binding ||
                        typeof binding.id !== 'string' ||
                        !['confidential', 'restricted'].includes(binding.sensitivity),
                    )
                  )
                    throw new MapQueryError('MAP_UNAVAILABLE');
                  // The same identifier rule as every node id, so list and detail agree.
                  for (const binding of bindings) mapIdentifier(binding.id, 'MAP_UNAVAILABLE');
                  wildcardSensitivity[tool] = bindings.map(binding => ({
                    id: binding.id as string,
                    sensitivity: binding.sensitivity as string,
                  }));
                });
              charge(wildcardSensitivity);
              projection = { ...projection, wildcardSensitivity };
            }
            if (!selection.summary && !selection.history && !selection.flags && id === currentId) {
              const plan = policyPlan(scope.companyId, tenantId, nodes, edges, 512 - policyPairCount);
              policyPairCount += plan.records.length;
              const reach = selection.agentId === undefined && selection.outsideGuard === true;
              const enrolled = record.get('policyCoverage');
              const maximumAge = plan.probes.length ? maximumAgeFor(enrolled) : this.#policyAge;
              const rows = await readPolicy(plan, params, true);
              const evidence = policyEvidence(plan, rows, now(), maximumAge);
              for (const item of evidence) charge(item);
              // A team reader sees only buckets and host targets that an in-scope binding maps;
              // null allows all.
              let readable: Set<string> | null = null;
              let inScopeTargets: string[] | undefined;
              if (selection.agentId !== undefined && boundary && !scope.allTeams) {
                const names = new Set(boundBuckets(nodes));
                const hosts = new Set<string>();
                let count = 0;
                // Host ids only for targets the agent's own declared paths name: bounded by the read.
                const targetRefs = [
                  ...new Set(
                    nodes
                      .filter(node => node.label === 'GuardDirectAccess')
                      .map(node => node.properties.target_ref)
                      .filter((ref): ref is string => typeof ref === 'string'),
                  ),
                ];
                await run(IN_SCOPE_TARGETS, { ...params, targetRefs }, item => {
                  if (++count > 20_000) return;
                  const name = bucketName(item.get('arn'));
                  if (name !== null) names.add(name);
                  const host = item.get('host');
                  if (typeof host === 'string' && /^opaque:[a-f0-9]{64}$/.test(host)) hosts.add(host);
                });
                // Past the bound, fall back to what this read holds: that only withholds more.
                readable = count > 20_000 ? new Set(boundBuckets(nodes)) : names;
                inScopeTargets = count > 20_000 ? [] : [...hosts].sort();
                charge(inScopeTargets);
              }
              let outsideVisibleScope: boolean | undefined;
              if (reach && !scope.allTeams) {
                const visibleIds = nodes
                  .filter(node => node.label === 'GuardDeployment' || node.label === 'GuardTask')
                  .map(node => node.id);
                const [hidden] = await run(HIDDEN_SCOPE, { ...params, visibleIds });
                // Only an explicit "nothing hidden" lets none_found stand.
                outsideVisibleScope = hidden?.get('hidden') !== false;
              }
              const enriched = {
                ...projection,
                policyEvidence: evidence,
                ...(outsideVisibleScope === undefined ? {} : { outsideVisibleScope }),
                ...(inScopeTargets === undefined ? {} : { inScopeTargets }),
              };
              const check = {
                plan,
                scopePlan: identityScopePlan(scope.companyId, tenantId, [], [], 0),
                params,
                rows,
                scopeRows: [] as JsonObject[],
                readable,
                projection: enriched,
                maximumAge,
                scopeBudget: SCOPE_RECORD_BYTES,
              };
              policyChecks.push(check);
              if ((selection.agentId !== undefined && boundary) || reach)
                scopeJobs.push({ sourceId, check, reach, enrolled });
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
        // Delegation ancestors last, after every source's own nodes and edges, so they never
        // crowd out an agent's own evidence: each source's ancestors are added only if they fit
        // what is left of the node, edge and byte budgets (keeping a quarter of the bytes for
        // evidence). Otherwise none are added and the projection says so.
        for (const job of ancestorJobs) {
          const index = sources.findIndex(item => item.id === job.sourceId);
          const current = sources[index]!.current;
          const loaded = new Set(current.nodes.map(node => node.id));
          const entities = new Set(current.nodes.map(node => node.entityId));
          const nodeRoom = this.#nodes - nodeCount;
          const found: string[] = [];
          const foundIds = new Set<string>();
          await run(
            ANCESTORS[accessMode]!,
            {
              ...job.params,
              GuardDeploymentIds: current.nodes.filter(node => node.label === 'GuardDeployment').map(node => node.id),
              nodeLimit: neo4j.int(this.#nodes + 1),
            },
            item => {
              const ancestor = text(item.get('id'));
              if (!loaded.has(ancestor) && !foundIds.has(ancestor) && found.length <= nodeRoom) {
                foundIds.add(ancestor);
                found.push(ancestor);
              }
            },
          );
          let notLoaded = found.length > nodeRoom;
          const records: MapNode[] = [],
            extra: MapEdge[] = [];
          if (!notLoaded && found.length) {
            const requested = new Set(found);
            await run(
              ANCESTOR_TASKS,
              { ...job.params, ancestorTaskIds: found, nodeLimit: neo4j.int(found.length + 1) },
              item => {
                if (item.get('label') !== 'GuardTask') throw new MapQueryError('MAP_UNAVAILABLE');
                const node = safeNode(item.get('node'), 'GuardTask', job.sourceId, current.id);
                // Each requested id once: a second node with the same id is malformed.
                if (!requested.delete(node.id) || entities.has(node.entityId))
                  throw new MapQueryError('MAP_UNAVAILABLE');
                entities.add(node.entityId);
                records.push(node);
              },
            );
            // Only delegation and handoff edges touch ancestors (their grants and deployments
            // are not read).
            const ancestorSet = new Set(records.map(node => node.id));
            const taskIds = [
              ...current.nodes.filter(node => node.label === 'GuardTask').map(node => node.id),
              ...ancestorSet,
            ];
            const tasks = new Set(taskIds);
            const edgeRoom = this.#edges - edgeCount;
            await run(
              EDGES,
              {
                ...job.params,
                nodeIds: taskIds,
                relationships: ['G_DELEGATED_FROM', 'G_DERIVED_FROM'],
                edgeLimit: neo4j.int(this.#edges + 1),
              },
              item => {
                const source = text(item.get('source')),
                  target = text(item.get('target'));
                const kind = item.get('kind');
                if (
                  (kind !== 'G_DELEGATED_FROM' && kind !== 'G_DERIVED_FROM') ||
                  !tasks.has(source) ||
                  !tasks.has(target)
                )
                  throw new MapQueryError('MAP_UNAVAILABLE');
                if (!ancestorSet.has(source) && !ancestorSet.has(target)) return;
                if (extra.length <= edgeRoom) extra.push({ source, target, kind });
              },
            );
            const bytes = Buffer.byteLength(JSON.stringify([records, extra]), 'utf8');
            notLoaded = extra.length > edgeRoom || materializedBytes + bytes > 3 * 1024 * 1024;
            if (!notLoaded) {
              charge([records, extra]);
              nodeCount += records.length;
              edgeCount += extra.length;
            }
          }
          sources[index] = {
            ...sources[index]!,
            current: notLoaded
              ? { ...current, ancestorsNotLoaded: true }
              : { ...current, nodes: [...current.nodes, ...records], edges: [...current.edges, ...extra] },
          };
        }
        // Identity scope, now that each projection holds its ancestors. A one-agent read lists
        // every bucket per identity; an outside-guard read (list_resources, get_resource_access)
        // asks only about the buckets visible bindings map to.
        for (const job of scopeJobs) {
          const index = sources.findIndex(item => item.id === job.sourceId);
          const current = sources[index]!.current;
          const buckets = boundBuckets(current.nodes);
          // Identity scope is optional evidence: if planning it needs more work than allowed,
          // the read goes on without it (records read unknown, reach cannot be none_found).
          let scopePlan: IdentityScopePlan;
          try {
            scopePlan = !job.reach
              ? // Each distinct identity can return about 1,500 candidates; eight keeps a broad
                // fleet inside the read's byte budget, and the rest report not_evaluated.
                identityScopePlan(
                  scope.companyId,
                  sources[index]!.tenantId,
                  current.nodes,
                  current.edges,
                  Math.max(0, 8 - scopePairCount),
                  null,
                  Date.parse(current.generatedAt),
                )
              : buckets.length
                ? identityScopePlan(
                    scope.companyId,
                    sources[index]!.tenantId,
                    current.nodes,
                    current.edges,
                    Math.max(0, 32 - scopePairCount),
                    buckets,
                    Date.parse(current.generatedAt),
                  )
                : identityScopePlan(scope.companyId, sources[index]!.tenantId, [], [], 0);
          } catch (error) {
            if (!(error instanceof MapQueryError) || error.code !== 'MAP_LIMIT_EXCEEDED') throw error;
            continue;
          }
          scopePairCount += scopePlan.probes.length;
          // Scope rows have their own byte bound in readScope; only the bounded records count
          // toward the view, so a broad role cannot crowd out the rest. A scope-only read with
          // an unreadable age bound, or a malformed row fan-out, also goes on without it.
          let scopeRows: JsonObject[];
          try {
            if (scopePlan.probes.length && !job.check.plan.probes.length)
              job.check.maximumAge = maximumAgeFor(job.enrolled);
            scopeRows = await readScope(scopePlan, job.check.params, false);
          } catch (error) {
            if (
              !(error instanceof MapQueryError) ||
              !['MAP_LIMIT_EXCEEDED', 'MAP_UNAVAILABLE'].includes(error.code) ||
              !transaction?.isOpen()
            )
              throw error;
            continue;
          }
          // The lists are optional detail: they get what is left of the read's byte budget,
          // less headroom for the final copy. If even the bare records do not fit, the read
          // answers without identity scope.
          const scopeBudget = Math.max(
            0,
            Math.min(SCOPE_RECORD_BYTES, 4 * 1024 * 1024 - SCOPE_HEADROOM_BYTES - materializedBytes),
          );
          const identityScope = boundedRecords(
            identityScopeEvidence(scopePlan, scopeRows, now(), job.check.maximumAge, job.check.readable),
            scopeBudget,
          );
          if (Buffer.byteLength(JSON.stringify(identityScope), 'utf8') > scopeBudget) continue;
          for (const item of identityScope) charge(item);
          const updated = {
            ...current,
            ...(job.reach ? { identityReach: identityScope } : { identityScope }),
          };
          sources[index] = { ...sources[index]!, current: updated };
          job.check.scopePlan = scopePlan;
          job.check.scopeRows = scopeRows;
          job.check.scopeBudget = scopeBudget;
          job.check.projection = updated;
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
          const scopeRows = await readScope(checked.scopePlan, checked.params, false);
          if (JSON.stringify(scopeRows) !== JSON.stringify(checked.scopeRows))
            throw new MapQueryError('MAP_UNAVAILABLE');
          const scoped = boundedRecords(
            identityScopeEvidence(checked.scopePlan, scopeRows, now(), checked.maximumAge, checked.readable),
            checked.scopeBudget,
          );
          if (
            JSON.stringify(scoped) !==
            JSON.stringify(checked.projection.identityScope ?? checked.projection.identityReach ?? [])
          )
            throw new MapQueryError('MAP_UNAVAILABLE');
        }
        const freeze = (items: readonly MapSource[]): MapView =>
          immutableJson({ sources: items }, 16, 200_000, 4 * 1024 * 1024) as unknown as MapView;
        try {
          return freeze(sources);
        } catch {
          // The identity-scope bucket lists are optional detail: drop them before refusing the
          // read (their statuses stand; see shortenScopeList).
          const bare = (records: readonly MapIdentityScope[]): readonly MapIdentityScope[] =>
            records.map(record => shortenScopeList(record, 0));
          const lean: MapSource[] = sources.map(item => ({
            ...item,
            current: {
              ...item.current,
              ...(item.current.identityScope ? { identityScope: bare(item.current.identityScope) } : {}),
              ...(item.current.identityReach ? { identityReach: bare(item.current.identityReach) } : {}),
            },
          }));
          try {
            return freeze(lean);
          } catch {
            throw new MapQueryError('MAP_LIMIT_EXCEEDED');
          }
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
