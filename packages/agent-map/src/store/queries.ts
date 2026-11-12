import { MAP_PROPERTIES } from '../projection-fields.js';
import { MAP_LABELS, type GuardLabel } from '../types.js';
import { coverage } from './nodes.js';

export interface QueryAccess {
  readonly allTeams: boolean;
  readonly agentSelected: boolean;
}
export const QUERY_ACCESS: readonly QueryAccess[] = Array.from({ length: 4 }, (_, mode) => ({
  allTeams: Boolean(mode & 2),
  agentSelected: Boolean(mode & 1),
}));
export function agentPredicate(variable: string, access: QueryAccess): string {
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
export const SOURCES = QUERY_ACCESS.map(access =>
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

export const scoped = (variable: string): string =>
  `${variable}.source_id=$sourceId AND ${variable}.projection_id=$projectionId AND ${variable}.tenant_id=$tenantId`;
// Derive each next set only from previously authorized nodes, with bounds after every set.
export const READ_ORDER: readonly GuardLabel[] = [
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
export const historicalVisibility = (label: 'GuardAgent' | 'GuardTask', parameter: string): string =>
  `(n.entity_id IN $${parameter} OR NOT EXISTS {
    MATCH (current:${label})-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$currentId})
    WHERE current.entity_id=n.entity_id AND current.source_id=$sourceId
      AND current.projection_id=$currentId AND current.tenant_id=$tenantId
  })`;
export function through(path: string, label: GuardLabel): string {
  return `EXISTS { MATCH ${path} WHERE ${scoped('visible')} AND visible.id IN $${label}Ids }`;
}
export const predicates: Readonly<Record<Exclude<GuardLabel, 'GuardAgent'>, string>> = {
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
export function nodePredicate(label: GuardLabel, access: QueryAccess, historical: boolean): string {
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
export const NODES = QUERY_ACCESS.map(access =>
  [false, true].map(
    historical =>
      Object.fromEntries(
        MAP_LABELS.map(label => [
          label,
          `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})
MATCH (n:${label})-[:G_IN_SNAPSHOT]->(p)
WHERE ${scoped('n')} AND size([label IN labels(n) WHERE label IN $labels])=1 AND
 (${nodePredicate(label, access, historical)})
RETURN '${label}' AS label,n { .id,.entity_id,.source_id,.projection_id,${MAP_PROPERTIES[label].map(field => `.${field}`).join(',')} } AS node
ORDER BY n.id LIMIT $nodeLimit`,
        ]),
      ) as Readonly<Record<GuardLabel, string>>,
  ),
);
// A boundary read (get_agent_access, page flags) also needs what the team-wide read would
// show the flags: the in-scope delegation ancestors of the agent's tasks (recipients are
// checked against every ancestor; read after the agent's own nodes, within what is left of
// the budget) and, for `*` grants, whether an in-scope binding of the tool is sensitive.
// Both follow the team-wide visibility rules, so a flag is the same in either read.
// Templates stay specialized per scope mode: an all-teams reader needs no team check.
// Delegation ancestors (at most 16 levels) of the selected agent's tasks. Anchored at the
// agent's deployments, so the work follows its own task chains, not every task in the graph.
// For a team reader every ancestor on the path must be in scope, so the walk stops at the
// first hidden one (where the flags stop too) and never counts tasks the reader can't see.
// Every node a boundary path passes through gets the same checks as the team-wide read:
// scoped to this source, projection and tenant, and carrying exactly one Map label.
export const checked = (variable: string): string =>
  `${scoped(variable)} AND size([label IN labels(${variable}) WHERE label IN $labels])=1`;
// A binding reachable from an agent in the reader's teams, every hop checked.
export const inScopeBinding = (binding: string): string => `EXISTS {
    MATCH (${binding})-[:G_BINDS_SELECTOR]->(r:GuardResource)<-[:G_TARGETS]-(g:GuardGrant)<-[:G_HAS_GRANT]-(t:GuardTask)
      -[:G_ASSIGNED_TO]->(d:GuardDeployment)-[:G_INSTANCE_OF]->(a:GuardAgent)
    WHERE ${['r', 'g', 't', 'd', 'a'].map(checked).join(' AND ')} AND a.team_id IN $teamIds
  }`;
export const ancestorsQuery = (
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
export const ANCESTORS = QUERY_ACCESS.map(ancestorsQuery);
// The ancestor task records themselves, once their ids are known and fit the budget.
export const ANCESTOR_TASKS = `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})
MATCH (n:GuardTask)-[:G_IN_SNAPSHOT]->(p)
WHERE ${scoped('n')} AND n.id IN $ancestorTaskIds AND size([label IN labels(n) WHERE label IN $labels])=1
RETURN 'GuardTask' AS label,n { .id,.entity_id,.source_id,.projection_id,${MAP_PROPERTIES.GuardTask.map(field => `.${field}`).join(',')} } AS node
ORDER BY n.id LIMIT $nodeLimit`;
// For each tool the agent holds a `*` grant on: up to five in-scope bindings of that tool
// marked confidential or restricted. Asked instead of loading every binding of the tool.
export const wildcardQuery = (access: QueryAccess): string => `UNWIND $wildcardTools AS tool
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
export const WILDCARD = QUERY_ACCESS.map(wildcardQuery);
// For a team-scoped reader: the S3 buckets that bindings reachable from an in-scope agent
// map to. Identity scope names only these; any other bucket (another team's, or one no
// binding maps) becomes a note without a name or a count.
export const IN_SCOPE_TARGETS = `MATCH (rb:GuardResourceBinding)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
WHERE ${checked('rb')} AND ${inScopeBinding('rb')}
MATCH (rb)-[:G_MAPS_TO]->(x:GuardExternalResource)
WHERE ${checked('x')}
  AND ((x.provider='host' AND x.host_resource_id IN $targetRefs) OR (x.provider='aws' AND x.arn STARTS WITH 'arn:aws:s3:::'))
RETURN DISTINCT substring(x.arn,0,2049) AS arn,substring(x.host_resource_id,0,72) AS host LIMIT 20001`;
// Whether any deployment or task lies outside the reader's read: a boolean, never a count.
export const HIDDEN_SCOPE = `RETURN EXISTS {
  MATCH (n)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
  WHERE (n:GuardDeployment OR n:GuardTask) AND ${scoped('n')} AND NOT n.id IN $visibleIds
} AS hidden`;
// Discovery reads, for all-teams readers only: nothing here belongs to a team, so a team-scoped
// read is refused before any of these run. A task is declared when a manifest task binding
// assigns it to a deployment of a declared agent; every hop gets the usual checks.
export const declaredTask = (task: string): string => `EXISTS {
    MATCH (${task})-[:G_ASSIGNED_TO]->(dd:GuardDeployment)-[:G_INSTANCE_OF]->(da:GuardAgent)
    WHERE ${checked('dd')} AND ${checked('da')}
  }`;
export const declaredPrincipal = (principal: string): string => `EXISTS {
    MATCH (${principal})<-[:G_ACTS_AS]-(pt:GuardTask)
    WHERE ${checked('pt')} AND ${declaredTask('pt')}
  }`;
export const SNAPSHOT = `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})`;
// Counting stops one past the limit, so the work is bounded and "at least" is reported honestly.
export const UNDECLARED_COUNT_LIMIT = 10_000;
export const UNDECLARED_COUNTS = `${SNAPSHOT}
CALL (p) {
  MATCH (t:GuardTask)-[:G_IN_SNAPSHOT]->(p)
  WHERE ${checked('t')} AND NOT ${declaredTask('t')}
  WITH t LIMIT $countLimit
  RETURN count(t) AS tasks
}
CALL (p) {
  MATCH (c:GuardPrincipal)-[:G_IN_SNAPSHOT]->(p)
  WHERE ${checked('c')} AND NOT ${declaredPrincipal('c')}
  WITH c LIMIT $countLimit
  RETURN count(c) AS principals
}
RETURN tasks, principals`;
// One page of undeclared tasks. `parentDeclared` looks one hop up: a sub-task of a declared
// agent's task that only lacks its own binding should not read like an unknown caller.
export const UNDECLARED_TASKS = `${SNAPSHOT}
MATCH (t:GuardTask)-[:G_IN_SNAPSHOT]->(p)
WHERE ${checked('t')} AND NOT ${declaredTask('t')}
WITH t ORDER BY t.task_id, t.id SKIP $pageOffset LIMIT $pageLimit
RETURN substring(t.entity_id,0,4097) AS id,substring(t.task_id,0,4097) AS taskId,
 substring(t.principal_id,0,4097) AS principalId,t.delegated AS delegated,t.derived AS derived,t.revoked AS revoked,
 EXISTS {
   MATCH (t)-[:G_DELEGATED_FROM|G_DERIVED_FROM]->(parent:GuardTask)
   WHERE ${checked('parent')} AND ${declaredTask('parent')}
 } AS parentDeclared,
 [(t)-[:G_HAS_GRANT]->(g:GuardGrant) WHERE ${checked('g')} | substring(g.tool,0,4097)][..33] AS tools
ORDER BY taskId, id`;
// One page of caller principals none of whose tasks is declared, with a bounded task count.
export const UNDECLARED_PRINCIPALS = `${SNAPSHOT}
MATCH (c:GuardPrincipal)-[:G_IN_SNAPSHOT]->(p)
WHERE ${checked('c')} AND NOT ${declaredPrincipal('c')}
WITH c ORDER BY c.principal_id, c.id SKIP $pageOffset LIMIT $pageLimit
CALL (c) {
  MATCH (c)<-[:G_ACTS_AS]-(t:GuardTask)
  WHERE ${checked('t')}
  WITH t LIMIT 1001
  RETURN count(t) AS tasks
}
RETURN substring(c.entity_id,0,4097) AS id,substring(c.principal_id,0,4097) AS principalId,tasks
ORDER BY principalId, id`;
// The AWS collections enrolled for the reader's company and tenants: at most one per account.
export const AWS_COLLECTION_LIMIT = 64;
export const AWS_COLLECTION_COLUMNS = [
  'id',
  'tenantId',
  'partition',
  'accountId',
  'schemaVersion',
  'status',
  'capturedAt',
  'contentHash',
] as const;
export const AWS_COLLECTIONS = `MATCH (c:GuardAwsCollection)
WHERE c.company_id=$companyId AND c.tenant_id IN $tenantIds
RETURN substring(c.id,0,65) AS id,substring(c.tenant_id,0,4097) AS tenantId,substring(c.partition,0,17) AS partition,
 substring(c.account_id,0,13) AS accountId,c.schema_version AS schemaVersion,substring(c.status,0,33) AS status,
 c.captured_at AS capturedAt,substring(c.content_hash,0,65) AS contentHash
ORDER BY id LIMIT $collectionLimit`;
// ARNs that a declared agent's execution binding names in this projection. The manifest's
// ARN is the claim: it stands whether or not the cloud join resolved it.
export const CLAIM_LIMIT = 10_000;
export const CLAIMED_IDENTITIES = `MATCH (i:GuardExternalIdentity)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
WHERE ${checked('i')} AND i.arn IS NOT NULL AND EXISTS {
  MATCH (i)<-[:G_USES_IDENTITY]-(b:GuardExecutionBinding)-[:G_EXECUTES_FOR]->(d:GuardDeployment)-[:G_INSTANCE_OF]->(a:GuardAgent)
  WHERE ${['b', 'd', 'a'].map(checked).join(' AND ')}
}
RETURN DISTINCT substring(i.arn,0,2049) AS arn LIMIT $claimLimit`;
// Whether some declared execution binding names no identity at all: it may use a listed one.
export const BINDINGS_WITHOUT_IDENTITY = `RETURN EXISTS {
  MATCH (b:GuardExecutionBinding)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
  WHERE ${checked('b')} AND NOT EXISTS { MATCH (b)-[:G_USES_IDENTITY]->() }
} AS open`;
// Per collection: its roles and users, how many are unclaimed, and how many members do not
// carry the collection's own capture receipt (any such member makes the account unknown).
export const AWS_MEMBER_LIMIT = 50_000;
export const UNCLAIMED_COUNTS = `MATCH (c:GuardAwsCollection)-[m:G_AWS_OBSERVED]->(p:AWSPrincipal)
WHERE c.id=$collectionId AND c.company_id=$companyId AND c.tenant_id=$collectionTenantId
WITH c,m,p LIMIT $memberLimit
RETURN count(p) AS observed,
 sum(CASE WHEN coalesce(p.arn IN $claimed,false) THEN 0 ELSE 1 END) AS unclaimed,
 sum(CASE WHEN m.capture_hash=c.content_hash AND m.captured_at=c.captured_at AND p.lastupdated=c.captured_at
   THEN 0 ELSE 1 END) AS inconsistent`;
export const UNCLAIMED_PAGE = `MATCH (c:GuardAwsCollection)-[:G_AWS_OBSERVED]->(p:AWSPrincipal)
WHERE c.id IN $collectionIds AND c.company_id=$companyId AND c.tenant_id IN $tenantIds
  AND NOT coalesce(p.arn IN $claimed,false)
WITH c,p ORDER BY p.arn, c.id SKIP $pageOffset LIMIT $pageLimit
RETURN substring(c.id,0,65) AS collectionId,substring(p.arn,0,2049) AS arn,p:AWSRole AS role,p:AWSUser AS user,
 substring(p.name,0,129) AS name,substring(p.path,0,513) AS path
ORDER BY arn, collectionId`;
// Start from the snapshot's unique id: an unlabelled `n.id IN $nodeIds` scans every node
// in the database, while snapshot membership bounds the work to this projection.
export const EDGES = `MATCH (n)-[:G_IN_SNAPSHOT]->(:GuardSnapshot {id:$projectionId})
MATCH (n)-[r]->(m)
WHERE n.id IN $nodeIds AND m.id IN $nodeIds AND type(r) IN $relationships
 AND n.source_id=$sourceId AND m.source_id=$sourceId
 AND n.projection_id=$projectionId AND m.projection_id=$projectionId
 AND n.tenant_id=$tenantId AND m.tenant_id=$tenantId
RETURN n.id AS source,m.id AS target,type(r) AS kind ORDER BY source,target,kind LIMIT $edgeLimit`;
export const PREVIOUS = `MATCH (p:GuardSnapshot {id:$projectionId,source_id:$sourceId,status:'published'})
RETURN p.id AS id,p.snapshot_id AS snapshotId,p.generated_at AS generatedAt,
 substring(p.coverage_json,0,4097) AS coverage LIMIT 1`;

// Hard ceilings for one read. Defaults stay at 2,000 nodes, 5,000 edges and 4 MiB; a host may
// raise them for a larger fleet, and every read is still one bounded transaction.
export const MAX_STORE_NODES = 10_000;
export const MAX_STORE_EDGES = 25_000;
export const MAX_STORE_BYTES = 16 * 1024 * 1024;
// list_owners needs only these labels. A team reader's bindings are visible through
// agent -> deployment -> task -> grant -> selector, so that chain is read too.
export const OWNER_INDEX: readonly GuardLabel[] = ['GuardAgent', 'GuardResourceBinding', 'GuardOwner'];
export const OWNER_INDEX_SCOPED: readonly GuardLabel[] = [
  'GuardAgent',
  'GuardDeployment',
  'GuardTask',
  'GuardGrant',
  'GuardResource',
  'GuardResourceBinding',
  'GuardOwner',
];
export const POLICY_SELECTION_KEYS = ['taskId', 'tool', 'resourceRef', 'action', 'optional'];
