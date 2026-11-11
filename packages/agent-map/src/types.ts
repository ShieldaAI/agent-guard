import { immutableJson } from '@shieldaai/agent-guard/internal';

export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };
export class MapQueryError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'MapQueryError';
  }
}
export interface ReadScope {
  readonly subject: string;
  readonly companyId: string;
  readonly tenantIds: readonly string[];
  readonly teamIds: readonly string[];
  readonly allTeams: boolean;
}
export const MAP_LABELS = [
  'GuardAgent',
  'GuardDeployment',
  'GuardTask',
  'GuardPrincipal',
  'GuardGrant',
  'GuardTool',
  'GuardResource',
  'GuardResourceBinding',
  'GuardExecutionBinding',
  'GuardExternalResource',
  'GuardExternalIdentity',
  'GuardMcpConnection',
  'GuardMcpOperation',
  'GuardOwner',
  'GuardCredentialReference',
  'GuardDirectAccess',
] as const;
export type GuardLabel = (typeof MAP_LABELS)[number];
export const MAP_RELATIONSHIPS = [
  'G_INSTANCE_OF',
  'G_ASSIGNED_TO',
  'G_ACTS_AS',
  'G_DELEGATED_FROM',
  'G_DERIVED_FROM',
  'G_HAS_GRANT',
  'G_FOR_TOOL',
  'G_TARGETS',
  'G_BINDS_SELECTOR',
  'G_MAPS_TO',
  'G_EXECUTES_FOR',
  'G_EXECUTES_TOOL',
  'G_USES_IDENTITY',
  'G_VIA_CONNECTION',
  'G_EXPOSES_OPERATION',
  'G_OPERATION_TOOL',
  'G_OWNED_BY',
  'G_RESOURCE_OWNED_BY',
  'G_USES_CREDENTIAL',
  'G_DEPENDS_ON',
  'G_DIRECT_ACCESS_FOR',
] as const;
export type GuardRelation = (typeof MAP_RELATIONSHIPS)[number];
export interface MapNode {
  readonly id: string;
  readonly entityId: string;
  readonly label: GuardLabel;
  readonly sourceId: string;
  readonly projectionId: string;
  readonly properties: JsonObject;
}
export interface MapEdge {
  readonly source: string;
  readonly target: string;
  readonly kind: GuardRelation;
}
export interface MapCoverage {
  readonly [component: string]: { readonly status: string; readonly observedAt?: string };
}
export interface MapPolicyCandidate {
  readonly relationship: 'CAN_READ' | 'CAN_WRITE' | 'CAN_LIST';
  readonly hasCondition: boolean;
  readonly conditionKeys: readonly string[];
  readonly resourceScope: 'bucket_summary';
}
export interface MapPolicyEvidence {
  readonly taskId: string;
  readonly deploymentId: string;
  readonly executionBindingId: string;
  readonly resourceBindingId: string;
  readonly identityId: string | null;
  readonly resourceId: string | null;
  readonly action: string;
  readonly status: 'complete' | 'unavailable' | 'not_collected';
  readonly reason:
    | 'no_candidate'
    | 'binding_ambiguous'
    | 'cloud_unresolved'
    | 'provider_missing'
    | 'collection_invalid'
    | 'stale'
    | 'changed'
    | 'boundary_unresolved'
    | 'unsupported_policy'
    | 'evidence_invalid'
    | 'unsupported_action'
    | 'identity_not_static'
    | 'unsupported_binding'
    | 'cloud_not_collected'
    | 'collection_missing'
    | 'disabled'
    | null;
  readonly observedAt: string | null;
  readonly assessment: 'unknown';
  readonly candidates: readonly MapPolicyCandidate[];
}
/** A bucket a tool's static identity has an identity-policy candidate on, outside that tool's bindings. */
export interface MapIdentityExtraResource {
  readonly resourceId: string;
  readonly bucketName: string;
  readonly relationship: MapPolicyCandidate['relationship'];
  readonly hasCondition: boolean;
  readonly conditionKeys: readonly string[];
}
/** C2: what a tool's execution identity reaches compared with what that tool's grants bind. */
export interface MapIdentityScope {
  readonly executionBindingId: string;
  readonly deploymentId: string | null;
  readonly tool: string | null;
  readonly identityId: string | null;
  /** The identity's AWS account; candidates are collected per account, so only its buckets are checked. */
  readonly accountId: string | null;
  readonly status: 'broader_than_grants' | 'matches_grants' | 'unknown';
  readonly reason:
    | Exclude<MapPolicyEvidence['reason'], 'no_candidate' | 'unsupported_action' | 'unsupported_binding'>
    | 'unsupported_identity'
    | 'not_evaluated'
    | 'wildcard_grant'
    | 'binding_narrower_than_candidate'
    | 'grant_lineage_unknown'
    | 'truncated';
  readonly observedAt: string | null;
  readonly boundBuckets: readonly string[];
  readonly extraResources: readonly MapIdentityExtraResource[];
  readonly truncated: boolean;
  /**
   * `evidence_outside_visible_scope`: some extra buckets have no binding in your scope (another
   * team's, or none). `bucket_list_shortened`: the list is cut; the status still stands.
   */
  readonly notes?: readonly string[];
  readonly evidenceKind: 'iam_identity_policy_candidate';
  readonly assessment: 'unknown';
}
export interface MapProjection {
  readonly id: string;
  readonly snapshotId: string;
  readonly generatedAt: string;
  readonly status: 'published';
  readonly nodes: readonly MapNode[];
  readonly edges: readonly MapEdge[];
  readonly coverage: MapCoverage;
  /** Current, independently checked policy evidence; omitted for summaries/history. */
  readonly policyEvidence?: readonly MapPolicyEvidence[];
  /** Current identity-scope comparison per static execution binding; only for one-agent reads. */
  readonly identityScope?: readonly MapIdentityScope[];
  /**
   * The same comparison limited to buckets that visible bindings map to; only for
   * `outsideGuard` reads. `matches_grants` here covers only those buckets.
   */
  readonly identityReach?: readonly MapIdentityScope[];
  /**
   * Outside-guard reads for a team-scoped reader: false when the projection has no
   * deployment or task outside the reader's read, so `none_found` can stand. Never a count.
   */
  readonly outsideVisibleScope?: boolean;
  /** A boundary read had no room left for delegation ancestors and loaded none. */
  readonly ancestorsNotLoaded?: boolean;
  /** One-agent boundary reads for a team reader: host resource ids in its scope. */
  readonly inScopeTargets?: readonly string[];
  /**
   * Boundary reads: for each tool the agent holds a `*` grant on, up to five in-scope bindings
   * of that tool marked confidential or restricted. Read in place of loading every binding.
   */
  readonly wildcardSensitivity?: Readonly<
    Record<string, readonly { readonly id: string; readonly sensitivity: string }[]>
  >;
  /** `undeclared` reads only: activity in this projection that no declared agent accounts for. */
  readonly undeclared?: MapUndeclaredActivity;
}
/** A task seen through an enrolled executor that no manifest task binding assigns to a declared agent. */
export interface MapUndeclaredTask {
  readonly id: string;
  readonly taskId: string;
  readonly principalId: string | null;
  readonly delegated: boolean | null;
  readonly derived: boolean | null;
  readonly revoked: boolean | null;
  /** Its direct parent or source task is assigned to a declared agent: likely that agent's sub-task. */
  readonly parentDeclared: boolean;
  /** Tools the task holds a declared grant on, at most 32. */
  readonly tools: readonly string[];
  readonly toolsTruncated: boolean;
}
/** A caller principal none of whose tasks is assigned to a declared agent. */
export interface MapUndeclaredPrincipal {
  readonly id: string;
  readonly principalId: string;
  /** Its tasks in this projection, counted up to 1,000. */
  readonly tasks: number;
  readonly tasksCapped: boolean;
}
/** Only for `undeclared` reads (all-teams readers). Counting stops at 10,000: `*Capped` means "at least". */
export interface MapUndeclaredActivity {
  readonly tasks: number;
  readonly tasksCapped: boolean;
  readonly principals: number;
  readonly principalsCapped: boolean;
  readonly page?:
    | { readonly kind: 'tasks'; readonly items: readonly MapUndeclaredTask[] }
    | { readonly kind: 'principals'; readonly items: readonly MapUndeclaredPrincipal[] };
}
/** One enrolled AWS account's collection, judged for an `unclaimedIdentities` read. */
export interface MapCloudAccount {
  readonly tenantId: string;
  readonly partition: string;
  readonly accountId: string;
  readonly status: 'complete' | 'unknown';
  readonly reason: 'collection_invalid' | 'stale' | 'changed' | 'limit_exceeded' | 'claims_limit_exceeded' | null;
  readonly observedAt: string | null;
  /** IAM roles and users in the collection, and how many of them no declared binding names; null when unknown. */
  readonly observed: number | null;
  readonly unclaimed: number | null;
}
/** An IAM role or user in a complete, fresh collection whose ARN no declared execution binding names. */
export interface MapUnclaimedIdentity {
  readonly arn: string;
  readonly kind: 'role' | 'user';
  readonly name: string;
  readonly path: string;
  readonly tenantId: string;
  readonly partition: string;
  readonly accountId: string;
}
/** Only for `unclaimedIdentities` reads (all-teams readers). */
export interface MapUnclaimedIdentities {
  readonly accounts: readonly MapCloudAccount[];
  /** One page over the complete accounts, ordered by ARN. */
  readonly identities: readonly MapUnclaimedIdentity[];
  /** Unclaimed identities across the complete accounts. */
  readonly total: number;
  /** Some declared execution binding names no identity, so a listed identity may be its own. */
  readonly bindingsWithoutIdentity: boolean;
}
export interface MapSource {
  readonly id: string;
  readonly tenantId: string;
  readonly sourceId: string;
  readonly profile: 'core' | 'host' | 'host-mcp';
  readonly current: MapProjection;
  readonly previous: MapProjection | null;
}
export interface MapView {
  readonly sources: readonly MapSource[];
  /** `unclaimedIdentities` reads only. */
  readonly unclaimedIdentities?: MapUnclaimedIdentities;
}
export interface MapReadRequest {
  readonly sourceId?: string;
  readonly agentId?: string;
  /** With agentId: also load boundary evidence (get_agent_access). */
  readonly boundary?: boolean;
  /** A flags read for a page of agents (1-100 native or entity ids), with one-agent rules. */
  readonly agentIds?: readonly string[];
  readonly history?: boolean;
  /** Agent/deployment index only; avoids loading task neighborhoods before selecting an agent. */
  readonly summary?: boolean;
  /** Full graph for boundary flags, without policy or identity evidence reads. */
  readonly flags?: boolean;
  /** Full graph plus identity reach limited to the buckets visible bindings map to. */
  readonly outsideGuard?: boolean;
  /**
   * All-teams readers only. Per source, counts of tasks and caller principals that no declared
   * agent accounts for; no nodes are loaded. With `sourceId` and `page`, also one page of them.
   */
  readonly undeclared?: boolean;
  /**
   * All-teams readers only, never with `sourceId`. IAM roles and users of the enrolled AWS
   * collections that no declared execution binding names, one `page` at a time.
   */
  readonly unclaimedIdentities?: boolean;
  /** `kind` is required with `undeclared` and refused with `unclaimedIdentities`. */
  readonly page?: { readonly kind?: 'tasks' | 'principals'; readonly offset: number; readonly limit: number };
}
export interface MapStore {
  read(scope: ReadScope, request?: MapReadRequest): Promise<MapView>;
}

export function mapIdentifier(value: unknown, code = 'MAP_REQUEST_INVALID'): string {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    [...value].length > 4096 ||
    value.includes('\0') ||
    /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
  )
    throw new MapQueryError(code);
  return value;
}
export function validateReadScope(value: unknown): ReadScope {
  try {
    const copied = immutableJson(value, 4, 1024, 64 * 1024) as unknown as Record<string, unknown>;
    if (
      !copied ||
      Array.isArray(copied) ||
      typeof copied !== 'object' ||
      Object.keys(copied).sort().join(',') !== 'allTeams,companyId,subject,teamIds,tenantIds'
    )
      throw new Error();
    mapIdentifier(copied.subject);
    mapIdentifier(copied.companyId);
    if (typeof copied.allTeams !== 'boolean') throw new Error();
    for (const key of ['tenantIds', 'teamIds']) {
      const items = copied[key];
      if (
        !Array.isArray(items) ||
        items.length > 128 ||
        (key === 'tenantIds' && items.length === 0) ||
        new Set(items).size !== items.length
      )
        throw new Error();
      items.forEach(item => mapIdentifier(item));
    }
    if (!copied.allTeams && (copied.teamIds as unknown[]).length === 0) throw new Error();
    return copied as unknown as ReadScope;
  } catch {
    throw new MapQueryError('MAP_SCOPE_INVALID');
  }
}
