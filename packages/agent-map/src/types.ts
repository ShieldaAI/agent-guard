import { immutableJson } from '@shieldaai/agent-guard';

export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };
export class MapQueryError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'MapQueryError'; }
}
export interface ReadScope {
  readonly subject: string;
  readonly companyId: string;
  readonly tenantIds: readonly string[];
  readonly teamIds: readonly string[];
  readonly allTeams: boolean;
}
export const MAP_LABELS = ['GuardAgent', 'GuardDeployment', 'GuardTask', 'GuardPrincipal', 'GuardGrant',
  'GuardTool', 'GuardResource', 'GuardResourceBinding', 'GuardExecutionBinding', 'GuardExternalResource',
  'GuardExternalIdentity', 'GuardMcpConnection', 'GuardMcpOperation'] as const;
export type GuardLabel = typeof MAP_LABELS[number];
export const MAP_RELATIONSHIPS = ['G_INSTANCE_OF', 'G_ASSIGNED_TO', 'G_ACTS_AS', 'G_DELEGATED_FROM',
  'G_DERIVED_FROM', 'G_HAS_GRANT', 'G_FOR_TOOL', 'G_TARGETS', 'G_BINDS_SELECTOR', 'G_MAPS_TO',
  'G_EXECUTES_FOR', 'G_EXECUTES_TOOL', 'G_USES_IDENTITY', 'G_VIA_CONNECTION', 'G_EXPOSES_OPERATION',
  'G_OPERATION_TOOL'] as const;
export type GuardRelation = typeof MAP_RELATIONSHIPS[number];
export interface MapNode {
  readonly id: string;
  readonly entityId: string;
  readonly label: GuardLabel;
  readonly sourceId: string;
  readonly projectionId: string;
  readonly properties: JsonObject;
}
export interface MapEdge { readonly source: string; readonly target: string; readonly kind: GuardRelation }
export interface MapCoverage { readonly [component: string]: { readonly status: string; readonly observedAt?: string } }
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
  readonly reason: 'no_candidate' | 'binding_ambiguous' | 'cloud_unresolved' | 'provider_missing' |
    'collection_invalid' | 'stale' | 'changed' | 'boundary_unresolved' | 'unsupported_policy' |
    'evidence_invalid' | 'unsupported_action' | 'identity_not_static' | 'unsupported_binding' |
    'cloud_not_collected' | 'collection_missing' | 'disabled' | null;
  readonly observedAt: string | null;
  readonly assessment: 'unknown';
  readonly candidates: readonly MapPolicyCandidate[];
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
}
export interface MapSource {
  readonly id: string;
  readonly tenantId: string;
  readonly sourceId: string;
  readonly profile: 'core' | 'host' | 'host-mcp';
  readonly current: MapProjection;
  readonly previous: MapProjection | null;
}
export interface MapView { readonly sources: readonly MapSource[] }
export interface MapReadRequest {
  readonly sourceId?: string;
  readonly agentId?: string;
  readonly history?: boolean;
  /** Agent/deployment index only; avoids loading task neighborhoods before selecting an agent. */
  readonly summary?: boolean;
}
export interface MapStore { read(scope: ReadScope, request?: MapReadRequest): Promise<MapView> }

export function mapIdentifier(value: unknown, code = 'MAP_REQUEST_INVALID'): string {
  if (typeof value !== 'string' || !value.trim() || [...value].length > 4096 || value.includes('\0') ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw new MapQueryError(code);
  return value;
}
export function validateReadScope(value: unknown): ReadScope {
  try {
    const copied = immutableJson(value, 4, 1024, 64 * 1024) as unknown as Record<string, unknown>;
    if (!copied || Array.isArray(copied) || typeof copied !== 'object' ||
        Object.keys(copied).sort().join(',') !== 'allTeams,companyId,subject,teamIds,tenantIds') throw new Error();
    mapIdentifier(copied.subject); mapIdentifier(copied.companyId);
    if (typeof copied.allTeams !== 'boolean') throw new Error();
    for (const key of ['tenantIds', 'teamIds']) {
      const items = copied[key];
      if (!Array.isArray(items) || items.length > 128 || (key === 'tenantIds' && items.length === 0) ||
          new Set(items).size !== items.length) throw new Error();
      items.forEach(item => mapIdentifier(item));
    }
    if (!copied.allTeams && (copied.teamIds as unknown[]).length === 0) throw new Error();
    return copied as unknown as ReadScope;
  } catch { throw new MapQueryError('MAP_SCOPE_INVALID'); }
}
