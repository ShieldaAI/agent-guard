import neo4j from 'neo4j-driver';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { s3BucketName, shortenScopeList } from '../common.js';
import { MAP_PROPERTIES } from '../projection-fields.js';
import {
  MAP_LABELS,
  mapIdentifier,
  MapQueryError,
  type GuardLabel,
  type JsonObject,
  type MapCoverage,
  type MapIdentityScope,
  type MapNode,
} from '../types.js';

export const SCOPE_RECORD_BYTES = 1024 * 1024;
export const SCOPE_HEADROOM_BYTES = 64 * 1024;
/**
 * A stable order for bounded, already materialized rows. Each row is serialized once: the
 * comparator would otherwise re-serialize rows of up to 1 MiB on every comparison.
 */
export function sortedBySerialization(rows: JsonObject[]): JsonObject[] {
  return rows
    .map(row => [JSON.stringify(row), row] as const)
    .sort((a, b) => a[0].localeCompare(b[0], 'en-US'))
    .map(entry => entry[1]);
}
/**
 * Tools sharing a role each list their own extras. Past the budget (1 MiB, or what is left of
 * the read's byte budget if that is less), keep every record but drop the lists and report
 * them truncated, rather than fail the read.
 */
export function boundedRecords(
  records: readonly MapIdentityScope[],
  budget = SCOPE_RECORD_BYTES,
): readonly MapIdentityScope[] {
  if (Buffer.byteLength(JSON.stringify(records), 'utf8') <= budget) return records;
  return records.map(item => shortenScopeList(item, 0));
}
/** Stands in for a scope row that could not be kept; the classifier reads it as truncated. */
export const oversized = (key: unknown): JsonObject =>
  immutableJson({ key: typeof key === 'number' ? key : -1, oversized: true }) as JsonObject;
/** S3 bucket names that visible host bindings map to; the outside-guard reach asks only about these. */
export function boundBuckets(nodes: readonly MapNode[]): string[] {
  const names = new Set<string>();
  for (const node of nodes) {
    if (node.label !== 'GuardExternalResource' || node.properties.provider !== 'aws') continue;
    const name = s3BucketName(node.properties.arn);
    if (name !== null) names.add(name);
  }
  return [...names].sort();
}
export function text(value: unknown): string {
  return mapIdentifier(value, 'MAP_UNAVAILABLE');
}
export function converted(value: unknown): unknown {
  if (neo4j.isInt(value)) {
    if (!value.inSafeRange()) throw new MapQueryError('MAP_UNAVAILABLE');
    return value.toNumber();
  }
  if (Array.isArray(value)) return value.map(converted);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, converted(child)]));
  return value;
}
export function safeNode(raw: unknown, label: unknown, sourceId: string, projectionId: string): MapNode {
  if (!MAP_LABELS.includes(label as GuardLabel) || !raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new MapQueryError('MAP_UNAVAILABLE');
  const data = raw as Record<string, unknown>;
  if (data.source_id !== sourceId || data.projection_id !== projectionId) throw new MapQueryError('MAP_UNAVAILABLE');
  const properties: Record<string, unknown> = {};
  for (const field of MAP_PROPERTIES[label as GuardLabel])
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
export function observationTime(value: unknown): number | undefined {
  if (
    typeof value !== 'string' ||
    !/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/.test(value)
  )
    return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19) ? time : undefined;
}
export function coreCaptureTimes(raw: unknown): Partial<Record<'tasks' | 'tools', string>> {
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
export function coverage(
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
