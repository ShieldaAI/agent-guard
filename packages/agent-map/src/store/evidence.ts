import neo4j from 'neo4j-driver';
import {
  IDENTITY_SCOPE_COLUMNS,
  IDENTITY_SCOPE_QUERY,
  identityScopeEvidence,
  identityScopeParameters,
  POLICY_COLUMNS,
  POLICY_QUERY,
  policyEvidence,
  policyParameters,
  safeIdentityScopeRow,
  safePolicyRow,
  type IdentityScopePlan,
  type PolicyPlan,
} from '../policy-reader.js';
import { MapQueryError, type JsonObject } from '../types.js';
import { boundedRecords, converted, oversized, sortedBySerialization } from './nodes.js';
import { checked, scoped } from './queries.js';
import { StoreRead } from './read.js';

/** Identity-scope rows for one plan, each bounded; a row that is too large stands in as truncated. */
export async function readScopeRows(
  read: StoreRead,
  plan: IdentityScopePlan,
  params: Record<string, unknown>,
  chargeRows: boolean,
): Promise<JsonObject[]> {
  if (!plan.probes.length) return [];
  const rows: JsonObject[] = [];
  let readBytes = 0;
  await read.run(
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
      const raw = Object.fromEntries(IDENTITY_SCOPE_COLUMNS.map(column => [column, converted(item.get(column))]));
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
      if (chargeRows) read.charge(safe);
      rows.push(safe);
    },
  );
  return sortedBySerialization(rows);
}
/** Policy rows for one plan, bounded in count and bytes. */
export async function readPolicyRows(
  read: StoreRead,
  plan: PolicyPlan,
  params: Record<string, unknown>,
  chargeRows: boolean,
): Promise<JsonObject[]> {
  if (!plan.probes.length) return [];
  const rows: JsonObject[] = [];
  let readBytes = 0;
  const pairs = policyParameters(plan);
  if (Buffer.byteLength(JSON.stringify(pairs), 'utf8') > 4 * 1024 * 1024) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
  await read.run(
    POLICY_QUERY,
    { ...params, policyPairs: pairs, policyRowLimit: neo4j.int(plan.probes.length * 3 + 1) },
    item => {
      if (rows.length >= plan.probes.length * 3) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
      const raw = Object.fromEntries(POLICY_COLUMNS.map(column => [column, converted(item.get(column))]));
      const safe = safePolicyRow(raw);
      readBytes += Buffer.byteLength(JSON.stringify(safe), 'utf8');
      if (readBytes > 4 * 1024 * 1024) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
      if (chargeRows) read.charge(safe);
      rows.push(safe);
    },
  );
  // Sort only the bounded materialized rows. A server ORDER BY would
  // expand malformed relationship fan-out before applying its LIMIT.
  return sortedBySerialization(rows);
}

/**
 * Reads every piece of evidence a second time, after the publication recheck: if a row, a
 * classification or an identity-scope record changed while the read ran, the read is refused.
 */
export async function verifyEvidence(read: StoreRead): Promise<void> {
  for (const checked of read.policyChecks) {
    const rows = await readPolicyRows(read, checked.plan, checked.params, false);
    if (JSON.stringify(rows) !== JSON.stringify(checked.rows)) throw new MapQueryError('MAP_UNAVAILABLE');
    const refreshed = policyEvidence(checked.plan, rows, read.now(), checked.maximumAge);
    if (JSON.stringify(refreshed) !== JSON.stringify(checked.projection.policyEvidence ?? []))
      throw new MapQueryError('MAP_UNAVAILABLE');
    const scopeRows = await readScopeRows(read, checked.scopePlan, checked.params, false);
    if (JSON.stringify(scopeRows) !== JSON.stringify(checked.scopeRows)) throw new MapQueryError('MAP_UNAVAILABLE');
    const scoped = boundedRecords(
      identityScopeEvidence(checked.scopePlan, scopeRows, read.now(), checked.maximumAge, checked.readable),
      checked.scopeBudget,
    );
    if (
      JSON.stringify(scoped) !==
      JSON.stringify(checked.projection.identityScope ?? checked.projection.identityReach ?? [])
    )
      throw new MapQueryError('MAP_UNAVAILABLE');
  }
}
