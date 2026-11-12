import { identityScopeEvidence, identityScopePlan, type IdentityScopePlan } from '../policy-reader.js';
import { MapQueryError, type JsonObject, type MapSource } from '../types.js';
import { readScopeRows } from './evidence.js';
import { boundBuckets, boundedRecords, SCOPE_HEADROOM_BYTES, SCOPE_RECORD_BYTES } from './nodes.js';
import { StoreRead } from './read.js';

/**
 * Identity scope, once each projection holds its ancestors. A one-agent read lists every bucket
 * per identity; an outside-guard read (list_resources, get_resource_access) asks only about the
 * buckets visible bindings map to. It is optional evidence throughout: whatever cannot be
 * planned, read or fitted is left out, and the read answers without it.
 */
export async function loadIdentityScope(read: StoreRead, sources: MapSource[]): Promise<void> {
  const { scope } = read;
  for (const job of read.scopeJobs) {
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
            Math.max(0, 8 - read.scopePairCount),
            null,
            Date.parse(current.generatedAt),
          )
        : buckets.length
          ? identityScopePlan(
              scope.companyId,
              sources[index]!.tenantId,
              current.nodes,
              current.edges,
              Math.max(0, 32 - read.scopePairCount),
              buckets,
              Date.parse(current.generatedAt),
            )
          : identityScopePlan(scope.companyId, sources[index]!.tenantId, [], [], 0);
    } catch (error) {
      if (!(error instanceof MapQueryError) || error.code !== 'MAP_LIMIT_EXCEEDED') throw error;
      continue;
    }
    read.scopePairCount += scopePlan.probes.length;
    // Scope rows have their own byte bound in readScope; only the bounded records count
    // toward the view, so a broad role cannot crowd out the rest. A scope-only read with
    // an unreadable age bound, or a malformed row fan-out, also goes on without it.
    let scopeRows: JsonObject[];
    try {
      if (scopePlan.probes.length && !job.check.plan.probes.length)
        job.check.maximumAge = read.maximumAgeFor(job.enrolled);
      scopeRows = await readScopeRows(read, scopePlan, job.check.params, false);
    } catch (error) {
      if (
        !(error instanceof MapQueryError) ||
        !['MAP_LIMIT_EXCEEDED', 'MAP_UNAVAILABLE'].includes(error.code) ||
        !read.transactionOpen()
      )
        throw error;
      continue;
    }
    // The lists are optional detail: they get what is left of the read's byte budget,
    // less headroom for the final copy. If even the bare records do not fit, the read
    // answers without identity scope.
    const scopeBudget = Math.max(
      0,
      Math.min(SCOPE_RECORD_BYTES, read.limits.bytes - SCOPE_HEADROOM_BYTES - read.materializedBytes),
    );
    const identityScope = boundedRecords(
      identityScopeEvidence(scopePlan, scopeRows, read.now(), job.check.maximumAge, job.check.readable),
      scopeBudget,
    );
    if (Buffer.byteLength(JSON.stringify(identityScope), 'utf8') > scopeBudget) continue;
    for (const item of identityScope) read.charge(item);
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
}
