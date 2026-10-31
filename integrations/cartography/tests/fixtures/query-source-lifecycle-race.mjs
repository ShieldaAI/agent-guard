// Exercise the real reader against an atomic, concurrent source retirement.
// The writer is restricted to the marked disposable database and exact fixture IDs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import neo4j from 'neo4j-driver';
import { Neo4jMapStore } from '../../../../packages/agent-map/dist/store.js';

const configuration = JSON.parse(readFileSync(process.env.AGENT_GUARD_TEST_NEO4J_CONFIG, 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(configuration.uri).hostname, '127.0.0.1');
assert.match(configuration.runId, /^[a-f0-9]{32}$/);
assert.equal(input.request.sourceId, input.predecessorSourceId);
assert.equal(input.request.history, true);
for (const key of ['predecessorSourceId', 'successorSourceId', 'currentId', 'previousId', 'successorCurrentId', 'transitionId']) {
  assert.match(input[key], /^[a-f0-9]{64}$/);
}
assert.ok(Number.isSafeInteger(input.supersededAtMs) && input.supersededAtMs >= 0);

const driver = neo4j.driver(configuration.uri, neo4j.auth.basic(configuration.username, configuration.password), {
  connectionTimeout: 5000, connectionAcquisitionTimeout: 5000, maxTransactionRetryTime: 0,
  maxConnectionPoolSize: 3,
});
const sourceReads = [], projectionsRead = new Set();
let mutationCount = 0, nodeRowsRead = 0;
const wrapped = {
  session(options) {
    const session = driver.session(options);
    return {
      beginTransaction(options) {
        const tx = session.beginTransaction(options);
        return {
          async *run(query, parameters) {
            const sourceQuery = query.startsWith('MATCH (s:GuardSource)');
            const nodeQuery = query.includes("RETURN 'Guard");
            const rows = [];
            for await (const record of tx.run(query, parameters)) {
              if (sourceQuery) rows.push(['id', 'currentId', 'previousId'].map(key => record.get(key)));
              if (nodeQuery) { nodeRowsRead++; projectionsRead.add(parameters.projectionId); }
              yield record;
            }
            if (!sourceQuery) return;
            sourceReads.push(rows);
            if (sourceReads.length !== 1) return;
            assert.deepEqual(rows, [[input.predecessorSourceId, input.currentId, input.previousId]]);
            // Barrier: every initial selection row has been consumed, but no
            // projection query or final source validation has started. There
            // are no timer sleeps or changes to the production reader.
            const write = driver.session({ database: 'neo4j', defaultAccessMode: neo4j.session.WRITE });
            try {
              const result = await write.run(`MATCH (old:GuardSource {id:$predecessorSourceId}),
                (next:GuardSource {id:$successorSourceId})
                WHERE old.company_id=$companyId AND next.company_id=old.company_id
                  AND old.tenant_id IN $tenantIds AND next.tenant_id=old.tenant_id
                  AND next.native_source_id=old.native_source_id AND next.profile=old.profile
                  AND old.current_snapshot_id=$currentId AND old.previous_snapshot_id=$previousId
                  AND next.current_snapshot_id=$successorCurrentId
                  AND coalesce(old.lifecycle_status,'active')='active'
                  AND coalesce(next.lifecycle_status,'active')='active'
                SET old.lifecycle_status='superseded',old.superseded_by=next.id,
                  old.lifecycle_operation_id=$transitionId,old.superseded_at_ms=$supersededAtMs,
                  old.superseded_current_snapshot_id=old.current_snapshot_id,
                  old.superseded_previous_snapshot_id=old.previous_snapshot_id
                REMOVE old.current_snapshot_id,old.previous_snapshot_id
                RETURN old.id AS id`, {
                ...input, companyId: input.scope.companyId, tenantIds: input.scope.tenantIds,
                supersededAtMs: neo4j.int(input.supersededAtMs),
              });
              mutationCount = result.records.length;
              assert.equal(mutationCount, 1);
              assert.equal(result.records[0].get('id'), input.predecessorSourceId);
            } finally { await write.close(); }
          },
          isOpen: () => tx.isOpen(),
          rollback: () => tx.rollback(),
        };
      },
      close: () => session.close(),
    };
  },
  close: () => driver.close(),
};
const store = new Neo4jMapStore(wrapped);
try {
  const guard = driver.session({ database: 'neo4j', defaultAccessMode: neo4j.session.READ });
  try {
    const marker = await guard.run('MATCH (r:GuardDisposableTestRun {id:$runId}) RETURN count(r) AS count', { runId: configuration.runId });
    assert.equal(marker.records[0].get('count').toNumber(), 1);
  } finally { await guard.close(); }
  let result;
  try { result = { ok: true, view: await store.read(input.scope, input.request) }; }
  catch (error) {
    if (error?.code !== 'MAP_UNAVAILABLE') throw error;
    result = { ok: false, code: error.code };
  }
  assert.equal(mutationCount, 1);
  assert.ok(nodeRowsRead > 0);
  assert.deepEqual([...projectionsRead].sort(), [input.currentId, input.previousId].sort());
  assert.deepEqual(sourceReads, [[[input.predecessorSourceId, input.currentId, input.previousId]], []]);
  process.stdout.write(JSON.stringify({ result, mutationCount, sourceReads: sourceReads.length,
    retainedProjectionsRead: projectionsRead.size, sourceSelectionChanged: true }));
} finally { await store.close(); }
