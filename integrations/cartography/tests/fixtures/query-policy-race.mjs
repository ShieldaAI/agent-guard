// Only the owned disposable database is writable. Production reader code is unchanged.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import neo4j from 'neo4j-driver';
import { Neo4jMapStore } from '../../../../packages/agent-map/dist/store.js';
import { POLICY_QUERY } from '../../../../packages/agent-map/dist/policy-reader.js';

const configuration = JSON.parse(readFileSync(process.env.AGENT_GUARD_TEST_NEO4J_CONFIG, 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(configuration.uri).hostname, '127.0.0.1');
assert.match(configuration.runId, /^[a-f0-9]{32}$/);
const mutations = {
  agent_team: `MATCH (agent:GuardAgent {id:$agentNodeId,source_id:$sourceId,projection_id:$projectionId})
    SET agent.team_id='race-hidden-team' RETURN count(agent) AS changed`,
  deployment_agent: `MATCH (deployment:GuardDeployment {id:$deploymentNodeId,source_id:$sourceId,projection_id:$projectionId})
    -[old:G_INSTANCE_OF]->(:GuardAgent {id:$agentNodeId})
    MATCH (other:GuardAgent {source_id:$sourceId,projection_id:$projectionId,agent_id:'hidden-agent-canary'})
    DELETE old CREATE (deployment)-[:G_INSTANCE_OF]->(other) RETURN count(deployment) AS changed`,
  execution_identity: `MATCH (execution:GuardExecutionBinding {id:$executionNodeId,source_id:$sourceId,projection_id:$projectionId})
    -[old:G_USES_IDENTITY]->(:GuardExternalIdentity {id:$identityNodeId})
    MATCH (:GuardExecutionBinding {source_id:$sourceId,projection_id:$projectionId,binding_id:'hidden-canary-execution'})
    -[:G_USES_IDENTITY]->(other:GuardExternalIdentity)
    DELETE old CREATE (execution)-[:G_USES_IDENTITY]->(other) RETURN count(execution) AS changed`,
  ...Object.fromEntries([
    ['duplicate_assignment', 'taskNodeId', 'G_ASSIGNED_TO', 'deploymentNodeId'],
    ['duplicate_agent', 'deploymentNodeId', 'G_INSTANCE_OF', 'agentNodeId'],
    ['duplicate_executor_deployment', 'executionNodeId', 'G_EXECUTES_FOR', 'deploymentNodeId'],
    ['duplicate_executor_tool', 'executionNodeId', 'G_EXECUTES_TOOL', 'toolNodeId'],
    ['duplicate_identity', 'executionNodeId', 'G_USES_IDENTITY', 'identityNodeId'],
    ['duplicate_grant_tool', 'grantNodeId', 'G_FOR_TOOL', 'toolNodeId'],
    ['duplicate_binding_selector', 'bindingNodeId', 'G_BINDS_SELECTOR', 'selectorNodeId'],
    ['duplicate_binding_resource', 'bindingNodeId', 'G_MAPS_TO', 'resourceNodeId'],
    ['duplicate_task_grant', 'taskNodeId', 'G_HAS_GRANT', 'grantNodeId'],
    ['duplicate_grant_selector', 'grantNodeId', 'G_TARGETS', 'selectorNodeId'],
  ].map(([name, from, kind, to]) => [name,
    `MATCH (origin {id:$${from},source_id:$sourceId,projection_id:$projectionId})
      -[:${kind}]->(target {id:$${to},source_id:$sourceId,projection_id:$projectionId})
     CREATE (origin)-[duplicate:${kind}]->(target) RETURN count(duplicate) AS changed`,
  ])),
};
assert.ok(Object.hasOwn(mutations, input.mutation));
const driver = neo4j.driver(configuration.uri, neo4j.auth.basic(configuration.username, configuration.password), {
  connectionTimeout: 5000, connectionAcquisitionTimeout: 5000, maxTransactionRetryTime: 0,
  maxConnectionPoolSize: 3,
});
const pointerReads = [], proofs = [];
let mutationCount = 0;
const wrapped = {
  session(options) {
    const session = driver.session(options);
    return {
      beginTransaction(options) {
        const tx = session.beginTransaction(options);
        return {
          async *run(query, parameters) {
            const policy = query === POLICY_QUERY;
            const source = query.startsWith('MATCH (s:GuardSource)');
            const rows = [];
            const policyProofs = [];
            for await (const record of tx.run(query, parameters)) {
              if (policy) policyProofs.push(record.get('bindingProof'));
              if (source) rows.push(['id', 'currentId', 'previousId', 'policyCoverage'].map(key => record.get(key)));
              yield record;
            }
            if (source) pointerReads.push(JSON.stringify(rows));
            if (policy) proofs.push(policyProofs);
            // This barrier is after every first-query row was consumed and before
            // the reader can issue either of its normal rechecks. No timing sleeps.
            if (policy && proofs.length === 1) {
              assert.deepEqual(policyProofs, [true]);
              assert.equal(parameters.policyPairs.length, 1);
              const write = driver.session({ database: 'neo4j', defaultAccessMode: neo4j.session.WRITE });
              try {
                const result = await write.run(mutations[input.mutation], {
                  ...parameters.policyPairs[0], sourceId: parameters.sourceId,
                  projectionId: parameters.projectionId,
                });
                assert.equal(result.records.length, 1);
                mutationCount = result.records[0].get('changed').toNumber();
                assert.equal(mutationCount, 1);
              } finally { await write.close(); }
            }
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
const store = new Neo4jMapStore(wrapped, { clock: () => input.now });
try {
  const guard = driver.session({ database: 'neo4j', defaultAccessMode: neo4j.session.READ });
  try {
    const marker = await guard.run('MATCH (r:GuardDisposableTestRun {id:$runId}) RETURN count(r) AS count', { runId: configuration.runId });
    assert.equal(marker.records[0].get('count').toNumber(), 1);
  } finally { await guard.close(); }
  let result;
  try { result = { ok: true, view: await store.read(input.scope, input.request) }; }
  catch (error) { result = { ok: false, code: error.code ?? 'MAP_UNAVAILABLE' }; }
  process.stdout.write(JSON.stringify({ result, mutationCount, proofs, sourceReads: pointerReads.length,
    sourcePointersUnchanged: pointerReads.length === 2 && pointerReads[0] === pointerReads[1] }));
} finally { await store.close(); }
