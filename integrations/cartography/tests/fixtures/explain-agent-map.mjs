// Records the exact Cypher the Map store runs for one read, then asks Neo4j to EXPLAIN each
// query with the same parameters. Output: the operator names of every plan. No credentials
// or graph values are printed.
import { readFileSync } from 'node:fs';
import neo4j from 'neo4j-driver';
import { Neo4jMapStore } from '../../../../packages/agent-map/dist/store.js';

const configuration = JSON.parse(readFileSync(process.env.AGENT_GUARD_TEST_NEO4J_CONFIG, 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));
const driver = neo4j.driver(configuration.uri, neo4j.auth.basic(configuration.username, configuration.password));
const recorded = [];
// A recording proxy around the real driver: the store's queries run unchanged.
const recording = {
  session(config) {
    const session = driver.session(config);
    return {
      beginTransaction(options) {
        const transaction = session.beginTransaction(options);
        return {
          run(query, parameters) {
            recorded.push({ query, parameters });
            return transaction.run(query, parameters);
          },
          isOpen: () => transaction.isOpen(),
          rollback: () => transaction.rollback(),
        };
      },
      close: () => session.close(),
    };
  },
  close: async () => {},
};
const operators = plan => [plan.operatorType, ...(plan.children ?? []).flatMap(operators)];
try {
  const store = new Neo4jMapStore(recording, { clock: () => input.now });
  const view = await store.read(input.scope, input.request ?? {});
  const plans = [];
  const session = driver.session({ defaultAccessMode: neo4j.session.READ });
  try {
    for (const { query, parameters } of recorded) {
      const summary = (await session.run(`EXPLAIN ${query}`, parameters)).summary;
      plans.push({
        head: query.split('\n')[0].slice(0, 120),
        kind: query.includes('$scopePairs')
          ? 'identity_scope'
          : query.includes('$ancestorTaskIds')
            ? 'ancestor_tasks'
            : query.includes('$wildcardTools')
            ? 'wildcard'
            : query.includes('G_DELEGATED_FROM|G_DERIVED_FROM*1..16')
              ? 'ancestors'
          : query.includes('$policyPairs')
            ? 'policy'
            : (/RETURN '(\w+)' AS label/.exec(query)?.[1] ?? 'other'),
        operators: operators(summary.plan).map(name => name.replace(/@.*$/, '')),
      });
    }
  } finally {
    await session.close();
  }
  process.stdout.write(JSON.stringify({ ok: true, sources: view.sources.length, plans }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, code: error.code ?? 'MAP_UNAVAILABLE' }));
} finally {
  await driver.close();
}
