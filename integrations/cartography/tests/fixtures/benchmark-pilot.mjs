// Exercise the actual scoped HTTP service against the runner-owned disposable DB.
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { createNeo4jMapStore, MapService, createMapToken, startMapServer } from '../../../../packages/agent-map/dist/index.js';

const config = JSON.parse(readFileSync(process.env.AGENT_GUARD_TEST_NEO4J_CONFIG, 'utf8'));
const input = JSON.parse(readFileSync(0, 'utf8'));
const store = createNeo4jMapStore({ uri: config.uri, username: config.username, password: config.password });
const token = createMapToken();
const server = await startMapServer({ service: new MapService(store), credentials: [{ token, scope: input.scope }],
  rateLimit: { maxRequests: 1000, windowMs: 60_000 } });
const samples = [];
try {
  for (let number = 0; number < input.samples; number++) {
    const source = input.sources[number % input.sources.length];
    const operation = number % 2 ? 'explain_access' : 'get_agent_access';
    const args = operation === 'get_agent_access' ? { sourceId: source, agentId: 'agent-0' }
      : { sourceId: source, taskId: 'task-0-0', tool: 'records.read-0', resourceId: 'record-0' };
    const started = performance.now();
    let ok = false, code = 'MAP_BENCHMARK_FAILED', bytes = 0;
    try {
      const response = await fetch(server.url + '/v1/query', { method: 'POST', redirect: 'error',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation, args }), signal: AbortSignal.timeout(12_000) });
      const text = await response.text(); bytes = Buffer.byteLength(text);
      const result = JSON.parse(text);
      ok = response.status === 200 && result.operation === operation && result.data?.assessment === 'unknown';
      if (operation === 'get_agent_access') ok &&= result.data?.agent?.agentId === 'agent-0' && result.graph.nodes.length > 0;
      if (operation === 'explain_access') ok &&= result.data?.taskId === 'task-0-0' && result.data?.matchedGrants?.length > 0;
      code = ok ? null : /^MAP_[A-Z_]+$/.test(result.error) ? result.error : 'MAP_BENCHMARK_FAILED';
    } catch { code = 'MAP_BENCHMARK_FAILED'; }
    samples.push({ operation, seconds: (performance.now() - started) / 1000, ok, code, bytes, cold: number === 0 });
    // Any failed request invalidates the gate; do not repeat a broken query.
    if (!ok) break;
  }
  process.stdout.write(JSON.stringify({ nodeVersion: process.version, samples,
    limits: { sources: 64, storeNodes: 2000, storeEdges: 5000, storeBytes: 4194304, graphNodes: 500,
      graphEdges: 1000, responseBytes: 1048576, queryTimeoutMs: 5000, httpTimeoutMs: 10000 },
    concurrency: 1, warmupSamples: 0 }));
} finally { await server.close(); await store.close(); }
