import test from 'node:test';
import assert from 'node:assert/strict';
import { runBenchmark } from './benchmark-agent-map.mjs';

test('every map operation answers for 200 agents across 20 sources', { timeout: 60_000 }, async () => {
  const { agents, results } = await runBenchmark(10, 20, 3);
  assert.equal(agents, 200);
  for (const [operation, result] of Object.entries(results))
    assert.equal(result.ok, true, `${operation}: ${result.code}`);
});

test('fleet-wide impact queries stay within the work budget at 1,000 agents', { timeout: 60_000 }, async () => {
  const { results } = await runBenchmark(50, 20, 5);
  for (const operation of [
    'find_agents_with_access',
    'get_changes',
    'get_resource_access',
    'list_resources',
    'list_agents_flags',
  ]) {
    assert.equal(results[operation].ok, true, `${operation}: ${results[operation].code}`);
  }
});
