import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentGuard } from '@shieldaai/agent-guard';
import { SCENARIO_CATALOG_VERSION, scenarioCatalog, runConformance } from '../dist/index.js';

test('catalog contains ten immutable, explicitly scoped protection scenarios', () => {
  assert.match(SCENARIO_CATALOG_VERSION, /^\d+\.\d+\.\d+$/);
  assert.deepEqual(scenarioCatalog.map(({ id }) => id), Array.from({ length: 10 }, (_, i) => `S${String(i + 1).padStart(2, '0')}`));
  assert.ok(Object.isFrozen(scenarioCatalog));
  for (const scenario of scenarioCatalog) {
    assert.ok(Object.isFrozen(scenario));
    assert.ok(Object.isFrozen(scenario.malicious));
    assert.ok(Object.isFrozen(scenario.limitations));
    assert.ok(scenario.boundary && scenario.benign && scenario.malicious.length && scenario.limitations.length);
  }
});

test('all ten protection scenarios deny hostile effects and allow their benign pair', { timeout: 15000 }, async () => {
  const report = await runConformance();
  assert.equal(report.catalogVersion, SCENARIO_CATALOG_VERSION);
  assert.equal(report.scenarioCount, 10);
  assert.equal(report.caseCount, 20);
  assert.equal(report.passed, true, JSON.stringify(report.results.filter(({ passed }) => !passed), null, 2));
  assert.equal(report.passedCases, 20);
  assert.equal(report.failedCases, 0);
  assert.ok(report.results.every(({ assertions }) => assertions > 0));
  assert.ok(Object.isFrozen(report) && Object.isFrozen(report.results));
  assert.equal(JSON.stringify(report).includes('fixture-secret-9c1e'), false);
  assert.equal(JSON.stringify(report).includes('fixture-canary-7f2b'), false);
});

test('selected scenarios still run both paired variants', async () => {
  const report = await runConformance({ scenarioIds: ['S07'] });
  assert.equal(report.passed, true);
  assert.equal(report.scenarioCount, 1);
  assert.equal(report.caseCount, 2);
  assert.deepEqual(report.results.map(({ scenarioId, variant }) => [scenarioId, variant]), [['S07', 'malicious'], ['S07', 'benign']]);
});

test('empty, duplicated and unknown selections cannot create a vacuous pass', async () => {
  await assert.rejects(runConformance({ scenarioIds: [] }), TypeError);
  await assert.rejects(runConformance({ scenarioIds: ['S01', 'S01'] }), TypeError);
  await assert.rejects(runConformance({ scenarioIds: ['S99'] }), TypeError);
});

test('a compatible adapter factory receives isolated fixtures and cannot pass by denying everything', async () => {
  let instances = 0;
  const report = await runConformance({
    scenarioIds: ['S01'],
    createGuard(options) {
      instances += 1;
      return new AgentGuard({ ...options, policy: () => 'deny' });
    },
  });
  assert.equal(instances, 2);
  assert.equal(report.passed, false);
  assert.equal(report.passedCases, 1);
  assert.equal(report.failedCases, 1);
  assert.equal(report.results[0].passed, true);
  assert.equal(report.results[1].passed, false);
  assert.equal(report.results[1].failure, 'Unexpected guard rejection (POLICY_DENIED).');
});
