import assert from 'node:assert/strict';
import test from 'node:test';
import * as scenarios from '../dist/index.js';

test('the package exports exactly the catalog and the runner', () => {
  assert.deepEqual(Object.keys(scenarios).sort(), ['SCENARIO_CATALOG_VERSION', 'runConformance', 'scenarioCatalog']);
  assert.equal(scenarios.runConformance.length, 0, 'runConformance(options = {})');
});

test('catalog 1.3.0 runs the same checks in every case: assertions, handler calls and denials', async () => {
  // Scenario, variant, assertions made, handlers invoked, denials observed. A change to any
  // case changes what a pass means, so it needs a new catalog version and a new table.
  const expected = [
    ['S01', 'malicious', 19, 0, 3],
    ['S01', 'benign', 2, 1, 0],
    ['S02', 'malicious', 48, 0, 8],
    ['S02', 'benign', 3, 1, 0],
    ['S03', 'malicious', 19, 0, 3],
    ['S03', 'benign', 2, 1, 0],
    ['S04', 'malicious', 26, 1, 4],
    ['S04', 'benign', 2, 1, 0],
    ['S05', 'malicious', 23, 1, 3],
    ['S05', 'benign', 2, 1, 0],
    ['S06', 'malicious', 24, 0, 4],
    ['S06', 'benign', 3, 2, 0],
    ['S07', 'malicious', 19, 0, 3],
    ['S07', 'benign', 2, 1, 0],
    ['S08', 'malicious', 38, 0, 6],
    ['S08', 'benign', 2, 1, 0],
    ['S09', 'malicious', 25, 0, 4],
    ['S09', 'benign', 2, 1, 0],
    ['S10', 'malicious', 91, 5, 14],
    ['S10', 'benign', 9, 8, 0],
    ['S11', 'malicious', 44, 0, 7],
    ['S11', 'benign', 5, 1, 0],
    ['S12', 'malicious', 23, 1, 4],
    ['S12', 'benign', 4, 2, 0],
    ['S13', 'malicious', 20, 1, 3],
    ['S13', 'benign', 2, 2, 0],
  ];
  assert.equal(scenarios.SCENARIO_CATALOG_VERSION, '1.3.0', 'update the table together with the catalog version');
  const report = await scenarios.runConformance();
  assert.deepEqual(
    report.results.map(result => [
      result.scenarioId,
      result.variant,
      result.assertions,
      result.handlerInvocations,
      result.denialCodes.length,
    ]),
    expected,
  );
  assert.equal(report.passed, true);
});
