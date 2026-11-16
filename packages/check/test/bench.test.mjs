import test from 'node:test';
import assert from 'node:assert/strict';
import { RULES } from '@shieldaai/agent-guard-check';
import { CASES } from '../bench/cases.mjs';
import { scoreCases } from '../bench/score.mjs';

// Ship gate: every rule has labeled cases on both sides, and none is missed or wrongly flagged.
test('every rule has at least one case it must flag and one look-alike it must not', () => {
  for (const rule of RULES) {
    const cases = CASES.filter(item => item.rule === rule.id);
    assert.ok(
      cases.some(item => item.expect),
      `${rule.id} has no positive case`,
    );
    assert.ok(
      cases.some(item => !item.expect),
      `${rule.id} has no negative case`,
    );
  }
  for (const item of CASES)
    assert.ok(
      RULES.some(rule => rule.id === item.rule),
      `${item.id} names an unknown rule`,
    );
  assert.equal(new Set(CASES.map(item => item.id)).size, CASES.length, 'case IDs are unique');
});

test('the labeled benchmark has full precision and recall', () => {
  const score = scoreCases(CASES);
  assert.deepEqual(score.misses, []);
  assert.equal(score.precision, 1);
  assert.equal(score.recall, 1);
});
