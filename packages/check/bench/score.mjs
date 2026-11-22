// Scores the labeled cases: per rule, true and false positives and negatives.
import { MemorySource, parseConfig, scan } from '@shieldaai/agent-guard-check';

/** Runs one case and says whether its rule fired. */
export function fires(item) {
  const result = scan({
    root: '/bench',
    source: new MemorySource(item.files ?? {}),
    ...(item.config ? { config: parseConfig(item.config) } : {}),
    ...(item.live ? { live: item.live } : {}),
    ...(item.github ? { github: item.github } : {}),
    ...(item.now ? { now: Date.parse(item.now) } : {}),
  });
  if (result.errors.length) throw new Error(`${item.id}: ${result.errors.map(error => error.message).join('; ')}`);
  return result.findings.some(finding => finding.ruleId === item.rule);
}

export function scoreCases(cases) {
  const byRule = new Map();
  const misses = [];
  for (const item of cases) {
    const row = byRule.get(item.rule) ?? { rule: item.rule, tp: 0, fp: 0, fn: 0, tn: 0 };
    const fired = fires(item);
    if (item.expect && fired) row.tp += 1;
    else if (item.expect) {
      row.fn += 1;
      misses.push({ id: item.id, kind: 'missed' });
    } else if (fired) {
      row.fp += 1;
      misses.push({ id: item.id, kind: 'false positive' });
    } else row.tn += 1;
    byRule.set(item.rule, row);
  }
  const rows = [...byRule.values()].sort((a, b) => a.rule.localeCompare(b.rule));
  const total = rows.reduce(
    (sum, row) => ({ tp: sum.tp + row.tp, fp: sum.fp + row.fp, fn: sum.fn + row.fn, tn: sum.tn + row.tn }),
    {
      tp: 0,
      fp: 0,
      fn: 0,
      tn: 0,
    },
  );
  const ratio = (a, b) => (a + b === 0 ? 1 : a / (a + b));
  return {
    rows,
    misses,
    precision: ratio(total.tp, total.fp),
    recall: ratio(total.tp, total.fn),
    total,
  };
}
