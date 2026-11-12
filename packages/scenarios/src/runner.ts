import { isGuardError } from '@shieldaai/agent-guard';
import { SCENARIO_CATALOG_VERSION, scenarioCatalog, type ScenarioId } from './catalog.js';
import { accessCases } from './cases/access.js';
import { approvalCases } from './cases/approval.js';
import { budgetCases } from './cases/budgets.js';
import { delegationCases } from './cases/delegation.js';
import { egressCases } from './cases/egress.js';
import { toolIntegrityCases } from './cases/tool-integrity.js';
import { bounded, CheckFailure, Checks, safeCode, type Pair } from './fixtures.js';
import type { ConformanceCaseResult, ConformanceOptions, ConformanceReport } from './types.js';

/** Every catalog scenario, as a malicious and a benign case. The type requires all thirteen. */
const cases: Record<ScenarioId, Pair> = {
  S01: accessCases.S01,
  S02: delegationCases.S02,
  S03: accessCases.S03,
  S04: egressCases.S04,
  S05: approvalCases.S05,
  S06: toolIntegrityCases.S06,
  S07: egressCases.S07,
  S08: delegationCases.S08,
  S09: accessCases.S09,
  S10: budgetCases.S10,
  S11: toolIntegrityCases.S11,
  S12: approvalCases.S12,
  S13: egressCases.S13,
};

/**
 * Run the catalog fixtures against AgentGuard or the supplied adapter.
 * The default implementation uses in-memory effects only. A custom adapter is
 * responsible for its own I/O; the runner cannot isolate or cancel it.
 */
export async function runConformance(options: ConformanceOptions = {}): Promise<ConformanceReport> {
  const caseTimeoutMs = options.caseTimeoutMs === undefined ? 5000 : options.caseTimeoutMs;
  if (!Number.isSafeInteger(caseTimeoutMs) || caseTimeoutMs < 1 || caseTimeoutMs > 2_147_483_647) {
    throw new TypeError('caseTimeoutMs must be an integer from 1 through 2147483647');
  }
  const selected = options.scenarioIds ?? scenarioCatalog.map(scenario => scenario.id);
  if (
    selected.length === 0 ||
    new Set(selected).size !== selected.length ||
    selected.some(id => !Object.hasOwn(cases, id))
  ) {
    throw new TypeError('scenarioIds must be a nonempty list of distinct catalog identifiers');
  }
  const results: ConformanceCaseResult[] = [];
  for (const scenarioId of selected) {
    for (const variant of ['malicious', 'benign'] as const) {
      const checks = new Checks(options.createGuard);
      let failure: string | undefined;
      try {
        await bounded(cases[scenarioId][variant](checks), 'case exceeded its asynchronous timeout', caseTimeoutMs);
      } catch (error) {
        failure =
          error instanceof CheckFailure
            ? error.message
            : isGuardError(error)
              ? `Unexpected guard rejection (${safeCode(error)}).`
              : 'Unexpected fixture failure; raw error details omitted.';
      }
      results.push(
        Object.freeze({
          scenarioId,
          variant,
          passed: failure === undefined,
          assertions: checks.assertions,
          handlerInvocations: checks.handlerInvocations,
          denialCodes: Object.freeze([...checks.denialCodes]),
          ...(failure === undefined ? {} : { failure }),
        }),
      );
    }
  }
  const passedCases = results.filter(result => result.passed).length;
  return Object.freeze({
    catalogVersion: SCENARIO_CATALOG_VERSION,
    passed: passedCases === results.length,
    scenarioCount: selected.length,
    caseCount: results.length,
    passedCases,
    failedCases: results.length - passedCases,
    results: Object.freeze(results),
  });
}
