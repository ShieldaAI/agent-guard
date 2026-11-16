import type { Finding, RuleMeta } from '../types.js';
import type { Project } from '../model.js';
import { fingerprint, type Report, type Rule, type RuleContext } from './common.js';
import { AGENT_GUARD_RULES } from './agent-guard.js';
import { AGENT_MAP_RULES } from './agent-map.js';
import { DEFAULT_CONFIG } from '../config.js';
import { PERMISSIONS_RULES } from './permissions.js';
import { TRIFECTA_RULES } from './trifecta.js';
import { SUPPLY_CHAIN_RULES } from './supply-chain.js';
import { PERSISTENCE_RULES } from './persistence.js';
import { SECRETS_RULES } from './secrets.js';
import { INSTRUCTIONS_RULES } from './instructions.js';
import { WORKFLOWS_RULES } from './workflows.js';
import { GOVERNANCE_RULES } from './governance.js';

export { fingerprint } from './common.js';
export type { Rule, RuleContext } from './common.js';

/** Every rule, in report order. IDs are never reused once retired. */
export const RULES: readonly Rule[] = Object.freeze([
  ...PERMISSIONS_RULES,
  ...TRIFECTA_RULES,
  ...SUPPLY_CHAIN_RULES,
  ...PERSISTENCE_RULES,
  ...SECRETS_RULES,
  ...INSTRUCTIONS_RULES,
  ...WORKFLOWS_RULES,
  ...GOVERNANCE_RULES,
  ...AGENT_GUARD_RULES,
  ...AGENT_MAP_RULES,
]);

export const RULES_BY_ID: Readonly<Record<string, RuleMeta>> = Object.freeze(
  Object.fromEntries(
    RULES.map(({ id, title, severity, confidence, owasp, help }) => [
      id,
      Object.freeze({ id, title, severity, confidence, owasp, help }),
    ]),
  ),
);

/**
 * Runs every rule. Duplicate findings (same fingerprint) are reported once. A rule that fails on
 * unexpected input is reported as an error and the other rules still run.
 */
export function runRules(
  project: Project,
  errors: { file: string; message: string }[] = [],
  context: RuleContext = { config: DEFAULT_CONFIG },
): Finding[] {
  const findings = new Map<string, Finding>();
  for (const item of RULES) {
    const report: Report = input => {
      const agentId = input.agent?.id ?? '';
      const key = fingerprint(item.id, agentId, input.location.file, input.subject);
      if (findings.has(key)) return;
      findings.set(key, {
        ruleId: item.id,
        severity: input.severity ?? item.severity,
        confidence: input.confidence ?? item.confidence,
        message: input.message,
        location: input.location,
        ...(input.agent ? { agentId } : {}),
        fingerprint: key,
        ...(input.fix ? { fix: input.fix } : {}),
      });
    };
    try {
      item.check(project, report, context);
    } catch (error) {
      errors.push({
        file: '',
        message: `${item.id} could not run: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  return [...findings.values()];
}
