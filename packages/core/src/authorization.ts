import { GuardError } from './types.js';
import type { Action, Budget, Capability, Json, TaskIdentity, TaskSnapshot } from './types.js';

/** Trusted, validated authority state. Authentication and state ownership belong to the caller. */
export interface AuthorityState {
  identity: Readonly<TaskIdentity>;
  grants: readonly Capability[];
  allowedRecipients: readonly string[];
  allowControlPlane: boolean;
  budget: Readonly<Budget>;
  snapshot: Readonly<TaskSnapshot>;
  revoked: boolean;
}

export function containsLiteralSecret(value: Json, secrets: readonly string[]): boolean {
  if (typeof value === 'string') return secrets.some(secret => value.includes(secret));
  if (value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(item => containsLiteralSecret(item, secrets));
  return Object.entries(value).some(
    ([key, item]) => secrets.some(secret => key.includes(secret)) || containsLiteralSecret(item, secrets),
  );
}

/**
 * When the gates run.
 * - `dispatch` (default): immediately before a handler runs. Every gate applies, including
 *   transient capacity: concurrent calls and cost reserved by in-flight calls.
 * - `prepare`: preparation and human approval. Authority gates and permanent capacity apply
 *   (calls and spent cost only grow). Transient capacity is left to dispatch, so a call in flight
 *   does not refuse preparation or lose a reviewer's approval.
 */
export type AuthorityPhase = 'prepare' | 'dispatch';

/** The mandatory gates shared by embedded and durable executors; never an authentication API. */
export function assertActionAuthority(
  action: Readonly<Action>,
  ancestors: readonly AuthorityState[],
  options: {
    now: number;
    maxCost: number;
    controlPlane: boolean;
    sensitive: boolean;
    secretValues: readonly string[];
    phase?: AuthorityPhase;
    /** The task family has read outside content. */
    untrusted?: boolean;
    /** This tool's mode once the family is untrusted; `deny` refuses even with an approval. */
    untrustedContext?: 'allow' | 'require_approval' | 'deny';
  },
): void {
  const deny = (code: ConstructorParameters<typeof GuardError>[0]): never => {
    throw new GuardError(code);
  };
  if (!ancestors.length || !Number.isFinite(options.now) || options.now < 0) deny('INVALID_INPUT');
  const phase = options.phase ?? 'dispatch';
  if (phase !== 'prepare' && phase !== 'dispatch') deny('INVALID_INPUT');
  const dispatch = phase === 'dispatch';
  if (action.tenantId !== ancestors[0]!.identity.tenantId) deny('TENANT_DENIED');
  for (const ancestor of ancestors) {
    if (ancestor.revoked) deny('TASK_REVOKED');
    if (options.now >= ancestor.budget.deadline) deny('TASK_EXPIRED');
    if (
      !ancestor.grants.some(
        grant =>
          grant.tool === action.tool && (grant.resources.includes(action.resourceId) || grant.resources.includes('*')),
      )
    )
      deny('GRANT_DENIED');
    if (options.controlPlane && !ancestor.allowControlPlane) deny('CONTROL_PLANE_DENIED');
    if (action.external && (!action.recipient || !ancestor.allowedRecipients.includes(action.recipient)))
      deny('RECIPIENT_DENIED');
    if (ancestor.snapshot.calls >= ancestor.budget.maxCalls) deny('CALL_BUDGET_EXCEEDED');
    // Preparation treats transient usage as zero: a budget that can never admit the call
    // (for example maxConcurrent 0) is still refused, but in-flight calls are not counted.
    const concurrent = dispatch ? ancestor.snapshot.concurrent : 0;
    const reserved = dispatch ? ancestor.snapshot.reserved : 0;
    if (concurrent >= ancestor.budget.maxConcurrent) deny('CONCURRENCY_EXCEEDED');
    if (options.maxCost > ancestor.budget.maxCost - ancestor.snapshot.spent - reserved) deny('COST_BUDGET_EXCEEDED');
  }
  if (action.external) {
    if (options.sensitive || action.sensitive) deny('SENSITIVE_EGRESS_DENIED');
    if (containsLiteralSecret(action.args, options.secretValues)) deny('SECRET_EGRESS_DENIED');
  }
  // require_approval is enforced by the caller's approval check; deny cannot be approved.
  if (options.untrusted && options.untrustedContext === 'deny') deny('UNTRUSTED_CONTEXT_DENIED');
}
