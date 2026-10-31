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
  return Object.entries(value).some(([key, item]) => secrets.some(secret => key.includes(secret)) || containsLiteralSecret(item, secrets));
}

/** The mandatory gates shared by embedded and durable executors; never an authentication API. */
export function assertActionAuthority(action: Readonly<Action>, ancestors: readonly AuthorityState[], options: {
  now: number; maxCost: number; controlPlane: boolean; sensitive: boolean; secretValues: readonly string[];
}): void {
  const deny = (code: ConstructorParameters<typeof GuardError>[0]): never => { throw new GuardError(code); };
  if (!ancestors.length || !Number.isFinite(options.now) || options.now < 0) deny('INVALID_INPUT');
  if (action.tenantId !== ancestors[0]!.identity.tenantId) deny('TENANT_DENIED');
  for (const ancestor of ancestors) {
    if (ancestor.revoked) deny('TASK_REVOKED');
    if (options.now >= ancestor.budget.deadline) deny('TASK_EXPIRED');
    if (!ancestor.grants.some(grant => grant.tool === action.tool &&
      (grant.resources.includes(action.resourceId) || grant.resources.includes('*')))) deny('GRANT_DENIED');
    if (options.controlPlane && !ancestor.allowControlPlane) deny('CONTROL_PLANE_DENIED');
    if (action.external && (!action.recipient || !ancestor.allowedRecipients.includes(action.recipient))) deny('RECIPIENT_DENIED');
    if (ancestor.snapshot.calls >= ancestor.budget.maxCalls) deny('CALL_BUDGET_EXCEEDED');
    if (ancestor.snapshot.concurrent >= ancestor.budget.maxConcurrent) deny('CONCURRENCY_EXCEEDED');
    if (options.maxCost > ancestor.budget.maxCost - ancestor.snapshot.spent - ancestor.snapshot.reserved) deny('COST_BUDGET_EXCEEDED');
  }
  if (action.external) {
    if (options.sensitive || action.sensitive) deny('SENSITIVE_EGRESS_DENIED');
    if (containsLiteralSecret(action.args, options.secretValues)) deny('SECRET_EGRESS_DENIED');
  }
}
