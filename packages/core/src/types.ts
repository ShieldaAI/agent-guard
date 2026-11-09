import type { JsonValue } from './json.js';

/** JSON accepted by the guard. Every invocation is copied and deeply frozen at runtime. */
export type Json = JsonValue;
export interface Capability { tool: string; resources: readonly string[] }
/** Costs use nonnegative safe integers in units chosen by the host, such as microcurrency units. */
export interface Budget { maxCalls: number; maxConcurrent: number; maxCost: number; deadline: number }
export interface TaskOptions {
  id: string; principalId: string; tenantId: string;
  grants: readonly Capability[]; budget: Budget;
  allowedRecipients?: readonly string[];
  allowControlPlane?: boolean;
}
export interface TaskIdentity { id: string; principalId: string; tenantId: string }
export interface TaskHandle { readonly id: string }
export interface ResolvedAction {
  resourceId: string; tenantId: string;
  external?: boolean; recipient?: string; sensitive?: boolean;
  /** Version bound into approval; the handler must enforce it at the actual resource. */
  resourceVersion?: string;
}
export interface ToolDefinition {
  name: string; description: string; inputSchema?: Json; metadata?: Json;
  requiresApproval?: boolean; controlPlane?: boolean;
  /** Maximum cost reserved before dispatch, as a nonnegative safe integer. Defaults to zero. */
  maxCost?: number;
  /** Trusted synchronous schema parser. Its normalized result is frozen before resolution. */
  parse?(input: Json): Json;
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction;
  execute(args: Json, context: {
    signal: AbortSignal; action: Readonly<Action>; task: Readonly<TaskIdentity>;
  }): Promise<ToolResult> | ToolResult;
}
/** actualCost must be a safe integer between zero and the tool's maxCost, inclusive. */
export interface ToolResult { value: Json; actualCost?: number }
export interface Action extends ResolvedAction {
  tool: string; args: Json; toolFingerprint: string; policyVersion: number;
}
export interface TaskSnapshot extends TaskIdentity {
  sensitive: boolean; calls: number; concurrent: number; spent: number; reserved: number;
}
/** `snapshot()` view for hosts: the policy snapshot plus the budget and revocation state. */
export interface TaskStatus extends TaskSnapshot {
  /** The task's own budget; `deadline` is in clock milliseconds. */
  budget: Readonly<Budget>;
  /** True when this task or any ancestor is revoked. */
  revoked: boolean;
}
export type PolicyDecision = 'allow' | 'deny' | 'require_approval';
export type Policy = (action: Readonly<Action>, task: Readonly<TaskSnapshot>,
  context?: Readonly<{ signal: AbortSignal }>) => PolicyDecision | Promise<PolicyDecision>;
export interface GuardOptions {
  policy?: Policy; secretValues?: readonly string[]; clock?: () => number;
  /**
   * How many times a custom policy may be evaluated for one prepare or execute when the task's
   * counters or shared sensitivity change while it runs (for example, a parallel call on the same
   * task starts or settles). Each attempt uses a fresh snapshot and a policy slot; the final checks
   * and dispatch still happen without an intervening await. Integer 1-16, default 5. With 1, any
   * change fails with POLICY_STATE_CHANGED as before.
   */
  maxPolicyAttempts?: number;
  /** Observes each decision after it is made. It cannot change the outcome; a throwing hook is ignored. */
  onDecision?: (event: Readonly<GuardDecision>) => void;
  /** Bounds that were fixed before 0.2. Every value defaults to the previous constant. */
  limits?: GuardLimits;
}
export interface GuardLimits {
  /** Outstanding approvals per prepared action. Integer 1-64, default 4. */
  maxApprovalsPerAction?: number;
  /** Policy evaluations in flight across the guard. Integer 1-1024, default 64. */
  maxPolicyEvaluations?: number;
  /** Policy evaluations in flight per task family. Integer 1-1024, default 8. */
  maxPolicyEvaluationsPerFamily?: number;
  /** Longest a policy may run before POLICY_TIMEOUT, in milliseconds. 100-300,000, default 30,000. */
  policyTimeoutMs?: number;
}
/**
 * One authorization decision, for audit. Carries identifiers only: never arguments,
 * results or policy reasons. `code` is set when the outcome is denied or failed.
 */
export interface GuardDecision {
  operation: 'prepare' | 'approve' | 'execute';
  outcome: 'allowed' | 'denied' | 'succeeded' | 'failed';
  taskId: string; tenantId: string; principalId: string;
  tool?: string; actionId?: string; resourceId?: string; approverId?: string;
  code?: GuardErrorCodeValue;
}
/** Result of `executeDetailed()`. */
export interface ExecutionResult {
  readonly value: Json;
  /** Cost units charged to the task: the reported actual cost, or the tool maximum. */
  readonly charged: number;
  readonly actionId: string;
}
export interface PreparedAction {
  readonly id: string; readonly digest: string;
  readonly action: Readonly<Action>; readonly requiresApproval: boolean;
}

export const GuardErrorCode = Object.freeze({
  INVALID_INPUT: 'INVALID_INPUT', INVALID_JSON: 'INVALID_JSON', INVALID_TASK: 'INVALID_TASK',
  ARGUMENT_INVALID: 'ARGUMENT_INVALID',
  DUPLICATE_TASK: 'DUPLICATE_TASK', INVALID_PREPARED: 'INVALID_PREPARED',
  TOOL_UNKNOWN: 'TOOL_UNKNOWN', TOOL_UNAPPROVED: 'TOOL_UNAPPROVED', TOOL_CHANGED: 'TOOL_CHANGED',
  TASK_REVOKED: 'TASK_REVOKED', TASK_EXPIRED: 'TASK_EXPIRED', GRANT_DENIED: 'GRANT_DENIED',
  DELEGATION_DENIED: 'DELEGATION_DENIED', TENANT_DENIED: 'TENANT_DENIED',
  CONTROL_PLANE_DENIED: 'CONTROL_PLANE_DENIED', RECIPIENT_DENIED: 'RECIPIENT_DENIED',
  SENSITIVE_EGRESS_DENIED: 'SENSITIVE_EGRESS_DENIED', SECRET_EGRESS_DENIED: 'SECRET_EGRESS_DENIED',
  RESOLUTION_FAILED: 'RESOLUTION_FAILED', POLICY_DENIED: 'POLICY_DENIED', POLICY_ERROR: 'POLICY_ERROR',
  POLICY_CHANGED: 'POLICY_CHANGED', POLICY_STATE_CHANGED: 'POLICY_STATE_CHANGED',
  POLICY_BUSY: 'POLICY_BUSY', POLICY_TIMEOUT: 'POLICY_TIMEOUT', ACTION_APPROVAL_LIMIT: 'ACTION_APPROVAL_LIMIT',
  ACTION_USED: 'ACTION_USED', APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  APPROVAL_INVALID: 'APPROVAL_INVALID', APPROVAL_EXPIRED: 'APPROVAL_EXPIRED', APPROVAL_USED: 'APPROVAL_USED',
  CALL_BUDGET_EXCEEDED: 'CALL_BUDGET_EXCEEDED', CONCURRENCY_EXCEEDED: 'CONCURRENCY_EXCEEDED',
  COST_BUDGET_EXCEEDED: 'COST_BUDGET_EXCEEDED', COST_REPORT_INVALID: 'COST_REPORT_INVALID',
  RESULT_INVALID: 'RESULT_INVALID', TOOL_FAILED: 'TOOL_FAILED', EXECUTION_ABORTED: 'EXECUTION_ABORTED',
  CLOCK_INVALID: 'CLOCK_INVALID',
} as const);

export type GuardErrorCodeValue = typeof GuardErrorCode[keyof typeof GuardErrorCode];

/** Errors emitted by the guard omit request values, policy exceptions and tool output. */
const GUARD_ERROR_BRAND = Symbol.for('@shieldaai/agent-guard.GuardError');
export class GuardError extends Error {
  readonly code: GuardErrorCodeValue;
  /**
   * Safe adapter code behind a flattened RESOLUTION_FAILED, ARGUMENT_INVALID or TOOL_FAILED
   * (for example IDENTITY_DENIED). Only an uppercase identifier; never request data.
   */
  readonly detail?: string;
  constructor(code: GuardErrorCodeValue, message: string = code, options: { detail?: string } = {}) {
    const detail = options.detail;
    super(message, detail === undefined ? undefined : { cause: Object.freeze({ code: detail }) });
    this.name = 'GuardError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}
// A global-registry brand survives two installed copies of this package, unlike instanceof.
Object.defineProperty(GuardError.prototype, GUARD_ERROR_BRAND, { value: true });

/**
 * True for a GuardError from any installed copy of this package. Prefer it over
 * `instanceof GuardError` in libraries that may load a different copy than the host.
 */
export function isGuardError(value: unknown): value is GuardError {
  try {
    return value !== null && typeof value === 'object' && (value as Record<symbol, unknown>)[GUARD_ERROR_BRAND] === true &&
      typeof (value as { code?: unknown }).code === 'string';
  } catch { return false; }
}

/** Reads an adapter error's `code` without running accessors; returns it only if it is a safe identifier. */
export function safeErrorDetail(error: unknown): string | undefined {
  try {
    if (error === null || typeof error !== 'object') return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const code = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    return typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : undefined;
  } catch { return undefined; }
}
