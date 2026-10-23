import type { JsonValue } from './json.js';

/** JSON accepted by the guard. Every invocation is copied and deeply frozen at runtime. */
export type Json = JsonValue;
export interface Capability { tool: string; resources: readonly string[] }
/** Cost is a nonnegative safe integer in host-chosen units (for example microcurrency). */
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
}
export interface ToolDefinition {
  name: string; description: string; inputSchema?: Json; metadata?: Json;
  requiresApproval?: boolean; controlPlane?: boolean;
  /** Maximum safe-integer cost units reserved before dispatch. Defaults to zero. */
  maxCost?: number;
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction;
  execute(args: Json, context: {
    signal: AbortSignal; action: Readonly<Action>; task: Readonly<TaskIdentity>;
  }): Promise<ToolResult> | ToolResult;
}
/** actualCost, when present, must be safe integer units from zero through the tool's maxCost. */
export interface ToolResult { value: Json; actualCost?: number }
export interface Action extends ResolvedAction {
  tool: string; args: Json; toolFingerprint: string; policyVersion: number;
}
export interface TaskSnapshot extends TaskIdentity {
  sensitive: boolean; calls: number; concurrent: number; spent: number; reserved: number;
}
export type PolicyDecision = 'allow' | 'deny' | 'require_approval';
export type Policy = (action: Readonly<Action>, task: Readonly<TaskSnapshot>) => PolicyDecision | Promise<PolicyDecision>;
export interface GuardOptions { policy?: Policy; secretValues?: readonly string[]; clock?: () => number }
export interface PreparedAction {
  readonly id: string; readonly digest: string;
  readonly action: Readonly<Action>; readonly requiresApproval: boolean;
}

export const GuardErrorCode = Object.freeze({
  INVALID_INPUT: 'INVALID_INPUT', INVALID_JSON: 'INVALID_JSON', INVALID_TASK: 'INVALID_TASK',
  DUPLICATE_TASK: 'DUPLICATE_TASK', INVALID_PREPARED: 'INVALID_PREPARED',
  TOOL_UNKNOWN: 'TOOL_UNKNOWN', TOOL_UNAPPROVED: 'TOOL_UNAPPROVED', TOOL_CHANGED: 'TOOL_CHANGED',
  TASK_REVOKED: 'TASK_REVOKED', TASK_EXPIRED: 'TASK_EXPIRED', GRANT_DENIED: 'GRANT_DENIED',
  DELEGATION_DENIED: 'DELEGATION_DENIED', TENANT_DENIED: 'TENANT_DENIED',
  CONTROL_PLANE_DENIED: 'CONTROL_PLANE_DENIED', RECIPIENT_DENIED: 'RECIPIENT_DENIED',
  SENSITIVE_EGRESS_DENIED: 'SENSITIVE_EGRESS_DENIED', SECRET_EGRESS_DENIED: 'SECRET_EGRESS_DENIED',
  RESOLUTION_FAILED: 'RESOLUTION_FAILED', POLICY_DENIED: 'POLICY_DENIED', POLICY_ERROR: 'POLICY_ERROR',
  POLICY_CHANGED: 'POLICY_CHANGED', ACTION_USED: 'ACTION_USED', APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  APPROVAL_INVALID: 'APPROVAL_INVALID', APPROVAL_EXPIRED: 'APPROVAL_EXPIRED', APPROVAL_USED: 'APPROVAL_USED',
  CALL_BUDGET_EXCEEDED: 'CALL_BUDGET_EXCEEDED', CONCURRENCY_EXCEEDED: 'CONCURRENCY_EXCEEDED',
  COST_BUDGET_EXCEEDED: 'COST_BUDGET_EXCEEDED', COST_REPORT_INVALID: 'COST_REPORT_INVALID',
  RESULT_INVALID: 'RESULT_INVALID', TOOL_FAILED: 'TOOL_FAILED', EXECUTION_ABORTED: 'EXECUTION_ABORTED',
  CLOCK_INVALID: 'CLOCK_INVALID',
} as const);

export type GuardErrorCodeValue = typeof GuardErrorCode[keyof typeof GuardErrorCode];

/** Messages intentionally contain no request values, policy exceptions or tool output. */
export class GuardError extends Error {
  readonly code: GuardErrorCodeValue;
  constructor(code: GuardErrorCodeValue, message: string = code) {
    super(message);
    this.name = 'GuardError';
    this.code = code;
  }
}
