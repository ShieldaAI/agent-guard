import type { JsonValue } from './json.js';

/** JSON accepted by the guard. Every value is copied and deeply frozen at runtime. */
export type Json = JsonValue;
/** Permission to call one tool on the listed resource IDs. `'*'` grants every resource of that tool. */
export interface Capability {
  tool: string;
  resources: readonly string[];
}
/**
 * What a task may use. Costs are nonnegative safe integers in units chosen by the host,
 * such as microcurrency units.
 */
export interface Budget {
  /** Most calls the task may dispatch, counting failed ones. */
  maxCalls: number;
  /** Most calls in flight at once. */
  maxConcurrent: number;
  /** Most cost the task may spend, summed over its calls. */
  maxCost: number;
  /** When the task ends, in clock milliseconds (`Date.now()` by default). */
  deadline: number;
}
/** Options for `createTask()`. `delegateTask()` takes the same options without the principal and tenant. */
export interface TaskOptions {
  /** Unique among the tasks this guard has not retired. */
  id: string;
  /** Who the agent acts for, as authenticated by the host. */
  principalId: string;
  /** The tenant whose resources the task may touch, as authenticated by the host. */
  tenantId: string;
  /** Tools and resources the task may use. */
  grants: readonly Capability[];
  budget: Budget;
  /** Exact recipients an external call may target. Default none. */
  allowedRecipients?: readonly string[];
  /** Lets the task call tools registered with `controlPlane: true`. Default false. */
  allowControlPlane?: boolean;
}
/** The identity a tool's `resolve` and `execute` receive. */
export interface TaskIdentity {
  id: string;
  principalId: string;
  tenantId: string;
}
/** Opaque reference to a task. Only the object returned by this guard works; a copy does not. */
export interface TaskHandle {
  readonly id: string;
}
/** What a tool's `resolve` returns: the resource the call would touch, looked up by trusted host code. */
export interface ResolvedAction {
  /** The resource the call acts on. Checked against the task's grants. */
  resourceId: string;
  /** The tenant that owns the resource. Must equal the task's tenant. */
  tenantId: string;
  /** The call sends data outside the trust boundary. Requires an allowed `recipient`. */
  external?: boolean;
  /** Where an external call sends data. Checked against `allowedRecipients`. */
  recipient?: string;
  /** The call reads sensitive data. Blocks later external calls in the task family. */
  sensitive?: boolean;
  /** Version bound into approval; the handler must enforce it at the actual resource. */
  resourceVersion?: string;
  /** Per-call mark that this call returns outside content; it can only add the flag, never clear it. */
  untrusted?: true;
}
/** What a tool does once its task family has read outside content. */
export type UntrustedContextMode = 'allow' | 'require_approval' | 'deny';
/** A tool as the host registers it. Every field except the three callbacks is part of the fingerprint. */
export interface ToolDefinition {
  /** The name the agent uses and grants refer to. */
  name: string;
  description: string;
  /** Recorded in the fingerprint. The guard does not validate arguments against it; use `parse`. */
  inputSchema?: Json;
  /** Any further data to include in the fingerprint. */
  metadata?: Json;
  /** Every call needs `approve()` before `execute()`. Default false. */
  requiresApproval?: boolean;
  /** An administrative tool. Only tasks created with `allowControlPlane` may call it. Default false. */
  controlPlane?: boolean;
  /** Maximum cost reserved before dispatch, as a nonnegative safe integer. Defaults to zero. */
  maxCost?: number;
  /**
   * The tool returns content that people outside the trust boundary can write (email, web
   * pages, customer tickets, third-party MCP results). Dispatching it marks the whole task
   * family `untrusted` for good. Labels are the host's claim; nothing here detects injection.
   */
  readsUntrusted?: boolean;
  /** What happens to this tool once the family is untrusted. Defaults to GuardOptions.untrustedContextDefault. */
  untrustedContext?: UntrustedContextMode;
  /** false is enforced: a resolver returning external: true fails RESOLUTION_FAILED (detail INVALID_INPUT). Omitted means unknown. */
  sendsExternal?: boolean;
  /** Trusted synchronous schema parser. Its normalized result is frozen before resolution. */
  parse?(input: Json): Json;
  /**
   * Trusted synchronous lookup of the resource the call would touch. Runs during `prepare()`
   * once the task is known to hold a grant for the tool, but before the resource and tenant
   * checks, so keep it read-only and scoped to the task's tenant.
   */
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction;
  /**
   * Performs the call. Runs only after every check passes. Honour `signal`: it aborts on
   * revocation and at the task deadline. When aborted before the effect has happened, throw
   * (for example `signal.throwIfAborted()`): the call fails with EXECUTION_ABORTED and no
   * detail. Returning normally says the effect happened: if the task was aborted meanwhile,
   * the result is withheld and the call fails with EXECUTION_ABORTED, detail
   * `EFFECT_COMMITTED`, which tells the caller not to retry.
   */
  execute(
    args: Json,
    context: {
      signal: AbortSignal;
      action: Readonly<Action>;
      task: Readonly<TaskIdentity>;
    },
  ): Promise<ToolResult> | ToolResult;
}
/**
 * What a tool's `execute` returns. actualCost must be a safe integer between zero and the
 * tool's maxCost, inclusive; without it the full maxCost is charged.
 */
export interface ToolResult {
  value: Json;
  actualCost?: number;
}
/** One exact call: the resolved resource plus the tool, its arguments and what they were checked against. */
export interface Action extends ResolvedAction {
  tool: string;
  args: Json;
  /** Fingerprint of the tool registration the action was prepared against. */
  toolFingerprint: string;
  /** Version of the policy the action was prepared under; `setPolicy()` advances it. */
  policyVersion: number;
}
/** The task state a policy sees. */
export interface TaskSnapshot extends TaskIdentity {
  /** The task family has read sensitive data. */
  sensitive: boolean;
  /** The task family has dispatched a call that reads outside content. */
  untrusted: boolean;
  /** Calls dispatched so far. */
  calls: number;
  /** Calls in flight. */
  concurrent: number;
  /** Cost charged by finished calls. */
  spent: number;
  /** Cost held for calls in flight. */
  reserved: number;
}
/** `snapshot()` view for hosts: the policy snapshot plus the budget and revocation state. */
export interface TaskStatus extends TaskSnapshot {
  /** The task's own budget; `deadline` is in clock milliseconds. */
  budget: Readonly<Budget>;
  /** True when this task or any ancestor is revoked. */
  revoked: boolean;
}
/** A policy's answer. `require_approval` allows the call only with an approval from `approve()`. */
export type PolicyDecision = 'allow' | 'deny' | 'require_approval';
/**
 * Host rule evaluated for every prepare and execute, after the built-in checks. It can deny
 * or require approval; it cannot allow what the built-in checks refuse. Pass `context.signal`
 * to cancellable I/O. A policy that throws fails the call with POLICY_ERROR.
 */
export type Policy = (
  action: Readonly<Action>,
  task: Readonly<TaskSnapshot>,
  context?: Readonly<{ signal: AbortSignal }>,
) => PolicyDecision | Promise<PolicyDecision>;
/** Options for `new AgentGuard()`. All are optional. */
export interface GuardOptions {
  /** Host rule evaluated for every prepare and execute. Default: allow what the built-in checks allow. */
  policy?: Policy;
  /** Exact secret strings that must not appear in the arguments of an external call. */
  secretValues?: readonly string[];
  /** Millisecond clock for deadlines and approval expiry. Default `Date.now`; see `monotonicClock`. */
  clock?: () => number;
  /**
   * How many times a custom policy may be evaluated for one prepare or execute when the task's
   * counters or shared sensitivity change while it runs (for example, a parallel call on the same
   * task starts or settles). Each attempt uses a fresh snapshot and a policy slot; the final checks
   * and dispatch still happen without an intervening await. Integer 1-16, default 5. With 1, any
   * change fails with POLICY_STATE_CHANGED.
   */
  maxPolicyAttempts?: number;
  /** Observes each decision after it is made. It cannot change the outcome; a throwing hook is ignored. */
  onDecision?: (event: Readonly<GuardDecision>) => void;
  /** Bounds on approvals, policy evaluation and JSON size. Every value has a default. */
  limits?: GuardLimits;
  /** untrustedContext for tools that do not set it. Default 'allow'. */
  untrustedContextDefault?: UntrustedContextMode;
}
/** Bounds the guard enforces. A value outside its range fails the constructor with INVALID_INPUT. */
export interface GuardLimits {
  /** Outstanding approvals per prepared action. Integer 1-64, default 4. */
  maxApprovalsPerAction?: number;
  /** Policy evaluations in flight across the guard. Integer 1-1024, default 64. */
  maxPolicyEvaluations?: number;
  /** Policy evaluations in flight per task family. Integer 1-1024, default 8. */
  maxPolicyEvaluationsPerFamily?: number;
  /** Longest a policy may run before POLICY_TIMEOUT, in milliseconds. 100-300,000, default 30,000. */
  policyTimeoutMs?: number;
  /**
   * Largest JSON value the guard accepts, in bytes of compact UTF-8 JSON. It applies to each
   * value the guard copies: a tool definition, task options, a `prepare` request (the arguments
   * plus the tool name), parsed arguments and a tool result (`{ value, actualCost }`).
   * Integer 65,536-67,108,864 (64 KiB to 64 MiB), default 1,048,576 (1 MiB).
   *
   * Arguments over the limit fail `prepare()` with INVALID_JSON before any callback runs. A
   * result over the limit fails `execute()` with RESULT_INVALID and revokes the task, because
   * the handler has already run and its result cannot be delivered.
   */
  maxJsonBytes?: number;
  /**
   * Most values (objects, arrays, strings, numbers, booleans and nulls) in one JSON value,
   * applied wherever maxJsonBytes applies. Integer 1,000-10,000,000, default 100,000.
   * Nesting is limited to 64 levels and is not configurable.
   */
  maxJsonNodes?: number;
  /**
   * Largest tool definition the guard keeps for `toolChanges()`, in bytes of compact UTF-8
   * JSON of the fingerprinted fields. A larger definition still registers and can be approved;
   * the guard keeps only its fingerprint, and `toolChanges()` says so with `status:
   * 'unavailable'` instead of a diff. Integer 1,024-1,048,576, default 65,536 (64 KiB).
   */
  maxToolDefinitionBytes?: number;
}
/**
 * Heuristic marks on one change, for the human reviewer. They are never a verdict and never
 * block anything: an empty list does not mean the change is safe.
 * - INSTRUCTION_TEXT: new text reads like an instruction to a model, or names credentials.
 * - HIDDEN_CHARACTERS: new text holds zero-width, bidirectional-control or control characters.
 * - SCHEMA_FIELD_ADDED: the input schema gained a property.
 * - SCHEMA_LOOSENED: the input schema accepts more than before (a constraint removed or changed,
 *   a wider enum, type or bound, a field no longer required, extra properties allowed).
 * - FLAG_LOOSENED: a guard flag became weaker (for example `requiresApproval` removed, or `maxCost` raised).
 */
export type ToolChangeHint =
  'INSTRUCTION_TEXT' | 'HIDDEN_CHARACTERS' | 'SCHEMA_FIELD_ADDED' | 'SCHEMA_LOOSENED' | 'FLAG_LOOSENED';
/** One changed JSON path of a tool definition. Values come from the tool: treat them as untrusted data. */
export interface ToolChange {
  /** RFC 6901 JSON Pointer into the fingerprinted definition, for example `/inputSchema/properties/path/type`. */
  readonly path: string;
  readonly kind: 'added' | 'removed' | 'changed';
  /** The approved value. Absent when `kind` is `added`. */
  readonly before?: Json;
  /** The value now registered. Absent when `kind` is `removed`. */
  readonly after?: Json;
  readonly hints: readonly ToolChangeHint[];
}
/** Result of `diffToolDefinitions()`. */
export interface ToolDefinitionDiff {
  readonly changes: readonly ToolChange[];
  /** True when there were more than 256 changes; the rest are not listed. Top-level guard fields are always listed. */
  readonly truncated: boolean;
}
/**
 * What `toolChanges()` reports: the current registration compared with the last approved
 * definition of the same name. Frozen. Descriptions, schemas and metadata in it are the
 * tool's own text: show them as data, never as markup or instructions.
 */
export interface ToolChanges extends ToolDefinitionDiff {
  readonly name: string;
  /**
   * - `first_approval`: no definition of this name has been approved (or it was unregistered since).
   * - `unchanged`: the registration has the approved fingerprint.
   * - `changed`: it differs; `changes` lists how.
   * - `unavailable`: it differs, but a definition was too large to keep, so there is no diff.
   *   `reason` says which. Compare the definitions yourself before approving.
   */
  readonly status: 'first_approval' | 'unchanged' | 'changed' | 'unavailable';
  /** Set only with `unavailable`: the current definition or the approved one exceeded `maxToolDefinitionBytes`. */
  readonly reason?: 'DEFINITION_TOO_LARGE' | 'APPROVED_DEFINITION_TOO_LARGE' | 'APPROVED_DEFINITION_NOT_KEPT';
  /** Fingerprint of the current registration: what `approveTool()` takes. */
  readonly fingerprint: string;
  /** Whether the current registration is approved. */
  readonly approved: boolean;
  /** Fingerprint of the last approved definition. Pass it as `reviewedAgainst` when approving. */
  readonly approvedFingerprint?: string;
  /** The fingerprinted fields of the current registration. Absent when too large to keep. */
  readonly definition?: Json;
  /** The fingerprinted fields of the last approved definition. Absent when none, or too large to keep. */
  readonly approvedDefinition?: Json;
}
/** Options for `approveTool()`. */
export interface ApproveToolOptions {
  /**
   * The `approvedFingerprint` of the `toolChanges()` result the reviewer read, or `null` when it
   * was a first approval. When given, approval fails with TOOL_CHANGED unless that is still the
   * last approved definition, so a reviewer never approves against a comparison they did not see.
   */
  reviewedAgainst?: string | null;
}
/**
 * One authorization decision, for audit. Carries identifiers only: never arguments,
 * results or policy reasons. `code` is set when the outcome is denied or failed.
 */
export interface GuardDecision {
  operation: 'prepare' | 'approve' | 'execute';
  /** `failed` means the handler started, so its effect is unknown; `denied` means it never ran. */
  outcome: 'allowed' | 'denied' | 'succeeded' | 'failed';
  taskId: string;
  tenantId: string;
  principalId: string;
  tool?: string;
  actionId?: string;
  resourceId?: string;
  approverId?: string;
  code?: GuardErrorCodeValue;
  /** Whether the task family had read outside content at this decision. */
  untrusted: boolean;
}
/** Result of `executeDetailed()`. */
export interface ExecutionResult {
  readonly value: Json;
  /** Cost units charged to the task: the reported actual cost, or the tool maximum. */
  readonly charged: number;
  readonly actionId: string;
}
/** One checked call, ready to approve or execute. Only the object returned by `prepare()` works. */
export interface PreparedAction {
  /** Unique ID of this prepared call. */
  readonly id: string;
  /** `sha256:` digest of the ID, task identity, action and tool registration: one value that names this exact call. */
  readonly digest: string;
  /** Exactly what will run: tool, arguments and resolved resource. Frozen. */
  readonly action: Readonly<Action>;
  /** True when `execute()` needs an approval ID from `approve()`. */
  readonly requiresApproval: boolean;
}

/** Every code a GuardError can carry. `GuardErrorCatalog` explains each one. */
export const GuardErrorCode = Object.freeze({
  INVALID_INPUT: 'INVALID_INPUT',
  INVALID_JSON: 'INVALID_JSON',
  INVALID_TASK: 'INVALID_TASK',
  ARGUMENT_INVALID: 'ARGUMENT_INVALID',
  DUPLICATE_TASK: 'DUPLICATE_TASK',
  INVALID_PREPARED: 'INVALID_PREPARED',
  TOOL_UNKNOWN: 'TOOL_UNKNOWN',
  TOOL_UNAPPROVED: 'TOOL_UNAPPROVED',
  TOOL_CHANGED: 'TOOL_CHANGED',
  TASK_REVOKED: 'TASK_REVOKED',
  TASK_EXPIRED: 'TASK_EXPIRED',
  GRANT_DENIED: 'GRANT_DENIED',
  DELEGATION_DENIED: 'DELEGATION_DENIED',
  TENANT_DENIED: 'TENANT_DENIED',
  CONTROL_PLANE_DENIED: 'CONTROL_PLANE_DENIED',
  RECIPIENT_DENIED: 'RECIPIENT_DENIED',
  SENSITIVE_EGRESS_DENIED: 'SENSITIVE_EGRESS_DENIED',
  SECRET_EGRESS_DENIED: 'SECRET_EGRESS_DENIED',
  RESOLUTION_FAILED: 'RESOLUTION_FAILED',
  POLICY_DENIED: 'POLICY_DENIED',
  POLICY_ERROR: 'POLICY_ERROR',
  POLICY_CHANGED: 'POLICY_CHANGED',
  POLICY_STATE_CHANGED: 'POLICY_STATE_CHANGED',
  POLICY_BUSY: 'POLICY_BUSY',
  POLICY_TIMEOUT: 'POLICY_TIMEOUT',
  ACTION_APPROVAL_LIMIT: 'ACTION_APPROVAL_LIMIT',
  ACTION_USED: 'ACTION_USED',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  APPROVAL_INVALID: 'APPROVAL_INVALID',
  APPROVAL_EXPIRED: 'APPROVAL_EXPIRED',
  APPROVAL_USED: 'APPROVAL_USED',
  CALL_BUDGET_EXCEEDED: 'CALL_BUDGET_EXCEEDED',
  CONCURRENCY_EXCEEDED: 'CONCURRENCY_EXCEEDED',
  COST_BUDGET_EXCEEDED: 'COST_BUDGET_EXCEEDED',
  COST_REPORT_INVALID: 'COST_REPORT_INVALID',
  RESULT_INVALID: 'RESULT_INVALID',
  TOOL_FAILED: 'TOOL_FAILED',
  EXECUTION_ABORTED: 'EXECUTION_ABORTED',
  CLOCK_INVALID: 'CLOCK_INVALID',
  UNTRUSTED_CONTEXT_DENIED: 'UNTRUSTED_CONTEXT_DENIED',
  APPROVAL_CONTEXT_CHANGED: 'APPROVAL_CONTEXT_CHANGED',
} as const);

/** Union of the GuardErrorCode values. */
export type GuardErrorCodeValue = (typeof GuardErrorCode)[keyof typeof GuardErrorCode];

const GUARD_ERROR_BRAND = Symbol.for('@shieldaai/agent-guard.GuardError');
/** Errors emitted by the guard omit request values, policy exceptions and tool output. */
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
    return (
      value !== null &&
      typeof value === 'object' &&
      (value as Record<symbol, unknown>)[GUARD_ERROR_BRAND] === true &&
      typeof (value as { code?: unknown }).code === 'string'
    );
  } catch {
    return false;
  }
}

/** Reads an adapter error's `code` without running accessors; returns it only if it is a safe identifier. */
export function safeErrorDetail(error: unknown): string | undefined {
  try {
    if (error === null || typeof error !== 'object') return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const code = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    return typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}
