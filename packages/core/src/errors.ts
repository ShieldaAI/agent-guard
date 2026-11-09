import type { GuardErrorCodeValue } from './types.js';

export interface GuardErrorInfo {
  /** What the code means. */
  readonly meaning: string;
  /**
   * True only when repeating the same request later may succeed and cannot repeat
   * an effect. A false value means: change the request, the grants or the state first.
   */
  readonly retryable: boolean;
  /** The usual reason a caller sees it. */
  readonly cause: string;
}

const entry = (meaning: string, retryable: boolean, cause: string): GuardErrorInfo =>
  Object.freeze({ meaning, retryable, cause });

/** Stable catalog of every GuardErrorCode. Codes never carry request data. */
export const GuardErrorCatalog: Readonly<Record<GuardErrorCodeValue, GuardErrorInfo>> = Object.freeze({
  INVALID_INPUT: entry(
    'A host-supplied option or argument is malformed.',
    false,
    'Wrong type, empty identifier or out-of-range number in a host call.',
  ),
  INVALID_JSON: entry(
    'A value is not bounded plain JSON.',
    false,
    'Cycles, accessors, non-finite numbers or values above the JSON limits.',
  ),
  INVALID_TASK: entry(
    'The task handle is unknown to this guard.',
    false,
    'A handle from another guard instance, or a task that was never created.',
  ),
  ARGUMENT_INVALID: entry(
    'The tool rejected the call arguments.',
    false,
    "The tool's parse() or input schema refused the arguments.",
  ),
  DUPLICATE_TASK: entry('A task with this ID already exists.', false, 'Task IDs must be unique within one guard.'),
  INVALID_PREPARED: entry(
    'The prepared action is unknown, foreign or no longer valid.',
    false,
    'The action was never prepared here, belongs to another task, or was pruned.',
  ),
  TOOL_UNKNOWN: entry('No tool with this name is registered.', false, 'A typo, or a tool that was never registered.'),
  TOOL_UNAPPROVED: entry(
    "The tool's current fingerprint is not approved.",
    false,
    'The host has not called approveTool() for this registration yet.',
  ),
  TOOL_CHANGED: entry(
    'The tool registration changed after preparation.',
    false,
    'The tool was re-registered; prepare and review again.',
  ),
  TASK_REVOKED: entry(
    'The task or one of its ancestors was revoked.',
    false,
    'revokeTask() was called on this task or a parent.',
  ),
  TASK_EXPIRED: entry('The task deadline has passed.', false, 'The budget deadline is in the past; create a new task.'),
  GRANT_DENIED: entry(
    'No grant in the task ancestry allows this tool and resource.',
    false,
    "The resolved resource is outside the task's grants.",
  ),
  DELEGATION_DENIED: entry(
    "A child task would exceed its parent's authority.",
    false,
    'Delegated grants, recipients or budget exceed the parent.',
  ),
  TENANT_DENIED: entry(
    'The resolved tenant differs from the task tenant.',
    false,
    'The tool resolved a resource belonging to another tenant.',
  ),
  CONTROL_PLANE_DENIED: entry(
    'The tool is control-plane and the task does not allow it.',
    false,
    'Set allowControlPlane on the task only for administrative work.',
  ),
  RECIPIENT_DENIED: entry(
    "The external recipient is not in the task's allowed recipients.",
    false,
    'An outbound call targets a recipient the task did not list.',
  ),
  SENSITIVE_EGRESS_DENIED: entry(
    'Sensitive data may not leave through this external call.',
    false,
    'The task family read sensitive data earlier and the call is external.',
  ),
  SECRET_EGRESS_DENIED: entry(
    'The arguments contain a protected host secret.',
    false,
    'A configured secret value appears in the outbound arguments.',
  ),
  RESOLUTION_FAILED: entry(
    'The tool could not resolve its resource.',
    false,
    "The tool's resolve() threw; see the error detail code when the adapter supplies one.",
  ),
  POLICY_DENIED: entry('The policy denied the action.', false, 'The configured policy returned deny.'),
  POLICY_ERROR: entry(
    'The policy threw or returned an invalid decision.',
    false,
    'A bug or invalid return value in the host policy.',
  ),
  POLICY_CHANGED: entry(
    'The policy changed after preparation.',
    false,
    'setPolicy() was called; prepare and review again.',
  ),
  POLICY_STATE_CHANGED: entry(
    'The task changed while the policy was evaluating, beyond the retry bound.',
    true,
    'Heavy parallel use of one task; retry, or raise maxPolicyAttempts.',
  ),
  POLICY_BUSY: entry(
    'Too many policy evaluations are in flight for this task family.',
    true,
    'Parallel calls exceeded the policy admission slots; retry shortly.',
  ),
  POLICY_TIMEOUT: entry(
    'The policy did not decide before the task deadline.',
    true,
    'A slow asynchronous policy; retry with more time or a faster policy.',
  ),
  ACTION_APPROVAL_LIMIT: entry(
    'The action already has the maximum number of approvals.',
    false,
    'Use an existing approval instead of issuing more.',
  ),
  ACTION_USED: entry(
    'The prepared action was already dispatched.',
    false,
    'Each prepared action runs at most once; prepare a new one.',
  ),
  APPROVAL_REQUIRED: entry(
    'The action needs a human approval before dispatch.',
    false,
    'Show the prepared action to a reviewer and pass the approval ID.',
  ),
  APPROVAL_INVALID: entry(
    'The approval does not match this action.',
    false,
    'A wrong, foreign or tampered approval ID.',
  ),
  APPROVAL_EXPIRED: entry('The approval expired.', false, 'Ask the reviewer to approve again.'),
  APPROVAL_USED: entry('The approval was already consumed.', false, 'Each approval authorizes one dispatch.'),
  CALL_BUDGET_EXCEEDED: entry('The task has no calls left.', false, 'maxCalls is exhausted; create a new task.'),
  CONCURRENCY_EXCEEDED: entry(
    'The task is at its concurrent-call limit.',
    true,
    'Other calls are in flight; retry when one finishes.',
  ),
  COST_BUDGET_EXCEEDED: entry(
    "The call would exceed the task's cost budget.",
    false,
    'Spent plus reserved cost would pass maxCost.',
  ),
  COST_REPORT_INVALID: entry(
    'The tool reported an invalid actual cost.',
    false,
    'actualCost was negative, fractional or above the declared maximum; the maximum was charged.',
  ),
  RESULT_INVALID: entry(
    'The tool returned a malformed result.',
    false,
    'The result was not bounded JSON; the effect may already have happened.',
  ),
  TOOL_FAILED: entry(
    'The tool handler failed; the outcome is unknown.',
    false,
    'The handler threw. Do not retry blindly: the effect may have happened.',
  ),
  EXECUTION_ABORTED: entry(
    'The call was aborted; the outcome is unknown.',
    false,
    'Deadline, revocation or cancellation during dispatch. Check the backend before retrying.',
  ),
  CLOCK_INVALID: entry(
    'The guard clock returned an invalid or backward time.',
    false,
    'A broken clock option, or a large backward wall-clock step.',
  ),
});
