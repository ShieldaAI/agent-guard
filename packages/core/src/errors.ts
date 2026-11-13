import type { GuardErrorCodeValue } from './types.js';

export interface GuardErrorInfo {
  /** What the code means. */
  readonly meaning: string;
  /**
   * True only when repeating the same request later may succeed and cannot repeat
   * an effect. A false value means: change the request, the grants or the state first.
   */
  readonly retryable: boolean;
  /** The usual reason a caller sees it, and what to do next. */
  readonly cause: string;
}

const entry = (meaning: string, retryable: boolean, cause: string): GuardErrorInfo =>
  Object.freeze({ meaning, retryable, cause });

/** Stable catalog of every GuardErrorCode. Codes never carry request data. */
export const GuardErrorCatalog: Readonly<Record<GuardErrorCodeValue, GuardErrorInfo>> = Object.freeze({
  INVALID_INPUT: entry(
    'A host-supplied option or argument is malformed.',
    false,
    'A wrong type, an empty identifier or an out-of-range number in a host call. Fix the calling code.',
  ),
  INVALID_JSON: entry(
    'A value is not plain JSON within the size limits.',
    false,
    'The value has a cycle, an accessor, a class instance or a non-finite number, or it exceeds limits.maxJsonBytes, limits.maxJsonNodes or 64 levels of nesting. Send plain data, make it smaller, or raise the limit.',
  ),
  INVALID_TASK: entry(
    'The task handle is unknown to this guard.',
    false,
    'The handle came from another guard, is a copy of the object createTask() returned, or the task was retired with retireTask(). Create a new task and use its handle.',
  ),
  ARGUMENT_INVALID: entry(
    'The tool rejected the call arguments.',
    false,
    "The tool's parse() threw or returned something that is not plain JSON. Correct the arguments and prepare again; the error detail carries the parser's code when it supplies one.",
  ),
  DUPLICATE_TASK: entry(
    'A task with this ID already exists.',
    false,
    'Task IDs are unique among the tasks a guard has not retired. Use a new ID, or call retireTask() on the finished task first.',
  ),
  INVALID_PREPARED: entry(
    'The prepared action is unknown here or no longer waiting to run.',
    false,
    'The action is not one this guard prepared (it came from another guard or is a copy), or, in the executor, it belongs to another task or has already run or been pruned. Call prepare() again and use what it returns.',
  ),
  TOOL_UNKNOWN: entry(
    'No tool with this name is registered.',
    false,
    'The name is misspelled, the tool was never registered, or it was removed with unregisterTool(). Register the tool or correct the name.',
  ),
  TOOL_UNAPPROVED: entry(
    "The tool's current registration is not approved.",
    false,
    'approveTool() has not been called for this registration, the tool was registered again since, or unapproveTool() withdrew the approval. Review the definition, call approveTool() with its current fingerprint, then prepare again.',
  ),
  TOOL_CHANGED: entry(
    'The tool registration is not the one this call refers to.',
    false,
    'The tool was registered again or removed with unregisterTool() after the action was prepared, or approveTool() was given a fingerprint that is not the current one or a reviewedAgainst value that is not the last approved fingerprint. Read toolChanges() again, approve the current fingerprint, then prepare and review the action again.',
  ),
  TASK_REVOKED: entry(
    'The task or one of its ancestors was revoked.',
    false,
    'revokeTask() or retireTask() was called on this task or a parent, or a tool returned an invalid result. Create a new task if the work should continue.',
  ),
  TASK_EXPIRED: entry(
    'The task deadline has passed.',
    false,
    'The budget deadline of the task or a parent is in the past. Create a new task with a later deadline.',
  ),
  GRANT_DENIED: entry(
    'No grant in the task ancestry allows this tool and resource.',
    false,
    'The tool or the resolved resource is outside the grants of the task or one of its parents. Grant the resource when creating the task if the call is legitimate; otherwise treat it as a blocked attempt.',
  ),
  DELEGATION_DENIED: entry(
    "A child task would exceed its parent's authority.",
    false,
    'Delegated grants, recipients or budget exceed the parent. The error detail names which: GRANT_, RECIPIENT_, CONTROL_PLANE_, BUDGET_ or DEADLINE_EXCEEDS_PARENT. Ask for the same or less than the parent holds.',
  ),
  TENANT_DENIED: entry(
    'The resolved tenant differs from the task tenant.',
    false,
    "The tool's resolve() returned a resource that belongs to another tenant. Nothing to fix when the request was hostile; otherwise correct the resource lookup.",
  ),
  CONTROL_PLANE_DENIED: entry(
    'The tool is control-plane and the task does not allow it.',
    false,
    'The tool is registered with controlPlane: true and the task (or a parent) was created without allowControlPlane. Set allowControlPlane only on tasks that do administrative work.',
  ),
  RECIPIENT_DENIED: entry(
    "The external recipient is not in the task's allowed recipients.",
    false,
    'An external call targets a recipient that the task or a parent did not list, or names none. Add the exact recipient to allowedRecipients when creating the task if it is legitimate.',
  ),
  SENSITIVE_EGRESS_DENIED: entry(
    'Sensitive data may not leave through this external call.',
    false,
    'The call is external and either reads sensitive data itself or runs in a task family that already did. Do the send from a separate task that has not read sensitive data.',
  ),
  SECRET_EGRESS_DENIED: entry(
    'The arguments contain a protected host secret.',
    false,
    'A value listed in secretValues appears in the arguments of an external call. Remove the secret from the arguments.',
  ),
  RESOLUTION_FAILED: entry(
    'The tool could not resolve its resource.',
    false,
    "The tool's resolve() threw or returned a malformed result. Check the arguments and the lookup; the error detail carries the adapter's code when it supplies one.",
  ),
  POLICY_DENIED: entry(
    'The policy denied the action.',
    false,
    'The configured policy returned deny. Change the request or the policy; repeating the call gives the same answer.',
  ),
  POLICY_ERROR: entry(
    'The policy threw or returned an invalid decision.',
    false,
    'The host policy has a bug or returned something other than allow, deny or require_approval. Fix the policy; the call was not run.',
  ),
  POLICY_CHANGED: entry(
    'The policy changed after preparation.',
    false,
    'setPolicy() was called after the action was prepared, or the durable executor restarted (a restart ends every prepared action). Prepare the action again and have it reviewed.',
  ),
  POLICY_STATE_CHANGED: entry(
    'The task changed while the policy was evaluating, beyond the retry bound.',
    true,
    'Other calls on the same task kept starting or finishing while the policy ran. Retry, run fewer calls in parallel on one task, or raise maxPolicyAttempts.',
  ),
  POLICY_BUSY: entry(
    'Too many policy evaluations are in flight for this task family.',
    true,
    'Parallel calls used every policy slot (limits.maxPolicyEvaluations and limits.maxPolicyEvaluationsPerFamily). Retry shortly, or raise the limits.',
  ),
  POLICY_TIMEOUT: entry(
    'The policy did not decide within the policy time limit (limits.policyTimeoutMs, 30 seconds by default).',
    true,
    'An asynchronous policy was too slow. Retry, make the policy faster, or raise limits.policyTimeoutMs.',
  ),
  ACTION_APPROVAL_LIMIT: entry(
    'The action already has the maximum number of approvals.',
    false,
    'approve() was called more often than limits.maxApprovalsPerAction allows for one action. Use an approval ID already issued, or wait for one to expire.',
  ),
  ACTION_USED: entry(
    'The prepared action was already dispatched.',
    false,
    'Each prepared action runs at most once, even when the first run failed. Call prepare() again for another call.',
  ),
  APPROVAL_REQUIRED: entry(
    'The action needs a human approval before dispatch.',
    false,
    'The tool, the policy or the outside-content rule requires approval and execute() was called without an approval ID. Show the prepared action to a reviewer, call approve(), and pass the approval ID to execute().',
  ),
  APPROVAL_INVALID: entry(
    'The approval does not match this action.',
    false,
    'The approval ID is unknown for this action (it was issued for another action or never issued), or approve() was given an expiry in the past or after the task deadline. Call approve() for this exact action with a valid expiry.',
  ),
  APPROVAL_EXPIRED: entry(
    'The approval expired.',
    false,
    'execute() ran after the expiresAt given to approve(). Ask the reviewer to approve the action again.',
  ),
  APPROVAL_USED: entry(
    'The approval was already consumed.',
    false,
    'Each approval authorizes one dispatch. The in-memory guard never returns this code (it reports ACTION_USED); only the executor does. Prepare and approve a new action.',
  ),
  CALL_BUDGET_EXCEEDED: entry(
    'The task has no calls left.',
    false,
    'The task or a parent has dispatched maxCalls calls. Create a new task with a budget for the remaining work.',
  ),
  CONCURRENCY_EXCEEDED: entry(
    'The task is at its concurrent-call limit.',
    true,
    'maxConcurrent calls are already in flight on the task or a parent. Retry when one finishes.',
  ),
  COST_BUDGET_EXCEEDED: entry(
    "The call would exceed the task's cost budget.",
    false,
    "Spent cost plus cost reserved by calls in flight plus this tool's maxCost would pass the budget's maxCost for the task or a parent. Create a new task with a larger budget if the spend is intended.",
  ),
  COST_REPORT_INVALID: entry(
    'The tool reported an invalid actual cost.',
    false,
    "The handler returned an actualCost that is negative, fractional or above the tool's maxCost. The maximum was charged and the task was revoked; the effect may have happened, so check the backend, then fix the handler.",
  ),
  RESULT_INVALID: entry(
    'The tool returned a malformed result.',
    false,
    'The handler returned something other than { value } in plain JSON, or a result larger than limits.maxJsonBytes or limits.maxJsonNodes. The task was revoked and the effect may have happened: check the backend, then fix the handler or raise the limit.',
  ),
  TOOL_FAILED: entry(
    'The tool handler failed; the outcome is unknown.',
    false,
    'The handler threw. The effect may have happened, so check the backend before preparing the call again.',
  ),
  EXECUTION_ABORTED: entry(
    'The call was aborted; the outcome is unknown.',
    false,
    'The task deadline passed or the task was revoked while the handler was running. Detail EFFECT_COMMITTED means the handler finished; otherwise check the backend before preparing the call again.',
  ),
  UNTRUSTED_CONTEXT_DENIED: entry(
    "This tool can't run after the task family read outside content.",
    false,
    'The tool sets untrustedContext deny (or inherits it) and an earlier call in the task family read outside content. Run the tool from a separate task that has not read outside content.',
  ),
  APPROVAL_CONTEXT_CHANGED: entry(
    'The task family read outside content after this approval was given.',
    false,
    'A call that reads outside content ran between approve() and execute(). Ask the reviewer to approve the action again, knowing what was read.',
  ),
  CLOCK_INVALID: entry(
    'The guard clock returned an invalid or backward time.',
    false,
    'The clock option threw or returned a bad value, or the system clock stepped backward. Calls work again once the clock passes the last time the guard saw; pass clock: monotonicClock to avoid this.',
  ),
});
