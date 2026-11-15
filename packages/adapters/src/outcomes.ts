import { GuardErrorCatalog, isGuardError, type GuardErrorCodeValue, type Json } from '@shieldaai/agent-guard';

/**
 * Codes the adapters add next to the guard's own. They never carry request data.
 * - INPUT_NOT_JSON: the provider sent tool arguments that are not valid JSON text.
 * - APPROVAL_QUEUE_FULL: too many actions already wait for a person.
 * - APPROVAL_REJECTED: a person denied the action in the approval queue.
 * - APPROVAL_TIMEOUT: nobody decided before the wait ended.
 * - APPROVAL_UNAVAILABLE: the action needs approval and this dispatcher has no approval queue.
 * - APPROVAL_CANCELLED: the wait was aborted by the caller's signal.
 * - HOST_ERROR: host code (a tool backend, the network to a remote executor) threw something
 *   that is not a guard decision. The model gets no detail; the dispatcher's `onHostError` does.
 */
export type AdapterCode =
  | 'INPUT_NOT_JSON'
  | 'APPROVAL_QUEUE_FULL'
  | 'APPROVAL_REJECTED'
  | 'APPROVAL_TIMEOUT'
  | 'APPROVAL_UNAVAILABLE'
  | 'APPROVAL_CANCELLED'
  | 'HOST_ERROR';

/** A denial code: one of the guard's codes, an executor response code, or an adapter code. */
export type OutcomeCode = GuardErrorCodeValue | AdapterCode | (string & {});

/** The call ran and returned a value. */
export interface OkOutcome {
  readonly status: 'ok';
  readonly tool: string;
  readonly actionId: string;
  readonly result: Json;
}
/** Nothing ran. `message` is written for the model; it never contains request data. */
export interface DeniedOutcome {
  readonly status: 'denied';
  readonly tool: string;
  readonly code: OutcomeCode;
  /** Safe uppercase reason behind the code, for example SCHEMA_REQUIRED from a schema parser. */
  readonly detail?: string;
  /** True only when the same call later may succeed and cannot repeat an effect. */
  readonly retryable: boolean;
  readonly message: string;
  /** Set when a prepared action was discarded (for example a rejected approval). */
  readonly actionId?: string;
}
/** The action is held for a person. Nothing ran yet. */
export interface WaitingOutcome {
  readonly status: 'waiting_for_approval';
  readonly tool: string;
  readonly actionId: string;
  readonly message: string;
}
/** The handler started and did not finish cleanly: the effect is unknown. Never retry blindly. */
export interface FailedOutcome {
  readonly status: 'failed';
  readonly tool: string;
  readonly code: OutcomeCode;
  readonly detail?: string;
  readonly retryable: false;
  readonly message: string;
  readonly actionId?: string;
}
/** What a dispatched tool call came to. Plain data: safe to log and to send to the model. */
export type DispatchOutcome = OkOutcome | DeniedOutcome | WaitingOutcome | FailedOutcome;

const FAILED_AFTER_DISPATCH = new Set<string>([
  'TOOL_FAILED',
  'EXECUTION_ABORTED',
  'RESULT_INVALID',
  'COST_REPORT_INVALID',
]);

const OUT_OF_SCOPE =
  'This call is outside what the current task is allowed to do. Do not retry it with other values; tell the user it is not permitted.';
const MODEL_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  GRANT_DENIED: OUT_OF_SCOPE,
  TENANT_DENIED: OUT_OF_SCOPE,
  CONTROL_PLANE_DENIED: OUT_OF_SCOPE,
  DELEGATION_DENIED: OUT_OF_SCOPE,
  RECIPIENT_DENIED:
    'This recipient is not on the list the task may send to. Do not try another recipient; tell the user it is not permitted.',
  SENSITIVE_EGRESS_DENIED:
    'This task has read sensitive data, so it may not send anything outside. Do not retry; tell the user.',
  SECRET_EGRESS_DENIED: 'The arguments contain a secret that may not leave the system. Do not retry; tell the user.',
  UNTRUSTED_CONTEXT_DENIED:
    'This tool is not available after the task has read outside content. Do not retry; tell the user.',
  POLICY_DENIED: 'A policy refused this call. Do not retry it; tell the user it is not permitted.',
  TOOL_UNKNOWN: 'This tool is not available. Use another tool or tell the user.',
  TOOL_UNAPPROVED: 'This tool is not available right now. Use another tool or tell the user.',
  TOOL_CHANGED: 'This tool changed and is waiting for review. Use another tool or tell the user.',
  ARGUMENT_INVALID: "The arguments were rejected. Check them against the tool's input schema and try again.",
  INVALID_JSON: 'The arguments are not plain JSON within the size limits. Send smaller, plain JSON arguments.',
  INPUT_NOT_JSON: 'The arguments were not valid JSON text. Send the arguments as a JSON object.',
  RESOLUTION_FAILED:
    'The target of this call could not be found or is not available to this task. Check the identifier; do not guess others.',
  TASK_REVOKED: 'This task has been stopped. Make no further tool calls; tell the user.',
  TASK_EXPIRED: 'This task has run out of time. Make no further tool calls; summarize what was done.',
  CALL_BUDGET_EXCEEDED: 'This task has used all of its tool calls. Make no further calls; summarize what was done.',
  COST_BUDGET_EXCEEDED: 'This task has used its cost budget. Make no further calls; summarize what was done.',
  CONCURRENCY_EXCEEDED: 'Too many calls are running at once. Wait for the others to finish, then try again.',
  POLICY_BUSY: 'The system is busy. Try this call again shortly.',
  POLICY_TIMEOUT: 'The permission check took too long. Try this call again shortly.',
  POLICY_STATE_CHANGED: 'The task changed while this call was checked. Try it again.',
  APPROVAL_REQUIRED: 'This action needs approval from a person, and none was given. Tell the user.',
  APPROVAL_UNAVAILABLE: 'This action needs approval from a person, and no reviewer is available here. Tell the user.',
  APPROVAL_QUEUE_FULL: 'Too many actions are already waiting for a person. Do not retry now; tell the user.',
  APPROVAL_REJECTED: 'A person reviewed this action and denied it. Do not retry it; ask the user how to proceed.',
  APPROVAL_TIMEOUT:
    'Nobody approved this action in time. Do not retry it now; tell the user it is still pending review.',
  APPROVAL_CANCELLED: 'The wait for approval was cancelled. Do not retry it now.',
  HOST_ERROR:
    'The call could not be completed because of a problem on the system side. Do not retry it now; tell the user.',
  APPROVAL_EXPIRED: 'The approval for this action expired before it ran. Tell the user it needs approval again.',
  APPROVAL_INVALID: 'The approval does not match this action. Tell the user it needs approval again.',
  APPROVAL_USED: 'The approval was already used. Tell the user it needs approval again.',
  APPROVAL_CONTEXT_CHANGED:
    'The task read outside content after the approval was given, so the approval no longer holds. Tell the user it needs approval again.',
  ACTION_USED: 'This action already ran. Do not repeat it.',
  ACTION_APPROVAL_LIMIT: 'This action already has the most approvals it can hold. Do not retry; tell the user.',
  POLICY_ERROR: 'The permission check failed. Do not retry; tell the user something is wrong with the setup.',
  POLICY_CHANGED: 'The rules changed while this call was being checked. Make the call again from the start.',
  INVALID_INPUT: 'The system rejected this request because of a setup problem. Do not retry; tell the user.',
  INVALID_TASK: 'This task is no longer active. Make no further tool calls; tell the user.',
  INVALID_PREPARED: 'This action is not valid here. Make the call again from the start.',
  DUPLICATE_TASK: 'The system rejected this request because of a setup problem. Do not retry; tell the user.',
  CLOCK_INVALID: 'The system clock is not reliable right now. Do not retry; tell the user.',
  TOOL_FAILED: 'The tool started but failed. Its effect is unknown: do not repeat the call; tell the user.',
  EXECUTION_ABORTED: 'The call was stopped while it ran. Its effect is unknown: do not repeat it; tell the user.',
  RESULT_INVALID: 'The tool ran but its result could not be delivered. Do not repeat the call; tell the user.',
  COST_REPORT_INVALID: 'The tool ran but reported an invalid cost. Do not repeat the call; tell the user.',
});
const FALLBACK_MESSAGE = 'The call was refused. Do not retry it with other values; tell the user.';
const FAILED_FALLBACK_MESSAGE =
  'The call may have run, but its result was lost. Its effect is unknown: do not repeat it; tell the user.';
const WAITING_MESSAGE =
  'This action is waiting for approval from a person. Do not repeat the call; tell the user it is pending review.';

const DETAIL_HINTS: Readonly<Record<string, string>> = Object.freeze({
  SCHEMA_TYPE: 'A value has the wrong type.',
  SCHEMA_REQUIRED: 'A required field is missing.',
  SCHEMA_ADDITIONAL_PROPERTIES: 'A field is not allowed by the schema.',
  SCHEMA_ENUM: 'A value is not one of the allowed values.',
  SCHEMA_CONST: 'A value does not equal the required value.',
  SCHEMA_LENGTH: 'A text value is too short or too long.',
  SCHEMA_PATTERN: 'A text value does not have the required format.',
  SCHEMA_RANGE: 'A number is outside the allowed range.',
  SCHEMA_MULTIPLE_OF: 'A number is not a multiple of the required step.',
  SCHEMA_ITEMS: 'A list has too few or too many items, or repeated items.',
  SCHEMA_PROPERTY_COUNT: 'An object has too few or too many fields.',
  SCHEMA_ASYNC: 'The tool cannot check these arguments; tell the user.',
  SCHEMA_COMBINATION: 'The arguments match none (or more than one) of the allowed shapes.',
  SCHEMA_MISMATCH: 'The arguments do not match the schema.',
});

/** The model-facing sentence for a code. Never contains request data. */
export function modelMessage(code: OutcomeCode, detail?: string): string {
  const base = MODEL_MESSAGES[code] ?? FALLBACK_MESSAGE;
  const hint = detail === undefined ? undefined : DETAIL_HINTS[detail];
  return hint === undefined ? base : `${base} ${hint}`;
}

const SAFE_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
function ownString(value: object, key: string): string | undefined {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    const found = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    return typeof found === 'string' && SAFE_CODE.test(found) ? found : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Turns an error from the guard, the executor or the executor client into an outcome.
 * Returns undefined for any other error (a bug in host code), which the caller should rethrow.
 */
export function outcomeFromError(
  error: unknown,
  tool: string,
  actionId?: string,
  phase: 'prepare' | 'approve' | 'execute' = actionId === undefined ? 'prepare' : 'execute',
): DeniedOutcome | FailedOutcome | undefined {
  let code: string | undefined;
  let detail: string | undefined;
  let retryable = false;
  if (isGuardError(error)) {
    code = error.code;
    detail = error.detail !== undefined && SAFE_CODE.test(error.detail) ? error.detail : undefined;
    retryable = GuardErrorCatalog[error.code]?.retryable === true;
  } else if (error !== null && typeof error === 'object' && (error as { name?: unknown }).name === 'ExecutorError') {
    code = ownString(error, 'code');
    detail = ownString(error, 'detail');
    // Only a server-confirmed boolean is trusted.
    retryable = Object.getOwnPropertyDescriptor(error, 'retryable')?.value === true;
  }
  if (code === undefined) return undefined;
  const base = {
    tool,
    code,
    ...(detail === undefined ? {} : { detail }),
    message: modelMessage(code, detail),
    ...(actionId === undefined ? {} : { actionId }),
  };
  if (FAILED_AFTER_DISPATCH.has(code)) return Object.freeze({ status: 'failed', retryable: false, ...base });
  // From a remote executor's execute, only a known guard denial proves nothing ran: a timeout,
  // an invalid or oversized response or a transport failure may come after the effect.
  if (phase === 'execute' && !isGuardError(error) && !Object.hasOwn(GuardErrorCatalog, code))
    return Object.freeze({
      status: 'failed',
      ...base,
      retryable: false,
      message: Object.hasOwn(MODEL_MESSAGES, code) ? base.message : FAILED_FALLBACK_MESSAGE,
    });
  return Object.freeze({ status: 'denied', retryable, ...base });
}

/** A denial produced by the adapters themselves. */
export function adapterDenial(tool: string, code: AdapterCode, actionId?: string): DeniedOutcome {
  return Object.freeze({
    status: 'denied',
    tool,
    code,
    retryable: false,
    message: modelMessage(code),
    ...(actionId === undefined ? {} : { actionId }),
  });
}

/**
 * The outcome for a host error. Before execute nothing ran (`denied`); during execute the
 * effect is unknown (`failed`). Never carries the error's text.
 */
export function hostErrorOutcome(
  tool: string,
  phase: 'prepare' | 'approve' | 'execute',
  actionId?: string,
): DeniedOutcome | FailedOutcome {
  const base = {
    tool,
    code: 'HOST_ERROR',
    message: modelMessage('HOST_ERROR'),
    ...(actionId === undefined ? {} : { actionId }),
  };
  return phase === 'execute'
    ? Object.freeze({
        status: 'failed',
        retryable: false,
        ...base,
        message: `${base.message} Its effect is unknown: do not repeat it.`,
      })
    : Object.freeze({ status: 'denied', retryable: false, ...base });
}

export function waitingOutcome(tool: string, actionId: string): WaitingOutcome {
  return Object.freeze({ status: 'waiting_for_approval', tool, actionId, message: WAITING_MESSAGE });
}

/**
 * The part of an outcome to send back to the model as the tool result. It drops nothing the
 * model needs and adds nothing it should not see: no task, tenant or principal identifiers.
 */
export function outcomeForModel(outcome: DispatchOutcome): Json {
  switch (outcome.status) {
    case 'ok':
      return { status: 'ok', result: outcome.result };
    case 'waiting_for_approval':
      return { status: outcome.status, actionId: outcome.actionId, message: outcome.message };
    default:
      return {
        status: outcome.status,
        code: outcome.code,
        // Only details with a known hint (schema reasons) go to the model; a handler's own
        // code (for example ECONNREFUSED) stays with the host.
        ...(outcome.detail === undefined || !Object.hasOwn(DETAIL_HINTS, outcome.detail)
          ? {}
          : { detail: outcome.detail }),
        retryable: outcome.retryable,
        message: outcome.message,
      };
  }
}

/** True when the outcome should be flagged as an error to the provider (`is_error` and the like). */
export function isErrorOutcome(outcome: DispatchOutcome): boolean {
  return outcome.status === 'denied' || outcome.status === 'failed';
}
