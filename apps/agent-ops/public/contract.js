// One source for facts the service and the browser client must agree on.
// Imported by the Node service and served to the browser as it is: no DOM and no Node APIs here.

export const TICKET_STATUSES = Object.freeze(['open', 'resolved']);

/** States a request can be shown in. `preparing` and `dispatching` never leave the service. */
export const REQUEST_STATES = Object.freeze([
  'pending',
  'completed',
  'denied',
  'withdrawn',
  'expired',
  'changed',
  'unconfirmed',
  'failed',
  'review_required',
]);

/** A request in one of these states is finished: nothing can approve, apply or change it again. */
export const TERMINAL_STATES = Object.freeze([
  'completed',
  'denied',
  'withdrawn',
  'expired',
  'changed',
  'failed',
  'review_required',
]);
export const isTerminalState = state => TERMINAL_STATES.includes(state);

/** Finished, or pending past its review deadline (which the service reports as expired). */
export const isSettled = (request, now) =>
  isTerminalState(request.state) || (request.state === 'pending' && request.expiresAt <= now);

/** A confirmation record belongs to a request only when every binding agrees. */
export function receiptMatches(request, receipt) {
  return (
    !!receipt &&
    typeof receipt === 'object' &&
    receipt.operationId === request.operationId &&
    receipt.requestId === request.id &&
    receipt.digest === request.digest &&
    receipt.tenantId === request.tenantId &&
    receipt.ticketId === request.ticketId &&
    receipt.status === request.afterStatus &&
    receipt.version === Number(request.resourceVersion) + 1
  );
}

export const DENIAL_REASON_MAX = 280;
export const REQUESTER_KINDS = Object.freeze(['person', 'agent']);

export const GENERIC_ERROR_MESSAGE =
  'The operation could not be confirmed. Refresh to check the current state before doing anything else.';

/** What a person is told for each refusal code. The service sends this text; the client falls back to it. */
export const ERROR_MESSAGES = Object.freeze({
  UNAUTHENTICATED: 'Your session ended. Sign in again.',
  FORBIDDEN: 'Your role does not permit this action.',
  CSRF_INVALID: 'The page is out of date. Refresh before trying again.',
  AUTH_FAILED: 'Sign-in could not be verified. Start a new sign-in.',
  ALREADY_SIGNED_IN: 'You are already signed in. Refresh the page.',
  NOT_FOUND: 'That item is no longer available. Refresh to load the current list.',
  REVIEW_STALE: 'This request changed or was already decided. Nothing was done.',
  REVIEW_EXPIRED: 'This review expired. Prepare a new request from the current ticket.',
  TICKET_CHANGED:
    'The ticket changed after this request was prepared, so nothing happened. Prepare a new request for its current version.',
  NO_CHANGE: 'The ticket already has this status. Choose a different status.',
  RECEIPT_NOT_FOUND:
    'No confirmation record was found, so the outcome is still unconfirmed. Do not repeat the change. If no confirmation will ever arrive, review the close-out evidence.',
  RECEIPT_FOUND: 'A confirmation record exists for this request. Check whether it was applied instead.',
  CLOSE_OUT_UNPROVEN:
    'The stored records do not prove that this change was never applied. Keep the request unconfirmed and ask the deployment owner.',
  CLOSE_OUT_STALE: 'The evidence changed after it was shown. Review it again before closing the request.',
  ARCHIVE_UNAVAILABLE: 'This request cannot be archived right now. Refresh to check its state.',
  ARCHIVE_PREVIEW_STALE: 'The archive preview expired or its records changed. Preview again.',
  RECORD_CAPACITY_REACHED: 'The record limit was reached. Ask the deployment owner to follow the capacity runbook.',
  LIMITS_BELOW_USAGE:
    'A configured storage limit was reached. Ask the deployment owner to review capacity offline; retained records will not be deleted.',
  HISTORY_SEGMENT_CAPACITY:
    'History recovery capacity is exhausted. Stop new compaction and ask the deployment owner for a reviewed migration plan. Preserve all records, history, witnesses and keys.',
  HISTORY_MIGRATION_REQUIRED:
    'History exceeds this recovery profile. Stop maintenance changes and ask the deployment owner for a reviewed compatible recovery or migration plan. Preserve all records, history, witnesses and keys.',
  RATE_LIMITED: 'Too many requests. Wait a minute and try again.',
  BUSY: 'The service is busy. Wait a moment and try again.',
  INVALID_INPUT: 'Check the values you entered.',
  INVALID_STATUS: 'That status is not available for this ticket.',
  SELF_APPROVAL_FORBIDDEN: 'You created this request, so another reviewer must decide it.',
  WITHDRAW_FORBIDDEN: 'Only the requester who created this request can withdraw it.',
  PENDING_LIMIT_REACHED: 'Too many requests are waiting for review. Decide or let some expire, then try again.',
  RECONCILIATION_UNAVAILABLE: 'This request cannot be checked in its current state. Refresh it.',
  PREVIEW_CAPACITY_REACHED: 'Too many archive previews are open. Wait a minute, then preview again.',
});

export const errorMessage = code =>
  typeof code === 'string' && Object.hasOwn(ERROR_MESSAGES, code) ? ERROR_MESSAGES[code] : GENERIC_ERROR_MESSAGE;

/** Refusals made before anything was done: the client reloads current state straight away. */
export const DEFINITIVE_REFUSALS = Object.freeze([
  'SELF_APPROVAL_FORBIDDEN',
  'WITHDRAW_FORBIDDEN',
  'NO_CHANGE',
  'NOT_FOUND',
  'REVIEW_EXPIRED',
  'REVIEW_STALE',
  'TICKET_CHANGED',
  'PENDING_LIMIT_REACHED',
  'RECEIPT_NOT_FOUND',
  'RECEIPT_FOUND',
  'RECONCILIATION_UNAVAILABLE',
  'CLOSE_OUT_UNPROVEN',
  'CLOSE_OUT_STALE',
  'ARCHIVE_UNAVAILABLE',
  'ARCHIVE_PREVIEW_STALE',
]);
/** Refusals made before anything was read or done: what is on screen is still good. */
export const HARMLESS_REFUSALS = Object.freeze([
  'RATE_LIMITED',
  'BUSY',
  'INVALID_INPUT',
  'INVALID_STATUS',
  'PREVIEW_CAPACITY_REACHED',
]);

/** Why a finished request cannot be archived yet, as a sentence. Unknown codes are shown as they are. */
export const ARCHIVE_BLOCKERS = Object.freeze({
  FAMILY_UNRESOLVED_WORK: 'Its outcome is still unconfirmed. Check whether it was applied first.',
  FAMILY_ACTIVE_WORK: 'It is still being worked on. Wait until it finishes.',
  FAMILY_EXTERNAL_REFERENCE: 'Another record still refers to it.',
  ARCHIVE_CAPACITY_EXCEEDED:
    'The archive is full. Ask the deployment owner to move older records into company history.',
});
