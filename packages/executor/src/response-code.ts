import { GuardError, GuardErrorCatalog, GuardErrorCode, type GuardErrorCodeValue } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';

// These codes help a caller decide whether to seek approval, check an outcome or stop.
// Tool exceptions, upstream bodies and arbitrary host-defined codes stay inside the host.
const codes = new Set<string>([...Object.values(GuardErrorCode),
  'UNAUTHENTICATED', 'REQUEST_DENIED', 'REQUEST_INVALID', 'REQUEST_TOO_LARGE', 'REQUEST_TIMEOUT', 'CAPACITY_EXCEEDED',
  'FAMILY_PENDING_LIMIT', 'FAMILY_PENDING_BYTES_LIMIT', 'FAMILY_TASK_LIMIT', 'FAMILY_TASK_BYTES_LIMIT',
  'FAMILY_MEMORY_LIMIT', 'MEMORY_LIMIT', 'MEMORY_UNAVAILABLE', 'MEMORY_VERSION_CHANGED', 'RECONCILIATION_INVALID',
  'OPERATION_FAILED',
]);

export function isExecutorResponseCode(value: unknown): value is string {
  return typeof value === 'string' && codes.has(value);
}

export function executorErrorResponse(error: unknown): string {
  try {
    if (!(error instanceof GuardError || error instanceof ExecutorError)) return 'REQUEST_INVALID';
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    return isExecutorResponseCode(code) ? code : 'OPERATION_FAILED';
  } catch { return 'OPERATION_FAILED'; }
}

const statuses: ReadonlyArray<readonly [number, readonly string[]]> = [
  [401, ['UNAUTHENTICATED']],
  [403, ['REQUEST_DENIED', 'TOOL_UNAPPROVED', 'TASK_REVOKED', 'TASK_EXPIRED', 'GRANT_DENIED', 'DELEGATION_DENIED', 'TENANT_DENIED',
    'CONTROL_PLANE_DENIED', 'RECIPIENT_DENIED', 'SENSITIVE_EGRESS_DENIED', 'SECRET_EGRESS_DENIED', 'POLICY_DENIED',
    'APPROVAL_REQUIRED', 'APPROVAL_INVALID', 'APPROVAL_EXPIRED', 'CALL_BUDGET_EXCEEDED', 'COST_BUDGET_EXCEEDED',
    'FAMILY_TASK_LIMIT', 'FAMILY_TASK_BYTES_LIMIT', 'FAMILY_MEMORY_LIMIT', 'MEMORY_LIMIT']],
  [404, ['INVALID_PREPARED', 'INVALID_TASK', 'TOOL_UNKNOWN']],
  [409, ['DUPLICATE_TASK', 'TOOL_CHANGED', 'POLICY_CHANGED', 'POLICY_STATE_CHANGED', 'ACTION_USED', 'APPROVAL_USED',
    'ACTION_APPROVAL_LIMIT', 'MEMORY_VERSION_CHANGED', 'RECONCILIATION_INVALID']],
  [429, ['CONCURRENCY_EXCEEDED', 'POLICY_BUSY', 'CAPACITY_EXCEEDED', 'FAMILY_PENDING_LIMIT', 'FAMILY_PENDING_BYTES_LIMIT']],
  [503, ['OPERATION_FAILED', 'CLOCK_INVALID', 'POLICY_ERROR', 'POLICY_TIMEOUT', 'MEMORY_UNAVAILABLE',
    'TOOL_FAILED', 'EXECUTION_ABORTED', 'RESULT_INVALID', 'COST_REPORT_INVALID']],
];
const statusByCode = new Map(statuses.flatMap(([status, list]) => list.map(code => [code, status] as const)));
/** Executor-only codes that are safe to repeat unchanged later. */
const retryableExecutorCodes = new Set(['REQUEST_TIMEOUT', 'CAPACITY_EXCEEDED', 'FAMILY_PENDING_LIMIT', 'FAMILY_PENDING_BYTES_LIMIT']);

/**
 * HTTP status for a task/admin response code: 401 unauthenticated, 403 authority denial,
 * 404 unknown action or task, 409 state change, 429 capacity, 503 store, tool or policy
 * failure, 400 for everything else (malformed requests).
 */
export function executorResponseStatus(code: string): number { return statusByCode.get(code) ?? 400; }
/** Whether repeating the same request later may succeed without repeating an effect. */
export function executorResponseRetryable(code: string): boolean {
  return Object.hasOwn(GuardErrorCatalog, code) ? GuardErrorCatalog[code as GuardErrorCodeValue].retryable : retryableExecutorCodes.has(code);
}
/** Every status a task client may receive with a JSON error body. */
export const executorErrorStatuses: ReadonlySet<number> = new Set([400, ...statuses.map(([status]) => status)]);
