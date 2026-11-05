import { GuardError, GuardErrorCode } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';

// These codes help a caller decide whether to seek approval, check an outcome or stop.
// Tool exceptions, upstream bodies and arbitrary host-defined codes stay inside the host.
const codes = new Set<string>([...Object.values(GuardErrorCode),
  'UNAUTHENTICATED', 'REQUEST_DENIED', 'REQUEST_INVALID', 'REQUEST_TOO_LARGE', 'CAPACITY_EXCEEDED',
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
