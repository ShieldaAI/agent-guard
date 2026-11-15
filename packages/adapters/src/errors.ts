/**
 * Codes for mistakes in host code that uses the adapters. They are thrown, never sent to the
 * model, and never carry request data.
 * - INVALID_OPTIONS: an option has the wrong type or is out of range.
 * - INVALID_TOOL_CALL: a dispatcher was called without a `{ name }` object.
 * - APPROVAL_NOT_FOUND: the action is not waiting in this approval queue.
 * - APPROVAL_UNAVAILABLE: the action's backend cannot issue approvals; use `complete()`.
 * - APPROVAL_NOT_ACCEPTED: the guard refused the approval itself (detail: its code); the action still waits.
 * - TOOL_NOT_APPROVED: a tool spec was requested for a tool whose current registration is not approved.
 * - TOOL_DEFINITION_UNAVAILABLE: the guard kept no definition for the tool (larger than `maxToolDefinitionBytes`).
 * - TOOL_PIN_MISMATCH: a tool's fingerprint differs from the pinned one.
 * - UNSUPPORTED_SCHEMA: a JSON Schema uses a keyword `jsonSchemaParser` does not enforce.
 * - FACTORY_REQUIRED: a framework adapter needs the framework's own factory function.
 */
export type AdapterErrorCode =
  | 'INVALID_OPTIONS'
  | 'INVALID_TOOL_CALL'
  | 'APPROVAL_NOT_FOUND'
  | 'APPROVAL_UNAVAILABLE'
  | 'APPROVAL_NOT_ACCEPTED'
  | 'TOOL_NOT_APPROVED'
  | 'TOOL_DEFINITION_UNAVAILABLE'
  | 'TOOL_PIN_MISMATCH'
  | 'UNSUPPORTED_SCHEMA'
  | 'FACTORY_REQUIRED';

const BRAND = Symbol.for('@shieldaai/agent-guard-adapters.AdapterError');

/** A mistake in host code that uses the adapters. */
export class AdapterError extends Error {
  readonly code: AdapterErrorCode;
  /** A safe uppercase reason or a tool name or JSON Pointer from host configuration. Never model input. */
  readonly detail?: string;
  constructor(code: AdapterErrorCode, detail?: string) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'AdapterError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}
Object.defineProperty(AdapterError.prototype, BRAND, { value: true });

/** True for an AdapterError, also across two installed copies of this package. */
export function isAdapterError(value: unknown): value is AdapterError {
  return value !== null && typeof value === 'object' && (value as Record<symbol, unknown>)[BRAND] === true;
}
