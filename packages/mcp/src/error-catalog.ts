import type { McpBoundaryErrorCode } from './boundary.js';

export interface McpBoundaryErrorInfo {
  /** What the code means. */
  readonly meaning: string;
  /** What to do next. */
  readonly action: string;
}

const entry = (meaning: string, action: string): McpBoundaryErrorInfo => Object.freeze({ meaning, action });

/**
 * Every McpBoundaryErrorCode with its meaning and what to do next. Codes never carry request
 * or server data. A code raised while the guard resolves or runs a call reaches the caller
 * as the `detail` of a GuardError (RESOLUTION_FAILED or TOOL_FAILED).
 */
export const McpBoundaryErrorCatalog: Readonly<Record<McpBoundaryErrorCode, McpBoundaryErrorInfo>> = Object.freeze({
  ACTIVE_CONTENT_DENIED: entry(
    'A definition or result carries UI or widget content: an HTML, JavaScript or SVG type, a ui: address or UI metadata.',
    'A definition with such content is skipped; a result with it fails the call and quarantines the connection. Remove the binding, or call refresh() and approve again to keep using the other operations.',
  ),
  ARGUMENTS_INVALID: entry(
    'The call arguments do not match the schema the server advertised, or are not a JSON object.',
    'Correct the arguments and prepare the call again.',
  ),
  AUTHORIZATION_DENIED: entry(
    'The host authorization check failed: the authorize callback threw or was asynchronous, or the token or its verified claims were refused.',
    'The connection is quarantined. Supply a valid credential (replaceCredential() on a verified session, or a new connection), then refresh() and approve again.',
  ),
  CAPABILITY_DENIED: entry(
    'A request outside the supported profile was refused: the server asked for sampling, elicitation, roots or an unknown method, or a list was requested outside a refresh.',
    'A refused server request needs no action. If it happened during a call, the connection is quarantined: call refresh() and approve again.',
  ),
  CONNECTION_CHANGED: entry(
    'The connection changed state while this operation was pending: a newer refresh, a change notification, an authorization failure or a close came first.',
    'Read status and failureReason. If the connection is not ready, call refresh(); then approve the new fingerprints and prepare the call again.',
  ),
  CONNECTION_FAILED: entry(
    'connect() could not complete the handshake, the authorization check or the first registry load.',
    'The connection is closed. Check the transport, the server and the credential, then connect again.',
  ),
  CONNECTION_UNAVAILABLE: entry(
    'The connection is closed or still connecting, or the operation is not in the current registry. As a failureReason: the transport closed or a send failed.',
    'If the connection is quarantined, call refresh() and approve again. If it is closed, create a new connection.',
  ),
  CREDENTIAL_REFLECTED: entry(
    'The server sent back a protected value, such as the access token, inside a message.',
    'The connection is closed and this code is its failureReason. Treat the server as hostile: rotate the credential and review the server before connecting again.',
  ),
  CREDENTIAL_REPLACEMENT_PENDING: entry(
    'replaceCredential() was called while an earlier replacement was still running.',
    'Wait for the earlier call to settle, then call replaceCredential() again if it is still needed.',
  ),
  ENDPOINT_DENIED: entry(
    'The HTTP endpoint is not acceptable: not HTTPS, carrying credentials or a fragment, or a request went to a different address.',
    'Use an exact https: endpoint. Plain http: is accepted only for 127.0.0.1 or [::1] with allowInsecureLoopback.',
  ),
  IDENTITY_DENIED: entry(
    'A task with a different principal or tenant tried to use this connection.',
    'Create one connection for each principal and tenant, and grant its operations only to tasks with that identity.',
  ),
  INVALID_CONFIGURATION: entry(
    'An option is malformed: an identifier, a binding, a limit or a protected value. From operationChanges(): the guard option has no toolChanges().',
    'Fix the options. Identifiers need visible text, no NUL and no unpaired surrogate, and at most 1,024 characters; an operation name (mcp:, the URL-encoded server ID and the URL-encoded binding name) needs at most 4,096; each limit has a documented range.',
  ),
  INVALID_JSON: entry(
    'A value is not plain JSON data: it is a proxy, has an accessor or a class instance, repeats an object or holds a non-finite number.',
    'Pass plain data. For a server message this is reported as MESSAGE_REJECTED.',
  ),
  JSON_LIMIT: entry(
    'A JSON value is too large, has too many values or is nested too deeply.',
    'Messages and results: limits.maxMessageBytes, 10,000 values, 32 levels. Schemas: 64 KiB, 2,048 values, 16 levels. Send less, or raise limits.maxMessageBytes.',
  ),
  MCP_INVENTORY_CLOCK_INVALID: entry(
    'inventory() could not read a valid time from the system clock.',
    'Fix the system clock and call inventory() again.',
  ),
  MCP_INVENTORY_INVALID: entry(
    'inventory() found an identifier or fingerprint it cannot report.',
    "Check that the guard option's registerTool returns the guard's sha256 fingerprint unchanged.",
  ),
  MCP_INVENTORY_LIMIT_EXCEEDED: entry(
    'The inventory would hold more than 256 operations or 2 MiB.',
    'Bind fewer operations on this connection.',
  ),
  MCP_OPERATION_FAILED: entry(
    'One remote call failed: a timeout, an abort, an error reply, an invalid or oversized result, a resource mismatch or a throwing measureCost.',
    'Only this call failed and its effect on the server is unknown. Check the server before preparing the call again; it is never retried automatically.',
  ),
  MESSAGE_BUDGET: entry(
    'The server sent more messages than limits.maxMessages within limits.messageWindowMs.',
    'The connection is quarantined. Call refresh() once the window has passed and approve again; raise the limits if the traffic is expected.',
  ),
  MESSAGE_REJECTED: entry(
    'A server message was malformed or over the size limits and answered no pending call.',
    'The connection is quarantined. Call refresh() and approve again; raise limits.maxMessageBytes if large messages are expected.',
  ),
  REDIRECT_DENIED: entry(
    'The HTTP endpoint answered with a redirect, or the response came from a different address.',
    'Configure the exact final endpoint address. Redirects are never followed.',
  ),
  REGISTRY_CHANGED: entry(
    'The server announced that its tools, resources or prompts changed.',
    'The connection is quarantined. Call refresh(), review the definitions (compare each descriptorDigest) and approve again.',
  ),
  REGISTRY_LIMIT: entry(
    'There are more bindings, or the server advertises more definitions, than limits.maxEntries.',
    'Raise limits.maxEntries (at most 256) or bind fewer operations.',
  ),
  REGISTRY_REJECTED: entry(
    "refresh() could not accept the server's registry: a list request failed, or the lists hold duplicate or malformed names or exceed a limit.",
    'The connection is quarantined and failureReason carries the specific code. Fix the server or the limits, then call refresh() again.',
  ),
  RESOURCE_MISMATCH: entry(
    'A resource read returned content for a different address than the bound one.',
    'Only this call failed. Check the server; the bound uri must be returned exactly.',
  ),
  RESPONSE_LIMIT: entry(
    'An HTTP response is larger than maxResponseBytes.',
    'Raise maxResponseBytes (at most 16 MiB) or have the server return less. Connect again after a long-lived stream reaches the limit.',
  ),
  SCHEMA_INVALID: entry(
    "A definition's schema is not valid JSON Schema, or a prompt's arguments are malformed.",
    'The operation is skipped and listed in skipped. Fix the definition on the server, then refresh().',
  ),
  SCHEMA_LIMIT: entry(
    "A definition's schema is too large once its local references are expanded, or combines more than eight alternatives.",
    'The operation is skipped and listed in skipped. Simplify the schema on the server, then refresh().',
  ),
  SCHEMA_REFERENCE_DENIED: entry(
    'A schema $ref points outside the schema itself, or to a location that does not exist.',
    'The operation is skipped and listed in skipped. Use only local references of the form #/..., then refresh().',
  ),
  SCHEMA_UNSUPPORTED: entry(
    'A schema uses a keyword, a dialect or a regular expression outside the supported profile.',
    'The operation is skipped and listed in skipped. Rewrite the schema within the profile, then refresh().',
  ),
});
