import { createHmac, randomBytes } from 'node:crypto';
import { immutableJson } from '@shieldaai/agent-guard';
import { McpBoundaryError } from './boundary.js';

export type McpConnectionState = 'connecting' | 'refreshing' | 'ready' | 'quarantined' | 'closed';
export type McpMetadataState = 'unobserved' | 'current' | 'stale';
export interface McpInventoryIdentity {
  readonly serverId: string;
  readonly transportRef: string;
  readonly principalId: string;
  readonly tenantId: string;
}
export interface McpInventoryOperation {
  readonly name: string;
  readonly kind: 'tool' | 'resource' | 'prompt';
  readonly fingerprint: string;
}
/** Observed registrations, never proof that an operation is approved or executable. */
export interface McpConnectionInventory {
  readonly schemaVersion: 1;
  readonly identity: McpInventoryIdentity;
  readonly sessionId: string;
  readonly revision: number;
  readonly authorizationEpoch: number;
  readonly metadataRevision: number;
  readonly state: McpConnectionState;
  readonly metadataState: McpMetadataState;
  readonly observedAt: string;
  readonly operations: readonly McpInventoryOperation[];
}

/** An opaque session-local reference cannot be used to guess a low-entropy endpoint. */
export function opaqueTransportRef(identity: string): string {
  const key = randomBytes(32);
  try { return `opaque:${createHmac('sha256', key).update(identity).digest('hex')}`; }
  finally { key.fill(0); }
}

function identifier(value: unknown): string {
  if (typeof value !== 'string' || /^[\s\u001c-\u001f\u0085]*$/u.test(value) || value.includes('\0') ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value) ||
      [...value].length > 4096) throw new McpBoundaryError('MCP_INVENTORY_INVALID');
  return value;
}
function integer(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new McpBoundaryError('MCP_INVENTORY_INVALID');
  return value;
}

/** Called only with connection-owned fields; copies an explicit, bounded allowlist. */
export function mcpInventorySnapshot(input: {
  identity: McpInventoryIdentity;
  sessionId: string;
  revision: number;
  authorizationEpoch: number;
  metadataRevision: number;
  state: McpConnectionState;
  registrations: readonly McpInventoryOperation[];
}): McpConnectionInventory {
  const observedAt = Date.now();
  if (!Number.isSafeInteger(observedAt) || observedAt < 0 || observedAt > 253_402_300_799_999) throw new McpBoundaryError('MCP_INVENTORY_CLOCK_INVALID');
  const identity = {
    serverId: identifier(input.identity.serverId), transportRef: identifier(input.identity.transportRef),
    principalId: identifier(input.identity.principalId), tenantId: identifier(input.identity.tenantId),
  };
  const operations = input.state === 'ready' ? input.registrations : [];
  if (operations.length > 256) throw new McpBoundaryError('MCP_INVENTORY_LIMIT_EXCEEDED');
  const projected = operations.map(operation => {
    if (typeof operation.fingerprint !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(operation.fingerprint) ||
        !['tool', 'resource', 'prompt'].includes(operation.kind)) throw new McpBoundaryError('MCP_INVENTORY_INVALID');
    return { name: identifier(operation.name), kind: operation.kind, fingerprint: operation.fingerprint.slice(7) };
  }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  const snapshot: McpConnectionInventory = {
    schemaVersion: 1, identity, sessionId: identifier(input.sessionId), revision: integer(input.revision),
    authorizationEpoch: integer(input.authorizationEpoch), metadataRevision: integer(input.metadataRevision),
    state: input.state, metadataState: input.state === 'ready' ? 'current' : input.metadataRevision === 0 ? 'unobserved' : 'stale',
    observedAt: new Date(observedAt).toISOString(), operations: projected,
  };
  try { return immutableJson(snapshot, 8, 2048, 2 * 1024 * 1024) as unknown as McpConnectionInventory; }
  catch { throw new McpBoundaryError('MCP_INVENTORY_LIMIT_EXCEEDED'); }
}
