/** Fixed private observer entrypoint. No database, network, host callbacks or inherited environment. */
import { parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import { ExecutorError, decodeLedgerObservation, decodeCoreInventoryObservation } from './store.js';
import { projectInventory, projectInventoryJson } from './inventory.js';
import { composeInventorySnapshot, type HostInventorySnapshot } from './inventory-manifest.js';
import { projectCapturedMcp, finishCapturedMcp, type McpRecheck } from './inventory-mcp-capture.js';
import type { McpInventorySnapshot } from './inventory-mcp.js';
import type { WorkerObservation } from './inventory-observer.js';
import { configureInventoryWorkerScheduling } from './inventory-scheduling.js';

const port = parentPort;
if (!port) throw new Error('INVENTORY_WORKER_UNAVAILABLE');
const scheduling = configureInventoryWorkerScheduling(workerData?.scheduling);
let pending: { request: WorkerObservation; snapshot: McpInventorySnapshot } | undefined;
const errors = new Set(['INVENTORY_SCOPE_INVALID', 'INVENTORY_STATE_INVALID', 'INVENTORY_LIMIT_EXCEEDED', 'INVENTORY_CLOCK_INVALID',
  'INVENTORY_CONFIG_INVALID', 'INVENTORY_MANIFEST_INVALID', 'INVENTORY_MANIFEST_LIMIT_EXCEEDED', 'INVENTORY_MANIFEST_SOURCE_MISMATCH',
  'INVENTORY_MANIFEST_REFERENCE_INVALID', 'INVENTORY_SNAPSHOT_INVALID', 'INVENTORY_MCP_INVALID', 'INVENTORY_MCP_LIMIT_EXCEEDED', 'INVENTORY_MCP_CONFIG_INVALID']);
function failed(id: number, error: unknown): void {
  port!.postMessage({ type: 'error', id, code: error instanceof ExecutorError && errors.has(error.code) ? error.code : 'INVENTORY_UNAVAILABLE' });
}
function publish(request: WorkerObservation,
  snapshot: Pick<ReturnType<typeof projectInventory> | HostInventorySnapshot | McpInventorySnapshot, 'profile' | 'source'>,
  serialized?: { readonly json: string; readonly bytes: number }): void {
  if (snapshot.profile !== request.profile || snapshot.source.tenantId !== request.scope.tenantId ||
      snapshot.source.companyId !== request.metadata.source.companyId || snapshot.source.sourceId !== request.metadata.source.sourceId ||
      snapshot.source.enrollmentGeneration !== request.metadata.source.enrollmentGeneration) throw new Error();
  const json = serialized?.json ?? JSON.stringify(snapshot), bytes = serialized?.bytes ?? Buffer.byteLength(json);
  if (bytes > 8 * 1024 * 1024) throw new ExecutorError('INVENTORY_LIMIT_EXCEEDED');
  port!.postMessage({ type: 'result', id: request.id, json, bytes, sha256: createHash('sha256').update(json).digest('hex'),
    profile: snapshot.profile, tenantId: snapshot.source.tenantId, companyId: snapshot.source.companyId,
    sourceId: snapshot.source.sourceId, enrollmentGeneration: snapshot.source.enrollmentGeneration });
}
port.on('message', (message: WorkerObservation | { type: 'mcp-after'; id: number; after: readonly McpRecheck[] }) => {
  const id = message?.id;
  if (!Number.isSafeInteger(id) || id < 1) { port.close(); return; }
  if (message.type === 'mcp-after') {
    const previous = pending; pending = undefined;
    try {
      if (!previous || previous.request.id !== id) throw new Error();
      publish(previous.request, finishCapturedMcp(previous.snapshot, previous.request.mcpBefore ?? [], message.after));
    } catch (error) { failed(id, error); }
    return;
  }
  if (message.type !== 'snapshot') { failed(id, undefined); return; }
  try {
    if (pending) throw new Error();
    const { ledger, metadata } = message;
    if (!(ledger.key instanceof Uint8Array) || ledger.key.byteLength !== 32 || typeof ledger.payload !== 'string' ||
        ledger.payload.length > ledger.maxBytes * 2 + 512) throw new Error();
    const decode = message.profile === 'core' ? decodeCoreInventoryObservation : decodeLedgerObservation;
    const state = decode(ledger.payload, ledger.key, ledger.maxBytes, ledger.witnessed);
    const mode = (state as typeof state & { recoveryMirror?: unknown }).recoveryMirror;
    // The owner checked the exact current mirror bytes. A decrypted state may not
    // introduce mirror semantics that were absent from that verified capture.
    if ((mode !== undefined || state.schema === 3 || ledger.mirror) &&
        (!ledger.witnessed || !ledger.mirror || mode !== 1 || state.schema !== 3)) throw new Error();
    if (message.profile === 'core') {
      const core = projectInventoryJson(state, new Map(metadata.registrations), metadata.source, message.scope,
        message.generatedAt, metadata.referenceKey);
      publish(message, core, core);
    } else {
      const core = projectInventory(state, new Map(metadata.registrations), metadata.source, message.scope,
        message.generatedAt, metadata.referenceKey);
      if (!message.manifest) throw new Error();
      const host = composeInventorySnapshot(core, message.manifest);
      if (message.profile === 'host') publish(message, host);
      else if (message.profile === 'host-mcp') {
        pending = { request: message, snapshot: projectCapturedMcp(host, message.mcpBefore ?? []) };
        port.postMessage({ type: 'mcp-after', id });
      }
      else throw new Error();
    }
  } catch (error) { failed(id, error); }
  finally { message.ledger?.key?.fill(0); message.metadata?.referenceKey?.fill(0); }
});
port.postMessage({ type: 'ready', scheduling });
