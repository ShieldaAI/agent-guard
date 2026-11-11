/** Private observer bridge: live host callbacks stay on the owning thread. */
import { createHash } from 'node:crypto';
import { isPromise } from 'node:util/types';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { ExecutorError } from './store.js';
import {
  composeMcpInventorySnapshot,
  validateMcpConnectionInventory,
  type InventoryMcpConnection,
  type InventoryMcpSourceBinding,
  type McpInventorySnapshot,
} from './inventory-mcp.js';
import type { HostInventorySnapshot, InventoryManifest } from './inventory-manifest.js';

export interface McpCapture {
  readonly tenantId: string;
  readonly connectionId: string;
  readonly inventory: InventoryMcpConnection | null;
  readonly digest: string | null;
}
export interface McpRecheck {
  readonly connectionId: string;
  readonly tenantId: string | null;
  readonly digest: string | null;
}
function capture(binding: InventoryMcpSourceBinding): InventoryMcpConnection | null {
  try {
    const value = binding.source.inventory();
    if (isPromise(value)) {
      Promise.prototype.then.call(value, undefined, () => undefined);
      return null;
    }
    return validateMcpConnectionInventory(value);
  } catch {
    return null;
  }
}
function digest(value: InventoryMcpConnection): string {
  const { observedAt: _observedAt, ...state } = value;
  return createHash('sha256').update(JSON.stringify(state)).digest('hex');
}
function selected(
  manifest: InventoryManifest,
  sources: readonly InventoryMcpSourceBinding[],
): readonly InventoryMcpSourceBinding[] {
  const expected = new Set(
    manifest.executionBindings.flatMap(binding => (binding.connectionId === null ? [] : [binding.connectionId])),
  );
  if (expected.size > 128) throw new ExecutorError('INVENTORY_MCP_LIMIT_EXCEEDED');
  return sources.filter(binding => binding.tenantId === manifest.source.tenantId && expected.has(binding.connectionId));
}
export function captureMcpBefore(
  manifest: InventoryManifest,
  sources: readonly InventoryMcpSourceBinding[],
): readonly McpCapture[] {
  let operationCount = 0,
    bytes = 2;
  const expected = new Map<string, Set<string>>();
  for (const binding of manifest.executionBindings)
    if (binding.connectionId !== null) {
      const names = expected.get(binding.connectionId) ?? new Set<string>();
      names.add(binding.tool);
      expected.set(binding.connectionId, names);
    }
  return selected(manifest, sources).map(binding => {
    const inventory = capture(binding);
    // Hash the complete validated lifecycle, but transfer only operations the
    // manifest could expose. Unselected operation changes still fail recheck.
    const stateDigest = inventory ? digest(inventory) : null;
    const operations =
      inventory?.operations.filter(operation => expected.get(binding.connectionId)!.has(operation.name)) ?? [];
    operationCount += operations.length;
    if (operationCount > 10_000) throw new ExecutorError('INVENTORY_MCP_LIMIT_EXCEEDED');
    const value = {
      tenantId: binding.tenantId,
      connectionId: binding.connectionId,
      inventory: inventory ? { ...inventory, operations } : null,
      digest: stateDigest,
    };
    bytes += Buffer.byteLength(JSON.stringify(value)) + 1;
    if (bytes > 8 * 1024 * 1024) throw new ExecutorError('INVENTORY_MCP_LIMIT_EXCEEDED');
    return value;
  });
}
export function captureMcpAfter(
  manifest: InventoryManifest,
  sources: readonly InventoryMcpSourceBinding[],
): readonly McpRecheck[] {
  return selected(manifest, sources).map(binding => {
    const inventory = capture(binding);
    return {
      connectionId: binding.connectionId,
      tenantId: inventory?.identity.tenantId ?? null,
      digest: inventory ? digest(inventory) : null,
    };
  });
}
/** Reuse the public projection/limits; only live capture and its lifecycle comparison are split across threads. */
export function projectCapturedMcp(
  snapshot: HostInventorySnapshot,
  before: readonly McpCapture[],
): McpInventorySnapshot {
  return composeMcpInventorySnapshot(
    snapshot,
    before.map(value => ({
      tenantId: value.tenantId,
      connectionId: value.connectionId,
      source: { inventory: () => value.inventory },
    })),
  );
}
export function finishCapturedMcp(
  base: McpInventorySnapshot,
  before: readonly McpCapture[],
  after: readonly McpRecheck[],
): McpInventorySnapshot {
  const first = new Map(before.map(value => [value.connectionId, value]));
  const second = new Map(after.map(value => [value.connectionId, value]));
  if (
    first.size !== before.length ||
    second.size !== after.length ||
    first.size !== second.size ||
    before.length > 128 ||
    before.some(value => !second.has(value.connectionId))
  )
    throw new ExecutorError('INVENTORY_MCP_INVALID');
  const connections = base.mcp.connections.map(connection => {
    const earlier = first.get(connection.connectionId),
      later = second.get(connection.connectionId);
    if (!later) return connection; // Missing source bindings remain explicitly missing.
    const unavailable = (reason: 'capture_failed' | 'scope_mismatch' | 'changed') => ({
      connectionId: connection.connectionId,
      status: 'unavailable' as const,
      reason,
    });
    if (later.digest === null) return unavailable('capture_failed');
    if (later.tenantId !== base.source.tenantId) return unavailable('scope_mismatch');
    if (earlier?.inventory && earlier.digest !== later.digest) return unavailable('changed');
    return connection;
  });
  const observed = connections.filter(connection => connection.status === 'observed').length;
  const status = observed === connections.length ? 'complete' : observed === 0 ? 'unavailable' : 'partial';
  try {
    return immutableJson(
      {
        ...base,
        mcp: { ...base.mcp, connections },
        coverage: { ...base.coverage, mcp: { ...base.coverage.mcp, status } },
      },
      32,
      500_000,
      8 * 1024 * 1024 - 16 * base.tasks.length,
    ) as unknown as McpInventorySnapshot;
  } catch {
    throw new ExecutorError('INVENTORY_LIMIT_EXCEEDED');
  }
}
