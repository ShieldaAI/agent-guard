import { randomUUID } from 'node:crypto';
import { isPromise } from 'node:util/types';
import { immutableJson, type Json } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';
import { composeInventorySnapshot, type HostInventorySnapshot } from './inventory-manifest.js';
import type { InventorySnapshot } from './inventory.js';

const INVALID = 'INVENTORY_MCP_INVALID';
const LIMIT = 'INVENTORY_MCP_LIMIT_EXCEEDED';
const CONFIG = 'INVENTORY_MCP_CONFIG_INVALID';
function fail(code = INVALID): never { throw new ExecutorError(code); }
function copy(value: unknown, bytes: number, values = 200_000): Json {
  try { return immutableJson(value, 32, values, bytes); }
  catch (error) { return fail(error instanceof Error && error.message.includes('limit') ? LIMIT : INVALID); }
}
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  const record = value as Record<string, unknown>;
  if (keys.some(key => !Object.hasOwn(record, key)) || Object.keys(record).some(key => !keys.includes(key))) fail();
  return record;
}
function identifier(value: unknown): string {
  if (typeof value !== 'string' || /^[\s\u001c-\u001f\u0085]*$/u.test(value) || value.includes('\0') ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value) ||
      [...value].length > 4096) return fail();
  return value;
}
function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return fail();
  return value;
}
function timestamp(value: unknown): string {
  if (typeof value !== 'string' || !/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)) return fail();
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19)) return fail();
  return value;
}

/** Detached observations only; neither the transport identity nor operations establish authorization. */
export interface InventoryMcpConnection {
  readonly schemaVersion: 1;
  readonly identity: {
    readonly serverId: string;
    readonly transportRef: string;
    readonly principalId: string;
    readonly tenantId: string;
  };
  readonly sessionId: string;
  readonly revision: number;
  readonly authorizationEpoch: number;
  readonly metadataRevision: number;
  readonly state: 'connecting' | 'refreshing' | 'ready' | 'quarantined' | 'closed';
  readonly metadataState: 'unobserved' | 'current' | 'stale';
  readonly observedAt: string;
  readonly operations: readonly {
    readonly name: string;
    readonly kind: 'tool' | 'resource' | 'prompt';
    readonly fingerprint: string;
  }[];
}
export interface InventoryMcpSourceBinding {
  readonly tenantId: string;
  readonly connectionId: string;
  readonly source: { inventory(): unknown };
}
export type InventoryMcpConnectionRecord =
  | { readonly connectionId: string; readonly status: 'observed'; readonly inventory: InventoryMcpConnection }
  | { readonly connectionId: string; readonly status: 'unavailable';
      readonly reason: 'missing' | 'capture_failed' | 'changed' | 'scope_mismatch' | 'registration_mismatch' };
export interface McpInventorySnapshot extends Omit<HostInventorySnapshot, 'profile' | 'coverage'> {
  readonly profile: 'host-mcp';
  readonly mcp: { readonly observedAt: string; readonly connections: readonly InventoryMcpConnectionRecord[] };
  readonly coverage: Omit<HostInventorySnapshot['coverage'], 'mcp'> & {
    readonly mcp: { readonly status: 'complete' | 'partial' | 'unavailable'; readonly observedAt: string };
  };
}

/** Validate closed, bounded data without invoking getters, serialization hooks or callbacks. */
export function validateMcpConnectionInventory(value: unknown): InventoryMcpConnection {
  const item = object(copy(value, 2 * 1024 * 1024), ['schemaVersion', 'identity', 'sessionId', 'revision',
    'authorizationEpoch', 'metadataRevision', 'state', 'metadataState', 'observedAt', 'operations']);
  if (item.schemaVersion !== 1) fail();
  const identity = object(item.identity, ['serverId', 'transportRef', 'principalId', 'tenantId']);
  identifier(identity.serverId); identifier(identity.principalId); identifier(identity.tenantId);
  if (typeof identity.transportRef !== 'string' || !/^opaque:[a-f0-9]{64}$/.test(identity.transportRef)) fail();
  identifier(item.sessionId); integer(item.revision); integer(item.authorizationEpoch);
  const metadataRevision = integer(item.metadataRevision); timestamp(item.observedAt);
  if (typeof item.state !== 'string' || !['connecting', 'refreshing', 'ready', 'quarantined', 'closed'].includes(item.state)) fail();
  if (!Array.isArray(item.operations)) fail();
  if (item.operations.length > 256) fail(LIMIT);
  if (item.state === 'ready') {
    if (item.metadataState !== 'current' || metadataRevision < 1) fail();
  } else if (item.operations.length || item.metadataState !== (metadataRevision === 0 ? 'unobserved' : 'stale')) fail();
  const names = new Set<string>();
  for (const value of item.operations) {
    const operation = object(value, ['name', 'kind', 'fingerprint']);
    const name = identifier(operation.name);
    if (names.has(name)) fail(); names.add(name);
    if (typeof operation.kind !== 'string' || !['tool', 'resource', 'prompt'].includes(operation.kind) ||
        typeof operation.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(operation.fingerprint)) fail();
  }
  return item as unknown as InventoryMcpConnection;
}

function dataFields(value: unknown, keys: readonly string[]): Record<string, PropertyDescriptor> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![null, Object.prototype].includes(Object.getPrototypeOf(value)) || Object.getOwnPropertySymbols(value).length) fail(CONFIG);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors, key) ||
      !('value' in descriptors[key]!) || !descriptors[key]!.enumerable)) fail(CONFIG);
  return descriptors;
}

/** Capture host reader methods once. The live source is intentionally retained, but its mutable registry is not. */
export function validateMcpInventorySources(sources: unknown): readonly InventoryMcpSourceBinding[] {
  try {
    if (!Array.isArray(sources) || Object.getPrototypeOf(sources) !== Array.prototype ||
        sources.length > 1024 || Object.getOwnPropertySymbols(sources).length ||
        Object.getOwnPropertyNames(sources).length !== sources.length + 1) fail(CONFIG);
    const bindings: InventoryMcpSourceBinding[] = []; const keys = new Set<string>();
    for (let i = 0; i < sources.length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(sources, String(i));
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) fail(CONFIG);
      const fields = dataFields(descriptor.value, ['tenantId', 'connectionId', 'source']);
      const tenantId = identifier(fields.tenantId!.value); const connectionId = identifier(fields.connectionId!.value);
      const key = JSON.stringify([tenantId, connectionId]); if (keys.has(key)) fail(CONFIG); keys.add(key);
      const source: unknown = fields.source!.value;
      if (!source || typeof source !== 'object') fail(CONFIG);
      let current: object | null = source; let method: unknown;
      for (let depth = 0; current !== null && depth < 32; depth++, current = Object.getPrototypeOf(current)) {
        const candidate = Object.getOwnPropertyDescriptor(current, 'inventory');
        if (candidate) {
          if (!('value' in candidate)) fail(CONFIG);
          method = candidate.value; break;
        }
      }
      if (typeof method !== 'function') fail(CONFIG);
      const captured = method;
      bindings.push(Object.freeze({ tenantId, connectionId,
        source: Object.freeze({ inventory: (): unknown => Reflect.apply(captured, source, []) }) }));
    }
    return Object.freeze(bindings);
  } catch { return fail(CONFIG); }
}

function hostSnapshot(value: unknown): HostInventorySnapshot {
  try {
    const input = object(copy(value, 8 * 1024 * 1024, 500_000), ['schemaVersion', 'profile', 'source', 'snapshotId',
      'generatedAt', 'ledgerRevision', 'policyEpoch', 'coverage', 'tasks', 'tools', 'manifest']);
    if (input.profile !== 'host') fail();
    const coverage = object(input.coverage, ['tasks', 'tools', 'manifest', 'mcp', 'cloud']);
    const manifestCoverage = object(coverage.manifest, ['status', 'observedAt']);
    if (manifestCoverage.status !== 'complete') fail(); timestamp(manifestCoverage.observedAt);
    const { manifest, ...core } = input;
    // Reuse authority/reference validation, then preserve the original capture and all validated fields.
    const checked = composeInventorySnapshot({ ...core, profile: 'core',
      coverage: { ...coverage, manifest: { status: 'not_collected' } } } as unknown as InventorySnapshot,
    manifest as HostInventorySnapshot['manifest']);
    if (manifestCoverage.observedAt !== checked.manifest.observedAt) fail();
    return input as unknown as HostInventorySnapshot;
  } catch (error) {
    if (error instanceof ExecutorError && [LIMIT, 'INVENTORY_LIMIT_EXCEEDED', 'INVENTORY_MANIFEST_LIMIT_EXCEEDED'].includes(error.code)) {
      fail('INVENTORY_LIMIT_EXCEEDED');
    }
    return fail('INVENTORY_SNAPSHOT_INVALID');
  }
}

function capture(binding: InventoryMcpSourceBinding): InventoryMcpConnection | undefined {
  try {
    const result = binding.source.inventory();
    // Readers are synchronous. Observe genuine rejected promises without executing arbitrary thenables.
    if (isPromise(result)) { Promise.prototype.then.call(result, undefined, () => undefined); return undefined; }
    return validateMcpConnectionInventory(result);
  } catch { return undefined; }
}
function stable(value: InventoryMcpConnection): string {
  const { observedAt: _time, ...rest } = value;
  return JSON.stringify(rest);
}

/** Separate captures, never an atomic authorization decision. Only explicitly bound tenant sources are read. */
export function composeMcpInventorySnapshot(base: HostInventorySnapshot,
  sources: readonly InventoryMcpSourceBinding[]): McpInventorySnapshot {
  const snapshot = hostSnapshot(base);
  const bindings = validateMcpInventorySources(sources);
  const expected = new Map<string, Set<string>>();
  for (const binding of snapshot.manifest.executionBindings) {
    if (binding.connectionId === null) continue;
    let names = expected.get(binding.connectionId);
    if (!names) { names = new Set(); expected.set(binding.connectionId, names); }
    names.add(binding.tool);
  }
  if (expected.size > 128) fail(LIMIT);
  const selected = new Map(bindings.filter(binding => binding.tenantId === snapshot.source.tenantId &&
    expected.has(binding.connectionId)).map(binding => [binding.connectionId, binding]));
  // Capture every selected source before projection and again afterwards to detect intervening lifecycle changes.
  const first = new Map([...selected].map(([id, binding]) => [id, capture(binding)]));
  const tools = new Map(snapshot.tools.map(tool => [tool.name, tool]));
  const projected = new Map<string, InventoryMcpConnectionRecord>();
  let operationCount = 0;
  for (const [connectionId, names] of expected) {
    const unavailable = (reason: Extract<InventoryMcpConnectionRecord, { status: 'unavailable' }>['reason']): void => {
      projected.set(connectionId, { connectionId, status: 'unavailable', reason });
    };
    if (!selected.has(connectionId)) { unavailable('missing'); continue; }
    const inventory = first.get(connectionId);
    if (!inventory) { unavailable('capture_failed'); continue; }
    if (inventory.identity.tenantId !== snapshot.source.tenantId) { unavailable('scope_mismatch'); continue; }
    const operations = inventory.operations.filter(operation => names.has(operation.name));
    if (operations.some(operation => {
      const tool = tools.get(operation.name);
      return !tool?.registered || tool.fingerprint !== operation.fingerprint;
    })) { unavailable('registration_mismatch'); continue; }
    operationCount += operations.length;
    if (operationCount > 10_000) fail(LIMIT);
    projected.set(connectionId, { connectionId, status: 'observed', inventory: { ...inventory, operations } });
  }
  for (const [connectionId, binding] of selected) {
    const before = first.get(connectionId); const after = capture(binding);
    if (!after) projected.set(connectionId, { connectionId, status: 'unavailable', reason: 'capture_failed' });
    else if (after.identity.tenantId !== snapshot.source.tenantId) {
      projected.set(connectionId, { connectionId, status: 'unavailable', reason: 'scope_mismatch' });
    } else if (before && stable(before) !== stable(after)) {
      projected.set(connectionId, { connectionId, status: 'unavailable', reason: 'changed' });
    }
  }
  const now = Date.now();
  if (!Number.isSafeInteger(now) || now < 0 || now > 253_402_300_799_999) fail('INVENTORY_CLOCK_INVALID');
  const observedAt = new Date(now).toISOString();
  const connections = [...projected.values()].sort((left, right) => left.connectionId < right.connectionId ? -1 : left.connectionId > right.connectionId ? 1 : 0);
  const observed = connections.filter(connection => connection.status === 'observed').length;
  const status = observed === connections.length ? 'complete' : observed === 0 ? 'unavailable' : 'partial';
  const result: McpInventorySnapshot = {
    ...snapshot, profile: 'host-mcp', snapshotId: randomUUID(), generatedAt: observedAt,
    mcp: { observedAt, connections }, coverage: { ...snapshot.coverage, mcp: { status, observedAt } },
  };
  try { return immutableJson(result, 32, 500_000, 8 * 1024 * 1024 - 16 * snapshot.tasks.length) as unknown as McpInventorySnapshot; }
  catch { return fail('INVENTORY_LIMIT_EXCEEDED'); }
}
