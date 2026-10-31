import { createHmac, randomUUID } from 'node:crypto';
import { immutableJson, type ToolDefinition } from '@shieldaai/agent-guard';
import { ExecutorError, type Ledger } from './store.js';

/** Trusted host enrollment; changing it creates a separate collector source. */
export interface InventorySourceOptions {
  readonly companyId: string;
  readonly sourceId: string;
  readonly enrollmentGeneration: string;
}
export interface InventoryOptions extends InventorySourceOptions {
  /** Opaque tenant-scoped resource and recipient references are the default. */
  readonly referenceMode?: 'opaque' | 'raw';
}
/** A snapshot always contains the complete task inventory for exactly one tenant. */
export interface InventoryScope { readonly tenantId: string }
export interface InventoryGrant { readonly tool: string; readonly resources: readonly string[] }
export interface InventoryBudget {
  readonly maxCalls: number; readonly maxConcurrent: number; readonly maxCost: number; readonly deadline: number;
}
export interface InventoryUsage {
  readonly calls: number; readonly concurrent: number; readonly spent: number; readonly reserved: number;
}
export interface InventoryTask {
  readonly id: string; readonly tenantId: string; readonly principalId: string;
  readonly parentTaskId: string | null; readonly sourceTaskId: string | null; readonly familyId: string;
  readonly grants: readonly InventoryGrant[]; readonly budget: InventoryBudget;
  readonly allowedRecipients: readonly string[]; readonly allowControlPlane: boolean;
  readonly revoked: boolean; readonly sensitive: boolean; readonly usage: InventoryUsage;
}
export interface InventoryTool {
  readonly name: string; readonly fingerprint: string; readonly revision: number;
  readonly registered: boolean; readonly approved: boolean;
  readonly requiresApproval: boolean | null; readonly controlPlane: boolean | null; readonly maxCost: number | null;
}
export interface InventorySnapshot {
  readonly schemaVersion: 1;
  readonly profile: 'core';
  readonly source: InventorySourceOptions & InventoryScope & { readonly inventoryInstanceId: string };
  readonly snapshotId: string; readonly generatedAt: string;
  readonly ledgerRevision: number; readonly policyEpoch: number;
  readonly coverage: {
    readonly tasks: { readonly status: 'complete'; readonly observedAt: string };
    readonly tools: { readonly status: 'complete'; readonly observedAt: string };
    readonly manifest: { readonly status: 'not_collected' };
    readonly mcp: { readonly status: 'not_collected' };
    readonly cloud: { readonly status: 'not_collected' };
  };
  readonly tasks: readonly InventoryTask[];
  readonly tools: readonly InventoryTool[];
}

type Registration = { readonly fingerprint: string; readonly revision: number; readonly definition: ToolDefinition };
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_VALUES = 500_000;
const MAX_SELECTORS = 100_000;
const STATE = 'INVENTORY_STATE_INVALID';
function fail(code = STATE): never { throw new ExecutorError(code); }
function limited(count: number, maximum: number): void { if (count > maximum) fail('INVENTORY_LIMIT_EXCEEDED'); }
function record(value: unknown, code = STATE): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return fail(code);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) return fail(code);
  return value as Record<string, unknown>;
}
/** Read data only: neither configuration nor registered flags may invoke accessors. */
function field(value: unknown, name: string, code = STATE): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record(value, code), name);
  if (!descriptor) return undefined;
  if (!('value' in descriptor)) return fail(code);
  return descriptor.value;
}
function identifier(value: unknown, code = STATE): string {
  if (typeof value !== 'string' || /^[\s\u001c-\u001f\u0085]*$/u.test(value) || value.includes('\0') ||
      // Reject unpaired surrogates: the Python consumer requires UTF-8 scalar values.
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) return fail(code);
  if ([...value].length > 4096) return fail(code);
  return value;
}
function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return fail();
  return value;
}
function boolean(value: unknown): boolean { if (typeof value !== 'boolean') return fail(); return value; }
function optionalBoolean(value: unknown): boolean { return value === undefined ? false : boolean(value); }
function array(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) return fail();
  return value;
}
function strings(value: unknown, maximum: number): string[] {
  const result = new Set<string>();
  for (const item of array(value)) { result.add(identifier(item)); limited(result.size, maximum); }
  return [...result].sort();
}
function closed(value: unknown, keys: readonly string[], code: string): void {
  const object = record(value, code);
  if (Object.getOwnPropertySymbols(object).length || Object.getOwnPropertyNames(object).length !== keys.length ||
      keys.some(key => !Object.hasOwn(object, key))) fail(code);
}

export function validateInventorySource(value: unknown): InventorySourceOptions {
  const code = 'INVENTORY_CONFIG_INVALID';
  closed(value, ['companyId', 'sourceId', 'enrollmentGeneration'], code);
  return Object.freeze({
    companyId: identifier(field(value, 'companyId', code), code),
    sourceId: identifier(field(value, 'sourceId', code), code),
    enrollmentGeneration: identifier(field(value, 'enrollmentGeneration', code), code),
  });
}

function relations(tasks: readonly InventoryTask[]): void {
  const byId = new Map(tasks.map(task => [task.id, task]));
  if (byId.size !== tasks.length) fail();
  const sensitivity = new Map<string, boolean>();
  for (const task of tasks) {
    if (sensitivity.has(task.familyId) && sensitivity.get(task.familyId) !== task.sensitive) fail();
    sensitivity.set(task.familyId, task.sensitive);
    for (const [kind, relatedId] of [['parent', task.parentTaskId], ['source', task.sourceTaskId]] as const) {
      if (relatedId === null) continue;
      const related = byId.get(relatedId);
      if (!related || related.familyId !== task.familyId ||
          (kind === 'parent' && related.principalId !== task.principalId)) fail();
    }
  }
  // Iterative DFS bounds call-stack use without imposing a new delegation-depth policy.
  const visited = new Map<string, number>();
  for (const task of tasks) {
    const stack: [string, boolean][] = [[task.id, false]];
    while (stack.length) {
      const [current, exiting] = stack.pop()!;
      if (exiting) { visited.set(current, 2); continue; }
      if (visited.get(current) === 1) fail();
      if (visited.get(current) === 2) continue;
      visited.set(current, 1);
      stack.push([current, true]);
      const related = byId.get(current)!;
      if (related.parentTaskId !== null) stack.push([related.parentTaskId, false]);
      if (related.sourceTaskId !== null) stack.push([related.sourceTaskId, false]);
    }
  }
}

/** Internal synchronous projection over one ledger read. No authorization callbacks or writes. */
export function projectInventory(
  state: Ledger,
  live: ReadonlyMap<string, Registration>,
  source: InventorySourceOptions,
  scope: InventoryScope,
  generatedAt: number,
  referenceKey?: Uint8Array,
): InventorySnapshot {
  const enrollment = validateInventorySource(source);
  const scopeCode = 'INVENTORY_SCOPE_INVALID';
  closed(scope, ['tenantId'], scopeCode);
  const tenantId = identifier(field(scope, 'tenantId', scopeCode), scopeCode);
  if (!Number.isSafeInteger(generatedAt) || generatedAt < 0 ||
      generatedAt > 253_402_300_799_999) fail('INVENTORY_CLOCK_INVALID');
  const timestamp = new Date(generatedAt).toISOString();
  if (referenceKey !== undefined && (!(referenceKey instanceof Uint8Array) || referenceKey.byteLength !== 32)) {
    fail('INVENTORY_CONFIG_INVALID');
  }
  // Repeated selectors share hashing work only during this snapshot. The bound
  // limits retained entries; reaching it never truncates inventory or skips validation.
  const resourceReferences = new Map<string, string>();
  const recipientReferences = new Map<string, string>();
  const reference = (kind: 'resource' | 'recipient', value: string): string => {
    if (referenceKey === undefined || (kind === 'resource' && value === '*')) return value;
    const cache = kind === 'resource' ? resourceReferences : recipientReferences;
    const existing = cache.get(value);
    if (existing !== undefined) return existing;
    const result = `opaque:${createHmac('sha256', referenceKey)
      .update(JSON.stringify(['agent-guard-inventory-v1', tenantId, kind, value])).digest('hex')}`;
    if (resourceReferences.size + recipientReferences.size < 1024) cache.set(value, result);
    return result;
  };
  const tasks: InventoryTask[] = [];
  const names = new Set<string>();
  let selectors = 0;
  const storedTasks = record(field(state, 'tasks'));
  const families = record(field(state, 'families'));
  for (const key of Object.keys(storedTasks).sort()) {
    const stored = field(storedTasks, key);
    const options = field(stored, 'options');
    // Tenant membership must be known before claiming complete coverage.
    const taskTenant = identifier(field(options, 'tenantId'));
    if (taskTenant !== tenantId) continue;
    limited(tasks.length + 1, 10_000);
    const taskId = identifier(field(options, 'id'));
    if (taskId !== key) fail();
    const familyId = identifier(field(stored, 'family'));
    const grants = new Map<string, Set<string>>();
    for (const raw of array(field(options, 'grants'))) {
      const tool = identifier(field(raw, 'tool'));
      const resources = grants.get(tool) ?? new Set<string>();
      for (const resource of array(field(raw, 'resources'))) {
        resources.add(identifier(resource)); limited(resources.size, 1024);
      }
      grants.set(tool, resources); limited(grants.size, 2048); names.add(tool);
    }
    const normalized = [...grants].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([tool, resources]) => {
      selectors += resources.size; limited(selectors, MAX_SELECTORS);
      return { tool, resources: [...resources].map(value => reference('resource', value)).sort() };
    });
    const rawBudget = field(options, 'budget');
    const deadline = field(rawBudget, 'deadline');
    if (typeof deadline !== 'number' || !Number.isFinite(deadline) || deadline < 0 || deadline > Number.MAX_SAFE_INTEGER) fail();
    const parent = field(stored, 'parent');
    const provenance = field(stored, 'sourceTaskId');
    tasks.push({
      id: taskId, tenantId, principalId: identifier(field(options, 'principalId')),
      parentTaskId: parent === null ? null : identifier(parent),
      sourceTaskId: provenance === undefined ? null : identifier(provenance),
      familyId, grants: normalized,
      budget: { maxCalls: integer(field(rawBudget, 'maxCalls')), maxConcurrent: integer(field(rawBudget, 'maxConcurrent')),
        maxCost: integer(field(rawBudget, 'maxCost')), deadline },
      allowedRecipients: strings(field(options, 'allowedRecipients') ?? [], 1024).map(value => reference('recipient', value)).sort(),
      allowControlPlane: optionalBoolean(field(options, 'allowControlPlane')),
      revoked: boolean(field(stored, 'revoked')), sensitive: boolean(field(field(families, familyId), 'sensitive')),
      usage: { calls: integer(field(stored, 'calls')), concurrent: integer(field(stored, 'concurrent')),
        spent: integer(field(stored, 'spent')), reserved: integer(field(stored, 'reserved')) },
    });
  }
  relations(tasks);
  const tools: InventoryTool[] = [];
  const storedTools = record(field(state, 'tools'));
  for (const name of [...names].sort()) {
    const stored = field(storedTools, name);
    if (stored === undefined) continue; // An unresolved grant is not invented tool metadata.
    limited(tools.length + 1, 10_000);
    const storedFingerprint = field(stored, 'fingerprint');
    if (typeof storedFingerprint !== 'string' || !/^(?:sha256:)?[a-f0-9]{64}$/.test(storedFingerprint)) fail();
    // Agent Guard's native fingerprint includes the algorithm; inventory v1 fixes SHA-256.
    const fingerprint = storedFingerprint.replace(/^sha256:/, '');
    const revision = integer(field(stored, 'revision'));
    const registration = live.get(name);
    const registered = registration !== undefined && field(registration, 'fingerprint') === storedFingerprint &&
      field(registration, 'revision') === revision;
    const definition = registered ? field(registration, 'definition') : undefined;
    tools.push({ name, fingerprint, revision, registered, approved: boolean(field(stored, 'approved')),
      requiresApproval: registered ? optionalBoolean(field(definition, 'requiresApproval')) : null,
      controlPlane: registered ? optionalBoolean(field(definition, 'controlPlane')) : null,
      maxCost: registered ? integer(field(definition, 'maxCost') ?? 0) : null });
  }
  const snapshot: InventorySnapshot = {
    schemaVersion: 1, profile: 'core',
    source: { companyId: enrollment.companyId, sourceId: enrollment.sourceId,
      enrollmentGeneration: enrollment.enrollmentGeneration,
      inventoryInstanceId: identifier(field(state, 'inventoryInstanceId')), tenantId },
    snapshotId: randomUUID(), generatedAt: timestamp,
    ledgerRevision: integer(field(state, 'revision')), policyEpoch: integer(field(state, 'epoch')),
    coverage: { tasks: { status: 'complete', observedAt: timestamp }, tools: { status: 'complete', observedAt: timestamp },
      manifest: { status: 'not_collected' }, mcp: { status: 'not_collected' }, cloud: { status: 'not_collected' } },
    tasks, tools,
  };
  // Python may serialize a fractional deadline with a longer exponent than JavaScript.
  // Reserve headroom per task so a producer-accepted snapshot also fits the consumer's 8 MiB cap.
  // Constructed fields above are JSON data; the remaining failure mode is a bounded output limit.
  try { return immutableJson(snapshot, 32, MAX_VALUES, MAX_BYTES - 16 * tasks.length) as unknown as InventorySnapshot; }
  catch { return fail('INVENTORY_LIMIT_EXCEEDED'); }
}
