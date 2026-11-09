import { ExecutorError, type Ledger, type StoredAction } from './store.js';

/**
 * Tenant-fair retention for settled receipts and recent events.
 *
 * Both stores are bounded. When a bound is reached, entries are removed from the
 * busiest owner (task family for receipts, tenant for events), oldest first, so
 * one tenant's traffic cannot evict another tenant's history.
 *
 * The state is additive: older code ignores `retention` and the extra event
 * fields, so no schema change is needed.
 */
export interface PrunedReceipt {
  taskId: string;
  outcome: 'SUCCEEDED' | 'FAILED';
  charged?: number;
  reconciliation?: { referenceHash: string; time: number };
}
export interface RetentionState {
  version: 1;
  /** Monotonic event sequence; a gap in exported events means they were evicted. */
  sequence: number;
  /** Per-family compact stubs for pruned settled receipts, oldest first. */
  pruned: Record<string, Record<string, PrunedReceipt>>;
}
type RetentionLedger = Ledger;

/** Stubs kept per family, and in total across families. */
export const PRUNED_PER_FAMILY = 256;
export const PRUNED_TOTAL = 1024;
/** Recent events kept in total; per-tenant caps keep any one tenant to a fair share. */
export const RECENT_EVENTS_TOTAL = 1000;
export const DEFAULT_RECENT_EVENTS_PER_TENANT = 256;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function own<T>(value: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

function retention(state: Ledger, create: boolean): RetentionState | undefined {
  const ledger = state as RetentionLedger;
  const value = ledger.retention;
  if (value === undefined) {
    if (!create) return undefined;
    return (ledger.retention = { version: 1, sequence: 0, pruned: Object.create(null) });
  }
  if (
    !record(value) ||
    value.version !== 1 ||
    !Number.isSafeInteger(value.sequence) ||
    value.sequence < 0 ||
    !record(value.pruned)
  ) {
    throw new ExecutorError('RETENTION_STATE_INVALID');
  }
  return value;
}

function largest<K>(counts: Map<K, number>): K | undefined {
  let selected: K | undefined;
  let size = 0;
  for (const [key, count] of counts)
    if (count > size) {
      selected = key;
      size = count;
    }
  return selected;
}

/** Event owner: explicit tenant, the task's tenant, or the shared system bucket (''). */
function bucket(state: Ledger, event: Ledger['audit'][number]): string {
  if (event.tenantId !== undefined) return event.tenantId;
  return (event.taskId === undefined ? undefined : own(state.tasks, event.taskId)?.options.tenantId) ?? '';
}

export interface EventScope {
  taskId?: string;
  actionId?: string;
  tenantId?: string;
}

/** Append one recent event and enforce the per-tenant cap and the fair total cap. */
export function recordEvent(
  state: Ledger,
  perTenant: number,
  time: number,
  event: string,
  scope: EventScope = {},
): void {
  const retained = retention(state, true)!;
  const tenantId =
    scope.tenantId ?? (scope.taskId === undefined ? undefined : own(state.tasks, scope.taskId)?.options.tenantId);
  retained.sequence++;
  state.audit.push({
    time,
    event,
    sequence: retained.sequence,
    ...(tenantId === undefined ? {} : { tenantId }),
    ...(scope.taskId === undefined ? {} : { taskId: scope.taskId }),
    ...(scope.actionId === undefined ? {} : { actionId: scope.actionId }),
  });
  const owner = tenantId ?? '';
  const owners = state.audit.map(entry => bucket(state, entry));
  const counts = new Map<string, number>();
  for (const key of owners) counts.set(key, (counts.get(key) ?? 0) + 1);
  const remove = new Set<number>();
  let excess = (counts.get(owner) ?? 0) - perTenant;
  for (let index = 0; excess > 0 && index < owners.length; index++) {
    if (owners[index] === owner) {
      remove.add(index);
      excess--;
      counts.set(owner, counts.get(owner)! - 1);
    }
  }
  let total = state.audit.length - remove.size;
  while (total > RECENT_EVENTS_TOTAL) {
    const busiest = largest(counts)!;
    const index = owners.findIndex((key, position) => key === busiest && !remove.has(position));
    remove.add(index);
    counts.set(busiest, counts.get(busiest)! - 1);
    total--;
  }
  if (remove.size) state.audit = state.audit.filter((_entry, index) => !remove.has(index));
}

/** Record a compact stub for a settled receipt that retention removed. */
export function recordPruned(state: Ledger, family: string, action: StoredAction): void {
  if (action.status !== 'SUCCEEDED' && action.status !== 'FAILED') return;
  const retained = retention(state, true)!;
  const stubs =
    own(retained.pruned, family) ?? (retained.pruned[family] = Object.create(null) as Record<string, PrunedReceipt>);
  stubs[action.id] = {
    taskId: action.taskId,
    outcome: action.status,
    ...(action.charged === undefined ? {} : { charged: action.charged }),
    ...(action.reconciliation === undefined ? {} : { reconciliation: { ...action.reconciliation } }),
  };
  const ids = Object.keys(stubs);
  for (const id of ids.slice(0, Math.max(0, ids.length - PRUNED_PER_FAMILY))) delete stubs[id];
  const counts = new Map(Object.entries(retained.pruned).map(([key, value]) => [key, Object.keys(value).length]));
  let total = [...counts.values()].reduce((sum, count) => sum + count, 0);
  while (total > PRUNED_TOTAL) {
    const busiest = largest(counts)!;
    const group = retained.pruned[busiest]!;
    delete group[Object.keys(group)[0]!];
    counts.set(busiest, counts.get(busiest)! - 1);
    total--;
    if (!counts.get(busiest)) {
      delete retained.pruned[busiest];
      counts.delete(busiest);
    }
  }
}

export function prunedReceipt(state: Ledger, family: string, actionId: string): PrunedReceipt | undefined {
  const group = own(retention(state, false)?.pruned ?? {}, family);
  const stub = group && own(group, actionId);
  return stub &&
    record(stub) &&
    typeof stub.taskId === 'string' &&
    (stub.outcome === 'SUCCEEDED' || stub.outcome === 'FAILED')
    ? stub
    : undefined;
}

export function familyStubs(state: Ledger, family: string): Record<string, PrunedReceipt> {
  const stubs = own(retention(state, false)?.pruned ?? {}, family);
  return stubs ? { ...stubs } : {};
}
/** Archive moves a family's stubs into the archive together with its actions. */
export function takeFamilyStubs(state: Ledger, family: string): Record<string, PrunedReceipt> {
  const retained = retention(state, false);
  const stubs = retained && own(retained.pruned, family);
  if (!stubs) return {};
  delete retained.pruned[family];
  return stubs;
}
