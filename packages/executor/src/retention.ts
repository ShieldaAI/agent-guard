import { ExecutorError, type Ledger, type StoredAction } from './store.js';

/**
 * Per-tenant retention for settled receipts, their compact stubs and recent events.
 *
 * Every store is bounded. A tenant's own traffic evicts that tenant's oldest entries
 * (per family, then per tenant). Only when a store-wide bound is reached does the
 * tenant holding the most entries lose its oldest, so a tenant at or below an equal
 * share never loses an entry to another tenant's traffic. Events with no tenant
 * (executor start, tool approval, policy change) live in their own system bucket,
 * which tenant events never evict.
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

/** Stubs kept per family, per tenant and in the whole ledger. */
export interface StubLimits {
  perFamily: number;
  perTenant: number;
  total: number;
}
/**
 * 256 stubs per family and 1,024 per tenant. The ledger-wide total is one stub per
 * 4 KiB of `maxLedgerBytes`, between 256 and 4,096 (4,096 at the default 16 MiB).
 */
export function stubLimits(maxLedgerBytes: number): StubLimits {
  const total = Math.max(256, Math.min(4096, Math.floor(maxLedgerBytes / 4096)));
  const perTenant = Math.min(1024, total);
  return { perFamily: Math.min(256, perTenant), perTenant, total };
}
/** Recent events kept in total; per-tenant caps keep any one tenant to a fair share. */
export const RECENT_EVENTS_TOTAL = 1000;
export const DEFAULT_RECENT_EVENTS_PER_TENANT = 256;
/** Owner of events and entries that belong to no tenant. */
const SYSTEM = '';

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

function largest(counts: Map<string, number>, skip?: string): string | undefined {
  let selected: string | undefined;
  let size = 0;
  for (const [key, count] of counts)
    if (key !== skip && count > size) {
      selected = key;
      size = count;
    }
  return selected;
}

/** Event owner: explicit tenant, the task's tenant, or the system bucket. */
function bucket(state: Ledger, event: Ledger['audit'][number]): string {
  if (event.tenantId !== undefined) return event.tenantId;
  return (event.taskId === undefined ? undefined : own(state.tasks, event.taskId)?.options.tenantId) ?? SYSTEM;
}

export interface EventScope {
  taskId?: string;
  actionId?: string;
  tenantId?: string;
}

/**
 * Append one recent event, then enforce the owner's cap and the total cap. The total cap
 * trims the tenant holding the most events; the system bucket is trimmed only by its own cap.
 */
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
  // No cap can be exceeded while the whole ring is within one owner's allowance.
  if (state.audit.length <= perTenant && state.audit.length <= RECENT_EVENTS_TOTAL) return;
  const owner = tenantId ?? SYSTEM;
  let held = 0;
  for (const entry of state.audit) if (bucket(state, entry) === owner) held++;
  let excess = held - perTenant;
  if (excess > 0)
    state.audit = state.audit.filter(entry => !(excess > 0 && bucket(state, entry) === owner && excess-- > 0));
  if (state.audit.length <= RECENT_EVENTS_TOTAL) return;
  const owners = state.audit.map(entry => bucket(state, entry));
  const counts = new Map<string, number>();
  for (const key of owners) counts.set(key, (counts.get(key) ?? 0) + 1);
  const remove = new Set<number>();
  for (let total = owners.length; total > RECENT_EVENTS_TOTAL; total--) {
    const busiest = largest(counts, SYSTEM) ?? SYSTEM;
    remove.add(owners.findIndex((key, position) => key === busiest && !remove.has(position)));
    counts.set(busiest, counts.get(busiest)! - 1);
  }
  state.audit = state.audit.filter((_entry, index) => !remove.has(index));
}

/** A family belongs to one tenant: its root task's, else the tenant of a task named by one of its stubs. */
function familyTenant(state: Ledger, family: string, stubs: Record<string, PrunedReceipt>): string {
  const root = own(state.tasks, family)?.options.tenantId;
  if (root !== undefined) return root;
  for (const stub of Object.values(stubs)) {
    const tenant = own(state.tasks, stub.taskId)?.options.tenantId;
    if (tenant !== undefined) return tenant;
  }
  return SYSTEM;
}

/**
 * Record a compact stub for a settled receipt that retention removed. The family's and the
 * tenant's own oldest stubs go first; the ledger-wide total takes from the tenant holding the most.
 */
export function recordPruned(state: Ledger, family: string, action: StoredAction, limits: StubLimits): void {
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
  for (const id of ids.slice(0, Math.max(0, ids.length - limits.perFamily))) delete stubs[id];
  // One pass over the families: how many stubs each tenant holds, and in which families.
  const sizes = new Map<string, number>();
  const tenants = new Map<string, number>();
  const families = new Map<string, string[]>();
  let total = 0;
  for (const [key, group] of Object.entries(retained.pruned)) {
    const size = Object.keys(group).length;
    const tenant = familyTenant(state, key, group);
    sizes.set(key, size);
    tenants.set(tenant, (tenants.get(tenant) ?? 0) + size);
    const list = families.get(tenant);
    if (list) list.push(key);
    else families.set(tenant, [key]);
    total += size;
  }
  const dropOldest = (tenant: string): void => {
    let busiest = '';
    let size = 0;
    for (const key of families.get(tenant)!)
      if (sizes.get(key)! > size) {
        busiest = key;
        size = sizes.get(key)!;
      }
    const group = retained.pruned[busiest]!;
    delete group[Object.keys(group)[0]!];
    sizes.set(busiest, size - 1);
    tenants.set(tenant, tenants.get(tenant)! - 1);
    total--;
    if (size === 1) delete retained.pruned[busiest];
  };
  const tenant = familyTenant(state, family, stubs);
  while (tenants.get(tenant)! > limits.perTenant) dropOldest(tenant);
  while (total > limits.total) dropOldest(largest(tenants)!);
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
