import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { familyStubs, takeFamilyStubs, recordEvent, DEFAULT_RECENT_EVENTS_PER_TENANT } from './retention.js';
import {
  ExecutorError,
  executionStatuses,
  type ExecutionStatus,
  type Ledger,
  type LedgerStore,
  type StoredTask,
  type StoredAction,
} from './store.js';

const MAX_ARCHIVES = 4096;
const MAX_ARCHIVED_IDS = 65_536;
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_PLAIN_BYTES = 16 * 1024 * 1024;
const MAX_SCAN_RECORDS = 100_000;
const unresolved = new Set<ExecutionStatus>(['ADMITTED', 'RUNNING', 'UNKNOWN']);
const sha = (value: string): string => createHash('sha256').update(value).digest('hex');
const taskDigest = (id: string): string => sha(`agent-guard-archived-task-v1\0${id}`);
const memoryDigest = (tenantId: string, id: string): string =>
  sha(JSON.stringify(['agent-guard-archived-memory-v1', tenantId, id]));
const tenantDigest = (id: string): string => sha(`agent-guard-archive-tenant-v1\0${id}`);
const own = <T>(record: Record<string, T>, key: string): T | undefined =>
  Object.hasOwn(record, key) ? record[key] : undefined;
function fail(code: string): never {
  throw new ExecutorError(code);
}
function text(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 4096 || value.includes('\0'))
    fail('LIFECYCLE_SCOPE_INVALID');
  return value;
}
function snapshot<T>(value: T): Readonly<T> {
  return immutableJson(value, 32, 100_000, 2 * 1024 * 1024) as Readonly<T>;
}
function input<T>(value: T, allowed: readonly string[]): T {
  let copy: T;
  try {
    copy = immutableJson(value, 8, 512, 32 * 1024) as T;
  } catch {
    return fail('LIFECYCLE_SCOPE_INVALID');
  }
  if (!copy || typeof copy !== 'object' || Array.isArray(copy) || Object.keys(copy).some(key => !allowed.includes(key)))
    fail('LIFECYCLE_SCOPE_INVALID');
  return copy;
}
export interface TaskFamilyScope {
  tenantId: string;
  taskId: string;
}
export interface TaskFamilyDecision extends TaskFamilyScope {
  expectedDigest: string;
}
export interface TaskFamilyCounts {
  tasks: number;
  actions: number;
  preparedActions: number;
  unresolvedActions: number;
  memoryEntries: number;
  memoryVersions: number;
}
export interface TaskFamilyRetirementPreview {
  tenantId: string;
  taskId: string;
  familyId: string;
  revision: number;
  reviewDigest: string;
  retired: boolean;
  counts: Readonly<TaskFamilyCounts>;
  retirementBlockers: readonly string[];
  archiveBlockers: readonly string[];
}
export interface TaskFamilyRetirementResult {
  tenantId: string;
  familyId: string;
  retiredAt: number;
  tasksRevoked: number;
  preparationsCancelled: number;
}
export interface TaskFamilyArchiveScope {
  tenantId: string;
  archiveId: string;
}
export interface TaskFamilyArchiveReceipt {
  archiveId: string;
  tenantId: string;
  familyId: string;
  retiredAt: number;
  archivedAt: number;
  counts: Readonly<TaskFamilyCounts>;
  ciphertextSha256: string;
  encryptedBytes: number;
  /** Decimal strings avoid overflow when summing independent root budgets. */
  rootUsage: Readonly<{ calls: string; spent: string }>;
}
export interface ExecutionListScope {
  tenantId: string;
  statuses?: readonly ExecutionStatus[];
  limit?: number;
  cursor?: string;
}
export interface ExecutionList {
  tenantId: string;
  revision: number;
  total: number;
  items: readonly Readonly<{
    actionId: string;
    taskId: string;
    tool: string;
    status: ExecutionStatus;
    charged?: number;
    reservedMaximum: number;
  }>[];
  nextCursor: string | null;
}
export interface MaintenanceStatistics {
  tenantId: string;
  tasks: number;
  families: number;
  retiredFamilies: number;
  actions: number;
  unresolvedActions: number;
  memoryEntries: number;
  archives: number;
  archivedTasks: number;
  /** Deployment-wide decoded ledger size; these are not tenant-specific byte counts. */
  ledgerBytes: number;
  ledgerByteLimit: number;
  retentionLimits: Readonly<{ archives: number; archivedIdentifiers: number; encryptedArchiveBytes: number }>;
}
interface ArchiveEntry {
  tenantDigest: string;
  familyDigest: string;
  keyBase64: string;
  cipherSha256: string;
  plainBytes: number;
  cipherBytes: number;
  retiredAt: number;
  archivedAt: number;
  counts: TaskFamilyCounts;
  rootUsage: { calls: string; spent: string };
}
export interface LifecycleState {
  version: 1;
  retiredFamilies: Record<string, { tenantDigest: string; retiredAt: number }>;
  archivedTaskIds: Record<string, string>;
  archivedMemoryIds: string[];
  archives: Record<string, ArchiveEntry>;
  externalHeads?: Record<string, { hash: string; namespace: string; through: number }>;
  namespaceFences?: Record<string, { tenantDigest: string; through: number }>;
}
type LifecycleLedger = Ledger;
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function safeCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function lifecycle(state: Ledger, create = false): LifecycleState | undefined {
  if (create && state.schema === 1) state.schema = 2; // Never downgrade a stronger authority format.
  const ledger = state as LifecycleLedger;
  const value = ledger.lifecycle;
  if (!value) {
    if (!create) return undefined;
    return (ledger.lifecycle = {
      version: 1,
      retiredFamilies: Object.create(null),
      archivedTaskIds: Object.create(null),
      archivedMemoryIds: [],
      archives: Object.create(null),
    });
  }
  if (
    value.version !== 1 ||
    !record(value.retiredFamilies) ||
    !record(value.archives) ||
    !record(value.archivedTaskIds) ||
    !Array.isArray(value.archivedMemoryIds) ||
    Object.keys(value.archivedTaskIds).length + value.archivedMemoryIds.length > MAX_ARCHIVED_IDS ||
    Object.keys(value.archives).length > MAX_ARCHIVES ||
    Object.entries(value.archivedTaskIds).some(
      ([id, archiveId]) =>
        !/^[a-f0-9]{64}$/.test(id) ||
        typeof archiveId !== 'string' ||
        (!own(value.archives, archiveId) &&
          !/^external:[a-f0-9]{64}(?::[a-f0-9-]{36}:[1-9][0-9]{0,15})?$/.test(archiveId)),
    ) ||
    value.archivedMemoryIds.some((id, index, ids) => !/^[a-f0-9]{64}$/.test(id) || (index > 0 && ids[index - 1]! >= id))
  )
    fail('LIFECYCLE_STATE_INVALID');
  let bytes = 0;
  for (const [id, entry] of Object.entries(value.archives)) {
    if (
      !/^[a-f0-9-]{36}$/.test(id) ||
      !record(entry) ||
      ![entry.tenantDigest, entry.familyDigest, entry.cipherSha256].every(
        digest => typeof digest === 'string' && /^[a-f0-9]{64}$/.test(digest),
      ) ||
      typeof entry.keyBase64 !== 'string' ||
      !/^[A-Za-z0-9+/]{43}=$/.test(entry.keyBase64) ||
      Buffer.from(entry.keyBase64, 'base64').toString('base64') !== entry.keyBase64 ||
      !safeCount(entry.plainBytes) ||
      entry.plainBytes > MAX_PLAIN_BYTES ||
      !safeCount(entry.cipherBytes) ||
      entry.cipherBytes > 32 * 1024 * 1024 ||
      !safeCount(entry.retiredAt) ||
      !safeCount(entry.archivedAt) ||
      entry.archivedAt < entry.retiredAt ||
      !record(entry.counts) ||
      !['tasks', 'actions', 'preparedActions', 'unresolvedActions', 'memoryEntries', 'memoryVersions'].every(key =>
        safeCount((entry.counts as unknown as Record<string, unknown>)[key]),
      ) ||
      entry.counts.tasks < 1 ||
      entry.counts.preparedActions !== 0 ||
      entry.counts.unresolvedActions !== 0 ||
      !record(entry.rootUsage) ||
      ![entry.rootUsage.calls, entry.rootUsage.spent].every(
        count => typeof count === 'string' && /^(?:0|[1-9][0-9]{0,23})$/.test(count),
      )
    )
      fail('LIFECYCLE_STATE_INVALID');
    bytes += entry.cipherBytes;
  }
  if (bytes > MAX_ARCHIVE_BYTES) fail('LIFECYCLE_STATE_INVALID');
  for (const [kind, entries] of [
    ['externalHeads', value.externalHeads],
    ['namespaceFences', value.namespaceFences],
  ] as const) {
    if (entries === undefined) continue;
    if (!record(entries) || Object.keys(entries).length > 10_000) fail('LIFECYCLE_STATE_INVALID');
    for (const [key, entry] of Object.entries(entries)) {
      if (
        !record(entry) ||
        !safeCount(entry.through) ||
        (kind === 'externalHeads'
          ? !/^[a-f0-9]{64}$/.test(key) ||
            !/^[a-f0-9]{64}$/.test(String(entry.hash)) ||
            !namespaceValid(entry.namespace)
          : !namespaceValid(key) || !/^[a-f0-9]{64}$/.test(String(entry.tenantDigest)))
      )
        fail('LIFECYCLE_STATE_INVALID');
    }
  }
  for (const [digest, head] of Object.entries(value.externalHeads ?? {})) {
    const fence = own(value.namespaceFences ?? {}, head.namespace);
    if (!fence || fence.tenantDigest !== digest || fence.through !== head.through) fail('LIFECYCLE_STATE_INVALID');
  }
  for (const [namespace, fence] of Object.entries(value.namespaceFences ?? {})) {
    if (own(value.externalHeads ?? {}, fence.tenantDigest)?.namespace !== namespace) fail('LIFECYCLE_STATE_INVALID');
  }
  for (const [id, marker] of Object.entries(value.archivedTaskIds)) {
    if (!marker.startsWith('external:')) continue;
    const [, digest, namespace, sequenceText] = marker.split(':');
    const head = own(value.externalHeads ?? {}, digest!);
    if (!head) fail('LIFECYCLE_STATE_INVALID');
    if (
      namespace !== undefined &&
      (!namespaceValid(namespace) ||
        head.namespace !== namespace ||
        !safeCount(Number(sequenceText)) ||
        Number(sequenceText) <= head.through ||
        id !== taskDigest(`${NUMBERED_TASK_PREFIX}${namespace}-${sequenceText}`))
    )
      fail('LIFECYCLE_STATE_INVALID');
  }
  for (const [familyId, retired] of Object.entries(value.retiredFamilies)) {
    if (
      !own(state.families, familyId) ||
      !record(retired) ||
      !safeCount(retired.retiredAt) ||
      typeof retired.tenantDigest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(retired.tenantDigest)
    )
      fail('LIFECYCLE_STATE_INVALID');
  }
  return value;
}
/** Tombstones stay inside the authenticated ledger; pruning cannot grant an old ID fresh authority. */
export function archivedTaskIdUsed(state: Ledger, id: string): boolean {
  const retained = lifecycle(state);
  if (!retained) return false;
  if (own(retained.archivedTaskIds, taskDigest(id)) !== undefined) return true;
  const numbered = numberedTask(id);
  return !!numbered && numbered.sequence <= (own(retained.namespaceFences ?? {}, numbered.namespace)?.through ?? 0);
}
/**
 * Numbered task IDs: `ticket:<namespace UUID v4>-<sequence>`. Any host may use them. After a
 * family export, the ledger keeps one fence per namespace (the highest exported sequence)
 * instead of one tombstone per ID, so an exported ID can never be reused. The prefix is part
 * of persisted fences and digests, so it is fixed for every ledger.
 */
export const NUMBERED_TASK_PREFIX = 'ticket:';
/** Builds a numbered task ID; throws INVALID_INPUT for a malformed namespace or sequence. */
export function numberedTaskId(namespace: string, sequence: number): string {
  if (!namespaceValid(namespace) || !Number.isSafeInteger(sequence) || sequence < 1 || sequence >= 1e16)
    throw new ExecutorError('INVALID_INPUT');
  return `${NUMBERED_TASK_PREFIX}${namespace}-${sequence}`;
}
function namespaceValid(value: unknown): value is string {
  return (
    typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)
  );
}
function numberedTask(id: string): { namespace: string; sequence: number } | undefined {
  const match = /^ticket:([a-f0-9-]{36})-([1-9][0-9]{0,15})$/.exec(id);
  if (!match || !namespaceValid(match[1])) return undefined;
  const sequence = Number(match[2]);
  if (!Number.isSafeInteger(sequence)) return undefined;
  return { namespace: match[1], sequence };
}
export function archivedMemoryIdUsed(state: Ledger, tenantId: string, id: string): boolean {
  return includesDigest(lifecycle(state)?.archivedMemoryIds, memoryDigest(tenantId, id));
}
function includesDigest(ids: readonly string[] | undefined, digest: string): boolean {
  if (!ids) return false;
  let low = 0,
    high = ids.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (ids[mid]! < digest) low = mid + 1;
    else high = mid;
  }
  return ids[low] === digest;
}
type Plan = {
  tenantId: string;
  taskId: string;
  familyId: string;
  taskIds: Set<string>;
  actionIds: Set<string>;
  memoryKeys: Set<string>;
  counts: TaskFamilyCounts;
  retiredAt: number | undefined;
  retirementBlockers: string[];
  archiveBlockers: string[];
};
function plan(state: Ledger, scope: TaskFamilyScope, active: ReadonlySet<string>): Plan {
  const tenantId = text(scope.tenantId),
    taskId = text(scope.taskId);
  const selected = own(state.tasks, taskId);
  if (!selected || selected.options.tenantId !== tenantId) fail('LIFECYCLE_SCOPE_DENIED');
  const familyId = selected.family;
  const family = own(state.families, familyId);
  if (!family) fail('LIFECYCLE_STATE_INVALID');
  let scanned = 0;
  const step = () => {
    if (++scanned > MAX_SCAN_RECORDS) fail('LIFECYCLE_LIMIT_EXCEEDED');
  };
  const tasks = Object.values(state.tasks),
    actions = Object.values(state.actions);
  const tenantFamilies = new Set(tasks.filter(task => task.options.tenantId === tenantId).map(task => task.family));
  const taskIds = new Set<string>();
  for (const task of tasks) {
    step();
    if (task.family === familyId) {
      if (task.options.tenantId !== tenantId) fail('LIFECYCLE_STATE_INVALID');
      taskIds.add(task.options.id);
    }
  }
  const retirementBlockers = new Set<string>(),
    archiveBlockers = new Set<string>();
  const actionIds = new Set<string>();
  let preparedActions = 0,
    unresolvedActions = 0;
  for (const action of actions) {
    step();
    if (!taskIds.has(action.taskId)) continue;
    actionIds.add(action.id);
    if (!executionStatuses.includes(action.status)) fail('LIFECYCLE_STATE_INVALID');
    if (action.status === 'PREPARED') preparedActions++;
    if (unresolved.has(action.status)) unresolvedActions++;
  }
  if (unresolvedActions) retirementBlockers.add('FAMILY_UNRESOLVED_WORK');
  for (const task of tasks) {
    if (taskIds.has(task.options.id)) {
      if (active.has(task.options.id) || task.concurrent !== 0 || task.reserved !== 0)
        retirementBlockers.add('FAMILY_ACTIVE_WORK');
      for (const reference of [task.parent, task.sourceTaskId])
        if (reference && !taskIds.has(reference)) archiveBlockers.add('FAMILY_EXTERNAL_REFERENCE');
    } else if ((task.parent && taskIds.has(task.parent)) || (task.sourceTaskId && taskIds.has(task.sourceTaskId)))
      archiveBlockers.add('FAMILY_EXTERNAL_REFERENCE');
  }
  const memoryKeys = new Set<string>(),
    memoryIds = new Set<string>();
  let memoryVersions = 0;
  for (const [key, history] of Object.entries(state.memory)) {
    const belongs = history.map(entry => {
      step();
      return entry.familyId === familyId || (entry.origin.startsWith('task:') && taskIds.has(entry.origin.slice(5)));
    });
    if (!belongs.some(Boolean)) continue;
    if (history.some(entry => entry.tenantId !== tenantId) || belongs.some(value => !value))
      archiveBlockers.add('FAMILY_EXTERNAL_REFERENCE');
    memoryKeys.add(key);
    memoryIds.add(history.at(-1)!.id);
    memoryVersions += history.length;
  }
  for (const [otherId, otherFamily] of Object.entries(state.families)) {
    step();
    if (otherId !== familyId && otherFamily.memorySources?.some(id => memoryIds.has(id)) && tenantFamilies.has(otherId))
      archiveBlockers.add('FAMILY_EXTERNAL_REFERENCE');
  }
  for (const [key, history] of Object.entries(state.memory)) {
    if (memoryKeys.has(key)) continue;
    for (const entry of history) {
      step();
      if (entry.tenantId === tenantId && entry.parentIds.some(parent => memoryIds.has(parent)))
        archiveBlockers.add('FAMILY_EXTERNAL_REFERENCE');
    }
  }
  const retained = lifecycle(state);
  const retirement = retained && own(retained.retiredFamilies, familyId);
  if (
    retirement &&
    (retirement.tenantDigest !== tenantDigest(tenantId) ||
      !tasks.filter(task => taskIds.has(task.options.id)).every(task => task.revoked))
  )
    fail('LIFECYCLE_STATE_INVALID');
  if (!retirement) archiveBlockers.add('FAMILY_NOT_RETIRED');
  for (const blocker of retirementBlockers) archiveBlockers.add(blocker);
  if (
    retained &&
    (Object.keys(retained.archives).length >= MAX_ARCHIVES ||
      Object.keys(retained.archivedTaskIds).length +
        retained.archivedMemoryIds.length +
        taskIds.size +
        memoryKeys.size >
        MAX_ARCHIVED_IDS)
  )
    archiveBlockers.add('ARCHIVE_CAPACITY_EXCEEDED');
  return {
    tenantId,
    taskId,
    familyId,
    taskIds,
    actionIds,
    memoryKeys,
    retiredAt: retirement?.retiredAt,
    counts: {
      tasks: taskIds.size,
      actions: actionIds.size,
      preparedActions,
      unresolvedActions,
      memoryEntries: memoryKeys.size,
      memoryVersions,
    },
    retirementBlockers: [...retirementBlockers].sort(),
    archiveBlockers: [...archiveBlockers].sort(),
  };
}
function aad(ledgerId: string, archiveId: string, tenant: string): Buffer {
  return Buffer.from(JSON.stringify(['agent-guard-family-archive-v1', ledgerId, archiveId, tenant]));
}

export interface TaskFamilyArchiveTransfer {
  archiveId: string;
  tenantId: string;
  catalog: ArchiveEntry;
  ciphertext: string;
}
interface ArchivePayload {
  schemaVersion: number;
  kind: string;
  ledgerInstanceId: string;
  archiveId: string;
  tenantId: string;
  familyId: string;
  tasks: Record<string, StoredTask>;
  actions: Record<string, StoredAction>;
  memory: Ledger['memory'];
}
/** Internal maintenance transfer. Contains confidential evidence and keys; never expose to an agent or HTTP client. */
export function verifyTransferredTaskFamilyArchive(
  ledgerInstanceId: string,
  transfer: TaskFamilyArchiveTransfer,
): ArchivePayload {
  const { archiveId, tenantId, catalog: entry, ciphertext } = transfer;
  if (
    entry.tenantDigest !== tenantDigest(tenantId) ||
    Buffer.byteLength(ciphertext) !== entry.cipherBytes ||
    sha(ciphertext) !== entry.cipherSha256
  )
    fail('ARCHIVE_INVALID');
  const key = Buffer.from(entry.keyBase64, 'base64');
  let plaintext: Buffer | undefined;
  try {
    const [iv, tag, data] = JSON.parse(ciphertext) as string[];
    const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv!, 'base64'));
    cipher.setAAD(aad(ledgerInstanceId, archiveId, tenantId));
    cipher.setAuthTag(Buffer.from(tag!, 'base64'));
    plaintext = Buffer.concat([cipher.update(Buffer.from(data!, 'base64')), cipher.final()]);
    if (plaintext.length !== entry.plainBytes || plaintext.length > MAX_PLAIN_BYTES) fail('ARCHIVE_INVALID');
    const decoded = JSON.parse(plaintext.toString('utf8')) as ArchivePayload;
    if (
      decoded.schemaVersion !== 1 ||
      decoded.kind !== 'agent-guard-task-family-archive' ||
      decoded.ledgerInstanceId !== ledgerInstanceId ||
      decoded.archiveId !== archiveId ||
      decoded.tenantId !== tenantId ||
      taskDigest(decoded.familyId) !== entry.familyDigest ||
      !record(decoded.tasks) ||
      !record(decoded.actions) ||
      !record(decoded.memory) ||
      Object.keys(decoded.tasks).length !== entry.counts.tasks
    )
      fail('ARCHIVE_INVALID');
    return decoded;
  } catch {
    return fail('ARCHIVE_INVALID');
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
}
export function readTaskFamilyArchiveTransfer(
  store: LedgerStore,
  scope: TaskFamilyArchiveScope,
): TaskFamilyArchiveTransfer {
  const state = store.read(),
    entry = lifecycle(state)?.archives[scope.archiveId];
  if (!entry || entry.tenantDigest !== tenantDigest(text(scope.tenantId))) fail('LIFECYCLE_SCOPE_DENIED');
  const transfer = {
    archiveId: scope.archiveId,
    tenantId: scope.tenantId,
    catalog: entry,
    ciphertext: store.readArchive(scope.archiveId),
  };
  verifyTransferredTaskFamilyArchive(state.inventoryInstanceId, transfer);
  return transfer;
}
/** Backup verification has no tenant enrollment input. No provisional plaintext escapes authentication. */
export function verifyAllArchiveStorage(store: Pick<LedgerStore, 'read' | 'readArchive'>): {
  archives: number;
  bytes: number;
  externalHistories: number;
} {
  const state = store.read(),
    retained = lifecycle(state);
  let archives = 0,
    bytes = 0;
  for (const [archiveId, entry] of Object.entries(retained?.archives ?? {})) {
    const ciphertext = store.readArchive(archiveId);
    if (Buffer.byteLength(ciphertext) !== entry.cipherBytes || sha(ciphertext) !== entry.cipherSha256)
      fail('ARCHIVE_INVALID');
    const key = Buffer.from(entry.keyBase64, 'base64');
    let candidate: Buffer | undefined;
    try {
      // The main ledger authenticates the exact ciphertext digest first. GCM's
      // bounded provisional plaintext supplies only the AAD tenant for a second,
      // fully authenticated decrypt; it never authorizes a result or mutation.
      const [iv, , data] = JSON.parse(ciphertext) as string[];
      candidate = createDecipheriv('aes-256-gcm', key, Buffer.from(iv!, 'base64')).update(Buffer.from(data!, 'base64'));
      if (candidate.length > MAX_PLAIN_BYTES) fail('ARCHIVE_INVALID');
      const tenantId = (JSON.parse(candidate.toString('utf8')) as { tenantId: string }).tenantId;
      verifyTransferredTaskFamilyArchive(state.inventoryInstanceId, {
        archiveId,
        tenantId: text(tenantId),
        catalog: entry,
        ciphertext,
      });
    } catch {
      fail('ARCHIVE_INVALID');
    } finally {
      key.fill(0);
      candidate?.fill(0);
    }
    archives++;
    bytes += entry.cipherBytes;
  }
  return { archives, bytes, externalHistories: Object.keys(retained?.externalHeads ?? {}).length };
}
export function externalTaskHistoryHead(
  store: LedgerStore,
  tenantId: string,
): Readonly<{ hash: string; namespace: string; through: number }> | null {
  const retained = lifecycle(store.read());
  return retained?.externalHeads?.[tenantDigest(text(tenantId))] ?? null;
}
/**
 * Internal offline maintenance only. The host must first fsync and authenticate
 * its encrypted export. This derives fences from authenticated archives, stops
 * before every live gap, retains markers above gaps, and atomically removes
 * exactly the exported ciphertext rows.
 */
export function compactExportedTaskFamilies(
  store: LedgerStore,
  scope: {
    tenantId: string;
    namespace: string;
    archiveIds: readonly string[];
    segmentHash: string;
    previousHash: string | null;
  },
): { archives: number; through: number; alreadyApplied: boolean } {
  const tenant = text(scope.tenantId),
    digest = tenantDigest(tenant);
  if (
    !namespaceValid(scope.namespace) ||
    !/^[a-f0-9]{64}$/.test(scope.segmentHash) ||
    (scope.previousHash !== null && !/^[a-f0-9]{64}$/.test(scope.previousHash)) ||
    !Array.isArray(scope.archiveIds) ||
    scope.archiveIds.length > 100 ||
    new Set(scope.archiveIds).size !== scope.archiveIds.length
  )
    fail('ARCHIVE_EXPORT_INVALID');
  return store.transaction((state, archives) => {
    const retained = lifecycle(state, true)!,
      previous = retained.externalHeads?.[digest];
    if (previous?.hash === scope.segmentHash) {
      if (previous.namespace !== scope.namespace) fail('ARCHIVE_EXPORT_INVALID');
      return { archives: 0, through: previous.through, alreadyApplied: true };
    }
    if ((previous?.hash ?? null) !== scope.previousHash || (previous && previous.namespace !== scope.namespace))
      fail('ARCHIVE_EXPORT_STALE');
    const oldFence = retained.namespaceFences?.[scope.namespace];
    if (oldFence && oldFence.tenantDigest !== digest) fail('ARCHIVE_EXPORT_INVALID');
    let through = oldFence?.through ?? 0;
    for (const marker of Object.values(retained.archivedTaskIds)) {
      const match = /^external:([a-f0-9]{64}):([a-f0-9-]{36}):([1-9][0-9]{0,15})$/.exec(marker);
      if (match?.[1] === digest && match[2] === scope.namespace) through = Math.max(through, Number(match[3]));
    }
    const transfers = scope.archiveIds.map(archiveId => {
      const entry = own(retained.archives, text(archiveId));
      if (!entry || entry.tenantDigest !== digest) fail('LIFECYCLE_SCOPE_DENIED');
      const transfer = { archiveId, tenantId: tenant, catalog: entry, ciphertext: archives.readArchive(archiveId) };
      const payload = verifyTransferredTaskFamilyArchive(state.inventoryInstanceId, transfer);
      const tasks = Object.values(payload.tasks);
      // More general delegation/memory histories keep the original finite profile.
      if (
        tasks.length !== 1 ||
        Object.keys(payload.memory).length ||
        entry.counts.memoryEntries !== 0 ||
        tasks[0]!.parent !== null ||
        tasks[0]!.sourceTaskId !== undefined ||
        !tasks[0]!.revoked ||
        tasks[0]!.concurrent !== 0 ||
        tasks[0]!.reserved !== 0 ||
        Object.values(payload.actions).some(action => unresolved.has(action.status))
      )
        fail('ARCHIVE_EXPORT_REFERENCED');
      const taskId = tasks[0]!.options.id,
        numbered = numberedTask(taskId);
      if (numbered) {
        if (numbered.namespace !== scope.namespace) fail('ARCHIVE_EXPORT_INVALID');
        through = Math.max(through, numbered.sequence);
      }
      if (tasks[0]!.options.tenantId !== tenant || payload.familyId !== taskId) fail('ARCHIVE_EXPORT_INVALID');
      return { transfer, taskId, numbered };
    });
    for (const task of Object.values(state.tasks)) {
      const numbered = numberedTask(task.options.id);
      if (numbered?.namespace === scope.namespace && numbered.sequence <= through) {
        if (numbered.sequence <= (oldFence?.through ?? 0)) fail('ARCHIVE_EXPORT_LIVE_GAP');
        through = numbered.sequence - 1;
      }
    }
    if (
      (!retained.externalHeads?.[digest] && Object.keys(retained.externalHeads ?? {}).length >= 10_000) ||
      (!oldFence && Object.keys(retained.namespaceFences ?? {}).length >= 10_000)
    )
      fail('ARCHIVE_CAPACITY_EXCEEDED');
    for (const { transfer, taskId, numbered } of transfers) {
      if (retained.archivedTaskIds[taskDigest(taskId)] !== transfer.archiveId) fail('ARCHIVE_INVALID');
      if (numbered && numbered.sequence <= through) delete retained.archivedTaskIds[taskDigest(taskId)];
      else if (numbered)
        retained.archivedTaskIds[taskDigest(taskId)] = `external:${digest}:${numbered.namespace}:${numbered.sequence}`;
      else retained.archivedTaskIds[taskDigest(taskId)] = `external:${digest}`;
      archives.deleteArchive(transfer.archiveId, transfer.catalog.cipherSha256);
      delete retained.archives[transfer.archiveId];
    }
    for (const [id, marker] of Object.entries(retained.archivedTaskIds)) {
      const match = /^external:([a-f0-9]{64}):([a-f0-9-]{36}):([1-9][0-9]{0,15})$/.exec(marker);
      if (match?.[1] === digest && match[2] === scope.namespace && Number(match[3]) <= through)
        delete retained.archivedTaskIds[id];
    }
    (retained.namespaceFences ??= Object.create(null))[scope.namespace] = { tenantDigest: digest, through };
    (retained.externalHeads ??= Object.create(null))[digest] = {
      hash: scope.segmentHash,
      namespace: scope.namespace,
      through,
    };
    return { archives: transfers.length, through, alreadyApplied: false };
  });
}
/** Host-only lifecycle operations. Never give this object or its decrypted ledger to a workload. */
export class TaskFamilyLifecycle {
  #reviewKey = randomBytes(32);
  constructor(
    private readonly store: LedgerStore,
    private readonly callbacks: {
      now(state?: Ledger): number;
      activeTaskIds(): ReadonlySet<string>;
      quarantine(state: Ledger, tenantId: string, memoryIds: Set<string>): void;
      retired(taskIds: readonly string[]): void;
      /** Records a recent event; defaults to the standard per-tenant rings. */
      event?(state: Ledger, time: number, event: string, scope: { taskId?: string; tenantId?: string }): void;
    },
  ) {}
  #event(state: Ledger, time: number, event: string, scope: { taskId?: string; tenantId?: string }): void {
    if (this.callbacks.event) this.callbacks.event(state, time, event, scope);
    else recordEvent(state, DEFAULT_RECENT_EVENTS_PER_TENANT, time, event, scope);
  }
  #digest(state: Ledger, scope: TaskFamilyScope): string {
    return createHmac('sha256', this.#reviewKey)
      .update(
        JSON.stringify(['family-review-v1', state.inventoryInstanceId, state.revision, scope.tenantId, scope.taskId]),
      )
      .digest('hex');
  }
  #decision(state: Ledger, scope: TaskFamilyDecision): Plan {
    if (
      typeof scope.expectedDigest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(scope.expectedDigest) ||
      !timingSafeEqual(Buffer.from(scope.expectedDigest, 'hex'), Buffer.from(this.#digest(state, scope), 'hex'))
    )
      fail('LIFECYCLE_PREVIEW_STALE');
    return plan(state, scope, this.callbacks.activeTaskIds());
  }
  preview(scope: TaskFamilyScope): TaskFamilyRetirementPreview {
    const selected = input(scope, ['tenantId', 'taskId']);
    const state = this.store.read(),
      current = plan(state, selected, this.callbacks.activeTaskIds());
    return snapshot({
      tenantId: current.tenantId,
      taskId: current.taskId,
      familyId: current.familyId,
      revision: state.revision,
      reviewDigest: this.#digest(state, selected),
      retired: current.retiredAt !== undefined,
      counts: current.counts,
      retirementBlockers: current.retirementBlockers,
      archiveBlockers: current.archiveBlockers,
    });
  }
  retire(scope: TaskFamilyDecision): TaskFamilyRetirementResult {
    const selected = input(scope, ['tenantId', 'taskId', 'expectedDigest']);
    let retiredIds: string[] = [];
    const result = this.store.transaction(state => {
      const current = this.#decision(state, selected);
      if (current.retirementBlockers.length) fail(current.retirementBlockers[0]!);
      if (current.retiredAt !== undefined) fail('FAMILY_ALREADY_RETIRED');
      const now = this.callbacks.now(state),
        retained = lifecycle(state, true)!;
      for (const taskId of current.taskIds) state.tasks[taskId]!.revoked = true;
      for (const actionId of current.actionIds) {
        const action = state.actions[actionId]!;
        if (action.status === 'PREPARED') {
          action.status = 'FAILED';
          action.charged = 0;
        }
      }
      const memoryIds = new Set([...current.memoryKeys].map(key => state.memory[key]!.at(-1)!.id));
      this.callbacks.quarantine(state, current.tenantId, memoryIds);
      retained.retiredFamilies[current.familyId] = { tenantDigest: tenantDigest(current.tenantId), retiredAt: now };
      this.#event(state, now, 'FAMILY_RETIRED', { taskId: current.taskId, tenantId: current.tenantId });
      retiredIds = [...current.taskIds];
      return snapshot({
        tenantId: current.tenantId,
        familyId: current.familyId,
        retiredAt: now,
        tasksRevoked: current.counts.tasks,
        preparationsCancelled: current.counts.preparedActions,
      });
    });
    this.callbacks.retired(retiredIds);
    return result;
  }
  archive(scope: TaskFamilyDecision): TaskFamilyArchiveReceipt {
    const selected = input(scope, ['tenantId', 'taskId', 'expectedDigest']);
    return this.store.transaction((state, archiveStore) => {
      const current = this.#decision(state, selected);
      if (current.archiveBlockers.length) fail(current.archiveBlockers[0]!);
      const retained = lifecycle(state, true)!,
        archiveId = randomUUID(),
        now = this.callbacks.now(state);
      const select = <T>(entries: Record<string, T>, ids: ReadonlySet<string>) =>
        Object.fromEntries(Object.entries(entries).filter(([id]) => ids.has(id)));
      const tasks = select(state.tasks, current.taskIds),
        actions = select(state.actions, current.actionIds);
      const approvals = Object.fromEntries(
        Object.entries(state.approvals).filter(([, value]) => current.actionIds.has(value.actionId)),
      );
      const prunedReceipts = familyStubs(state, current.familyId);
      const audit = state.audit.filter(
        event =>
          (event.taskId && current.taskIds.has(event.taskId)) ||
          (event.actionId && current.actionIds.has(event.actionId)),
      );
      const payload = JSON.stringify({
        schemaVersion: 1,
        kind: 'agent-guard-task-family-archive',
        ledgerInstanceId: state.inventoryInstanceId,
        archiveId,
        tenantId: current.tenantId,
        familyId: current.familyId,
        retiredAt: current.retiredAt,
        archivedAt: now,
        family: state.families[current.familyId],
        tasks,
        actions,
        approvals,
        memory: select(state.memory, current.memoryKeys),
        audit,
        prunedReceipts,
      });
      if (Buffer.byteLength(payload) > MAX_PLAIN_BYTES) fail('ARCHIVE_CAPACITY_EXCEEDED');
      const key = randomBytes(32),
        iv = randomBytes(12);
      let ciphertext: string;
      try {
        const cipher = createCipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(aad(state.inventoryInstanceId, archiveId, current.tenantId));
        const bytes = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
        ciphertext = JSON.stringify([
          iv.toString('base64'),
          cipher.getAuthTag().toString('base64'),
          bytes.toString('base64'),
        ]);
        if (
          Object.values(retained.archives).reduce(
            (sum, entry) => sum + entry.cipherBytes,
            Buffer.byteLength(ciphertext),
          ) > MAX_ARCHIVE_BYTES
        )
          fail('ARCHIVE_CAPACITY_EXCEEDED');
        const roots = Object.values(tasks).filter(task => task.parent === null);
        const entry: ArchiveEntry = {
          tenantDigest: tenantDigest(current.tenantId),
          familyDigest: taskDigest(current.familyId),
          keyBase64: key.toString('base64'),
          cipherSha256: sha(ciphertext),
          cipherBytes: Buffer.byteLength(ciphertext),
          plainBytes: Buffer.byteLength(payload),
          retiredAt: current.retiredAt!,
          archivedAt: now,
          counts: current.counts,
          rootUsage: {
            calls: roots.reduce((sum, task) => sum + BigInt(task.calls), 0n).toString(),
            spent: roots.reduce((sum, task) => sum + BigInt(task.spent), 0n).toString(),
          },
        };
        archiveStore.putArchive(archiveId, ciphertext);
        retained.archives[archiveId] = entry;
        for (const taskId of current.taskIds) retained.archivedTaskIds[taskDigest(taskId)] = archiveId;
        retained.archivedMemoryIds = [
          ...retained.archivedMemoryIds,
          ...[...current.memoryKeys].map(key => memoryDigest(current.tenantId, state.memory[key]!.at(-1)!.id)),
        ].sort();
        for (const id of current.taskIds) delete state.tasks[id];
        for (const id of current.actionIds) delete state.actions[id];
        for (const id of Object.keys(approvals)) delete state.approvals[id];
        for (const key of current.memoryKeys) delete state.memory[key];
        takeFamilyStubs(state, current.familyId);
        delete state.families[current.familyId];
        delete retained.retiredFamilies[current.familyId];
        const archivedEvents = new Set(audit);
        state.audit = state.audit.filter(event => !archivedEvents.has(event));
        this.#event(state, now, 'FAMILY_ARCHIVED', { tenantId: current.tenantId });
        return this.#receipt(archiveId, current.tenantId, current.familyId, entry);
      } finally {
        key.fill(0);
      }
    });
  }
  #receipt(archiveId: string, tenantId: string, familyId: string, entry: ArchiveEntry): TaskFamilyArchiveReceipt {
    return snapshot({
      archiveId,
      tenantId,
      familyId,
      retiredAt: entry.retiredAt,
      archivedAt: entry.archivedAt,
      counts: entry.counts,
      ciphertextSha256: entry.cipherSha256,
      encryptedBytes: entry.cipherBytes,
      rootUsage: entry.rootUsage,
    });
  }
  /** Authenticate/decrypt retained evidence internally; return only bounded metadata, never arguments or archive keys. */
  verifyArchive(scope: TaskFamilyArchiveScope): TaskFamilyArchiveReceipt {
    const selected = input(scope, ['tenantId', 'archiveId']);
    const state = this.store.read(),
      tenantId = text(selected.tenantId),
      archiveId = text(selected.archiveId);
    const current = lifecycle(state);
    const entry = current && own(current.archives, archiveId);
    if (!entry || entry.tenantDigest !== tenantDigest(tenantId)) fail('LIFECYCLE_SCOPE_DENIED');
    const ciphertext = this.store.readArchive(archiveId);
    if (Buffer.byteLength(ciphertext) !== entry.cipherBytes || sha(ciphertext) !== entry.cipherSha256)
      fail('ARCHIVE_INVALID');
    const key = Buffer.from(entry.keyBase64, 'base64');
    let plaintext: Buffer | undefined;
    try {
      const [iv, tag, data] = JSON.parse(ciphertext) as string[];
      const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv!, 'base64'));
      cipher.setAAD(aad(state.inventoryInstanceId, archiveId, tenantId));
      cipher.setAuthTag(Buffer.from(tag!, 'base64'));
      plaintext = Buffer.concat([cipher.update(Buffer.from(data!, 'base64')), cipher.final()]);
      if (plaintext.length !== entry.plainBytes || plaintext.length > MAX_PLAIN_BYTES) fail('ARCHIVE_INVALID');
      const decoded = JSON.parse(plaintext.toString('utf8')) as {
        schemaVersion: number;
        kind: string;
        ledgerInstanceId: string;
        archiveId: string;
        tenantId: string;
        familyId: string;
      };
      if (
        decoded.schemaVersion !== 1 ||
        decoded.kind !== 'agent-guard-task-family-archive' ||
        decoded.ledgerInstanceId !== state.inventoryInstanceId ||
        decoded.archiveId !== archiveId ||
        decoded.tenantId !== tenantId ||
        taskDigest(decoded.familyId) !== entry.familyDigest
      )
        fail('ARCHIVE_INVALID');
      return this.#receipt(archiveId, tenantId, decoded.familyId, entry);
    } catch {
      return fail('ARCHIVE_INVALID');
    } finally {
      key.fill(0);
      plaintext?.fill(0);
    }
  }
  findArchive(scope: TaskFamilyScope): TaskFamilyArchiveReceipt | null {
    const selected = input(scope, ['tenantId', 'taskId']),
      tenantId = text(selected.tenantId),
      taskId = text(selected.taskId);
    const state = this.store.read(),
      retained = lifecycle(state);
    const archiveId = retained && own(retained.archivedTaskIds, taskDigest(taskId));
    if (
      archiveId?.startsWith(`external:${tenantDigest(tenantId)}`) ||
      (numberedTask(taskId) &&
        own(retained?.namespaceFences ?? {}, numberedTask(taskId)!.namespace)?.tenantDigest ===
          tenantDigest(tenantId) &&
        archivedTaskIdUsed(state, taskId))
    )
      fail('ARCHIVE_EXPORTED');
    if (!archiveId || own(retained!.archives, archiveId)?.tenantDigest !== tenantDigest(tenantId)) return null;
    return this.verifyArchive({ tenantId, archiveId });
  }
  listExecutions(scope: ExecutionListScope): ExecutionList {
    const selected = input(scope, ['tenantId', 'statuses', 'limit', 'cursor']),
      tenantId = text(selected.tenantId);
    const statuses = selected.statuses ?? ['UNKNOWN'];
    if (
      !Array.isArray(statuses) ||
      !statuses.length ||
      statuses.length > executionStatuses.length ||
      new Set(statuses).size !== statuses.length ||
      statuses.some(status => !executionStatuses.includes(status))
    )
      fail('LIFECYCLE_SCOPE_INVALID');
    const limit = selected.limit ?? 25;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) fail('LIFECYCLE_SCOPE_INVALID');
    const state = this.store.read(),
      filter = sha(JSON.stringify([tenantId, [...statuses].sort()]));
    let after = '';
    if (selected.cursor !== undefined) {
      if (typeof selected.cursor !== 'string' || selected.cursor.length > 8192) fail('LIFECYCLE_CURSOR_INVALID');
      try {
        const parts = selected.cursor.split('.');
        if (parts.length !== 2) fail('LIFECYCLE_CURSOR_INVALID');
        const [encoded, signature] = parts;
        const expected = createHmac('sha256', this.#reviewKey).update(`execution-list-v1\0${encoded}`).digest('hex');
        if (
          !signature ||
          !/^[a-f0-9]{64}$/.test(signature) ||
          !timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'))
        )
          fail('LIFECYCLE_CURSOR_INVALID');
        const cursor = JSON.parse(Buffer.from(encoded!, 'base64url').toString()) as {
          revision: number;
          filter: string;
          after: string;
        };
        if (cursor.filter !== filter) fail('LIFECYCLE_CURSOR_INVALID');
        if (cursor.revision !== state.revision) fail('LIFECYCLE_CURSOR_STALE');
        after = text(cursor.after);
      } catch (error) {
        if (error instanceof ExecutorError) throw error;
        return fail('LIFECYCLE_CURSOR_INVALID');
      }
    }
    const matches = Object.values(state.actions)
      .filter(
        action => statuses.includes(action.status) && own(state.tasks, action.taskId)?.options.tenantId === tenantId,
      )
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    if (matches.length > MAX_SCAN_RECORDS) fail('LIFECYCLE_LIMIT_EXCEEDED');
    const remaining = matches.filter(action => action.id > after),
      page = remaining.slice(0, limit);
    let nextCursor: string | null = null;
    if (remaining.length > page.length) {
      const encoded = Buffer.from(
        JSON.stringify({ revision: state.revision, filter, after: page.at(-1)!.id }),
      ).toString('base64url');
      nextCursor =
        encoded + '.' + createHmac('sha256', this.#reviewKey).update(`execution-list-v1\0${encoded}`).digest('hex');
    }
    return snapshot({
      tenantId,
      revision: state.revision,
      total: matches.length,
      items: page.map(action => ({
        actionId: action.id,
        taskId: action.taskId,
        tool: action.action.tool,
        status: action.status,
        ...(action.charged === undefined ? {} : { charged: action.charged }),
        reservedMaximum: action.maxCost,
      })),
      nextCursor,
    });
  }
  statistics(scope: { tenantId: string }): MaintenanceStatistics {
    const selected = input(scope, ['tenantId']),
      tenantId = text(selected.tenantId),
      state = this.store.read();
    const tasks = Object.values(state.tasks).filter(task => task.options.tenantId === tenantId),
      ids = new Set(tasks.map(task => task.options.id));
    const families = new Set(tasks.map(task => task.family)),
      actions = Object.values(state.actions).filter(action => ids.has(action.taskId));
    const retained = lifecycle(state),
      archives = Object.values(retained?.archives ?? {}).filter(entry => entry.tenantDigest === tenantDigest(tenantId));
    return snapshot({
      tenantId,
      ledgerBytes: Buffer.byteLength(JSON.stringify(state)),
      ledgerByteLimit: this.store.maxBytes,
      tasks: tasks.length,
      families: families.size,
      retiredFamilies: [...families].filter(id => retained && own(retained.retiredFamilies, id)).length,
      actions: actions.length,
      unresolvedActions: actions.filter(action => unresolved.has(action.status)).length,
      memoryEntries: Object.values(state.memory).filter(history => history.at(-1)?.tenantId === tenantId).length,
      archives: archives.length,
      archivedTasks: archives.reduce((sum, entry) => sum + entry.counts.tasks, 0),
      retentionLimits: {
        archives: MAX_ARCHIVES,
        archivedIdentifiers: MAX_ARCHIVED_IDS,
        encryptedArchiveBytes: MAX_ARCHIVE_BYTES,
      },
    });
  }
  close(): void {
    this.#reviewKey.fill(0);
  }
}
