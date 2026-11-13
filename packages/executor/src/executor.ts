import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  AgentGuard,
  GuardError,
  diffToolDefinitions,
  type ApproveToolOptions,
  type Json,
  type Policy,
  type PreparedAction,
  type TaskOptions,
  type TaskSnapshot,
  type ToolChanges,
  type ToolDefinition,
  type UntrustedContextMode,
} from '@shieldaai/agent-guard';
import {
  PolicyAdmission,
  assertActionAuthority,
  canonicalJson,
  digestJson,
  immutableJson,
  type AuthorityPhase,
  type AuthorityState,
} from '@shieldaai/agent-guard/internal';
import {
  ExecutorError,
  LedgerStore,
  validatePublicLedgerMaxBytes,
  type AuditEvent,
  type ExecutionReceipt,
  type Ledger,
  type LedgerWitness,
  type LedgerWriteOptions,
  type MemoryRecord,
  type StoredAction,
  type StoredTask,
} from './store.js';
import {
  projectInventory,
  validateInventorySource,
  captureInventoryRegistrations,
  type InventoryOptions,
  type InventoryScope,
  type InventorySnapshot,
  type InventorySourceOptions,
} from './inventory.js';
import {
  DecisionTraces,
  decisionTraceCode,
  type DecisionTraceOptions,
  type DecisionTraceScope,
  type DecisionTraceSnapshot,
  type DecisionTraceSink,
  type DecisionTraceExportResult,
  type TraceContext,
  type DecisionTraceEventName,
  type DecisionTraceOutcome,
} from './traces.js';
import { bindExecutorObservation, closeExecutorObservation } from './inventory-observer.js';
import {
  archivedTaskIdUsed,
  archivedMemoryIdUsed,
  TaskFamilyLifecycle,
  type TaskFamilyScope,
  type TaskFamilyDecision,
  type TaskFamilyArchiveScope,
  type TaskFamilyRetirementPreview,
  type TaskFamilyRetirementResult,
  type TaskFamilyArchiveReceipt,
  type ExecutionListScope,
  type ExecutionList,
  type MaintenanceStatistics,
} from './lifecycle.js';
import {
  recordEvent,
  recordPruned,
  prunedReceipt,
  stubLimits,
  DEFAULT_RECENT_EVENTS_PER_TENANT,
  RECENT_EVENTS_TOTAL,
  type EventScope,
  type StubLimits,
} from './retention.js';
import { toolRefusal, toolRefusalOf } from './tool-errors.js';
import { migrateLedger, describeLedgerFormat, type LedgerFormat } from './ledger-format.js';

function id(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 4096 || value.includes('\0'))
    throw new GuardError('INVALID_INPUT');
  return value;
}
function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
function own<T>(record: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}
function clone<T>(value: T): T {
  return immutableJson(value) as T;
}
/** A detached copy of a host argument. Data that is not bounded JSON is INVALID_JSON, as in the guard. */
function input<T>(value: T): T {
  try {
    return immutableJson(value) as T;
  } catch {
    throw new GuardError('INVALID_JSON');
  }
}
function plain(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/** A handler error's `code`, read without running accessors and kept only if it is a safe identifier. */
function safeDetail(error: unknown): string | undefined {
  try {
    if (error === null || typeof error !== 'object') return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const code: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    return typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}
/** Operations that only add state stop at the ledger's soft limit. */
const GROWTH: LedgerWriteOptions = Object.freeze({ growth: true });
/**
 * Writes that must not fail (revoke, cancel, settle, mark UNKNOWN, reconcile, withdrawing or removing
 * a tool, recovery at open) may use the reserve; if even that is full they drop the oldest half of
 * the recent-event ring, which readers detect as a gap in `sequence`.
 */
const CRITICAL: LedgerWriteOptions = Object.freeze({
  relief: (state: Ledger): boolean => {
    if (!state.audit.length) return false;
    state.audit.splice(0, Math.ceil(state.audit.length / 2));
    return true;
  },
});
/** Internal signal: a policy decision was made on a task snapshot that has since changed. */
class StalePolicyDecision extends Error {}
type Registered = {
  definition: ToolDefinition;
  fingerprint: string;
  revision: number;
  /** The fingerprinted fields, frozen. Undefined when larger than maxToolDefinitionBytes. */
  canonical: Json | undefined;
};
/** The approval behind `approvedFingerprint`, as the ledger records it. */
export interface ToolApprovalRecord {
  /** Executor clock time of the approval, in milliseconds. */
  readonly approvedAt: number;
  /** Who approved, when `approveTool()` was given an `approverId`. */
  readonly approverId?: string;
  /** The approved fingerprint this approval replaced. Absent for a first approval. */
  readonly replacedFingerprint?: string;
}
/** `toolChanges()` of the executor: the guard's result plus the recorded approval. */
export interface ExecutorToolChanges extends ToolChanges {
  readonly approval?: ToolApprovalRecord;
}
/** Options for the executor's `approveTool()`. */
export interface ExecutorApproveToolOptions extends ApproveToolOptions {
  /** Recorded in the ledger with the approval. A non-empty string of at most 4,096 characters. */
  approverId?: string;
}

export interface ExecutorOptions {
  database: string;
  /** Exactly 32 random bytes supplied through the protected host's key custody. Never an agent secret. */
  encryptionKey: Uint8Array;
  /** Optional POSIX rollback detection: separate private state outside the database restore domain. */
  rollbackWitness?: LedgerWitness;
  clock?: () => number;
  policy?: Policy;
  secretValues?: readonly string[];
  maxRecords?: number;
  /**
   * Settled receipts kept per task family before the oldest are pruned to a PRUNED stub
   * (integer 1-4096, default 64). Each tenant then keeps at most 256 (or this value, if larger).
   */
  maxReceiptsPerFamily?: number;
  /** Unused, unexpired approvals one prepared action may hold (integer 1-64, default 4). */
  maxApprovalsPerAction?: number;
  /** Recent events kept per tenant (integer 16-1000, default 256); the busiest tenant is trimmed first. */
  maxRecentEventsPerTenant?: number;
  /**
   * How many times a custom policy may be evaluated for one prepare or execute when the task's own
   * snapshot (counters or shared sensitivity) changes while it runs. Writes by other tasks or tenants
   * never invalidate a decision. Integer 1-16, default 5; 1 keeps single-evaluation behaviour.
   */
  maxPolicyAttempts?: number;
  /** untrustedContext for tools that do not set it. Default 'allow'. */
  untrustedContextDefault?: UntrustedContextMode;
  /**
   * Operator override for a backward system-clock step, in milliseconds (up to 24 hours).
   * At startup only, if the clock is behind the last recorded time by no more than this,
   * the executor accepts the current time once and records CLOCK_SKEW_ACCEPTED. Leave unset
   * normally: a backward step otherwise fails closed with CLOCK_INVALID.
   */
  acceptClockSkewMs?: number;
  /**
   * Largest tool definition kept in the ledger for `toolChanges()`, in bytes of compact JSON of
   * the fingerprinted fields (integer 1,024-1,048,576, default 65,536). A larger definition
   * still registers and can be approved; only its fingerprint is kept.
   */
  maxToolDefinitionBytes?: number;
  /** Maximum decoded ledger snapshot bytes: 1 MiB through 64 MiB; defaults to 16 MiB. */
  maxLedgerBytes?: number;
  /** Aggregate unresolved actions across a task family, including delegated children. */
  maxPendingActionsPerFamily?: number;
  maxPendingBytesPerFamily?: number;
  /** Lifetime task/argument storage caps prevent delegation from bypassing family quotas. */
  maxTasksPerFamily?: number;
  maxTaskBytesPerFamily?: number;
  /** Trusted host enrollment. Omit to disable inventory; never accept this configuration from a task. */
  inventory?: InventoryOptions;
  /** Opt-in volatile observation. Export is explicit and never runs during admission. */
  decisionTraces?: DecisionTraceOptions;
}
export interface TaskCredential {
  taskId: string;
  token: string;
}

/** Trusted host object. Expose only the task HTTP handler to agents, never this administration object. */
export class DurableExecutor {
  readonly #store: LedgerStore;
  readonly #clock: () => number;
  readonly #secrets: readonly string[];
  readonly #maxRecords: number;
  readonly #maxToolDefinitionBytes: number;
  readonly #maxReceiptsPerFamily: number;
  readonly #maxReceiptsPerTenant: number;
  readonly #maxApprovalsPerAction: number;
  readonly #stubLimits: StubLimits;
  /** Serialized size of each settled receipt. A settled record never changes, so its size is computed once. */
  #receiptBytes = new Map<string, number>();
  /**
   * Revocations the ledger could not record. These tasks are denied in this process, and every later
   * ledger write first tries to record them, so the next write that succeeds makes them durable.
   */
  readonly #unsavedRevocations = new Set<string>();
  readonly #maxRecentEventsPerTenant: number;
  readonly #maxPolicyAttempts: number;
  readonly #untrustedDefault: UntrustedContextMode;
  /** Per-task queue for policy re-evaluations; first attempts stay parallel. */
  readonly #policyTurns = new Map<string, Promise<void>>();
  readonly #maxPendingActionsPerFamily: number;
  readonly #maxPendingBytesPerFamily: number;
  readonly #maxTasksPerFamily: number;
  readonly #maxTaskBytesPerFamily: number;
  readonly #inventorySource: InventorySourceOptions | undefined;
  readonly #inventoryReferenceKey: Buffer | undefined;
  readonly #traces: DecisionTraces | undefined;
  readonly #lifecycle: TaskFamilyLifecycle;
  readonly #tools = new Map<string, Registered>();
  readonly #active = new Map<string, { taskId: string; taskIds: string[]; controller: AbortController }>();
  readonly #policyAdmission = new PolicyAdmission();
  /**
   * Token hash -> task ID, maintained after each committed task creation. This process owns
   * the ledger exclusively, so unknown tokens are refused without a ledger read. An entry can
   * go stale (an archived task); authentication then re-verifies against the ledger.
   */
  readonly #tokenIndex = new Map<string, string>();
  #policy: Policy | undefined;
  #observedClock = 0;

  constructor(options: ExecutorOptions) {
    if (!plain(options)) throw new GuardError('INVALID_INPUT');
    if (
      (options.clock !== undefined && typeof options.clock !== 'function') ||
      (options.policy !== undefined && typeof options.policy !== 'function') ||
      (options.secretValues !== undefined && !Array.isArray(options.secretValues))
    )
      throw new GuardError('INVALID_INPUT');
    // Store configuration (database, key, ledger size) is STORE_CONFIG_INVALID, here and in the /ops tools.
    if (
      typeof options.database !== 'string' ||
      !options.database ||
      !(options.encryptionKey instanceof Uint8Array) ||
      options.encryptionKey.byteLength !== 32
    )
      throw new ExecutorError('STORE_CONFIG_INVALID');
    const maxLedgerBytes = validatePublicLedgerMaxBytes(options.maxLedgerBytes);
    this.#clock = options.clock ?? Date.now;
    this.#policy = options.policy;
    this.#maxToolDefinitionBytes = options.maxToolDefinitionBytes ?? 65_536;
    if (
      !Number.isSafeInteger(this.#maxToolDefinitionBytes) ||
      this.#maxToolDefinitionBytes < 1_024 ||
      this.#maxToolDefinitionBytes > 1_048_576
    )
      throw new GuardError('INVALID_INPUT');
    this.#maxRecords = options.maxRecords ?? 10_000;
    if (!Number.isSafeInteger(this.#maxRecords) || this.#maxRecords < 1) throw new GuardError('INVALID_INPUT');
    const familyShare = Math.max(1, Math.floor(this.#maxRecords / 4));
    const bounded = (value: number | undefined, fallback: number, maximum: number): number => {
      const selected = value ?? fallback;
      if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) throw new GuardError('INVALID_INPUT');
      return selected;
    };
    this.#maxPolicyAttempts = bounded(options.maxPolicyAttempts, 5, 16);
    const untrustedDefault = options.untrustedContextDefault ?? 'allow';
    if (!['allow', 'require_approval', 'deny'].includes(untrustedDefault)) throw new GuardError('INVALID_INPUT');
    this.#untrustedDefault = untrustedDefault;
    this.#maxReceiptsPerFamily = bounded(options.maxReceiptsPerFamily, 64, 4096);
    this.#maxReceiptsPerTenant = Math.min(
      Math.max(256, this.#maxReceiptsPerFamily),
      Math.max(1, Math.floor(this.#maxRecords / 2)),
    );
    this.#maxApprovalsPerAction = bounded(options.maxApprovalsPerAction, 4, 64);
    this.#stubLimits = stubLimits(maxLedgerBytes);
    this.#maxRecentEventsPerTenant = bounded(
      options.maxRecentEventsPerTenant,
      DEFAULT_RECENT_EVENTS_PER_TENANT,
      RECENT_EVENTS_TOTAL,
    );
    if (this.#maxRecentEventsPerTenant < 16) throw new GuardError('INVALID_INPUT');
    this.#maxPendingActionsPerFamily = bounded(
      options.maxPendingActionsPerFamily,
      Math.min(32, familyShare),
      familyShare,
    );
    this.#maxPendingBytesPerFamily = bounded(options.maxPendingBytesPerFamily, 256 * 1024, 1024 * 1024);
    this.#maxTasksPerFamily = bounded(options.maxTasksPerFamily, Math.min(64, familyShare), familyShare);
    this.#maxTaskBytesPerFamily = bounded(options.maxTaskBytesPerFamily, 256 * 1024, 1024 * 1024);
    this.#secrets = Object.freeze((options.secretValues ?? []).map(id));
    if (options.inventory !== undefined) {
      try {
        const config = immutableJson(options.inventory, 4, 32, 64 * 1024) as unknown as InventoryOptions;
        if (
          !config ||
          Array.isArray(config) ||
          typeof config !== 'object' ||
          Object.keys(config).some(
            key => !['companyId', 'sourceId', 'enrollmentGeneration', 'referenceMode'].includes(key),
          ) ||
          (config.referenceMode !== undefined && config.referenceMode !== 'opaque' && config.referenceMode !== 'raw')
        ) {
          throw new ExecutorError('INVENTORY_CONFIG_INVALID');
        }
        this.#inventorySource = validateInventorySource({
          companyId: config.companyId,
          sourceId: config.sourceId,
          enrollmentGeneration: config.enrollmentGeneration,
        });
        if (config.referenceMode !== 'raw') {
          this.#inventoryReferenceKey = createHmac('sha256', options.encryptionKey)
            .update('agent-guard-inventory-references-v1\0')
            .update(JSON.stringify(this.#inventorySource))
            .digest();
        }
      } catch {
        throw new ExecutorError('INVENTORY_CONFIG_INVALID');
      }
    }
    try {
      this.#store = new LedgerStore(options.database, options.encryptionKey, maxLedgerBytes, options.rollbackWitness);
    } catch (error) {
      this.#inventoryReferenceKey?.fill(0);
      throw error;
    }
    try {
      if (options.decisionTraces !== undefined)
        this.#traces = new DecisionTraces(
          options.decisionTraces,
          options.encryptionKey,
          this.#store.read().inventoryInstanceId,
        );
      const skew = options.acceptClockSkewMs;
      if (skew !== undefined && (!Number.isSafeInteger(skew) || skew < 1 || skew > 24 * 60 * 60_000))
        throw new GuardError('INVALID_INPUT');
      const recovered = this.#store.transaction(state => {
        let skewAccepted: { from: number; to: number } | undefined;
        if (skew !== undefined) {
          let current: number | undefined;
          try {
            current = this.#clock();
          } catch {
            /* #now reports CLOCK_INVALID below. */
          }
          if (Number.isSafeInteger(current) && current! < state.lastClock && state.lastClock - current! <= skew) {
            skewAccepted = { from: state.lastClock, to: current! };
            state.lastClock = current!;
          }
        }
        const now = this.#now(state);
        if (skewAccepted) this.#audit(state, now, 'CLOCK_SKEW_ACCEPTED');
        // Bring an older ledger layout forward first; a newer one is refused unchanged.
        migrateLedger(state);
        state.epoch++; // Process/code changes invalidate every outstanding preparation.
        for (const tool of Object.values(state.tools)) tool.approved = false;
        const recovered: TraceContext[] = [];
        for (const action of Object.values(state.actions)) {
          if (action.status === 'RUNNING' || action.status === 'ADMITTED') {
            action.status = 'UNKNOWN';
            if (this.#traces)
              recovered.push({
                tenantId: state.tasks[action.taskId]!.options.tenantId,
                taskId: action.taskId,
                actionId: action.id,
                policyRevision: state.epoch,
                toolRevision: action.toolRevision,
                started: performance.now(),
              });
          }
        }
        this.#audit(state, now, 'EXECUTOR_STARTED');
        return recovered;
      }, CRITICAL);
      for (const context of recovered) this.#record(context, 'unknown', 'UNKNOWN', 'RECOVERY_UNKNOWN');
    } catch (error) {
      this.#store.close();
      this.#inventoryReferenceKey?.fill(0);
      this.#traces?.close();
      throw error;
    }
    bindExecutorObservation(this, this.#store, () => {
      if (!this.#inventorySource) throw new ExecutorError('INVENTORY_DISABLED');
      // Every registration also occupies the bounded encrypted tool ledger. Four
      // times that ceiling accommodates detached flags without a hidden global
      // 10k-tool cap on a tenant whose own exported tools remain within 10k.
      return {
        // The default travels beside the enrollment identity; it never enters reference keys.
        source: { ...this.#inventorySource, untrustedContextDefault: this.#untrustedDefault },
        registrations: captureInventoryRegistrations(this.#tools, this.#store.maxBytes * 4),
        referenceKey: this.#inventoryReferenceKey ? new Uint8Array(this.#inventoryReferenceKey) : undefined,
      };
    });
    for (const task of Object.values(this.#store.read().tasks)) this.#tokenIndex.set(task.tokenHash, task.options.id);
    this.#lifecycle = new TaskFamilyLifecycle(this.#store, {
      now: state => this.#now(state),
      activeTaskIds: () => new Set([...this.#active.values()].flatMap(active => active.taskIds)),
      quarantine: (state, tenantId, ids) => this.#quarantine(state, tenantId, ids),
      event: (state, time, event, scope) => this.#recordEvent(state, time, event, scope),
      retired: ids => {
        for (const taskId of ids) this.#policyAdmission.revokeTask(taskId);
      },
      // Without this the token index would keep one entry per archived task for the life of the process.
      archived: tokenHashes => {
        for (const tokenHash of tokenHashes) this.#tokenIndex.delete(tokenHash);
      },
    });
  }

  /** Host-only maintenance: authenticate the operator before selecting tenant/task scope. */
  previewTaskFamilyRetirement(scope: TaskFamilyScope): TaskFamilyRetirementPreview {
    return this.#lifecycle.preview(scope);
  }
  retireTaskFamily(scope: TaskFamilyDecision): TaskFamilyRetirementResult {
    this.#saveRevocations();
    return this.#lifecycle.retire(scope);
  }
  archiveTaskFamily(scope: TaskFamilyDecision): TaskFamilyArchiveReceipt {
    // A pending revocation must reach the ledger before its task can leave it.
    this.#saveRevocations();
    return this.#lifecycle.archive(scope);
  }
  verifyTaskFamilyArchive(scope: TaskFamilyArchiveScope): TaskFamilyArchiveReceipt {
    return this.#lifecycle.verifyArchive(scope);
  }
  findTaskFamilyArchive(scope: TaskFamilyScope): TaskFamilyArchiveReceipt | null {
    return this.#lifecycle.findArchive(scope);
  }
  listExecutions(scope: ExecutionListScope): ExecutionList {
    return this.#lifecycle.listExecutions(scope);
  }
  maintenanceStatistics(scope: { tenantId: string }): MaintenanceStatistics {
    return this.#lifecycle.statistics(scope);
  }

  #traceStart(taskId: string | undefined, actionId: string, observedState?: Ledger): TraceContext | undefined {
    if (!this.#traces) return undefined;
    try {
      const state = observedState ?? this.#store.read();
      const action = own(state.actions, actionId);
      const owner = taskId ?? action?.taskId;
      const task = owner === undefined ? undefined : own(state.tasks, owner);
      if (!task) return undefined; // Unknown/unauthenticated identities cannot select a tenant.
      return {
        tenantId: task.options.tenantId,
        taskId: task.options.id,
        actionId,
        policyRevision: state.epoch,
        toolRevision: action && action.taskId === owner ? action.toolRevision : 0,
        started: performance.now(),
      };
    } catch {
      return undefined;
    }
  }
  #record(
    context: TraceContext | undefined,
    event: DecisionTraceEventName,
    outcome: DecisionTraceOutcome,
    code = 'OK',
  ): void {
    // Observation failure cannot replace an authorization result or enter an exporter.
    if (context)
      try {
        this.#traces?.record(context, event, outcome, code);
      } catch {
        /* Optional observation only. */
      }
  }
  /** Host-only tenant-scoped observation. Authentication must precede choosing this scope. */
  decisionTraceSnapshot(scope: DecisionTraceScope): DecisionTraceSnapshot {
    if (!this.#traces) throw new ExecutorError('TRACE_DISABLED');
    let selected: DecisionTraceScope;
    try {
      selected = clone(scope);
    } catch {
      throw new ExecutorError('TRACE_SCOPE_INVALID');
    }
    if (!plain(selected)) throw new ExecutorError('TRACE_SCOPE_INVALID');
    if (
      selected.taskId !== undefined &&
      this.#task(this.#store.read(), selected.taskId).options.tenantId !== selected.tenantId
    )
      throw new ExecutorError('TRACE_SCOPE_DENIED');
    return this.#traces.snapshot(selected);
  }
  /** Explicit host export. No trace callback is registered on the execution path. Every failure is a rejection. */
  async exportDecisionTraces(
    scope: { tenantId: string },
    sink: DecisionTraceSink,
    options?: { timeoutMs?: number },
  ): Promise<DecisionTraceExportResult> {
    if (!this.#traces) throw new ExecutorError('TRACE_DISABLED');
    return this.#traces.export(scope, sink, options);
  }
  /** Host-only aggregate health. Never expose these cross-tenant counters to a tenant observer. */
  decisionTraceStatistics(): Readonly<{ tenantCapacityDrops: number; tenants: number }> {
    if (!this.#traces) throw new ExecutorError('TRACE_DISABLED');
    return this.#traces.statistics();
  }
  /** Records an authenticated host review refusal, without granting or revoking authority. */
  recordReviewDecision(actionId: string, decision: 'denied'): void {
    if (decision !== 'denied') throw new GuardError('INVALID_INPUT');
    const action = own(this.#store.read().actions, id(actionId));
    if (!action || action.status !== 'PREPARED') throw new GuardError('INVALID_PREPARED');
    this.#record(this.#traceStart(action.taskId, actionId), 'review', 'DENIED', 'REVIEW_DENIED');
  }

  #now(state?: Ledger): number {
    let now: number;
    try {
      now = this.#clock();
    } catch {
      throw new GuardError('CLOCK_INVALID');
    }
    if (!Number.isSafeInteger(now) || now < (state?.lastClock ?? 0) || now < this.#observedClock)
      throw new GuardError('CLOCK_INVALID');
    this.#observedClock = now;
    if (state) state.lastClock = now;
    return now;
  }
  #task(state: Ledger, taskId: string): StoredTask {
    const task = own(state.tasks, id(taskId));
    if (!task) throw new GuardError('INVALID_TASK');
    return task;
  }
  #lineage(state: Ledger, taskId: string): StoredTask[] {
    const ancestors: StoredTask[] = [];
    let task: StoredTask | undefined = this.#task(state, taskId);
    while (task) {
      if (ancestors.length >= 64 || ancestors.includes(task)) throw new ExecutorError('LINEAGE_INVALID');
      ancestors.push(task);
      task = task.parent === null ? undefined : this.#task(state, task.parent);
    }
    return ancestors;
  }
  #snapshot(state: Ledger, task: StoredTask): TaskSnapshot {
    return {
      id: task.options.id,
      principalId: task.options.principalId,
      tenantId: task.options.tenantId,
      sensitive: state.families[task.family]!.sensitive,
      untrusted: state.families[task.family]!.untrusted === true,
      calls: task.calls,
      concurrent: task.concurrent,
      spent: task.spent,
      reserved: task.reserved,
    };
  }
  #provenance(state: Ledger, taskId: string): StoredTask[] {
    const pending = [taskId];
    const visited = new Map<string, StoredTask>();
    while (pending.length) {
      const current = pending.pop()!;
      if (visited.has(current)) continue;
      if (visited.size >= 1000) throw new ExecutorError('PROVENANCE_LIMIT');
      const task = this.#task(state, current);
      visited.set(current, task);
      if (task.parent !== null) pending.push(task.parent);
      if (task.sourceTaskId !== undefined) pending.push(task.sourceTaskId);
    }
    return [...visited.values()];
  }
  #recordEvent(state: Ledger, time: number, event: string, scope: EventScope = {}): void {
    recordEvent(state, this.#maxRecentEventsPerTenant, time, event, scope);
  }
  #audit(state: Ledger, time: number, event: string, taskId?: string, actionId?: string): void {
    this.#recordEvent(state, time, event, {
      ...(taskId === undefined ? {} : { taskId }),
      ...(actionId === undefined ? {} : { actionId }),
    });
  }
  /** Revoked in the ledger, or revoked in this process while the ledger write failed. */
  #isRevoked(task: StoredTask): boolean {
    return task.revoked || this.#unsavedRevocations.has(task.options.id);
  }
  /** The ledger effect of one revocation: the task, everything derived from it and the memory those tasks wrote. */
  #revokeIn(state: Ledger, taskId: string, time: number): void {
    const revoked = this.#task(state, taskId);
    revoked.revoked = true;
    // One pass builds the reverse links; the walk then visits only the revoked task's descendants.
    const derived = new Map<string, string[]>();
    const link = (from: string, to: string): void => {
      const list = derived.get(from);
      if (list) list.push(to);
      else derived.set(from, [to]);
    };
    for (const task of Object.values(state.tasks)) {
      if (task.parent !== null) link(task.parent, task.options.id);
      if (task.sourceTaskId !== undefined) link(task.sourceTaskId, task.options.id);
    }
    const descendants = new Set([taskId]);
    const pending = [taskId];
    while (pending.length)
      for (const next of derived.get(pending.pop()!) ?? [])
        if (!descendants.has(next)) {
          descendants.add(next);
          pending.push(next);
        }
    const entries = new Set(
      Object.values(state.memory)
        .filter(history =>
          history.some(
            entry =>
              entry.tenantId === revoked.options.tenantId &&
              entry.origin.startsWith('task:') &&
              descendants.has(entry.origin.slice(5)),
          ),
        )
        .map(history => history.at(-1)!.id),
    );
    this.#quarantine(state, revoked.options.tenantId, entries);
    this.#audit(state, time, 'TASK_REVOKED', taskId);
  }
  /**
   * Records the revocations whose own write failed, in one commit of their own. Runs before every
   * ledger write of this executor and in close(). A failure leaves them pending: the tasks stay
   * denied in this process and the next write tries again.
   */
  #saveRevocations(): boolean {
    if (!this.#unsavedRevocations.size) return true;
    try {
      this.#store.transaction(state => {
        const now = this.#now(state);
        // A task archived since then has nothing left to revoke.
        for (const taskId of this.#unsavedRevocations) if (own(state.tasks, taskId)) this.#revokeIn(state, taskId, now);
      }, CRITICAL);
      this.#unsavedRevocations.clear();
      return true;
    } catch {
      return false;
    }
  }
  /** Every ledger write of this executor: pending revocations are recorded first, then the operation commits. */
  #write<T>(operation: (state: Ledger) => T, options?: LedgerWriteOptions): T {
    this.#saveRevocations();
    return this.#store.transaction(operation, options);
  }
  /**
   * Pruning never changes cumulative counters or releases unresolved reservations.
   * Settled receipts are kept per family, then per tenant: a tenant's traffic evicts only its own
   * oldest receipts. Only the ledger-wide bounds (an eighth of the ledger bytes, the action table)
   * evict across tenants, and then from the tenant holding the most.
   */
  #prune(state: Ledger, now: number): void {
    type Kept = { action: StoredAction; bytes: number };
    type Holder = { count: number; families: Map<string, Kept[]> };
    const tenants = new Map<string, Holder>();
    let bytes = 0;
    let records = 0;
    let settled = 0;
    for (const [actionId, action] of Object.entries(state.actions)) {
      records++;
      if (action.status === 'PREPARED') {
        const tool = own(state.tools, action.action.tool);
        if (
          action.action.policyVersion !== state.epoch ||
          !tool ||
          tool.revision !== action.toolRevision ||
          this.#provenance(state, action.taskId).some(task => this.#isRevoked(task)) ||
          this.#lineage(state, action.taskId).some(task => now >= task.options.budget.deadline)
        ) {
          delete state.actions[actionId];
          records--;
        }
      } else if (action.status === 'SUCCEEDED' || action.status === 'FAILED') {
        const task = this.#task(state, action.taskId);
        let size = this.#receiptBytes.get(actionId);
        if (size === undefined) {
          size = Buffer.byteLength(JSON.stringify(action));
          this.#receiptBytes.set(actionId, size);
        }
        let holder = tenants.get(task.options.tenantId);
        if (!holder) tenants.set(task.options.tenantId, (holder = { count: 0, families: new Map() }));
        let list = holder.families.get(task.family);
        if (!list) holder.families.set(task.family, (list = []));
        list.push({ action, bytes: size });
        holder.count++;
        settled++;
        bytes += size;
      }
    }
    // Sizes of receipts that left the ledger (archived, retired or pruned) are forgotten.
    if (this.#receiptBytes.size > settled)
      for (const actionId of this.#receiptBytes.keys())
        if (!own(state.actions, actionId)) this.#receiptBytes.delete(actionId);
    const evict = (holder: Holder, family: string): void => {
      const list = holder.families.get(family)!;
      const oldest = list.shift()!;
      if (!list.length) holder.families.delete(family);
      delete state.actions[oldest.action.id];
      this.#receiptBytes.delete(oldest.action.id);
      recordPruned(state, family, oldest.action, this.#stubLimits);
      holder.count--;
      bytes -= oldest.bytes;
      records--;
    };
    /** The tenant's oldest receipt in the family that holds the most. */
    const evictFrom = (holder: Holder): void => {
      let busiest = '';
      let size = 0;
      for (const [family, list] of holder.families)
        if (list.length > size) {
          busiest = family;
          size = list.length;
        }
      evict(holder, busiest);
    };
    for (const holder of tenants.values()) {
      for (const [family, list] of [...holder.families])
        while (list.length > this.#maxReceiptsPerFamily) evict(holder, family);
      while (holder.count > this.#maxReceiptsPerTenant) evictFrom(holder);
    }
    while (bytes > this.#store.maxBytes / 8 || records >= this.#maxRecords) {
      let largest: Holder | undefined;
      for (const holder of tenants.values()) if (holder.count > (largest?.count ?? 0)) largest = holder;
      if (!largest) break;
      evictFrom(largest);
    }
    for (const [approvalId, approval] of Object.entries(state.approvals)) {
      const action = own(state.actions, approval.actionId);
      if (approval.used || approval.expiresAt <= now || !action || action.status !== 'PREPARED')
        delete state.approvals[approvalId];
    }
  }
  #assertPendingCapacity(state: Ledger, candidate: StoredAction): void {
    const family = this.#task(state, candidate.taskId).family;
    let count = 1;
    let bytes = Buffer.byteLength(JSON.stringify(candidate));
    for (const action of Object.values(state.actions)) {
      if (
        action.status !== 'SUCCEEDED' &&
        action.status !== 'FAILED' &&
        this.#task(state, action.taskId).family === family
      ) {
        count++;
        bytes += Buffer.byteLength(JSON.stringify(action));
      }
    }
    if (count > this.#maxPendingActionsPerFamily) throw new ExecutorError('FAMILY_PENDING_LIMIT');
    if (bytes > this.#maxPendingBytesPerFamily) throw new ExecutorError('FAMILY_PENDING_BYTES_LIMIT');
  }
  #authorities(state: Ledger, taskId: string): AuthorityState[] {
    return this.#lineage(state, taskId).map(task => ({
      identity: task.options,
      grants: task.options.grants,
      allowedRecipients: task.options.allowedRecipients ?? [],
      allowControlPlane: task.options.allowControlPlane ?? false,
      budget: task.options.budget,
      snapshot: this.#snapshot(state, task),
      revoked: this.#isRevoked(task),
    }));
  }
  #gates(state: Ledger, action: StoredAction, phase: AuthorityPhase = 'dispatch'): void {
    if (this.#provenance(state, action.taskId).some(task => this.#isRevoked(task)))
      throw new GuardError('TASK_REVOKED');
    const current = own(state.tools, action.action.tool);
    if (action.action.policyVersion !== state.epoch) throw new GuardError('POLICY_CHANGED');
    if (!current || current.revision !== action.toolRevision || current.fingerprint !== action.action.toolFingerprint)
      throw new GuardError('TOOL_CHANGED');
    if (!current.approved) throw new GuardError('TOOL_UNAPPROVED');
    const registration = this.#tools.get(action.action.tool);
    if (!registration || registration.revision !== current.revision) throw new GuardError('TOOL_UNKNOWN');
    const task = this.#task(state, action.taskId);
    assertActionAuthority(action.action, this.#authorities(state, action.taskId), {
      now: this.#now(state),
      maxCost: action.maxCost,
      controlPlane: registration.definition.controlPlane ?? false,
      sensitive: state.families[task.family]!.sensitive,
      secretValues: this.#secrets,
      phase,
      untrusted: state.families[task.family]!.untrusted === true,
      untrustedContext: this.#untrustedModeOf(registration.definition),
    });
  }
  #untrustedModeOf(definition: ToolDefinition): UntrustedContextMode {
    return definition.untrustedContext ?? this.#untrustedDefault;
  }
  /** The family has read outside content and this tool requires a review after that. */
  #untrustedApproval(state: Ledger, action: StoredAction): boolean {
    const registration = this.#tools.get(action.action.tool);
    return (
      state.families[this.#task(state, action.taskId).family]!.untrusted === true &&
      !!registration &&
      this.#untrustedModeOf(registration.definition) === 'require_approval'
    );
  }
  /** The exact inputs a custom policy sees for this task: its own counters and shared sensitivity. */
  #policyInputs(state: Ledger, taskId: string): string {
    return canonicalJson(this.#snapshot(state, this.#task(state, taskId)) as unknown as Json);
  }
  /** Waits for this task's earlier re-evaluations; the returned function ends this turn (idempotent). */
  async #policyTurn(taskId: string): Promise<() => void> {
    const previous = this.#policyTurns.get(taskId) ?? Promise.resolve();
    let end!: () => void;
    const turn = new Promise<void>(resolve => {
      end = resolve;
    });
    const tail = previous.then(() => turn);
    this.#policyTurns.set(taskId, tail);
    await previous;
    let ended = false;
    return () => {
      if (ended) return;
      ended = true;
      end();
      if (this.#policyTurns.get(taskId) === tail) this.#policyTurns.delete(taskId);
    };
  }
  async #decision(state: Ledger, action: StoredAction): Promise<'allow' | 'require_approval'> {
    if (!this.#policy) return 'allow';
    const task = this.#task(state, action.taskId);
    return this.#policyAdmission.evaluate(this.#policy, clone(action.action), clone(this.#snapshot(state, task)), {
      familyId: task.family,
      taskIds: this.#provenance(state, action.taskId).map(source => source.options.id),
      remainingMs: task.options.budget.deadline - this.#now(state),
    });
  }

  /**
   * Registers a tool and returns its fingerprint; the tool then needs approveTool(). A new or changed
   * tool adds to the ledger and is refused at its soft limit. A tool the ledger already records with
   * the same fingerprint is not: the first registration after a start writes nothing at all, so a
   * process can always register its tools again, and a repeated one only resets the approval.
   */
  registerTool(definition: ToolDefinition): string {
    // Reuse the core's definition validation and canonical fingerprint.
    const verifier = new AgentGuard({
      clock: this.#clock,
      limits: { maxToolDefinitionBytes: this.#maxToolDefinitionBytes },
    });
    const fingerprint = verifier.registerTool(definition);
    const canonical = verifier.toolChanges(definition.name).definition;
    const trusted = Object.freeze({ ...definition });
    const recorded = own(this.#store.read().tools, definition.name);
    const unchanged = recorded !== undefined && recorded.fingerprint === fingerprint;
    // Opening the executor withdrew every approval and ended every earlier preparation, so the record
    // of a tool this process has not registered yet is already what registering it again would write.
    if (unchanged && !recorded.approved && !this.#tools.has(definition.name)) {
      this.#tools.set(definition.name, { definition: trusted, fingerprint, revision: recorded.revision, canonical });
      return fingerprint;
    }
    // Replacing a record with the same fingerprint only withdraws its approval: that is not growth.
    const growth = unchanged ? undefined : GROWTH;
    const revision = this.#write(state => {
      const now = this.#now(state);
      const old = own(state.tools, definition.name);
      if (!old && Object.keys(state.tools).length >= this.#maxRecords) {
        // Records left by earlier runs for tools this process has not registered are reclaimed first.
        for (const name of Object.keys(state.tools)) if (!this.#tools.has(name)) delete state.tools[name];
        if (Object.keys(state.tools).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      }
      let revision = (old?.revision ?? 0) + 1;
      // A name registered again after its record was removed must not match an action prepared before.
      if (!old)
        for (const action of Object.values(state.actions))
          if (action.action.tool === definition.name && action.toolRevision >= revision)
            revision = action.toolRevision + 1;
      // The approved definition stays: it is what toolChanges() compares the new registration with.
      state.tools[definition.name] = {
        fingerprint,
        revision,
        approved: false,
        ...(old?.baseline === undefined ? {} : { baseline: old.baseline }),
      };
      this.#audit(state, now, 'TOOL_REGISTERED');
      return revision;
    }, growth);
    this.#tools.set(definition.name, { definition: trusted, fingerprint, revision, canonical });
    return fingerprint;
  }
  /**
   * Approves the current registration and records the approval in the ledger: the fingerprint, the
   * definition (for toolChanges() after a later change or a restart), the time, the optional
   * `approverId` and the approved fingerprint it replaces. With `reviewedAgainst`, approval is refused
   * unless that is still the last approved fingerprint. TOOL_UNKNOWN for a name this process has not
   * registered; TOOL_CHANGED when the fingerprint is not current or `reviewedAgainst` does not match;
   * INVALID_INPUT for malformed options.
   */
  approveTool(name: string, fingerprint: string, options?: ExecutorApproveToolOptions): void {
    if (options !== undefined && (options === null || typeof options !== 'object'))
      throw new GuardError('INVALID_INPUT');
    const reviewed = options?.reviewedAgainst;
    if (reviewed !== undefined && reviewed !== null && typeof reviewed !== 'string')
      throw new GuardError('INVALID_INPUT');
    const approverId = options?.approverId === undefined ? undefined : id(options.approverId);
    const approve = (keepDefinition: boolean) => (state: Ledger) => {
      const tool = own(state.tools, id(name));
      const registered = this.#tools.get(name);
      if (!tool || !registered) throw new GuardError('TOOL_UNKNOWN');
      if (tool.fingerprint !== fingerprint) throw new GuardError('TOOL_CHANGED');
      const previous = tool.baseline;
      if (reviewed !== undefined && reviewed !== (previous?.fingerprint ?? null)) throw new GuardError('TOOL_CHANGED');
      const now = this.#now(state);
      // Approving the same definition again keeps what the first approval of it replaced.
      const replaced = previous?.fingerprint === fingerprint ? previous.replaced : previous?.fingerprint;
      let definition =
        previous?.fingerprint === fingerprint && previous.definition !== undefined
          ? previous.definition
          : keepDefinition && registered.fingerprint === fingerprint
            ? registered.canonical
            : undefined;
      // Kept definitions share an eighth of the ledger, so they cannot crowd out tasks and actions.
      if (definition !== undefined && definition !== previous?.definition) {
        let bytes = Buffer.byteLength(canonicalJson(definition as Json));
        for (const [other, record] of Object.entries(state.tools))
          if (other !== name && record.baseline?.definition !== undefined)
            bytes += Buffer.byteLength(JSON.stringify(record.baseline.definition));
        if (bytes > this.#store.maxBytes / 8) definition = undefined;
      }
      tool.approved = true;
      tool.baseline = {
        fingerprint,
        ...(definition === undefined ? {} : { definition: clone(definition) }),
        approvedAt: now,
        ...(approverId === undefined ? {} : { approverId }),
        ...(replaced === undefined ? {} : { replaced }),
      };
      this.#audit(state, now, 'TOOL_APPROVED');
    };
    // Approving a definition the ledger already holds adds nothing: a plain write, as in 1.0.
    const held = own(this.#store.read().tools, name)?.baseline;
    const adds =
      this.#tools.get(name)?.canonical !== undefined &&
      !(held?.fingerprint === fingerprint && held.definition !== undefined);
    if (!adds) return this.#write(approve(false));
    try {
      // Keeping a new definition adds to the ledger, so it stops at the soft limit like any growth.
      this.#write(approve(true), GROWTH);
    } catch (error) {
      if (!(error instanceof ExecutorError) || error.code !== 'STORE_CAPACITY_EXCEEDED') throw error;
      // The approval itself must not be lost to a full ledger: record it without the definition.
      // toolChanges() then reports APPROVED_DEFINITION_NOT_KEPT instead of a diff.
      this.#write(approve(false));
    }
  }
  /**
   * Compares a tool's current registration with the last approved definition recorded in the ledger,
   * so the comparison also works after a restart. See AgentGuard.toolChanges() for the result; the
   * executor adds `approval`, the recorded approval behind `approvedFingerprint`. Read-only. A ledger
   * written by 1.0.0 holds no approved definitions: its tools report `first_approval` until approved
   * once. TOOL_UNKNOWN for a name this process has not registered.
   */
  toolChanges(name: string): ExecutorToolChanges {
    const tool = own(this.#store.read().tools, id(name));
    const registered = this.#tools.get(name);
    if (!tool || !registered) throw new GuardError('TOOL_UNKNOWN');
    const baseline = tool.baseline;
    const approvedDefinition = baseline?.definition === undefined ? undefined : immutableJson(baseline.definition);
    const base = {
      name,
      fingerprint: registered.fingerprint,
      approved: tool.approved,
      ...(baseline === undefined ? {} : { approvedFingerprint: baseline.fingerprint }),
      ...(registered.canonical === undefined ? {} : { definition: registered.canonical }),
      ...(approvedDefinition === undefined ? {} : { approvedDefinition: approvedDefinition as Json }),
      ...(baseline === undefined
        ? {}
        : {
            approval: Object.freeze({
              approvedAt: baseline.approvedAt,
              ...(baseline.approverId === undefined ? {} : { approverId: baseline.approverId }),
              ...(baseline.replaced === undefined ? {} : { replacedFingerprint: baseline.replaced }),
            }),
          }),
    };
    const none = { changes: Object.freeze([]), truncated: false };
    if (baseline === undefined) return Object.freeze({ ...base, status: 'first_approval' as const, ...none });
    if (baseline.fingerprint === registered.fingerprint)
      return Object.freeze({ ...base, status: 'unchanged' as const, ...none });
    if (registered.canonical === undefined || approvedDefinition === undefined)
      return Object.freeze({
        ...base,
        status: 'unavailable' as const,
        reason:
          registered.canonical === undefined
            ? ('DEFINITION_TOO_LARGE' as const)
            : ('APPROVED_DEFINITION_NOT_KEPT' as const),
        ...none,
      });
    return Object.freeze({
      ...base,
      status: 'changed' as const,
      ...diffToolDefinitions(approvedDefinition, registered.canonical),
    });
  }
  /**
   * Withdraws a tool's approval: new and prepared actions for it fail with TOOL_UNAPPROVED until
   * approveTool() is called again. TOOL_UNKNOWN for a name this process has not registered.
   */
  unapproveTool(name: string): void {
    this.#write(state => {
      const tool = own(state.tools, id(name));
      if (!tool || !this.#tools.has(name)) throw new GuardError('TOOL_UNKNOWN');
      tool.approved = false;
      this.#audit(state, this.#now(state), 'TOOL_APPROVAL_WITHDRAWN');
    }, CRITICAL);
  }
  /**
   * Removes a tool and its ledger record. Actions already prepared for it fail with TOOL_CHANGED and
   * new ones with TOOL_UNKNOWN; a later registration needs a new approval. A call already dispatched
   * runs to completion. TOOL_UNKNOWN when neither this process nor the ledger knows the name.
   */
  unregisterTool(name: string): void {
    id(name);
    this.#write(state => {
      if (!this.#tools.has(name) && !own(state.tools, name)) throw new GuardError('TOOL_UNKNOWN');
      delete state.tools[name];
      this.#audit(state, this.#now(state), 'TOOL_UNREGISTERED');
    }, CRITICAL);
    this.#tools.delete(name);
  }
  setPolicy(policy: Policy): void {
    if (typeof policy !== 'function') throw new GuardError('INVALID_INPUT');
    this.#write(state => {
      state.epoch++;
      this.#audit(state, this.#now(state), 'POLICY_CHANGED');
    });
    this.#policy = policy;
    this.#policyAdmission.invalidate('POLICY_CHANGED');
  }
  createTask(options: TaskOptions, provenance: { sensitive?: boolean; sourceTaskId?: string } = {}): TaskCredential {
    if (!plain(provenance)) throw new GuardError('INVALID_INPUT');
    return this.#newTask(options, null, provenance);
  }
  delegateTask(parentId: string, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskCredential {
    if (!plain(options)) throw new GuardError('INVALID_INPUT');
    const parent = this.#task(this.#store.read(), parentId);
    return this.#newTask(
      { ...options, principalId: parent.options.principalId, tenantId: parent.options.tenantId },
      parentId,
      {},
    );
  }
  #newTask(
    source: TaskOptions,
    parentId: string | null,
    provenance: { sensitive?: boolean; sourceTaskId?: string },
  ): TaskCredential {
    const options = input(source);
    if (!plain(options)) throw new GuardError('INVALID_INPUT');
    const token = randomBytes(32).toString('base64url');
    this.#write(state => {
      const now = this.#now(state);
      this.#prune(state, now);
      if (own(state.tasks, options.id) || archivedTaskIdUsed(state, options.id)) throw new GuardError('DUPLICATE_TASK');
      if (Object.keys(state.tasks).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      const validator = new AgentGuard({ clock: () => now });
      if (parentId !== null) {
        let handle;
        for (const parent of this.#lineage(state, parentId).reverse()) {
          if (this.#isRevoked(parent)) throw new GuardError('TASK_REVOKED');
          handle = handle ? validator.delegateTask(handle, parent.options) : validator.createTask(parent.options);
        }
        validator.delegateTask(handle!, options);
      } else validator.createTask(options);
      let family = parentId === null ? options.id : this.#task(state, parentId).family;
      if (provenance.sourceTaskId !== undefined) {
        const source = this.#task(state, provenance.sourceTaskId);
        if (this.#provenance(state, provenance.sourceTaskId).some(task => this.#isRevoked(task)))
          throw new GuardError('TASK_REVOKED');
        if (source.options.tenantId !== options.tenantId) throw new GuardError('TENANT_DENIED');
        family = source.family; // Handoffs share a monotonic family, including later sensitive reads.
      }
      const members = Object.values(state.tasks).filter(task => task.family === family);
      if (members.length >= this.#maxTasksPerFamily) throw new ExecutorError('FAMILY_TASK_LIMIT');
      const taskBytes =
        Buffer.byteLength(JSON.stringify(options)) +
        members.reduce((sum, task) => sum + Buffer.byteLength(JSON.stringify(task.options)), 0);
      if (taskBytes > this.#maxTaskBytesPerFamily) throw new ExecutorError('FAMILY_TASK_BYTES_LIMIT');
      if (!own(state.families, family)) state.families[family] = { sensitive: false };
      if (provenance.sensitive === true) state.families[family]!.sensitive = true;
      state.tasks[options.id] = {
        options,
        parent: parentId,
        family,
        tokenHash: hash(token),
        revoked: false,
        calls: 0,
        concurrent: 0,
        spent: 0,
        reserved: 0,
        ...(provenance.sourceTaskId === undefined ? {} : { sourceTaskId: provenance.sourceTaskId }),
      };
      // Refuse a task whose own ancestry or provenance is past the bounds every later check
      // (authentication, revocation) relies on; the transaction rolls back.
      this.#lineage(state, options.id);
      this.#provenance(state, options.id);
      this.#audit(state, now, 'TASK_CREATED', options.id);
    }, GROWTH);
    this.#tokenIndex.set(hash(token), options.id);
    return Object.freeze({ taskId: options.id, token });
  }
  /**
   * Whether a task of this executor holds the token: an in-memory lookup that never reads the ledger.
   * It is not authentication, because the task may be revoked or expired. A server uses it to refuse
   * unknown tokens and to charge rate limits before authenticate() reads the ledger.
   */
  knowsToken(token: string): boolean {
    return typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token) && this.#tokenIndex.has(hash(token));
  }
  authenticate(token: string): string {
    // Issued tokens are exactly 32 random bytes in base64url; anything else never reaches the ledger.
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new ExecutorError('UNAUTHENTICATED');
    const tokenHash = hash(token);
    const taskId = this.#tokenIndex.get(tokenHash);
    if (taskId === undefined) throw new ExecutorError('UNAUTHENTICATED');
    const state = this.#store.read();
    const task = own(state.tasks, taskId);
    if (!task || !timingSafeEqual(Buffer.from(tokenHash, 'hex'), Buffer.from(task.tokenHash, 'hex'))) {
      if (!task) this.#tokenIndex.delete(tokenHash);
      throw new ExecutorError('UNAUTHENTICATED');
    }
    if (this.#provenance(state, task.options.id).some(task => this.#isRevoked(task)))
      throw new ExecutorError('UNAUTHENTICATED');
    const now = this.#now(state);
    for (const ancestor of this.#lineage(state, task.options.id)) {
      if (this.#isRevoked(ancestor) || now >= ancestor.options.budget.deadline)
        throw new ExecutorError('UNAUTHENTICATED');
    }
    return task.options.id;
  }
  /**
   * Revokes a task, everything derived from it and the memory those tasks wrote, and aborts their
   * running handlers.
   *
   * If the ledger write fails, the handlers are still aborted and the task is denied in this process,
   * and the call throws OPERATION_FAILED with `detail: 'REVOCATION_NOT_DURABLE'` (the store error is
   * the `cause`). The revocation is then recorded by the next ledger write that succeeds, by close(),
   * or by calling revokeTask() again, which is always safe. If the process exits before any write
   * succeeds, the revocation is lost: the task is valid again after a restart.
   */
  revokeTask(taskId: string): void {
    id(taskId);
    try {
      this.#store.transaction(state => {
        this.#task(state, taskId);
        const now = this.#now(state);
        // Revocations whose own write failed earlier are recorded in the same commit.
        for (const earlier of this.#unsavedRevocations)
          if (earlier !== taskId && own(state.tasks, earlier)) this.#revokeIn(state, earlier, now);
        this.#revokeIn(state, taskId, now);
      }, CRITICAL);
      this.#unsavedRevocations.clear();
    } catch (error) {
      // Only an existing task is remembered, so unknown IDs cannot grow this set.
      let known = false;
      if (!(error instanceof GuardError && error.code === 'INVALID_TASK'))
        for (const candidate of this.#tokenIndex.values())
          if (candidate === taskId) {
            known = true;
            break;
          }
      if (!known) throw error;
      this.#unsavedRevocations.add(taskId);
      throw new ExecutorError('OPERATION_FAILED', { detail: 'REVOCATION_NOT_DURABLE', cause: error });
    } finally {
      this.#policyAdmission.revokeTask(taskId);
      for (const active of this.#active.values()) if (active.taskIds.includes(taskId)) active.controller.abort();
    }
  }
  markSensitive(taskId: string): void {
    this.#write(state => {
      state.families[this.#task(state, taskId).family]!.sensitive = true;
      this.#now(state);
    }, CRITICAL);
  }
  /** Host-only artifact verification: historical expiry does not remove labels; revocation invalidates the source. */
  assertProvenance(taskId: string): Readonly<TaskSnapshot> {
    const state = this.#store.read();
    if (this.#provenance(state, taskId).some(task => this.#isRevoked(task))) throw new GuardError('TASK_REVOKED');
    return clone(this.#snapshot(state, this.#task(state, taskId)));
  }
  provenanceTaskIds(taskId: string): readonly string[] {
    const tasks = this.#provenance(this.#store.read(), taskId);
    if (tasks.some(task => this.#isRevoked(task))) throw new GuardError('TASK_REVOKED');
    return Object.freeze(tasks.map(task => task.options.id));
  }
  cancel(taskId: string, actionId: string): void {
    const trace = this.#traceStart(taskId, actionId);
    let cancelled: boolean;
    try {
      cancelled = this.#write(state => {
        const action = own(state.actions, actionId);
        if (!action || action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
        const cancelled = action.status === 'PREPARED';
        if (action.status === 'PREPARED') {
          action.status = 'FAILED';
          action.charged = 0;
        }
        this.#audit(state, this.#now(state), 'CANCELLATION_REQUESTED', taskId, actionId);
        return cancelled;
      }, CRITICAL);
    } catch (error) {
      // The running handler belongs to this task: stop it even though the ledger did not record the request.
      const active = this.#active.get(actionId);
      if (active && active.taskId === taskId) active.controller.abort();
      this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error));
      throw error;
    }
    this.#active.get(actionId)?.controller.abort();
    this.#record(trace, 'cancel', cancelled ? 'CANCELLED' : 'CANCEL_REQUESTED');
  }
  snapshot(taskId: string): Readonly<TaskSnapshot> {
    const state = this.#store.read();
    return clone(this.#snapshot(state, this.#task(state, taskId)));
  }

  /** Host-only, complete single-tenant observation. Never evaluates authority or invokes host callbacks. */
  inventorySnapshot(scope: InventoryScope): InventorySnapshot {
    if (!this.#inventorySource) throw new ExecutorError('INVENTORY_DISABLED');
    const state = this.#store.read();
    // Observation time is independent of the authorization clock and cannot advance its watermark.
    return projectInventory(
      state,
      this.#tools,
      { ...this.#inventorySource, untrustedContextDefault: this.#untrustedDefault },
      scope,
      Date.now(),
      this.#inventoryReferenceKey,
    );
  }

  async prepare(taskId: string, request: { tool: string; args: Json }): Promise<PreparedAction> {
    const actionId = randomUUID();
    const trace = this.#traceStart(taskId, actionId);
    try {
      const prepared = await this.#prepare(taskId, request, actionId, trace);
      this.#record(trace, 'prepare', 'PREPARED', prepared.requiresApproval ? 'REVIEW_REQUIRED' : 'OK');
      return prepared;
    } catch (error) {
      this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error));
      throw error;
    }
  }
  async #prepare(
    taskId: string,
    request: { tool: string; args: Json },
    actionId: string,
    trace: TraceContext | undefined,
  ): Promise<PreparedAction> {
    const wanted = input(request);
    if (
      !plain(wanted) ||
      Object.keys(wanted).some(key => key !== 'tool' && key !== 'args') ||
      !Object.hasOwn(wanted, 'args')
    )
      throw new GuardError('INVALID_INPUT');
    const registration = this.#tools.get(id(wanted.tool));
    if (!registration) throw new GuardError('TOOL_UNKNOWN');
    const state = this.#store.read();
    const task = this.#task(state, taskId);
    if (this.#provenance(state, taskId).some(ancestor => this.#isRevoked(ancestor)))
      throw new GuardError('TASK_REVOKED');
    if (!own(state.tools, wanted.tool)?.approved) throw new GuardError('TOOL_UNAPPROVED');
    if (this.#policy) this.#policyAdmission.assertCapacity(task.family);
    // Core preparation validates resolver output, mandatory gates and immutable argument binding.
    const verifier = new AgentGuard({ clock: () => this.#now(state), secretValues: this.#secrets });
    const fp = verifier.registerTool(registration.definition);
    verifier.approveTool(wanted.tool, fp);
    const handle = verifier.createTask(task.options);
    const verified = await verifier.prepare(handle, wanted);
    const action = clone({ ...verified.action, toolFingerprint: registration.fingerprint, policyVersion: state.epoch });
    const stored: StoredAction = {
      id: actionId,
      taskId,
      action,
      toolRevision: registration.revision,
      digest: `sha256:${digestJson(clone({ id: actionId, taskId, action, revision: registration.revision }))}`,
      requiresApproval: registration.definition.requiresApproval ?? false,
      status: 'PREPARED',
      maxCost: registration.definition.maxCost ?? 0,
    };
    // Retain the action's revisions, not a registration replaced before the caller resumes.
    if (trace) {
      trace.toolRevision = stored.toolRevision;
      trace.policyRevision = stored.action.policyVersion;
    }
    this.#gates(state, stored, 'prepare');
    const toolRequiresApproval = stored.requiresApproval;
    let evaluated = state;
    let endTurn: (() => void) | undefined;
    try {
      // A policy decision is only stale if this task's own snapshot changed while it ran; other
      // tasks' writes never invalidate it. A stale decision is re-evaluated on fresh state.
      for (let attempt = 1; ; attempt++) {
        if (attempt > 1) {
          endTurn ??= await this.#policyTurn(taskId);
          evaluated = this.#store.read();
          this.#gates(evaluated, stored, 'prepare');
        }
        const decision = await this.#decision(evaluated, stored);
        stored.requiresApproval =
          toolRequiresApproval || decision === 'require_approval' || this.#untrustedApproval(evaluated, stored);
        const expected = this.#policy ? this.#policyInputs(evaluated, taskId) : undefined;
        try {
          this.#write(current => {
            if (expected !== undefined && this.#policyInputs(current, taskId) !== expected)
              throw new StalePolicyDecision();
            this.#gates(current, stored, 'prepare');
            this.#prune(current, this.#now(current));
            this.#assertPendingCapacity(current, stored);
            if (Object.keys(current.actions).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
            current.actions[actionId] = stored;
            this.#audit(current, this.#now(current), 'ACTION_PREPARED', taskId, actionId);
          }, GROWTH);
          break;
        } catch (error) {
          if (!(error instanceof StalePolicyDecision)) throw error;
          if (attempt >= this.#maxPolicyAttempts) throw new GuardError('POLICY_STATE_CHANGED');
        }
      }
    } finally {
      endTurn?.();
    }
    return clone({
      id: stored.id,
      digest: stored.digest,
      action: stored.action,
      requiresApproval: stored.requiresApproval,
    });
  }
  approve(actionId: string, options: { approverId: string; expiresAt: number }): string {
    const trace = this.#traceStart(undefined, actionId);
    try {
      const approval = this.#approve(actionId, options);
      this.#record(trace, 'review', 'APPROVED');
      return approval;
    } catch (error) {
      this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error));
      throw error;
    }
  }
  #approve(actionId: string, options: { approverId: string; expiresAt: number }): string {
    if (!plain(options)) throw new GuardError('INVALID_INPUT');
    const approverId = id(options.approverId);
    const approvalId = randomUUID();
    this.#write(state => {
      this.#prune(state, this.#now(state));
      const action = own(state.actions, id(actionId));
      if (!action || action.status !== 'PREPARED') throw new GuardError('INVALID_PREPARED');
      this.#gates(state, action, 'prepare');
      const now = this.#now(state);
      if (
        !Number.isSafeInteger(options.expiresAt) ||
        options.expiresAt <= now ||
        this.#lineage(state, action.taskId).some(task => options.expiresAt > task.options.budget.deadline)
      )
        throw new GuardError('APPROVAL_INVALID');
      if (Object.keys(state.approvals).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      if (
        Object.values(state.approvals).filter(approval => approval.actionId === actionId).length >=
        this.#maxApprovalsPerAction
      )
        throw new GuardError('ACTION_APPROVAL_LIMIT');
      state.approvals[approvalId] = {
        actionId,
        digest: action.digest,
        expiresAt: options.expiresAt,
        approverId,
        used: false,
        untrusted: state.families[this.#task(state, action.taskId).family]!.untrusted === true,
      };
      this.#audit(state, now, 'ACTION_APPROVED', action.taskId, actionId);
    }, GROWTH);
    return approvalId;
  }
  /**
   * Runs a prepared action once. Before the handler starts, a refusal is the executor's own code and
   * nothing happened. After it starts, a host handler's error is always TOOL_FAILED (its safe code is
   * `detail`) or EXECUTION_ABORTED: the outcome is unknown until reconcile(). The built-in tools keep
   * their documented codes.
   */
  async execute(taskId: string, actionId: string, options: { approvalId?: string } = {}): Promise<Json> {
    let trace: TraceContext | undefined;
    try {
      if (!plain(options)) throw new GuardError('INVALID_INPUT');
      const initial = this.#store.read();
      trace = this.#traceStart(taskId, actionId, initial);
      return await this.#execute(taskId, actionId, options, trace, initial);
    } catch (error) {
      this.#record(
        trace,
        trace?.admitted ? 'error' : 'deny',
        trace?.admitted ? 'ERROR' : 'DENIED',
        decisionTraceCode(error),
      );
      throw error;
    }
  }
  async #execute(
    taskId: string,
    actionId: string,
    options: { approvalId?: string },
    trace: TraceContext | undefined,
    initial: Ledger,
  ): Promise<Json> {
    const check = (state: Ledger): StoredAction => {
      const found = own(state.actions, id(actionId));
      if (!found || found.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
      if (found.status !== 'PREPARED') throw new GuardError('ACTION_USED');
      this.#gates(state, found);
      return found;
    };
    let record = check(initial);
    let decision: 'allow' | 'require_approval' = 'allow';
    let expected: string | undefined;
    const controller = new AbortController();
    const admit = () =>
      this.#write(state => {
        // Only this task's own policy inputs can make the decision stale; other tenants' writes cannot.
        if (expected !== undefined && this.#policyInputs(state, taskId) !== expected) throw new StalePolicyDecision();
        // The action can be pruned while a policy evaluation is pending (tool re-registered,
        // task expired or revoked): that is a denial, never an internal error.
        const action = own(state.actions, actionId);
        if (!action || action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
        if (action.status !== 'PREPARED') throw new GuardError('ACTION_USED');
        this.#gates(state, action);
        const now = this.#now(state);
        let approvalDeadline: number | undefined;
        if (
          options.approvalId !== undefined ||
          action.requiresApproval ||
          decision === 'require_approval' ||
          this.#untrustedApproval(state, action)
        ) {
          if (!options.approvalId) throw new GuardError('APPROVAL_REQUIRED');
          const approval = own(state.approvals, options.approvalId);
          if (!approval || approval.actionId !== actionId || approval.digest !== action.digest)
            throw new GuardError('APPROVAL_INVALID');
          if (approval.used) throw new GuardError('APPROVAL_USED');
          if (now >= approval.expiresAt) throw new GuardError('APPROVAL_EXPIRED');
          const family = state.families[this.#task(state, taskId).family]!;
          const registration = this.#tools.get(action.action.tool);
          // Approved while the family was clean (or by an alpha that did not record it); it has since read outside content.
          if (
            approval.untrusted !== true &&
            family.untrusted === true &&
            registration &&
            this.#untrustedModeOf(registration.definition) !== 'allow'
          )
            throw new GuardError('APPROVAL_CONTEXT_CHANGED');
          approval.used = true;
          approvalDeadline = approval.expiresAt;
        }
        const ancestors = this.#lineage(state, taskId);
        for (const task of ancestors) {
          task.calls++;
          task.concurrent++;
          task.reserved += action.maxCost;
        }
        const task = this.#task(state, taskId);
        if (action.action.sensitive) state.families[task.family]!.sensitive = true;
        // Persisted at admission, before the handler runs, and never cleared; it survives restart.
        if (this.#tools.get(action.action.tool)?.definition.readsUntrusted || action.action.untrusted)
          state.families[task.family]!.untrusted = true;
        // Admission and dispatch are one commit: recovery treats ADMITTED and RUNNING alike, and a
        // separate RUNNING commit would only add a full ledger write to every call.
        action.status = 'RUNNING';
        this.#audit(state, now, 'ACTION_ADMITTED', taskId, actionId);
        return {
          action: clone(action),
          identity: clone({ id: taskId, principalId: task.options.principalId, tenantId: task.options.tenantId }),
          taskIds: this.#provenance(state, taskId).map(parent => parent.options.id),
          deadline: task.options.budget.deadline,
          approvalDeadline,
        };
      }, GROWTH);
    let admitted!: ReturnType<typeof admit>;
    let endTurn: (() => void) | undefined;
    try {
      for (let attempt = 1; ; attempt++) {
        if (attempt > 1) {
          endTurn ??= await this.#policyTurn(taskId);
          initial = this.#store.read();
          record = check(initial);
        }
        decision = await this.#decision(initial, record);
        expected = this.#policy ? this.#policyInputs(initial, taskId) : undefined;
        try {
          admitted = admit();
          break;
        } catch (error) {
          if (!(error instanceof StalePolicyDecision)) throw error;
          if (attempt >= this.#maxPolicyAttempts) throw new GuardError('POLICY_STATE_CHANGED');
        }
      }
    } finally {
      endTurn?.();
    }
    if (trace) trace.admitted = true;
    this.#record(trace, 'admit', 'ADMITTED');
    this.#active.set(actionId, { taskId, taskIds: admitted.taskIds, controller });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = (now: number): void => {
      const remaining = admitted.deadline - now;
      if (remaining <= 0) {
        controller.abort();
        return;
      }
      timer = setTimeout(
        () => {
          try {
            arm(this.#now());
          } catch {
            controller.abort();
          }
        },
        Math.min(remaining, 2_147_483_647),
      );
    };
    /** The store error behind a failed settlement or UNKNOWN write, kept on the error the caller gets. */
    const withLedgerError = <E extends object>(error: E, ledgerError: unknown): E => {
      try {
        if (!Object.hasOwn(error, 'ledgerError'))
          Object.defineProperty(error, 'ledgerError', { value: ledgerError, enumerable: false });
      } catch {
        /* A frozen error keeps its own shape. */
      }
      return error;
    };
    /** Revocation after a malformed result must not replace the error that explains it. */
    const revoke = (): void => {
      try {
        this.revokeTask(taskId);
      } catch {
        /* revokeTask already denied the task in this process and stopped its handlers. */
      }
    };
    try {
      // SQLite commits can take long enough to outlive the task or its one-use approval.
      // No handler has run, so a deadline denial can safely settle with zero cost.
      const dispatchTime = this.#now();
      if (
        dispatchTime >= admitted.deadline ||
        (admitted.approvalDeadline !== undefined && dispatchTime >= admitted.approvalDeadline)
      ) {
        const code = dispatchTime >= admitted.deadline ? 'TASK_EXPIRED' : 'APPROVAL_EXPIRED';
        this.#settle(actionId, 'FAILED', 0);
        this.#record(trace, 'settle', 'FAILED', code);
        throw new GuardError(code);
      }
      arm(dispatchTime);
      const tool = this.#tools.get(admitted.action.action.tool)!;
      let raw: Awaited<ReturnType<ToolDefinition['execute']>>;
      try {
        raw = await tool.definition.execute(
          admitted.action.action.args,
          Object.freeze({
            signal: controller.signal,
            action: admitted.action.action,
            task: admitted.identity,
          }),
        );
      } catch (error) {
        const refusal = toolRefusalOf(error);
        // A cancelled, revoked or expired call is EXECUTION_ABORTED whichever tool was running:
        // a built-in tool's own abort code (for example SANDBOX_ABORTED) does not replace it.
        if (refusal && (refusal.noEffect || !controller.signal.aborted)) {
          // A built-in tool's own refusal keeps its code. One that provably changed nothing (it was
          // raised inside a rolled-back ledger transaction) settles FAILED at zero cost, so it does
          // not hold a concurrency slot or a reservation as an unknown outcome would.
          if (refusal.noEffect) {
            this.#settle(actionId, 'FAILED', 0);
            this.#record(trace, 'settle', 'FAILED', decisionTraceCode(error));
          }
          throw error;
        }
        // A host handler cannot speak for the executor: whatever it threw is a tool failure.
        const detail = controller.signal.aborted ? undefined : safeDetail(error);
        const code = controller.signal.aborted ? 'EXECUTION_ABORTED' : 'TOOL_FAILED';
        throw new GuardError(code, code, detail === undefined ? {} : { detail });
      }
      let result: { value: Json; actualCost?: number };
      try {
        result = clone(raw);
        if (!result || typeof result !== 'object' || !Object.hasOwn(result, 'value')) throw new Error();
      } catch {
        revoke();
        throw new GuardError('RESULT_INVALID');
      }
      const cost = result.actualCost ?? admitted.action.maxCost;
      if (!Number.isSafeInteger(cost) || cost < 0 || cost > admitted.action.maxCost) {
        revoke();
        throw new GuardError('COST_REPORT_INVALID');
      }
      try {
        this.#settle(actionId, 'SUCCEEDED', cost);
      } catch (error) {
        // The handler finished but the ledger could not record it: say the effect happened.
        throw withLedgerError(
          new GuardError('EXECUTION_ABORTED', 'EXECUTION_ABORTED', { detail: 'EFFECT_COMMITTED' }),
          error,
        );
      }
      this.#record(trace, 'settle', 'SUCCEEDED');
      // The effect is committed and settled as SUCCEEDED, but the task was cancelled, revoked or
      // ran past its deadline: withhold the result and say the effect happened. A clock that
      // fails here is the same case, never a CLOCK_INVALID denial.
      let late = controller.signal.aborted;
      if (!late) {
        try {
          late = this.#now() >= admitted.deadline;
        } catch {
          late = true;
        }
      }
      if (late) throw new GuardError('EXECUTION_ABORTED', 'EXECUTION_ABORTED', { detail: 'EFFECT_COMMITTED' });
      return result.value;
    } catch (error) {
      let unknown = false;
      let ledgerError: unknown;
      try {
        unknown = this.#write(state => {
          const action = own(state.actions, actionId);
          if (action && (action.status === 'ADMITTED' || action.status === 'RUNNING')) {
            // A faulty clock must not roll back conservative recovery and strand a reservation
            // in RUNNING. Use the last trusted time for this audit entry only.
            let observed = state.lastClock;
            try {
              observed = this.#now(state);
            } catch (clockError) {
              if (!(clockError instanceof GuardError && clockError.code === 'CLOCK_INVALID')) throw clockError;
            }
            action.status = 'UNKNOWN';
            this.#audit(state, observed, 'OUTCOME_UNKNOWN', taskId, actionId);
            return true;
          }
          return false;
        }, CRITICAL);
      } catch (failure) {
        // The action stays RUNNING in the ledger; reconcile() accepts it once this call has returned.
        ledgerError = failure;
      }
      if (unknown) this.#record(trace, 'unknown', 'UNKNOWN', 'OUTCOME_UNKNOWN');
      const reported =
        error instanceof GuardError || error instanceof ExecutorError
          ? error
          : new GuardError(controller.signal.aborted ? 'EXECUTION_ABORTED' : 'TOOL_FAILED');
      // The caller always gets the error that explains the call, never the recovery failure in its place.
      throw ledgerError === undefined ? reported : withLedgerError(reported, ledgerError);
    } finally {
      if (timer) clearTimeout(timer);
      this.#active.delete(actionId);
    }
  }
  #settle(
    actionId: string,
    status: 'SUCCEEDED' | 'FAILED',
    actualCost: number,
    reconciliationReferenceHash?: string,
  ): void {
    this.#write(state => {
      const action = own(state.actions, actionId);
      if (!action || !['ADMITTED', 'RUNNING', 'UNKNOWN'].includes(action.status))
        throw new ExecutorError('RECONCILIATION_INVALID');
      if (!Number.isSafeInteger(actualCost) || actualCost < 0 || actualCost > action.maxCost)
        throw new GuardError('COST_REPORT_INVALID');
      for (const task of this.#lineage(state, action.taskId)) {
        task.concurrent--;
        task.reserved -= action.maxCost;
        task.spent += actualCost;
      }
      action.status = status;
      action.charged = actualCost;
      const now = this.#now(state);
      if (reconciliationReferenceHash !== undefined)
        action.reconciliation = { referenceHash: reconciliationReferenceHash, time: now };
      this.#audit(state, now, 'ACTION_SETTLED', action.taskId, actionId);
    }, CRITICAL);
  }
  /**
   * Operator-only reconciliation requires evidence that backend work has ended; never call on lease
   * expiry alone. Accepts an UNKNOWN action, and one left RUNNING because the ledger could not record
   * UNKNOWN, once no handler for it is running in this process.
   */
  reconcile(
    actionId: string,
    evidence: { outcome: 'SUCCEEDED' | 'FAILED'; actualCost: number; reference: string },
  ): void {
    const trace = this.#traceStart(undefined, actionId);
    try {
      let supplied: typeof evidence;
      try {
        supplied = clone(evidence);
      } catch {
        throw new ExecutorError('RECONCILIATION_INVALID');
      }
      this.#reconcile(actionId, supplied);
      this.#record(trace, 'reconcile', supplied.outcome, 'RECONCILED');
    } catch (error) {
      this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error));
      throw error;
    }
  }
  #reconcile(
    actionId: string,
    evidence: { outcome: 'SUCCEEDED' | 'FAILED'; actualCost: number; reference: string },
  ): void {
    if (!plain(evidence) || (evidence.outcome !== 'SUCCEEDED' && evidence.outcome !== 'FAILED'))
      throw new ExecutorError('RECONCILIATION_INVALID');
    if (typeof evidence.reference !== 'string' || !evidence.reference.trim() || evidence.reference.length > 4096)
      throw new ExecutorError('RECONCILIATION_INVALID');
    const action = own(this.#store.read().actions, id(actionId));
    if (!action || !['UNKNOWN', 'ADMITTED', 'RUNNING'].includes(action.status) || this.#active.has(actionId))
      throw new ExecutorError('RECONCILIATION_INVALID');
    this.#settle(actionId, evidence.outcome, evidence.actualCost, hash(evidence.reference));
  }
  execution(taskId: string, actionId: string): ExecutionReceipt {
    const state = this.#store.read();
    const action = own(state.actions, id(actionId));
    if (!action) {
      const task = own(state.tasks, id(taskId));
      const stub = task && prunedReceipt(state, task.family, actionId);
      if (!stub || stub.taskId !== taskId) {
        // The stub is gone too, but a retained settlement event still shows that this task's
        // action settled: report PRUNED without an outcome rather than "never prepared".
        if (
          task &&
          state.audit.some(
            event => event.event === 'ACTION_SETTLED' && event.actionId === actionId && event.taskId === taskId,
          )
        )
          return clone({ id: actionId, status: 'PRUNED' as const });
        throw new GuardError('INVALID_PREPARED');
      }
      return clone({
        id: actionId,
        status: 'PRUNED',
        outcome: stub.outcome,
        ...(stub.charged === undefined ? {} : { charged: stub.charged }),
        ...(stub.reconciliation === undefined ? {} : { reconciliation: stub.reconciliation }),
      });
    }
    if (action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
    return clone({
      id: action.id,
      status: action.status,
      ...(action.charged === undefined ? {} : { charged: action.charged }),
      ...(action.reconciliation === undefined ? {} : { reconciliation: action.reconciliation }),
    });
  }
  /** The ledger's data layout version, authority-mode schema and optional features. */
  ledgerFormat(): LedgerFormat {
    return describeLedgerFormat(this.#store.read());
  }
  /**
   * Recent metadata events, oldest first. Bounded per tenant: this is not a complete history.
   * Export durably by polling and comparing `sequence`; a gap means events were evicted.
   */
  audit(scope: { tenantId?: string } = {}): readonly Readonly<AuditEvent>[] {
    if (!plain(scope)) throw new GuardError('INVALID_INPUT');
    const tenantId = scope.tenantId === undefined ? undefined : id(scope.tenantId);
    const events = this.#store.read().audit;
    // Identifiers may be long: the ring can exceed the default 1 MiB value bound.
    return immutableJson(
      tenantId === undefined ? events : events.filter(event => event.tenantId === tenantId),
      8,
      200_000,
      64 * 1024 * 1024,
    ) as unknown as readonly Readonly<AuditEvent>[];
  }
  /**
   * Host-only read-back of a stored action, for the review screen: what an action ID denotes,
   * from the ledger, not from the party that asked for approval. Show `action` (tool, arguments,
   * resource, recipient) to the authenticated reviewer before calling approve().
   */
  preparedAction(actionId: string): Readonly<{
    id: string;
    taskId: string;
    digest: string;
    action: PreparedAction['action'];
    requiresApproval: boolean;
    status: StoredAction['status'];
  }> {
    const stored = own(this.#store.read().actions, id(actionId));
    if (!stored) throw new GuardError('INVALID_PREPARED');
    return clone({
      id: stored.id,
      taskId: stored.taskId,
      digest: stored.digest,
      action: stored.action,
      requiresApproval: stored.requiresApproval,
      status: stored.status,
    });
  }

  #memory(state: Ledger, tenantId: string, entryId: string): MemoryRecord {
    const entry = own(state.memory, JSON.stringify([tenantId, entryId]))?.at(-1);
    if (!entry || entry.quarantined) throw new ExecutorError('MEMORY_UNAVAILABLE');
    return entry;
  }
  #writeMemory(state: Ledger, entry: Omit<MemoryRecord, 'version' | 'quarantined'>, taskId?: string): MemoryRecord {
    if (archivedMemoryIdUsed(state, entry.tenantId, entry.id)) throw new ExecutorError('MEMORY_UNAVAILABLE');
    if (Buffer.byteLength(canonicalJson(clone(entry.value) as Json)) > 65_536) throw new ExecutorError('MEMORY_LIMIT');
    const key = JSON.stringify([id(entry.tenantId), id(entry.id)]);
    const history = own(state.memory, key) ?? [];
    if (entry.familyId !== undefined) {
      const familyEntries = Object.values(state.memory)
        .flat()
        .filter(item => item.familyId === entry.familyId);
      const bytes = familyEntries.reduce(
        (total, item) => total + Buffer.byteLength(JSON.stringify(item)),
        Buffer.byteLength(JSON.stringify(entry)),
      );
      if (familyEntries.length >= 256 || bytes > 512 * 1024) throw new ExecutorError('FAMILY_MEMORY_LIMIT');
    }
    if (history.length >= 128 || (!history.length && Object.keys(state.memory).length >= this.#maxRecords))
      throw new ExecutorError('MEMORY_LIMIT');
    const next: MemoryRecord = { ...entry, version: (history.at(-1)?.version ?? 0) + 1, quarantined: false };
    state.memory[key] = [...history, next];
    // Recorded under the entry's tenant, so memory traffic never displaces system events.
    this.#recordEvent(state, this.#now(state), 'MEMORY_WRITTEN', {
      tenantId: entry.tenantId,
      ...(taskId === undefined ? {} : { taskId }),
    });
    return next;
  }
  /** Operator import. Unknown sensitivity is restricted; trust is metadata, never execution authority. */
  importMemory(entry: {
    id: string;
    tenantId: string;
    origin: string;
    value: Json;
    sensitive?: boolean;
    trusted?: boolean;
    /** The content came from outside the trust boundary: reading it marks the reader's family. */
    untrusted?: boolean;
  }): void {
    const supplied = input(entry);
    if (!plain(supplied) || !Object.hasOwn(supplied, 'value')) throw new GuardError('INVALID_INPUT');
    id(supplied.tenantId);
    id(supplied.id);
    this.#write(state => {
      const previous = own(state.memory, JSON.stringify([supplied.tenantId, supplied.id]))?.at(-1);
      this.#writeMemory(state, {
        id: supplied.id,
        tenantId: supplied.tenantId,
        origin: id(supplied.origin),
        value: supplied.value,
        sensitive: supplied.sensitive !== false || previous?.sensitive === true,
        trusted: supplied.trusted === true,
        ...(supplied.untrusted === true ? { untrusted: true } : {}),
        parentIds: previous?.parentIds ?? [],
      });
    }, GROWTH);
  }
  /** Registers two ordinary scoped tools. The caller must approve their fingerprints separately. */
  registerMemoryTools(prefix = 'memory'): Readonly<{ read: string; write: string }> {
    id(prefix);
    const parse = (value: Json, write: boolean): Json => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new GuardError('ARGUMENT_INVALID');
      const fields = value as Record<string, Json>;
      if (Object.keys(fields).some(key => !(write ? ['id', 'value', 'ifVersion'] : ['id']).includes(key)))
        throw new GuardError('ARGUMENT_INVALID');
      id(fields.id);
      if (
        write &&
        (!Object.hasOwn(fields, 'value') || !Number.isSafeInteger(fields.ifVersion) || Number(fields.ifVersion) < 0)
      )
        throw new GuardError('ARGUMENT_INVALID');
      return value;
    };
    // A memory tool's whole effect is one ledger transaction. A coded refusal from inside it rolled
    // that transaction back, so nothing happened: execute() keeps the code and settles the action
    // FAILED at zero cost. The ledger revision is compared to make "nothing happened" a checked fact.
    const transact = <T>(operation: (state: Ledger) => T): T => {
      let revision: number | undefined;
      try {
        return this.#write(state => {
          revision = state.revision;
          return operation(state);
        }, GROWTH);
      } catch (error) {
        let unchanged = false;
        try {
          unchanged = revision !== undefined && this.#store.read().revision === revision;
        } catch {
          /* An unreadable ledger proves nothing: the outcome stays unknown. */
        }
        throw toolRefusal(error, unchanged);
      }
    };
    const read = this.registerTool({
      name: `${prefix}.read`,
      description: 'Read versioned, labeled memory as untrusted content.',
      parse: value => parse(value, false),
      resolve: (args, task) => {
        const entry = this.#memory(this.#store.read(), task.tenantId, (args as { id: string }).id);
        return {
          resourceId: entry.id,
          tenantId: entry.tenantId,
          resourceVersion: String(entry.version),
          sensitive: entry.sensitive,
          // Content written after its author read outside content carries that mark to the reader.
          ...(entry.untrusted === true ? { untrusted: true as const } : {}),
        };
      },
      execute: (args, context) =>
        transact(state => {
          const entry = this.#memory(state, context.task.tenantId, (args as { id: string }).id);
          if (String(entry.version) !== context.action.resourceVersion)
            throw new ExecutorError('MEMORY_VERSION_CHANGED');
          const family = state.families[this.#task(state, context.task.id).family]!;
          family.sensitive ||= entry.sensitive;
          family.memorySources = [...new Set([...(family.memorySources ?? []), entry.id])];
          if (family.memorySources.length > 1000) throw new ExecutorError('MEMORY_LIMIT');
          return { value: clone(entry) as unknown as Json };
        }),
    });
    const write = this.registerTool({
      name: `${prefix}.write`,
      description: 'Write untrusted memory with an exact expected version and inherited labels.',
      parse: value => parse(value, true),
      resolve: (args, task) => {
        const wanted = args as { id: string; ifVersion: number };
        const state = this.#store.read();
        if (archivedMemoryIdUsed(state, task.tenantId, wanted.id)) throw new ExecutorError('MEMORY_UNAVAILABLE');
        const previous = own(state.memory, JSON.stringify([task.tenantId, wanted.id]))?.at(-1);
        if (previous?.quarantined || (previous?.version ?? 0) !== wanted.ifVersion)
          throw new ExecutorError('MEMORY_VERSION_CHANGED');
        return { resourceId: wanted.id, tenantId: task.tenantId, resourceVersion: String(wanted.ifVersion) };
      },
      execute: (args, context) =>
        transact(state => {
          const wanted = args as { id: string; value: Json; ifVersion: number };
          const previous = own(state.memory, JSON.stringify([context.task.tenantId, wanted.id]))?.at(-1);
          if (previous?.quarantined || String(previous?.version ?? 0) !== context.action.resourceVersion)
            throw new ExecutorError('MEMORY_VERSION_CHANGED');
          const familyId = this.#task(state, context.task.id).family;
          const family = state.families[familyId]!;
          for (const parent of family.memorySources ?? []) this.#memory(state, context.task.tenantId, parent);
          const entry = this.#writeMemory(
            state,
            {
              id: wanted.id,
              tenantId: context.task.tenantId,
              origin: `task:${context.task.id}`,
              value: wanted.value,
              sensitive: family.sensitive || previous?.sensitive === true,
              trusted: false,
              ...(family.untrusted === true ? { untrusted: true } : {}),
              familyId,
              parentIds: [...new Set([...(previous?.parentIds ?? []), ...(family.memorySources ?? [])])],
            },
            context.task.id,
          );
          return { value: { id: entry.id, version: entry.version, sensitive: entry.sensitive, trusted: false } };
        }),
    });
    return Object.freeze({ read, write });
  }
  /**
   * Operator quarantine propagates to known descendants in the same tenant. MEMORY_UNAVAILABLE when
   * the tenant has no such entry; quarantining an entry again is allowed.
   */
  quarantineMemory(tenantId: string, entryId: string): void {
    id(tenantId);
    id(entryId);
    this.#write(state => {
      if (!own(state.memory, JSON.stringify([tenantId, entryId]))?.length)
        throw new ExecutorError('MEMORY_UNAVAILABLE');
      this.#quarantine(state, tenantId, new Set([entryId]));
      this.#recordEvent(state, this.#now(state), 'MEMORY_QUARANTINED', { tenantId });
    }, CRITICAL);
  }
  #quarantine(state: Ledger, tenantId: string, denied: Set<string>): void {
    let changed = true;
    while (changed) {
      changed = false;
      for (const history of Object.values(state.memory)) {
        const latest = history.at(-1)!;
        if (
          latest.tenantId === tenantId &&
          (denied.has(latest.id) || latest.parentIds.some(parent => denied.has(parent)))
        ) {
          if (!denied.has(latest.id)) {
            denied.add(latest.id);
            changed = true;
          }
          for (const entry of history) entry.quarantined = true;
        }
      }
    }
  }
  /** Operator-only rollback creates a new version; it never removes history or lowers sensitivity. */
  rollbackMemory(tenantId: string, entryId: string, version: number): void {
    id(tenantId);
    id(entryId);
    this.#write(state => {
      const history = own(state.memory, JSON.stringify([tenantId, entryId]));
      const previous = history?.find(entry => entry.version === version);
      if (!previous || previous.quarantined) throw new ExecutorError('MEMORY_UNAVAILABLE');
      this.#writeMemory(state, {
        ...previous,
        sensitive: history!.some(entry => entry.sensitive),
        parentIds: [...new Set(history!.flatMap(entry => entry.parentIds))],
      });
      this.#recordEvent(state, this.#now(state), 'MEMORY_ROLLED_BACK', { tenantId });
    }, GROWTH);
  }
  close(): void {
    if (this.#active.size) throw new ExecutorError('EXECUTIONS_ACTIVE');
    // The last chance to record a revocation whose write failed; if this fails too, it is lost.
    this.#saveRevocations();
    closeExecutorObservation(this);
    this.#store.close();
    this.#policyAdmission.invalidate('TASK_REVOKED');
    this.#inventoryReferenceKey?.fill(0);
    this.#traces?.close();
    this.#lifecycle.close();
  }
}
