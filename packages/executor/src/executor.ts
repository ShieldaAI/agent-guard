import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  AgentGuard, GuardError, PolicyAdmission, assertActionAuthority, canonicalJson, digestJson, immutableJson,
  type Action, type AuthorityPhase, type AuthorityState, type Json, type Policy, type PreparedAction, type TaskIdentity,
  type TaskOptions, type TaskSnapshot, type ToolDefinition,
} from '@shieldaai/agent-guard';
import { ExecutorError, LedgerStore, type ExecutionReceipt, type Ledger, type LedgerWitness, type MemoryRecord, type StoredAction, type StoredTask } from './store.js';
import { projectInventory, validateInventorySource, captureInventoryRegistrations, type InventoryOptions, type InventoryScope,
  type InventorySnapshot, type InventorySourceOptions } from './inventory.js';
import { DecisionTraces, decisionTraceCode, type DecisionTraceOptions, type DecisionTraceScope,
  type DecisionTraceSnapshot, type DecisionTraceSink, type DecisionTraceExportResult,
  type TraceContext, type DecisionTraceEventName, type DecisionTraceOutcome } from './traces.js';
import { bindExecutorObservation, closeExecutorObservation } from './inventory-observer.js';
import { archivedTaskIdUsed, archivedMemoryIdUsed, TaskFamilyLifecycle, type TaskFamilyScope, type TaskFamilyDecision, type TaskFamilyArchiveScope,
  type TaskFamilyRetirementPreview, type TaskFamilyRetirementResult, type TaskFamilyArchiveReceipt,
  type ExecutionListScope, type ExecutionList, type MaintenanceStatistics } from './lifecycle.js';
import { recordEvent, recordPruned, prunedReceipt, DEFAULT_RECENT_EVENTS_PER_TENANT, RECENT_EVENTS_TOTAL, type EventScope } from './retention.js';

function id(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 4096 || value.includes('\0')) throw new GuardError('INVALID_INPUT');
  return value;
}
function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function own<T>(record: Record<string, T>, key: string): T | undefined { return Object.hasOwn(record, key) ? record[key] : undefined; }
function clone<T>(value: T): T { return immutableJson(value) as T; }
/** Internal signal: a policy decision was made on a task snapshot that has since changed. */
class StalePolicyDecision extends Error {}
type Registered = { definition: ToolDefinition; fingerprint: string; revision: number };

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
   * (integer 1-4096, default 64). Shared caps then prune from the busiest family first.
   */
  maxReceiptsPerFamily?: number;
  /** Recent events kept per tenant (integer 16-1000, default 256); the busiest tenant is trimmed first. */
  maxRecentEventsPerTenant?: number;
  /**
   * How many times a custom policy may be evaluated for one prepare or execute when the task's own
   * snapshot (counters or shared sensitivity) changes while it runs. Writes by other tasks or tenants
   * never invalidate a decision. Integer 1-16, default 5; 1 keeps single-evaluation behaviour.
   */
  maxPolicyAttempts?: number;
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
export interface TaskCredential { taskId: string; token: string }

/** Trusted host object. Expose only the task HTTP handler to agents, never this administration object. */
export class DurableExecutor {
  readonly #store: LedgerStore;
  readonly #clock: () => number;
  readonly #secrets: readonly string[];
  readonly #maxRecords: number;
  readonly #maxReceiptsPerFamily: number;
  readonly #maxRecentEventsPerTenant: number;
  readonly #maxPolicyAttempts: number;
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
  readonly #active = new Map<string, { taskIds: string[]; controller: AbortController }>();
  readonly #policyAdmission = new PolicyAdmission();
  #policy: Policy | undefined;
  #observedClock = 0;

  constructor(options: ExecutorOptions) {
    this.#clock = options.clock ?? Date.now;
    this.#policy = options.policy;
    this.#maxRecords = options.maxRecords ?? 10_000;
    if (!Number.isSafeInteger(this.#maxRecords) || this.#maxRecords < 1) throw new GuardError('INVALID_INPUT');
    const maxLedgerBytes = options.maxLedgerBytes === undefined ? 16 * 1024 * 1024 : options.maxLedgerBytes;
    if (!Number.isSafeInteger(maxLedgerBytes) || maxLedgerBytes < 1024 * 1024 || maxLedgerBytes > 64 * 1024 * 1024) throw new GuardError('INVALID_INPUT');
    const familyShare = Math.max(1, Math.floor(this.#maxRecords / 4));
    const bounded = (value: number | undefined, fallback: number, maximum: number): number => {
      const selected = value ?? fallback;
      if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) throw new GuardError('INVALID_INPUT');
      return selected;
    };
    this.#maxPolicyAttempts = bounded(options.maxPolicyAttempts, 5, 16);
    this.#maxReceiptsPerFamily = bounded(options.maxReceiptsPerFamily, 64, 4096);
    this.#maxRecentEventsPerTenant = bounded(options.maxRecentEventsPerTenant, DEFAULT_RECENT_EVENTS_PER_TENANT, RECENT_EVENTS_TOTAL);
    if (this.#maxRecentEventsPerTenant < 16) throw new GuardError('INVALID_INPUT');
    this.#maxPendingActionsPerFamily = bounded(options.maxPendingActionsPerFamily, Math.min(32, familyShare), familyShare);
    this.#maxPendingBytesPerFamily = bounded(options.maxPendingBytesPerFamily, 256 * 1024, 1024 * 1024);
    this.#maxTasksPerFamily = bounded(options.maxTasksPerFamily, Math.min(64, familyShare), familyShare);
    this.#maxTaskBytesPerFamily = bounded(options.maxTaskBytesPerFamily, 256 * 1024, 1024 * 1024);
    this.#secrets = Object.freeze((options.secretValues ?? []).map(id));
    if (options.inventory !== undefined) {
      try {
        const config = immutableJson(options.inventory, 4, 32, 64 * 1024) as unknown as InventoryOptions;
        if (!config || Array.isArray(config) || typeof config !== 'object' ||
            Object.keys(config).some(key => !['companyId', 'sourceId', 'enrollmentGeneration', 'referenceMode'].includes(key)) ||
            (config.referenceMode !== undefined && config.referenceMode !== 'opaque' && config.referenceMode !== 'raw')) {
          throw new ExecutorError('INVENTORY_CONFIG_INVALID');
        }
        this.#inventorySource = validateInventorySource({ companyId: config.companyId, sourceId: config.sourceId,
          enrollmentGeneration: config.enrollmentGeneration });
        if (config.referenceMode !== 'raw') {
          this.#inventoryReferenceKey = createHmac('sha256', options.encryptionKey)
            .update('agent-guard-inventory-references-v1\0').update(JSON.stringify(this.#inventorySource)).digest();
        }
      } catch { throw new ExecutorError('INVENTORY_CONFIG_INVALID'); }
    }
    try { this.#store = new LedgerStore(options.database, options.encryptionKey, maxLedgerBytes, options.rollbackWitness); }
    catch (error) { this.#inventoryReferenceKey?.fill(0); throw error; }
    try {
      if (options.decisionTraces !== undefined) this.#traces = new DecisionTraces(options.decisionTraces, options.encryptionKey, this.#store.read().inventoryInstanceId);
      const recovered = this.#store.transaction(state => {
        const now = this.#now(state);
        state.epoch++; // Process/code changes invalidate every outstanding preparation.
        for (const tool of Object.values(state.tools)) tool.approved = false;
        const recovered: TraceContext[] = [];
        for (const action of Object.values(state.actions)) {
          if (action.status === 'RUNNING' || action.status === 'ADMITTED') {
            action.status = 'UNKNOWN';
            if (this.#traces) recovered.push({ tenantId: state.tasks[action.taskId]!.options.tenantId,
              taskId: action.taskId, actionId: action.id, policyRevision: state.epoch,
              toolRevision: action.toolRevision, started: performance.now() });
          }
        }
        this.#audit(state, now, 'EXECUTOR_STARTED');
        return recovered;
      });
      for (const context of recovered) this.#record(context, 'unknown', 'UNKNOWN', 'RECOVERY_UNKNOWN');
    } catch (error) { this.#store.close(); this.#inventoryReferenceKey?.fill(0); this.#traces?.close(); throw error; }
    bindExecutorObservation(this, this.#store, () => {
      if (!this.#inventorySource) throw new ExecutorError('INVENTORY_DISABLED');
      // Every registration also occupies the bounded encrypted tool ledger. Four
      // times that ceiling accommodates detached flags without a hidden global
      // 10k-tool cap on a tenant whose own exported tools remain within 10k.
      return { source: this.#inventorySource, registrations: captureInventoryRegistrations(this.#tools, this.#store.maxBytes * 4),
        referenceKey: this.#inventoryReferenceKey ? new Uint8Array(this.#inventoryReferenceKey) : undefined };
    });
    this.#lifecycle = new TaskFamilyLifecycle(this.#store, {
      now: state => this.#now(state),
      activeTaskIds: () => new Set([...this.#active.values()].flatMap(active => active.taskIds)),
      quarantine: (state, tenantId, ids) => this.#quarantine(state, tenantId, ids),
      event: (state, time, event, scope) => this.#recordEvent(state, time, event, scope),
      retired: ids => { for (const taskId of ids) this.#policyAdmission.revokeTask(taskId); },
    });
  }

  /** Host-only maintenance: authenticate the operator before selecting tenant/task scope. */
  previewTaskFamilyRetirement(scope: TaskFamilyScope): TaskFamilyRetirementPreview { return this.#lifecycle.preview(scope); }
  retireTaskFamily(scope: TaskFamilyDecision): TaskFamilyRetirementResult { return this.#lifecycle.retire(scope); }
  archiveTaskFamily(scope: TaskFamilyDecision): TaskFamilyArchiveReceipt { return this.#lifecycle.archive(scope); }
  verifyTaskFamilyArchive(scope: TaskFamilyArchiveScope): TaskFamilyArchiveReceipt { return this.#lifecycle.verifyArchive(scope); }
  findTaskFamilyArchive(scope: TaskFamilyScope): TaskFamilyArchiveReceipt | null { return this.#lifecycle.findArchive(scope); }
  listExecutions(scope: ExecutionListScope): ExecutionList { return this.#lifecycle.listExecutions(scope); }
  maintenanceStatistics(scope: { tenantId: string }): MaintenanceStatistics { return this.#lifecycle.statistics(scope); }

  #traceStart(taskId: string | undefined, actionId: string, observedState?: Ledger): TraceContext | undefined {
    if (!this.#traces) return undefined;
    try {
      const state = observedState ?? this.#store.read();
      const action = own(state.actions, actionId);
      const owner = taskId ?? action?.taskId;
      const task = owner === undefined ? undefined : own(state.tasks, owner);
      if (!task) return undefined; // Unknown/unauthenticated identities cannot select a tenant.
      return { tenantId: task.options.tenantId, taskId: task.options.id, actionId,
        policyRevision: state.epoch, toolRevision: action && action.taskId === owner ? action.toolRevision : 0,
        started: performance.now() };
    } catch { return undefined; }
  }
  #record(context: TraceContext | undefined, event: DecisionTraceEventName, outcome: DecisionTraceOutcome, code = 'OK'): void {
    // Observation failure cannot replace an authorization result or enter an exporter.
    if (context) try { this.#traces?.record(context, event, outcome, code); } catch { /* Optional observation only. */ }
  }
  /** Host-only tenant-scoped observation. Authentication must precede choosing this scope. */
  decisionTraceSnapshot(scope: DecisionTraceScope): DecisionTraceSnapshot {
    if (!this.#traces) throw new ExecutorError('TRACE_DISABLED');
    const selected = clone(scope);
    if (selected.taskId !== undefined && this.#task(this.#store.read(), selected.taskId).options.tenantId !== selected.tenantId) throw new ExecutorError('TRACE_SCOPE_DENIED');
    return this.#traces.snapshot(selected);
  }
  /** Explicit host export. No trace callback is registered on the execution path. */
  exportDecisionTraces(scope: { tenantId: string }, sink: DecisionTraceSink, options?: { timeoutMs?: number }): Promise<DecisionTraceExportResult> {
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
    try { now = this.#clock(); } catch { throw new GuardError('CLOCK_INVALID'); }
    if (!Number.isSafeInteger(now) || now < (state?.lastClock ?? 0) || now < this.#observedClock) throw new GuardError('CLOCK_INVALID');
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
    return { id: task.options.id, principalId: task.options.principalId, tenantId: task.options.tenantId,
      sensitive: state.families[task.family]!.sensitive, calls: task.calls, concurrent: task.concurrent,
      spent: task.spent, reserved: task.reserved };
  }
  #provenance(state: Ledger, taskId: string): StoredTask[] {
    const pending = [taskId]; const visited = new Map<string, StoredTask>();
    while (pending.length) {
      const current = pending.pop()!;
      if (visited.has(current)) continue;
      if (visited.size >= 1000) throw new ExecutorError('PROVENANCE_LIMIT');
      const task = this.#task(state, current); visited.set(current, task);
      if (task.parent !== null) pending.push(task.parent);
      if (task.sourceTaskId !== undefined) pending.push(task.sourceTaskId);
    }
    return [...visited.values()];
  }
  #recordEvent(state: Ledger, time: number, event: string, scope: EventScope = {}): void {
    recordEvent(state, this.#maxRecentEventsPerTenant, time, event, scope);
  }
  #audit(state: Ledger, time: number, event: string, taskId?: string, actionId?: string): void {
    this.#recordEvent(state, time, event, { ...(taskId === undefined ? {} : { taskId }), ...(actionId === undefined ? {} : { actionId }) });
  }
  /**
   * Pruning never changes cumulative counters or releases unresolved reservations.
   * Settled receipts are kept per family; shared caps prune the busiest family first,
   * so one tenant's traffic cannot evict another tenant's receipts.
   */
  #prune(state: Ledger, now: number): void {
    const settled = new Map<string, { action: StoredAction; bytes: number }[]>();
    let count = 0; let bytes = 0; let records = 0;
    for (const [actionId, action] of Object.entries(state.actions)) {
      records++;
      if (action.status === 'PREPARED') {
        const tool = own(state.tools, action.action.tool);
        if (action.action.policyVersion !== state.epoch || !tool || tool.revision !== action.toolRevision ||
            this.#provenance(state, action.taskId).some(task => task.revoked) ||
            this.#lineage(state, action.taskId).some(task => now >= task.options.budget.deadline)) { delete state.actions[actionId]; records--; }
      } else if (action.status === 'SUCCEEDED' || action.status === 'FAILED') {
        const family = this.#task(state, action.taskId).family;
        const size = Buffer.byteLength(JSON.stringify(action));
        let list = settled.get(family);
        if (!list) settled.set(family, list = []);
        list.push({ action, bytes: size }); count++; bytes += size;
      }
    }
    const evict = (family: string): void => {
      const oldest = settled.get(family)!.shift()!;
      delete state.actions[oldest.action.id]; recordPruned(state, family, oldest.action);
      count--; bytes -= oldest.bytes; records--;
    };
    for (const [family, list] of settled) while (list.length > this.#maxReceiptsPerFamily) evict(family);
    const retained = Math.min(256, Math.floor(this.#maxRecords / 2));
    while (count > 0 && (count > retained || bytes > this.#store.maxBytes / 8 || records >= this.#maxRecords)) {
      let busiest = ''; let size = 0;
      for (const [family, list] of settled) if (list.length > size) { busiest = family; size = list.length; }
      evict(busiest);
    }
    for (const [approvalId, approval] of Object.entries(state.approvals)) {
      const action = own(state.actions, approval.actionId);
      if (approval.used || approval.expiresAt <= now || !action || action.status !== 'PREPARED') delete state.approvals[approvalId];
    }
  }
  #assertPendingCapacity(state: Ledger, candidate: StoredAction): void {
    const family = this.#task(state, candidate.taskId).family;
    let count = 1; let bytes = Buffer.byteLength(JSON.stringify(candidate));
    for (const action of Object.values(state.actions)) {
      if (action.status !== 'SUCCEEDED' && action.status !== 'FAILED' && this.#task(state, action.taskId).family === family) {
        count++; bytes += Buffer.byteLength(JSON.stringify(action));
      }
    }
    if (count > this.#maxPendingActionsPerFamily) throw new ExecutorError('FAMILY_PENDING_LIMIT');
    if (bytes > this.#maxPendingBytesPerFamily) throw new ExecutorError('FAMILY_PENDING_BYTES_LIMIT');
  }
  #authorities(state: Ledger, taskId: string): AuthorityState[] {
    return this.#lineage(state, taskId).map(task => ({
      identity: task.options, grants: task.options.grants, allowedRecipients: task.options.allowedRecipients ?? [],
      allowControlPlane: task.options.allowControlPlane ?? false, budget: task.options.budget,
      snapshot: this.#snapshot(state, task), revoked: task.revoked,
    }));
  }
  #gates(state: Ledger, action: StoredAction, phase: AuthorityPhase = 'dispatch'): void {
    if (this.#provenance(state, action.taskId).some(task => task.revoked)) throw new GuardError('TASK_REVOKED');
    const current = own(state.tools, action.action.tool);
    if (action.action.policyVersion !== state.epoch) throw new GuardError('POLICY_CHANGED');
    if (!current || current.revision !== action.toolRevision || current.fingerprint !== action.action.toolFingerprint) throw new GuardError('TOOL_CHANGED');
    if (!current.approved) throw new GuardError('TOOL_UNAPPROVED');
    const registration = this.#tools.get(action.action.tool);
    if (!registration || registration.revision !== current.revision) throw new GuardError('TOOL_UNKNOWN');
    const task = this.#task(state, action.taskId);
    assertActionAuthority(action.action, this.#authorities(state, action.taskId), {
      now: this.#now(state), maxCost: action.maxCost, controlPlane: registration.definition.controlPlane ?? false,
      sensitive: state.families[task.family]!.sensitive, secretValues: this.#secrets, phase,
    });
  }
  /** The exact inputs a custom policy sees for this task: its own counters and shared sensitivity. */
  #policyInputs(state: Ledger, taskId: string): string {
    return canonicalJson(this.#snapshot(state, this.#task(state, taskId)) as unknown as Json);
  }
  /** Waits for this task's earlier re-evaluations; the returned function ends this turn (idempotent). */
  async #policyTurn(taskId: string): Promise<() => void> {
    const previous = this.#policyTurns.get(taskId) ?? Promise.resolve();
    let end!: () => void;
    const turn = new Promise<void>(resolve => { end = resolve; });
    const tail = previous.then(() => turn);
    this.#policyTurns.set(taskId, tail);
    await previous;
    let ended = false;
    return () => {
      if (ended) return;
      ended = true; end();
      if (this.#policyTurns.get(taskId) === tail) this.#policyTurns.delete(taskId);
    };
  }
  async #decision(state: Ledger, action: StoredAction): Promise<'allow' | 'require_approval'> {
    if (!this.#policy) return 'allow';
    const task = this.#task(state, action.taskId);
    return this.#policyAdmission.evaluate(this.#policy, clone(action.action), clone(this.#snapshot(state, task)), {
      familyId: task.family, taskIds: this.#provenance(state, action.taskId).map(source => source.options.id),
      remainingMs: task.options.budget.deadline - this.#now(state),
    });
  }

  registerTool(definition: ToolDefinition): string {
    // Reuse the core's definition validation and canonical fingerprint.
    const verifier = new AgentGuard({ clock: this.#clock });
    const fingerprint = verifier.registerTool(definition);
    const trusted = Object.freeze({ ...definition });
    const revision = this.#store.transaction(state => {
      const now = this.#now(state);
      const old = own(state.tools, definition.name);
      if (!old && Object.keys(state.tools).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      const revision = (old?.revision ?? 0) + 1;
      state.tools[definition.name] = { fingerprint, revision, approved: false };
      this.#audit(state, now, 'TOOL_REGISTERED');
      return revision;
    });
    this.#tools.set(definition.name, { definition: trusted, fingerprint, revision });
    return fingerprint;
  }
  approveTool(name: string, fingerprint: string): void {
    this.#store.transaction(state => {
      const tool = own(state.tools, id(name));
      if (!tool || tool.fingerprint !== fingerprint || !this.#tools.has(name)) throw new GuardError('TOOL_CHANGED');
      tool.approved = true;
      this.#audit(state, this.#now(state), 'TOOL_APPROVED');
    });
  }
  setPolicy(policy: Policy): void {
    if (typeof policy !== 'function') throw new GuardError('INVALID_INPUT');
    this.#store.transaction(state => { state.epoch++; this.#audit(state, this.#now(state), 'POLICY_CHANGED'); });
    this.#policy = policy;
    this.#policyAdmission.invalidate('POLICY_CHANGED');
  }
  createTask(options: TaskOptions, provenance: { sensitive?: boolean; sourceTaskId?: string } = {}): TaskCredential {
    return this.#newTask(options, null, provenance);
  }
  delegateTask(parentId: string, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskCredential {
    const parent = this.#task(this.#store.read(), parentId);
    return this.#newTask({ ...options, principalId: parent.options.principalId, tenantId: parent.options.tenantId }, parentId, {});
  }
  #newTask(input: TaskOptions, parentId: string | null, provenance: { sensitive?: boolean; sourceTaskId?: string }): TaskCredential {
    const options = clone(input);
    const token = randomBytes(32).toString('base64url');
    this.#store.transaction(state => {
      const now = this.#now(state);
      this.#prune(state, now);
      if (own(state.tasks, options.id) || archivedTaskIdUsed(state, options.id)) throw new GuardError('DUPLICATE_TASK');
      if (Object.keys(state.tasks).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      const validator = new AgentGuard({ clock: () => now });
      if (parentId !== null) {
        let handle;
        for (const parent of this.#lineage(state, parentId).reverse()) {
          if (parent.revoked) throw new GuardError('TASK_REVOKED');
          handle = handle ? validator.delegateTask(handle, parent.options) : validator.createTask(parent.options);
        }
        validator.delegateTask(handle!, options);
      } else validator.createTask(options);
      let family = parentId === null ? options.id : this.#task(state, parentId).family;
      if (provenance.sourceTaskId !== undefined) {
        const source = this.#task(state, provenance.sourceTaskId);
        if (this.#provenance(state, provenance.sourceTaskId).some(task => task.revoked)) throw new GuardError('TASK_REVOKED');
        if (source.options.tenantId !== options.tenantId) throw new GuardError('TENANT_DENIED');
        family = source.family; // Handoffs share a monotonic family, including later sensitive reads.
      }
      const members = Object.values(state.tasks).filter(task => task.family === family);
      if (members.length >= this.#maxTasksPerFamily) throw new ExecutorError('FAMILY_TASK_LIMIT');
      const taskBytes = Buffer.byteLength(JSON.stringify(options)) + members.reduce((sum, task) => sum + Buffer.byteLength(JSON.stringify(task.options)), 0);
      if (taskBytes > this.#maxTaskBytesPerFamily) throw new ExecutorError('FAMILY_TASK_BYTES_LIMIT');
      if (!own(state.families, family)) state.families[family] = { sensitive: false };
      if (provenance.sensitive === true) state.families[family]!.sensitive = true;
      state.tasks[options.id] = { options, parent: parentId, family, tokenHash: hash(token), revoked: false,
        calls: 0, concurrent: 0, spent: 0, reserved: 0,
        ...(provenance.sourceTaskId === undefined ? {} : { sourceTaskId: provenance.sourceTaskId }) };
      this.#audit(state, now, 'TASK_CREATED', options.id);
    });
    return Object.freeze({ taskId: options.id, token });
  }
  authenticate(token: string): string {
    if (typeof token !== 'string' || token.length > 256) throw new ExecutorError('UNAUTHENTICATED');
    const candidate = Buffer.from(hash(token), 'hex');
    const state = this.#store.read();
    const task = Object.values(state.tasks).find(task => timingSafeEqual(candidate, Buffer.from(task.tokenHash, 'hex')));
    if (!task) throw new ExecutorError('UNAUTHENTICATED');
    if (this.#provenance(state, task.options.id).some(task => task.revoked)) throw new ExecutorError('UNAUTHENTICATED');
    const now = this.#now(state);
    for (const ancestor of this.#lineage(state, task.options.id)) {
      if (ancestor.revoked || now >= ancestor.options.budget.deadline) throw new ExecutorError('UNAUTHENTICATED');
    }
    return task.options.id;
  }
  revokeTask(taskId: string): void {
    this.#store.transaction(state => {
      const revoked = this.#task(state, taskId);
      revoked.revoked = true;
      const descendants = new Set(Object.keys(state.tasks).filter(candidate => this.#provenance(state, candidate).some(task => task.options.id === taskId)));
      const entries = new Set(Object.values(state.memory).filter(history => history.some(entry =>
        entry.tenantId === revoked.options.tenantId && entry.origin.startsWith('task:') && descendants.has(entry.origin.slice(5)),
      )).map(history => history.at(-1)!.id));
      this.#quarantine(state, revoked.options.tenantId, entries);
      this.#audit(state, this.#now(state), 'TASK_REVOKED', taskId);
    });
    this.#policyAdmission.revokeTask(taskId);
    for (const active of this.#active.values()) if (active.taskIds.includes(taskId)) active.controller.abort();
  }
  markSensitive(taskId: string): void {
    this.#store.transaction(state => { state.families[this.#task(state, taskId).family]!.sensitive = true; this.#now(state); });
  }
  /** Host-only artifact verification: historical expiry does not remove labels; revocation invalidates the source. */
  assertProvenance(taskId: string): Readonly<TaskSnapshot> {
    const state = this.#store.read();
    if (this.#provenance(state, taskId).some(task => task.revoked)) throw new GuardError('TASK_REVOKED');
    return clone(this.#snapshot(state, this.#task(state, taskId)));
  }
  provenanceTaskIds(taskId: string): readonly string[] {
    const tasks = this.#provenance(this.#store.read(), taskId);
    if (tasks.some(task => task.revoked)) throw new GuardError('TASK_REVOKED');
    return Object.freeze(tasks.map(task => task.options.id));
  }
  cancel(taskId: string, actionId: string): void {
    const trace = this.#traceStart(taskId, actionId);
    let cancelled: boolean;
    try { cancelled = this.#store.transaction(state => {
      const action = own(state.actions, actionId);
      if (!action || action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
      const cancelled = action.status === 'PREPARED';
      if (action.status === 'PREPARED') { action.status = 'FAILED'; action.charged = 0; }
      this.#audit(state, this.#now(state), 'CANCELLATION_REQUESTED', taskId, actionId);
      return cancelled;
    }); } catch (error) { this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error)); throw error; }
    this.#active.get(actionId)?.controller.abort();
    this.#record(trace, 'cancel', cancelled ? 'CANCELLED' : 'CANCEL_REQUESTED');
  }
  snapshot(taskId: string): Readonly<TaskSnapshot> { const state = this.#store.read(); return clone(this.#snapshot(state, this.#task(state, taskId))); }

  /** Host-only, complete single-tenant observation. Never evaluates authority or invokes host callbacks. */
  inventorySnapshot(scope: InventoryScope): InventorySnapshot {
    if (!this.#inventorySource) throw new ExecutorError('INVENTORY_DISABLED');
    const state = this.#store.read();
    // Observation time is independent of the authorization clock and cannot advance its watermark.
    return projectInventory(state, this.#tools, this.#inventorySource, scope, Date.now(), this.#inventoryReferenceKey);
  }

  async prepare(taskId: string, request: { tool: string; args: Json }): Promise<PreparedAction> {
    const actionId = randomUUID();
    const trace = this.#traceStart(taskId, actionId);
    try {
      const prepared = await this.#prepare(taskId, request, actionId, trace);
      this.#record(trace, 'prepare', 'PREPARED', prepared.requiresApproval ? 'REVIEW_REQUIRED' : 'OK');
      return prepared;
    } catch (error) { this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error)); throw error; }
  }
  async #prepare(taskId: string, request: { tool: string; args: Json }, actionId: string, trace: TraceContext | undefined): Promise<PreparedAction> {
    const input = clone(request);
    if (Object.keys(input).some(key => key !== 'tool' && key !== 'args') || !Object.hasOwn(input, 'args')) throw new GuardError('INVALID_INPUT');
    const registration = this.#tools.get(id(input.tool));
    if (!registration) throw new GuardError('TOOL_UNKNOWN');
    const state = this.#store.read();
    const task = this.#task(state, taskId);
    if (this.#provenance(state, taskId).some(ancestor => ancestor.revoked)) throw new GuardError('TASK_REVOKED');
    if (!own(state.tools, input.tool)?.approved) throw new GuardError('TOOL_UNAPPROVED');
    if (this.#policy) this.#policyAdmission.assertCapacity(task.family);
    // Core preparation validates resolver output, mandatory gates and immutable argument binding.
    const verifier = new AgentGuard({ clock: () => this.#now(state), secretValues: this.#secrets });
    const fp = verifier.registerTool(registration.definition);
    verifier.approveTool(input.tool, fp);
    const handle = verifier.createTask(task.options);
    const verified = await verifier.prepare(handle, input);
    const action = clone({ ...verified.action, toolFingerprint: registration.fingerprint, policyVersion: state.epoch });
    const stored: StoredAction = { id: actionId, taskId, action, toolRevision: registration.revision,
      digest: `sha256:${digestJson(clone({ id: actionId, taskId, action, revision: registration.revision }))}`,
      requiresApproval: registration.definition.requiresApproval ?? false, status: 'PREPARED', maxCost: registration.definition.maxCost ?? 0 };
    // Retain the action's revisions, not a registration replaced before the caller resumes.
    if (trace) { trace.toolRevision = stored.toolRevision; trace.policyRevision = stored.action.policyVersion; }
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
        stored.requiresApproval = toolRequiresApproval || decision === 'require_approval';
        const expected = this.#policy ? this.#policyInputs(evaluated, taskId) : undefined;
        try {
          this.#store.transaction(current => {
            if (expected !== undefined && this.#policyInputs(current, taskId) !== expected) throw new StalePolicyDecision();
            this.#gates(current, stored, 'prepare');
            this.#prune(current, this.#now(current));
            this.#assertPendingCapacity(current, stored);
            if (Object.keys(current.actions).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
            current.actions[actionId] = stored;
            this.#audit(current, this.#now(current), 'ACTION_PREPARED', taskId, actionId);
          });
          break;
        } catch (error) {
          if (!(error instanceof StalePolicyDecision)) throw error;
          if (attempt >= this.#maxPolicyAttempts) throw new GuardError('POLICY_STATE_CHANGED');
        }
      }
    } finally { endTurn?.(); }
    return clone({ id: stored.id, digest: stored.digest, action: stored.action, requiresApproval: stored.requiresApproval });
  }
  approve(actionId: string, options: { approverId: string; expiresAt: number }): string {
    const trace = this.#traceStart(undefined, actionId);
    try {
      const approval = this.#approve(actionId, options);
      this.#record(trace, 'review', 'APPROVED');
      return approval;
    } catch (error) { this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error)); throw error; }
  }
  #approve(actionId: string, options: { approverId: string; expiresAt: number }): string {
    const approvalId = randomUUID();
    this.#store.transaction(state => {
      this.#prune(state, this.#now(state));
      const action = own(state.actions, id(actionId));
      if (!action || action.status !== 'PREPARED') throw new GuardError('INVALID_PREPARED');
      this.#gates(state, action, 'prepare');
      const now = this.#now(state);
      if (!Number.isSafeInteger(options.expiresAt) || options.expiresAt <= now ||
          this.#lineage(state, action.taskId).some(task => options.expiresAt > task.options.budget.deadline)) throw new GuardError('APPROVAL_INVALID');
      if (Object.keys(state.approvals).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      if (Object.values(state.approvals).filter(approval => approval.actionId === actionId).length >= 4) throw new ExecutorError('ACTION_APPROVAL_LIMIT');
      state.approvals[approvalId] = { actionId, digest: action.digest, expiresAt: options.expiresAt, approverId: id(options.approverId), used: false };
      this.#audit(state, now, 'ACTION_APPROVED', action.taskId, actionId);
    });
    return approvalId;
  }
  async execute(taskId: string, actionId: string, options: { approvalId?: string } = {}): Promise<Json> {
    let trace: TraceContext | undefined;
    try {
      const initial = this.#store.read();
      trace = this.#traceStart(taskId, actionId, initial);
      return await this.#execute(taskId, actionId, options, trace, initial);
    }
    catch (error) { this.#record(trace, trace?.admitted ? 'error' : 'deny', trace?.admitted ? 'ERROR' : 'DENIED', decisionTraceCode(error)); throw error; }
  }
  async #execute(taskId: string, actionId: string, options: { approvalId?: string }, trace: TraceContext | undefined, initial: Ledger): Promise<Json> {
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
    const admit = () => this.#store.transaction(state => {
      // Only this task's own policy inputs can make the decision stale; other tenants' writes cannot.
      if (expected !== undefined && this.#policyInputs(state, taskId) !== expected) throw new StalePolicyDecision();
      const action = own(state.actions, actionId)!;
      if (action.status !== 'PREPARED') throw new GuardError('ACTION_USED');
      this.#gates(state, action);
      const now = this.#now(state);
      let approvalDeadline: number | undefined;
      if (options.approvalId !== undefined || action.requiresApproval || decision === 'require_approval') {
        if (!options.approvalId) throw new GuardError('APPROVAL_REQUIRED');
        const approval = own(state.approvals, options.approvalId);
        if (!approval || approval.actionId !== actionId || approval.digest !== action.digest) throw new GuardError('APPROVAL_INVALID');
        if (approval.used) throw new GuardError('APPROVAL_USED');
        if (now >= approval.expiresAt) throw new GuardError('APPROVAL_EXPIRED');
        approval.used = true;
        approvalDeadline = approval.expiresAt;
      }
      const ancestors = this.#lineage(state, taskId);
      for (const task of ancestors) { task.calls++; task.concurrent++; task.reserved += action.maxCost; }
      const task = this.#task(state, taskId);
      if (action.action.sensitive) state.families[task.family]!.sensitive = true;
      action.status = 'ADMITTED';
      this.#audit(state, now, 'ACTION_ADMITTED', taskId, actionId);
      return { action: clone(action), identity: clone({ id: taskId, principalId: task.options.principalId, tenantId: task.options.tenantId }),
        taskIds: this.#provenance(state, taskId).map(parent => parent.options.id), deadline: task.options.budget.deadline, approvalDeadline };
    });
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
    } finally { endTurn?.(); }
    if (trace) trace.admitted = true;
    this.#record(trace, 'admit', 'ADMITTED');
    this.#active.set(actionId, { taskIds: admitted.taskIds, controller });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = (now: number): void => {
      const remaining = admitted.deadline - now;
      if (remaining <= 0) { controller.abort(); return; }
      timer = setTimeout(() => {
        try { arm(this.#now()); } catch { controller.abort(); }
      }, Math.min(remaining, 2_147_483_647));
    };
    try {
      this.#store.transaction(state => { state.actions[actionId]!.status = 'RUNNING'; this.#now(state); });
      // SQLite commits can take long enough to outlive the task or its one-use approval.
      // No handler has run, so a deadline denial can safely settle with zero cost.
      const dispatchTime = this.#now();
      if (dispatchTime >= admitted.deadline || (admitted.approvalDeadline !== undefined && dispatchTime >= admitted.approvalDeadline)) {
        const code = dispatchTime >= admitted.deadline ? 'TASK_EXPIRED' : 'APPROVAL_EXPIRED';
        this.#settle(actionId, 'FAILED', 0);
        this.#record(trace, 'settle', 'FAILED', code);
        throw new GuardError(code);
      }
      arm(dispatchTime);
      const tool = this.#tools.get(admitted.action.action.tool)!;
      const raw = await tool.definition.execute(admitted.action.action.args, Object.freeze({
        signal: controller.signal, action: admitted.action.action, task: admitted.identity,
      }));
      let result: { value: Json; actualCost?: number };
      try {
        result = clone(raw);
        if (!result || typeof result !== 'object' || !Object.hasOwn(result, 'value')) throw new Error();
      } catch { this.revokeTask(taskId); throw new GuardError('RESULT_INVALID'); }
      const cost = result.actualCost ?? admitted.action.maxCost;
      if (!Number.isSafeInteger(cost) || cost < 0 || cost > admitted.action.maxCost) {
        this.revokeTask(taskId); throw new GuardError('COST_REPORT_INVALID');
      }
      this.#settle(actionId, 'SUCCEEDED', cost);
      this.#record(trace, 'settle', 'SUCCEEDED');
      if (controller.signal.aborted || this.#now() >= admitted.deadline) throw new GuardError('EXECUTION_ABORTED');
      return result.value;
    } catch (error) {
      const unknown = this.#store.transaction(state => {
        const action = state.actions[actionId]!;
        if (action.status === 'ADMITTED' || action.status === 'RUNNING') {
          // A faulty clock must not roll back conservative recovery and strand a reservation
          // in RUNNING. Use the last trusted time for this audit entry only.
          let observed = state.lastClock;
          try { observed = this.#now(state); }
          catch (clockError) { if (!(clockError instanceof GuardError && clockError.code === 'CLOCK_INVALID')) throw clockError; }
          action.status = 'UNKNOWN'; this.#audit(state, observed, 'OUTCOME_UNKNOWN', taskId, actionId);
          return true;
        }
        return false;
      });
      if (unknown) this.#record(trace, 'unknown', 'UNKNOWN', 'OUTCOME_UNKNOWN');
      if (error instanceof GuardError || error instanceof ExecutorError) throw error;
      throw new GuardError(controller.signal.aborted ? 'EXECUTION_ABORTED' : 'TOOL_FAILED');
    } finally { if (timer) clearTimeout(timer); this.#active.delete(actionId); }
  }
  #settle(actionId: string, status: 'SUCCEEDED' | 'FAILED', actualCost: number, reconciliationReferenceHash?: string): void {
    this.#store.transaction(state => {
      const action = own(state.actions, actionId);
      if (!action || !['ADMITTED', 'RUNNING', 'UNKNOWN'].includes(action.status)) throw new ExecutorError('RECONCILIATION_INVALID');
      if (!Number.isSafeInteger(actualCost) || actualCost < 0 || actualCost > action.maxCost) throw new GuardError('COST_REPORT_INVALID');
      for (const task of this.#lineage(state, action.taskId)) {
        task.concurrent--; task.reserved -= action.maxCost; task.spent += actualCost;
      }
      action.status = status; action.charged = actualCost;
      const now = this.#now(state);
      if (reconciliationReferenceHash !== undefined) action.reconciliation = { referenceHash: reconciliationReferenceHash, time: now };
      this.#audit(state, now, 'ACTION_SETTLED', action.taskId, actionId);
    });
  }
  /** Operator-only reconciliation requires evidence that backend work has ended; never call on lease expiry alone. */
  reconcile(actionId: string, evidence: { outcome: 'SUCCEEDED' | 'FAILED'; actualCost: number; reference: string }): void {
    const trace = this.#traceStart(undefined, actionId);
    try {
      let input: typeof evidence;
      try { input = clone(evidence); } catch { throw new ExecutorError('RECONCILIATION_INVALID'); }
      this.#reconcile(actionId, input);
      this.#record(trace, 'reconcile', input.outcome, 'RECONCILED');
    } catch (error) { this.#record(trace, 'deny', 'DENIED', decisionTraceCode(error)); throw error; }
  }
  #reconcile(actionId: string, evidence: { outcome: 'SUCCEEDED' | 'FAILED'; actualCost: number; reference: string }): void {
    if (!evidence || (evidence.outcome !== 'SUCCEEDED' && evidence.outcome !== 'FAILED')) throw new ExecutorError('RECONCILIATION_INVALID');
    id(evidence.reference);
    const action = own(this.#store.read().actions, actionId);
    if (!action || action.status !== 'UNKNOWN' || this.#active.has(actionId)) throw new ExecutorError('RECONCILIATION_INVALID');
    this.#settle(actionId, evidence.outcome, evidence.actualCost, hash(evidence.reference));
  }
  execution(taskId: string, actionId: string): ExecutionReceipt {
    const state = this.#store.read();
    const action = own(state.actions, actionId);
    if (!action) {
      const task = own(state.tasks, taskId);
      const stub = task && prunedReceipt(state, task.family, actionId);
      if (!stub || stub.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
      return clone({ id: actionId, status: 'PRUNED', outcome: stub.outcome, ...(stub.charged === undefined ? {} : { charged: stub.charged }),
        ...(stub.reconciliation === undefined ? {} : { reconciliation: stub.reconciliation }) });
    }
    if (action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
    return clone({ id: action.id, status: action.status, ...(action.charged === undefined ? {} : { charged: action.charged }),
      ...(action.reconciliation === undefined ? {} : { reconciliation: action.reconciliation }) });
  }
  /**
   * Recent metadata events, oldest first. Bounded per tenant: this is not a complete history.
   * Export durably by polling and comparing `sequence`; a gap means events were evicted.
   */
  audit(scope: { tenantId?: string } = {}): readonly Readonly<Ledger['audit'][number]>[] {
    const tenantId = scope.tenantId === undefined ? undefined : id(scope.tenantId);
    const events = this.#store.read().audit;
    return clone(tenantId === undefined ? events : events.filter(event => event.tenantId === tenantId));
  }

  #memory(state: Ledger, tenantId: string, entryId: string): MemoryRecord {
    const entry = own(state.memory, JSON.stringify([tenantId, entryId]))?.at(-1);
    if (!entry || entry.quarantined) throw new ExecutorError('MEMORY_UNAVAILABLE');
    return entry;
  }
  #writeMemory(state: Ledger, entry: Omit<MemoryRecord, 'version' | 'quarantined'>): MemoryRecord {
    if (archivedMemoryIdUsed(state, entry.tenantId, entry.id)) throw new ExecutorError('MEMORY_UNAVAILABLE');
    if (Buffer.byteLength(canonicalJson(clone(entry.value) as Json)) > 65_536) throw new ExecutorError('MEMORY_LIMIT');
    const key = JSON.stringify([id(entry.tenantId), id(entry.id)]);
    const history = own(state.memory, key) ?? [];
    if (entry.familyId !== undefined) {
      const familyEntries = Object.values(state.memory).flat().filter(item => item.familyId === entry.familyId);
      const bytes = familyEntries.reduce((total, item) => total + Buffer.byteLength(JSON.stringify(item)), Buffer.byteLength(JSON.stringify(entry)));
      if (familyEntries.length >= 256 || bytes > 512 * 1024) throw new ExecutorError('FAMILY_MEMORY_LIMIT');
    }
    if (history.length >= 128 || (!history.length && Object.keys(state.memory).length >= this.#maxRecords)) throw new ExecutorError('MEMORY_LIMIT');
    const next: MemoryRecord = { ...entry, version: (history.at(-1)?.version ?? 0) + 1, quarantined: false };
    state.memory[key] = [...history, next];
    this.#audit(state, this.#now(state), 'MEMORY_WRITTEN');
    return next;
  }
  /** Operator import. Unknown sensitivity is restricted; trust is metadata, never execution authority. */
  importMemory(entry: { id: string; tenantId: string; origin: string; value: Json; sensitive?: boolean; trusted?: boolean }): void {
    const input = clone(entry);
    this.#store.transaction(state => {
      const previous = own(state.memory, JSON.stringify([input.tenantId, input.id]))?.at(-1);
      this.#writeMemory(state, { id: input.id, tenantId: input.tenantId, origin: id(input.origin), value: input.value,
        sensitive: input.sensitive !== false || previous?.sensitive === true, trusted: input.trusted === true, parentIds: previous?.parentIds ?? [] });
    });
  }
  /** Registers two ordinary scoped tools. The caller must approve their fingerprints separately. */
  registerMemoryTools(prefix = 'memory'): Readonly<{ read: string; write: string }> {
    id(prefix);
    const parse = (value: Json, write: boolean): Json => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new GuardError('ARGUMENT_INVALID');
      const input = value as Record<string, Json>;
      if (Object.keys(input).some(key => !(write ? ['id', 'value', 'ifVersion'] : ['id']).includes(key))) throw new GuardError('ARGUMENT_INVALID');
      id(input.id);
      if (write && (!Object.hasOwn(input, 'value') || !Number.isSafeInteger(input.ifVersion) || Number(input.ifVersion) < 0)) throw new GuardError('ARGUMENT_INVALID');
      return value;
    };
    const read = this.registerTool({ name: `${prefix}.read`, description: 'Read versioned, labeled memory as untrusted content.',
      parse: value => parse(value, false),
      resolve: (args, task) => {
        const entry = this.#memory(this.#store.read(), task.tenantId, (args as { id: string }).id);
        return { resourceId: entry.id, tenantId: entry.tenantId, resourceVersion: String(entry.version), sensitive: entry.sensitive };
      },
      execute: (args, context) => this.#store.transaction(state => {
        const entry = this.#memory(state, context.task.tenantId, (args as { id: string }).id);
        if (String(entry.version) !== context.action.resourceVersion) throw new ExecutorError('MEMORY_VERSION_CHANGED');
        const family = state.families[this.#task(state, context.task.id).family]!;
        family.sensitive ||= entry.sensitive;
        family.memorySources = [...new Set([...(family.memorySources ?? []), entry.id])];
        if (family.memorySources.length > 1000) throw new ExecutorError('MEMORY_LIMIT');
        return { value: clone(entry) as unknown as Json };
      }),
    });
    const write = this.registerTool({ name: `${prefix}.write`, description: 'Write untrusted memory with an exact expected version and inherited labels.',
      parse: value => parse(value, true),
      resolve: (args, task) => {
        const input = args as { id: string; ifVersion: number };
        const state = this.#store.read();
        if (archivedMemoryIdUsed(state, task.tenantId, input.id)) throw new ExecutorError('MEMORY_UNAVAILABLE');
        const previous = own(state.memory, JSON.stringify([task.tenantId, input.id]))?.at(-1);
        if (previous?.quarantined || (previous?.version ?? 0) !== input.ifVersion) throw new ExecutorError('MEMORY_VERSION_CHANGED');
        return { resourceId: input.id, tenantId: task.tenantId, resourceVersion: String(input.ifVersion) };
      },
      execute: (args, context) => this.#store.transaction(state => {
        const input = args as { id: string; value: Json; ifVersion: number };
        const previous = own(state.memory, JSON.stringify([context.task.tenantId, input.id]))?.at(-1);
        if (previous?.quarantined || String(previous?.version ?? 0) !== context.action.resourceVersion) throw new ExecutorError('MEMORY_VERSION_CHANGED');
        const familyId = this.#task(state, context.task.id).family;
        const family = state.families[familyId]!;
        for (const parent of family.memorySources ?? []) this.#memory(state, context.task.tenantId, parent);
        const entry = this.#writeMemory(state, { id: input.id, tenantId: context.task.tenantId, origin: `task:${context.task.id}`, value: input.value,
          sensitive: family.sensitive || previous?.sensitive === true, trusted: false, familyId,
          parentIds: [...new Set([...(previous?.parentIds ?? []), ...(family.memorySources ?? [])])] });
        return { value: { id: entry.id, version: entry.version, sensitive: entry.sensitive, trusted: false } };
      }),
    });
    return Object.freeze({ read, write });
  }
  /** Operator quarantine propagates to known descendants in the same tenant. */
  quarantineMemory(tenantId: string, entryId: string): void {
    this.#store.transaction(state => {
      this.#quarantine(state, id(tenantId), new Set([id(entryId)]));
      this.#audit(state, this.#now(state), 'MEMORY_QUARANTINED');
    });
  }
  #quarantine(state: Ledger, tenantId: string, denied: Set<string>): void {
    let changed = true;
    while (changed) {
      changed = false;
      for (const history of Object.values(state.memory)) {
        const latest = history.at(-1)!;
        if (latest.tenantId === tenantId && (denied.has(latest.id) || latest.parentIds.some(parent => denied.has(parent)))) {
          if (!denied.has(latest.id)) { denied.add(latest.id); changed = true; }
          for (const entry of history) entry.quarantined = true;
        }
      }
    }
  }
  /** Operator-only rollback creates a new version; it never removes history or lowers sensitivity. */
  rollbackMemory(tenantId: string, entryId: string, version: number): void {
    this.#store.transaction(state => {
      const history = own(state.memory, JSON.stringify([tenantId, entryId]));
      const previous = history?.find(entry => entry.version === version);
      if (!previous || previous.quarantined) throw new ExecutorError('MEMORY_UNAVAILABLE');
      this.#writeMemory(state, { ...previous, sensitive: history!.some(entry => entry.sensitive),
        parentIds: [...new Set(history!.flatMap(entry => entry.parentIds))] });
      this.#audit(state, this.#now(state), 'MEMORY_ROLLED_BACK');
    });
  }
  close(): void {
    if (this.#active.size) throw new ExecutorError('EXECUTIONS_ACTIVE');
    closeExecutorObservation(this);
    this.#store.close();
    this.#policyAdmission.invalidate('TASK_REVOKED');
    this.#inventoryReferenceKey?.fill(0);
    this.#traces?.close();
    this.#lifecycle.close();
  }
}
