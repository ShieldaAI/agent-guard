import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  AgentGuard, GuardError, assertActionAuthority, canonicalJson, digestJson, immutableJson,
  type Action, type AuthorityState, type Json, type Policy, type PreparedAction, type TaskIdentity,
  type TaskOptions, type TaskSnapshot, type ToolDefinition,
} from '@shieldaai/agent-guard';
import { ExecutorError, LedgerStore, type Ledger, type MemoryRecord, type StoredAction, type StoredTask } from './store.js';
import { projectInventory, validateInventorySource, type InventoryOptions, type InventoryScope,
  type InventorySnapshot, type InventorySourceOptions } from './inventory.js';

function id(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 4096 || value.includes('\0')) throw new GuardError('INVALID_INPUT');
  return value;
}
function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function own<T>(record: Record<string, T>, key: string): T | undefined { return Object.hasOwn(record, key) ? record[key] : undefined; }
function clone<T>(value: T): T { return immutableJson(value) as T; }
function audit(state: Ledger, time: number, event: string, taskId?: string, actionId?: string): void {
  state.audit.push({ time, event, ...(taskId === undefined ? {} : { taskId }), ...(actionId === undefined ? {} : { actionId }) });
  if (state.audit.length > 1000) state.audit.splice(0, state.audit.length - 1000);
}
type Registered = { definition: ToolDefinition; fingerprint: string; revision: number };

export interface ExecutorOptions {
  database: string;
  /** Exactly 32 random bytes supplied through the protected host's key custody. Never an agent secret. */
  encryptionKey: Uint8Array;
  clock?: () => number;
  policy?: Policy;
  secretValues?: readonly string[];
  maxRecords?: number;
  /** Aggregate unresolved actions across a task family, including delegated children. */
  maxPendingActionsPerFamily?: number;
  maxPendingBytesPerFamily?: number;
  /** Lifetime task/argument storage caps prevent delegation from bypassing family quotas. */
  maxTasksPerFamily?: number;
  maxTaskBytesPerFamily?: number;
  /** Trusted host enrollment. Omit to disable inventory; never accept this configuration from a task. */
  inventory?: InventoryOptions;
}
export interface TaskCredential { taskId: string; token: string }

/** Trusted host object. Expose only the task HTTP handler to agents, never this administration object. */
export class DurableExecutor {
  readonly #store: LedgerStore;
  readonly #clock: () => number;
  readonly #secrets: readonly string[];
  readonly #maxRecords: number;
  readonly #maxPendingActionsPerFamily: number;
  readonly #maxPendingBytesPerFamily: number;
  readonly #maxTasksPerFamily: number;
  readonly #maxTaskBytesPerFamily: number;
  readonly #inventorySource: InventorySourceOptions | undefined;
  readonly #inventoryReferenceKey: Buffer | undefined;
  readonly #tools = new Map<string, Registered>();
  readonly #active = new Map<string, { taskIds: string[]; controller: AbortController }>();
  #policy: Policy | undefined;
  #observedClock = 0;

  constructor(options: ExecutorOptions) {
    this.#clock = options.clock ?? Date.now;
    this.#policy = options.policy;
    this.#maxRecords = options.maxRecords ?? 10_000;
    if (!Number.isSafeInteger(this.#maxRecords) || this.#maxRecords < 1) throw new GuardError('INVALID_INPUT');
    const familyShare = Math.max(1, Math.floor(this.#maxRecords / 4));
    const bounded = (value: number | undefined, fallback: number, maximum: number): number => {
      const selected = value ?? fallback;
      if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) throw new GuardError('INVALID_INPUT');
      return selected;
    };
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
    try { this.#store = new LedgerStore(options.database, options.encryptionKey); }
    catch (error) { this.#inventoryReferenceKey?.fill(0); throw error; }
    try {
      this.#store.transaction(state => {
        const now = this.#now(state);
        state.epoch++; // Process/code changes invalidate every outstanding preparation.
        for (const tool of Object.values(state.tools)) tool.approved = false;
        for (const action of Object.values(state.actions)) {
          if (action.status === 'RUNNING' || action.status === 'ADMITTED') action.status = 'UNKNOWN';
        }
        audit(state, now, 'EXECUTOR_STARTED');
      });
    } catch (error) { this.#store.close(); this.#inventoryReferenceKey?.fill(0); throw error; }
  }

  #now(state: Ledger): number {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < state.lastClock || now < this.#observedClock || now < 0) throw new GuardError('CLOCK_INVALID');
    this.#observedClock = now;
    state.lastClock = now;
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
  /** Pruning never changes cumulative counters or releases unresolved reservations. */
  #prune(state: Ledger, now: number): void {
    const terminal: StoredAction[] = [];
    let terminalBytes = 0;
    for (const [actionId, action] of Object.entries(state.actions)) {
      if (action.status === 'PREPARED') {
        const tool = own(state.tools, action.action.tool);
        if (action.action.policyVersion !== state.epoch || !tool || tool.revision !== action.toolRevision ||
            this.#provenance(state, action.taskId).some(task => task.revoked) ||
            this.#lineage(state, action.taskId).some(task => now >= task.options.budget.deadline)) delete state.actions[actionId];
      } else if (action.status === 'SUCCEEDED' || action.status === 'FAILED') {
        terminal.push(action); terminalBytes += Buffer.byteLength(JSON.stringify(action));
      }
    }
    const retained = Math.min(256, Math.floor(this.#maxRecords / 2));
    while (terminal.length > retained || terminalBytes > this.#store.maxBytes / 8 ||
        (Object.keys(state.actions).length >= this.#maxRecords && terminal.length > 0)) {
      const oldest = terminal.shift(); if (!oldest) break;
      terminalBytes -= Buffer.byteLength(JSON.stringify(oldest)); delete state.actions[oldest.id];
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
  #gates(state: Ledger, action: StoredAction): void {
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
      sensitive: state.families[task.family]!.sensitive, secretValues: this.#secrets,
    });
  }
  async #decision(state: Ledger, action: StoredAction): Promise<'allow' | 'require_approval'> {
    if (!this.#policy) return 'allow';
    let decision: unknown;
    try { decision = await this.#policy(clone(action.action), clone(this.#snapshot(state, this.#task(state, action.taskId)))); }
    catch { throw new GuardError('POLICY_ERROR'); }
    if (decision === 'deny') throw new GuardError('POLICY_DENIED');
    if (decision !== 'allow' && decision !== 'require_approval') throw new GuardError('POLICY_ERROR');
    return decision;
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
      audit(state, now, 'TOOL_REGISTERED');
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
      audit(state, this.#now(state), 'TOOL_APPROVED');
    });
  }
  setPolicy(policy: Policy): void {
    if (typeof policy !== 'function') throw new GuardError('INVALID_INPUT');
    this.#store.transaction(state => { state.epoch++; audit(state, this.#now(state), 'POLICY_CHANGED'); });
    this.#policy = policy;
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
      if (own(state.tasks, options.id)) throw new GuardError('DUPLICATE_TASK');
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
      audit(state, now, 'TASK_CREATED', options.id);
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
      audit(state, this.#now(state), 'TASK_REVOKED', taskId);
    });
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
    this.#store.transaction(state => {
      const action = own(state.actions, actionId);
      if (!action || action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
      if (action.status === 'PREPARED') { action.status = 'FAILED'; action.charged = 0; }
      audit(state, this.#now(state), 'CANCELLATION_REQUESTED', taskId, actionId);
    });
    this.#active.get(actionId)?.controller.abort();
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
    const input = clone(request);
    if (Object.keys(input).some(key => key !== 'tool' && key !== 'args') || !Object.hasOwn(input, 'args')) throw new GuardError('INVALID_INPUT');
    const registration = this.#tools.get(id(input.tool));
    if (!registration) throw new GuardError('TOOL_UNKNOWN');
    const state = this.#store.read();
    const task = this.#task(state, taskId);
    let args = input.args;
    if (registration.definition.parse) {
      try { args = clone(registration.definition.parse(args)); } catch { throw new GuardError('ARGUMENT_INVALID'); }
    }
    // Core preparation validates resolver output, mandatory gates and immutable argument binding.
    const verifier = new AgentGuard({ clock: () => this.#now(state), secretValues: this.#secrets });
    const { parse: _parse, ...validatedDefinition } = registration.definition;
    const fp = verifier.registerTool(validatedDefinition);
    verifier.approveTool(input.tool, fp);
    const handle = verifier.createTask(task.options);
    const verified = await verifier.prepare(handle, { tool: input.tool, args });
    const action = clone({ ...verified.action, toolFingerprint: registration.fingerprint, policyVersion: state.epoch });
    const actionId = randomUUID();
    const stored: StoredAction = { id: actionId, taskId, action, toolRevision: registration.revision,
      digest: `sha256:${digestJson(clone({ id: actionId, taskId, action, revision: registration.revision }))}`,
      requiresApproval: registration.definition.requiresApproval ?? false, status: 'PREPARED', maxCost: registration.definition.maxCost ?? 0 };
    this.#gates(state, stored);
    const decision = await this.#decision(state, stored);
    stored.requiresApproval ||= decision === 'require_approval';
    this.#store.transaction(current => {
      if (current.revision !== state.revision) throw new GuardError('POLICY_STATE_CHANGED');
      this.#gates(current, stored);
      this.#prune(current, this.#now(current));
      this.#assertPendingCapacity(current, stored);
      if (Object.keys(current.actions).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      current.actions[actionId] = stored;
      audit(current, this.#now(current), 'ACTION_PREPARED', taskId, actionId);
    });
    return clone({ id: stored.id, digest: stored.digest, action: stored.action, requiresApproval: stored.requiresApproval });
  }
  approve(actionId: string, options: { approverId: string; expiresAt: number }): string {
    const approvalId = randomUUID();
    this.#store.transaction(state => {
      this.#prune(state, this.#now(state));
      const action = own(state.actions, id(actionId));
      if (!action || action.status !== 'PREPARED') throw new GuardError('INVALID_PREPARED');
      this.#gates(state, action);
      const now = this.#now(state);
      if (!Number.isSafeInteger(options.expiresAt) || options.expiresAt <= now ||
          this.#lineage(state, action.taskId).some(task => options.expiresAt > task.options.budget.deadline)) throw new GuardError('APPROVAL_INVALID');
      if (Object.keys(state.approvals).length >= this.#maxRecords) throw new ExecutorError('CAPACITY_EXCEEDED');
      if (Object.values(state.approvals).filter(approval => approval.actionId === actionId).length >= 4) throw new ExecutorError('ACTION_APPROVAL_LIMIT');
      state.approvals[approvalId] = { actionId, digest: action.digest, expiresAt: options.expiresAt, approverId: id(options.approverId), used: false };
      audit(state, now, 'ACTION_APPROVED', action.taskId, actionId);
    });
    return approvalId;
  }
  async execute(taskId: string, actionId: string, options: { approvalId?: string } = {}): Promise<Json> {
    const initial = this.#store.read();
    const record = own(initial.actions, id(actionId));
    if (!record || record.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
    if (record.status !== 'PREPARED') throw new GuardError('ACTION_USED');
    this.#gates(initial, record);
    const decision = await this.#decision(initial, record);
    const controller = new AbortController();
    const admitted = this.#store.transaction(state => {
      if (state.revision !== initial.revision) throw new GuardError('POLICY_STATE_CHANGED');
      const action = own(state.actions, actionId)!;
      if (action.status !== 'PREPARED') throw new GuardError('ACTION_USED');
      this.#gates(state, action);
      const now = this.#now(state);
      if (options.approvalId !== undefined || action.requiresApproval || decision === 'require_approval') {
        if (!options.approvalId) throw new GuardError('APPROVAL_REQUIRED');
        const approval = own(state.approvals, options.approvalId);
        if (!approval || approval.actionId !== actionId || approval.digest !== action.digest) throw new GuardError('APPROVAL_INVALID');
        if (approval.used) throw new GuardError('APPROVAL_USED');
        if (now >= approval.expiresAt) throw new GuardError('APPROVAL_EXPIRED');
        approval.used = true;
      }
      const ancestors = this.#lineage(state, taskId);
      for (const task of ancestors) { task.calls++; task.concurrent++; task.reserved += action.maxCost; }
      const task = this.#task(state, taskId);
      if (action.action.sensitive) state.families[task.family]!.sensitive = true;
      action.status = 'ADMITTED';
      audit(state, now, 'ACTION_ADMITTED', taskId, actionId);
      return { action: clone(action), identity: clone({ id: taskId, principalId: task.options.principalId, tenantId: task.options.tenantId }),
        taskIds: this.#provenance(state, taskId).map(parent => parent.options.id), deadline: task.options.budget.deadline };
    });
    this.#active.set(actionId, { taskIds: admitted.taskIds, controller });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = (): void => {
      const remaining = admitted.deadline - this.#clock();
      if (remaining <= 0) { controller.abort(); return; }
      timer = setTimeout(arm, Math.min(remaining, 2_147_483_647));
    };
    arm();
    try {
      this.#store.transaction(state => { state.actions[actionId]!.status = 'RUNNING'; this.#now(state); });
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
      if (controller.signal.aborted || this.#clock() >= admitted.deadline) throw new GuardError('EXECUTION_ABORTED');
      return result.value;
    } catch (error) {
      this.#store.transaction(state => {
        const action = state.actions[actionId]!;
        if (action.status === 'ADMITTED' || action.status === 'RUNNING') {
          action.status = 'UNKNOWN'; audit(state, this.#now(state), 'OUTCOME_UNKNOWN', taskId, actionId);
        }
      });
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
      audit(state, now, 'ACTION_SETTLED', action.taskId, actionId);
    });
  }
  /** Operator-only reconciliation requires evidence that backend work has ended; never call on lease expiry alone. */
  reconcile(actionId: string, evidence: { outcome: 'SUCCEEDED' | 'FAILED'; actualCost: number; reference: string }): void {
    if (!evidence || (evidence.outcome !== 'SUCCEEDED' && evidence.outcome !== 'FAILED')) throw new ExecutorError('RECONCILIATION_INVALID');
    id(evidence.reference);
    const action = own(this.#store.read().actions, actionId);
    if (!action || action.status !== 'UNKNOWN' || this.#active.has(actionId)) throw new ExecutorError('RECONCILIATION_INVALID');
    this.#settle(actionId, evidence.outcome, evidence.actualCost, hash(evidence.reference));
  }
  execution(taskId: string, actionId: string): Readonly<{ id: string; status: string; charged?: number; reconciliation?: { referenceHash: string; time: number } }> {
    const action = own(this.#store.read().actions, actionId);
    if (!action || action.taskId !== taskId) throw new GuardError('INVALID_PREPARED');
    return clone({ id: action.id, status: action.status, ...(action.charged === undefined ? {} : { charged: action.charged }),
      ...(action.reconciliation === undefined ? {} : { reconciliation: action.reconciliation }) });
  }
  audit(): readonly Readonly<Ledger['audit'][number]>[] { return clone(this.#store.read().audit); }

  #memory(state: Ledger, tenantId: string, entryId: string): MemoryRecord {
    const entry = own(state.memory, JSON.stringify([tenantId, entryId]))?.at(-1);
    if (!entry || entry.quarantined) throw new ExecutorError('MEMORY_UNAVAILABLE');
    return entry;
  }
  #writeMemory(state: Ledger, entry: Omit<MemoryRecord, 'version' | 'quarantined'>): MemoryRecord {
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
    audit(state, this.#now(state), 'MEMORY_WRITTEN');
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
      audit(state, this.#now(state), 'MEMORY_QUARANTINED');
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
      audit(state, this.#now(state), 'MEMORY_ROLLED_BACK');
    });
  }
  close(): void {
    if (this.#active.size) throw new ExecutorError('EXECUTIONS_ACTIVE');
    this.#store.close();
    this.#inventoryReferenceKey?.fill(0);
  }
}
