import { randomUUID } from 'node:crypto';
import { isPromise } from 'node:util/types';
import { digestJson, immutableJson, type JsonObject } from './json.js';
import { GuardError, safeErrorDetail } from './types.js';
import { assertActionAuthority, type AuthorityPhase } from './authorization.js';
import { PolicyAdmission } from './policy-admission.js';
import type {
  Action, Budget, Capability, ExecutionResult, GuardDecision, GuardOptions, Json, Policy, PolicyDecision,
  PreparedAction, ResolvedAction, TaskHandle, TaskIdentity, TaskOptions, TaskSnapshot, TaskStatus, ToolDefinition, ToolResult,
} from './types.js';

export { GuardError, GuardErrorCode, isGuardError } from './types.js';
export { InvalidJsonError } from './json.js';
export { GuardErrorCatalog, type GuardErrorInfo } from './errors.js';

// Deprecated root aliases for the internal SPI, kept for one minor release.
export * from './deprecated.js';
export type {
  Action, Budget, Capability, ExecutionResult, GuardDecision, GuardLimits, GuardOptions, GuardErrorCodeValue, Json, Policy, PolicyDecision,
  PreparedAction, ResolvedAction, TaskHandle, TaskIdentity, TaskOptions, TaskSnapshot, TaskStatus, ToolDefinition, ToolResult,
} from './types.js';

/**
 * A wall-clock-anchored monotonic clock in milliseconds: it never steps backward when the
 * system clock is adjusted. Pass it as `clock` to avoid CLOCK_INVALID on a backward step.
 * The default clock remains `Date.now`, and all deadlines are clock milliseconds.
 */
export function monotonicClock(): number { return Math.floor(performance.timeOrigin + performance.now()); }
const FAILED_AFTER_DISPATCH = new Set(['TOOL_FAILED', 'EXECUTION_ABORTED', 'RESULT_INVALID', 'COST_REPORT_INVALID']);

const MAX_TIMER_DELAY = 2_147_483_647;

type ToolState = {
  name: string; fingerprint: string; revision: number; approved: boolean;
  requiresApproval: boolean; controlPlane: boolean; maxCost: number;
  resolve: ToolDefinition['resolve']; execute: ToolDefinition['execute'];
  parse: ToolDefinition['parse'];
};
type TaskState = {
  handle: TaskHandle; identity: Readonly<TaskIdentity>; grants: Map<string, Set<string>>;
  recipients: Set<string>; allowControlPlane: boolean; budget: Readonly<Budget>;
  parent: TaskState | undefined; family: { id: string; sensitive: boolean }; revoked: boolean;
  calls: number; concurrent: number; spent: number; reserved: number;
  active: Set<AbortController>;
};
type PreparedState = {
  handle: PreparedAction; task: TaskState; tool: ToolState; policyVersion: number;
  dispatched: boolean; approvals: Map<string, ApprovalState>;
};
type ApprovalState = {
  expiresAt: number; approverId: string;
};
type PolicyEvaluation = { decision: PolicyDecision; snapshot?: Readonly<TaskSnapshot> };

function fail(code: ConstructorParameters<typeof GuardError>[0], cause?: unknown): never {
  const detail = cause === undefined ? undefined : safeErrorDetail(cause);
  throw new GuardError(code, code, detail === undefined ? {} : { detail });
}

function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 && value.trim().length > 0 && !value.includes('\0');
}
function identifier(value: unknown): string {
  if (!nonempty(value)) fail('INVALID_INPUT');
  return value;
}
function nonnegative(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}
function costUnits(value: unknown): value is number {
  return nonnegative(value) && Number.isSafeInteger(value);
}
function optionalBoolean(value: unknown): boolean {
  if (value === undefined) return false;
  if (typeof value !== 'boolean') fail('INVALID_INPUT');
  return value;
}
function normalizeJson(value: unknown): Json {
  try {
    return immutableJson(value);
  } catch { return fail('INVALID_JSON'); }
}
function synchronousResult<T>(value: T): T {
  if (isPromise(value)) {
    // A misconfigured async parser/resolver must not crash the host or print a
    // raw rejection after prepare() has already returned its sanitized error.
    void Promise.prototype.then.call(value, undefined, () => {});
    fail('INVALID_INPUT');
  }
  return value;
}
function asObject(value: Json): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('INVALID_INPUT');
  return value as JsonObject;
}
function budgetFrom(input: unknown): Readonly<Budget> {
  const data = asObject(normalizeJson(input));
  const { maxCalls, maxConcurrent, maxCost, deadline } = data;
  if (!Number.isSafeInteger(maxCalls) || !nonnegative(maxCalls) ||
      !Number.isSafeInteger(maxConcurrent) || !nonnegative(maxConcurrent) ||
      !costUnits(maxCost) || !nonnegative(deadline)) fail('INVALID_INPUT');
  return Object.freeze({ maxCalls, maxConcurrent, maxCost, deadline });
}
function stringSet(input: unknown): Set<string> {
  if (!Array.isArray(input)) fail('INVALID_INPUT');
  return new Set(input.map(identifier));
}
function grantsFrom(input: readonly Capability[]): Map<string, Set<string>> {
  const data = normalizeJson(input);
  if (!Array.isArray(data)) fail('INVALID_INPUT');
  const grants = new Map<string, Set<string>>();
  for (const entry of data) {
    const object = asObject(entry);
    const name = identifier(object.tool);
    const resources = stringSet(object.resources);
    const existing = grants.get(name) ?? new Set<string>();
    for (const resource of resources) existing.add(resource);
    grants.set(name, existing);
  }
  return grants;
}
function permits(grants: Map<string, Set<string>>, tool: string, resource: string): boolean {
  const resources = grants.get(tool);
  return Boolean(resources && (resources.has(resource) || resources.has('*')));
}
function lineage(task: TaskState): TaskState[] {
  const result: TaskState[] = [];
  let current: TaskState | undefined = task;
  while (current) { result.push(current); current = current.parent; }
  return result;
}
/** Executes registered tools in memory. The host must provide isolation and backend authorization. */
export class AgentGuard {
  #tools = new Map<string, ToolState>();
  #tasks = new WeakMap<TaskHandle, TaskState>();
  #prepared = new WeakMap<PreparedAction, PreparedState>();
  #policyAdmission: PolicyAdmission;
  #maxApprovals: number;
  #onDecision: ((event: Readonly<GuardDecision>) => void) | undefined;
  #taskIds = new Set<string>();
  #revision = 0;
  #policyVersion = 1;
  #policy: Policy | undefined;
  #clock: () => number;
  #observedClock = 0;
  #secrets: readonly string[];
  #maxPolicyAttempts: number;
  /** Per-task queue for policy re-evaluations; first attempts stay parallel. */
  #policyTurns = new WeakMap<TaskState, Promise<void>>();

  constructor(options: GuardOptions = {}) {
    if (options === null || typeof options !== 'object') fail('INVALID_INPUT');
    if (options.policy !== undefined && typeof options.policy !== 'function') fail('INVALID_INPUT');
    if (options.clock !== undefined && typeof options.clock !== 'function') fail('INVALID_INPUT');
    const attempts = options.maxPolicyAttempts === undefined ? 5 : options.maxPolicyAttempts;
    if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 16) fail('INVALID_INPUT');
    this.#maxPolicyAttempts = attempts;
    if (options.onDecision !== undefined && typeof options.onDecision !== 'function') fail('INVALID_INPUT');
    this.#onDecision = options.onDecision;
    const limits = options.limits === undefined ? {} : options.limits;
    if (limits === null || typeof limits !== 'object') fail('INVALID_INPUT');
    const bounded = (value: unknown, fallback: number, min: number, max: number): number => {
      const selected = value === undefined ? fallback : value;
      if (typeof selected !== 'number' || !Number.isSafeInteger(selected) || selected < min || selected > max) fail('INVALID_INPUT');
      return selected;
    };
    this.#maxApprovals = bounded(limits.maxApprovalsPerAction, 4, 1, 64);
    this.#policyAdmission = new PolicyAdmission({
      maxPending: bounded(limits.maxPolicyEvaluations, 64, 1, 1024),
      maxPendingPerFamily: bounded(limits.maxPolicyEvaluationsPerFamily, 8, 1, 1024),
      maxWaitMs: bounded(limits.policyTimeoutMs, 30_000, 100, 300_000),
    });
    this.#policy = options.policy;
    this.#clock = options.clock ?? Date.now;
    this.#secrets = Object.freeze([...stringSet(options.secretValues ?? [])]);
    this.#now();
  }

  registerTool(definition: ToolDefinition): string {
    this.#now();
    if (!definition || typeof definition !== 'object') fail('INVALID_INPUT');
    const name = identifier(definition.name);
    if (typeof definition.description !== 'string' || typeof definition.resolve !== 'function' ||
        typeof definition.execute !== 'function') fail('INVALID_INPUT');
    if (definition.parse !== undefined && typeof definition.parse !== 'function') fail('INVALID_INPUT');
    const requiresApproval = optionalBoolean(definition.requiresApproval);
    const controlPlane = optionalBoolean(definition.controlPlane);
    const maxCost = definition.maxCost ?? 0;
    if (!costUnits(maxCost)) fail('INVALID_INPUT');
    const metadata = normalizeJson({
      name, description: definition.description, inputSchema: definition.inputSchema ?? null,
      metadata: definition.metadata ?? null, requiresApproval, controlPlane, maxCost,
      parsedArguments: definition.parse !== undefined,
    });
    const fingerprint = `sha256:${digestJson(metadata)}`;
    this.#tools.set(name, {
      name, fingerprint, revision: ++this.#revision, approved: false,
      requiresApproval, controlPlane, maxCost, resolve: definition.resolve, execute: definition.execute,
      parse: definition.parse,
    });
    return fingerprint;
  }

  approveTool(name: string, fingerprint: string): void {
    this.#now();
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    if (fingerprint !== tool.fingerprint) fail('TOOL_CHANGED');
    tool.approved = true;
  }

  /** Withdraws approval: prepared actions for the tool fail with TOOL_UNAPPROVED until it is approved again. */
  unapproveTool(name: string): void {
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    tool.approved = false;
  }

  /** Removes the tool. Prepared actions for it fail with TOOL_CHANGED; a later registration needs a new approval. */
  unregisterTool(name: string): void {
    if (!this.#tools.delete(name)) fail('TOOL_UNKNOWN');
  }

  createTask(options: TaskOptions): TaskHandle { return this.#newTask(options, undefined); }

  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle {
    const state = this.#task(parent);
    this.#live(state);
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    return this.#newTask({ ...options, principalId: state.identity.principalId, tenantId: state.identity.tenantId }, state);
  }

  revokeTask(task: TaskHandle): void { this.#revoke(this.#task(task)); }

  /**
   * Revokes the task and forgets it, freeing its ID and memory. Its handle becomes
   * INVALID_TASK, its prepared actions fail, and its descendants stay revoked. Retire
   * finished tasks in a long-running guard; a later task may reuse the ID.
   */
  retireTask(task: TaskHandle): void {
    const state = this.#task(task);
    this.#revoke(state);
    this.#tasks.delete(task);
    this.#taskIds.delete(state.identity.id);
  }

  setPolicy(policy: Policy): void {
    if (typeof policy !== 'function') fail('INVALID_INPUT');
    this.#policy = policy;
    this.#policyVersion++;
    this.#policyAdmission.invalidate('POLICY_CHANGED');
  }

  async prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction> {
    try {
      const prepared = await this.#prepare(task, request);
      this.#decision('prepare', 'allowed', this.#tasks.get(task), { tool: prepared.action.tool, actionId: prepared.id, resourceId: prepared.action.resourceId });
      return prepared;
    } catch (error) {
      const tool = request !== null && typeof request === 'object' && typeof request.tool === 'string' && this.#tools.has(request.tool) ? request.tool : undefined;
      this.#decision('prepare', 'denied', this.#tasks.get(task), { ...(tool === undefined ? {} : { tool }) }, error);
      throw error;
    }
  }

  async #prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction> {
    const state = this.#task(task);
    this.#live(state);
    if (this.#policy) this.#policyAdmission.assertCapacity(state.family.id);
    const input = asObject(normalizeJson(request));
    if (Object.keys(input).some(key => key !== 'tool' && key !== 'args') || !Object.hasOwn(input, 'args')) fail('INVALID_INPUT');
    const name = identifier(input.tool);
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    if (!tool.approved) fail('TOOL_UNAPPROVED');
    // Delegation only narrows authority. Reject a tool outside the leaf's scope
    // before running host callbacks, which may look up private resource metadata.
    if (!state.grants.get(name)?.size) fail('GRANT_DENIED');
    if (tool.controlPlane && !state.allowControlPlane) fail('CONTROL_PLANE_DENIED');
    const policyVersion = this.#policyVersion;
    let args: Json = input.args as Json;
    const parse = tool.parse;
    if (parse) {
      try { args = normalizeJson(synchronousResult(parse(args))); } catch (error) { return fail('ARGUMENT_INVALID', error); }
    }
    let resolved: ResolvedAction;
    const resolve = tool.resolve;
    try { resolved = this.#resolved(synchronousResult(resolve(args, state.identity))); }
    catch (error) { return fail('RESOLUTION_FAILED', error); }
    const action: Readonly<Action> = Object.freeze({
      ...resolved, tool: name, args, toolFingerprint: tool.fingerprint, policyVersion,
    });
    this.#gates(state, tool, action, policyVersion, 'prepare');
    let evaluation: PolicyEvaluation;
    let endTurn: (() => void) | undefined;
    try {
      // A decision made on a snapshot that changed during the await is re-evaluated, never reused.
      for (let attempt = 1; ; attempt++) {
        if (attempt > 1) endTurn ??= await this.#policyTurn(state);
        evaluation = await this.#evaluate(action, state);
        this.#gates(state, tool, action, policyVersion, 'prepare');
        if (!this.#policySnapshotChanged(state, evaluation)) break;
        if (attempt >= this.#maxPolicyAttempts) fail('POLICY_STATE_CHANGED');
      }
    } finally { endTurn?.(); }
    const id = randomUUID();
    const digest = `sha256:${digestJson(normalizeJson({
      preparedId: id, task: state.identity, action, toolRevision: tool.revision,
    }))}`;
    const handle: PreparedAction = Object.freeze({
      id, digest, action, requiresApproval: tool.requiresApproval || evaluation.decision === 'require_approval',
    });
    this.#prepared.set(handle, { handle, task: state, tool, policyVersion, dispatched: false, approvals: new Map() });
    return handle;
  }

  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string {
    const state = this.#prepared.get(prepared);
    const detail = state ? { tool: state.tool.name, actionId: state.handle.id, resourceId: state.handle.action.resourceId } : {};
    try {
      const id = this.#approve(prepared, options);
      this.#decision('approve', 'allowed', state?.task, { ...detail, approverId: options.approverId });
      return id;
    } catch (error) { this.#decision('approve', 'denied', state?.task, detail, error); throw error; }
  }

  #approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string {
    const state = this.#invocation(prepared);
    this.#fresh(state);
    const now = this.#gates(state.task, state.tool, state.handle.action, state.policyVersion, 'prepare');
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    const approverId = identifier(options.approverId);
    const expiresAt = options.expiresAt;
    if (!nonnegative(expiresAt) || expiresAt <= now ||
        lineage(state.task).some(task => expiresAt > task.budget.deadline)) fail('APPROVAL_INVALID');
    for (const [id, approval] of state.approvals) if (now >= approval.expiresAt) state.approvals.delete(id);
    if (state.approvals.size >= this.#maxApprovals) fail('ACTION_APPROVAL_LIMIT');
    const id = randomUUID();
    state.approvals.set(id, { expiresAt, approverId });
    return id;
  }

  async execute(prepared: PreparedAction, options: { approvalId?: string } = {}): Promise<Json> {
    return (await this.executeDetailed(prepared, options)).value;
  }

  /** Like execute(), but also returns the charged cost and the action ID for receipts. */
  async executeDetailed(prepared: PreparedAction, options: { approvalId?: string } = {}): Promise<ExecutionResult> {
    const state = this.#prepared.get(prepared);
    const detail = state ? { tool: state.tool.name, actionId: state.handle.id, resourceId: state.handle.action.resourceId } : {};
    try {
      const result = await this.#execute(prepared, options);
      this.#decision('execute', 'succeeded', state?.task, detail);
      return result;
    } catch (error) {
      const code = error instanceof GuardError ? error.code : undefined;
      this.#decision('execute', code !== undefined && FAILED_AFTER_DISPATCH.has(code) ? 'failed' : 'denied', state?.task, detail, error);
      throw error;
    }
  }

  async #execute(prepared: PreparedAction, options: { approvalId?: string }): Promise<ExecutionResult> {
    const state = this.#invocation(prepared);
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    const approvalId = options.approvalId;
    if (approvalId !== undefined && typeof approvalId !== 'string') fail('APPROVAL_INVALID');
    this.#fresh(state);
    this.#gates(state.task, state.tool, state.handle.action, state.policyVersion);
    let evaluation: PolicyEvaluation;
    let dispatchTime: number;
    let endTurn: (() => void) | undefined;
    try {
      // A decision made on a snapshot that changed during the await is re-evaluated, never reused.
      // Re-evaluations on one task take turns, so concurrent calls converge instead of invalidating
      // each other. The loop exits synchronously after the final checks: no await occurs between
      // those checks, reservation, approval consumption and handler invocation.
      for (let attempt = 1; ; attempt++) {
        if (attempt > 1) endTurn ??= await this.#policyTurn(state.task);
        evaluation = await this.#evaluate(state.handle.action, state.task);
        this.#fresh(state);
        dispatchTime = this.#gates(state.task, state.tool, state.handle.action, state.policyVersion);
        if (!this.#policySnapshotChanged(state.task, evaluation)) break;
        if (attempt >= this.#maxPolicyAttempts) fail('POLICY_STATE_CHANGED');
      }
      // Ending the turn only schedules the next waiter; it resumes after this synchronous dispatch.
    } finally { endTurn?.(); }
    this.#approval(state, approvalId, state.handle.requiresApproval || evaluation.decision === 'require_approval', dispatchTime);
    const ancestors = lineage(state.task);
    const controller = new AbortController();
    const cancelTimer = this.#deadlineTimer(state.task.budget.deadline - dispatchTime, controller);
    state.dispatched = true;
    state.approvals.clear();
    for (const task of ancestors) {
      task.calls++;
      task.concurrent++;
      task.reserved += state.tool.maxCost;
      task.active.add(controller);
    }
    if (state.handle.action.sensitive) state.task.family.sensitive = true;

    let charge = state.tool.maxCost;
    try {
      let result: ToolResult;
      try {
        const execute = state.tool.execute;
        result = await execute(state.handle.action.args, Object.freeze({
          signal: controller.signal, action: state.handle.action, task: state.task.identity,
        }));
      } catch (error) {
        return fail(controller.signal.aborted ? 'EXECUTION_ABORTED' : 'TOOL_FAILED', controller.signal.aborted ? undefined : error);
      }
      let value: Json;
      try {
        const data = asObject(normalizeJson(result));
        if (!Object.hasOwn(data, 'value')) fail('RESULT_INVALID');
        if (Object.hasOwn(data, 'actualCost')) {
          const actual = data.actualCost;
          if (!costUnits(actual) || actual > state.tool.maxCost) fail('COST_REPORT_INVALID');
          charge = actual;
        }
        value = data.value!;
      } catch (error) {
        charge = state.tool.maxCost;
        this.#revoke(state.task);
        return fail(error instanceof GuardError && error.code === 'COST_REPORT_INVALID' ? 'COST_REPORT_INVALID' : 'RESULT_INVALID');
      }
      // A synchronous handler or a busy microtask queue can settle before the deadline timer runs.
      if (this.#now() >= state.task.budget.deadline) controller.abort(new GuardError('TASK_EXPIRED'));
      if (controller.signal.aborted) fail('EXECUTION_ABORTED');
      return Object.freeze({ value, charged: charge, actionId: state.handle.id });
    } finally {
      cancelTimer();
      for (const task of ancestors) {
        task.concurrent--;
        task.reserved = Math.max(0, task.reserved - state.tool.maxCost);
        task.spent += charge;
        task.active.delete(controller);
      }
    }
  }

  /** Counters, budget and revocation state for the task. */
  snapshot(task: TaskHandle): Readonly<TaskStatus> {
    const state = this.#task(task);
    return Object.freeze({ ...this.#snapshot(state), budget: state.budget, revoked: lineage(state).some(ancestor => ancestor.revoked) });
  }

  #decision(operation: GuardDecision['operation'], outcome: GuardDecision['outcome'], task: TaskState | undefined,
    detail: { tool?: string; actionId?: string; resourceId?: string; approverId?: string }, error?: unknown): void {
    const hook = this.#onDecision;
    if (!hook || !task) return;
    const code = error instanceof GuardError ? error.code : undefined;
    const approverId = typeof detail.approverId === 'string' && detail.approverId.length <= 4096 ? detail.approverId : undefined;
    try {
      const event = Object.freeze({ operation, outcome, taskId: task.identity.id, tenantId: task.identity.tenantId, principalId: task.identity.principalId,
        ...(detail.tool === undefined ? {} : { tool: detail.tool }), ...(detail.actionId === undefined ? {} : { actionId: detail.actionId }),
        ...(detail.resourceId === undefined ? {} : { resourceId: detail.resourceId }), ...(approverId === undefined ? {} : { approverId }),
        ...(code === undefined ? {} : { code }) });
      const returned: unknown = hook(event);
      if (isPromise(returned)) void (returned as Promise<unknown>).catch(() => {});
    } catch { /* Observation never changes an authorization outcome. */ }
  }

  #now(): number {
    let now: unknown;
    try { now = this.#clock(); } catch { return fail('CLOCK_INVALID'); }
    if (!nonnegative(now) || now < this.#observedClock) fail('CLOCK_INVALID');
    this.#observedClock = now;
    return now;
  }

  #newTask(options: TaskOptions, parent: TaskState | undefined): TaskHandle {
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    const identity = Object.freeze({
      id: identifier(options.id), principalId: identifier(options.principalId), tenantId: identifier(options.tenantId),
    });
    if (this.#taskIds.has(identity.id)) fail('DUPLICATE_TASK');
    const budget = budgetFrom(options.budget);
    const grants = grantsFrom(options.grants);
    const recipients = stringSet(normalizeJson(options.allowedRecipients ?? []));
    const allowControlPlane = optionalBoolean(options.allowControlPlane);
    const now = this.#now();
    if (budget.deadline <= now) fail('TASK_EXPIRED');
    if (parent) {
      for (const ancestor of lineage(parent)) {
        for (const [tool, resources] of grants) {
          for (const resource of resources) {
            if (!permits(ancestor.grants, tool, resource)) fail('DELEGATION_DENIED');
          }
        }
        if ([...recipients].some(recipient => !ancestor.recipients.has(recipient)) ||
            (allowControlPlane && !ancestor.allowControlPlane) ||
            budget.maxCalls > ancestor.budget.maxCalls || budget.maxConcurrent > ancestor.budget.maxConcurrent ||
            budget.maxCost > ancestor.budget.maxCost || budget.deadline > ancestor.budget.deadline) fail('DELEGATION_DENIED');
      }
    }
    const handle = Object.freeze({ id: identity.id });
    const state: TaskState = {
      handle, identity, grants, recipients, allowControlPlane, budget, parent,
      family: parent?.family ?? { id: identity.id, sensitive: false }, revoked: false,
      calls: 0, concurrent: 0, spent: 0, reserved: 0, active: new Set(),
    };
    this.#tasks.set(handle, state);
    this.#taskIds.add(identity.id);
    return handle;
  }

  #task(handle: TaskHandle): TaskState {
    if (handle === null || typeof handle !== 'object') fail('INVALID_TASK');
    const state = this.#tasks.get(handle);
    if (!state) fail('INVALID_TASK');
    return state;
  }

  #invocation(handle: PreparedAction): PreparedState {
    if (handle === null || typeof handle !== 'object') fail('INVALID_PREPARED');
    const state = this.#prepared.get(handle);
    if (!state) fail('INVALID_PREPARED');
    return state;
  }

  #fresh(state: PreparedState): void { if (state.dispatched) fail('ACTION_USED'); }

  #live(task: TaskState): number {
    const now = this.#now();
    for (const ancestor of lineage(task)) {
      if (ancestor.revoked) fail('TASK_REVOKED');
      if (now >= ancestor.budget.deadline) fail('TASK_EXPIRED');
    }
    return now;
  }

  #resolved(value: ResolvedAction): ResolvedAction {
    const data = asObject(normalizeJson(value));
    if (Object.keys(data).some(key => !['resourceId', 'tenantId', 'external', 'recipient', 'sensitive', 'resourceVersion'].includes(key))) fail('INVALID_INPUT');
    const result: ResolvedAction = {
      resourceId: identifier(data.resourceId), tenantId: identifier(data.tenantId),
      external: optionalBoolean(data.external), sensitive: optionalBoolean(data.sensitive),
    };
    if (Object.hasOwn(data, 'recipient')) result.recipient = identifier(data.recipient);
    if (Object.hasOwn(data, 'resourceVersion')) result.resourceVersion = identifier(data.resourceVersion);
    return Object.freeze(result);
  }

  #gates(task: TaskState, tool: ToolState, action: Readonly<Action>, version: number, phase: AuthorityPhase = 'dispatch'): number {
    const now = this.#live(task);
    if (version !== this.#policyVersion) fail('POLICY_CHANGED');
    if (this.#tools.get(tool.name) !== tool) fail('TOOL_CHANGED');
    if (!tool.approved) fail('TOOL_UNAPPROVED');
    assertActionAuthority(action, lineage(task).map(ancestor => ({
      identity: ancestor.identity,
      grants: [...ancestor.grants].map(([tool, resources]) => ({ tool, resources: [...resources] })),
      allowedRecipients: [...ancestor.recipients], allowControlPlane: ancestor.allowControlPlane,
      budget: ancestor.budget, snapshot: this.#snapshot(ancestor), revoked: ancestor.revoked,
    })), { now, maxCost: tool.maxCost, controlPlane: tool.controlPlane, sensitive: task.family.sensitive, secretValues: this.#secrets, phase });
    return now;
  }

  async #evaluate(action: Readonly<Action>, task: TaskState): Promise<PolicyEvaluation> {
    const policy = this.#policy;
    if (!policy) return { decision: 'allow' };
    const snapshot = this.#snapshot(task);
    const ancestors = lineage(task);
    const decision = await this.#policyAdmission.evaluate(policy, action, snapshot, {
      familyId: task.family.id,
      taskIds: ancestors.map(ancestor => ancestor.identity.id), remainingMs: task.budget.deadline - this.#now(),
    });
    return { decision, snapshot };
  }

  /** Waits for this task's earlier re-evaluations; the returned function ends this turn (idempotent). */
  async #policyTurn(task: TaskState): Promise<() => void> {
    const previous = this.#policyTurns.get(task) ?? Promise.resolve();
    let end!: () => void;
    const turn = new Promise<void>(resolve => { end = resolve; });
    this.#policyTurns.set(task, previous.then(() => turn));
    await previous;
    return end;
  }

  #policySnapshotChanged(task: TaskState, evaluation: PolicyEvaluation): boolean {
    const snapshot = evaluation.snapshot;
    return !!snapshot && (snapshot.calls !== task.calls || snapshot.concurrent !== task.concurrent ||
      snapshot.spent !== task.spent || snapshot.reserved !== task.reserved ||
      snapshot.sensitive !== task.family.sensitive);
  }

  #approval(state: PreparedState, id: string | undefined, required: boolean, now: number): void {
    if (id === undefined) {
      if (required) fail('APPROVAL_REQUIRED');
      return;
    }
    // Lookup is scoped to the exact issued action. #gates checked its policy and tool revision.
    const approval = state.approvals.get(id);
    if (!approval) fail('APPROVAL_INVALID');
    if (now >= approval.expiresAt) { state.approvals.delete(id); fail('APPROVAL_EXPIRED'); }
  }

  #snapshot(task: TaskState): Readonly<TaskSnapshot> {
    return Object.freeze({
      ...task.identity, sensitive: task.family.sensitive, calls: task.calls,
      concurrent: task.concurrent, spent: task.spent, reserved: task.reserved,
    });
  }

  #revoke(task: TaskState): void {
    task.revoked = true;
    // Revocation must work even if an injected clock fails.
    this.#policyAdmission.revokeTask(task.identity.id);
    for (const controller of task.active) controller.abort(new GuardError('TASK_REVOKED'));
  }

  #deadlineTimer(remaining: number, controller: AbortController): () => void {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let canceled = false;
    const schedule = (delay: number): void => {
      const chunk = Math.max(0, Math.min(delay, MAX_TIMER_DELAY));
      timer = setTimeout(() => {
        if (canceled) return;
        if (delay > MAX_TIMER_DELAY) schedule(delay - chunk);
        else controller.abort(new GuardError('TASK_EXPIRED'));
      }, chunk);
    };
    schedule(remaining);
    return () => { canceled = true; if (timer) clearTimeout(timer); };
  }
}
