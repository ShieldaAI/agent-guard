import { randomUUID } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { canonicalJson, digestJson, immutableJson, type JsonObject } from './json.js';
import { GuardError } from './types.js';
import type {
  Action, Budget, Capability, GuardOptions, Json, Policy, PolicyDecision,
  PreparedAction, ResolvedAction, TaskHandle, TaskIdentity, TaskOptions, TaskSnapshot, ToolDefinition, ToolResult,
} from './types.js';

export { GuardError, GuardErrorCode } from './types.js';
export type {
  Action, Budget, Capability, GuardOptions, GuardErrorCodeValue, Json, Policy, PolicyDecision,
  PreparedAction, ResolvedAction, TaskHandle, TaskIdentity, TaskOptions, TaskSnapshot, ToolDefinition, ToolResult,
} from './types.js';

const MAX_JSON_BYTES = 1_048_576;
const MAX_TIMER_DELAY = 2_147_483_647;

type ToolState = {
  name: string; fingerprint: string; revision: number; approved: boolean;
  requiresApproval: boolean; controlPlane: boolean; maxCost: number;
  resolve: ToolDefinition['resolve']; execute: ToolDefinition['execute'];
};
type TaskState = {
  handle: TaskHandle; identity: Readonly<TaskIdentity>; grants: Map<string, Set<string>>;
  recipients: Set<string>; allowControlPlane: boolean; budget: Readonly<Budget>;
  parent: TaskState | undefined; family: { sensitive: boolean }; revoked: boolean;
  calls: number; concurrent: number; spent: number; reserved: number;
  active: Set<AbortController>;
};
type PreparedState = {
  handle: PreparedAction; task: TaskState; tool: ToolState; policyVersion: number;
  dispatched: boolean;
};
type ApprovalState = {
  prepared: WeakRef<PreparedState>; digest: string; toolRevision: number; policyVersion: number;
  expiresAt: number; used: boolean; approverId: string;
};

function fail(code: ConstructorParameters<typeof GuardError>[0]): never { throw new GuardError(code); }

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
    const copied = immutableJson(value);
    if (Buffer.byteLength(canonicalJson(copied), 'utf8') > MAX_JSON_BYTES) fail('INVALID_JSON');
    return copied;
  } catch { return fail('INVALID_JSON'); }
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
function containsSecret(value: Json, secrets: readonly string[]): boolean {
  if (typeof value === 'string') return secrets.some(secret => value.includes(secret));
  if (value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(item => containsSecret(item, secrets));
  return Object.entries(value).some(([key, item]) =>
    secrets.some(secret => key.includes(secret)) || containsSecret(item, secrets));
}

/** In-memory trusted-host executor. It does not sandbox code or replace backend authorization. */
export class AgentGuard {
  #tools = new Map<string, ToolState>();
  #tasks = new WeakMap<TaskHandle, TaskState>();
  #prepared = new WeakMap<PreparedAction, PreparedState>();
  #approvals = new Map<string, ApprovalState>();
  #taskIds = new Set<string>();
  #revision = 0;
  #policyVersion = 1;
  #policy: Policy | undefined;
  #clock: () => number;
  #secrets: readonly string[];

  constructor(options: GuardOptions = {}) {
    if (options === null || typeof options !== 'object') fail('INVALID_INPUT');
    if (options.policy !== undefined && typeof options.policy !== 'function') fail('INVALID_INPUT');
    if (options.clock !== undefined && typeof options.clock !== 'function') fail('INVALID_INPUT');
    this.#policy = options.policy;
    this.#clock = options.clock ?? Date.now;
    this.#secrets = Object.freeze([...stringSet(options.secretValues ?? [])]);
    this.#now();
  }

  registerTool(definition: ToolDefinition): string {
    const now = this.#now();
    if (!definition || typeof definition !== 'object') fail('INVALID_INPUT');
    const name = identifier(definition.name);
    if (typeof definition.description !== 'string' || typeof definition.resolve !== 'function' ||
        typeof definition.execute !== 'function') fail('INVALID_INPUT');
    const requiresApproval = optionalBoolean(definition.requiresApproval);
    const controlPlane = optionalBoolean(definition.controlPlane);
    const maxCost = definition.maxCost ?? 0;
    if (!costUnits(maxCost)) fail('INVALID_INPUT');
    const metadata = normalizeJson({
      name, description: definition.description, inputSchema: definition.inputSchema ?? null,
      metadata: definition.metadata ?? null, requiresApproval, controlPlane, maxCost,
    });
    const fingerprint = `sha256:${digestJson(metadata)}`;
    this.#tools.set(name, {
      name, fingerprint, revision: ++this.#revision, approved: false,
      requiresApproval, controlPlane, maxCost, resolve: definition.resolve, execute: definition.execute,
    });
    this.#pruneApprovals(now);
    return fingerprint;
  }

  approveTool(name: string, fingerprint: string): void {
    this.#pruneApprovals(this.#now());
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    if (fingerprint !== tool.fingerprint) fail('TOOL_CHANGED');
    tool.approved = true;
  }

  createTask(options: TaskOptions): TaskHandle { return this.#newTask(options, undefined); }

  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle {
    const state = this.#task(parent);
    this.#live(state);
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    return this.#newTask({ ...options, principalId: state.identity.principalId, tenantId: state.identity.tenantId }, state);
  }

  revokeTask(task: TaskHandle): void { this.#revoke(this.#task(task)); }

  setPolicy(policy: Policy): void {
    if (typeof policy !== 'function') fail('INVALID_INPUT');
    this.#policy = policy;
    this.#policyVersion++;
    this.#pruneApprovals(this.#now());
  }

  async prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction> {
    const state = this.#task(task);
    this.#live(state);
    const input = asObject(normalizeJson(request));
    if (Object.keys(input).some(key => key !== 'tool' && key !== 'args') || !Object.hasOwn(input, 'args')) fail('INVALID_INPUT');
    const name = identifier(input.tool);
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    if (!tool.approved) fail('TOOL_UNAPPROVED');
    const policyVersion = this.#policyVersion;
    const args = input.args!;
    let resolved: ResolvedAction;
    const resolve = tool.resolve;
    try { resolved = this.#resolved(resolve(args, state.identity)); }
    catch { return fail('RESOLUTION_FAILED'); }
    const action: Readonly<Action> = Object.freeze({
      ...resolved, tool: name, args, toolFingerprint: tool.fingerprint, policyVersion,
    });
    this.#gates(state, tool, action, policyVersion);
    const decision = await this.#evaluate(action, state);
    this.#gates(state, tool, action, policyVersion);
    const id = randomUUID();
    const digest = `sha256:${digestJson(normalizeJson({
      preparedId: id, task: state.identity, action, toolRevision: tool.revision,
    }))}`;
    const handle: PreparedAction = Object.freeze({
      id, digest, action, requiresApproval: tool.requiresApproval || decision === 'require_approval',
    });
    this.#prepared.set(handle, { handle, task: state, tool, policyVersion, dispatched: false });
    return handle;
  }

  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string {
    const state = this.#invocation(prepared);
    this.#fresh(state);
    const now = this.#gates(state.task, state.tool, state.handle.action, state.policyVersion);
    this.#pruneApprovals(now);
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    const approverId = identifier(options.approverId);
    const expiresAt = options.expiresAt;
    if (!nonnegative(expiresAt) || expiresAt <= now ||
        lineage(state.task).some(task => expiresAt > task.budget.deadline)) fail('APPROVAL_INVALID');
    const id = randomUUID();
    this.#approvals.set(id, {
      prepared: new WeakRef(state), digest: state.handle.digest, toolRevision: state.tool.revision,
      policyVersion: state.policyVersion, expiresAt, used: false, approverId,
    });
    return id;
  }

  async execute(prepared: PreparedAction, options: { approvalId?: string } = {}): Promise<Json> {
    const state = this.#invocation(prepared);
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    const approvalId = options.approvalId;
    if (approvalId !== undefined && typeof approvalId !== 'string') fail('APPROVAL_INVALID');
    this.#fresh(state);
    this.#gates(state.task, state.tool, state.handle.action, state.policyVersion);
    const decision = await this.#evaluate(state.handle.action, state.task);
    // No await occurs between these final checks, reservation, approval consumption and handler invocation.
    this.#fresh(state);
    const dispatchTime = this.#gates(state.task, state.tool, state.handle.action, state.policyVersion);
    const approval = this.#approval(state, approvalId, state.handle.requiresApproval || decision === 'require_approval', dispatchTime);
    const ancestors = lineage(state.task);
    const controller = new AbortController();
    const cancelTimer = this.#deadlineTimer(state.task.budget.deadline - dispatchTime, controller);
    state.dispatched = true;
    if (approval) approval.used = true;
    this.#pruneApprovals(dispatchTime);
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
      } catch {
        return fail(controller.signal.aborted ? 'EXECUTION_ABORTED' : 'TOOL_FAILED');
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
      if (controller.signal.aborted) fail('EXECUTION_ABORTED');
      return value;
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

  snapshot(task: TaskHandle): Readonly<TaskSnapshot> { return this.#snapshot(this.#task(task)); }

  #now(): number {
    let now: unknown;
    try { now = this.#clock(); } catch { return fail('CLOCK_INVALID'); }
    if (!nonnegative(now)) fail('CLOCK_INVALID');
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
      family: parent?.family ?? { sensitive: false }, revoked: false,
      calls: 0, concurrent: 0, spent: 0, reserved: 0, active: new Set(),
    };
    this.#tasks.set(handle, state);
    this.#taskIds.add(identity.id);
    this.#pruneApprovals(now);
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
    if (Object.keys(data).some(key => !['resourceId', 'tenantId', 'external', 'recipient', 'sensitive'].includes(key))) fail('INVALID_INPUT');
    const result: ResolvedAction = {
      resourceId: identifier(data.resourceId), tenantId: identifier(data.tenantId),
      external: optionalBoolean(data.external), sensitive: optionalBoolean(data.sensitive),
    };
    if (Object.hasOwn(data, 'recipient')) result.recipient = identifier(data.recipient);
    return Object.freeze(result);
  }

  #gates(task: TaskState, tool: ToolState, action: Readonly<Action>, version: number): number {
    const now = this.#live(task);
    if (version !== this.#policyVersion) fail('POLICY_CHANGED');
    if (this.#tools.get(tool.name) !== tool) fail('TOOL_CHANGED');
    if (!tool.approved) fail('TOOL_UNAPPROVED');
    if (action.tenantId !== task.identity.tenantId) fail('TENANT_DENIED');
    for (const ancestor of lineage(task)) {
      if (!permits(ancestor.grants, action.tool, action.resourceId)) fail('GRANT_DENIED');
      if (tool.controlPlane && !ancestor.allowControlPlane) fail('CONTROL_PLANE_DENIED');
      if (action.external && (!action.recipient || !ancestor.recipients.has(action.recipient))) fail('RECIPIENT_DENIED');
      if (ancestor.calls >= ancestor.budget.maxCalls) fail('CALL_BUDGET_EXCEEDED');
      if (ancestor.concurrent >= ancestor.budget.maxConcurrent) fail('CONCURRENCY_EXCEEDED');
      // Integer units and subtraction first keep the admission comparison exact at MAX_SAFE_INTEGER.
      if (tool.maxCost > ancestor.budget.maxCost - ancestor.spent - ancestor.reserved) fail('COST_BUDGET_EXCEEDED');
    }
    if (action.external) {
      if (task.family.sensitive || action.sensitive) fail('SENSITIVE_EGRESS_DENIED');
      if (containsSecret(action.args, this.#secrets)) fail('SECRET_EGRESS_DENIED');
    }
    return now;
  }

  async #evaluate(action: Readonly<Action>, task: TaskState): Promise<PolicyDecision> {
    const policy = this.#policy;
    if (!policy) return 'allow';
    let decision: unknown;
    try { decision = await policy(action, this.#snapshot(task)); }
    catch { return fail('POLICY_ERROR'); }
    if (decision === 'deny') fail('POLICY_DENIED');
    if (decision !== 'allow' && decision !== 'require_approval') fail('POLICY_ERROR');
    return decision;
  }

  #approval(state: PreparedState, id: string | undefined, required: boolean, now: number): ApprovalState | undefined {
    if (id === undefined) {
      if (required) fail('APPROVAL_REQUIRED');
      return undefined;
    }
    const approval = this.#approvals.get(id);
    if (!approval || approval.prepared.deref() !== state || approval.digest !== state.handle.digest ||
        approval.policyVersion !== this.#policyVersion || approval.toolRevision !== state.tool.revision) fail('APPROVAL_INVALID');
    if (approval.used) fail('APPROVAL_USED');
    if (now >= approval.expiresAt) { this.#approvals.delete(id); fail('APPROVAL_EXPIRED'); }
    return approval;
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
    this.#pruneApprovals();
    for (const controller of task.active) controller.abort(new GuardError('TASK_REVOKED'));
  }

  #pruneApprovals(now?: number): void {
    for (const [id, approval] of this.#approvals) {
      const prepared = approval.prepared.deref();
      if (!prepared || prepared.dispatched || approval.policyVersion !== this.#policyVersion ||
          this.#tools.get(prepared.tool.name) !== prepared.tool ||
          (now !== undefined && now >= approval.expiresAt) ||
          lineage(prepared.task).some(task => task.revoked || (now !== undefined && now >= task.budget.deadline))) {
        this.#approvals.delete(id);
      }
    }
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
