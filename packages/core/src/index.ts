import { randomUUID } from 'node:crypto';
import { isPromise } from 'node:util/types';
import { digestJson, immutableJson, type JsonObject } from './json.js';
import { GuardError, safeErrorDetail } from './types.js';
import { assertActionAuthority, type AuthorityPhase, type AuthorityView } from './authorization.js';
import { PolicyAdmission } from './policy-admission.js';
import type {
  Action,
  UntrustedContextMode,
  Budget,
  ExecutionResult,
  GuardDecision,
  GuardOptions,
  Json,
  Policy,
  PolicyDecision,
  PreparedAction,
  ResolvedAction,
  TaskHandle,
  TaskIdentity,
  TaskOptions,
  TaskSnapshot,
  TaskStatus,
  ToolDefinition,
  ToolResult,
} from './types.js';

export { GuardError, GuardErrorCode, isGuardError } from './types.js';
export { InvalidJsonError } from './json.js';
export { GuardErrorCatalog, type GuardErrorInfo } from './errors.js';

export type {
  Action,
  UntrustedContextMode,
  Budget,
  Capability,
  ExecutionResult,
  GuardDecision,
  GuardLimits,
  GuardOptions,
  GuardErrorCodeValue,
  Json,
  Policy,
  PolicyDecision,
  PreparedAction,
  ResolvedAction,
  TaskHandle,
  TaskIdentity,
  TaskOptions,
  TaskSnapshot,
  TaskStatus,
  ToolDefinition,
  ToolResult,
} from './types.js';

/**
 * A wall-clock-anchored monotonic clock in milliseconds: it never steps backward when the
 * system clock is adjusted. Pass it as `clock` to avoid CLOCK_INVALID on a backward step.
 * The default clock is `Date.now`, and all deadlines are clock milliseconds.
 */
export function monotonicClock(): number {
  return Math.floor(performance.timeOrigin + performance.now());
}
const FAILED_AFTER_DISPATCH = new Set(['TOOL_FAILED', 'EXECUTION_ABORTED', 'RESULT_INVALID', 'COST_REPORT_INVALID']);

const MAX_TIMER_DELAY = 2_147_483_647;

type ToolState = {
  name: string;
  fingerprint: string;
  revision: number;
  approved: boolean;
  requiresApproval: boolean;
  controlPlane: boolean;
  maxCost: number;
  readsUntrusted: boolean;
  untrustedContext: UntrustedContextMode | undefined;
  sendsExternal: boolean | undefined;
  resolve: ToolDefinition['resolve'];
  execute: ToolDefinition['execute'];
  parse: ToolDefinition['parse'];
};
type TaskState = {
  identity: Readonly<TaskIdentity>;
  grants: Map<string, Set<string>>;
  recipients: Set<string>;
  allowControlPlane: boolean;
  budget: Readonly<Budget>;
  parent: TaskState | undefined;
  /** This task first, then each parent up to the root. Fixed at creation. */
  lineage: readonly TaskState[];
  /** The IDs of `lineage`, in the same order. */
  lineageIds: readonly string[];
  /** One frozen authority view per entry of `lineage`, built once and reused by every check. */
  authorities: readonly AuthorityView[];
  family: { id: string; sensitive: boolean; untrusted: boolean };
  revoked: boolean;
  calls: number;
  concurrent: number;
  spent: number;
  reserved: number;
  active: Set<AbortController>;
};
type PreparedState = {
  handle: PreparedAction;
  task: TaskState;
  tool: ToolState;
  policyVersion: number;
  dispatched: boolean;
  approvals: Map<string, ApprovalState>;
};
type ApprovalState = {
  expiresAt: number;
  /** Whether the family had read outside content when the approval was issued. */
  untrusted: boolean;
};
const UNTRUSTED_MODES: readonly string[] = ['allow', 'require_approval', 'deny'];
function untrustedMode(value: unknown): UntrustedContextMode | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !UNTRUSTED_MODES.includes(value)) fail('INVALID_INPUT');
  return value as UntrustedContextMode;
}
type PolicyEvaluation = { decision: PolicyDecision; snapshot?: Readonly<TaskSnapshot> };

function fail(code: ConstructorParameters<typeof GuardError>[0], cause?: unknown): never {
  const detail = cause === undefined ? undefined : safeErrorDetail(cause);
  throw new GuardError(code, code, detail === undefined ? {} : { detail });
}

function nonempty(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 4096 &&
    value.trim().length > 0 &&
    !value.includes('\0')
  );
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
const MAX_JSON_DEPTH = 64;
type JsonLimits = { readonly maxNodes: number; readonly maxBytes: number };
function normalizeJson(value: unknown, limits: JsonLimits): Json {
  try {
    return immutableJson(value, MAX_JSON_DEPTH, limits.maxNodes, limits.maxBytes);
  } catch {
    return fail('INVALID_JSON');
  }
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
function budgetFrom(input: Json): Readonly<Budget> {
  const data = asObject(input);
  const { maxCalls, maxConcurrent, maxCost, deadline } = data;
  if (
    !Number.isSafeInteger(maxCalls) ||
    !nonnegative(maxCalls) ||
    !Number.isSafeInteger(maxConcurrent) ||
    !nonnegative(maxConcurrent) ||
    !costUnits(maxCost) ||
    !nonnegative(deadline)
  )
    fail('INVALID_INPUT');
  return Object.freeze({ maxCalls, maxConcurrent, maxCost, deadline });
}
function stringSet(input: unknown): Set<string> {
  if (!Array.isArray(input)) fail('INVALID_INPUT');
  return new Set(input.map(identifier));
}
function grantsFrom(data: Json): Map<string, Set<string>> {
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
/**
 * A frozen view of one task's authority for the shared gates. Grants and recipients are the
 * task's own lookup tables; the counters and the revoked flag are read live through getters.
 */
function authorityView(task: TaskState): AuthorityView {
  return Object.freeze({
    identity: task.identity,
    grants: task.grants,
    allowedRecipients: task.recipients,
    allowControlPlane: task.allowControlPlane,
    budget: task.budget,
    snapshot: Object.freeze({
      get calls() {
        return task.calls;
      },
      get concurrent() {
        return task.concurrent;
      },
      get spent() {
        return task.spent;
      },
      get reserved() {
        return task.reserved;
      },
    }),
    get revoked() {
      return task.revoked;
    },
  });
}
/**
 * Authorizes AI-agent tool calls in memory. Trusted host code registers and approves tools,
 * creates tasks with grants and budgets, and runs each call in two steps: `prepare()` checks
 * it and `execute()` checks it again and runs the tool's handler. Every refusal is a
 * GuardError whose `code` is listed in GuardErrorCatalog. The guard is not a sandbox: the
 * host must isolate handlers and enforce authorization in its backends as well.
 */
export class AgentGuard {
  #tools = new Map<string, ToolState>();
  #tasks = new WeakMap<TaskHandle, TaskState>();
  #prepared = new WeakMap<PreparedAction, PreparedState>();
  #policyAdmission: PolicyAdmission;
  #maxApprovals: number;
  #untrustedDefault: UntrustedContextMode;
  #onDecision: ((event: Readonly<GuardDecision>) => void) | undefined;
  #taskIds = new Set<string>();
  #revision = 0;
  #policyVersion = 1;
  #policy: Policy | undefined;
  #clock: () => number;
  #observedClock = 0;
  #secrets: readonly string[];
  #jsonLimits: JsonLimits;
  #maxPolicyAttempts: number;
  /** Per-task queue for policy re-evaluations; first attempts stay parallel. */
  #policyTurns = new WeakMap<TaskState, Promise<void>>();

  /** Throws INVALID_INPUT for a malformed option or a limit outside its range. */
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
      if (typeof selected !== 'number' || !Number.isSafeInteger(selected) || selected < min || selected > max)
        fail('INVALID_INPUT');
      return selected;
    };
    this.#maxApprovals = bounded(limits.maxApprovalsPerAction, 4, 1, 64);
    this.#jsonLimits = Object.freeze({
      maxBytes: bounded(limits.maxJsonBytes, 1_048_576, 65_536, 67_108_864),
      maxNodes: bounded(limits.maxJsonNodes, 100_000, 1_000, 10_000_000),
    });
    this.#untrustedDefault = untrustedMode(options.untrustedContextDefault) ?? 'allow';
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

  /**
   * Registers a tool, or replaces the tool of the same name, and returns its fingerprint: a
   * `sha256:` digest of the definition's name, description, schema, metadata and flags. The
   * tool cannot be called until `approveTool()` is given that fingerprint. Registering again
   * withdraws the approval and fails actions already prepared for the tool with TOOL_CHANGED.
   * Throws INVALID_INPUT for a malformed definition and INVALID_JSON when the schema or
   * metadata is not plain JSON within the limits.
   */
  registerTool(definition: ToolDefinition): string {
    this.#now();
    if (!definition || typeof definition !== 'object') fail('INVALID_INPUT');
    const name = identifier(definition.name);
    if (
      typeof definition.description !== 'string' ||
      typeof definition.resolve !== 'function' ||
      typeof definition.execute !== 'function'
    )
      fail('INVALID_INPUT');
    if (definition.parse !== undefined && typeof definition.parse !== 'function') fail('INVALID_INPUT');
    const requiresApproval = optionalBoolean(definition.requiresApproval);
    const controlPlane = optionalBoolean(definition.controlPlane);
    const maxCost = definition.maxCost ?? 0;
    if (!costUnits(maxCost)) fail('INVALID_INPUT');
    const readsUntrusted = optionalBoolean(definition.readsUntrusted);
    const untrustedContext = untrustedMode(definition.untrustedContext);
    const sendsExternal =
      definition.sendsExternal === undefined ? undefined : optionalBoolean(definition.sendsExternal);
    const metadata = this.#json({
      name,
      description: definition.description,
      inputSchema: definition.inputSchema ?? null,
      metadata: definition.metadata ?? null,
      requiresApproval,
      controlPlane,
      maxCost,
      parsedArguments: definition.parse !== undefined,
      // Added only when set, so a tool that uses none of them keeps the same fingerprint.
      ...(definition.readsUntrusted === undefined ? {} : { readsUntrusted }),
      ...(untrustedContext === undefined ? {} : { untrustedContext }),
      ...(sendsExternal === undefined ? {} : { sendsExternal }),
    });
    const fingerprint = `sha256:${digestJson(metadata)}`;
    this.#tools.set(name, {
      name,
      fingerprint,
      revision: ++this.#revision,
      approved: false,
      requiresApproval,
      controlPlane,
      maxCost,
      readsUntrusted,
      untrustedContext,
      sendsExternal,
      resolve: definition.resolve,
      execute: definition.execute,
      parse: definition.parse,
    });
    return fingerprint;
  }

  /**
   * Approves one tool definition, identified by the fingerprint `registerTool()` returned, so
   * tasks holding a grant can call it. This approves the definition once; it is not the
   * per-call approval, which is `approve()`. Throws TOOL_UNKNOWN for an unregistered name
   * and TOOL_CHANGED when the fingerprint is not the current registration's.
   */
  approveTool(name: string, fingerprint: string): void {
    this.#now();
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    if (fingerprint !== tool.fingerprint) fail('TOOL_CHANGED');
    tool.approved = true;
  }

  /**
   * Withdraws a tool's approval: new and prepared actions for it fail with TOOL_UNAPPROVED
   * until `approveTool()` is called again. Throws TOOL_UNKNOWN for an unregistered name.
   */
  unapproveTool(name: string): void {
    const tool = this.#tools.get(name);
    if (!tool) fail('TOOL_UNKNOWN');
    tool.approved = false;
  }

  /**
   * Removes a tool. Actions already prepared for it fail with TOOL_CHANGED and new ones with
   * TOOL_UNKNOWN; a later registration needs a new approval. Throws TOOL_UNKNOWN for an
   * unregistered name.
   */
  unregisterTool(name: string): void {
    if (!this.#tools.delete(name)) fail('TOOL_UNKNOWN');
  }

  /**
   * Creates a task: one unit of agent work with an identity, grants and a budget. Pass the
   * returned handle to `prepare()`. Throws INVALID_INPUT or INVALID_JSON for malformed
   * options, DUPLICATE_TASK when the ID is in use and TASK_EXPIRED when the deadline has passed.
   */
  createTask(options: TaskOptions): TaskHandle {
    return this.#newTask(options, undefined);
  }

  /**
   * Creates a child task for a sub-agent. The child keeps the parent's principal and tenant
   * and may hold only what every ancestor holds: the same or fewer grants and recipients, the
   * same or a smaller budget and the same or an earlier deadline. Calls by the child also
   * count against each ancestor's budget, and revoking an ancestor revokes the child.
   * Throws DELEGATION_DENIED when the child asks for more (`detail` names the limit),
   * INVALID_TASK, TASK_REVOKED or TASK_EXPIRED for an unusable parent, and what
   * `createTask()` throws for malformed options.
   */
  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle {
    const state = this.#task(parent);
    this.#live(state);
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    return this.#newTask(
      { ...options, principalId: state.identity.principalId, tenantId: state.identity.tenantId },
      state,
    );
  }

  /**
   * Stops a task and its descendants for good: later calls fail with TASK_REVOKED, waiting
   * policy evaluations are cancelled and handlers in flight receive an abort signal. It works
   * even when the clock is failing. Throws INVALID_TASK for an unknown handle.
   */
  revokeTask(task: TaskHandle): void {
    this.#revoke(this.#task(task));
  }

  /**
   * Revokes the task and forgets it, freeing its ID and memory. Its handle then fails with
   * INVALID_TASK, its prepared actions fail with TASK_REVOKED and its descendants stay
   * revoked. Retire finished tasks in a long-running guard; a later task may reuse the ID.
   * Throws INVALID_TASK for an unknown handle.
   */
  retireTask(task: TaskHandle): void {
    const state = this.#task(task);
    this.#revoke(state);
    this.#tasks.delete(task);
    this.#taskIds.delete(state.identity.id);
  }

  /**
   * Replaces the policy. Actions prepared under the previous policy fail with POLICY_CHANGED
   * and evaluations in flight are cancelled, so every action is prepared and reviewed again
   * under the new policy. Throws INVALID_INPUT when `policy` is not a function.
   */
  setPolicy(policy: Policy): void {
    if (typeof policy !== 'function') fail('INVALID_INPUT');
    this.#policy = policy;
    this.#policyVersion++;
    this.#policyAdmission.invalidate('POLICY_CHANGED');
  }

  /**
   * Checks one call and returns it as a frozen PreparedAction without running the handler.
   * It copies the arguments, runs the tool's `parse` and `resolve`, then checks the grant,
   * tenant, recipient, sensitive-data and budget rules and the policy. `requiresApproval` on
   * the result says whether `execute()` needs an approval.
   *
   * Rejects with a GuardError: INVALID_TASK, TASK_REVOKED or TASK_EXPIRED for the task;
   * INVALID_INPUT or INVALID_JSON for the request; TOOL_UNKNOWN or TOOL_UNAPPROVED for the
   * tool; ARGUMENT_INVALID or RESOLUTION_FAILED from the tool's callbacks; a denial such as
   * GRANT_DENIED, TENANT_DENIED, RECIPIENT_DENIED, CONTROL_PLANE_DENIED,
   * SENSITIVE_EGRESS_DENIED, SECRET_EGRESS_DENIED, UNTRUSTED_CONTEXT_DENIED,
   * CALL_BUDGET_EXCEEDED or COST_BUDGET_EXCEEDED; or a POLICY_ code from the policy.
   */
  async prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction> {
    try {
      const prepared = await this.#prepare(task, request);
      this.#decision('prepare', 'allowed', this.#tasks.get(task), {
        tool: prepared.action.tool,
        actionId: prepared.id,
        resourceId: prepared.action.resourceId,
      });
      return prepared;
    } catch (error) {
      const tool =
        request !== null &&
        typeof request === 'object' &&
        typeof request.tool === 'string' &&
        this.#tools.has(request.tool)
          ? request.tool
          : undefined;
      this.#decision('prepare', 'denied', this.#tasks.get(task), { ...(tool === undefined ? {} : { tool }) }, error);
      throw error;
    }
  }

  async #prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction> {
    const state = this.#task(task);
    this.#live(state);
    if (this.#policy) this.#policyAdmission.assertCapacity(state.family.id);
    const input = asObject(this.#json(request));
    if (Object.keys(input).some(key => key !== 'tool' && key !== 'args') || !Object.hasOwn(input, 'args'))
      fail('INVALID_INPUT');
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
      try {
        args = this.#json(synchronousResult(parse(args)));
      } catch (error) {
        return fail('ARGUMENT_INVALID', error);
      }
    }
    let resolved: ResolvedAction;
    const resolve = tool.resolve;
    try {
      resolved = this.#resolved(synchronousResult(resolve(args, state.identity)));
      // sendsExternal: false is a promise about every call; an external resolution breaks it.
      if (tool.sendsExternal === false && resolved.external) fail('INVALID_INPUT');
    } catch (error) {
      return fail('RESOLUTION_FAILED', error);
    }
    const action: Readonly<Action> = Object.freeze({
      ...resolved,
      tool: name,
      args,
      toolFingerprint: tool.fingerprint,
      policyVersion,
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
    } finally {
      endTurn?.();
    }
    const id = randomUUID();
    // Every part was copied and bounded when it was admitted, so the digest is taken directly:
    // measuring this slightly larger envelope again could refuse arguments already accepted.
    const digest = `sha256:${digestJson({
      preparedId: id,
      task: state.identity,
      action,
      toolRevision: tool.revision,
    } as unknown as Json)}`;
    const handle: PreparedAction = Object.freeze({
      id,
      digest,
      action,
      requiresApproval:
        tool.requiresApproval || evaluation.decision === 'require_approval' || this.#untrustedApproval(state, tool),
    });
    this.#prepared.set(handle, { handle, task: state, tool, policyVersion, dispatched: false, approvals: new Map() });
    return handle;
  }

  /**
   * Records a reviewer's approval of one exact prepared action and returns an approval ID to
   * pass to `execute()`. The approval covers only this action (these arguments, this
   * resource), works once and ends at `expiresAt` (clock milliseconds, no later than the
   * task deadline). Call it only from trusted code that has shown the action to the reviewer.
   *
   * Throws INVALID_PREPARED for an unknown action, ACTION_USED when it has already run,
   * APPROVAL_INVALID for a bad expiry, ACTION_APPROVAL_LIMIT when the action already holds
   * the maximum number of live approvals, INVALID_INPUT for a malformed approver ID, and the
   * same task, tool, policy and denial codes as `prepare()` when the action is no longer allowed.
   */
  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string {
    const state = this.#prepared.get(prepared);
    const detail = state
      ? { tool: state.tool.name, actionId: state.handle.id, resourceId: state.handle.action.resourceId }
      : {};
    try {
      const id = this.#approve(prepared, options);
      this.#decision('approve', 'allowed', state?.task, { ...detail, approverId: options.approverId });
      return id;
    } catch (error) {
      this.#decision('approve', 'denied', state?.task, detail, error);
      throw error;
    }
  }

  #approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string {
    const state = this.#invocation(prepared);
    this.#fresh(state);
    const now = this.#gates(state.task, state.tool, state.handle.action, state.policyVersion, 'prepare');
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    identifier(options.approverId);
    const expiresAt = options.expiresAt;
    if (
      !nonnegative(expiresAt) ||
      expiresAt <= now ||
      state.task.lineage.some(task => expiresAt > task.budget.deadline)
    )
      fail('APPROVAL_INVALID');
    for (const [id, approval] of state.approvals) if (now >= approval.expiresAt) state.approvals.delete(id);
    if (state.approvals.size >= this.#maxApprovals) fail('ACTION_APPROVAL_LIMIT');
    const id = randomUUID();
    state.approvals.set(id, { expiresAt, untrusted: state.task.family.untrusted });
    return id;
  }

  /**
   * Runs a prepared action once and returns the handler's value. Immediately before the
   * handler runs, every check from `prepare()` is repeated against current state, the
   * approval is verified and the call is counted against the budget of the task and each
   * ancestor.
   *
   * Rejects with a GuardError. Before the handler starts (nothing happened): INVALID_PREPARED,
   * ACTION_USED, the task, tool, policy and denial codes of `prepare()`, POLICY_CHANGED,
   * TOOL_CHANGED, CONCURRENCY_EXCEEDED, APPROVAL_REQUIRED, APPROVAL_INVALID, APPROVAL_EXPIRED
   * or APPROVAL_CONTEXT_CHANGED. After the handler started (the effect may have happened, do
   * not retry blindly): TOOL_FAILED, EXECUTION_ABORTED, RESULT_INVALID or COST_REPORT_INVALID.
   * The last two also revoke the task.
   */
  async execute(prepared: PreparedAction, options: { approvalId?: string } = {}): Promise<Json> {
    return (await this.executeDetailed(prepared, options)).value;
  }

  /** Like `execute()`, with the same errors, but also returns the charged cost and the action ID for receipts. */
  async executeDetailed(prepared: PreparedAction, options: { approvalId?: string } = {}): Promise<ExecutionResult> {
    const state = this.#prepared.get(prepared);
    const detail = state
      ? { tool: state.tool.name, actionId: state.handle.id, resourceId: state.handle.action.resourceId }
      : {};
    try {
      const result = await this.#execute(prepared, options);
      this.#decision('execute', 'succeeded', state?.task, detail);
      return result;
    } catch (error) {
      const code = error instanceof GuardError ? error.code : undefined;
      this.#decision(
        'execute',
        code !== undefined && FAILED_AFTER_DISPATCH.has(code) ? 'failed' : 'denied',
        state?.task,
        detail,
        error,
      );
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
    } finally {
      endTurn?.();
    }
    this.#approval(
      state,
      approvalId,
      state.handle.requiresApproval ||
        evaluation.decision === 'require_approval' ||
        this.#untrustedApproval(state.task, state.tool),
      dispatchTime,
    );
    const ancestors = state.task.lineage;
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
    // Set at dispatch, before the handler runs: a read that fails partway may already have content.
    if (state.tool.readsUntrusted || state.handle.action.untrusted) state.task.family.untrusted = true;

    let charge = state.tool.maxCost;
    try {
      let result: ToolResult;
      try {
        const execute = state.tool.execute;
        result = await execute(
          state.handle.action.args,
          Object.freeze({
            signal: controller.signal,
            action: state.handle.action,
            task: state.task.identity,
          }),
        );
      } catch (error) {
        return fail(
          controller.signal.aborted ? 'EXECUTION_ABORTED' : 'TOOL_FAILED',
          controller.signal.aborted ? undefined : error,
        );
      }
      let value: Json;
      try {
        const data = asObject(this.#json(result));
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
        return fail(
          error instanceof GuardError && error.code === 'COST_REPORT_INVALID'
            ? 'COST_REPORT_INVALID'
            : 'RESULT_INVALID',
        );
      }
      // A synchronous handler or a busy microtask queue can settle before the deadline timer runs.
      // The handler has already run: a clock that fails here is an aborted execution with an
      // unknown outcome, never a denial.
      let expired: boolean;
      // The handler returned, so its effect happened: say so, as the durable executor does.
      try {
        expired = this.#now() >= state.task.budget.deadline;
      } catch {
        return fail('EXECUTION_ABORTED', { code: 'EFFECT_COMMITTED' });
      }
      if (expired) controller.abort(new GuardError('TASK_EXPIRED'));
      if (controller.signal.aborted) fail('EXECUTION_ABORTED', { code: 'EFFECT_COMMITTED' });
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

  /** Counters, budget and revocation state for the task. Throws INVALID_TASK for an unknown handle. */
  snapshot(task: TaskHandle): Readonly<TaskStatus> {
    const state = this.#task(task);
    return Object.freeze({
      ...this.#snapshot(state),
      budget: state.budget,
      revoked: state.lineage.some(ancestor => ancestor.revoked),
    });
  }

  /** Copies and freezes a JSON value within this guard's configured size limits. */
  #json(value: unknown): Json {
    return normalizeJson(value, this.#jsonLimits);
  }

  #decision(
    operation: GuardDecision['operation'],
    outcome: GuardDecision['outcome'],
    task: TaskState | undefined,
    detail: { tool?: string; actionId?: string; resourceId?: string; approverId?: string },
    error?: unknown,
  ): void {
    const hook = this.#onDecision;
    if (!hook || !task) return;
    const code = error instanceof GuardError ? error.code : undefined;
    const approverId =
      typeof detail.approverId === 'string' && detail.approverId.length <= 4096 ? detail.approverId : undefined;
    try {
      const event = Object.freeze({
        operation,
        outcome,
        taskId: task.identity.id,
        untrusted: task.family.untrusted,
        tenantId: task.identity.tenantId,
        principalId: task.identity.principalId,
        ...(detail.tool === undefined ? {} : { tool: detail.tool }),
        ...(detail.actionId === undefined ? {} : { actionId: detail.actionId }),
        ...(detail.resourceId === undefined ? {} : { resourceId: detail.resourceId }),
        ...(approverId === undefined ? {} : { approverId }),
        ...(code === undefined ? {} : { code }),
      });
      const returned: unknown = hook(event);
      if (isPromise(returned)) void (returned as Promise<unknown>).catch(() => {});
    } catch {
      /* Observation never changes an authorization outcome. */
    }
  }

  #now(): number {
    let now: unknown;
    try {
      now = this.#clock();
    } catch {
      return fail('CLOCK_INVALID');
    }
    if (!nonnegative(now) || now < this.#observedClock) fail('CLOCK_INVALID');
    this.#observedClock = now;
    return now;
  }

  #newTask(options: TaskOptions, parent: TaskState | undefined): TaskHandle {
    if (!options || typeof options !== 'object') fail('INVALID_INPUT');
    const identity = Object.freeze({
      id: identifier(options.id),
      principalId: identifier(options.principalId),
      tenantId: identifier(options.tenantId),
    });
    if (this.#taskIds.has(identity.id)) fail('DUPLICATE_TASK');
    const budget = budgetFrom(this.#json(options.budget));
    const grants = grantsFrom(this.#json(options.grants));
    const recipients = stringSet(this.#json(options.allowedRecipients ?? []));
    const allowControlPlane = optionalBoolean(options.allowControlPlane);
    const now = this.#now();
    if (budget.deadline <= now) fail('TASK_EXPIRED');
    if (parent) {
      // The detail names which limit the child exceeded; it never carries a value.
      const exceeds = (detail: string): never => fail('DELEGATION_DENIED', { code: detail });
      for (const ancestor of parent.lineage) {
        for (const [tool, resources] of grants) {
          for (const resource of resources) {
            if (!permits(ancestor.grants, tool, resource)) exceeds('GRANT_EXCEEDS_PARENT');
          }
        }
        if ([...recipients].some(recipient => !ancestor.recipients.has(recipient))) exceeds('RECIPIENT_EXCEEDS_PARENT');
        if (allowControlPlane && !ancestor.allowControlPlane) exceeds('CONTROL_PLANE_EXCEEDS_PARENT');
        if (
          budget.maxCalls > ancestor.budget.maxCalls ||
          budget.maxConcurrent > ancestor.budget.maxConcurrent ||
          budget.maxCost > ancestor.budget.maxCost
        )
          exceeds('BUDGET_EXCEEDS_PARENT');
        if (budget.deadline > ancestor.budget.deadline) exceeds('DEADLINE_EXCEEDS_PARENT');
      }
    }
    const handle = Object.freeze({ id: identity.id });
    const lineage: TaskState[] = [];
    const state: TaskState = {
      identity,
      grants,
      recipients,
      allowControlPlane,
      budget,
      parent,
      lineage,
      lineageIds: Object.freeze([identity.id, ...(parent?.lineageIds ?? [])]),
      authorities: [],
      family: parent?.family ?? { id: identity.id, sensitive: false, untrusted: false },
      revoked: false,
      calls: 0,
      concurrent: 0,
      spent: 0,
      reserved: 0,
      active: new Set(),
    };
    // The ancestry never changes, so the lineage and its authority views are built once here.
    lineage.push(state, ...(parent?.lineage ?? []));
    Object.freeze(lineage);
    state.authorities = Object.freeze([authorityView(state), ...(parent?.authorities ?? [])]);
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

  #fresh(state: PreparedState): void {
    if (state.dispatched) fail('ACTION_USED');
  }

  #live(task: TaskState): number {
    const now = this.#now();
    for (const ancestor of task.lineage) {
      if (ancestor.revoked) fail('TASK_REVOKED');
      if (now >= ancestor.budget.deadline) fail('TASK_EXPIRED');
    }
    return now;
  }

  #resolved(value: ResolvedAction): ResolvedAction {
    const data = asObject(this.#json(value));
    if (
      Object.keys(data).some(
        key =>
          !['resourceId', 'tenantId', 'external', 'recipient', 'sensitive', 'resourceVersion', 'untrusted'].includes(
            key,
          ),
      )
    )
      fail('INVALID_INPUT');
    const result: ResolvedAction = {
      resourceId: identifier(data.resourceId),
      tenantId: identifier(data.tenantId),
      external: optionalBoolean(data.external),
      sensitive: optionalBoolean(data.sensitive),
    };
    if (Object.hasOwn(data, 'recipient')) result.recipient = identifier(data.recipient);
    if (Object.hasOwn(data, 'resourceVersion')) result.resourceVersion = identifier(data.resourceVersion);
    // A resolver may only add the outside-content mark; false cannot clear it.
    if (Object.hasOwn(data, 'untrusted')) {
      if (data.untrusted !== true) fail('INVALID_INPUT');
      result.untrusted = true;
    }
    return Object.freeze(result);
  }

  #gates(
    task: TaskState,
    tool: ToolState,
    action: Readonly<Action>,
    version: number,
    phase: AuthorityPhase = 'dispatch',
  ): number {
    const now = this.#live(task);
    if (version !== this.#policyVersion) fail('POLICY_CHANGED');
    if (this.#tools.get(tool.name) !== tool) fail('TOOL_CHANGED');
    if (!tool.approved) fail('TOOL_UNAPPROVED');
    assertActionAuthority(action, task.authorities, {
      now,
      maxCost: tool.maxCost,
      controlPlane: tool.controlPlane,
      sensitive: task.family.sensitive,
      secretValues: this.#secrets,
      phase,
      untrusted: task.family.untrusted,
      untrustedContext: this.#untrustedModeOf(tool),
    });
    return now;
  }

  async #evaluate(action: Readonly<Action>, task: TaskState): Promise<PolicyEvaluation> {
    const policy = this.#policy;
    if (!policy) return { decision: 'allow' };
    const snapshot = this.#snapshot(task);
    const decision = await this.#policyAdmission.evaluate(policy, action, snapshot, {
      familyId: task.family.id,
      taskIds: task.lineageIds,
      remainingMs: task.budget.deadline - this.#now(),
    });
    return { decision, snapshot };
  }

  /** Waits for this task's earlier re-evaluations; the returned function ends this turn (idempotent). */
  async #policyTurn(task: TaskState): Promise<() => void> {
    const previous = this.#policyTurns.get(task) ?? Promise.resolve();
    let end!: () => void;
    const turn = new Promise<void>(resolve => {
      end = resolve;
    });
    this.#policyTurns.set(
      task,
      previous.then(() => turn),
    );
    await previous;
    return end;
  }

  #policySnapshotChanged(task: TaskState, evaluation: PolicyEvaluation): boolean {
    const snapshot = evaluation.snapshot;
    return (
      !!snapshot &&
      (snapshot.calls !== task.calls ||
        snapshot.concurrent !== task.concurrent ||
        snapshot.spent !== task.spent ||
        snapshot.reserved !== task.reserved ||
        snapshot.sensitive !== task.family.sensitive ||
        snapshot.untrusted !== task.family.untrusted)
    );
  }

  #approval(state: PreparedState, id: string | undefined, required: boolean, now: number): void {
    if (id === undefined) {
      if (required) fail('APPROVAL_REQUIRED');
      return;
    }
    // Lookup is scoped to the exact issued action. #gates checked its policy and tool revision.
    const approval = state.approvals.get(id);
    if (!approval) fail('APPROVAL_INVALID');
    if (now >= approval.expiresAt) {
      state.approvals.delete(id);
      fail('APPROVAL_EXPIRED');
    }
    // The reviewer approved a clean family; it has since read outside content.
    if (!approval.untrusted && state.task.family.untrusted && this.#untrustedModeOf(state.tool) !== 'allow')
      fail('APPROVAL_CONTEXT_CHANGED');
  }

  #untrustedModeOf(tool: ToolState): UntrustedContextMode {
    return tool.untrustedContext ?? this.#untrustedDefault;
  }
  #untrustedApproval(task: TaskState, tool: ToolState): boolean {
    return task.family.untrusted && this.#untrustedModeOf(tool) === 'require_approval';
  }

  #snapshot(task: TaskState): Readonly<TaskSnapshot> {
    return Object.freeze({
      ...task.identity,
      sensitive: task.family.sensitive,
      untrusted: task.family.untrusted,
      calls: task.calls,
      concurrent: task.concurrent,
      spent: task.spent,
      reserved: task.reserved,
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
    return () => {
      canceled = true;
      if (timer) clearTimeout(timer);
    };
  }
}
