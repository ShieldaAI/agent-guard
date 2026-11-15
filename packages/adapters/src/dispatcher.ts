import type { Action, AgentGuard, Json, TaskHandle } from '@shieldaai/agent-guard';
import { isGuardError } from '@shieldaai/agent-guard';
import {
  adapterDenial,
  hostErrorOutcome,
  modelMessage,
  outcomeFromError,
  waitingOutcome,
  type DeniedOutcome,
  type DispatchOutcome,
  type FailedOutcome,
} from './outcomes.js';
import { AdapterError } from './errors.js';

/** One tool call as a model asked for it. `input` is the parsed argument object. */
export interface ToolCall {
  readonly name: string;
  readonly input?: unknown;
  /** The provider's ID for this call, passed through to hooks. Not checked. */
  readonly id?: string;
}
/** A prepared action as the guard and the executor return it. */
export interface PreparedCall {
  readonly id: string;
  readonly digest: string;
  readonly action: Readonly<Action>;
  readonly requiresApproval: boolean;
}
/**
 * What a dispatcher needs from a guard. `guardBackend`, `executorBackend` and
 * `executorClientBackend` build one; any object of this shape works.
 */
export interface GuardBackend {
  prepare(request: { tool: string; args: Json }, signal?: AbortSignal): Promise<PreparedCall>;
  execute(prepared: PreparedCall, options: { approvalId?: string; signal?: AbortSignal }): Promise<Json>;
  /** Issues a per-action approval. Absent when approvals are issued elsewhere (for example the executor's admin API). */
  approve?(prepared: PreparedCall, options: { approverId: string; expiresAt: number }): string | Promise<string>;
  /** The task's deadline in clock milliseconds, when known. Approvals never outlive it. */
  deadline?(): number | undefined;
  /** False once the task is revoked, retired or unknown. Waiting actions of an inactive task are dropped. */
  active?(): boolean;
}

/** A backend for the in-process core guard and one task handle. */
export function guardBackend(guard: AgentGuard, task: TaskHandle): GuardBackend {
  const handles = new WeakMap<PreparedCall, Parameters<AgentGuard['execute']>[0]>();
  const own = (prepared: PreparedCall) => handles.get(prepared) ?? (prepared as Parameters<AgentGuard['execute']>[0]);
  return Object.freeze({
    async prepare(request: { tool: string; args: Json }) {
      const prepared = await guard.prepare(task, request);
      handles.set(prepared, prepared);
      return prepared;
    },
    execute(prepared: PreparedCall, options: { approvalId?: string }) {
      return guard.execute(own(prepared), options.approvalId === undefined ? {} : { approvalId: options.approvalId });
    },
    approve(prepared: PreparedCall, options: { approverId: string; expiresAt: number }) {
      return guard.approve(own(prepared), options);
    },
    deadline() {
      try {
        return guard.snapshot(task).budget.deadline;
      } catch {
        return undefined;
      }
    },
    active() {
      try {
        return !guard.snapshot(task).revoked;
      } catch {
        return false;
      }
    },
  });
}

/** The parts of the durable executor (`@shieldaai/agent-guard-executor`) a backend uses. */
export interface ExecutorLike {
  prepare(taskId: string, request: { tool: string; args: Json }): Promise<PreparedCall>;
  approve(actionId: string, options: { approverId: string; expiresAt: number }): string;
  execute(taskId: string, actionId: string, options?: { approvalId?: string }): Promise<Json>;
  snapshot?(taskId: string): { readonly revoked?: boolean; readonly budget?: { readonly deadline?: number } };
}
/** A backend for the durable executor, in process, and one task ID. */
export function executorBackend(executor: ExecutorLike, taskId: string): GuardBackend {
  return Object.freeze({
    prepare: (request: { tool: string; args: Json }) => executor.prepare(taskId, request),
    execute: (prepared: PreparedCall, options: { approvalId?: string }) =>
      executor.execute(taskId, prepared.id, options.approvalId === undefined ? {} : { approvalId: options.approvalId }),
    approve: (prepared: PreparedCall, options: { approverId: string; expiresAt: number }) =>
      executor.approve(prepared.id, options),
    deadline() {
      try {
        const deadline = executor.snapshot?.(taskId)?.budget?.deadline;
        return typeof deadline === 'number' ? deadline : undefined;
      } catch {
        return undefined;
      }
    },
    active() {
      if (typeof executor.snapshot !== 'function') return true;
      try {
        return executor.snapshot(taskId)?.revoked !== true;
      } catch {
        return false;
      }
    },
  });
}

/** The parts of the executor's task client (`ExecutorClient`) a backend uses. */
export interface ExecutorClientLike {
  prepare(tool: string, args: Json, signal?: AbortSignal): Promise<PreparedCall>;
  execute(actionId: string, options?: { approvalId?: string; signal?: AbortSignal }): Promise<Json>;
}
/**
 * A backend for a remote executor reached with a task token. It cannot approve: approvals
 * come from the executor's admin API, and `ApprovalQueue.complete()` runs the action with one.
 */
export function executorClientBackend(client: ExecutorClientLike): GuardBackend {
  return Object.freeze({
    prepare: (request: { tool: string; args: Json }, signal?: AbortSignal) =>
      client.prepare(request.tool, request.args, signal),
    execute: (prepared: PreparedCall, options: { approvalId?: string; signal?: AbortSignal }) =>
      client.execute(prepared.id, {
        ...(options.approvalId === undefined ? {} : { approvalId: options.approvalId }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      }),
  });
}

/** One action waiting for a person, as `ApprovalQueue.pending()` lists it. */
export interface PendingApproval {
  readonly actionId: string;
  /** Names this exact call. Show it, and compare it with what the reviewer approved. */
  readonly digest: string;
  readonly tool: string;
  /** Exactly what will run. Arguments came from the model: show them as data, never as markup. */
  readonly action: Readonly<Action>;
  /** When the action was queued, in clock milliseconds. */
  readonly queuedAt: number;
}
/** Options for `new ApprovalQueue()`. */
export interface ApprovalQueueOptions {
  /** Most actions that may wait at once. Integer 1-10,000, default 100. Past it, calls are denied with APPROVAL_QUEUE_FULL. */
  maxPending?: number;
  /**
   * Most actions one dispatcher (one task) may have waiting at once, so one task cannot fill a
   * shared queue. Integer 1-10,000, default 10. Past it, that task's calls get APPROVAL_QUEUE_FULL.
   */
  maxPendingPerTask?: number;
  /**
   * Longest an action may wait, in milliseconds; older actions are dropped with APPROVAL_TIMEOUT.
   * Actions of a task that is revoked or past its deadline are dropped too (TASK_REVOKED,
   * TASK_EXPIRED). Integer 1,000-2,592,000,000 (30 days), default 86,400,000 (one day).
   */
  maxWaitMs?: number;
  /** How long an approval issued by `approve()` stays valid, in milliseconds. Integer 1,000-86,400,000, default 60,000. */
  approvalTtlMs?: number;
  /** Clock for timestamps and approval expiry. Must match the guard's clock. Default `Date.now`. */
  clock?: () => number;
  /** Called after an action starts waiting (in a microtask). Use it to notify reviewers. A throwing hook is ignored. */
  onPending?: (entry: PendingApproval) => void;
  /** Called once with the final outcome of every queued action. A throwing hook is ignored. */
  onSettled?: (entry: PendingApproval, outcome: DispatchOutcome) => void;
  /** Receives errors from host code while an approved action runs. The model never sees them. Default: a process warning. */
  onHostError?: (error: unknown, entry: PendingApproval) => void;
}

type Entry = {
  view: PendingApproval;
  prepared: PreparedCall;
  backend: GuardBackend;
  state: 'pending' | 'deciding' | 'settled';
  settled: Promise<DispatchOutcome>;
  resolve: (outcome: DispatchOutcome) => void;
  /** Waiters whose time ran out while a decision was in progress; settled if it is undone. */
  expired: ('APPROVAL_TIMEOUT' | 'APPROVAL_CANCELLED')[];
};

function integerOption(value: unknown, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max)
    throw new AdapterError('INVALID_OPTIONS');
  return value;
}
function quietly(hook: (() => void) | undefined): void {
  try {
    hook?.();
  } catch {
    // Hooks observe; they cannot change an outcome.
  }
}
function defaultHostError(error: unknown): void {
  // Host-side only: the model never sees this text.
  process.emitWarning('Host code threw during an Agent Guard tool call', {
    code: 'AGENT_GUARD_HOST_ERROR',
    detail: error instanceof Error ? (error.stack ?? error.message) : String(error),
  });
}
/** The code of a guard error or an executor error, else undefined. */
function guardCode(error: unknown): string | undefined {
  if (isGuardError(error)) return error.code;
  if (error !== null && typeof error === 'object' && (error as { name?: unknown }).name === 'ExecutorError') {
    const code = Object.getOwnPropertyDescriptor(error, 'code')?.value;
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}
/** Codes that mean the host passed a bad approval, not that the action is impossible. */
const ISSUANCE_MISTAKES = new Set(['INVALID_INPUT', 'APPROVAL_INVALID']);
/**
 * Codes from execute with an outside approval ID that prove the action was not admitted. Not
 * APPROVAL_EXPIRED or APPROVAL_USED: the durable executor can return those after admitting the
 * action, which is then spent.
 */
const EXTERNAL_APPROVAL_MISTAKES = new Set(['INVALID_INPUT', 'APPROVAL_INVALID']);

/**
 * Actions that wait for a person, kept by the host. The model-facing dispatcher only ever adds
 * to it; approving and rejecting are host calls made after your own sign-in check.
 * One queue can serve many dispatchers and tasks; each dispatcher has its own share.
 */
export class ApprovalQueue {
  readonly #entries = new Map<string, Entry>();
  readonly #maxPending: number;
  readonly #maxPerTask: number;
  readonly #maxWait: number;
  readonly #ttl: number;
  readonly #clock: () => number;
  readonly #onPending: ApprovalQueueOptions['onPending'];
  readonly #onSettled: ApprovalQueueOptions['onSettled'];
  readonly #onHostError: NonNullable<ApprovalQueueOptions['onHostError']>;

  constructor(options: ApprovalQueueOptions = {}) {
    if (options === null || typeof options !== 'object') throw new AdapterError('INVALID_OPTIONS');
    this.#maxPending = integerOption(options.maxPending, 100, 1, 10_000);
    this.#maxPerTask = integerOption(options.maxPendingPerTask, 10, 1, 10_000);
    this.#maxWait = integerOption(options.maxWaitMs, 86_400_000, 1_000, 2_592_000_000);
    this.#ttl = integerOption(options.approvalTtlMs, 60_000, 1_000, 86_400_000);
    for (const hook of [options.clock, options.onPending, options.onSettled, options.onHostError])
      if (hook !== undefined && typeof hook !== 'function') throw new AdapterError('INVALID_OPTIONS');
    this.#clock = options.clock ?? Date.now;
    this.#onPending = options.onPending;
    this.#onSettled = options.onSettled;
    this.#onHostError = options.onHostError ?? defaultHostError;
  }

  /** Drops waiting actions that can no longer run: too old, or their task is inactive or expired. */
  #prune(): void {
    const now = this.#clock();
    for (const entry of [...this.#entries.values()]) {
      if (entry.state !== 'pending') continue;
      let code: 'APPROVAL_TIMEOUT' | 'TASK_REVOKED' | 'TASK_EXPIRED' | undefined;
      try {
        if (now - entry.view.queuedAt >= this.#maxWait) code = 'APPROVAL_TIMEOUT';
        else if (entry.backend.active?.() === false) code = 'TASK_REVOKED';
        else {
          const deadline = entry.backend.deadline?.();
          if (typeof deadline === 'number' && now >= deadline) code = 'TASK_EXPIRED';
        }
      } catch (error) {
        // A broken custom backend affects only its own actions, never the rest of the queue.
        quietly(() => this.#onHostError(error, entry.view));
        code = 'TASK_REVOKED';
      }
      if (code === undefined) continue;
      entry.state = 'deciding';
      this.#settle(
        entry,
        code === 'APPROVAL_TIMEOUT'
          ? adapterDenial(entry.view.tool, code, entry.view.actionId)
          : Object.freeze({
              status: 'denied',
              tool: entry.view.tool,
              code,
              retryable: false,
              message: modelMessage(code),
              actionId: entry.view.actionId,
            }),
      );
    }
  }

  /** Actions waiting now, oldest first. Actions that can no longer run are dropped first. */
  pending(): readonly PendingApproval[] {
    this.#prune();
    return Object.freeze(
      [...this.#entries.values()].filter(entry => entry.state === 'pending').map(entry => entry.view),
    );
  }

  /** One waiting action, or undefined. */
  get(actionId: string): PendingApproval | undefined {
    this.#prune();
    const entry = this.#entries.get(actionId);
    return entry?.state === 'pending' ? entry.view : undefined;
  }

  /** @internal Called by dispatchers. Returns undefined when the queue, or the task's share of it, is full. */
  enqueue(prepared: PreparedCall, backend: GuardBackend): PendingApproval | undefined {
    const existing = this.#entries.get(prepared.id);
    if (existing) return existing.view;
    const waiting = this.pending();
    if (waiting.length >= this.#maxPending) return undefined;
    let mine = 0;
    for (const entry of this.#entries.values()) if (entry.state === 'pending' && entry.backend === backend) mine += 1;
    if (mine >= this.#maxPerTask) return undefined;
    let resolve!: (outcome: DispatchOutcome) => void;
    const settled = new Promise<DispatchOutcome>(ok => {
      resolve = ok;
    });
    const view: PendingApproval = Object.freeze({
      actionId: prepared.id,
      digest: prepared.digest,
      tool: prepared.action.tool,
      action: prepared.action,
      queuedAt: this.#clock(),
    });
    this.#entries.set(prepared.id, { view, prepared, backend, state: 'pending', settled, resolve, expired: [] });
    // After the dispatcher has started waiting, so a hook that decides at once is seen by it.
    queueMicrotask(() => quietly(() => this.#onPending?.(view)));
    return view;
  }

  #take(actionId: string): Entry {
    this.#prune();
    const entry = this.#entries.get(actionId);
    if (!entry || entry.state !== 'pending') throw new AdapterError('APPROVAL_NOT_FOUND');
    entry.state = 'deciding';
    return entry;
  }
  #settle(entry: Entry, outcome: DispatchOutcome): DispatchOutcome {
    entry.state = 'settled';
    this.#entries.delete(entry.view.actionId);
    entry.resolve(outcome);
    quietly(() => this.#onSettled?.(entry.view, outcome));
    return outcome;
  }
  /**
   * Puts an entry back to waiting after the guard refused the approval itself, then throws
   * APPROVAL_NOT_ACCEPTED to the host. A dispatcher whose wait ran out meanwhile gets its
   * timeout now, instead of waiting for a decision that may never come.
   */
  #undo(entry: Entry, code: string | undefined): never {
    entry.state = 'pending';
    const expired = entry.expired.shift();
    entry.expired.length = 0;
    if (expired !== undefined) {
      entry.state = 'deciding';
      this.#settle(entry, adapterDenial(entry.view.tool, expired, entry.view.actionId));
    }
    throw new AdapterError('APPROVAL_NOT_ACCEPTED', code);
  }
  async #run(entry: Entry, approvalId: () => string | Promise<string>, external: boolean): Promise<DispatchOutcome> {
    let id: string;
    try {
      id = await approvalId();
    } catch (error) {
      // The approval was refused before anything ran.
      if (ISSUANCE_MISTAKES.has(guardCode(error) ?? '')) this.#undo(entry, guardCode(error));
      const outcome = outcomeFromError(error, entry.view.tool, entry.view.actionId, 'approve');
      if (outcome) return this.#settle(entry, outcome);
      quietly(() => this.#onHostError(error, entry.view));
      return this.#settle(entry, hostErrorOutcome(entry.view.tool, 'approve', entry.view.actionId));
    }
    try {
      const result = await entry.backend.execute(entry.prepared, { approvalId: id });
      return this.#settle(
        entry,
        Object.freeze({ status: 'ok', tool: entry.view.tool, actionId: entry.view.actionId, result }),
      );
    } catch (error) {
      // An approval ID from elsewhere that the guard refused: the reviewer can try again.
      if (external && EXTERNAL_APPROVAL_MISTAKES.has(guardCode(error) ?? '')) this.#undo(entry, guardCode(error));
      const outcome = outcomeFromError(error, entry.view.tool, entry.view.actionId, 'execute');
      if (outcome) return this.#settle(entry, outcome);
      quietly(() => this.#onHostError(error, entry.view));
      return this.#settle(entry, hostErrorOutcome(entry.view.tool, 'execute', entry.view.actionId));
    }
  }

  /**
   * Approves one waiting action for `approverId` and runs it. Call it only after your own
   * code has signed the reviewer in and shown them the action. `expiresAt` defaults to now plus
   * `approvalTtlMs`, capped at the task's deadline. Resolves with the outcome, which also goes
   * to any dispatcher waiting on it. Throws APPROVAL_NOT_FOUND when the action is not waiting,
   * APPROVAL_UNAVAILABLE when its backend cannot approve (use `complete()`), INVALID_OPTIONS
   * without an `approverId`, and APPROVAL_NOT_ACCEPTED (detail: the guard's code) when the guard
   * refuses the approval itself; in those cases the action stays in the queue.
   */
  async approve(actionId: string, options: { approverId: string; expiresAt?: number }): Promise<DispatchOutcome> {
    if (
      options === null ||
      typeof options !== 'object' ||
      typeof options.approverId !== 'string' ||
      options.approverId.trim() === ''
    )
      throw new AdapterError('INVALID_OPTIONS');
    const current = this.#entries.get(actionId);
    if (current?.state === 'pending' && typeof current.backend.approve !== 'function')
      throw new AdapterError('APPROVAL_UNAVAILABLE');
    const entry = this.#take(actionId);
    const approve = entry.backend.approve!.bind(entry.backend);
    const now = this.#clock();
    const deadline = entry.backend.deadline?.();
    const expiresAt =
      options.expiresAt ??
      Math.min(now + this.#ttl, typeof deadline === 'number' ? deadline : Number.POSITIVE_INFINITY);
    const approverId = options.approverId;
    return this.#run(entry, () => approve(entry.prepared, { approverId, expiresAt }), false);
  }

  /**
   * Runs a waiting action with an approval ID issued elsewhere, for example by the executor's
   * admin API. When the guard refuses that approval ID (invalid, expired, used), throws
   * APPROVAL_NOT_ACCEPTED and keeps the action waiting.
   */
  async complete(actionId: string, options: { approvalId: string }): Promise<DispatchOutcome> {
    if (options === null || typeof options !== 'object' || typeof options.approvalId !== 'string')
      throw new AdapterError('INVALID_OPTIONS');
    const entry = this.#take(actionId);
    const approvalId = options.approvalId;
    return this.#run(entry, () => approvalId, true);
  }

  /** Denies one waiting action. Nothing runs. Returns the outcome, which also goes to any waiting dispatcher. */
  reject(actionId: string): DeniedOutcome {
    const entry = this.#take(actionId);
    return this.#settle(entry, adapterDenial(entry.view.tool, 'APPROVAL_REJECTED', actionId)) as DeniedOutcome;
  }

  /**
   * Resolves with the outcome once the action is approved and run, or rejected. Resolves with
   * APPROVAL_TIMEOUT after `timeoutMs` (the action is then dropped from the queue), and with
   * APPROVAL_CANCELLED when `signal` aborts. Throws APPROVAL_NOT_FOUND for an unknown action.
   */
  waitFor(actionId: string, options: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<DispatchOutcome> {
    const entry = this.#entries.get(actionId);
    if (!entry) return Promise.reject(new AdapterError('APPROVAL_NOT_FOUND'));
    const timeoutMs = integerOption(options.timeoutMs, 0, 0, 2_147_483_647);
    if (timeoutMs === 0 && options.signal === undefined) return entry.settled;
    return new Promise<DispatchOutcome>(resolve => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const stop = (code: 'APPROVAL_TIMEOUT' | 'APPROVAL_CANCELLED') => {
        cleanup();
        if (entry.state === 'pending') {
          entry.state = 'deciding';
          resolve(this.#settle(entry, adapterDenial(entry.view.tool, code, actionId)));
        } else {
          // A decision is in progress. If it is undone, this waiter is settled then.
          if (entry.state === 'deciding') entry.expired.push(code);
          void entry.settled.then(resolve);
        }
      };
      const onAbort = () => stop('APPROVAL_CANCELLED');
      const cleanup = () => {
        if (timer !== undefined) clearTimeout(timer);
        options.signal?.removeEventListener('abort', onAbort);
      };
      if (options.signal?.aborted) return onAbort();
      options.signal?.addEventListener('abort', onAbort, { once: true });
      if (timeoutMs > 0) timer = setTimeout(() => stop('APPROVAL_TIMEOUT'), timeoutMs);
      void entry.settled.then(outcome => {
        cleanup();
        resolve(outcome);
      });
    });
  }
}

/** Options for `createDispatcher()`. */
export interface DispatcherOptions {
  /** Where actions that need a person wait. Without it, such calls are denied with APPROVAL_UNAVAILABLE. */
  approvals?: ApprovalQueue;
  /**
   * Hold the call open until a person decides, instead of returning `waiting_for_approval` at
   * once. For frameworks whose tool function must return the final result. `timeoutMs` 0 waits
   * without limit (not recommended). Default: do not wait.
   */
  waitForApproval?: { timeoutMs: number };
  /** Observes every outcome. A throwing hook is ignored. */
  onOutcome?: (outcome: DispatchOutcome, call: ToolCall) => void;
  /**
   * Receives errors thrown by host code that are not guard decisions (a broken backend, a
   * network failure to a remote executor). The model gets a HOST_ERROR outcome with no detail.
   * Default: a process warning (`process.emitWarning`).
   */
  onHostError?: (error: unknown, call: ToolCall) => void;
}

/** The one function model-facing code gets. It never exposes the guard, the task or approvals. */
export type Dispatcher = (call: ToolCall, options?: { signal?: AbortSignal }) => Promise<DispatchOutcome>;

function isBackend(value: unknown): value is GuardBackend {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as GuardBackend).prepare === 'function' &&
    typeof (value as GuardBackend).execute === 'function' &&
    !('task' in value)
  );
}

/**
 * Builds the dispatcher: every model tool call goes through prepare, an optional wait for a
 * person, and execute, and always comes back as a plain outcome. Guard and executor denials
 * become `denied` outcomes the model can read. Any other error is reported to `onHostError`
 * and becomes a HOST_ERROR outcome without detail, so host internals never reach the model
 * and one broken call never loses the other results of a model turn.
 *
 * Pass `{ guard, task }` for the core guard, or a backend from `executorBackend` or
 * `executorClientBackend`.
 */
export function createDispatcher(
  target: { guard: AgentGuard; task: TaskHandle } | GuardBackend,
  options: DispatcherOptions = {},
): Dispatcher {
  if (target === null || typeof target !== 'object') throw new AdapterError('INVALID_OPTIONS');
  const backend = isBackend(target) ? target : guardBackend(target.guard, target.task);
  if (options === null || typeof options !== 'object') throw new AdapterError('INVALID_OPTIONS');
  const { approvals, waitForApproval, onOutcome } = options;
  if (approvals !== undefined && !(approvals instanceof ApprovalQueue)) throw new AdapterError('INVALID_OPTIONS');
  if (waitForApproval !== undefined) integerOption(waitForApproval?.timeoutMs, -1, 0, 2_147_483_647);
  if (options.onHostError !== undefined && typeof options.onHostError !== 'function')
    throw new AdapterError('INVALID_OPTIONS');
  const onHostError = options.onHostError ?? defaultHostError;
  const report = (outcome: DispatchOutcome, call: ToolCall): DispatchOutcome => {
    quietly(() => onOutcome?.(outcome, call));
    return outcome;
  };
  const hostError = (error: unknown, call: ToolCall, phase: 'prepare' | 'execute', actionId?: string) => {
    quietly(() => onHostError(error, call));
    return report(hostErrorOutcome(call.name, phase, actionId), call);
  };
  return async function dispatch(call: ToolCall, callOptions: { signal?: AbortSignal } = {}) {
    if (call === null || typeof call !== 'object' || typeof call.name !== 'string')
      throw new AdapterError('INVALID_TOOL_CALL');
    const tool = call.name;
    const signal = callOptions?.signal;
    let prepared: PreparedCall;
    try {
      prepared = await backend.prepare({ tool, args: (call.input ?? {}) as Json }, signal);
    } catch (error) {
      const outcome = outcomeFromError(error, tool, undefined, 'prepare');
      if (outcome) return report(outcome, call);
      return hostError(error, call, 'prepare');
    }
    if (prepared.requiresApproval) {
      if (!approvals) return report(adapterDenial(tool, 'APPROVAL_UNAVAILABLE'), call);
      const entry = approvals.enqueue(prepared, backend);
      if (!entry) return report(adapterDenial(tool, 'APPROVAL_QUEUE_FULL'), call);
      if (!waitForApproval) return report(waitingOutcome(tool, prepared.id), call);
      const outcome = await approvals.waitFor(prepared.id, {
        timeoutMs: waitForApproval.timeoutMs,
        ...(signal === undefined ? {} : { signal }),
      });
      return report(outcome, call);
    }
    try {
      const result = await backend.execute(prepared, signal === undefined ? {} : { signal });
      return report(Object.freeze({ status: 'ok', tool, actionId: prepared.id, result }), call);
    } catch (error) {
      const outcome: DeniedOutcome | FailedOutcome | undefined = outcomeFromError(error, tool, prepared.id, 'execute');
      if (outcome) return report(outcome, call);
      return hostError(error, call, 'execute', prepared.id);
    }
  };
}
