import { GuardError } from './types.js';
import type { Action, Policy, TaskSnapshot } from './types.js';

const MAX_PENDING = 64;
const MAX_PENDING_PER_FAMILY = 8;
const MAX_WAIT_MS = 30_000;

type Pending = { familyId: string; taskIds: readonly string[]; controller: AbortController };

/** One pool per executor, shared by preparations and executions, including delegated tasks. */
export class PolicyAdmission {
  #pending = new Set<Pending>();
  readonly #maxPending: number;
  readonly #maxPerFamily: number;
  readonly #maxWaitMs: number;

  constructor(limits: { maxPending?: number; maxPendingPerFamily?: number; maxWaitMs?: number } = {}) {
    this.#maxPending = limits.maxPending ?? MAX_PENDING;
    this.#maxPerFamily = limits.maxPendingPerFamily ?? MAX_PENDING_PER_FAMILY;
    this.#maxWaitMs = limits.maxWaitMs ?? MAX_WAIT_MS;
  }

  assertCapacity(familyId: string): void {
    if (
      this.#pending.size >= this.#maxPending ||
      [...this.#pending].filter(entry => entry.familyId === familyId).length >= this.#maxPerFamily
    ) {
      throw new GuardError('POLICY_BUSY');
    }
  }

  async evaluate(
    policy: Policy,
    action: Readonly<Action>,
    snapshot: Readonly<TaskSnapshot>,
    scope: { familyId: string; taskIds: readonly string[]; remainingMs: number },
  ): Promise<'allow' | 'require_approval'> {
    if (!Number.isFinite(scope.remainingMs) || scope.remainingMs <= 0) throw new GuardError('TASK_EXPIRED');
    this.assertCapacity(scope.familyId);
    const controller = new AbortController();
    const entry = { familyId: scope.familyId, taskIds: scope.taskIds, controller };
    this.#pending.add(entry);
    const deadlineFirst = scope.remainingMs <= this.#maxWaitMs;
    const timeoutCode = deadlineFirst ? 'TASK_EXPIRED' : 'POLICY_TIMEOUT';
    const waitMs = Math.min(scope.remainingMs, this.#maxWaitMs);
    const expires = performance.now() + waitMs;
    const timer = setTimeout(() => controller.abort(new GuardError(timeoutCode)), waitMs);
    let rejectWait!: (reason: unknown) => void;
    const canceled = new Promise<never>((_resolve, reject) => {
      rejectWait = reject;
    });
    const onAbort = () => rejectWait(controller.signal.reason);
    controller.signal.addEventListener('abort', onAbort, { once: true });
    const operation = (async () => {
      try {
        return await policy(action, snapshot, Object.freeze({ signal: controller.signal }));
      } catch {
        throw new GuardError('POLICY_ERROR');
      } finally {
        // A callback that ignores cancellation still occupies its original slot.
        this.#pending.delete(entry);
      }
    })();
    try {
      const decision = await Promise.race([canceled, operation]);
      if (performance.now() >= expires) throw new GuardError(timeoutCode);
      if (decision === 'deny') throw new GuardError('POLICY_DENIED');
      if (decision !== 'allow' && decision !== 'require_approval') throw new GuardError('POLICY_ERROR');
      return decision;
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener('abort', onAbort);
    }
  }

  revokeTask(taskId: string): void {
    for (const entry of this.#pending) {
      if (entry.taskIds.includes(taskId)) entry.controller.abort(new GuardError('TASK_REVOKED'));
    }
  }

  invalidate(reason: 'TASK_REVOKED' | 'POLICY_CHANGED'): void {
    for (const entry of this.#pending) entry.controller.abort(new GuardError(reason));
  }
}
