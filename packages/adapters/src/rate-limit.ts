import type { Action, GuardDecision, Policy, TaskSnapshot } from '@shieldaai/agent-guard';
import { AdapterError } from './errors.js';
import type { DecisionHook } from './observability.js';

/** One rule for `RateLimiter`. */
export interface RateLimitRule {
  /** The tools the rule counts. Omit to count every tool. */
  tools?: readonly string[];
  /** Most dispatched calls in one window, per key. Integer 1-1,000,000. */
  max: number;
  /** Window length in milliseconds (a sliding window). Integer 1,000-86,400,000. */
  windowMs: number;
  /**
   * What the limit is shared by: `'tenant'`, `'principal'` or `'global'` (default `'tenant'`).
   * Unlike a task budget, the count is shared by every task with the same key.
   */
  per?: 'tenant' | 'principal' | 'global';
  /** What a call over the limit gets. Default `'deny'`. */
  over?: 'deny' | 'require_approval';
}

type Compiled = Required<Omit<RateLimitRule, 'tools'>> & { tools: ReadonlySet<string> | undefined; index: number };

/**
 * Limits how often tools run across tasks, in one process: for example at most 20 emails per
 * tenant per hour, however many tasks the tenant starts. Pass `limiter.policy` as (or into)
 * the guard's `policy`, and `limiter.hook` as (or into) its `onDecision`.
 *
 * Calls are counted when the guard dispatches them (an `execute` decision that `succeeded`
 * or `failed`), so a denied call never uses the allowance. The check happens before dispatch,
 * so calls that are already past the check when the limit is reached still run: the count can
 * exceed `max` by at most the number of calls in flight for that key. Counts live in memory
 * and are not shared between processes.
 */
export class RateLimiter {
  readonly #rules: readonly Compiled[];
  readonly #clock: () => number;
  /** Rule index and key to dispatch times, oldest first. */
  readonly #hits = new Map<string, number[]>();
  readonly #maxKeys: number;

  constructor(rules: readonly RateLimitRule[], options: { clock?: () => number; maxKeys?: number } = {}) {
    if (!Array.isArray(rules) || rules.length === 0) throw new AdapterError('INVALID_OPTIONS');
    this.#rules = rules.map((rule, index) => {
      const per = rule?.per ?? 'tenant';
      const over = rule?.over ?? 'deny';
      if (
        !Number.isSafeInteger(rule?.max) ||
        rule.max < 1 ||
        rule.max > 1_000_000 ||
        !Number.isSafeInteger(rule.windowMs) ||
        rule.windowMs < 1_000 ||
        rule.windowMs > 86_400_000 ||
        !['tenant', 'principal', 'global'].includes(per) ||
        !['deny', 'require_approval'].includes(over) ||
        (rule.tools !== undefined &&
          (!Array.isArray(rule.tools) || rule.tools.some((tool: unknown) => typeof tool !== 'string')))
      )
        throw new AdapterError('INVALID_OPTIONS');
      return {
        max: rule.max,
        windowMs: rule.windowMs,
        per,
        over,
        index,
        tools: rule.tools ? new Set(rule.tools) : undefined,
      };
    });
    this.#clock = options.clock ?? Date.now;
    this.#maxKeys = options.maxKeys ?? 100_000;
    if (typeof this.#clock !== 'function' || !Number.isSafeInteger(this.#maxKeys) || this.#maxKeys < 1)
      throw new AdapterError('INVALID_OPTIONS');
  }

  #key(rule: Compiled, tenantId: string, principalId: string): string {
    const scope = rule.per === 'global' ? '' : rule.per === 'tenant' ? tenantId : `${tenantId}\u0000${principalId}`;
    return `${rule.index}\u0000${scope}`;
  }
  #recent(key: string, windowMs: number, now: number): number[] {
    const hits = this.#hits.get(key);
    if (!hits) return [];
    while (hits.length > 0 && hits[0]! <= now - windowMs) hits.shift();
    if (hits.length === 0) this.#hits.delete(key);
    return hits;
  }
  #applies(rule: Compiled, tool: string): boolean {
    return rule.tools === undefined || rule.tools.has(tool);
  }

  /** The policy: answers `over` for a call whose key has used its allowance in the window. */
  readonly policy: Policy = (action: Readonly<Action>, task: Readonly<TaskSnapshot>) => {
    const now = this.#clock();
    let answer: 'allow' | 'deny' | 'require_approval' = 'allow';
    for (const rule of this.#rules) {
      if (!this.#applies(rule, action.tool)) continue;
      if (this.#recent(this.#key(rule, task.tenantId, task.principalId), rule.windowMs, now).length >= rule.max) {
        if (rule.over === 'deny') return 'deny';
        answer = 'require_approval';
      }
    }
    return answer;
  };

  /** The decision hook: counts each dispatched call. */
  readonly hook: DecisionHook = (event: Readonly<GuardDecision>) => {
    if (event.operation !== 'execute' || (event.outcome !== 'succeeded' && event.outcome !== 'failed')) return;
    if (event.tool === undefined) return;
    const now = this.#clock();
    for (const rule of this.#rules) {
      if (!this.#applies(rule, event.tool)) continue;
      const key = this.#key(rule, event.tenantId, event.principalId);
      const hits = this.#recent(key, rule.windowMs, now);
      if (hits.length === 0) {
        if (this.#hits.size >= this.#maxKeys) {
          // Bounded memory: forget the oldest key. This can only loosen a limit, never deny wrongly.
          const oldest = this.#hits.keys().next().value;
          if (oldest !== undefined) this.#hits.delete(oldest);
        }
        this.#hits.set(key, [now]);
      } else hits.push(now);
    }
  };

  /** Calls counted in the current window for one rule and key, for dashboards and tests. */
  usage(ruleIndex: number, scope: { tenantId?: string; principalId?: string } = {}): number {
    const rule = this.#rules[ruleIndex];
    if (!rule) throw new AdapterError('INVALID_OPTIONS');
    return this.#recent(this.#key(rule, scope.tenantId ?? '', scope.principalId ?? ''), rule.windowMs, this.#clock())
      .length;
  }
}
