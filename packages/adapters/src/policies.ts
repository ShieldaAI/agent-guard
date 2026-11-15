import type { Action, Policy, PolicyDecision, TaskSnapshot } from '@shieldaai/agent-guard';
import { AdapterError } from './errors.js';

/** A synchronous test on an action and the task's state. */
export type ActionPredicate = (action: Readonly<Action>, task: Readonly<TaskSnapshot>) => boolean;

const RANK: Readonly<Record<PolicyDecision, number>> = { allow: 0, require_approval: 1, deny: 2 };

function names(list: readonly string[]): ReadonlySet<string> {
  if (!Array.isArray(list) || list.some(name => typeof name !== 'string' || name.length === 0))
    throw new AdapterError('INVALID_OPTIONS');
  return new Set(list);
}
function predicate(test: ActionPredicate): ActionPredicate {
  if (typeof test !== 'function') throw new AdapterError('INVALID_OPTIONS');
  return test;
}

/**
 * Runs each policy in order and returns the most restrictive answer: deny over
 * require_approval over allow. Stops at the first deny. Any policy that throws or answers
 * something else fails the call with POLICY_ERROR, as the guard does for a single policy.
 */
export function combinePolicies(...policies: readonly Policy[]): Policy {
  if (policies.some(policy => typeof policy !== 'function')) throw new AdapterError('INVALID_OPTIONS');
  const list = [...policies];
  return async (action, task, context) => {
    let result: PolicyDecision = 'allow';
    for (const policy of list) {
      context?.signal.throwIfAborted();
      const decision: unknown = await policy(action, task, context);
      if (typeof decision !== 'string' || !Object.hasOwn(RANK, decision))
        throw new AdapterError('INVALID_OPTIONS', 'POLICY_ANSWER');
      if (RANK[decision as PolicyDecision] > RANK[result]) result = decision as PolicyDecision;
      if (result === 'deny') break;
    }
    return result;
  };
}

/** Denies every call that matches. */
export function denyWhen(test: ActionPredicate): Policy {
  const check = predicate(test);
  return (action, task) => (check(action, task) ? 'deny' : 'allow');
}

/** Requires a person's approval for every call that matches. */
export function requireApprovalWhen(test: ActionPredicate): Policy {
  const check = predicate(test);
  return (action, task) => (check(action, task) ? 'require_approval' : 'allow');
}

/** Denies the named tools, for example while an incident is open, without unregistering them. */
export function denyTools(tools: readonly string[]): Policy {
  const set = names(tools);
  return action => (set.has(action.tool) ? 'deny' : 'allow');
}

/** Requires a person's approval for the named tools, on top of their own `requiresApproval`. */
export function requireApprovalForTools(tools: readonly string[]): Policy {
  const set = names(tools);
  return action => (set.has(action.tool) ? 'require_approval' : 'allow');
}

/** Requires a person's approval for every call whose resolver marked it `external`. */
export function requireApprovalForExternal(): Policy {
  return action => (action.external === true ? 'require_approval' : 'allow');
}

/**
 * Requires a person's approval for every call once the task family has read outside content,
 * except the tools listed in `except` (typically read-only tools). A blunter, task-wide version
 * of the per-tool `untrustedContext` setting.
 */
export function requireApprovalAfterUntrusted(options: { except?: readonly string[] } = {}): Policy {
  const except = names(options?.except ?? []);
  return (action, task) => (task.untrusted && !except.has(action.tool) ? 'require_approval' : 'allow');
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

/**
 * Allows calls only inside a weekly time window in one time zone; outside it, calls are denied
 * or need approval. `days` uses 0 for Sunday through 6 for Saturday; `from` and `to` are hours
 * 0-24 with `from` inclusive and `to` exclusive. `tools` limits the rule to those tools.
 * The time comes from `clock`, which must match the guard's clock (default `Date.now`).
 */
export function withinHours(options: {
  timeZone: string;
  days?: readonly number[];
  from: number;
  to: number;
  outside?: 'deny' | 'require_approval';
  tools?: readonly string[];
  clock?: () => number;
}): Policy {
  if (options === null || typeof options !== 'object') throw new AdapterError('INVALID_OPTIONS');
  const { timeZone, from, to } = options;
  if (typeof timeZone !== 'string' || timeZone.length === 0) throw new AdapterError('INVALID_OPTIONS', 'TIME_ZONE');
  const days = new Set(options.days ?? [1, 2, 3, 4, 5]);
  const outside = options.outside ?? 'deny';
  if (
    ![from, to].every(hour => Number.isInteger(hour) && hour >= 0 && hour <= 24) ||
    from >= to ||
    [...days].some(day => !Number.isInteger(day) || day < 0 || day > 6) ||
    (outside !== 'deny' && outside !== 'require_approval')
  )
    throw new AdapterError('INVALID_OPTIONS');
  let format: Intl.DateTimeFormat;
  try {
    format = new Intl.DateTimeFormat('en-US', { timeZone, weekday: 'short', hour: 'numeric', hourCycle: 'h23' });
  } catch {
    throw new AdapterError('INVALID_OPTIONS', 'TIME_ZONE');
  }
  const tools = options.tools === undefined ? undefined : names(options.tools);
  const clock = options.clock ?? Date.now;
  return action => {
    if (tools && !tools.has(action.tool)) return 'allow';
    const parts = format.formatToParts(clock());
    const day = WEEKDAYS.indexOf(parts.find(part => part.type === 'weekday')?.value ?? '');
    const hour = Number(parts.find(part => part.type === 'hour')?.value);
    return days.has(day) && hour >= from && hour < to ? 'allow' : outside;
  };
}
