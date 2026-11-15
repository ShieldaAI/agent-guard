import type { GuardDecision } from '@shieldaai/agent-guard';
import { AdapterError } from './errors.js';

/** A guard `onDecision` hook. */
export type DecisionHook = (event: Readonly<GuardDecision>) => void;

/** Calls every hook for each decision. A throwing hook does not stop the others. */
export function combineDecisionHooks(...hooks: readonly (DecisionHook | undefined)[]): DecisionHook {
  const list = hooks.filter((hook): hook is DecisionHook => hook !== undefined);
  if (list.some(hook => typeof hook !== 'function')) throw new AdapterError('INVALID_OPTIONS');
  return event => {
    for (const hook of list) {
      try {
        hook(event);
      } catch {
        // One broken sink must not silence the rest.
      }
    }
  };
}

/**
 * Writes each decision as one JSON line, for log shippers (Datadog, Loki, CloudWatch, ...).
 * Events carry identifiers and codes only, never arguments or results. `write` defaults to
 * standard error; `fields` are added to every line (for example the service name).
 */
export function jsonLinesDecisionLogger(
  options: {
    write?: (line: string) => void;
    clock?: () => number;
    fields?: Readonly<Record<string, string | number | boolean>>;
  } = {},
): DecisionHook {
  const write = options.write ?? ((line: string) => process.stderr.write(`${line}\n`));
  const clock = options.clock ?? Date.now;
  const fields = { ...options.fields };
  if (typeof write !== 'function' || typeof clock !== 'function') throw new AdapterError('INVALID_OPTIONS');
  return event => {
    write(
      JSON.stringify({ ...fields, time: new Date(clock()).toISOString(), event: 'agent_guard.decision', ...event }),
    );
  };
}

type Attributes = Record<string, string | number | boolean>;
/** The part of an OpenTelemetry `Meter` used here (`metrics.getMeter(...)`). */
export interface MeterLike {
  createCounter(
    name: string,
    options?: { description?: string; unit?: string },
  ): {
    add(value: number, attributes?: Attributes): void;
  };
}
/** The part of an OpenTelemetry `Span` used here. */
export interface SpanLike {
  addEvent(name: string, attributes?: Attributes): unknown;
}

/**
 * An `onDecision` hook for OpenTelemetry, without depending on it. Pass your meter for the
 * counter `agent_guard.decisions` (attributes: operation, outcome, code, tool, untrusted;
 * bounded cardinality, no identifiers), and `activeSpan: () => trace.getActiveSpan()` to add an
 * `agent_guard.decision` event to the current span. Span events also carry the task and action
 * IDs; resource, tenant, principal and approver IDs only with `includeIdentifiers: true`.
 */
export function openTelemetryDecisionHook(options: {
  meter?: MeterLike;
  activeSpan?: () => SpanLike | undefined;
  includeIdentifiers?: boolean;
}): DecisionHook {
  if (options === null || typeof options !== 'object') throw new AdapterError('INVALID_OPTIONS');
  const counter = options.meter?.createCounter('agent_guard.decisions', {
    description: 'Agent Guard authorization decisions',
    unit: '{decision}',
  });
  const activeSpan = options.activeSpan;
  const identifiers = options.includeIdentifiers === true;
  return event => {
    const attributes: Attributes = {
      'agent_guard.operation': event.operation,
      'agent_guard.outcome': event.outcome,
      'agent_guard.untrusted': event.untrusted,
    };
    if (event.code !== undefined) attributes['agent_guard.code'] = event.code;
    if (event.tool !== undefined) attributes['agent_guard.tool'] = event.tool;
    counter?.add(1, attributes);
    const span = activeSpan?.();
    if (span) {
      const detail: Attributes = { ...attributes, 'agent_guard.task_id': event.taskId };
      if (event.actionId !== undefined) detail['agent_guard.action_id'] = event.actionId;
      if (identifiers) {
        detail['agent_guard.tenant_id'] = event.tenantId;
        detail['agent_guard.principal_id'] = event.principalId;
        if (event.resourceId !== undefined) detail['agent_guard.resource_id'] = event.resourceId;
        if (event.approverId !== undefined) detail['agent_guard.approver_id'] = event.approverId;
      }
      span.addEvent('agent_guard.decision', detail);
    }
  };
}

/** Counts of decisions, as `DecisionStats.snapshot()` returns them. */
export interface DecisionStatsSnapshot {
  readonly total: number;
  readonly byOutcome: Readonly<Record<string, number>>;
  readonly byCode: Readonly<Record<string, number>>;
  readonly byTool: Readonly<Record<string, { readonly allowed: number; readonly refused: number }>>;
}

/**
 * In-memory decision counters, for a health page, a test or a quick look during a pilot.
 * Pass `stats.hook` as (or combine it into) the guard's `onDecision`.
 */
export class DecisionStats {
  #total = 0;
  #byOutcome = new Map<string, number>();
  #byCode = new Map<string, number>();
  #byTool = new Map<string, { allowed: number; refused: number }>();

  /** The hook to pass to the guard. */
  readonly hook: DecisionHook = event => {
    this.#total += 1;
    this.#byOutcome.set(event.outcome, (this.#byOutcome.get(event.outcome) ?? 0) + 1);
    if (event.code !== undefined) this.#byCode.set(event.code, (this.#byCode.get(event.code) ?? 0) + 1);
    if (event.tool !== undefined) {
      const tool = this.#byTool.get(event.tool) ?? { allowed: 0, refused: 0 };
      if (event.outcome === 'allowed' || event.outcome === 'succeeded') tool.allowed += 1;
      else tool.refused += 1;
      this.#byTool.set(event.tool, tool);
    }
  };

  snapshot(): DecisionStatsSnapshot {
    const record = <T>(map: Map<string, T>, copy: (value: T) => T) =>
      Object.freeze(Object.fromEntries([...map].map(([key, value]) => [key, copy(value)])));
    return Object.freeze({
      total: this.#total,
      byOutcome: record(this.#byOutcome, value => value),
      byCode: record(this.#byCode, value => value),
      byTool: record(this.#byTool, value => Object.freeze({ ...value })),
    });
  }

  reset(): void {
    this.#total = 0;
    this.#byOutcome.clear();
    this.#byCode.clear();
    this.#byTool.clear();
  }
}
