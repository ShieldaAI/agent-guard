import { createHmac, randomUUID } from 'node:crypto';
import { GuardError, GuardErrorCode, immutableJson } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';

export interface DecisionTraceOptions {
  /** Retained events per tenant, 1–4096. Defaults to 256. */
  maxEventsPerTenant?: number;
  /** Distinct tenant buffers per executor session, 1–256. Defaults to 64. */
  maxTenants?: number;
  /** Volatile event retention, 1–86400000 ms. Defaults to one hour. */
  retentionMs?: number;
}
export interface DecisionTraceScope { tenantId: string; taskId?: string; afterSequence?: number; limit?: number }
export type DecisionTraceEventName = 'prepare' | 'deny' | 'error' | 'review' | 'admit' | 'settle' | 'unknown' | 'cancel' | 'reconcile';
export type DecisionTraceOutcome = 'PREPARED' | 'APPROVED' | 'DENIED' | 'ERROR' | 'ADMITTED' | 'SUCCEEDED' | 'FAILED' | 'UNKNOWN' | 'CANCELLED' | 'CANCEL_REQUESTED';
export interface DecisionTraceEvent {
  readonly sequence: number;
  readonly sessionRef: string;
  readonly time: number;
  readonly event: DecisionTraceEventName;
  readonly outcome: DecisionTraceOutcome;
  readonly code: string;
  readonly tenantRef: string;
  readonly taskRef: string;
  readonly actionRef: string;
  readonly policyRevision: number;
  readonly toolRevision: number;
  readonly durationMs: number;
}
export interface DecisionTraceSnapshot {
  readonly version: 1;
  readonly sessionRef: string;
  readonly tenantRef: string;
  readonly events: readonly DecisionTraceEvent[];
  readonly nextSequence: number;
  readonly retained: number;
  readonly dropped: number;
  readonly expired: number;
  readonly exported: number;
  readonly exportFailures: number;
  readonly accepting: boolean;
}
export type DecisionTraceSink = (batch: DecisionTraceSnapshot, options: { signal: AbortSignal }) => void | Promise<void>;
export interface DecisionTraceExportResult { status: 'exported' | 'failed' | 'timeout' | 'busy' | 'empty'; count: number }

/** Internal metadata only. Never pass this object to an exporter. */
export interface TraceContext {
  tenantId: string; taskId: string; actionId: string; policyRevision: number; toolRevision: number; started: number; admitted?: boolean;
}
const codes = new Set<string>([...Object.values(GuardErrorCode),
  'OK', 'REVIEW_REQUIRED', 'REVIEW_DENIED', 'RECOVERY_UNKNOWN', 'OUTCOME_UNKNOWN', 'RECONCILED', 'OPERATION_FAILED',
  'ACTION_APPROVAL_LIMIT', 'CAPACITY_EXCEEDED', 'FAMILY_PENDING_LIMIT', 'FAMILY_PENDING_BYTES_LIMIT',
  'RECONCILIATION_INVALID', 'STORE_CAPACITY_EXCEEDED', 'STORE_CLOSED', 'STORE_CORRUPT',
  'LINEAGE_INVALID', 'PROVENANCE_LIMIT', 'MEMORY_VERSION_CHANGED', 'MEMORY_UNAVAILABLE', 'MEMORY_LIMIT',
  'FAMILY_MEMORY_LIMIT', 'EXECUTIONS_ACTIVE',
]);
export function decisionTraceCode(error: unknown): string {
  try {
    if (!(error instanceof GuardError || error instanceof ExecutorError)) return 'OPERATION_FAILED';
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const value: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    return typeof value === 'string' && codes.has(value) ? value : 'OPERATION_FAILED';
  } catch { return 'OPERATION_FAILED'; }
}
type Entry = { event: DecisionTraceEvent; created: number };
type Bucket = { entries: Entry[]; sequence: number; dropped: number; expired: number; exported: number; failures: number; busy: boolean; controller?: AbortController };
const safeInteger = (value: unknown, min: number, max: number): value is number => Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
const events = new Set<DecisionTraceEventName>(['prepare', 'deny', 'error', 'review', 'admit', 'settle', 'unknown', 'cancel', 'reconcile']);
const outcomes = new Set<DecisionTraceOutcome>(['PREPARED', 'APPROVED', 'DENIED', 'ERROR', 'ADMITTED', 'SUCCEEDED', 'FAILED', 'UNKNOWN', 'CANCELLED', 'CANCEL_REQUESTED']);
function identifier(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value.trim() || value.length > 4096 || value.includes('\0')) throw new ExecutorError('TRACE_SCOPE_INVALID');
}

/** Volatile, bounded observation. No external callback runs when record() is called. */
export class DecisionTraces {
  readonly #key: Buffer;
  readonly #session = randomUUID();
  readonly #buckets = new Map<string, Bucket>();
  readonly #capacity: number;
  readonly #tenants: number;
  readonly #retention: number;
  #closed = false;
  #tenantCapacityDrops = 0;
  constructor(options: DecisionTraceOptions, key: Uint8Array, instanceId: string) {
    let config: DecisionTraceOptions;
    try { config = immutableJson(options, 2, 16, 2048) as DecisionTraceOptions; }
    catch { throw new ExecutorError('TRACE_CONFIG_INVALID'); }
    if (!config || typeof config !== 'object' || Array.isArray(config) ||
        Object.keys(config).some(name => !['maxEventsPerTenant', 'maxTenants', 'retentionMs'].includes(name))) throw new ExecutorError('TRACE_CONFIG_INVALID');
    this.#capacity = config.maxEventsPerTenant ?? 256;
    this.#tenants = config.maxTenants ?? 64;
    this.#retention = config.retentionMs ?? 3_600_000;
    if (!safeInteger(this.#capacity, 1, 4096) || !safeInteger(this.#tenants, 1, 256) || !safeInteger(this.#retention, 1, 86_400_000)) throw new ExecutorError('TRACE_CONFIG_INVALID');
    this.#key = createHmac('sha256', key).update('agent-guard-decision-traces-v1\0').update(instanceId).digest();
  }
  #reference(domain: string, tenant: string, value = ''): string {
    return createHmac('sha256', this.#key).update(JSON.stringify([domain, tenant, value])).digest('base64url');
  }
  #prune(bucket: Bucket): void {
    const cutoff = performance.now() - this.#retention;
    while (bucket.entries[0] && bucket.entries[0].created <= cutoff) { bucket.entries.shift(); bucket.expired++; }
  }
  record(context: TraceContext, event: DecisionTraceEventName, outcome: DecisionTraceOutcome, code = 'OK'): void {
    if (this.#closed) return;
    if (!events.has(event) || !outcomes.has(outcome) || !safeInteger(context.policyRevision, 0, Number.MAX_SAFE_INTEGER) ||
        !safeInteger(context.toolRevision, 0, Number.MAX_SAFE_INTEGER)) return;
    const tenantRef = this.#reference('tenant', context.tenantId);
    let bucket = this.#buckets.get(tenantRef);
    if (!bucket) {
      if (this.#buckets.size >= this.#tenants) { this.#tenantCapacityDrops++; return; }
      bucket = { entries: [], sequence: 0, dropped: 0, expired: 0, exported: 0, failures: 0, busy: false };
      this.#buckets.set(tenantRef, bucket);
    }
    this.#prune(bucket);
    while (bucket.entries.length >= this.#capacity) { bucket.entries.shift(); bucket.dropped++; }
    const value: DecisionTraceEvent = Object.freeze({
      sequence: ++bucket.sequence, sessionRef: this.#session, time: Date.now(), event, outcome,
      code: codes.has(code) ? code : 'OPERATION_FAILED', tenantRef,
      taskRef: this.#reference('task', context.tenantId, context.taskId),
      actionRef: this.#reference('action', context.tenantId, context.actionId),
      policyRevision: context.policyRevision, toolRevision: context.toolRevision,
      durationMs: Math.round(Math.max(0, Math.min(86_400_000, performance.now() - context.started)) * 1000) / 1000,
    });
    bucket.entries.push({ event: value, created: performance.now() });
  }
  snapshot(scope: DecisionTraceScope): DecisionTraceSnapshot {
    if (this.#closed) throw new ExecutorError('TRACE_CLOSED');
    const input = immutableJson(scope, 2, 16, 20_000) as unknown as DecisionTraceScope;
    if (!input || typeof input !== 'object' || Array.isArray(input) ||
        Object.keys(input).some(name => !['tenantId', 'taskId', 'afterSequence', 'limit'].includes(name))) throw new ExecutorError('TRACE_SCOPE_INVALID');
    identifier(input.tenantId);
    if (input.taskId !== undefined) identifier(input.taskId);
    const after = input.afterSequence ?? 0, limit = input.limit ?? this.#capacity;
    if (!safeInteger(after, 0, Number.MAX_SAFE_INTEGER) || !safeInteger(limit, 1, this.#capacity)) throw new ExecutorError('TRACE_SCOPE_INVALID');
    const tenantRef = this.#reference('tenant', input.tenantId);
    const bucket = this.#buckets.get(tenantRef);
    if (bucket) this.#prune(bucket);
    const taskRef = input.taskId === undefined ? undefined : this.#reference('task', input.tenantId, input.taskId);
    const selected = (bucket?.entries ?? []).filter(({ event }) => event.sequence > after && (taskRef === undefined || event.taskRef === taskRef));
    const events = selected.slice(0, limit).map(entry => entry.event);
    return Object.freeze({ version: 1, sessionRef: this.#session, tenantRef, events: Object.freeze(events),
      nextSequence: events.at(-1)?.sequence ?? after, retained: selected.length,
      dropped: bucket?.dropped ?? 0, expired: bucket?.expired ?? 0, exported: bucket?.exported ?? 0,
      exportFailures: bucket?.failures ?? 0, accepting: Boolean(bucket) });
  }
  statistics(): Readonly<{ tenantCapacityDrops: number; tenants: number }> {
    if (this.#closed) throw new ExecutorError('TRACE_CLOSED');
    return Object.freeze({ tenantCapacityDrops: this.#tenantCapacityDrops, tenants: this.#buckets.size });
  }
  async export(scope: { tenantId: string }, sink: DecisionTraceSink, options: { timeoutMs?: number } = {}): Promise<DecisionTraceExportResult> {
    const selected = immutableJson(scope, 2, 8, 20_000) as unknown as { tenantId: string };
    const settings = immutableJson(options, 2, 8, 2048) as { timeoutMs?: number };
    if (!selected || Object.keys(selected).some(key => key !== 'tenantId') || typeof sink !== 'function' ||
        !settings || Object.keys(settings).some(key => key !== 'timeoutMs')) throw new ExecutorError('TRACE_SCOPE_INVALID');
    const timeoutMs = settings.timeoutMs ?? 5000;
    if (!safeInteger(timeoutMs, 1, 60_000)) throw new ExecutorError('TRACE_CONFIG_INVALID');
    const batch = this.snapshot(selected);
    const bucket = this.#buckets.get(batch.tenantRef);
    if (bucket?.busy) return { status: 'busy', count: 0 };
    if (!bucket || batch.events.length === 0) return { status: 'empty', count: 0 };
    bucket.busy = true;
    const controller = new AbortController();
    bucket.controller = controller;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let settled = false, timedOut = false;
    const release = (): void => { bucket.busy = false; delete bucket.controller; };
    // Only this explicitly invoked host operation can call the sink. Recording never does.
    const operation = Promise.resolve().then(() => sink(batch, { signal: controller.signal }))
      .then(() => 'exported' as const, () => 'failed' as const).finally(() => { settled = true; if (timedOut) release(); });
    const timeout = new Promise<'timeout'>(resolve => { timer = setTimeout(() => { controller.abort(); resolve('timeout'); }, timeoutMs); });
    let status = await Promise.race([operation, timeout]);
    if (timer) clearTimeout(timer);
    if (status === 'timeout') { timedOut = true; if (settled) release(); }
    else release();
    if (this.#closed) status = 'failed';
    if (status !== 'exported') { bucket.failures++; return { status, count: 0 }; }
    const through = batch.events.at(-1)!.sequence;
    bucket.entries = bucket.entries.filter(entry => entry.event.sequence > through);
    bucket.exported += batch.events.length;
    return { status: 'exported', count: batch.events.length };
  }
  close(): void { this.#closed = true; for (const bucket of this.#buckets.values()) bucket.controller?.abort(); this.#buckets.clear(); this.#key.fill(0); }
}
