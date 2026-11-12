/** Private trusted-worker transport. No key, database handle or capture callback is exposed by the SDK index. */
import { createHash } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { ExecutorError } from './store.js';
import type { InventoryScope, InventorySourceOptions, InventoryRegistration } from './inventory.js';
import type { InventoryManifest } from './inventory-manifest.js';
import type { InventoryMcpSourceBinding } from './inventory-mcp.js';
import { captureMcpBefore, captureMcpAfter, type McpCapture } from './inventory-mcp-capture.js';
import {
  currentLinuxThreadPriority,
  readLinuxThreadPriority,
  schedulingMode,
  schedulingUnavailable,
  type InventoryWorkerScheduling,
  type WorkerSchedulingEvidence,
} from './inventory-scheduling.js';

export interface LedgerObservation {
  readonly payload: string;
  readonly key: Uint8Array;
  readonly maxBytes: number;
  readonly witnessed: boolean;
  readonly mirror: boolean;
}
export interface ObservationMetadata {
  readonly source: InventorySourceOptions;
  readonly registrations: readonly [string, InventoryRegistration][];
  readonly referenceKey: Uint8Array | undefined;
}
export interface ObservationRequest {
  readonly scope: InventoryScope;
  readonly profile: 'core' | 'host' | 'host-mcp';
  readonly manifest?: InventoryManifest;
  readonly mcpSources?: readonly InventoryMcpSourceBinding[];
  readonly signal: AbortSignal;
  readonly deadline: number;
}
export interface SerializedObservation {
  readonly json: string;
  readonly bytes: number;
  readonly profile: 'core' | 'host' | 'host-mcp';
  readonly tenantId: string;
}
export interface WorkerObservation {
  readonly type: 'snapshot';
  readonly id: number;
  readonly ledger: LedgerObservation;
  readonly metadata: ObservationMetadata;
  readonly scope: InventoryScope;
  readonly generatedAt: number;
  readonly profile: ObservationRequest['profile'];
  readonly manifest?: InventoryManifest;
  readonly mcpBefore?: readonly McpCapture[];
}
interface LedgerEntry {
  readonly capture: () => LedgerObservation;
  readonly maxBytes: number;
  closed: boolean;
  readonly pools: Set<ObservationPool>;
}
interface ExecutorEntry {
  readonly ledger: object;
  readonly metadata: () => ObservationMetadata;
  closed: boolean;
  pool?: ObservationPool;
}
const ledgers = new WeakMap<object, LedgerEntry>(),
  executors = new WeakMap<object, ExecutorEntry>();
const MAX_JOBS = 4,
  MAX_RESULT = 8 * 1024 * 1024;
const safeErrors = new Set([
  'INVENTORY_DISABLED',
  'INVENTORY_SCOPE_INVALID',
  'INVENTORY_STATE_INVALID',
  'INVENTORY_LIMIT_EXCEEDED',
  'INVENTORY_CLOCK_INVALID',
  'INVENTORY_CONFIG_INVALID',
  'INVENTORY_MANIFEST_INVALID',
  'INVENTORY_MANIFEST_LIMIT_EXCEEDED',
  'INVENTORY_MANIFEST_SOURCE_MISMATCH',
  'INVENTORY_MANIFEST_REFERENCE_INVALID',
  'INVENTORY_SNAPSHOT_INVALID',
  'INVENTORY_MCP_INVALID',
  'INVENTORY_MCP_LIMIT_EXCEEDED',
  'INVENTORY_MCP_CONFIG_INVALID',
  'INVENTORY_SCHEDULING_UNAVAILABLE',
]);
const unavailable = () => new ExecutorError('INVENTORY_UNAVAILABLE');
function safeError(error: unknown): ExecutorError {
  return error instanceof ExecutorError && safeErrors.has(error.code) ? error : unavailable();
}
function zero(value: Uint8Array | undefined): void {
  try {
    value?.fill(0);
  } catch {
    /* Transferred buffers are already detached. */
  }
}
export function bindLedgerObservation(owner: object, maxBytes: number, capture: () => LedgerObservation): void {
  ledgers.set(owner, { capture, maxBytes, closed: false, pools: new Set() });
}
export function closeLedgerObservation(owner: object): void {
  const entry = ledgers.get(owner);
  if (!entry) return;
  entry.closed = true;
  for (const pool of entry.pools) void pool.close().catch(() => {});
}
export function bindExecutorObservation(owner: object, ledger: object, metadata: () => ObservationMetadata): void {
  executors.set(owner, { ledger, metadata, closed: false });
}
export function closeExecutorObservation(owner: object): void {
  const entry = executors.get(owner);
  if (!entry) return;
  entry.closed = true;
  void entry.pool?.close().catch(() => {});
}
interface Job {
  readonly id: number;
  readonly session: InventoryObservationSession;
  readonly request: ObservationRequest;
  readonly resolve: (value: SerializedObservation) => void;
  readonly reject: (error: ExecutorError) => void;
  readonly abort: () => void;
  readonly timer: ReturnType<typeof setTimeout>;
  settled: boolean;
  metadata?: ObservationMetadata;
  secondCapture: boolean;
  /** Digest of every input that determines the result; absent when reuse does not apply. */
  reuseKey?: string;
}
class ObservationPool {
  readonly #entry: ExecutorEntry;
  readonly #ledger: LedgerEntry;
  readonly scheduling: InventoryWorkerScheduling;
  readonly #ownerScheduling: { readonly tid: number; readonly nice: number } | undefined;
  #workerScheduling: WorkerSchedulingEvidence | undefined;
  readonly #sessions = new Set<InventoryObservationSession>();
  readonly #queue: Job[] = [];
  #worker: Worker | undefined;
  #ready = false;
  #readyPromise: Promise<void> | undefined;
  #readyResolve: (() => void) | undefined;
  #readyReject: ((error: ExecutorError) => void) | undefined;
  #startup: ReturnType<typeof setTimeout> | undefined;
  #active: Job | undefined;
  #stopping: Promise<void> | undefined;
  #closed = false;
  #sequence = 0;
  #teardownFailed = false;
  #closePromise: Promise<void> | undefined;
  readonly #reuseMs: number;
  get reuseMs(): number {
    return this.#reuseMs;
  }
  /** The last completed observation and the inputs that produced it. */
  #last: { key: string; result: SerializedObservation; at: number } | undefined;
  get closed(): boolean {
    return this.#closed;
  }
  constructor(entry: ExecutorEntry, ledger: LedgerEntry, scheduling: InventoryWorkerScheduling, reuseMs: number) {
    this.#reuseMs = reuseMs;
    this.#entry = entry;
    this.#ledger = ledger;
    this.scheduling = scheduling;
    this.#ownerScheduling = scheduling === 'linux-background' ? currentLinuxThreadPriority() : undefined;
    ledger.pools.add(this);
  }
  schedulingEvidence(): InventorySchedulingEvidence {
    if (this.#closed || this.#entry.closed || this.#ledger.closed || !this.#ready || !this.#worker)
      throw schedulingUnavailable();
    if (this.scheduling === 'default') return Object.freeze({ mode: 'default', verified: false });
    const worker = this.#workerScheduling,
      owner = this.#ownerScheduling;
    if (!worker || worker.mode !== 'linux-background' || !owner) throw schedulingUnavailable();
    const current = currentLinuxThreadPriority(),
      currentNice = readLinuxThreadPriority(worker.workerTid);
    if (current.tid !== owner.tid || current.nice !== owner.nice || currentNice !== worker.afterNice)
      throw schedulingUnavailable();
    return Object.freeze({
      ...worker,
      verified: true,
      currentNice,
      ownerTid: owner.tid,
      ownerBeforeNice: owner.nice,
      ownerCurrentNice: current.nice,
    });
  }
  async attach(session: InventoryObservationSession): Promise<void> {
    if (this.#closed || this.#entry.closed || this.#ledger.closed) throw unavailable();
    this.#sessions.add(session);
    try {
      await this.#start();
    } catch (error) {
      this.#sessions.delete(session);
      await this.close();
      throw safeError(error);
    }
  }
  #start(): Promise<void> {
    if (this.#closed) return Promise.reject(unavailable());
    if (this.#stopping) return this.#stopping.then(() => this.#start());
    if (this.#readyPromise) return this.#readyPromise;
    this.#readyPromise = new Promise<void>((resolve, reject) => {
      this.#readyResolve = resolve;
      this.#readyReject = reject;
    });
    try {
      // No inherited preload/inspector flags, environment secrets or listening port.
      const worker = new Worker(new URL('./inventory-worker.js', import.meta.url), {
        execArgv: [],
        env: {},
        stdout: true,
        stderr: true,
        workerData: { scheduling: this.scheduling },
        resourceLimits: {
          maxOldGenerationSizeMb: 128 + Math.ceil(this.#ledger.maxBytes / 1024 / 1024) * 32,
          maxYoungGenerationSizeMb: 32,
          stackSizeMb: 4,
        },
      });
      this.#worker = worker;
      worker.stdout?.resume();
      worker.stderr?.resume();
      worker.on('message', message => {
        try {
          this.#message(worker, message);
        } catch (error) {
          void this.#failWorker(worker, safeError(error));
        }
      });
      worker.on('error', () => {
        void this.#failWorker(
          worker,
          !this.#ready && this.scheduling === 'linux-background' ? schedulingUnavailable() : unavailable(),
        );
      });
      worker.on('exit', () => {
        if (this.#worker === worker) void this.#failWorker(worker);
      });
      this.#startup = setTimeout(() => {
        void this.#failWorker(worker);
      }, 5000);
      this.#startup.unref();
    } catch {
      this.#readyReject?.(unavailable());
      this.#readyReject = undefined;
    }
    return this.#readyPromise;
  }
  async #failWorker(worker: Worker, failure: ExecutorError = unavailable()): Promise<void> {
    if (this.#worker !== worker) return this.#stopping;
    this.#worker = undefined;
    this.#ready = false;
    this.#workerScheduling = undefined;
    if (this.#startup) clearTimeout(this.#startup);
    this.#startup = undefined;
    this.#readyReject?.(failure);
    this.#readyReject = undefined;
    this.#readyResolve = undefined;
    this.#readyPromise = undefined;
    const active = this.#active;
    if (active) this.#settle(active, unavailable());
    const stopping = worker.terminate().then(
      () => undefined,
      () => {
        this.#teardownFailed = true;
        this.#closed = true;
        for (const job of this.#queue.splice(0)) this.#settle(job, unavailable());
      },
    );
    this.#stopping = stopping;
    try {
      await stopping;
    } finally {
      if (this.#active === active) this.#active = undefined;
      if (this.#stopping === stopping) this.#stopping = undefined;
      if (!this.#closed) this.#pump();
    }
  }
  #settle(job: Job, error?: ExecutorError, value?: SerializedObservation): void {
    if (job.settled) return;
    job.settled = true;
    clearTimeout(job.timer);
    job.request.signal.removeEventListener('abort', job.abort);
    if (error) job.reject(error);
    else job.resolve(value!);
  }
  async detach(session: InventoryObservationSession): Promise<void> {
    this.#sessions.delete(session);
    for (const job of [...this.#queue]) if (job.session === session) this.#cancel(job, unavailable());
    if (this.#active?.session === session) this.#cancel(this.#active, unavailable());
    if (!this.#sessions.size) await this.close();
    else await this.#stopping;
  }
  enqueue(session: InventoryObservationSession, request: ObservationRequest): Promise<SerializedObservation> {
    if (this.#closed || this.#entry.closed || this.#ledger.closed || !this.#sessions.has(session))
      return Promise.reject(unavailable());
    if (!Number.isFinite(request.deadline) || request.signal.aborted || performance.now() >= request.deadline)
      return Promise.reject(new ExecutorError('REQUEST_TIMEOUT'));
    if (this.#queue.length + (this.#active ? 1 : 0) >= MAX_JOBS)
      return Promise.reject(new ExecutorError('INVENTORY_BUSY'));
    return new Promise((resolve, reject) => {
      const abort = () => this.#cancel(job, new ExecutorError('REQUEST_TIMEOUT'));
      const timer = setTimeout(abort, Math.max(1, request.deadline - performance.now()));
      timer.unref();
      const job: Job = {
        id: ++this.#sequence,
        session,
        request,
        resolve,
        reject,
        abort,
        timer,
        settled: false,
        secondCapture: false,
      };
      request.signal.addEventListener('abort', abort, { once: true });
      this.#queue.push(job);
      if (request.signal.aborted) abort();
      else this.#pump();
    });
  }
  #cancel(job: Job, error: ExecutorError): void {
    this.#settle(job, error);
    const position = this.#queue.indexOf(job);
    if (position >= 0) this.#queue.splice(position, 1);
    if (this.#active === job && this.#worker) void this.#failWorker(this.#worker);
  }
  #pump(): void {
    if (this.#closed || this.#active || this.#stopping || !this.#queue.length) return;
    if (!this.#ready) {
      void this.#start().then(
        () => this.#pump(),
        () => {
          for (const job of this.#queue.splice(0)) this.#settle(job, unavailable());
        },
      );
      return;
    }
    const job = this.#queue.shift()!;
    if (job.settled) {
      this.#pump();
      return;
    }
    this.#active = job;
    let ledger: LedgerObservation | undefined,
      metadata: ObservationMetadata | undefined,
      referenced = false;
    try {
      if (
        this.#entry.closed ||
        this.#ledger.closed ||
        job.request.signal.aborted ||
        performance.now() >= job.request.deadline
      )
        throw new ExecutorError('REQUEST_TIMEOUT');
      // Linearization point: same owner-thread turn, fresh payload+anchor and live flags.
      ledger = this.#ledger.capture();
      const generatedAt = Date.now();
      metadata = this.#entry.metadata();
      job.metadata = metadata;
      const { manifest, profile } = job.request;
      if (
        profile !== 'core' &&
        (!manifest ||
          manifest.source.tenantId !== job.request.scope.tenantId ||
          manifest.source.companyId !== metadata.source.companyId ||
          manifest.source.sourceId !== metadata.source.sourceId ||
          manifest.source.enrollmentGeneration !== metadata.source.enrollmentGeneration)
      )
        throw unavailable();
      const mcpBefore = profile === 'host-mcp' ? captureMcpBefore(manifest!, job.request.mcpSources ?? []) : undefined;
      if (job.request.signal.aborted || performance.now() >= job.request.deadline)
        throw new ExecutorError('REQUEST_TIMEOUT');
      if (this.#reuseMs > 0 && profile !== 'host-mcp') {
        const sha = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
        job.reuseKey = sha(
          JSON.stringify([
            sha(ledger.payload),
            ledger.witnessed,
            ledger.mirror,
            metadata.source,
            metadata.registrations,
            metadata.referenceKey ? sha(metadata.referenceKey) : null,
            job.request.scope,
            profile,
            manifest ?? null,
          ]),
        );
        const last = this.#last;
        if (last && last.key === job.reuseKey && performance.now() - last.at < this.#reuseMs) {
          // Identical inputs moments ago: the worker would produce the same projection.
          this.#settle(job, undefined, last.result);
          this.#active = undefined;
          this.#pump();
          return;
        }
      }
      const message: WorkerObservation = {
        type: 'snapshot',
        id: job.id,
        ledger,
        metadata,
        scope: job.request.scope,
        generatedAt,
        profile,
        ...(manifest ? { manifest } : {}),
        ...(mcpBefore ? { mcpBefore } : {}),
      };
      const transfer: ArrayBuffer[] = [ledger.key.buffer as ArrayBuffer];
      if (metadata.referenceKey) transfer.push(metadata.referenceKey.buffer as ArrayBuffer);
      this.#worker!.ref();
      referenced = true;
      this.#worker!.postMessage(message, transfer);
    } catch (error) {
      this.#settle(job, error instanceof ExecutorError && error.code === 'REQUEST_TIMEOUT' ? error : safeError(error));
      if (referenced && this.#worker) void this.#failWorker(this.#worker);
      else {
        this.#active = undefined;
        this.#pump();
      }
    } finally {
      zero(ledger?.key);
      zero(metadata?.referenceKey);
    }
  }
  #message(worker: Worker, value: unknown): void {
    if (worker !== this.#worker || this.#closed) return;
    const message = value as Record<string, unknown>;
    if (!message || typeof message !== 'object') throw unavailable();
    if (message.type === 'ready' && !this.#ready && !this.#active) {
      const evidence = message.scheduling as Record<string, unknown> | undefined;
      if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence) || evidence.mode !== this.scheduling)
        throw schedulingUnavailable();
      if (this.scheduling === 'linux-background') {
        const { workerTid, beforeNice, afterNice } = evidence;
        const owner = this.#ownerScheduling!;
        if (
          typeof workerTid !== 'number' ||
          !Number.isSafeInteger(workerTid) ||
          workerTid < 1 ||
          workerTid > 2_147_483_647 ||
          workerTid === owner.tid ||
          workerTid === process.pid ||
          typeof beforeNice !== 'number' ||
          !Number.isInteger(beforeNice) ||
          beforeNice < -20 ||
          beforeNice > 19 ||
          typeof afterNice !== 'number' ||
          afterNice !== Math.min(19, beforeNice + 5) ||
          readLinuxThreadPriority(workerTid) !== afterNice ||
          readLinuxThreadPriority(owner.tid) !== owner.nice
        )
          throw schedulingUnavailable();
        this.#workerScheduling = { mode: 'linux-background', workerTid, beforeNice, afterNice };
      } else this.#workerScheduling = { mode: 'default' };
      if (this.#startup) clearTimeout(this.#startup);
      this.#startup = undefined;
      this.#ready = true;
      this.#readyResolve?.();
      this.#readyResolve = undefined;
      this.#readyReject = undefined;
      worker.unref();
      this.#pump();
      return;
    }
    const job = this.#active;
    if (!job || message.id !== job.id) throw unavailable();
    if (
      job.settled ||
      job.request.signal.aborted ||
      performance.now() >= job.request.deadline ||
      this.#ledger.closed ||
      this.#entry.closed
    ) {
      this.#cancel(job, new ExecutorError('REQUEST_TIMEOUT'));
      return;
    }
    if (message.type === 'mcp-after' && job.request.profile === 'host-mcp' && !job.secondCapture) {
      job.secondCapture = true;
      const after = captureMcpAfter(job.request.manifest!, job.request.mcpSources ?? []);
      if (job.request.signal.aborted || performance.now() >= job.request.deadline) {
        this.#cancel(job, new ExecutorError('REQUEST_TIMEOUT'));
        return;
      }
      worker.postMessage({ type: 'mcp-after', id: job.id, after });
      return;
    }
    if (message.type === 'error') {
      const error =
        typeof message.code === 'string' && safeErrors.has(message.code)
          ? new ExecutorError(message.code)
          : unavailable();
      this.#settle(job, error);
    } else if (message.type === 'result') {
      const expected = job.metadata!.source;
      if (
        message.profile !== job.request.profile ||
        message.tenantId !== job.request.scope.tenantId ||
        message.companyId !== expected.companyId ||
        message.sourceId !== expected.sourceId ||
        message.enrollmentGeneration !== expected.enrollmentGeneration ||
        (job.request.profile === 'host-mcp' && !job.secondCapture) ||
        typeof message.json !== 'string' ||
        typeof message.bytes !== 'number' ||
        message.bytes !== Buffer.byteLength(message.json) ||
        message.bytes > MAX_RESULT ||
        typeof message.sha256 !== 'string' ||
        createHash('sha256').update(message.json).digest('hex') !== message.sha256
      )
        throw unavailable();
      const result = {
        json: message.json,
        bytes: message.bytes,
        profile: job.request.profile,
        tenantId: job.request.scope.tenantId,
      };
      if (job.reuseKey) this.#last = { key: job.reuseKey, result, at: performance.now() };
      this.#settle(job, undefined, result);
    } else throw unavailable();
    this.#active = undefined;
    worker.unref();
    this.#pump();
  }
  close(): Promise<void> {
    if (this.#closePromise) return this.#closePromise;
    this.#closed = true;
    this.#ledger.pools.delete(this);
    for (const job of this.#queue.splice(0)) this.#settle(job, unavailable());
    if (this.#active) this.#settle(this.#active, unavailable());
    const worker = this.#worker;
    const stopped = worker ? this.#failWorker(worker) : this.#stopping;
    this.#closePromise = Promise.resolve(stopped).then(() => {
      if (this.#teardownFailed) throw unavailable();
      if (this.#entry.pool === this) delete this.#entry.pool;
    });
    return this.#closePromise;
  }
}
export class InventoryObservationSession {
  readonly #pool: ObservationPool;
  #closed = false;
  #closing: Promise<void> | undefined;
  constructor(pool: ObservationPool) {
    this.#pool = pool;
  }
  async snapshot(request: ObservationRequest): Promise<SerializedObservation> {
    if (this.#closed) throw unavailable();
    return this.#pool.enqueue(this, request);
  }
  close(): Promise<void> {
    if (!this.#closing) {
      this.#closed = true;
      this.#closing = this.#pool.detach(this);
    }
    return this.#closing;
  }
}
export async function createInventoryObservationSession(
  executor: object,
  policy: InventoryWorkerScheduling = 'default',
  options: { reuseUnchangedMs?: number } = {},
): Promise<InventoryObservationSession> {
  const reuseMs = options.reuseUnchangedMs ?? 0;
  if (!Number.isSafeInteger(reuseMs) || reuseMs < 0 || reuseMs > 60_000)
    throw new ExecutorError('INVENTORY_CONFIG_INVALID');
  const scheduling = schedulingMode(policy);
  const entry = executors.get(executor),
    ledger = entry && ledgers.get(entry.ledger);
  if (!entry || !ledger || entry.closed || ledger.closed) throw unavailable();
  if (entry.pool?.closed) await entry.pool.close();
  if (entry.closed || ledger.closed) throw unavailable();
  if (entry.pool && entry.pool.scheduling !== scheduling) throw schedulingUnavailable();
  // One pool serves every listener of an executor: a second listener cannot silently run
  // with the first one's reuse window, so a different value is refused like a scheduling mismatch.
  if (entry.pool && entry.pool.reuseMs !== reuseMs)
    throw new ExecutorError('INVENTORY_CONFIG_INVALID', { detail: 'REUSE_WINDOW_MISMATCH' });
  const pool = entry.pool ?? new ObservationPool(entry, ledger, scheduling, reuseMs);
  entry.pool = pool;
  const session = new InventoryObservationSession(pool);
  await pool.attach(session);
  return session;
}

export type InventorySchedulingEvidence =
  | { readonly mode: 'default'; readonly verified: false }
  | {
      readonly mode: 'linux-background';
      readonly verified: true;
      readonly workerTid: number;
      readonly beforeNice: number;
      readonly afterNice: number;
      readonly currentNice: number;
      readonly ownerTid: number;
      readonly ownerBeforeNice: number;
      readonly ownerCurrentNice: number;
    };
/** Private local qualification metadata. Never exported by the SDK index or observer HTTP. */
export function readInventoryWorkerScheduling(executor: object): InventorySchedulingEvidence {
  const entry = executors.get(executor);
  if (!entry || entry.closed || !entry.pool) throw schedulingUnavailable();
  return entry.pool.schedulingEvidence();
}
