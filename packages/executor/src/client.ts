import type { Json, PreparedAction, TaskSnapshot } from '@shieldaai/agent-guard';
import { ExecutorError, executionStatuses, type ExecutionReceipt, type ExecutionStatus } from './store.js';
import { executorErrorStatuses, isExecutorResponseCode } from './response-code.js';

/** Task-only client. It has no administration or approval API and never follows redirects with credentials. */
export class ExecutorClient {
  readonly #endpoint: URL;
  readonly #token: string;
  readonly #fetch: typeof fetch;
  constructor(options: { endpoint: string; token: string; fetch?: typeof fetch }) {
    try {
      this.#endpoint = new URL(options.endpoint);
    } catch {
      throw new ExecutorError('CLIENT_CONFIG_INVALID');
    }
    if (
      this.#endpoint.username ||
      this.#endpoint.password ||
      this.#endpoint.hash ||
      this.#endpoint.search ||
      this.#endpoint.pathname !== '/' ||
      (this.#endpoint.protocol !== 'https:' &&
        !(this.#endpoint.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(this.#endpoint.hostname)))
    )
      throw new ExecutorError('CLIENT_CONFIG_INVALID');
    if (!/^[A-Za-z0-9_-]{43,256}$/.test(options.token)) throw new ExecutorError('CLIENT_CONFIG_INVALID');
    this.#token = options.token;
    this.#fetch = options.fetch ?? fetch;
  }
  async #call<T>(operation: string, input: unknown, signal?: AbortSignal): Promise<T> {
    const response = await this.#fetch(new URL(`/v1/task/${operation}`, this.#endpoint), {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.#token}` },
      body: JSON.stringify(input),
      redirect: 'error',
      ...(signal === undefined ? {} : { signal }),
    });
    const denied = !response.ok;
    if (
      response.redirected ||
      (denied &&
        (!executorErrorStatuses.has(response.status) ||
          response.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/json'))
    ) {
      void response.body?.cancel().catch(() => {});
      throw new ExecutorError('EXECUTOR_REQUEST_DENIED');
    }
    const limit = denied ? 1024 : 2_097_152;
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    let timedOut = false;
    const timer =
      denied && reader
        ? setTimeout(() => {
            timedOut = true;
            void reader.cancel().catch(() => {});
          }, 1000)
        : undefined;
    try {
      if (reader)
        for (;;) {
          const item = await reader.read();
          if (item.done) break;
          bytes += item.value.byteLength;
          if (bytes > limit) {
            void reader.cancel().catch(() => {});
            throw new ExecutorError(denied ? 'EXECUTOR_REQUEST_DENIED' : 'EXECUTOR_RESPONSE_LIMIT');
          }
          chunks.push(item.value);
        }
      if (timedOut) throw new ExecutorError('EXECUTOR_REQUEST_DENIED');
      let value;
      try {
        value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        throw new ExecutorError(denied ? 'EXECUTOR_REQUEST_DENIED' : 'EXECUTOR_RESPONSE_INVALID');
      }
      if (denied) {
        const error = new ExecutorError(isExecutorResponseCode(value?.error) ? value.error : 'EXECUTOR_REQUEST_DENIED');
        // Only a server-confirmed boolean is trusted; anything else means "do not retry".
        Object.defineProperty(error, 'retryable', {
          value: isExecutorResponseCode(value?.error) && value?.retryable === true,
          enumerable: true,
        });
        throw error;
      }
      return value as T;
    } finally {
      if (timer) clearTimeout(timer);
      reader?.releaseLock();
    }
  }
  prepare(tool: string, args: Json, signal?: AbortSignal): Promise<PreparedAction> {
    return this.#call('prepare', { tool, args }, signal);
  }
  async execute(actionId: string, options: { approvalId?: string; signal?: AbortSignal } = {}): Promise<Json> {
    const cancel = (): void => {
      void this.#call('cancel', { actionId }).catch(() => {});
    };
    options.signal?.throwIfAborted();
    options.signal?.addEventListener('abort', cancel, { once: true });
    try {
      return (
        await this.#call<{ value: Json }>(
          'execute',
          { actionId, ...(options.approvalId === undefined ? {} : { approvalId: options.approvalId }) },
          options.signal,
        )
      ).value;
    } finally {
      options.signal?.removeEventListener('abort', cancel);
    }
  }
  snapshot(signal?: AbortSignal): Promise<TaskSnapshot> {
    return this.#call('snapshot', {}, signal);
  }
  async execution(actionId: string, signal?: AbortSignal): Promise<ExecutionReceipt> {
    const receipt = await this.#call<ExecutionReceipt>('execution', { actionId }, signal);
    const pruned = receipt?.status === 'PRUNED';
    if (
      !receipt ||
      receipt.id !== actionId ||
      (!pruned && !executionStatuses.includes(receipt.status as ExecutionStatus)) ||
      // A PRUNED receipt carries its outcome while the compact stub is retained; later it has none,
      // and then no charge or evidence either.
      (pruned
        ? receipt.outcome === undefined
          ? receipt.charged !== undefined || receipt.reconciliation !== undefined
          : receipt.outcome !== 'SUCCEEDED' && receipt.outcome !== 'FAILED'
        : receipt.outcome !== undefined) ||
      (receipt.charged !== undefined && (!Number.isSafeInteger(receipt.charged) || receipt.charged < 0))
    )
      throw new ExecutorError('EXECUTOR_RESPONSE_INVALID');
    const evidence = receipt.reconciliation;
    if (
      evidence !== undefined &&
      (!evidence ||
        typeof evidence.referenceHash !== 'string' ||
        !/^[a-f0-9]{64}$/.test(evidence.referenceHash) ||
        !Number.isSafeInteger(evidence.time) ||
        evidence.time < 0)
    )
      throw new ExecutorError('EXECUTOR_RESPONSE_INVALID');
    return {
      id: receipt.id,
      status: receipt.status,
      ...(receipt.outcome === undefined ? {} : { outcome: receipt.outcome }),
      ...(receipt.charged === undefined ? {} : { charged: receipt.charged }),
      ...(evidence === undefined
        ? {}
        : { reconciliation: { referenceHash: evidence.referenceHash, time: evidence.time } }),
    };
  }
}
