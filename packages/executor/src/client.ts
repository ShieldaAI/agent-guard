import type { Json, PreparedAction, TaskSnapshot } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';

/** Task-only client. It has no administration or approval API and never follows redirects with credentials. */
export class ExecutorClient {
  readonly #endpoint: URL;
  readonly #token: string;
  readonly #fetch: typeof fetch;
  constructor(options: { endpoint: string; token: string; fetch?: typeof fetch }) {
    this.#endpoint = new URL(options.endpoint);
    if (this.#endpoint.username || this.#endpoint.password || this.#endpoint.hash || this.#endpoint.search ||
        this.#endpoint.pathname !== '/' || (this.#endpoint.protocol !== 'https:' &&
        !(this.#endpoint.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(this.#endpoint.hostname)))) throw new ExecutorError('CLIENT_CONFIG_INVALID');
    if (!/^[A-Za-z0-9_-]{43,256}$/.test(options.token)) throw new ExecutorError('CLIENT_CONFIG_INVALID');
    this.#token = options.token; this.#fetch = options.fetch ?? fetch;
  }
  async #call<T>(operation: string, input: unknown, signal?: AbortSignal): Promise<T> {
    const response = await this.#fetch(new URL(`/v1/task/${operation}`, this.#endpoint), {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${this.#token}` },
      body: JSON.stringify(input), redirect: 'error', ...(signal === undefined ? {} : { signal }),
    });
    if (response.redirected || response.status >= 300) { await response.body?.cancel(); throw new ExecutorError('EXECUTOR_REQUEST_DENIED'); }
    const reader = response.body?.getReader(); const chunks: Uint8Array[] = []; let bytes = 0;
    try {
      if (reader) for (;;) {
        const item = await reader.read(); if (item.done) break;
        bytes += item.value.byteLength;
        if (bytes > 2_097_152) { await reader.cancel(); throw new ExecutorError('EXECUTOR_RESPONSE_LIMIT'); }
        chunks.push(item.value);
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T;
    } finally { reader?.releaseLock(); }
  }
  prepare(tool: string, args: Json, signal?: AbortSignal): Promise<PreparedAction> { return this.#call('prepare', { tool, args }, signal); }
  async execute(actionId: string, options: { approvalId?: string; signal?: AbortSignal } = {}): Promise<Json> {
    const cancel = (): void => { void this.#call('cancel', { actionId }).catch(() => {}); };
    options.signal?.throwIfAborted(); options.signal?.addEventListener('abort', cancel, { once: true });
    try { return (await this.#call<{ value: Json }>('execute', { actionId, ...(options.approvalId === undefined ? {} : { approvalId: options.approvalId }) }, options.signal)).value; }
    finally { options.signal?.removeEventListener('abort', cancel); }
  }
  snapshot(signal?: AbortSignal): Promise<TaskSnapshot> { return this.#call('snapshot', {}, signal); }
}
