import { StreamableHTTPClientTransport, type FetchLike, type Transport } from '@modelcontextprotocol/client';
import { McpBoundaryError } from './boundary.js';

export interface RestrictedMcpHttpOptions {
  endpoint: string;
  /** Trusted executor fetch; it must enforce DNS/IP/egress policy at connection time. */
  fetch: FetchLike;
  /** Pre-issued, audience-bound credentials from the trusted host. Never model-supplied. */
  headers?: Readonly<Record<string, string>>;
  allowInsecureLoopback?: boolean;
  maxResponseBytes?: number;
}

/**
 * Maintained SDK transport with an exact endpoint, no redirects, no automatic OAuth,
 * no reconnection retries, and bounded response streams. OAuth/issuer/audience checks
 * and DNS/IP pinning belong to the trusted credential provider and executor.
 */
export function createRestrictedMcpHttpTransport(options: RestrictedMcpHttpOptions): Transport {
  const endpoint = new URL(options.endpoint);
  const loopback = ['127.0.0.1', '[::1]'].includes(endpoint.hostname);
  if (endpoint.username || endpoint.password || endpoint.hash ||
      (endpoint.protocol !== 'https:' && !(options.allowInsecureLoopback === true && loopback && endpoint.protocol === 'http:'))) throw new McpBoundaryError('ENDPOINT_DENIED');
  const maxBytes = options.maxResponseBytes ?? 1_048_576;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 16_777_216) throw new McpBoundaryError('INVALID_CONFIGURATION');
  const approved = endpoint.href;
  const network = options.fetch;
  if (typeof network !== 'function') throw new McpBoundaryError('INVALID_CONFIGURATION');
  const restricted: FetchLike = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.href !== approved) throw new McpBoundaryError('ENDPOINT_DENIED');
    const response = await network(input, { ...init, redirect: 'error' });
    if (response.redirected || (response.status >= 300 && response.status < 400) || (response.url && response.url !== approved)) {
      await response.body?.cancel(); throw new McpBoundaryError('REDIRECT_DENIED');
    }
    const declared = response.headers.get('content-length');
    if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > maxBytes)) {
      await response.body?.cancel(); throw new McpBoundaryError('RESPONSE_LIMIT');
    }
    if (!response.body) return response;
    let received = 0;
    const bounded = response.body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        received += chunk.byteLength;
        if (received > maxBytes) { controller.error(new McpBoundaryError('RESPONSE_LIMIT')); return; }
        controller.enqueue(chunk);
      },
    }));
    return new Response(bounded, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
  return new StreamableHTTPClientTransport(endpoint, {
    fetch: restricted, requestInit: { headers: { ...options.headers }, redirect: 'error' },
    redirectPolicy: 'same-origin',
    reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1_000, maxReconnectionDelay: 1_000, reconnectionDelayGrowFactor: 1 },
  });
}
