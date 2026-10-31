import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { lookup } from 'node:dns';
import { isIP, type LookupFunction } from 'node:net';
import ipaddr from 'ipaddr.js';
import { ExecutorError } from './store.js';

export interface NetworkPolicy {
  allowedOrigins: readonly string[];
  /** Exact operator-approved origins only; permits private addresses and HTTP on those origins. */
  allowPrivateOrigins?: readonly string[];
  maxResponseBytes?: number;
  maxRequestBytes?: number;
  timeoutMs?: number;
}
export function isPublicAddress(address: string): boolean {
  try { return ipaddr.process(address).range() === 'unicast'; } catch { return false; }
}
/** Policy is checked by the actual socket lookup. No proxy environment variables or redirects are used. */
export function createRestrictedFetch(policy: NetworkPolicy): typeof fetch {
  const origins = new Set(policy.allowedOrigins);
  const privateOrigins = new Set(policy.allowPrivateOrigins ?? []);
  const maxResponse = policy.maxResponseBytes ?? 1_048_576;
  const maxRequest = policy.maxRequestBytes ?? 262_144;
  const timeout = policy.timeoutMs ?? 20_000;
  for (const n of [maxResponse, maxRequest, timeout]) if (!Number.isSafeInteger(n) || n < 1) throw new ExecutorError('NETWORK_CONFIG_INVALID');
  for (const origin of [...origins, ...privateOrigins]) {
    const url = new URL(origin);
    if (url.origin !== origin || !['http:', 'https:'].includes(url.protocol) || !origins.has(origin)) throw new ExecutorError('NETWORK_CONFIG_INVALID');
  }
  return async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const allowPrivate = privateOrigins.has(url.origin);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (!origins.has(url.origin) || url.username || url.password || url.hash ||
        (url.protocol !== 'https:' && !(allowPrivate && url.protocol === 'http:')) ||
        (!allowPrivate && ((isIP(host) && !isPublicAddress(host)) || host === 'localhost' || host.endsWith('.localhost')))) throw new ExecutorError('DESTINATION_DENIED');
    const controller = new AbortController();
    const signal = AbortSignal.any([request.signal, controller.signal]);
    const timer = setTimeout(() => controller.abort(), timeout); timer.unref();
    const chunks: Uint8Array[] = []; let requestSize = 0;
    const reader = request.body?.getReader();
    const cancelReader = (): void => { void reader?.cancel().catch(() => {}); };
    signal.addEventListener('abort', cancelReader, { once: true });
    try {
      if (reader) for (;;) {
        if (signal.aborted) throw new ExecutorError('REQUEST_ABORTED');
        const item = await reader.read();
        if (item.done) break;
        requestSize += item.value.byteLength;
        if (requestSize > maxRequest) { await reader.cancel(); throw new ExecutorError('REQUEST_TOO_LARGE'); }
        chunks.push(item.value);
      }
      if (signal.aborted) throw new ExecutorError('REQUEST_ABORTED');
    } catch (error) { clearTimeout(timer); throw error; }
    finally { signal.removeEventListener('abort', cancelReader); reader?.releaseLock(); }
    const headers: Record<string, string> = {};
    for (const [key, value] of request.headers) {
      if (['host', 'connection', 'transfer-encoding', 'content-length', 'upgrade', 'proxy-authorization', 'proxy-connection', 'accept-encoding'].includes(key)) continue;
      headers[key] = value;
    }
    headers['accept-encoding'] = 'identity';
    if (requestSize) headers['content-length'] = String(requestSize);
    const secureLookup: LookupFunction = (hostname, opts, callback) => {
      lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
        if (error || !addresses.length) { callback(new ExecutorError('DNS_FAILED'), '', 4); return; }
        if (!allowPrivate && addresses.some(item => !isPublicAddress(item.address))) { callback(new ExecutorError('DESTINATION_DENIED'), '', 4); return; }
        if (opts.all) callback(null, addresses); else callback(null, addresses[0]!.address, addresses[0]!.family);
      });
    };
    return new Promise<Response>((resolve, reject) => {
      const req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: request.method, headers, lookup: secureLookup, agent: false, signal,
      }, res => {
        try {
          const status = res.statusCode ?? 502;
          // Node accepts three-digit statuses outside the Fetch Response range.
          // This callback runs after the Promise executor, so construction errors need an explicit boundary.
          if (!Number.isInteger(status) || status < 200 || status > 599) throw new ExecutorError('RESPONSE_INVALID');
          const length = res.headers['content-length'];
          if ((status >= 300 && status < 400) || (length !== undefined && (!/^\d+$/.test(length) || Number(length) > maxResponse)) ||
              (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity')) {
            clearTimeout(timer); res.destroy(); req.destroy();
            reject(new ExecutorError(status >= 300 && status < 400 ? 'REDIRECT_DENIED' : 'RESPONSE_LIMIT')); return;
          }
          let received = 0; let ended = false;
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(res.headers)) if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : value);
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              res.on('data', (chunk: Buffer) => {
                if (ended) return;
                received += chunk.length;
                if (received > maxResponse) { ended = true; controller.error(new ExecutorError('RESPONSE_LIMIT')); res.destroy(); req.destroy(); clearTimeout(timer); return; }
                controller.enqueue(new Uint8Array(chunk)); res.pause();
              });
              res.on('end', () => { clearTimeout(timer); if (!ended) { ended = true; controller.close(); } });
              res.on('error', () => { clearTimeout(timer); if (!ended) { ended = true; controller.error(new ExecutorError('RESPONSE_FAILED')); } });
            },
            pull() { res.resume(); },
            cancel() { ended = true; clearTimeout(timer); res.destroy(); req.destroy(); },
          });
          if (request.method === 'HEAD' || [204, 205, 304].includes(status)) { res.resume(); clearTimeout(timer); resolve(new Response(null, { status, headers: responseHeaders })); }
          else resolve(new Response(stream, { status, headers: responseHeaders }));
        } catch {
          clearTimeout(timer); res.destroy(); req.destroy(); reject(new ExecutorError('RESPONSE_INVALID'));
        }
      });
      req.on('error', error => { clearTimeout(timer); reject(error instanceof ExecutorError ? error : new ExecutorError(signal.aborted ? 'REQUEST_ABORTED' : 'REQUEST_FAILED')); });
      if (requestSize) req.write(Buffer.concat(chunks));
      req.end();
    });
  };
}
