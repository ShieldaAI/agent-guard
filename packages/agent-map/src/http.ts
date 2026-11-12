import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Socket } from 'node:net';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { MapService } from './service.js';
import { validateReadScope, type ReadScope } from './types.js';
import { createMapMcpHandler } from './mcp.js';
import { fail, integer } from './common.js';
import { fields } from './boundary.js';
import {
  headers,
  errorResponse,
  respondError,
  count,
  consume,
  queryEnvelope,
  rateLimit,
  readJsonBody,
  refuseOtherTraffic,
  sendAsset,
  type Bucket,
} from './transport.js';
import { loadMapAssets } from './assets.js';

export interface MapCredential {
  readonly token: string;
  readonly scope: ReadScope;
}
export interface MapServerOptions {
  service: MapService;
  credentials: readonly MapCredential[];
  viewerDirectory?: string;
  port?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  requestTimeoutMs?: number;
  maxConcurrentRequests?: number;
  rateLimit?: { maxRequests: number; windowMs: number };
}
const TOKEN = /^agm_v1\.[A-Za-z0-9_-]{43}$/;
const hash = (text: string): Buffer => createHash('sha256').update(text).digest();
export function createMapToken(): string {
  return `agm_v1.${randomBytes(32).toString('base64url')}`;
}
/** Loopback pilot server. Remote serving requires a trusted, verified TLS reverse proxy. */
export async function startMapServer(options: MapServerOptions) {
  const config = fields(
    options,
    [
      'service',
      'credentials',
      'viewerDirectory',
      'port',
      'maxRequestBytes',
      'maxResponseBytes',
      'requestTimeoutMs',
      'maxConcurrentRequests',
      'rateLimit',
    ],
    ['service', 'credentials'],
  );
  if (!(config.service instanceof MapService)) fail('MAP_CONFIG_INVALID');
  const service = config.service;
  const port = integer(config.port, 0, 0, 65535);
  const requestLimit = integer(config.maxRequestBytes, 32_768, 128, 65_536);
  const responseLimit = integer(config.maxResponseBytes, 2 * 1024 * 1024, 128, 2 * 1024 * 1024);
  const timeout = integer(config.requestTimeoutMs, 10_000, 10, 30_000);
  const concurrency = integer(config.maxConcurrentRequests, 4, 1, 32);
  const { maxRequests, windowMs } = rateLimit(config.rateLimit, 120);
  let copied: unknown;
  try {
    copied = immutableJson(config.credentials, 8, 100_000, 1024 * 1024);
  } catch {
    fail('MAP_CONFIG_INVALID');
  }
  if (!Array.isArray(copied) || copied.length === 0 || copied.length > 128) fail('MAP_CONFIG_INVALID');
  const seen = new Set<string>();
  const credentials = copied.map(value => {
    const entry = fields(value, ['token', 'scope'], ['token', 'scope']);
    if (typeof entry.token !== 'string' || !TOKEN.test(entry.token) || seen.has(entry.token))
      fail('MAP_CONFIG_INVALID');
    seen.add(entry.token);
    const scope = validateReadScope(entry.scope);
    return { digest: hash(entry.token), scope, bucket: { since: performance.now(), count: 0 } };
  });
  seen.clear();
  const assets = await loadMapAssets(config.viewerDirectory);
  const sockets = new Set<Socket>();
  const aborts = new Set<AbortController>();
  const socketTimers = new WeakMap<Socket, ReturnType<typeof setTimeout>>();
  let active = 0,
    closing = false,
    host = '';
  const globalBucket: Bucket = { since: performance.now(), count: 0 };
  const server = createServer(
    { maxHeaderSize: 8192, headersTimeout: timeout, requestTimeout: timeout, keepAliveTimeout: 1 },
    (request, response) => {
      void handle(request, response);
    },
  );
  server.maxConnections = 64;
  server.maxHeadersCount = 0;
  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    request.on('error', () => {});
    response.on('error', () => {});
    // Once headers arrive, leave a short bounded flush window after the request
    // deadline. A connection timer at the same instant would erase the 408.
    clearTimeout(socketTimers.get(request.socket));
    const socketTimer = setTimeout(() => request.socket.destroy(), timeout + 250);
    socketTimer.unref();
    socketTimers.set(request.socket, socketTimer);
    const started = performance.now();
    const abort = new AbortController();
    let admitted = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const check = (): void => {
      if (abort.signal.aborted || performance.now() - started > timeout) fail('MAP_TIMEOUT');
    };
    try {
      consume(globalBucket, Math.min(maxRequests * credentials.length, 10_000), windowMs);
      if (closing || active >= concurrency) fail('MAP_BUSY');
      active++;
      admitted = true;
      aborts.add(abort);
      timer = setTimeout(() => {
        abort.abort();
        errorResponse(response, 'MAP_TIMEOUT');
      }, timeout);
      timer.unref();
      if (
        count(request, 'host') !== 1 ||
        request.headers.host !== host ||
        request.headers['proxy-authorization'] !== undefined
      )
        fail('MAP_REQUEST_DENIED');
      const origin = request.headers.origin;
      if (
        count(request, 'origin') > 1 ||
        (origin !== undefined && origin !== `http://${host}`) ||
        (request.headers['sec-fetch-site'] !== undefined &&
          !['same-origin', 'none'].includes(request.headers['sec-fetch-site']))
      )
        fail('MAP_REQUEST_DENIED');
      const path = request.url === '/' ? '/index.html' : (request.url ?? '');
      if (request.method === 'GET' && path === '/auth/session') {
        const body = Buffer.from(JSON.stringify({ mode: 'bearer' }));
        headers(response, body.length);
        response.writeHead(200);
        response.end(body);
        return;
      }
      const asset = assets.get(path);
      if (request.method === 'GET' && asset) {
        sendAsset(response, asset);
        return;
      }
      if (request.method !== 'POST' || !['/v1/query', '/mcp'].includes(path)) fail('MAP_REQUEST_DENIED');
      if (count(request, 'authorization') !== 1) fail('MAP_UNAUTHENTICATED');
      const authorization = request.headers.authorization;
      if (!authorization?.startsWith('Bearer ') || !TOKEN.test(authorization.slice(7))) fail('MAP_UNAUTHENTICATED');
      const digest = hash(authorization.slice(7));
      let credential: (typeof credentials)[number] | undefined;
      for (const item of credentials) if (timingSafeEqual(item.digest, digest)) credential = item;
      digest.fill(0);
      if (!credential) fail('MAP_UNAUTHENTICATED');
      consume(credential.bucket, maxRequests, windowMs);
      // The credential and rate checks have passed; a refusal above already answered with its status.
      const parsed = await readJsonBody(request, response, requestLimit, abort.signal);
      check();
      let output: Buffer;
      let status = 200;
      let mime = 'application/json';
      if (path === '/v1/query') {
        const envelope = queryEnvelope(parsed);
        const result = await service.query(credential.scope, envelope.operation, envelope.args);
        check();
        output = Buffer.from(JSON.stringify(result));
      } else {
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail('MAP_REQUEST_INVALID');
        const method = (parsed as Record<string, unknown>).method;
        if (
          typeof method !== 'string' ||
          !['initialize', 'notifications/initialized', 'server/discover', 'tools/list', 'tools/call', 'ping'].includes(
            method,
          )
        )
          fail('MAP_REQUEST_DENIED');
        const handler = createMapMcpHandler(service, credential.scope);
        try {
          const forwarded = new Headers({
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
          });
          for (const name of ['mcp-protocol-version', 'mcp-session-id']) {
            if (count(request, name) > 1) fail('MAP_REQUEST_INVALID');
            const value = request.headers[name];
            if (typeof value === 'string') forwarded.set(name, value);
          }
          const result = await handler.fetch(
            new Request(`http://${host}/mcp`, {
              method: 'POST',
              headers: forwarded,
              body: JSON.stringify(parsed),
              signal: abort.signal,
            }),
            { parsedBody: parsed },
          );
          const reader = result.body?.getReader();
          const chunks: Uint8Array[] = [];
          let size = 0;
          if (reader) {
            try {
              while (true) {
                const { value, done } = await reader.read();
                check();
                if (done) break;
                size += value.byteLength;
                if (size > responseLimit) fail('MAP_RESPONSE_TOO_LARGE');
                chunks.push(value);
              }
            } finally {
              await reader.cancel().catch(() => {});
            }
          }
          output = Buffer.concat(chunks);
          status = result.status;
          mime = result.headers.get('content-type') ?? 'application/json';
        } finally {
          await handler.close();
        }
      }
      check();
      if (output.length > responseLimit) fail('MAP_RESPONSE_TOO_LARGE');
      headers(response, output.length, mime);
      response.writeHead(status);
      response.end(output);
    } catch (error) {
      respondError(response, error);
    } finally {
      if (timer) clearTimeout(timer);
      aborts.delete(abort);
      if (admitted) active--;
    }
  }
  server.on('connection', socket => {
    sockets.add(socket);
    const timer = setTimeout(() => socket.destroy(), timeout);
    timer.unref();
    socketTimers.set(socket, timer);
    socket.once('close', () => {
      sockets.delete(socket);
      clearTimeout(socketTimers.get(socket));
    });
  });
  refuseOtherTraffic(server, handle);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') fail('MAP_UNAVAILABLE');
  host = `127.0.0.1:${address.port}`;
  return {
    server,
    url: `http://${host}`,
    async close(): Promise<void> {
      if (closing) return;
      closing = true;
      for (const abort of aborts) abort.abort();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}
