import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';
import { immutableJson } from '@shieldaai/agent-guard';
import { DurableExecutor } from './executor.js';
import { ExecutorError } from './store.js';
import { composeInventorySnapshot, validateInventoryManifest, type InventoryManifest } from './inventory-manifest.js';
import { composeMcpInventorySnapshot, validateMcpInventorySources, type InventoryMcpSourceBinding } from './inventory-mcp.js';

export interface InventoryObserverCredential {
  readonly token: string;
  readonly tenantIds: readonly string[];
  /** Fixed by the host; host enrichment requires a manifest for every permitted tenant. */
  readonly profile?: 'core' | 'host' | 'host-mcp';
}
export interface InventoryServerOptions {
  executor: DurableExecutor;
  observers: readonly InventoryObserverCredential[];
  /** Validated once at startup. Bindings are checked against each fresh executor snapshot. */
  manifests?: readonly InventoryManifest[];
  /** Live host-owned readers, selected by tenant and manifest connection ID before capture. */
  mcpSources?: readonly InventoryMcpSourceBinding[];
  port?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  requestTimeoutMs?: number;
  maxConcurrentRequests?: number;
  maxConnections?: number;
  rateLimit?: { maxRequests: number; windowMs: number };
}

const TOKEN = /^agi_v1\.[A-Za-z0-9_-]{43}$/;
const CONFIG = 'INVENTORY_SERVER_CONFIG_INVALID';
const digest = (value: string): Buffer => createHash('sha256').update(value).digest();
function fail(code: string): never { throw new ExecutorError(code); }

/** Keep this independent observer credential outside both tasks and administration clients. */
export function createInventoryObserverToken(): string { return `agi_v1.${randomBytes(32).toString('base64url')}`; }

function object(value: unknown, allowed: readonly string[], required: readonly string[] = []): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return fail(CONFIG);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) return fail(CONFIG);
  if (Object.getOwnPropertySymbols(value).length) return fail(CONFIG);
  const copied: Record<string, unknown> = Object.create(null);
  for (const name of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)!;
    if (!allowed.includes(name) || !descriptor.enumerable || !('value' in descriptor)) return fail(CONFIG);
    copied[name] = descriptor.value;
  }
  if (required.some(name => !Object.hasOwn(copied, name))) return fail(CONFIG);
  return copied;
}
function integer(value: unknown, fallback: number, minimum: number, maximum: number): number {
  const result = value === undefined ? fallback : value;
  if (typeof result !== 'number' || !Number.isSafeInteger(result) || result < minimum || result > maximum) return fail(CONFIG);
  return result;
}
function identifier(value: unknown, code: string): string {
  if (typeof value !== 'string' || value.length > 8192 || [...value].length > 4096 ||
      /^[\s\u001c-\u001f\u0085]*$/u.test(value) || value.includes('\0') ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) return fail(code);
  return value;
}

type Bucket = { started: number; used: number };
function consume(bucket: Bucket, now: number, maximum: number, windowMs: number): number | undefined {
  if (now - bucket.started >= windowMs) { bucket.started = now; bucket.used = 0; }
  if (bucket.used >= maximum) return Math.max(1, Math.ceil((windowMs - (now - bucket.started)) / 1000));
  bucket.used++;
  return undefined;
}

function headerCount(request: IncomingMessage, name: string): number {
  let count = 0;
  for (let i = 0; i < request.rawHeaders.length; i += 2) if (request.rawHeaders[i]!.toLowerCase() === name) count++;
  return count;
}

function readBody(request: IncomingMessage, maximum: number, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let size = 0;
    const cleanup = (): void => {
      request.off('data', data); request.off('end', end); request.off('aborted', aborted); request.off('error', aborted);
      signal.removeEventListener('abort', timeout);
    };
    const stop = (code: string): void => { cleanup(); request.pause(); reject(new ExecutorError(code)); };
    const data = (chunk: Buffer): void => {
      size += chunk.length;
      if (size > maximum) { stop('REQUEST_TOO_LARGE'); return; }
      chunks.push(chunk);
    };
    const end = (): void => { cleanup(); resolve(Buffer.concat(chunks, size)); };
    const aborted = (): void => stop('REQUEST_INVALID');
    const timeout = (): void => stop('REQUEST_TIMEOUT');
    if (signal.aborted) { timeout(); return; }
    request.on('data', data); request.once('end', end); request.once('aborted', aborted); request.once('error', aborted);
    signal.addEventListener('abort', timeout, { once: true });
  });
}

function tenantFromBody(bytes: Buffer): string {
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    // Exactly one string-valued member; duplicate/extra keys cannot disappear in JSON.parse.
    // JSON.parse then validates escapes, control characters and JSON-only whitespace.
    if (!/^\s*\{\s*"(?:[^"\\]|\\.)*"\s*:\s*"(?:[^"\\]|\\.)*"\s*\}\s*$/.test(text)) return fail('REQUEST_INVALID');
    const parsed = JSON.parse(text) as Record<string, unknown>;
    if (Object.keys(parsed).length !== 1 || !Object.hasOwn(parsed, 'tenantId')) return fail('REQUEST_INVALID');
    return identifier(parsed.tenantId, 'REQUEST_INVALID');
  } catch { return fail('REQUEST_INVALID'); }
}

const ERRORS = new Map<string, number>([
  ['UNAUTHENTICATED', 401], ['INVENTORY_SCOPE_DENIED', 403], ['REQUEST_DENIED', 403],
  ['REQUEST_INVALID', 400], ['REQUEST_TOO_LARGE', 413], ['REQUEST_TIMEOUT', 408],
  ['INVENTORY_RESPONSE_TOO_LARGE', 413], ['INVENTORY_LIMIT_EXCEEDED', 413],
  ['INVENTORY_MCP_LIMIT_EXCEEDED', 413],
  ['INVENTORY_RATE_LIMITED', 429], ['INVENTORY_BUSY', 503], ['INVENTORY_UNAVAILABLE', 503],
  ['INVENTORY_DISABLED', 503], ['INVENTORY_STATE_INVALID', 503], ['INVENTORY_CLOCK_INVALID', 503],
]);
function responseHeaders(response: ServerResponse, size: number): void {
  response.setHeader('Content-Type', 'application/json');
  response.setHeader('Content-Length', size);
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Connection', 'close');
}
function errorResponse(response: ServerResponse, code: string, status = ERRORS.get(code) ?? 503, retry?: number): void {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) { response.destroy(); return; }
  const value = JSON.stringify({ error: code });
  responseHeaders(response, Buffer.byteLength(value));
  if (status === 401) response.setHeader('WWW-Authenticate', 'Bearer realm="agent-guard-inventory"');
  if (retry !== undefined) response.setHeader('Retry-After', retry);
  response.writeHead(status); response.end(value);
}
function socketError(socket: Socket, code: string, status: number, retry?: number): void {
  if (socket.destroyed || socket.writableEnded) return;
  if (!socket.writable) { socket.destroy(); return; }
  const value = JSON.stringify({ error: code });
  socket.end(`HTTP/1.1 ${status} Rejected\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(value)}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n${retry === undefined ? '' : `Retry-After: ${retry}\r\n`}\r\n${value}`);
}

/** Read-only loopback observer transport. A separately authenticated TLS bridge is required remotely. */
export async function startInventoryServer(options: InventoryServerOptions): Promise<{ server: Server; url: string; close(): Promise<void> }> {
  const config = object(options, ['executor', 'observers', 'manifests', 'mcpSources', 'port', 'maxRequestBytes', 'maxResponseBytes',
    'requestTimeoutMs', 'maxConcurrentRequests', 'maxConnections', 'rateLimit'], ['executor', 'observers']);
  if (!(config.executor instanceof DurableExecutor)) return fail(CONFIG);
  const executor = config.executor;
  const port = integer(config.port, 0, 0, 65535);
  const requestLimit = integer(config.maxRequestBytes, 16 * 1024, 1, 64 * 1024);
  const responseLimit = integer(config.maxResponseBytes, 8 * 1024 * 1024, 128, 8 * 1024 * 1024);
  const timeout = integer(config.requestTimeoutMs, 10_000, 10, 60_000);
  const maxConcurrent = integer(config.maxConcurrentRequests, 4, 1, 64);
  const maxConnections = integer(config.maxConnections, 32, 1, 256);
  const rate = config.rateLimit === undefined ? {} : object(config.rateLimit, ['maxRequests', 'windowMs'], ['maxRequests', 'windowMs']);
  const rateMaximum = integer(rate.maxRequests, 60, 1, 10_000);
  const rateWindow = integer(rate.windowMs, 60_000, 10, 60_000);
  const manifests = new Map<string, InventoryManifest>();
  if (config.manifests !== undefined) {
    try {
      const entries = immutableJson(config.manifests, 32, 500_000, 8 * 1024 * 1024);
      if (!Array.isArray(entries) || entries.length > 1024) fail(CONFIG);
      for (const entry of entries) {
        const manifest = validateInventoryManifest(entry);
        if (manifests.has(manifest.source.tenantId)) fail(CONFIG);
        manifests.set(manifest.source.tenantId, manifest);
      }
    } catch { return fail(CONFIG); }
  }
  let mcpSources: readonly InventoryMcpSourceBinding[];
  try { mcpSources = validateMcpInventorySources(config.mcpSources === undefined ? [] : config.mcpSources); }
  catch { return fail(CONFIG); }
  let copied: unknown;
  try { copied = immutableJson(config.observers, 5, 150_000, 8 * 1024 * 1024); }
  catch { return fail(CONFIG); }
  if (!Array.isArray(copied) || copied.length < 1 || copied.length > 128) return fail(CONFIG);
  const seen = new Set<string>();
  const observers = copied.map(value => {
    const observer = object(value, ['token', 'tenantIds', 'profile'], ['token', 'tenantIds']);
    if (typeof observer.token !== 'string' || !TOKEN.test(observer.token) || seen.has(observer.token) ||
        (observer.profile !== undefined && observer.profile !== 'core' && observer.profile !== 'host' && observer.profile !== 'host-mcp') || !Array.isArray(observer.tenantIds) ||
        observer.tenantIds.length < 1 || observer.tenantIds.length > 1024) return fail(CONFIG);
    seen.add(observer.token);
    const tenants = new Set(observer.tenantIds.map(value => identifier(value, CONFIG)));
    if (tenants.size !== observer.tenantIds.length) return fail(CONFIG);
    const profile = observer.profile === 'host-mcp' ? 'host-mcp' : observer.profile === 'host' ? 'host' : 'core';
    if (profile !== 'core' && [...tenants].some(tenant => !manifests.has(tenant))) return fail(CONFIG);
    return { hash: digest(observer.token), tenants, profile, bucket: { started: performance.now(), used: 0 } };
  });
  seen.clear();
  const globalBucket = { started: performance.now(), used: 0 };
  const globalMaximum = Math.min(10_000, rateMaximum * observers.length);
  const sockets = new Map<Socket, ReturnType<typeof setTimeout>>();
  let active = 0; let expectedHost = ''; let closing = false;
  const server = createServer({ maxHeaderSize: 8192, headersTimeout: timeout, requestTimeout: timeout,
    keepAliveTimeout: 1 }, (request, response) => { void handle(request, response); });
  server.maxConnections = maxConnections;
  // Keep all headers visible to our own count/duplicate checks. The parser's
  // 8 KiB byte cap bounds work; truncating this list could hide a late security header.
  server.maxHeadersCount = 0;

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    response.on('error', () => {});
    request.on('error', () => {});
    const started = performance.now();
    const globalRetry = consume(globalBucket, started, globalMaximum, rateWindow);
    if (globalRetry !== undefined) { errorResponse(response, 'INVENTORY_RATE_LIMITED', 429, globalRetry); return; }
    if (closing || active >= maxConcurrent) { errorResponse(response, 'INVENTORY_BUSY'); return; }
    const headerTimer = sockets.get(request.socket); if (headerTimer) clearTimeout(headerTimer);
    active++;
    let finished = false;
    const abort = new AbortController();
    const timer = setTimeout(() => {
      abort.abort();
      if (response.headersSent) response.destroy(); else errorResponse(response, 'REQUEST_TIMEOUT');
    }, timeout);
    timer.unref();
    const release = (): void => {
      if (finished) return;
      finished = true; active--; clearTimeout(timer); abort.abort();
    };
    response.once('finish', release); response.once('close', release);
    const checkTime = (): void => { if (abort.signal.aborted || performance.now() - started >= timeout) fail('REQUEST_TIMEOUT'); };
    try {
      if (request.method !== 'POST' || request.url !== '/v1/inventory/snapshot' || request.headers.origin !== undefined ||
          // Node's fetch sends this standalone mode header. Browser requests also carry
          // Origin or other fetch metadata, which remains prohibited on this host API.
          Object.keys(request.headers).some(name => name.startsWith('sec-fetch-') &&
            (name !== 'sec-fetch-mode' || request.headers[name] !== 'cors')) || request.headers.expect !== undefined ||
          request.headers.upgrade !== undefined || request.headers['content-encoding'] !== undefined ||
          request.rawHeaders.length > 64) fail('REQUEST_DENIED');
      if (headerCount(request, 'authorization') !== 1) fail('UNAUTHENTICATED');
      if (headerCount(request, 'host') !== 1 || request.headers.host !== expectedHost ||
          headerCount(request, 'content-type') !== 1 || headerCount(request, 'content-length') > 1 ||
          headerCount(request, 'transfer-encoding') > 1) fail('REQUEST_INVALID');
      const authorization = request.headers.authorization;
      if (!authorization?.startsWith('Bearer ') || !TOKEN.test(authorization.slice(7))) fail('UNAUTHENTICATED');
      const candidate = digest(authorization.slice(7));
      let matched: (typeof observers)[number] | undefined;
      for (const observer of observers) if (timingSafeEqual(candidate, observer.hash)) matched = observer;
      candidate.fill(0);
      if (!matched) fail('UNAUTHENTICATED');
      const retry = consume(matched.bucket, performance.now(), rateMaximum, rateWindow);
      if (retry !== undefined) { errorResponse(response, 'INVENTORY_RATE_LIMITED', 429, retry); return; }
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')) fail('REQUEST_INVALID');
      if (request.headers['transfer-encoding'] !== undefined && request.headers['transfer-encoding'] !== 'chunked') fail('REQUEST_INVALID');
      const length = request.headers['content-length'];
      if (length !== undefined && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))) fail('REQUEST_INVALID');
      if (length !== undefined && Number(length) > requestLimit) fail('REQUEST_TOO_LARGE');
      const bytes = await readBody(request, requestLimit, abort.signal);
      checkTime();
      const tenantId = tenantFromBody(bytes);
      if (!matched.tenants.has(tenantId)) fail('INVENTORY_SCOPE_DENIED');
      checkTime();
      const core = executor.inventorySnapshot({ tenantId });
      checkTime();
      if (core.profile !== 'core' || core.source.tenantId !== tenantId) fail('INVENTORY_UNAVAILABLE');
      const host = matched.profile === 'core' ? undefined : composeInventorySnapshot(core, manifests.get(tenantId)!);
      checkTime();
      const snapshot = matched.profile === 'host-mcp' ? composeMcpInventorySnapshot(host!, mcpSources) : host ?? core;
      checkTime();
      if (snapshot.profile !== matched.profile || snapshot.source.tenantId !== tenantId) fail('INVENTORY_UNAVAILABLE');
      const serialized = JSON.stringify(snapshot);
      const size = Buffer.byteLength(serialized);
      checkTime();
      if (size > responseLimit) fail('INVENTORY_RESPONSE_TOO_LARGE');
      responseHeaders(response, size);
      response.writeHead(200); response.end(serialized);
    } catch (error) {
      const code = error instanceof ExecutorError && ERRORS.has(error.code) ? error.code : 'INVENTORY_UNAVAILABLE';
      errorResponse(response, code);
    }
  }

  server.on('connection', socket => {
    const timer = setTimeout(() => socket.destroy(), timeout); timer.unref();
    sockets.set(socket, timer);
    socket.setTimeout(timeout, () => socket.destroy());
    socket.once('close', () => { clearTimeout(timer); sockets.delete(socket); });
  });
  server.on('checkContinue', (request, response) => { void handle(request, response); });
  server.on('checkExpectation', (request, response) => { void handle(request, response); });
  const rejectTunnel = (socket: Socket): void => {
    const retry = consume(globalBucket, performance.now(), globalMaximum, rateWindow);
    socketError(socket, retry === undefined ? 'REQUEST_DENIED' : 'INVENTORY_RATE_LIMITED', retry === undefined ? 403 : 429, retry);
  };
  server.on('upgrade', (_request, socket) => rejectTunnel(socket as Socket));
  server.on('connect', (_request, socket) => rejectTunnel(socket as Socket));
  server.on('clientError', (error, socket) => {
    const retry = consume(globalBucket, performance.now(), globalMaximum, rateWindow);
    if (retry !== undefined) { socketError(socket as Socket, 'INVENTORY_RATE_LIMITED', 429, retry); return; }
    const overflow = (error as NodeJS.ErrnoException).code === 'HPE_HEADER_OVERFLOW';
    socketError(socket as Socket, overflow ? 'REQUEST_TOO_LARGE' : 'REQUEST_INVALID', overflow ? 431 : 400);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
  } catch (error) { for (const observer of observers) observer.hash.fill(0); throw error; }
  const address = server.address();
  if (!address || typeof address === 'string') return fail(CONFIG);
  expectedHost = `127.0.0.1:${address.port}`;
  let closePromise: Promise<void> | undefined;
  return { server, url: `http://${expectedHost}`, close() {
    if (closePromise) return closePromise;
    closing = true;
    closePromise = new Promise<void>((resolve, reject) => {
      server.close(error => {
        for (const observer of observers) observer.hash.fill(0);
        if (error) reject(error); else resolve();
      });
      for (const [socket, timer] of sockets) { clearTimeout(timer); socket.destroy(); }
    });
    return closePromise;
  } };
}
