import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { isIP } from 'node:net';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { immutableJson } from '@shieldaai/agent-guard';
import { MapService } from './service.js';
import { mapIdentifier, validateReadScope, type ReadScope } from './types.js';
import { fail, fields, integer, parseRequest } from './boundary.js';
import { loadMapAssets } from './assets.js';
import { count, consume, headers, errorResponse, readBody, safeError, type Bucket } from './transport.js';
import { createMapOidcClient, type MapOidcOptions } from './oidc.js';

export interface MapIdentityBinding { readonly subject: string; readonly scope: ReadScope }
export interface MapIdentityServerOptions {
  service: MapService;
  publicOrigin: string;
  tls: { readonly key: string; readonly cert: string };
  oidc: Omit<MapOidcOptions, 'redirectUri'>;
  companyId: string;
  bindings: readonly MapIdentityBinding[];
  listenHost?: string;
  port?: number;
  viewerDirectory?: string;
  sessionTtlMs?: number;
  loginTtlMs?: number;
  maxSessions?: number;
  maxLoginTransactions?: number;
  requestTimeoutMs?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxConcurrentRequests?: number;
  rateLimit?: { maxRequests: number; windowMs: number };
}
export interface MapIdentityServer {
  readonly server: Server;
  readonly url: string;
  close(): Promise<void>;
  replaceBindings(bindings: readonly MapIdentityBinding[]): void;
  revokeSubject(subject: string): void;
  invalidateSessions(): void;
}
const SESSION_COOKIE = '__Host-agm_session', LOGIN_COOKIE = '__Host-agm_login';
const SESSION = /^agm_sess_v1\.[A-Za-z0-9_-]{43}$/;
const LOGIN = /^agm_login_v1\.[A-Za-z0-9_-]{43}$/;
const CSRF = /^agm_csrf_v1\.[A-Za-z0-9_-]{43}$/;
const token = (prefix: string): string => `${prefix}.${randomBytes(32).toString('base64url')}`;
const hash = (value: string): string => createHash('sha256').update(value).digest('hex');
type Session = { csrf: string; expiresAt: number; deadline: number; epoch: number; scope: ReadScope | null; bucket: Bucket };
type Transaction = { state: string; nonce: string; codeVerifier: string; sessionId: string; expiresAt: number; deadline: number; epoch: number };

function cookies(request: IncomingMessage): Map<string, string> {
  if (count(request, 'cookie') > 1) fail('MAP_REQUEST_INVALID');
  const header = request.headers.cookie;
  if (header === undefined) return new Map();
  if (Buffer.byteLength(header) > 4096) fail('MAP_REQUEST_INVALID');
  const result = new Map<string, string>();
  for (const field of header.split(';')) {
    const part = field.trim(), at = part.indexOf('=');
    if (at < 1) fail('MAP_REQUEST_INVALID');
    const name = part.slice(0, at), value = part.slice(at + 1);
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name) || /[^\x21-\x7e]|[",;\\]/.test(value) || result.has(name)) fail('MAP_REQUEST_INVALID');
    result.set(name, value);
  }
  return result;
}
function cookie(name: string, value: string, ttl: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Math.ceil(ttl / 1000))}`;
}
function setCookies(response: ServerResponse, values: string[]): void { response.setHeader('Set-Cookie', values); }
function json(response: ServerResponse, value: unknown, maximum: number): void {
  const body = Buffer.from(JSON.stringify(value));
  if (body.length > maximum) fail('MAP_RESPONSE_TOO_LARGE');
  headers(response, body.length); response.writeHead(200); response.end(body);
}
function redirect(response: ServerResponse, destination: '/' | '/?auth_error=1'): void {
  headers(response, 0); response.setHeader('Location', destination); response.writeHead(303); response.end();
}
function validateBindings(value: unknown, companyId: string): Map<string, ReadScope> {
  let copied: unknown;
  try { copied = immutableJson(value, 8, 100_000, 1024 * 1024); } catch { fail('MAP_CONFIG_INVALID'); }
  if (!Array.isArray(copied) || copied.length > 1024) fail('MAP_CONFIG_INVALID');
  const bindings = new Map<string, ReadScope>();
  for (const item of copied) {
    const entry = fields(item, ['subject', 'scope'], ['subject', 'scope']);
    const subject = mapIdentifier(entry.subject, 'MAP_CONFIG_INVALID');
    const scope = validateReadScope(entry.scope);
    if (scope.companyId !== companyId || bindings.has(subject)) fail('MAP_CONFIG_INVALID');
    bindings.set(subject, scope);
  }
  return bindings;
}

/** Dedicated HTTPS browser boundary. It calls the scoped service directly and trusts no proxy identity headers. */
export async function startMapIdentityServer(options: MapIdentityServerOptions): Promise<MapIdentityServer> {
  const config = fields(options, ['service', 'publicOrigin', 'tls', 'oidc', 'companyId', 'bindings', 'listenHost', 'port',
    'viewerDirectory', 'sessionTtlMs', 'loginTtlMs', 'maxSessions', 'maxLoginTransactions', 'requestTimeoutMs',
    'maxRequestBytes', 'maxResponseBytes', 'maxConcurrentRequests', 'rateLimit'], ['service', 'publicOrigin', 'tls', 'oidc', 'companyId', 'bindings']);
  if (!(config.service instanceof MapService)) fail('MAP_CONFIG_INVALID');
  const service = config.service, companyId = mapIdentifier(config.companyId, 'MAP_CONFIG_INVALID');
  let origin: URL;
  try {
    if (typeof config.publicOrigin !== 'string') throw new Error();
    origin = new URL(config.publicOrigin);
    if (origin.protocol !== 'https:' || origin.origin !== config.publicOrigin || origin.username || origin.password) throw new Error();
  } catch { fail('MAP_CONFIG_INVALID'); }
  const listenHost = config.listenHost === undefined ? '127.0.0.1' : config.listenHost;
  if (typeof listenHost !== 'string' || !isIP(listenHost)) fail('MAP_CONFIG_INVALID');
  const ephemeral = origin.port === '0';
  if (ephemeral && (!['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname) || !['127.0.0.1', '::1'].includes(listenHost))) fail('MAP_CONFIG_INVALID');
  const port = integer(config.port, Number(origin.port || 443), 0, 65535);
  if ((port === 0) !== ephemeral) fail('MAP_CONFIG_INVALID');
  const tls = fields(config.tls, ['key', 'cert'], ['key', 'cert']);
  if (typeof tls.key !== 'string' || typeof tls.cert !== 'string' || !tls.key || !tls.cert ||
      Buffer.byteLength(tls.key) > 256 * 1024 || Buffer.byteLength(tls.cert) > 256 * 1024) fail('MAP_CONFIG_INVALID');
  const oidc = fields(config.oidc, ['issuer', 'clientId', 'clientSecret', 'clientAuthMethod', 'endpointOrigins', 'ca', 'requestTimeoutMs', 'maxResponseBytes'], ['issuer', 'clientId', 'clientSecret']);
  const ttl = integer(config.sessionTtlMs, 900_000, 10, 900_000), loginTtl = integer(config.loginTtlMs, 300_000, 10, 300_000);
  const sessionLimit = integer(config.maxSessions, 1024, 1, 4096), flowLimit = integer(config.maxLoginTransactions, 128, 1, 1024);
  const timeout = integer(config.requestTimeoutMs, 10_000, 10, 30_000), requestLimit = integer(config.maxRequestBytes, 32_768, 128, 65_536);
  const responseLimit = integer(config.maxResponseBytes, 2 * 1024 * 1024, 128, 2 * 1024 * 1024);
  const concurrency = integer(config.maxConcurrentRequests, 4, 1, 32);
  const rate = config.rateLimit === undefined ? {} : fields(config.rateLimit, ['maxRequests', 'windowMs'], ['maxRequests', 'windowMs']);
  const rateMax = integer(rate.maxRequests, 600, 1, 10_000), rateWindow = integer(rate.windowMs, 60_000, 10, 60_000);
  let bindings = validateBindings(config.bindings, companyId), epoch = 0, active = 0, closing = false;
  let client: Awaited<ReturnType<typeof createMapOidcClient>> | undefined;
  const sessions = new Map<string, Session>(), transactions = new Map<string, Transaction>();
  const sockets = new Set<Duplex>(), aborts = new Set<AbortController>();
  const socketTimers = new WeakMap<Duplex, ReturnType<typeof setTimeout>>();
  const globalBucket: Bucket = { since: performance.now(), count: 0 };
  const assets = await loadMapAssets(config.viewerDirectory);
  const invalidate = (): void => { epoch++; sessions.clear(); transactions.clear(); };
  const prune = (): void => {
    const now = Date.now();
    for (const [key, value] of sessions) if (value.expiresAt <= now || value.deadline <= performance.now()) sessions.delete(key);
    for (const [key, value] of transactions) if (value.expiresAt <= now || value.deadline <= performance.now() || !sessions.has(value.sessionId)) transactions.delete(key);
  };
  const newSession = (scope: ReadScope | null, expiresAt: number): { value: string; id: string; session: Session } => {
    prune(); if (sessions.size >= sessionLimit) fail('MAP_BUSY');
    const value = token('agm_sess_v1'), id = hash(value);
    const session = { csrf: token('agm_csrf_v1'), expiresAt, deadline: performance.now() + Math.max(0, expiresAt - Date.now()),
      epoch, scope, bucket: { since: performance.now(), count: 0 } };
    sessions.set(id, session); return { value, id, session };
  };
  const findSession = (supplied: Map<string, string>): { id: string; session: Session } | null => {
    const value = supplied.get(SESSION_COOKIE); if (!value || !SESSION.test(value)) return null;
    const id = hash(value), session = sessions.get(id);
    return session && session.epoch === epoch && session.expiresAt > Date.now() && session.deadline > performance.now() ? { id, session } : null;
  };
  const live = (id: string, session: Session): void => {
    if (closing || sessions.get(id) !== session || session.epoch !== epoch || session.expiresAt <= Date.now() || session.deadline <= performance.now()) fail('MAP_SESSION_REQUIRED');
  };
  let server: Server;
  try {
    server = createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2', maxHeaderSize: 8192,
      headersTimeout: timeout, requestTimeout: timeout, keepAliveTimeout: 1, handshakeTimeout: timeout },
    (request, response) => { void handle(request, response); });
  } catch { fail('MAP_CONFIG_INVALID'); }
  server.maxConnections = 64; server.maxHeadersCount = 0;
  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    request.on('error', () => {}); response.on('error', () => {});
    response.setHeader('Strict-Transport-Security', 'max-age=31536000');
    clearTimeout(socketTimers.get(request.socket));
    const socketTimer = setTimeout(() => request.socket.destroy(), timeout + 250); socketTimer.unref(); socketTimers.set(request.socket, socketTimer);
    const abort = new AbortController(), started = performance.now();
    let admitted = false, timer: ReturnType<typeof setTimeout> | undefined;
    const disconnected = (): void => { if (!response.writableEnded) abort.abort(); };
    request.once('aborted', disconnected); response.once('close', disconnected);
    const check = (): void => { if (closing || response.destroyed || abort.signal.aborted || performance.now() - started > timeout) fail('MAP_TIMEOUT'); };
    try {
      consume(globalBucket, rateMax, rateWindow);
      if (closing || !client || active >= concurrency) fail('MAP_BUSY');
      active++; admitted = true; aborts.add(abort);
      timer = setTimeout(() => { abort.abort(); errorResponse(response, 'MAP_TIMEOUT'); }, timeout); timer.unref();
      if (count(request, 'host') !== 1 || request.headers.host !== origin.host ||
          ['authorization', 'proxy-authorization', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-port', 'x-original-url', 'x-rewrite-url'].some(name => request.headers[name] !== undefined)) fail('MAP_REQUEST_DENIED');
      if (!request.url?.startsWith('/') || request.url.startsWith('//') || request.url.length > 8192) fail('MAP_REQUEST_INVALID');
      const url = new URL(request.url, origin);
      if (url.origin !== origin.origin || url.hash) fail('MAP_REQUEST_INVALID');
      const callback = request.method === 'GET' && url.pathname === '/auth/callback';
      if (count(request, 'origin') > 1 || (request.headers.origin !== undefined && request.headers.origin !== origin.origin) ||
          (!callback && request.headers['sec-fetch-site'] !== undefined && !['same-origin', 'none'].includes(request.headers['sec-fetch-site']))) fail('MAP_REQUEST_DENIED');
      // The callback is the only cross-site navigation. All write-like browser routes require Origin and CSRF.
      if (request.method === 'POST' && request.headers.origin !== origin.origin) fail('MAP_REQUEST_DENIED');
      if (!callback && url.search && !(url.pathname === '/' && url.search === '?auth_error=1')) fail('MAP_REQUEST_INVALID');
      prune(); const supplied = cookies(request);
      if (callback) {
        const seen = new Set<string>();
        const flowValue = supplied.get(LOGIN_COOKIE), flowId = flowValue && LOGIN.test(flowValue) ? hash(flowValue) : '';
        const transaction = transactions.get(flowId);
        transactions.delete(flowId); // Consume before any asynchronous exchange, including all failures.
        setCookies(response, [cookie(LOGIN_COOKIE, '', 0)]);
        try {
          for (const [key] of url.searchParams) {
            if (!key || key.length > 128 || seen.has(key) || seen.size >= 16) fail('MAP_IDENTITY_INVALID'); seen.add(key);
          }
          const current = findSession(supplied);
          if (!transaction || !current || transaction.sessionId !== current.id || transaction.epoch !== epoch || transaction.expiresAt <= Date.now() || transaction.deadline <= performance.now()) fail('MAP_IDENTITY_INVALID');
          const identity = await client.complete(url, { state: transaction.state, nonce: transaction.nonce, codeVerifier: transaction.codeVerifier }, abort.signal);
          check(); live(current.id, current.session);
          const scope = bindings.get(identity.subject);
          if (!scope || transaction.epoch !== epoch || !Number.isSafeInteger(identity.expiresAt) || identity.expiresAt <= Date.now()) fail('MAP_IDENTITY_INVALID');
          sessions.delete(current.id);
          for (const [key, value] of transactions) if (value.sessionId === current.id) transactions.delete(key);
          const authenticated = newSession(scope, Math.min(Date.now() + ttl, identity.expiresAt));
          setCookies(response, [cookie(SESSION_COOKIE, authenticated.value, authenticated.session.expiresAt - Date.now()), cookie(LOGIN_COOKIE, '', 0)]);
          redirect(response, '/');
        } catch { if (!response.headersSent && !response.destroyed && !abort.signal.aborted && !closing) redirect(response, '/?auth_error=1'); }
        return;
      }
      const asset = assets.get(url.pathname === '/' ? '/index.html' : url.pathname);
      if (request.method === 'GET' && asset) { headers(response, asset.body.length, asset.mime); response.writeHead(200); response.end(asset.body); return; }
      if (request.method === 'GET' && url.pathname === '/auth/session') {
        let current = findSession(supplied);
        if (!current) {
          const created = newSession(null, Date.now() + loginTtl); current = created;
          setCookies(response, [cookie(SESSION_COOKIE, created.value, loginTtl)]);
        }
        consume(current.session.bucket, rateMax, rateWindow);
        json(response, { mode: 'oidc', authenticated: current.session.scope !== null,
          csrfToken: current.session.csrf, expiresAt: new Date(current.session.expiresAt).toISOString() }, responseLimit); return;
      }
      if (request.method !== 'POST' || !['/v1/query', '/auth/login', '/auth/logout'].includes(url.pathname)) fail('MAP_REQUEST_DENIED');
      const current = findSession(supplied); if (!current) fail('MAP_SESSION_REQUIRED');
      const csrf = request.headers['x-csrf-token'];
      if (count(request, 'x-csrf-token') !== 1 || typeof csrf !== 'string' || !CSRF.test(csrf) ||
          !timingSafeEqual(Buffer.from(csrf), Buffer.from(current.session.csrf))) fail('MAP_REQUEST_DENIED');
      consume(current.session.bucket, rateMax, rateWindow);
      if (count(request, 'content-type') !== 1 || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '') ||
          count(request, 'content-length') > 1 || count(request, 'transfer-encoding') > 1 || request.headers['content-encoding'] !== undefined) fail('MAP_REQUEST_INVALID');
      const length = request.headers['content-length'];
      if (length !== undefined && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))) fail('MAP_REQUEST_INVALID');
      if (length !== undefined && Number(length) > requestLimit) fail('MAP_REQUEST_TOO_LARGE');
      const parsed = parseRequest(await readBody(request, requestLimit, abort.signal), requestLimit); check(); live(current.id, current.session);
      if (url.pathname === '/auth/logout') {
        try { fields(parsed, [], []); } catch { fail('MAP_REQUEST_INVALID'); }
        sessions.delete(current.id);
        for (const [key, value] of transactions) if (value.sessionId === current.id) transactions.delete(key);
        setCookies(response, [cookie(SESSION_COOKIE, '', 0), cookie(LOGIN_COOKIE, '', 0)]);
        json(response, { ok: true }, responseLimit); return;
      }
      if (url.pathname === '/auth/login') {
        try { fields(parsed, [], []); } catch { fail('MAP_REQUEST_INVALID'); }
        const prior = supplied.get(LOGIN_COOKIE); if (prior && LOGIN.test(prior)) transactions.delete(hash(prior));
        if (transactions.size >= flowLimit) fail('MAP_BUSY');
        const transaction = await client.begin(); check(); live(current.id, current.session);
        if (transactions.size >= flowLimit) fail('MAP_BUSY');
        const flowValue = token('agm_login_v1');
        transactions.set(hash(flowValue), { state: transaction.state, nonce: transaction.nonce, codeVerifier: transaction.codeVerifier,
          sessionId: current.id, expiresAt: Math.min(Date.now() + loginTtl, current.session.expiresAt),
          deadline: Math.min(performance.now() + loginTtl, current.session.deadline), epoch });
        setCookies(response, [cookie(LOGIN_COOKIE, flowValue, loginTtl)]);
        json(response, { authorizationUrl: transaction.authorizationUrl }, responseLimit); return;
      }
      if (!current.session.scope) fail('MAP_SESSION_REQUIRED');
      let envelope: Record<string, unknown>;
      try { envelope = fields(parsed, ['operation', 'args'], ['operation', 'args']); } catch { fail('MAP_REQUEST_INVALID'); }
      const result = await service.query(current.session.scope, envelope.operation, envelope.args);
      check(); live(current.id, current.session); json(response, result, responseLimit);
    } catch (error) { errorResponse(response, safeError(error)); }
    finally {
      if (timer) clearTimeout(timer);
      request.off('aborted', disconnected); response.off('close', disconnected);
      aborts.delete(abort); if (admitted) active--;
    }
  }
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('secureConnection', socket => { sockets.add(socket); const timer = setTimeout(() => socket.destroy(), timeout); timer.unref(); socketTimers.set(socket, timer);
    socket.once('close', () => { sockets.delete(socket); clearTimeout(socketTimers.get(socket)); }); });
  server.on('checkContinue', (request, response) => { void handle(request, response); });
  server.on('checkExpectation', (_request, response) => errorResponse(response, 'MAP_REQUEST_DENIED'));
  server.on('connect', (_request, socket) => socket.destroy()); server.on('upgrade', (_request, socket) => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy()); server.on('tlsClientError', (_error, socket) => socket.destroy());
  const close = async (): Promise<void> => {
    if (closing) return; closing = true; invalidate(); for (const abort of aborts) abort.abort();
    for (const socket of sockets) socket.destroy();
    if (server.listening) await new Promise<void>(resolve => server.close(() => resolve()));
  };
  try {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, listenHost, () => { server.off('error', reject); resolve(); }); });
    const address = server.address(); if (!address || typeof address === 'string') fail('MAP_UNAVAILABLE');
    if (ephemeral) origin.port = String(address.port);
    client = await createMapOidcClient({ ...oidc, redirectUri: `${origin.origin}/auth/callback` } as MapOidcOptions);
  } catch (error) { await close(); throw error; }
  return { server, url: origin.origin, close,
    replaceBindings(value: readonly MapIdentityBinding[]): void { const next = validateBindings(value, companyId); bindings = next; invalidate(); },
    revokeSubject(subject: string): void { bindings.delete(mapIdentifier(subject, 'MAP_CONFIG_INVALID')); invalidate(); },
    invalidateSessions(): void { invalidate(); },
  };
}
