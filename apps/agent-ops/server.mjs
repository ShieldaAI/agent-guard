import { createServer } from 'node:https';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { createMapOidcClient } from '@shieldaai/agent-map/oidc';
import { parseEvidenceJson } from '@shieldaai/agent-guard-executor/internal';
import { OpsError, SYSTEM_ACTOR_PREFIX, fail, fields, identifier, safeCode } from './workflow.mjs';
import { errorBody, recoveryBody, sessionBody, setupBody, setupChecks } from './responses.mjs';
import {
  createOpsTelemetry,
  operationalStatus,
  prometheusStatus,
  exportActivity,
  monitoringSummary,
} from './observability.mjs';
import { validateTls } from './tls-policy.mjs';

const COOKIE = '__Host-agent_ops';
const random = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value).digest();
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqual(digest(a), digest(b));
const roles = ['requester', 'reviewer', 'operator'];
const ANONYMOUS_TTL_MS = 5 * 60_000;
const MAX_PENDING_FLOWS = 128;
const MAX_CONNECTIONS = 128;
// One client address never holds more than half of the connections.
const MAX_CONNECTIONS_PER_CLIENT = MAX_CONNECTIONS / 2;
const MAX_IN_FLIGHT = 32;
// Requests without a signed-in session or an enrolled agent token share half of the slots;
// the rest stay free for signed-in people and agents. Health probes use no slot.
const MAX_ANONYMOUS_IN_FLIGHT = MAX_IN_FLIGHT / 2;
// One client address holds at most a quarter of the anonymous slots, so a single address that
// sends slow sign-in requests cannot keep everyone else from the sign-in page.
const MAX_ANONYMOUS_IN_FLIGHT_PER_CLIENT = MAX_ANONYMOUS_IN_FLIGHT / 4;
const TLS_HANDSHAKE_TIMEOUT_MS = 5000;
const SOCKET_IDLE_TIMEOUT_MS = 30_000;
const READINESS_CACHE_MS = 2000;
const ANONYMOUS_EVENT_WINDOW_MS = 60_000;
/**
 * Session, rate and sign-in settings shared by the runtime configuration and the server.
 * Every value is bounded: a session never outlives 15 minutes and limits cannot be switched off.
 */
export function validateServerLimits({
  sessionTtlMs = 15 * 60_000,
  rateLimitPerMinute = 180,
  signInFlowsPerClient = 4,
}) {
  const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
  if (!integer(sessionTtlMs, 1000, 15 * 60_000)) fail('SESSION_CONFIG_INVALID');
  if (!integer(rateLimitPerMinute, 60, 100_000)) fail('RATE_LIMIT_CONFIG_INVALID');
  if (!integer(signInFlowsPerClient, 1, MAX_PENDING_FLOWS)) fail('SIGN_IN_CONFIG_INVALID');
  return { sessionTtlMs, rateLimitPerMinute, signInFlowsPerClient };
}
/**
 * Rate-limit key: an IPv4 address, or the /64 prefix of an IPv6 address (one host
 * usually owns a whole /64). Behind an L4 passthrough every client shares the proxy's
 * address; enforce a per-client limit at that layer as well.
 */
export function clientKey(address) {
  const ip = String(address ?? 'unknown').split('%')[0];
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return mapped[1];
  if (!ip.includes(':')) return ip;
  const width = part => (part.includes('.') ? 2 : 1);
  const [head, tail] = ip.split('::');
  const left = head ? head.split(':') : [],
    right = tail ? tail.split(':') : [];
  const used = [...left, ...right].reduce((sum, part) => sum + width(part), 0);
  const groups = tail === undefined ? left : [...left, ...Array(Math.max(0, 8 - used)).fill('0'), ...right];
  return `${groups
    .slice(0, 4)
    .map(group => (parseInt(group, 16) || 0).toString(16))
    .join(':')}::/64`;
}
/**
 * In-flight admission. Every request takes one of `total` slots; requests without a signed-in
 * session or an enrolled agent token share `anonymous` of them, and one client address (see
 * clientKey) at most `anonymousPerClient` of those. `enter` returns the function that frees the
 * slot, or refuses with BUSY.
 */
export function createAdmission({
  total = MAX_IN_FLIGHT,
  anonymous = MAX_ANONYMOUS_IN_FLIGHT,
  anonymousPerClient = MAX_ANONYMOUS_IN_FLIGHT_PER_CLIENT,
} = {}) {
  let active = 0,
    anonymousActive = 0;
  const perClient = new Map();
  return {
    enter(isAnonymous, client) {
      const held = isAnonymous ? (perClient.get(client) ?? 0) : 0;
      if (active >= total || (isAnonymous && (anonymousActive >= anonymous || held >= anonymousPerClient)))
        fail('BUSY', 503);
      active++;
      if (isAnonymous) {
        anonymousActive++;
        perClient.set(client, held + 1);
      }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        active--;
        if (!isAnonymous) return;
        anonymousActive--;
        const left = perClient.get(client) - 1;
        if (left > 0) perClient.set(client, left);
        else perClient.delete(client);
      };
    },
  };
}
/**
 * Makes room for one more pending sign-in. Many people can share one address (a proxy or NAT):
 * at the per-address cap that address's oldest pending sign-in gives way, and at the overall cap
 * the oldest pending sign-in of all does. A full table therefore never refuses a new sign-in;
 * it ends the one that has waited longest.
 */
export function makeRoomForSignIn(flows, client, perClient, maximum = MAX_PENDING_FLOWS) {
  const mine = [...flows].filter(([, flow]) => flow.client === client);
  while (mine.length >= perClient) flows.delete(mine.shift()[0]);
  while (flows.size >= maximum) flows.delete(flows.keys().next().value);
}
function enroll(values) {
  if (!Array.isArray(values) || !values.length || values.length > 100) fail('IDENTITY_CONFIG_INVALID');
  const map = new Map(),
    ids = new Set();
  for (const binding of values) {
    fields(binding, ['subject', 'id', 'name', 'tenantId', 'roles']);
    identifier(binding.id);
    identifier(binding.tenantId);
    if (
      typeof binding.subject !== 'string' ||
      !binding.subject ||
      binding.subject.length > 256 ||
      map.has(binding.subject) ||
      ids.has(binding.id) ||
      binding.id.startsWith(SYSTEM_ACTOR_PREFIX) ||
      !Array.isArray(binding.roles) ||
      !binding.roles.length ||
      binding.roles.some(role => !roles.includes(role)) ||
      new Set(binding.roles).size !== binding.roles.length ||
      (binding.name !== undefined && (typeof binding.name !== 'string' || binding.name.length > 120))
    )
      fail('IDENTITY_CONFIG_INVALID');
    ids.add(binding.id);
    map.set(binding.subject, structuredClone(binding));
  }
  return map;
}
function agentEnroll(values = []) {
  if (!Array.isArray(values) || values.length > 100) fail('IDENTITY_CONFIG_INVALID');
  const ids = new Set(),
    tokens = new Set();
  return values.map(value => {
    fields(value, ['id', 'tenantId', 'token', 'allowedTicketIds']);
    identifier(value.id);
    identifier(value.tenantId);
    if (
      ids.has(value.id) ||
      value.id.startsWith(SYSTEM_ACTOR_PREFIX) ||
      typeof value.token !== 'string' ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(value.token) ||
      tokens.has(value.token) ||
      !Array.isArray(value.allowedTicketIds) ||
      !value.allowedTicketIds.length ||
      value.allowedTicketIds.length > 500
    )
      fail('IDENTITY_CONFIG_INVALID');
    value.allowedTicketIds.forEach(identifier);
    ids.add(value.id);
    tokens.add(value.token);
    const { token, ...operator } = value;
    return { operator: { ...structuredClone(operator), kind: 'agent' }, tokenHash: digest(token) };
  });
}
export function validateIdentityEnrollment(bindings, agents = []) {
  const humans = enroll(bindings),
    machines = agentEnroll(agents),
    ids = new Set([...humans.values()].map(value => value.id));
  if (machines.some(value => ids.has(value.operator.id))) fail('IDENTITY_CONFIG_INVALID');
  return { operators: humans.size, agents: machines.length };
}
function pageScope(url) {
  const page = {};
  for (const [key, value] of url.searchParams) {
    if (!/^(0|[1-9][0-9]{0,5})$/.test(value)) fail('INVALID_INPUT');
    // Assign only literal fields: request keys never select object properties.
    if (key === 'offset') {
      if (Object.hasOwn(page, 'offset')) fail('INVALID_INPUT');
      page.offset = Number(value);
    } else if (key === 'limit') {
      if (Object.hasOwn(page, 'limit')) fail('INVALID_INPUT');
      page.limit = Number(value);
    } else fail('INVALID_INPUT');
  }
  return page;
}

export async function startOpsServer(options) {
  const origin = new URL(options.publicOrigin);
  if (origin.protocol !== 'https:' || origin.origin !== options.publicOrigin || origin.username || origin.password)
    fail('PUBLIC_ORIGIN_INVALID');
  let { expiresAt: tlsExpiresAt } = validateTls(options.tls, options.publicOrigin);
  let bindings = enroll(options.bindings),
    agents = agentEnroll(options.agents),
    generation = 0,
    draining = false;
  const admission = createAdmission();
  const disjoint = (humans, machines) => {
    const ids = new Set([...humans.values()].map(value => value.id));
    if (machines.some(value => ids.has(value.operator.id))) fail('IDENTITY_CONFIG_INVALID');
  };
  disjoint(bindings, agents);
  const {
    sessionTtlMs: ttl,
    rateLimitPerMinute: rateLimit,
    signInFlowsPerClient: flowsPerClient,
  } = validateServerLimits(options);
  // Signs pre-login cookies; anonymous visitors create no server-side state.
  const anonymousKey = randomBytes(32);
  const sign = (purpose, value) =>
    createHmac('sha256', anonymousKey).update(`${purpose}\0${value}`).digest('base64url');
  const workflow = options.workflow,
    sessions = new Map(),
    flows = new Map(),
    limits = new Map();
  const telemetry = createOpsTelemetry({ securityLoggingEnabled: typeof options.onSecurityEvent === 'function' });
  const oidc = await createMapOidcClient({ ...options.oidc, redirectUri: `${origin.origin}/auth/callback` });
  const authorizationOrigins = [
    ...new Set([new URL(options.oidc.issuer).origin, ...(options.oidc.endpointOrigins ?? [])]),
  ];
  // Every client file is read once at startup: the page, its stylesheet and the ES modules
  // in public/ and public/views/. Nothing else under the application directory is served.
  const publicDirectory = new URL('./public/', import.meta.url);
  const assets = new Map([
    ['/', { type: 'text/html; charset=utf-8', body: readFileSync(new URL('index.html', publicDirectory)) }],
  ]);
  for (const directory of ['', 'views/'])
    for (const name of readdirSync(new URL(directory, publicDirectory)).sort()) {
      const kind = /^[a-z][a-z0-9-]*\.(js|css)$/.exec(name)?.[1];
      if (kind)
        assets.set(`/${directory}${name}`, {
          type: kind === 'js' ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8',
          body: readFileSync(new URL(`${directory}${name}`, publicDirectory)),
        });
    }
  const securityHeaders = {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'Strict-Transport-Security': 'max-age=31536000',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
  // Refusals without a signed-in person: the first of each kind in a window is logged at once,
  // the rest are counted and reported in one line, so a flood cannot fill the security log.
  const anonymousEvents = new Map();
  function flushAnonymousEvents(now = Date.now()) {
    for (const [key, entry] of anonymousEvents) {
      if (now - entry.started < ANONYMOUS_EVENT_WINDOW_MS) continue;
      anonymousEvents.delete(key);
      if (entry.suppressed) emit({ event: entry.event, code: entry.code, count: entry.suppressed });
    }
  }
  const anonymousEventTimer = setInterval(flushAnonymousEvents, ANONYMOUS_EVENT_WINDOW_MS);
  anonymousEventTimer.unref();
  function securityEvent(event, session, code, cause) {
    const actor = session && valid(session) ? session.operator : undefined;
    if (!actor && ['ACCESS_DENIED', 'SIGN_IN_FAILED'].includes(event)) {
      flushAnonymousEvents();
      const key = `${event}\0${code}\0${cause ?? ''}`,
        entry = anonymousEvents.get(key);
      if (entry) {
        entry.suppressed++;
        return;
      }
      anonymousEvents.set(key, { event, code, started: Date.now(), suppressed: 0 });
    }
    emit({
      event,
      ...(actor ? { operatorId: actor.id, tenantId: actor.tenantId } : {}),
      ...(code ? { code } : {}),
      ...(cause ? { cause } : {}),
    });
  }
  function emit(line) {
    const value = Object.freeze(line);
    // Logging is observational; a broken collector cannot grant access or replace an auth failure.
    try {
      const result = options.onSecurityEvent?.(value);
      if (result?.then) void Promise.resolve(result).catch(() => telemetry.securityLogFailed());
    } catch {
      telemetry.securityLogFailed();
    }
  }
  function send(response, status, value, extra = {}) {
    if (response.destroyed || response.writableEnded) return;
    response.writeHead(status, { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8', ...extra });
    response.end(JSON.stringify(value));
  }
  function valid(session) {
    return (
      session &&
      (session.anonymous || sessions.get(session.id) === session) &&
      session.generation === generation &&
      Date.now() < session.expiresAt &&
      performance.now() < session.deadline &&
      !draining
    );
  }
  function cleanup() {
    for (const [id, session] of sessions) if (!valid(session)) sessions.delete(id);
    for (const [id, flow] of flows)
      if (flow.generation !== generation || Date.now() >= flow.expiresAt) flows.delete(id);
    for (const [id, limit] of limits) if (Date.now() - limit.started > 60_000) limits.delete(id);
  }
  /** Stateless pre-login session: an HMAC-signed, short-lived cookie with a derived CSRF token. */
  function anonymousSession(value) {
    const match = /^a\.(\d{1,9})\.(\d{1,16})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/.exec(value ?? '');
    if (!match) return undefined;
    const body = value.slice(0, value.lastIndexOf('.'));
    if (!equal(match[4], sign('anonymous', body))) return undefined;
    const session = {
      id: value,
      anonymous: true,
      generation: Number(match[1]),
      expiresAt: Number(match[2]),
      deadline: Number.POSITIVE_INFINITY,
      csrfToken: sign('csrf', body),
    };
    return valid(session) ? session : undefined;
  }
  function newAnonymousSession(response) {
    const body = `a.${generation}.${Date.now() + ANONYMOUS_TTL_MS}.${random()}`,
      value = `${body}.${sign('anonymous', body)}`;
    response.setHeader(
      'Set-Cookie',
      `${COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${ANONYMOUS_TTL_MS / 1000}`,
    );
    return anonymousSession(value);
  }
  function newSession(response, identity) {
    cleanup();
    if (sessions.size >= 512) fail('SESSION_CAPACITY_REACHED', 503);
    const duration = Math.min(ttl, identity.expiresAt - Date.now());
    if (duration <= 0) fail('AUTH_FAILED', 401);
    const session = {
      id: random(),
      csrfToken: random(),
      generation,
      expiresAt: Date.now() + duration,
      deadline: performance.now() + duration,
      operator: identity.operator,
    };
    sessions.set(session.id, session);
    response.setHeader(
      'Set-Cookie',
      `${COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(duration / 1000)}`,
    );
    return session;
  }
  function cookieSession(request) {
    const values = (request.headers.cookie ?? '')
      .split(';')
      .map(value => value.trim())
      .filter(value => value.startsWith(`${COOKIE}=`));
    if (values.length > 1) fail('UNAUTHENTICATED', 401);
    const value = values[0]?.slice(COOKIE.length + 1);
    if (value?.startsWith('a.')) return anonymousSession(value);
    const session = sessions.get(value);
    return valid(session) ? session : undefined;
  }
  function authorized(session, role) {
    if (!valid(session) || !session.operator) fail('UNAUTHENTICATED', 401);
    if (role && !session.operator.roles.includes(role)) fail('FORBIDDEN', 403);
  }
  function csrf(request, session) {
    if (
      !valid(session) ||
      request.headers.origin !== origin.origin ||
      !equal(request.headers['x-csrf-token'], session.csrfToken)
    )
      fail('CSRF_INVALID', 403);
    if (request.headers['sec-fetch-site'] && request.headers['sec-fetch-site'] !== 'same-origin')
      fail('CSRF_INVALID', 403);
  }
  async function body(request) {
    if (request.headers['content-type']?.split(';')[0] !== 'application/json' || request.headers['content-encoding'])
      fail('INVALID_INPUT');
    const length = Number(request.headers['content-length'] ?? 0);
    if (!Number.isSafeInteger(length) || length < 0 || length > 8192) fail('BODY_TOO_LARGE', 413);
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => request.destroy(), 5000);
    timer.unref();
    try {
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 8192) fail('BODY_TOO_LARGE', 413);
        chunks.push(chunk);
      }
      try {
        return parseEvidenceJson(Buffer.concat(chunks), 8192);
      } catch {
        fail('INVALID_INPUT');
      }
    } finally {
      clearTimeout(timer);
    }
  }
  function bearerAgent(request) {
    const match = /^Bearer ([A-Za-z0-9_-]{43,128})$/.exec(request.headers.authorization ?? '');
    const presented = match && digest(match[1]);
    return (presented && agents.find(value => timingSafeEqual(value.tokenHash, presented))) || undefined;
  }
  /** A signed-in session or an enrolled agent token, decided before a slot is taken. */
  function known(request) {
    try {
      return !!cookieSession(request)?.operator || !!bearerAgent(request);
    } catch {
      return false;
    }
  }
  // Readiness reads and verifies both stores. Probes share one result for a short time.
  let readiness = { at: Number.NEGATIVE_INFINITY, error: undefined };
  function ready() {
    const now = performance.now();
    if (now - readiness.at >= READINESS_CACHE_MS) {
      readiness = { at: now, error: undefined };
      try {
        if (Date.now() >= tlsExpiresAt) fail('TLS_CERTIFICATE_EXPIRED', 503);
        workflow.health();
      } catch (error) {
        readiness.error = error;
      }
    }
    if (readiness.error) throw readiness.error;
  }
  function limit(request) {
    cleanup();
    const key = clientKey(request.socket.remoteAddress);
    if (!limits.has(key)) {
      // A full table drops its oldest window instead of refusing every new client.
      if (limits.size >= 2048) limits.delete(limits.keys().next().value);
      limits.set(key, { started: Date.now(), count: 0 });
    }
    if (++limits.get(key).count > rateLimit) fail('RATE_LIMITED', 429);
  }
  const server = createServer(
    {
      ...options.tls,
      minVersion: 'TLSv1.2',
      // A connection that does not finish its TLS handshake is dropped, not held for two minutes.
      handshakeTimeout: TLS_HANDSHAKE_TIMEOUT_MS,
      maxHeaderSize: 16 * 1024,
      requestTimeout: 10_000,
      headersTimeout: 10_000,
      connectionsCheckingInterval: 1000,
    },
    async (request, response) => {
      const started = performance.now();
      let observed = false;
      response.once('finish', () => {
        observed = true;
        telemetry.record({ statusCode: response.statusCode, durationMs: performance.now() - started });
      });
      response.once('close', () => {
        if (!observed) telemetry.record({ statusCode: 499, durationMs: performance.now() - started });
      });
      let release,
        isCallback = false,
        isAuthFlow = false,
        requestSession;
      try {
        if (
          request.headers.host !== origin.host ||
          Object.keys(request.headers).some(
            key => key === 'forwarded' || key.startsWith('x-forwarded-') || key.startsWith('x-auth-'),
          )
        )
          fail('REQUEST_ORIGIN_INVALID', 400);
        let url;
        try {
          url = new URL(request.url, origin);
        } catch {
          fail('REQUEST_ORIGIN_INVALID', 400); // An unparseable request target (for example "//") is the client's error.
        }
        isCallback = url.pathname === '/auth/callback' && request.method === 'GET';
        isAuthFlow = isCallback || (url.pathname === '/auth/login' && request.method === 'POST');
        if (url.origin !== origin.origin || !request.url?.startsWith('/')) fail('REQUEST_ORIGIN_INVALID', 400);
        if (request.method === 'GET' && url.pathname === '/health/live') return send(response, 200, { status: 'ok' });
        if (draining) fail('NOT_READY', 503);
        if (request.method === 'GET' && url.pathname === '/health/ready') {
          limit(request);
          ready();
          return send(response, 200, { status: 'ok' });
        }
        release = admission.enter(!known(request), clientKey(request.socket.remoteAddress));
        // The page and its modules are answered from memory and are not counted against the
        // per-address request limit: one page load is fifteen files. The connection and
        // in-flight caps above still bound them.
        if (request.method === 'GET' && assets.has(url.pathname) && !url.search) {
          const asset = assets.get(url.pathname);
          response.writeHead(200, { ...securityHeaders, 'Content-Type': asset.type });
          return response.end(asset.body);
        }
        limit(request);
        const agentRequest = /^\/agent\/requests\/([a-zA-Z0-9-]{1,80})$/.exec(url.pathname);
        if (
          (url.pathname === '/agent/requests' && request.method === 'POST') ||
          (agentRequest && request.method === 'GET')
        ) {
          if (request.headers.cookie || request.headers.origin) fail('FORBIDDEN', 403);
          const agent = bearerAgent(request);
          if (!agent) fail('UNAUTHENTICATED', 401);
          const epoch = generation,
            check = () => {
              if (draining || generation !== epoch || !agents.includes(agent)) fail('UNAUTHENTICATED', 401);
            };
          if (agentRequest) {
            check();
            const item = workflow.request(agentRequest[1], agent.operator.tenantId);
            if (item.requesterId !== agent.operator.id || !agent.operator.allowedTicketIds.includes(item.ticketId))
              fail('NOT_FOUND', 404);
            return send(response, 200, { request: workflow.public(item, { forAgent: true }) });
          }
          const input = await body(request);
          check();
          return send(response, 201, await workflow.propose(agent.operator, input, check));
        }
        if (request.headers.authorization) fail('FORBIDDEN', 403);
        let session = cookieSession(request);
        requestSession = session;
        if (url.pathname === '/api/session' && request.method === 'GET') {
          session ??= newAnonymousSession(response);
          return send(
            response,
            200,
            sessionBody({
              session,
              authorizationOrigins,
              issuer: options.oidc.issuer,
              policy: workflow.requestPolicy,
            }),
          );
        }
        if (url.pathname === '/auth/callback' && request.method === 'GET') {
          const stateValues = url.searchParams.getAll('state'),
            flow = stateValues.length === 1 && flows.get(stateValues[0]);
          if (
            !flow ||
            !session ||
            flow.sessionId !== session.id ||
            flow.generation !== generation ||
            flow.expiresAt <= Date.now()
          )
            fail('AUTH_FAILED', 401);
          flows.delete(stateValues[0]);
          let identity;
          try {
            const { state, nonce, codeVerifier } = flow.transaction;
            identity = await oidc.complete(url, { state, nonce, codeVerifier });
          } catch {
            fail('AUTH_FAILED', 401);
          }
          if (!valid(session)) fail('AUTH_FAILED', 401);
          const binding = bindings.get(identity.subject);
          if (!binding) fail('FORBIDDEN', 403);
          const { subject: _, ...operator } = binding;
          sessions.delete(session.id);
          const signedIn = newSession(response, { operator, expiresAt: identity.expiresAt });
          securityEvent('SIGN_IN_SUCCEEDED', signedIn);
          response.writeHead(303, { ...securityHeaders, Location: '/' });
          return response.end();
        }
        if (request.method === 'POST' && url.pathname === '/auth/login') {
          csrf(request, session);
          // Sign-in starts from the pre-login session only. A signed-in session keeps its cookie
          // and its server-side session: sign out first.
          if (session.operator) fail('ALREADY_SIGNED_IN', 409);
          fields(await body(request), []);
          csrf(request, session);
          cleanup();
          const client = clientKey(request.socket.remoteAddress);
          for (const [id, flow] of flows) if (flow.sessionId === session.id) flows.delete(id);
          const transaction = await oidc.begin();
          csrf(request, session);
          makeRoomForSignIn(flows, client, flowsPerClient);
          // A fresh pre-login cookie outlives the three-minute flow however old the page was.
          const renewed = newAnonymousSession(response);
          flows.set(transaction.state, {
            transaction,
            sessionId: renewed.id,
            client,
            generation,
            expiresAt: Date.now() + 3 * 60_000,
          });
          return send(response, 200, { authorizationUrl: transaction.authorizationUrl });
        }
        if (request.method === 'POST' && url.pathname === '/auth/logout') {
          csrf(request, session);
          fields(await body(request), []);
          csrf(request, session);
          securityEvent('SIGNED_OUT', session);
          sessions.delete(session.id);
          cleanup();
          response.setHeader('Set-Cookie', `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
          return send(response, 200, { signedOut: true });
        }
        authorized(session);
        if (request.method === 'GET' && ['/api/status', '/api/metrics'].includes(url.pathname)) {
          authorized(session, 'operator');
          if (url.search) fail('INVALID_INPUT');
          const status = operationalStatus({
            workflow,
            verify: ready,
            operator: session.operator,
            telemetry,
            keyring: options.keyringPolicy?.(),
            tlsExpiresAt,
          });
          if (url.pathname === '/api/status') return send(response, 200, status);
          response.writeHead(200, { ...securityHeaders, 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
          return response.end(prometheusStatus(status));
        }
        if (request.method === 'GET' && url.pathname === '/api/tickets')
          return send(response, 200, workflow.tickets(session.operator.tenantId, pageScope(url)));
        if (request.method === 'GET' && url.pathname === '/api/requests') {
          const scope = pageScope(url),
            tenant = session.operator.tenantId;
          // The tag names this tenant's list at this page. An unchanged poll costs no list at all.
          const etag = `"${createHash('sha256')
            .update(JSON.stringify([workflow.requestsRevision(tenant), tenant, scope.offset ?? 0, scope.limit ?? 500]))
            .digest('base64url')
            .slice(0, 32)}"`;
          if (request.headers['if-none-match'] === etag) {
            response.writeHead(304, { ...securityHeaders, ETag: etag });
            return response.end();
          }
          return send(response, 200, workflow.requests(tenant, scope), { ETag: etag });
        }
        const detail = /^\/api\/requests\/([a-zA-Z0-9-]{1,80})$/.exec(url.pathname);
        if (request.method === 'GET' && detail) {
          if (url.search) fail('INVALID_INPUT');
          return send(response, 200, workflow.detail(detail[1], session.operator.tenantId));
        }
        if (request.method === 'GET' && url.pathname === '/api/maintenance') {
          authorized(session, 'operator');
          return send(response, 200, {
            ...workflow.maintenance(session.operator),
            ...(options.keyringPolicy ? { keyring: options.keyringPolicy() } : {}),
          });
        }
        if (request.method === 'GET' && url.pathname === '/api/setup') {
          authorized(session, 'operator');
          if (url.search) fail('INVALID_INPUT');
          // One verified read of both stores answers the whole page (and is shared with the
          // other requests of the same refresh).
          ready();
          const tenant = session.operator.tenantId,
            data = workflow.data(),
            maintenance = workflow.maintenance(session.operator),
            recovery = recoveryBody(options.recovery),
            keyring = options.keyringPolicy?.();
          const mine = rows => Object.values(rows).filter(row => row.tenantId === tenant).length;
          return send(
            response,
            200,
            setupBody({
              company: options.company,
              issuer: options.oidc.issuer,
              callbackUrl: `${origin.origin}/auth/callback`,
              counts: { tickets: mine(data.tickets), requests: mine(data.requests), receipts: mine(data.receipts) },
              maintenance,
              recovery,
              keyring,
              checks: setupChecks({
                securityLog: telemetry.snapshot().securityLog,
                tlsExpiresAt,
                recovery,
                capacityWarning: maintenance.capacityWarning,
                now: Date.now(),
              }),
            }),
          );
        }
        if (request.method !== 'POST') fail('NOT_FOUND', 404);
        csrf(request, session);
        const input = await body(request);
        csrf(request, session);
        authorized(session);
        if (url.pathname === '/api/audit/export') {
          authorized(session, 'operator');
          fields(input, []);
          if (url.search) fail('INVALID_INPUT');
          return send(response, 200, exportActivity({ workflow, operator: session.operator }));
        }
        if (url.pathname === '/api/requests') {
          authorized(session, 'requester');
          return send(
            response,
            201,
            await workflow.propose(session.operator, input, () => authorized(session, 'requester')),
          );
        }
        const decision = /^\/api\/requests\/([a-zA-Z0-9-]{1,80})\/(approve|deny|withdraw|reconcile|close-out)$/.exec(
          url.pathname,
        );
        if (decision) {
          const [, id, action] = decision;
          if (action === 'reconcile') {
            authorized(session, 'operator');
            fields(input, []);
            return send(response, 200, workflow.reconcile(session.operator, id));
          }
          if (action === 'close-out') {
            authorized(session, 'operator');
            // An empty body only shows the evidence; closing needs the digest of what was shown.
            fields(input, ['digest']);
            return send(
              response,
              200,
              input.digest === undefined
                ? workflow.previewCloseOut(session.operator, id)
                : workflow.closeOut(session.operator, id, input),
            );
          }
          if (action === 'withdraw') {
            authorized(session, 'requester');
            return send(
              response,
              200,
              workflow.withdraw(session.operator, id, input, () => authorized(session, 'requester')),
            );
          }
          authorized(session, 'reviewer');
          return send(
            response,
            200,
            await workflow.decide(session.operator, id, input, action === 'approve', () =>
              authorized(session, 'reviewer'),
            ),
          );
        }
        if (url.pathname === '/api/maintenance/archive/preview') {
          authorized(session, 'operator');
          return send(response, 200, workflow.previewArchive(session.operator, input));
        }
        if (url.pathname === '/api/maintenance/archive/apply') {
          authorized(session, 'operator');
          return send(response, 200, workflow.archive(session.operator, input));
        }
        fail('NOT_FOUND', 404);
      } catch (error) {
        const capacityError = ['LIMITS_BELOW_USAGE', 'HISTORY_SEGMENT_CAPACITY', 'HISTORY_MIGRATION_REQUIRED'].includes(
          error?.code,
        );
        const code = error instanceof OpsError || capacityError ? error.code : 'SERVICE_UNAVAILABLE';
        const status = error instanceof OpsError ? error.status : capacityError ? 409 : 503;
        // Only a fixed identifier leaves the process: never a message, a path or request data.
        const cause = error instanceof OpsError || capacityError ? undefined : safeCode(error, 'UNCODED');
        const signInCode = ['AUTH_FAILED', 'FORBIDDEN', 'CSRF_INVALID', 'UNAUTHENTICATED', 'RATE_LIMITED'].includes(
          code,
        )
          ? code
          : 'SIGN_IN_UNAVAILABLE';
        if (isAuthFlow)
          securityEvent(
            'SIGN_IN_FAILED',
            requestSession,
            signInCode,
            signInCode === 'SIGN_IN_UNAVAILABLE' ? (cause ?? code) : undefined,
          );
        else if (['FORBIDDEN', 'UNAUTHENTICATED', 'CSRF_INVALID'].includes(code))
          securityEvent('ACCESS_DENIED', requestSession, code);
        // One trace for every failure the service answers with 5xx, except load shedding and shutdown.
        else if (status >= 500 && !['BUSY', 'NOT_READY'].includes(code))
          securityEvent('REQUEST_FAILED', requestSession, code, cause);
        if (isCallback && !response.destroyed && !response.writableEnded) {
          response.writeHead(status, {
            ...securityHeaders,
            'Content-Type': 'text/html; charset=utf-8',
          });
          response.end(
            '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign-in needs attention · Agent Ops</title><link rel="stylesheet" href="/app.css"><main><h1>Sign-in needs attention</h1><p>The identity could not be verified. Sign-in may have expired, or the deployment owner may need to enroll your account.</p><p><a href="/">Return to sign-in</a></p></main></html>',
          );
          return;
        }
        send(response, status, errorBody(code));
      } finally {
        release?.();
      }
    },
  );
  server.maxConnections = MAX_CONNECTIONS;
  server.keepAliveTimeout = 5000;
  // A socket with no traffic in either direction is closed, whatever state its request is in.
  server.setTimeout(SOCKET_IDLE_TIMEOUT_MS, socket => socket.destroy());
  // Counted from the TCP connection, so slow or unfinished TLS handshakes count too.
  const connections = new Map();
  server.on('connection', socket => {
    const key = clientKey(socket.remoteAddress),
      held = (connections.get(key) ?? 0) + 1;
    if (held > MAX_CONNECTIONS_PER_CLIENT) {
      socket.destroy();
      return;
    }
    connections.set(key, held);
    socket.once('close', () => {
      const left = connections.get(key) - 1;
      if (left > 0) connections.set(key, left);
      else connections.delete(key);
    });
  });
  server.on('clientError', (_error, socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? Number(origin.port || 443), options.host ?? '127.0.0.1', resolve);
  });
  return {
    server,
    publicOrigin: origin.origin,
    monitoringSummary() {
      return monitoringSummary({
        workflow,
        telemetry,
        keyring: options.keyringPolicy?.(),
        tlsExpiresAt,
        tenantIdForStatistics: bindings.values().next().value.tenantId,
      });
    },
    /** Reload rotated TLS material without a restart; existing connections keep their context. */
    replaceTls(tls) {
      const { expiresAt } = validateTls(tls, options.publicOrigin);
      server.setSecureContext({ ...tls, minVersion: 'TLSv1.2' });
      tlsExpiresAt = expiresAt;
      readiness.at = Number.NEGATIVE_INFINITY;
      securityEvent('TLS_RELOADED');
    },
    replaceBindings(values, agentValues = []) {
      const next = enroll(values),
        nextAgents = agentEnroll(agentValues);
      disjoint(next, nextAgents);
      bindings = next;
      agents = nextAgents;
      generation++;
      sessions.clear();
      flows.clear();
      securityEvent('IDENTITY_BINDINGS_RELOADED');
    },
    async close() {
      draining = true;
      clearInterval(anonymousEventTimer);
      flushAnonymousEvents(Number.POSITIVE_INFINITY);
      generation++;
      sessions.clear();
      flows.clear();
      await new Promise(resolve => server.close(resolve));
    },
  };
}
