import { createServer } from 'node:https';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createMapOidcClient } from '@shieldaai/agent-map/oidc';
import { parseEvidenceJson } from '@shieldaai/agent-guard-executor/internal';
import { OpsError, fail, fields, identifier } from './workflow.mjs';
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
const FLOWS_PER_CLIENT = 4;
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
const messages = {
  UNAUTHENTICATED: 'Your session expired or was revoked. Sign in again.',
  FORBIDDEN: 'Your enrolled role does not permit this action.',
  CSRF_INVALID: 'The page is out of date. Refresh before trying again.',
  AUTH_FAILED: 'Sign-in could not be verified. Start a new sign-in.',
  REVIEW_STALE: 'This review changed or was already used. Refresh the request.',
  REVIEW_EXPIRED: 'This review expired. Create a new request.',
  TICKET_CHANGED: 'The ticket changed after review. Create a new request for its current version.',
  NO_CHANGE: 'This ticket already has that status.',
  RECEIPT_NOT_FOUND: 'No matching receipt is available. The outcome remains unconfirmed. Do not retry the change.',
  ARCHIVE_PREVIEW_STALE: 'The archive preview expired or state changed. Preview again.',
  RECORD_CAPACITY_REACHED:
    'The durable record limit was reached. Ask the deployment owner to follow the capacity runbook.',
  LIMITS_BELOW_USAGE:
    'The configured storage capacity cannot accept this change. Ask the deployment owner to review capacity offline; retained records will not be deleted.',
  HISTORY_SEGMENT_CAPACITY:
    'History recovery capacity is exhausted. Stop new compaction and ask the deployment owner for a reviewed migration plan. Preserve all records, history, witnesses and keys.',
  HISTORY_MIGRATION_REQUIRED:
    'History exceeds this recovery profile. Stop maintenance changes and ask the deployment owner for a reviewed compatible recovery or migration plan. Preserve all records, history, witnesses and keys.',
  RATE_LIMITED: 'Too many requests. Wait a minute and try again.',
  INVALID_INPUT: 'Check the requested values.',
};
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
    return { operator: structuredClone(operator), tokenHash: digest(token) };
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
    draining = false,
    active = 0;
  const disjoint = (humans, machines) => {
    const ids = new Set([...humans.values()].map(value => value.id));
    if (machines.some(value => ids.has(value.operator.id))) fail('IDENTITY_CONFIG_INVALID');
  };
  disjoint(bindings, agents);
  const ttl = options.sessionTtlMs ?? 15 * 60_000;
  if (!Number.isSafeInteger(ttl) || ttl < 1000 || ttl > 15 * 60_000) fail('SESSION_CONFIG_INVALID');
  const rateLimit = options.rateLimitPerMinute ?? 180;
  if (!Number.isSafeInteger(rateLimit) || rateLimit < 60 || rateLimit > 100_000) fail('RATE_LIMIT_CONFIG_INVALID');
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
  const assets = new Map(
    [
      ['/', ['text/html; charset=utf-8', 'index.html']],
      ['/app.js', ['text/javascript; charset=utf-8', 'app.js']],
      ['/app.css', ['text/css; charset=utf-8', 'app.css']],
    ].map(([path, [type, file]]) => [path, { type, body: readFileSync(new URL(`./public/${file}`, import.meta.url)) }]),
  );
  const securityHeaders = {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'Strict-Transport-Security': 'max-age=31536000',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
  function securityEvent(event, session, code) {
    const actor = session && valid(session) ? session.operator : undefined;
    const value = Object.freeze({
      event,
      ...(actor ? { operatorId: actor.id, tenantId: actor.tenantId } : {}),
      ...(code ? { code } : {}),
    });
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
      let counted = false,
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
        const url = new URL(request.url, origin);
        isCallback = url.pathname === '/auth/callback' && request.method === 'GET';
        isAuthFlow = isCallback || (url.pathname === '/auth/login' && request.method === 'POST');
        if (url.origin !== origin.origin || !request.url?.startsWith('/')) fail('REQUEST_ORIGIN_INVALID', 400);
        if (request.method === 'GET' && url.pathname === '/health/live') return send(response, 200, { status: 'ok' });
        if (draining) fail('NOT_READY', 503);
        if (active >= 32) fail('BUSY', 503);
        active++;
        counted = true;
        limit(request);
        if (request.method === 'GET' && url.pathname === '/health/ready') {
          if (Date.now() >= tlsExpiresAt) fail('TLS_CERTIFICATE_EXPIRED', 503);
          workflow.health();
          return send(response, 200, { status: 'ok' });
        }
        if (request.method === 'GET' && assets.has(url.pathname) && !url.search) {
          const asset = assets.get(url.pathname);
          response.writeHead(200, { ...securityHeaders, 'Content-Type': asset.type });
          return response.end(asset.body);
        }
        const agentRequest = /^\/agent\/requests\/([a-zA-Z0-9-]{1,80})$/.exec(url.pathname);
        if (
          (url.pathname === '/agent/requests' && request.method === 'POST') ||
          (agentRequest && request.method === 'GET')
        ) {
          if (request.headers.cookie || request.headers.origin) fail('FORBIDDEN', 403);
          const match = /^Bearer ([A-Za-z0-9_-]{43,128})$/.exec(request.headers.authorization ?? '');
          const agent = match && agents.find(value => timingSafeEqual(value.tokenHash, digest(match[1])));
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
            return send(response, 200, { request: workflow.public(item) });
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
          return send(response, 200, {
            authenticated: !!session.operator,
            csrfToken: session.csrfToken,
            authorizationOrigins,
            publicAuthIssuer: options.oidc.issuer,
            ...(session.operator ? { operator: session.operator, expiresAt: session.expiresAt } : {}),
          });
        }
        if (url.pathname === '/auth/callback' && request.method === 'GET') {
          const stateValues = url.searchParams.getAll('state'),
            flow = stateValues.length === 1 && flows.get(stateValues[0]);
          if (
            !flow ||
            !session ||
            flow.sessionId !== session.id ||
            flow.generation !== generation ||
            flow.expiresAt <= Date.now() ||
            flow.busy
          )
            fail('AUTH_FAILED', 401);
          flow.busy = true;
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
          fields(await body(request), []);
          csrf(request, session);
          cleanup();
          const client = clientKey(request.socket.remoteAddress);
          for (const [id, flow] of flows) if (flow.sessionId === session.id) flows.delete(id);
          if ([...flows.values()].filter(flow => flow.client === client).length >= FLOWS_PER_CLIENT)
            fail('RATE_LIMITED', 429);
          if (flows.size >= 128) fail('LOGIN_CAPACITY_REACHED', 503);
          const transaction = await oidc.begin();
          csrf(request, session);
          flows.set(transaction.state, {
            transaction,
            sessionId: session.id,
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
        if (request.method === 'GET' && url.pathname === '/api/requests')
          return send(response, 200, workflow.requests(session.operator.tenantId, pageScope(url)));
        if (request.method === 'GET' && url.pathname === '/api/maintenance') {
          authorized(session, 'operator');
          return send(response, 200, {
            ...workflow.maintenance(session.operator),
            ...(options.keyringPolicy ? { keyring: options.keyringPolicy() } : {}),
          });
        }
        if (request.method === 'GET' && url.pathname === '/api/setup') {
          authorized(session, 'operator');
          workflow.health();
          const maintenance = workflow.maintenance(session.operator),
            tenant = session.operator.tenantId;
          const data = workflow.data();
          const observed = options.recovery;
          const verified =
            observed &&
            ['current-state-mirror', 'not-enrolled'].includes(observed.mode) &&
            Number.isSafeInteger(observed.verifiedAt) &&
            observed.verifiedAt > 0 &&
            ['executorMirror', 'backendMirror', 'historyMirror'].every(key => typeof observed[key] === 'boolean');
          const recovery = verified
            ? {
                mode:
                  observed.executorMirror && observed.backendMirror && observed.historyMirror
                    ? 'current-state-mirror'
                    : 'not-enrolled',
                executorMirror: observed.executorMirror,
                backendMirror: observed.backendMirror,
                historyMirror: observed.historyMirror,
                verifiedAt: observed.verifiedAt,
              }
            : { mode: 'unverified', verifiedAt: null };
          return send(response, 200, {
            deployment: 'self-hosted',
            ...(options.company
              ? { company: { id: options.company.id, ...(options.company.name ? { name: options.company.name } : {}) } }
              : {}),
            identity: { issuer: options.oidc.issuer, callbackUrl: `${origin.origin}/auth/callback` },
            data: {
              kind: 'local-tickets',
              tickets: Object.values(data.tickets).filter(t => t.tenantId === tenant).length,
              requests: Object.values(data.requests).filter(r => r.tenantId === tenant).length,
              receipts: Object.values(data.receipts).filter(r => r.tenantId === tenant).length,
            },
            limits: maintenance.limits,
            usage: maintenance.usage,
            historyCapacity: maintenance.historyCapacity,
            recovery,
            ...(options.keyringPolicy ? { keyring: options.keyringPolicy() } : {}),
            checks: [
              {
                id: 'identity',
                label: 'Company sign-in',
                status: 'passed',
                message: 'OIDC discovery and this signed-in identity were verified.',
              },
              {
                id: 'storage',
                label: 'Private durable storage',
                status: 'passed',
                message: 'Both encrypted stores and their independent witnesses are readable.',
              },
              {
                id: 'ownership',
                label: 'Company data ownership',
                status: 'passed',
                message:
                  'Ticket records and encrypted execution evidence stay in this installation. Sign-in uses your configured identity provider.',
              },
            ],
            commands: [
              {
                label: 'Check configuration and OIDC discovery',
                command:
                  'docker compose -f deployment/production/compose.yaml run --rm onboarding preflight --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}"',
              },
              {
                label: 'Preview a company ticket import (stop the service first)',
                command:
                  'docker compose -f deployment/production/compose.yaml run --rm onboarding import-tickets --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}" --tickets /run/company/additional-tickets.json',
              },
              {
                label: 'Preview changed capacity limits (stop the service first)',
                command:
                  'docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance apps/agent-ops/cli.mjs configure-limits --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}"',
              },
            ],
          });
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
        const decision = /^\/api\/requests\/([a-zA-Z0-9-]{1,80})\/(approve|deny|reconcile)$/.exec(url.pathname);
        if (decision) {
          const [, id, action] = decision;
          if (action === 'reconcile') {
            authorized(session, 'operator');
            fields(input, []);
            return send(response, 200, workflow.reconcile(session.operator, id));
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
        if (isAuthFlow)
          securityEvent(
            'SIGN_IN_FAILED',
            requestSession,
            ['AUTH_FAILED', 'FORBIDDEN', 'CSRF_INVALID', 'UNAUTHENTICATED', 'RATE_LIMITED'].includes(code)
              ? code
              : 'SIGN_IN_UNAVAILABLE',
          );
        else if (['FORBIDDEN', 'UNAUTHENTICATED', 'CSRF_INVALID'].includes(code))
          securityEvent('ACCESS_DENIED', requestSession, code);
        if (isCallback && !response.destroyed && !response.writableEnded) {
          response.writeHead(error instanceof OpsError ? error.status : 503, {
            ...securityHeaders,
            'Content-Type': 'text/html; charset=utf-8',
          });
          response.end(
            '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign-in needs attention · Agent Ops</title><link rel="stylesheet" href="/app.css"><main><h1>Sign-in needs attention</h1><p>The identity could not be verified. Sign-in may have expired, or the deployment owner may need to enroll your account.</p><p><a href="/">Return to sign-in</a></p></main></html>',
          );
          return;
        }
        send(response, error instanceof OpsError ? error.status : capacityError ? 409 : 503, {
          error: {
            code,
            message:
              messages[code] ?? 'The operation could not complete. Refresh its status before taking another action.',
          },
        });
      } finally {
        if (counted) active--;
      }
    },
  );
  server.maxConnections = 128;
  server.keepAliveTimeout = 5000;
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
      generation++;
      sessions.clear();
      flows.clear();
      await new Promise(resolve => server.close(resolve));
    },
  };
}
