import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';
import { MapService } from '../dist/service.js';
import { startMapIdentityServer } from '../dist/identity-http.js';
import { createTestIdentityProvider } from './helpers/oidc-provider.mjs';

const SESSION = '__Host-agm_session';
const LOGIN = '__Host-agm_login';
const scope = (subject = 'user-one', team = 'blue') => ({ subject, companyId: 'company',
  tenantIds: ['alpha'], teamIds: [team], allTeams: false });
const queryBody = { operation: 'list_agents', args: {} };
const plain = value => JSON.parse(JSON.stringify(value));

// Deliberately use real verified TLS; no process-wide trust or cookie bypass flags.
function browser(url, ca) {
  const cookies = new Map();
  async function send(path, { method = 'GET', body, headers = {}, rawHeaders, cookie, applyCookies = true } = {}) {
    const payload = body === undefined ? undefined : typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body);
    const selectedCookies = cookie === undefined ? [...cookies].map(([name, value]) => `${name}=${value}`).join('; ') : cookie;
    const normalHeaders = { ...(selectedCookies ? { Cookie: selectedCookies } : {}),
      ...(method === 'POST' ? { Origin: url, 'Content-Type': 'application/json' } : {}),
      ...(payload === undefined ? {} : { 'Content-Length': Buffer.byteLength(payload) }), ...headers };
    return new Promise((resolve, reject) => {
      const request = httpsRequest(new URL(path, url), { ca, rejectUnauthorized: true, agent: false,
        // Keep TLS identity verification independent of deliberately hostile HTTP Host headers.
        servername: 'localhost', family: 4, method, headers: rawHeaders ?? normalHeaders }, response => {
        const chunks = []; let size = 0;
        response.on('data', chunk => { size += chunk.length; if (size > 3 * 1024 * 1024) response.destroy(new Error('TEST_RESPONSE_TOO_LARGE')); else chunks.push(chunk); });
        response.on('error', reject);
        response.once('end', () => {
          const text = Buffer.concat(chunks).toString();
          const setCookies = response.headers['set-cookie'] ?? [];
          if (applyCookies) for (const header of setCookies) {
            const [pair] = header.split(';'); const separator = pair.indexOf('=');
            const name = pair.slice(0, separator), value = pair.slice(separator + 1);
            if (!value || /(?:^|;)\s*Max-Age=0(?:;|$)/i.test(header)) cookies.delete(name); else cookies.set(name, value);
          }
          let data = null; try { data = JSON.parse(text); } catch { /* Redirect/static responses are not JSON. */ }
          resolve({ status: response.statusCode, headers: response.headers, setCookies, text, data });
        });
      });
      request.setTimeout(8000, () => request.destroy(new Error('TEST_TIMEOUT')));
      request.on('error', reject);
      request.end(payload);
    });
  }
  return { send, cookies };
}

async function setup(t, options = {}, read = async () => ({ sources: [] })) {
  const provider = await createTestIdentityProvider(t);
  const calls = [];
  const inputBindings = [{ subject: 'user-one', scope: scope() }, { subject: 'user-two', scope: scope('user-two', 'red') }];
  const server = await startMapIdentityServer({
    service: new MapService({ read: async (...args) => { calls.push(args); return read(...args); } }),
    publicOrigin: 'https://127.0.0.1:0', port: 0, listenHost: '127.0.0.1',
    tls: { cert: provider.cert, key: provider.key }, companyId: 'company', bindings: inputBindings,
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret, ca: provider.ca },
    ...options,
  });
  t.after(() => server.close());
  const client = browser(server.url, provider.ca);
  const bootstrap = async (selected = client) => {
    const result = await selected.send('/auth/session'); assert.equal(result.status, 200, result.text);
    assert.equal(result.data.mode, 'oidc'); assert.match(result.data.csrfToken, /^agm_csrf_v1\.[A-Za-z0-9_-]{43}$/);
    return result;
  };
  const begin = async (selected = client) => {
    const session = await bootstrap(selected);
    const result = await selected.send('/auth/login', { method: 'POST', body: {}, headers: { 'X-CSRF-Token': session.data.csrfToken } });
    return { session, ...result };
  };
  const login = async (overrides = {}, selected = client) => {
    const begun = await begin(selected); assert.equal(begun.status, 200, begun.text);
    const callback = await provider.authorize(begun.data.authorizationUrl, { subject: 'user-one', ...overrides });
    const response = await selected.send(callback.pathname + callback.search);
    return { begun, callback, response };
  };
  const query = async (csrfToken, body = queryBody, extra = {}) => client.send('/v1/query', {
    method: 'POST', body, headers: { 'X-CSRF-Token': csrfToken }, ...extra,
  });
  return { ...server, provider, client, calls, inputBindings, bootstrap, begin, login, query };
}

function assertPrivateCookie(value) {
  assert.match(value, /;\s*Secure(?:;|$)/i); assert.match(value, /;\s*HttpOnly(?:;|$)/i);
  assert.match(value, /;\s*Path=\/(?:;|$)/i); assert.match(value, /;\s*SameSite=(?:Lax|Strict)(?:;|$)/i);
  assert.doesNotMatch(value, /;\s*Domain=/i);
}

async function authenticated(t, options, read) {
  const s = await setup(t, options, read);
  const logged = await s.login(); assert.equal(logged.response.status, 303, logged.response.text);
  assert.equal(logged.response.headers.location, '/');
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  return { ...s, session, logged };
}

test('identity listener configuration rejects ambiguous origins and scopes before contacting the provider', async t => {
  const provider = await createTestIdentityProvider(t);
  const base = { service: new MapService({ read: async () => ({ sources: [] }) }),
    publicOrigin: 'https://127.0.0.1:0', port: 0, tls: { cert: provider.cert, key: provider.key },
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret, ca: provider.ca },
    companyId: 'company', bindings: [{ subject: 'user-one', scope: scope() }] };
  for (const changed of [{ publicOrigin: 'http://127.0.0.1:0' }, { publicOrigin: 'https://127.0.0.1:0/path' },
    { publicOrigin: 'https://127.0.0.1:0?ignored=1' }, { publicOrigin: 'https://127.0.0.1' },
    { listenHost: '0.0.0.0' }, { companyId: '' }, { bindings: [base.bindings[0], base.bindings[0]] },
    { bindings: [{ subject: 'user-one', scope: { ...scope(), companyId: 'other-company' } }] },
    { bindings: [{ subject: 'user-one', scope: { ...scope(), teamIds: [] } }] },
    { tls: { cert: 'invalid-certificate', key: 'invalid-private-key' } }, { trustProxy: true }]) {
    await assert.rejects(async () => {
      const server = await startMapIdentityServer({ ...base, ...changed });
      await server.close();
    }, error => /^MAP_(?:CONFIG|SCOPE)_INVALID$/.test(error.code));
  }
  assert.equal(provider.requests.length, 0);
});

test('HTTPS OIDC login rotates private browser session and queries the immutable host scope', async t => {
  const s = await setup(t);
  const begun = await s.begin(); assert.equal(begun.status, 200, begun.text);
  assert.equal(begun.session.data.authenticated, false);
  const originalSession = s.client.cookies.get(SESSION);
  for (const cookie of [...begun.session.setCookies, ...begun.setCookies]) assertPrivateCookie(cookie);
  const authorization = new URL(begun.data.authorizationUrl);
  assert.equal(authorization.searchParams.get('response_type'), 'code');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorization.searchParams.get('redirect_uri'), s.url + '/auth/callback');
  assert.ok(authorization.searchParams.get('nonce')); assert.ok(authorization.searchParams.get('state'));
  const callback = await s.provider.authorize(authorization, { subject: 'user-one' });
  const response = await s.client.send(callback.pathname + callback.search, { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate' } });
  assert.equal(response.status, 303); assert.equal(response.headers.location, '/');
  assert.notEqual(s.client.cookies.get(SESSION), originalSession); assert.equal(s.client.cookies.has(LOGIN), false);
  response.setCookies.forEach(assertPrivateCookie);
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  assert.notEqual(session.data.csrfToken, begun.session.data.csrfToken);
  assert.deepEqual(Object.keys(session.data).sort(), ['authenticated', 'csrfToken', 'expiresAt', 'mode']);
  s.inputBindings[0].scope.tenantIds.push('hidden'); s.inputBindings[0].scope.companyId = 'attacker';
  const result = await s.query(session.data.csrfToken); assert.equal(result.status, 200, result.text);
  assert.deepEqual(plain(s.calls[0][0]), scope()); assert.ok(Object.isFrozen(s.calls[0][0]));
  assert.equal(result.headers['cache-control'], 'no-store'); assert.equal(result.headers['access-control-allow-origin'], undefined);
  assert.equal(result.headers['x-content-type-options'], 'nosniff');
  assert.match(result.headers['strict-transport-security'], /max-age=/);
  for (const text of [session.text, result.text, response.text, JSON.stringify(response.headers)]) {
    assert.equal(text.includes(s.provider.clientSecret), false); assert.equal(text.includes('access_token'), false);
    assert.equal(text.includes('id_token'), false); assert.equal(text.includes('refresh_token'), false);
  }
  assert.equal((await s.query(session.data.csrfToken, { ...queryBody, scope: scope('attacker') })).status, 400);
  assert.equal((await s.query(session.data.csrfToken, { operation: 'run_cypher', args: {} })).status, 400);
  assert.equal(s.calls.length, 1);
});

test('unmapped signed identity cannot acquire a scope or use the query endpoint', async t => {
  const s = await setup(t);
  const { response } = await s.login({ subject: 'unmapped-subject' });
  assert.equal(response.status, 303); assert.equal(response.headers.location, '/?auth_error=1');
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, false);
  assert.equal((await s.query(session.data.csrfToken)).status, 401); assert.equal(s.calls.length, 0);
});

test('a second mapped identity receives only its own explicit binding', async t => {
  const s = await setup(t);
  const { response } = await s.login({ subject: 'user-two' }); assert.equal(response.status, 303);
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  assert.equal((await s.query(session.data.csrfToken)).status, 200);
  assert.deepEqual(plain(s.calls[0][0]), scope('user-two', 'red'));
});

test('signed provider organization and group claims cannot broaden the host binding', async t => {
  const s = await setup(t);
  const { response } = await s.login({ extraClaims: { companyId: 'other-company', tenantIds: ['hidden'],
    teamIds: ['administrators'], allTeams: true, groups: ['global-admins'], email: 'owner@example.invalid' } });
  assert.equal(response.headers.location, '/');
  const session = await s.bootstrap(); assert.equal((await s.query(session.data.csrfToken)).status, 200);
  assert.deepEqual(plain(s.calls[0][0]), scope());
  assert.equal(session.text.includes('global-admins'), false); assert.equal(session.text.includes('owner@example.invalid'), false);
});

test('session expiry never outlives the verified identity token', async t => {
  const s = await setup(t); const expiresAt = Date.now() + 10_000;
  const { response } = await s.login({ expiresAt }); assert.equal(response.headers.location, '/');
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  assert.ok(Date.parse(session.data.expiresAt) <= Math.floor(expiresAt / 1000) * 1000);
});

test('session cookies alone or CSRF tokens alone cannot query, start login or log out', async t => {
  const s = await authenticated(t);
  for (const path of ['/v1/query', '/auth/login', '/auth/logout']) {
    const body = path === '/v1/query' ? queryBody : {};
    for (const headers of [{}, { 'X-CSRF-Token': 'agm_csrf_v1.' + 'a'.repeat(43) }]) {
      assert.equal((await s.client.send(path, { method: 'POST', body, headers })).status, 403, path);
    }
    const absentCookie = await s.client.send(path, { method: 'POST', body,
      cookie: '', applyCookies: false, headers: { 'X-CSRF-Token': s.session.data.csrfToken } });
    assert.equal(absentCookie.status, 401, path);
  }
  assert.equal(s.calls.length, 0);
  assert.equal((await s.query(s.session.data.csrfToken)).status, 200);
});

test('exact Host and Origin are required and forwarded authority never grants trust', async t => {
  const s = await authenticated(t);
  for (const headers of [{ Origin: 'https://attacker.invalid' }, { Origin: 'null' }, { Origin: '' },
    { Host: 'attacker.invalid' }, { 'Sec-Fetch-Site': 'cross-site' },
    { Forwarded: `host=${new URL(s.url).host};proto=https` }, { 'X-Forwarded-Host': new URL(s.url).host },
    { 'X-Forwarded-Proto': 'https' }, { 'Proxy-Authorization': 'Bearer private-canary' },
    { Authorization: 'Bearer agm_v1.' + 'a'.repeat(43) }]) {
    const result = await s.query(s.session.data.csrfToken, queryBody, { headers: { 'X-CSRF-Token': s.session.data.csrfToken, ...headers } });
    assert.equal(result.status, 403, JSON.stringify(headers));
  }
  for (const path of ['/v1/query?scope=all', '/mcp', '/admin', '/auth/login?returnTo=https://attacker.invalid']) {
    assert.ok([400, 403, 404].includes((await s.client.send(path, { method: 'POST', body: {}, headers: { 'X-CSRF-Token': s.session.data.csrfToken } })).status), path);
  }
  assert.equal(s.calls.length, 0);
});

test('duplicate cookies, CSRF, Origin and Host headers cannot select ambiguous credentials', async t => {
  const s = await authenticated(t); const body = JSON.stringify(queryBody), host = new URL(s.url).host;
  const cookie = `${SESSION}=${s.client.cookies.get(SESSION)}`;
  const base = ['Host', host, 'Origin', s.url, 'Cookie', cookie, 'X-CSRF-Token', s.session.data.csrfToken,
    'Content-Type', 'application/json', 'Content-Length', String(Buffer.byteLength(body))];
  for (const addition of [['Cookie', cookie], ['X-CSRF-Token', s.session.data.csrfToken], ['Origin', s.url], ['Host', host]]) {
    const result = await s.client.send('/v1/query', { method: 'POST', body, rawHeaders: [...base, ...addition], applyCookies: false });
    assert.ok([400, 401, 403].includes(result.status));
  }
  const duplicateName = await s.query(s.session.data.csrfToken, queryBody, { cookie: `${cookie}; ${cookie}`, applyCookies: false });
  assert.ok([400, 401, 403].includes(duplicateName.status)); assert.equal(s.calls.length, 0);
});

test('callbacks require browser-bound single-use state and reject duplicate parameters', async t => {
  const s = await setup(t);
  const begun = await s.begin(); const callback = await s.provider.authorize(begun.data.authorizationUrl, { subject: 'user-one' });
  const outsider = browser(s.url, s.provider.ca); await s.bootstrap(outsider);
  const unbound = await outsider.send(callback.pathname + callback.search);
  assert.notEqual(unbound.headers.location, '/');
  const duplicate = new URL(callback); duplicate.searchParams.append('state', callback.searchParams.get('state'));
  const bad = await s.client.send(duplicate.pathname + duplicate.search);
  assert.notEqual(bad.headers.location, '/'); assert.notEqual(bad.status, 200);
  const retry = await s.client.send(callback.pathname + callback.search);
  assert.notEqual(retry.headers.location, '/');
  assert.equal((await s.bootstrap()).data.authenticated, false);
});

test('successful callback cannot be replayed and prior anonymous cookie cannot use the session', async t => {
  const s = await setup(t); const begun = await s.begin();
  const anonymous = s.client.cookies.get(SESSION);
  const callback = await s.provider.authorize(begun.data.authorizationUrl, { subject: 'user-one' });
  const originalCookies = [...s.client.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  const good = await s.client.send(callback.pathname + callback.search); assert.equal(good.headers.location, '/');
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  const replay = await s.client.send(callback.pathname + callback.search, { cookie: originalCookies, applyCookies: false });
  assert.notEqual(replay.headers.location, '/');
  const stolenOld = await s.query(begun.session.data.csrfToken, queryBody, { cookie: `${SESSION}=${anonymous}`, applyCookies: false });
  assert.equal(stolenOld.status, 401); assert.equal(s.calls.length, 0);
});

test('local logout invalidates the old cookie and does not call a provider logout endpoint', async t => {
  const s = await authenticated(t);
  const cookie = `${SESSION}=${s.client.cookies.get(SESSION)}`; const before = s.provider.requests.length;
  const result = await s.client.send('/auth/logout', { method: 'POST', body: {}, headers: { 'X-CSRF-Token': s.session.data.csrfToken } });
  assert.equal(result.status, 200); assert.deepEqual(result.data, { ok: true }); assert.equal(s.client.cookies.has(SESSION), false);
  result.setCookies.forEach(assertPrivateCookie);
  assert.equal(s.provider.requests.length, before);
  assert.equal((await s.query(s.session.data.csrfToken, queryBody, { cookie, applyCookies: false })).status, 401);
  assert.equal((await s.bootstrap()).data.authenticated, false);
});

test('expired login transactions and sessions never regain authentication', async t => {
  const s = await setup(t, { loginTtlMs: 1000, sessionTtlMs: 1000 });
  const begun = await s.begin(); const callback = await s.provider.authorize(begun.data.authorizationUrl, { subject: 'user-one' });
  await sleep(1100); const expired = await s.client.send(callback.pathname + callback.search);
  assert.notEqual(expired.headers.location, '/');
  const fresh = await s.login(); assert.equal(fresh.response.headers.location, '/');
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  await sleep(1100); assert.equal((await s.query(session.data.csrfToken)).status, 401);
  assert.equal((await s.bootstrap()).data.authenticated, false); assert.equal(s.calls.length, 0);
});

test('host policy replacement is atomic, immutable and invalidates existing sessions', async t => {
  const s = await authenticated(t);
  assert.throws(() => s.replaceBindings([{ subject: 'user-one', scope: { ...scope(), companyId: 'different-company' } }]), { code: 'MAP_CONFIG_INVALID' });
  assert.equal((await s.query(s.session.data.csrfToken)).status, 200);
  const replacement = [{ subject: 'user-one', scope: scope('user-one', 'replacement-team') }];
  s.replaceBindings(replacement); replacement[0].scope.teamIds.push('hidden');
  assert.equal((await s.query(s.session.data.csrfToken)).status, 401);
  const fresh = await s.login(); assert.equal(fresh.response.headers.location, '/');
  const session = await s.bootstrap(); assert.equal((await s.query(session.data.csrfToken)).status, 200);
  assert.deepEqual(s.calls.at(-1)[0].teamIds, ['replacement-team']);
});

test('subject revocation removes the binding and invalidates sessions and unfinished login', async t => {
  const s = await authenticated(t);
  const otherBrowser = browser(s.url, s.provider.ca); const pending = await s.begin(otherBrowser);
  const callback = await s.provider.authorize(pending.data.authorizationUrl, { subject: 'user-one' });
  s.revokeSubject('user-one');
  assert.equal((await s.query(s.session.data.csrfToken)).status, 401);
  const oldFlow = await otherBrowser.send(callback.pathname + callback.search); assert.notEqual(oldFlow.headers.location, '/');
  const next = await s.login(); assert.notEqual(next.response.headers.location, '/');
  assert.equal(s.calls.length, 0);
});

test('policy revocation during token exchange cannot create a late authenticated session', async t => {
  const s = await setup(t); const begun = await s.begin();
  const callback = await s.provider.authorize(begun.data.authorizationUrl, { subject: 'user-one' });
  s.provider.controls.tokenDelayMs = 150;
  const pending = s.client.send(callback.pathname + callback.search);
  const deadline = Date.now() + 2000;
  while (!s.provider.requests.some(item => item.path === '/token') && Date.now() < deadline) await sleep(5);
  assert.ok(s.provider.requests.some(item => item.path === '/token'));
  s.revokeSubject('user-one');
  const response = await pending; assert.notEqual(response.headers.location, '/');
  assert.equal((await s.bootstrap()).data.authenticated, false); assert.equal(s.calls.length, 0);
});

test('disconnect during token exchange cannot leave an authenticated orphan occupying session capacity', async t => {
  const s = await setup(t, { maxSessions: 1, loginTtlMs: 1000, sessionTtlMs: 5000 });
  const begun = await s.begin(); assert.equal(begun.status, 200);
  const callback = await s.provider.authorize(begun.data.authorizationUrl, { subject: 'user-one' });
  s.provider.controls.tokenDelayMs = 150;
  let request;
  const disconnected = new Promise(resolve => {
    request = httpsRequest(callback, { ca: s.provider.ca, rejectUnauthorized: true, agent: false, servername: 'localhost',
      headers: { Cookie: [...s.client.cookies].map(([name, value]) => `${name}=${value}`).join('; ') } }, response => {
      response.resume(); response.once('end', () => resolve({ status: response.statusCode }));
    });
    request.once('error', error => resolve({ error: error.code })); request.end();
  });
  const deadline = Date.now() + 2000;
  while (!s.provider.requests.some(item => item.path === '/token') && Date.now() < deadline) await sleep(5);
  assert.ok(s.provider.requests.some(item => item.path === '/token'));
  request.destroy(); assert.deepEqual(await disconnected, { error: 'ECONNRESET' });
  // The original anonymous session expires, but a wrongly minted authenticated
  // session would occupy the single slot for another four seconds.
  await sleep(1100);
  const fresh = browser(s.url, s.provider.ca);
  const session = await s.bootstrap(fresh);
  assert.equal(session.data.authenticated, false); assert.equal(s.calls.length, 0);
});

test('revocation while a query is pending prevents release of its completed response', async t => {
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const blocked = new Promise(resolve => { release = resolve; });
  const s = await authenticated(t, {}, async () => { entered(); await blocked; return { sources: [] }; });
  const pending = s.query(s.session.data.csrfToken); await started;
  s.revokeSubject('user-one'); release();
  const result = await pending; assert.equal(result.status, 401); assert.equal(result.data.error, 'MAP_SESSION_REQUIRED');
});

test('logout while a query is pending prevents release after its session ends', async t => {
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const blocked = new Promise(resolve => { release = resolve; });
  const s = await authenticated(t, {}, async () => { entered(); await blocked; return { sources: [] }; });
  const pending = s.query(s.session.data.csrfToken); await started;
  const logout = await s.client.send('/auth/logout', { method: 'POST', body: {}, headers: { 'X-CSRF-Token': s.session.data.csrfToken } });
  assert.equal(logout.status, 200); release();
  assert.equal((await pending).status, 401);
});

test('host session invalidation blocks pending reads but permits a fresh mapped login', async t => {
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const blocked = new Promise(resolve => { release = resolve; });
  const s = await authenticated(t, {}, async () => { entered(); await blocked; return { sources: [] }; });
  const pending = s.query(s.session.data.csrfToken); await started;
  s.invalidateSessions(); release();
  assert.equal((await pending).status, 401);
  assert.equal((await s.query(s.session.data.csrfToken)).status, 401);
  const next = await s.login(); assert.equal(next.response.headers.location, '/');
  const fresh = await s.bootstrap(); assert.equal(fresh.data.authenticated, true);
  assert.equal((await s.query(fresh.data.csrfToken)).status, 200);
});

test('closing the listener promptly drops an unfinished read and refuses new connections', async t => {
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const blocked = new Promise(resolve => { release = resolve; });
  const s = await authenticated(t, {}, async () => { entered(); await blocked; return { sources: [] }; });
  const pending = s.query(s.session.data.csrfToken).then(response => ({ response }), error => ({ error }));
  await started;
  try { await s.close(); } finally { release(); }
  const result = await pending;
  assert.equal(result.response, undefined);
  assert.equal(result.error.code, 'ECONNRESET');
  await assert.rejects(s.client.send('/auth/session'), { code: 'ECONNREFUSED' });
  await s.close();
});

test('session and login capacities fail closed without evicting an active user', async t => {
  const s = await setup(t, { maxSessions: 2, maxLoginTransactions: 1 });
  const first = await s.begin(); assert.equal(first.status, 200);
  const second = browser(s.url, s.provider.ca); const secondSession = await s.bootstrap(second);
  const overFlow = await second.send('/auth/login', { method: 'POST', body: {}, headers: { 'X-CSRF-Token': secondSession.data.csrfToken } });
  assert.equal(overFlow.status, 503);
  const third = browser(s.url, s.provider.ca); assert.equal((await third.send('/auth/session')).status, 503);
  const callback = await s.provider.authorize(first.data.authorizationUrl, { subject: 'user-one' });
  assert.equal((await s.client.send(callback.pathname + callback.search)).headers.location, '/');
  const session = await s.bootstrap(); assert.equal(session.data.authenticated, true);
  assert.equal((await s.query(session.data.csrfToken)).status, 200);
});

test('malformed, oversized and compressed query bodies are rejected before graph reads', async t => {
  const s = await authenticated(t, { maxRequestBytes: 512 });
  for (const body of ['{"operation":"list_agents","operation":"get_changes","args":{}}',
    '{"operation":"list_agents","args":{}} trailing', new Uint8Array([0xff]),
    '[{"operation":"list_agents","args":{}}]']) assert.equal((await s.query(s.session.data.csrfToken, body)).status, 400);
  assert.equal((await s.query(s.session.data.csrfToken, ' '.repeat(513))).status, 413);
  assert.equal((await s.query(s.session.data.csrfToken, queryBody, { headers: { 'X-CSRF-Token': s.session.data.csrfToken, 'Content-Encoding': 'gzip' } })).status, 400);
  assert.equal(s.calls.length, 0);
});

test('query response size and backend errors produce bounded safe errors', async t => {
  const current = { id: 'current', snapshotId: 'snapshot', generatedAt: new Date().toISOString(), status: 'published',
    coverage: { tasks: { status: 'visible_scope' } }, edges: [], nodes: [{ id: 'agent', entityId: 'agent',
      sourceId: 'source', projectionId: 'current', label: 'GuardAgent', properties: { agent_id: 'agent', name: 'x'.repeat(600), team_id: 'blue' } }] };
  const small = await authenticated(t, { maxResponseBytes: 512 }, async () => ({ sources: [{ id: 'source',
    sourceId: 'executor', tenantId: 'alpha', profile: 'host', current, previous: null }] }));
  const oversized = await small.query(small.session.data.csrfToken);
  assert.equal(oversized.status, 413); assert.equal(oversized.data.error, 'MAP_RESPONSE_TOO_LARGE');
  const failed = await authenticated(t, {}, async () => { throw new Error('backend-private-token-canary'); });
  const response = await failed.query(failed.session.data.csrfToken);
  assert.equal(response.status, 503); assert.equal(response.text.includes('backend-private-token-canary'), false);
});

test('request deadline and concurrency bound pending reads without leaving a usable late response', async t => {
  let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const blocked = new Promise(resolve => { release = resolve; });
  const s = await authenticated(t, { maxConcurrentRequests: 1, requestTimeoutMs: 1000 }, async () => { entered(); await blocked; return { sources: [] }; });
  const pending = s.query(s.session.data.csrfToken); await started;
  assert.equal((await s.client.send('/auth/session')).status, 503);
  const result = await pending; assert.equal(result.status, 408); release();
  await sleep(10);
  assert.equal((await s.bootstrap()).data.authenticated, true);
});

test('global rate limits bound unauthenticated bootstrap requests', async t => {
  const s = await setup(t, { rateLimit: { maxRequests: 1, windowMs: 60_000 } });
  assert.equal((await s.client.send('/auth/session')).status, 200);
  const result = await s.client.send('/auth/session'); assert.equal(result.status, 429);
  assert.equal(result.headers['cache-control'], 'no-store');
});

test('HTTPS identity listener rejects plaintext and does not offer an HTTP downgrade', async t => {
  const s = await setup(t);
  const result = await new Promise(resolve => {
    const insecure = new URL(s.url); insecure.protocol = 'http:';
    const request = httpRequest(insecure, { method: 'GET', agent: false }, response => { response.resume(); response.once('end', () => resolve(response.statusCode)); });
    request.setTimeout(1000, () => request.destroy()); request.on('error', () => resolve(null)); request.end();
  });
  assert.notEqual(result, 200); assert.notEqual(result, 301); assert.notEqual(result, 302);
  const untrusted = await new Promise(resolve => {
    const request = httpsRequest(s.url + '/auth/session', { agent: false }, response => { response.resume(); response.once('end', () => resolve(null)); });
    request.on('error', error => resolve(error.code)); request.end();
  });
  assert.ok(['SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(untrusted));
});
