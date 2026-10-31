import test from 'node:test';
import assert from 'node:assert/strict';
import { createCompanyQuerySession, endCompanySession, queryCompanySession, readCompanySession, retryCompanyLogout,
  startCompanyLogin, watchCompanySession } from '../src/view-model.mjs';

const csrf = `agm_csrf_v1.${'c'.repeat(43)}`;
const session = (extra = {}) => ({ mode: 'oidc', authenticated: true, csrfToken: csrf,
  expiresAt: new Date(Date.now() + 60_000).toISOString(), ...extra });
const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json', ...headers },
});

test('company discovery accepts only explicit host modes and keeps identity claims out of browser state', async () => {
  let request;
  const value = session();
  const result = await readCompanySession({ fetchImpl: async (...args) => { request = args; return json(value); } });
  assert.deepEqual(result, value); assert.ok(Object.isFrozen(result));
  assert.equal(request[0], '/auth/session'); assert.equal(request[1].method, 'GET');
  assert.equal(request[1].credentials, 'same-origin'); assert.equal(request[1].headers, undefined);
  for (const name of ['cache', 'redirect', 'referrerPolicy']) assert.equal(request[1][name], { cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' }[name]);
  assert.deepEqual(await readCompanySession({ fetchImpl: async () => json({ mode: 'bearer' }) }), { mode: 'bearer' });
  assert.equal((await readCompanySession({ fetchImpl: async () => json(session({ authenticated: false })) })).authenticated, false);
  for (const body of [{}, null, [], { mode: 'unknown' }, { mode: 'bearer', token: 'private' },
    session({ access_token: 'private-provider-token' }), session({ scope: { allTeams: true } }),
    session({ authenticated: 1 }), session({ csrfToken: [csrf] }), session({ csrfToken: 'invalid' }),
    session({ expiresAt: 'next week' }), session({ expiresAt: '2026-10-30' })]) {
    await assert.rejects(readCompanySession({ fetchImpl: async () => json(body) }), { code: 'VIEWER_SESSION_INVALID' });
  }
  await assert.rejects(readCompanySession({ fetchImpl: async () => json(session({ expiresAt: '2020-01-01T00:00:00Z' })) }), { code: 'VIEWER_SESSION_EXPIRED', status: 401 });
  for (const status of [401, 403, 404, 503]) await assert.rejects(readCompanySession({ fetchImpl: async () => json({ error: 'MAP_UNAVAILABLE' }, status) }), { status });
});

test('company query uses same-origin cookies and explicit CSRF without a bearer credential', async () => {
  let request;
  const body = { operation: 'list_agents', data: { agents: [] } };
  assert.deepEqual(await queryCompanySession(csrf, 'list_agents', { limit: 10 }, {
    fetchImpl: async (...args) => { request = args; return json(body); },
  }), body);
  assert.equal(request[0], '/v1/query'); assert.equal(request[1].method, 'POST');
  assert.equal(request[1].credentials, 'same-origin');
  assert.deepEqual(request[1].headers, { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf });
  assert.deepEqual(JSON.parse(request[1].body), { operation: 'list_agents', args: { limit: 10 } });
  const noNetwork = { fetchImpl: () => assert.fail('Invalid authentication reached transport') };
  for (const token of ['', 'agm_v1.' + 'c'.repeat(43), csrf + 'x', null, [csrf]])
    await assert.rejects(queryCompanySession(token, 'list_agents', {}, noNetwork), { code: 'VIEWER_CSRF_INVALID' });
  await assert.rejects(queryCompanySession(csrf, 'raw_cypher', {}, noNetwork), { code: 'VIEWER_OPERATION_INVALID' });
  await assert.rejects(queryCompanySession(csrf, 'list_agents', {}, { fetchImpl: async () => json({ operation: 'get_changes', data: {} }) }), { code: 'VIEWER_RESPONSE_INVALID' });
});

test('company sign-in and logout use fixed CSRF-protected routes and accept only validated results', async () => {
  const calls = [];
  const options = { fetchImpl: async (url, init) => { calls.push([url, init]); return json(url === '/auth/login' ?
    { authorizationUrl: 'https://idp.example/authorize?state=opaque&code_challenge=challenge' } : { ok: true }); } };
  assert.equal(await startCompanyLogin(csrf, options), 'https://idp.example/authorize?state=opaque&code_challenge=challenge');
  assert.equal(await endCompanySession(csrf, options), undefined);
  assert.deepEqual(calls.map(([url]) => url), ['/auth/login', '/auth/logout']);
  for (const [, init] of calls) {
    assert.equal(init.method, 'POST'); assert.equal(init.credentials, 'same-origin'); assert.equal(init.body, '{}');
    assert.deepEqual(init.headers, { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf });
    assert.equal(init.redirect, 'error'); assert.equal(init.referrerPolicy, 'no-referrer');
  }
  for (const authorizationUrl of ['http://idp.example/authorize', '//idp.example/authorize', '/auth/callback',
    'javascript:alert(1)', 'https://user:secret@idp.example/authorize', 'https://idp.example/#access_token=private',
    'https://idp.example/authorize\n', 'https://idp.example/' + 'x'.repeat(8192)]) {
    await assert.rejects(startCompanyLogin(csrf, { fetchImpl: async () => json({ authorizationUrl }) }), { code: 'VIEWER_SESSION_INVALID' });
  }
  await assert.rejects(startCompanyLogin(csrf, { fetchImpl: async () => json({ authorizationUrl: 'https://idp.example/', access_token: 'private' }) }), { code: 'VIEWER_SESSION_INVALID' });
  for (const body of [null, {}, { ok: false }, { ok: true, token: 'private' }])
    await assert.rejects(endCompanySession(csrf, { fetchImpl: async () => json(body) }), { code: 'VIEWER_SESSION_INVALID' });
});

test('authentication endpoints keep strict body bounds, safe errors, cancellation and deadlines', async () => {
  for (const invoke of [options => readCompanySession(options), options => startCompanyLogin(csrf, options), options => endCompanySession(csrf, options)]) {
    await assert.rejects(invoke({ fetchImpl: async () => json({}, 200, { 'content-length': '16385' }) }), { code: 'VIEWER_RESPONSE_LIMIT' });
    let cancelled = false;
    await assert.rejects(invoke({ fetchImpl: async () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(16385)); }, cancel() { cancelled = true; },
    }), { headers: { 'content-type': 'application/json' } }) }), { code: 'VIEWER_RESPONSE_LIMIT' });
    assert.equal(cancelled, true);
    await assert.rejects(invoke({ fetchImpl: async () => json({ error: '<script>private-provider-token</script>' }, 503) }), { code: 'REFERENCE_UNAVAILABLE', status: 503 });
    await assert.rejects(invoke({ fetchImpl: async () => new Response('secret', { headers: { 'content-type': 'text/html' } }) }), { code: 'VIEWER_RESPONSE_INVALID' });
    await assert.rejects(invoke({ timeoutMs: 5, fetchImpl: async (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }) }), { name: 'AbortError' });
    await assert.rejects(invoke({ signal: AbortSignal.abort(), fetchImpl: () => assert.fail('Pre-aborted authentication request was sent') }), { name: 'AbortError' });
  }
});

test('company authentication loss aborts sibling reads and discards queued evidence', async () => {
  for (const status of [401, 403]) {
    let release, signal, ended = 0;
    const current = createCompanyQuerySession(csrf, { onEnded: () => { ended++; }, fetchImpl: async (_url, options) => {
      if (JSON.parse(options.body).operation === 'get_inventory_health') { signal = options.signal; return new Promise(resolve => { release = resolve; }); }
      return json({ error: status === 401 ? 'MAP_UNAUTHENTICATED' : 'MAP_REQUEST_DENIED' }, status);
    } });
    const pending = current.query('get_inventory_health');
    await assert.rejects(current.query('list_agents'), { code: 'VIEWER_SESSION_ENDED' });
    assert.equal(signal.aborted, true); assert.equal(ended, 1);
    release(json({ operation: 'get_inventory_health', data: { sources: ['previous-account'] } }));
    await assert.rejects(pending, { code: 'VIEWER_SESSION_ENDED' });
    await assert.rejects(current.query('list_agents'), { code: 'VIEWER_SESSION_ENDED' });
    assert.equal(ended, 1);
  }
});

const denialBodies = [
  ['HTML', status => new Response('<html>denial-body-canary</html>', { status, headers: { 'content-type': 'text/html' } })],
  ['empty body', status => new Response(null, { status, headers: { 'content-type': 'application/json' } })],
  ['invalid JSON', status => new Response('{"error":"denial-body-canary"', { status, headers: { 'content-type': 'application/json' } })],
  ['invalid UTF-8', status => new Response(new Uint8Array([255]), { status, headers: { 'content-type': 'application/json' } })],
  ['invalid declared size', status => json({}, status, { 'content-length': 'invalid' })],
  ['oversized declared body', status => json({}, status, { 'content-length': '4194305' })],
  ['oversized streamed body', status => new Response(new Uint8Array(4 * 1024 * 1024 + 1), { status, headers: { 'content-type': 'application/json' } })],
  ['failed body read', status => new Response(new ReadableStream({
    start(controller) { controller.error(new Error('denial-body-canary')); },
  }), { status, headers: { 'content-type': 'application/json' } })],
  ['stalled body and cancellation', status => new Response(new ReadableStream({
    cancel() { return new Promise(() => {}); },
  }), { status, headers: { 'content-type': 'application/json' } })],
  ['rejected cancellation', status => new Response(new ReadableStream({
    cancel() { return Promise.reject(new Error('denial-body-canary')); },
  }), { status, headers: { 'content-type': 'application/json' } })],
  ['valid JSON', status => json({ error: 'DENIAL_BODY_CANARY' }, status)],
];

test('authentication rejection status is authoritative before denial body parsing', { timeout: 2000 }, async () => {
  for (const status of [401, 403]) for (const [name, response] of denialBodies) {
    let signal;
    await assert.rejects(queryCompanySession(csrf, 'list_agents', {}, {
      fetchImpl: async (_url, options) => { signal = options.signal; return response(status); },
    }), { code: 'REFERENCE_UNAVAILABLE', message: 'REFERENCE_UNAVAILABLE', status }, name);
    assert.equal(signal.aborted, true, name);
  }
});

test('every company denial clears evidence and cancels siblings without waiting for its body', { timeout: 2000 }, async () => {
  for (const status of [401, 403]) for (const [name, response] of denialBodies) {
    let release, siblingSignal, ended = 0, displayedEvidence = ['previous-account'];
    const current = createCompanyQuerySession(csrf, {
      onEnded: () => { ended++; displayedEvidence = []; },
      fetchImpl: async (_url, options) => {
        if (JSON.parse(options.body).operation === 'get_inventory_health') {
          siblingSignal = options.signal; return new Promise(resolve => { release = resolve; });
        }
        return response(status);
      },
    });
    const pending = current.query('get_inventory_health');
    try {
      await assert.rejects(current.query('list_agents'), { code: 'VIEWER_SESSION_ENDED' }, name);
      assert.equal(ended, 1, name); assert.deepEqual(displayedEvidence, [], name);
      assert.equal(siblingSignal.aborted, true, name);
    } finally {
      current.close();
      release(json({ operation: 'get_inventory_health', data: { sources: ['previous-account'] } }));
      await assert.rejects(pending, { code: 'VIEWER_SESSION_ENDED' }, name);
    }
    await assert.rejects(current.query('list_agents'), { code: 'VIEWER_SESSION_ENDED' }, name);
    assert.equal(ended, 1, name);
  }
});

test('ordinary query errors keep their safe codes and do not end a company session', async () => {
  for (const status of [404, 413, 429, 503]) {
    let ended = 0;
    const current = createCompanyQuerySession(csrf, { onEnded: () => { ended++; },
      fetchImpl: async (_url, options) => JSON.parse(options.body).operation === 'get_inventory_health'
        ? json({ operation: 'get_inventory_health', data: { sources: ['current-account'] } })
        : json({ error: 'MAP_UNAVAILABLE' }, status),
    });
    await assert.rejects(current.query('list_agents'), { code: 'MAP_UNAVAILABLE', status });
    assert.deepEqual((await current.query('get_inventory_health')).data.sources, ['current-account']);
    assert.equal(ended, 0); current.close();
  }
});

test('a manually closed company session cannot invalidate a replacement after a delayed authentication error', async () => {
  let release, ended = 0;
  const previous = createCompanyQuerySession(csrf, { onEnded: () => { ended++; }, fetchImpl: async () => new Promise(resolve => { release = resolve; }) });
  const pending = previous.query('list_agents'); previous.close();
  const current = createCompanyQuerySession(csrf, { fetchImpl: async () => json({ operation: 'list_agents', data: { agents: ['current-account'] } }) });
  release(json({ error: 'MAP_UNAUTHENTICATED' }, 401));
  await assert.rejects(pending, { code: 'VIEWER_SESSION_ENDED' }); assert.equal(ended, 0);
  assert.deepEqual((await current.query('list_agents')).data.agents, ['current-account']); current.close();
});

test('failed logout never discovers or reopens a company session', async () => {
  const calls = [];
  await assert.rejects(endCompanySession(csrf, { fetchImpl: async (url) => { calls.push(url); return json({ error: 'MAP_UNAVAILABLE' }, 503); } }), { status: 503 });
  assert.deepEqual(calls, ['/auth/logout']);
});

test('explicit logout retry confirms an anonymous session or uses fresh CSRF without querying inventory', async () => {
  const anonymous = session({ authenticated: false }), calls = [];
  assert.deepEqual(await retryCompanyLogout({ fetchImpl: async url => { calls.push(url); return json(anonymous); } }), anonymous);
  assert.deepEqual(calls, ['/auth/session']);
  calls.length = 0; let discovered = 0;
  const fresh = `agm_csrf_v1.${'n'.repeat(43)}`;
  assert.deepEqual(await retryCompanyLogout({ fetchImpl: async (url, options) => {
    calls.push(url);
    if (url === '/auth/session') return json(discovered++ === 0 ? session({ csrfToken: fresh }) : anonymous);
    assert.equal(url, '/auth/logout'); assert.equal(options.headers['X-CSRF-Token'], fresh); return json({ ok: true });
  } }), anonymous);
  assert.deepEqual(calls, ['/auth/session', '/auth/logout', '/auth/session']);
  await assert.rejects(retryCompanyLogout({ fetchImpl: async url => json(url === '/auth/logout' ? { ok: true } : session()) }), { code: 'VIEWER_LOGOUT_UNCONFIRMED' });
  await assert.rejects(retryCompanyLogout({ fetchImpl: async () => json({ mode: 'bearer' }) }), { code: 'VIEWER_SESSION_INVALID' });
});

function lifecycle() {
  const windowImpl = new EventTarget(), documentImpl = new EventTarget(); documentImpl.visibilityState = 'visible';
  const events = [], timers = new Map(); let now = 1000, next = 1;
  const close = watchCompanySession({ expiresAt: new Date(2000).toISOString(), windowImpl, documentImpl, now: () => now,
    onInvalidate: reason => events.push(['clear', reason]), onRevalidate: reason => events.push(['check', reason]),
    schedule: (callback, delay) => { const id = next++; timers.set(id, { callback, delay }); return id; }, cancel: id => timers.delete(id) });
  return { windowImpl, documentImpl, events, timers, close, advance: value => { now = value; } };
}
test('company session expiry clears evidence before revalidation, with canceled timers after teardown', () => {
  const l = lifecycle(); const timer = [...l.timers.values()][0]; assert.equal(timer.delay, 1000);
  l.advance(2000); timer.callback();
  assert.deepEqual(l.events, [['clear', 'expired'], ['check', 'expired']]);
  l.close(); timer.callback(); assert.equal(l.events.length, 2); assert.equal(l.timers.size, 0);
});
test('hidden and restored company pages cannot retain cached evidence without revalidation', () => {
  const l = lifecycle();
  l.documentImpl.visibilityState = 'hidden'; l.documentImpl.dispatchEvent(new Event('visibilitychange'));
  assert.deepEqual(l.events, [['clear', 'hidden']]);
  l.documentImpl.visibilityState = 'visible'; l.documentImpl.dispatchEvent(new Event('visibilitychange'));
  l.documentImpl.dispatchEvent(new Event('visibilitychange'));
  assert.deepEqual(l.events, [['clear', 'hidden'], ['check', 'hidden']]); l.close();
  const restored = lifecycle(), event = new Event('pageshow'); Object.defineProperty(event, 'persisted', { value: true });
  restored.windowImpl.dispatchEvent(event); assert.deepEqual(restored.events, [['clear', 'restored'], ['check', 'restored']]);
  restored.close(); restored.windowImpl.dispatchEvent(event); assert.equal(restored.events.length, 2);
});
