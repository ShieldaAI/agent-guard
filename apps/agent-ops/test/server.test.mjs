import nodeTest from 'node:test';
const test = (name, fn) =>
  nodeTest(
    name,
    {
      skip:
        process.platform === 'win32'
          ? 'The witnessed single-owner deployment requires POSIX; Linux is the supported runtime.'
          : false,
    },
    fn,
  );
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { httpsSetup } from './helpers.mjs';

test('real signed OIDC login, exact review, durable ticket update and authenticated archival', async t => {
  const { login, request, fixture } = await httpsSetup(t);
  assert.equal((await request('/api/tickets')).status, 401);
  const operator = await login();
  assert.equal(operator.session.operator.id, 'owner');
  const tickets = await operator.get('/api/tickets');
  assert.equal(tickets.json().tickets.length, 1);
  const proposal = await operator.post('/api/requests', { ticketId: 'T-1', status: 'resolved' });
  assert.equal(proposal.status, 201, proposal.text);
  const pending = proposal.json().request;
  const approval = await operator.post(`/api/requests/${pending.id}/approve`, { digest: pending.digest });
  assert.equal(approval.status, 200, approval.text);
  assert.equal(approval.json().request.state, 'completed');
  assert.equal(approval.json().request.reviewerId, 'owner');
  const preview = (await operator.post('/api/maintenance/archive/preview', { taskId: `ticket:${pending.id}` })).json()
    .preview;
  const archive = await operator.post('/api/maintenance/archive/apply', { id: preview.id, digest: preview.digest });
  assert.equal(archive.status, 200, archive.text);
  assert.equal(archive.json().archivedCount, 1);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  const logout = await operator.post('/auth/logout', {});
  assert.equal(logout.status, 200);
  assert.equal((await operator.get('/api/tickets')).status, 401);
});
test('roles, tenants, CSRF, strict origin and duplicate JSON keys fail closed', async t => {
  const { login, request, origin, fixture } = await httpsSetup(t);
  const requester = await login('requester'),
    owner = await login(),
    foreign = await login('foreign');
  const pending = (await requester.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
  assert.equal((await requester.post(`/api/requests/${pending.id}/approve`, { digest: pending.digest })).status, 403);
  assert.equal((await requester.get('/api/maintenance')).status, 403);
  assert.equal((await foreign.post(`/api/requests/${pending.id}/approve`, { digest: pending.digest })).status, 404);
  assert.equal(
    (
      await owner.post(
        `/api/requests/${pending.id}/approve`,
        { digest: pending.digest },
        { Origin: 'https://attacker.invalid' },
      )
    ).status,
    403,
  );
  assert.equal(
    (await owner.post(`/api/requests/${pending.id}/approve`, { digest: pending.digest }, { 'X-CSRF-Token': 'wrong' }))
      .status,
    403,
  );
  assert.equal(
    (await request('/api/tickets', { headers: { Cookie: owner.cookie, 'X-Forwarded-User': 'owner' } })).status,
    400,
  );
  assert.equal(
    (
      await request('/api/requests', {
        method: 'POST',
        headers: {
          Cookie: owner.cookie,
          Origin: origin,
          'X-CSRF-Token': owner.session.csrfToken,
          'Content-Type': 'application/json',
        },
        body: '{"ticketId":"T-1","ticketId":"T-2","status":"resolved"}',
      })
    ).status,
    400,
  );
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
});
test('identity reload revokes existing sessions and agent proposals cannot approve or access other resources', async t => {
  const token = randomBytes(32).toString('base64url');
  const { login, request, app, config, fixture } = await httpsSetup(t, {
    server: { agents: [{ id: 'worker-1', tenantId: 'acme', token, allowedTicketIds: ['T-1'] }] },
  });
  const operator = await login();
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  const proposal = await request('/agent/requests', {
    method: 'POST',
    headers,
    body: JSON.stringify({ ticketId: 'T-1', status: 'resolved' }),
  });
  assert.equal(proposal.status, 201, proposal.text);
  assert.equal(proposal.json().request.requesterId, 'worker-1');
  assert.equal(
    (
      await request(`/agent/requests/${proposal.json().request.id}`, { headers: { Authorization: `Bearer ${token}` } })
    ).json().request.state,
    'pending',
  );
  const human = (await operator.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
  assert.equal(
    (await request(`/agent/requests/${human.id}`, { headers: { Authorization: `Bearer ${token}` } })).status,
    404,
  );
  // No existence oracle: outside the allowlist a foreign ticket and a nonexistent one get the same answer.
  const outside = [];
  for (const ticketId of ['T-2', 'T-404'])
    outside.push(
      await request('/agent/requests', {
        method: 'POST',
        headers,
        body: JSON.stringify({ ticketId, status: 'resolved' }),
      }),
    );
  assert.deepEqual(
    outside.map(result => [result.status, result.text]),
    [
      [403, outside[0].text],
      [403, outside[0].text],
    ],
  );
  assert.equal(outside[0].json().error.code, 'FORBIDDEN');
  assert.equal(
    (await request(`/api/requests/${proposal.json().request.id}/approve`, { method: 'POST', headers, body: '{}' }))
      .status,
    403,
  );
  app.replaceBindings(config.bindings, []);
  assert.equal((await operator.get('/api/tickets')).status, 401);
  assert.equal(
    (
      await request('/agent/requests', {
        method: 'POST',
        headers,
        body: JSON.stringify({ ticketId: 'T-1', status: 'resolved' }),
      })
    ).status,
    401,
  );
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
});
test('login callbacks are browser-bound, single-use and reject unenrolled or invalid identities', async t => {
  const { request, provider, origin } = await httpsSetup(t);
  async function begin() {
    const initial = await request('/api/session'),
      cookie = initial.headers['set-cookie'][0].split(';')[0];
    assert.match(initial.headers['set-cookie'][0], /Secure; HttpOnly; SameSite=Lax/);
    const login = await request('/auth/login', {
      method: 'POST',
      headers: {
        Cookie: cookie,
        Origin: origin,
        'X-CSRF-Token': initial.json().csrfToken,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    assert.equal(login.status, 200, login.text);
    const renewed = login.headers['set-cookie'][0];
    assert.match(renewed, /^__Host-agent_ops=a\.[^;]+; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=300$/);
    return { stale: cookie, cookie: renewed.split(';')[0], authorizationUrl: login.json().authorizationUrl };
  }
  const first = await begin(),
    second = await begin(),
    callback = await provider.authorize(first.authorizationUrl, { subject: 'owner' });
  assert.equal(
    (await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: second.cookie } })).status,
    401,
  );
  // The flow is bound to the cookie renewed at sign-in start, so an old page never outlives its flow.
  assert.notEqual(first.cookie, first.stale);
  assert.equal(
    (await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: first.stale } })).status,
    401,
  );
  assert.equal(
    (await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: first.cookie } })).status,
    303,
  );
  assert.equal(
    (await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: first.cookie } })).status,
    401,
  );
  const outsider = await begin(),
    outsiderCallback = await provider.authorize(outsider.authorizationUrl, { subject: 'not-enrolled' });
  const rejected = await request(`${outsiderCallback.pathname}${outsiderCallback.search}`, {
    headers: { Cookie: outsider.cookie },
  });
  assert.equal(rejected.status, 403);
  assert.match(rejected.text, /Return to sign-in/);
  assert.equal(rejected.text.includes(outsiderCallback.searchParams.get('code')), false);
});
test('sessions expire, responses expose no credentials and static UI has restrictive CSP', async t => {
  const { login, request, provider } = await httpsSetup(t, { server: { sessionTtlMs: 1000 } });
  const operator = await login(),
    page = await request('/');
  assert.equal(page.status, 200);
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.match(page.headers['content-security-policy'], /script-src 'self'/);
  const sessionText = JSON.stringify(operator.session);
  assert.equal(sessionText.includes(provider.clientSecret), false);
  assert.equal(sessionText.includes('id_token'), false);
  await new Promise(resolve => setTimeout(resolve, 1050));
  assert.equal((await operator.get('/api/tickets')).status, 401);
  const ready = await request('/health/ready');
  assert.deepEqual(ready.json(), { status: 'ok' });
});
test('setup is operator-only, exposes only safe configuration and pages company data past the old cap', async t => {
  const tickets = Array.from({ length: 505 }, (_, i) => ({
    id: `T-${String(i).padStart(4, '0')}`,
    tenantId: 'acme',
    title: 'Company ticket',
    status: 'open',
  }));
  tickets.push({ id: 'PRIVATE', tenantId: 'other', title: 'Foreign company data', status: 'open' });
  const fixture = await httpsSetup(t, { tickets, limits: { maxTickets: 1000, maxRetainedKeys: 8 } });
  const operator = await fixture.login(),
    requester = await fixture.login('requester');
  assert.equal((await fixture.request('/api/setup')).status, 401);
  assert.equal((await requester.get('/api/setup')).status, 403);
  const settings = (await operator.get('/api/setup')).json();
  assert.equal(settings.deployment, 'self-hosted');
  assert.equal(settings.data.tickets, 505);
  assert.deepEqual(settings.historyCapacity, { committed: 0, reserved: 0, total: 0, limit: 10_000 });
  assert.equal(settings.recovery.mode, 'current-state-mirror');
  for (const key of ['executorMirror', 'backendMirror', 'historyMirror']) assert.equal(settings.recovery[key], true);
  assert.ok(Number.isSafeInteger(settings.recovery.verifiedAt));
  assert.equal(settings.limits.maxTickets, 1000);
  assert.deepEqual(settings.keyring, { keyCount: 1, maxKeys: 8 });
  assert.equal(
    settings.commands.every(item => item.command.includes('"${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}"')),
    true,
  );
  assert.match(settings.commands[0].command, /run --rm onboarding preflight/);
  const text = JSON.stringify(settings);
  for (const secret of [
    fixture.provider.clientSecret,
    fixture.provider.key,
    fixture.fixture.config.keyringFile,
    fixture.fixture.config.backendDatabase,
  ])
    assert.equal(text.includes(secret), false);
  const first = (await operator.get('/api/tickets?limit=500&offset=0')).json();
  const next = (await operator.get(`/api/tickets?offset=${first.nextOffset}`)).json();
  assert.equal(first.tickets.length, 500);
  assert.equal(next.tickets.length, 5);
  assert.equal(next.total, 505);
  assert.equal(
    [...first.tickets, ...next.tickets].some(ticket => ticket.id === 'PRIVATE'),
    false,
  );
  for (const query of ['offset=-1', 'offset=1.2', 'offset=01', 'limit=501', 'offset=0&offset=1', 'tenantId=other']) {
    const result = await operator.get(`/api/tickets?${query}`);
    assert.equal(result.status, 400, query);
  }
});

test('setup explicitly distinguishes legacy recovery and unreported host verification', async t => {
  for (const options of [{ mirror: false }, { server: { recovery: undefined } }]) {
    const fixture = await httpsSetup(t, options),
      operator = await fixture.login();
    const recovery = (await operator.get('/api/setup')).json().recovery;
    if (options.mirror === false) {
      assert.equal(recovery.mode, 'not-enrolled');
      for (const key of ['executorMirror', 'backendMirror', 'historyMirror']) assert.equal(recovery[key], false);
      assert.ok(recovery.verifiedAt > 0);
    } else assert.deepEqual(recovery, { mode: 'unverified', verifiedAt: null });
  }
});

test('pagination accepts only exact fields and rejects reserved, duplicate and malformed query keys', async t => {
  const fixture = await httpsSetup(t),
    operator = await fixture.login();
  const prototypeKeys = Object.getOwnPropertyNames(Object.prototype);
  for (const path of ['/api/tickets', '/api/requests']) {
    for (const query of ['offset=0&limit=1', 'limit=1&offset=0']) {
      const result = await operator.get(`${path}?${query}`);
      assert.equal(result.status, 200, result.text);
      assert.equal(result.json().offset, 0);
      assert.equal(result.json().limit, 1);
    }
    for (const query of [
      '__proto__=1',
      'constructor=1',
      'prototype=1',
      'toString=1',
      '%5F%5Fproto%5F%5F=1',
      'offset%5B__proto__%5D=1',
      'offset=0&offset=1',
      'limit=1&limit=2',
      'Offset=0',
      'offset=-1',
      'offset=01',
      'offset=1.0',
      'offset=1e2',
      'limit=0',
      'limit=501',
    ]) {
      const result = await operator.get(`${path}?${query}`);
      assert.equal(result.status, 400, `${path}?${query}: ${result.text}`);
      assert.equal(
        result.json().error.code,
        ['limit=0', 'limit=501'].includes(query) ? 'PAGINATION_INVALID' : 'INVALID_INPUT',
      );
    }
  }
  assert.deepEqual(Object.getOwnPropertyNames(Object.prototype), prototypeKeys);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
});

async function beginSignIn({ request, origin }) {
  const initial = await request('/api/session'),
    cookie = initial.headers['set-cookie'][0].split(';')[0];
  const login = await request('/auth/login', {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: origin,
      'X-CSRF-Token': initial.json().csrfToken,
      'Content-Type': 'application/json',
    },
    body: '{}',
  });
  return {
    status: login.status,
    cookie: login.headers['set-cookie']?.[0].split(';')[0],
    authorizationUrl: login.status === 200 ? login.json().authorizationUrl : undefined,
  };
}
test('abandoned sign-ins behind one address evict the oldest instead of locking everyone out', async t => {
  const fixture = await httpsSetup(t),
    { request, provider } = fixture;
  // Four people behind one proxy address start and abandon a sign-in; the fifth must still get in.
  const flows = [];
  for (let index = 0; index < 5; index++) flows.push(await beginSignIn(fixture));
  assert.deepEqual(
    flows.map(flow => flow.status),
    [200, 200, 200, 200, 200],
  );
  const complete = async flow => {
    const callback = await provider.authorize(flow.authorizationUrl, { subject: 'owner' });
    return (await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: flow.cookie } })).status;
  };
  assert.equal(await complete(flows[0]), 401, 'only the oldest pending flow gave way');
  assert.equal(await complete(flows[1]), 303);
  assert.equal(await complete(flows[4]), 303);
});
test('the per-address sign-in cap, rate limit and session lifetime are configurable within safe bounds', async t => {
  const fixture = await httpsSetup(t, { server: { signInFlowsPerClient: 1, rateLimitPerMinute: 60 } }),
    { request, provider } = fixture;
  const first = await beginSignIn(fixture),
    second = await beginSignIn(fixture);
  const callback = await provider.authorize(first.authorizationUrl, { subject: 'owner' });
  assert.equal(
    (await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: first.cookie } })).status,
    401,
  );
  const kept = await provider.authorize(second.authorizationUrl, { subject: 'owner' });
  assert.equal((await request(`${kept.pathname}${kept.search}`, { headers: { Cookie: second.cookie } })).status, 303);
  let last;
  for (let index = 0; index < 60; index++) last = await request('/health/ready');
  assert.equal(last.status, 429, 'the configured 60 per minute applies');
  for (const [server, code] of [
    [{ signInFlowsPerClient: 0 }, 'SIGN_IN_CONFIG_INVALID'],
    [{ signInFlowsPerClient: 129 }, 'SIGN_IN_CONFIG_INVALID'],
    [{ rateLimitPerMinute: 59 }, 'RATE_LIMIT_CONFIG_INVALID'],
    [{ sessionTtlMs: 15 * 60_000 + 1 }, 'SESSION_CONFIG_INVALID'],
  ])
    await assert.rejects(httpsSetup(t, { server }), { code }, code);
});
test('an unparseable request target is a client error and an unexpected failure leaves one coded trace', async t => {
  const events = [],
    fixture = await httpsSetup(t, { server: { onSecurityEvent: event => events.push(event) } }),
    operator = await fixture.login();
  for (const target of ['//', '//?x=1', 'https://[', '*']) {
    const refused = await fixture.raw(target);
    assert.equal(refused.status, 400, target);
    assert.equal(refused.json().error.code, 'REQUEST_ORIGIN_INVALID');
  }
  assert.equal((await operator.get('/api/status')).json().http.lifetime.serverErrors, 0);
  assert.deepEqual(
    events.filter(event => event.event === 'REQUEST_FAILED'),
    [],
  );
  const tickets = fixture.workflow.tickets.bind(fixture.workflow);
  fixture.workflow.tickets = () => {
    throw Object.assign(Error('PRIVATE store detail /srv/data/tickets.sqlite'), { code: 'STORE_CORRUPT' });
  };
  const failed = await operator.get('/api/tickets');
  assert.equal(failed.status, 503);
  assert.equal(failed.json().error.code, 'SERVICE_UNAVAILABLE');
  fixture.workflow.tickets = () => {
    throw Object.assign(Error('PRIVATE'), { code: 'not a safe code: /srv/data' });
  };
  assert.equal((await operator.get('/api/tickets')).status, 503);
  fixture.workflow.tickets = tickets;
  assert.deepEqual(
    events.filter(event => event.event === 'REQUEST_FAILED'),
    [
      {
        event: 'REQUEST_FAILED',
        operatorId: 'owner',
        tenantId: 'acme',
        code: 'SERVICE_UNAVAILABLE',
        cause: 'STORE_CORRUPT',
      },
      { event: 'REQUEST_FAILED', operatorId: 'owner', tenantId: 'acme', code: 'SERVICE_UNAVAILABLE', cause: 'UNCODED' },
    ],
  );
  assert.equal(/PRIVATE|srv/.test(JSON.stringify(events)), false);
  assert.equal(/PRIVATE|srv/.test(failed.text), false);
  // An ordinary refusal is not a server failure and leaves no such event.
  assert.equal((await operator.get('/api/tickets?limit=0')).status, 400);
  assert.equal(events.filter(event => event.event === 'REQUEST_FAILED').length, 2);
});
test('close-out over HTTP is operator-only, previews without a digest and never touches a request that is not unconfirmed', async t => {
  const fixture = await httpsSetup(t),
    operator = await fixture.login(),
    requester = await fixture.login('requester');
  const pending = (await requester.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
  assert.equal((await requester.post(`/api/requests/${pending.id}/close-out`, {})).status, 403);
  const refused = await operator.post(`/api/requests/${pending.id}/close-out`, {});
  assert.equal(refused.status, 409);
  assert.equal(refused.json().error.code, 'RECONCILIATION_UNAVAILABLE');
  assert.equal((await operator.post(`/api/requests/${pending.id}/close-out`, { other: 1 })).status, 400);
  // The state a crash leaves between the recorded approval and the dispatch.
  fixture.runtime.backend.transaction(state => {
    Object.assign(state.ticketService.requests[pending.id], { state: 'dispatching', reviewerId: 'owner' });
  });
  const missing = await operator.post(`/api/requests/${pending.id}/reconcile`, {});
  assert.equal(missing.json().error.code, 'RECEIPT_NOT_FOUND');
  const preview = (await operator.post(`/api/requests/${pending.id}/close-out`, {})).json().closeOut;
  assert.equal(preview.receipt, 'absent');
  assert.equal((await operator.get('/api/requests')).json().requests[0].state, 'unconfirmed');
  const stale = await operator.post(`/api/requests/${pending.id}/close-out`, { digest: '0'.repeat(64) });
  assert.equal(stale.json().error.code, 'CLOSE_OUT_STALE');
  const closed = await operator.post(`/api/requests/${pending.id}/close-out`, { digest: preview.digest });
  assert.equal(closed.status, 200, closed.text);
  assert.deepEqual([closed.json().request.state, closed.json().request.cause], ['failed', 'CLOSED_WITHOUT_RECEIPT']);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
});
