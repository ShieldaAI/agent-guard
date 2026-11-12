// Reviewer-facing behaviour of the service and its resistance to idle or anonymous load.
import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { createAdmission, makeRoomForSignIn, validateIdentityEnrollment } from '../server.mjs';
import { setup, owner, httpsSetup } from './helpers.mjs';

const test = (name, fn) =>
  nodeTest(name, { skip: process.platform === 'win32' ? 'The witnessed deployment requires POSIX.' : false }, fn);
const reviewer = { id: 'reviewer-alice', tenantId: 'acme', roles: ['reviewer'] };

test('a requester withdraws their own pending request; nobody else can, and nothing is applied', async t => {
  const fixture = setup(t),
    workflow = fixture.workflow;
  const { request } = await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  assert.throws(() => workflow.withdraw({ ...owner, id: 'someone-else' }, request.id, { digest: request.digest }), {
    code: 'WITHDRAW_FORBIDDEN',
    status: 409,
  });
  assert.throws(() => workflow.withdraw(owner, request.id, { digest: 'f'.repeat(64) }), { code: 'REVIEW_STALE' });
  assert.throws(() => workflow.withdraw(owner, request.id, { digest: request.digest, reason: 'x' }), {
    code: 'INVALID_INPUT',
  });
  const withdrawn = workflow.withdraw(owner, request.id, { digest: request.digest }).request;
  assert.equal(withdrawn.state, 'withdrawn');
  await assert.rejects(workflow.decide(reviewer, request.id, { digest: request.digest }, true), {
    code: 'REVIEW_STALE',
  });
  assert.throws(() => workflow.withdraw(owner, request.id, { digest: request.digest }), { code: 'REVIEW_STALE' });
  assert.equal(workflow.tickets('acme').tickets[0].version, 1);
  assert.equal(workflow.data().audit.at(-1).event, 'WITHDRAWN');
  // A withdrawn request is finished: it can be archived like a denied one.
  const preview = workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }).preview;
  assert.deepEqual(preview.blockers, []);
  assert.equal(workflow.archive(owner, { id: preview.id, digest: preview.digest }).archivedCount, 1);
});

test('a denial reason is stored for people and withheld from the agent unless the policy shares it', async t => {
  const token = randomBytes(32).toString('base64url');
  const agents = [{ id: 'worker-1', tenantId: 'acme', token, allowedTicketIds: ['T-1'] }];
  for (const shareDenialReason of [false, true]) {
    const fixture = await httpsSetup(t, { requests: { shareDenialReason }, server: { agents } });
    const person = await fixture.login();
    const agentHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
    // Every answer that carries a request to the agent applies the policy, the proposal's too.
    const shaped = [],
      shape = fixture.workflow.public.bind(fixture.workflow);
    fixture.workflow.public = (request, options) => {
      shaped.push(options?.forAgent === true);
      return shape(request, options);
    };
    const proposed = (
      await fixture.request('/agent/requests', {
        method: 'POST',
        headers: agentHeaders,
        body: JSON.stringify({ ticketId: 'T-1', status: 'resolved' }),
      })
    ).json().request;
    assert.equal(proposed.requesterKind, 'agent');
    assert.deepEqual(shaped, [true]);
    const path = `/api/requests/${proposed.id}`;
    for (const reason of ['x'.repeat(281), 'two\nlines', 7, { text: 'no' }])
      assert.equal((await person.post(`${path}/deny`, { digest: proposed.digest, reason })).status, 400);
    assert.equal(
      (await person.post(`${path}/approve`, { digest: proposed.digest, reason: 'ok' })).status,
      400,
      'approval takes no reason',
    );
    const denied = (await person.post(`${path}/deny`, { digest: proposed.digest, reason: '  Wrong ticket  ' })).json();
    assert.equal(denied.request.state, 'denied');
    assert.equal(denied.request.denialReason, 'Wrong ticket');
    assert.equal((await person.get('/api/requests')).json().requests[0].denialReason, 'Wrong ticket');
    const seenByAgent = (
      await fixture.request(`/agent/requests/${proposed.id}`, { headers: { Authorization: `Bearer ${token}` } })
    ).json().request;
    assert.equal(seenByAgent.state, 'denied');
    assert.equal(seenByAgent.denialReason, shareDenialReason ? 'Wrong ticket' : undefined);
    // The reason is not an activity-log field.
    assert.equal(JSON.stringify(fixture.workflow.data().audit).includes('Wrong ticket'), false);
    const own = (await person.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
    assert.equal(own.requesterKind, 'person');
    assert.equal(
      (await person.post(`/api/requests/${own.id}/deny`, { digest: own.digest })).json().request.denialReason,
      undefined,
    );
  }
});

test('the session carries the self-approval policy and withdrawal works over HTTP for the requester only', async t => {
  const fixture = await httpsSetup(t, { requests: { forbidSelfApproval: true } });
  const person = await fixture.login(),
    other = await fixture.login('requester');
  assert.deepEqual(person.session.policy, { forbidSelfApproval: true });
  assert.equal((await fixture.request('/api/session')).json().policy, undefined, 'nothing before sign-in');
  const request = (await person.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
  const approve = await person.post(`/api/requests/${request.id}/approve`, { digest: request.digest });
  assert.equal(approve.json().error.code, 'SELF_APPROVAL_FORBIDDEN');
  const refused = await other.post(`/api/requests/${request.id}/withdraw`, { digest: request.digest });
  assert.equal(refused.status, 409);
  assert.equal(refused.json().error.code, 'WITHDRAW_FORBIDDEN');
  assert.match(refused.json().error.message, /Only the requester/);
  const done = await person.post(`/api/requests/${request.id}/withdraw`, { digest: request.digest });
  assert.equal(done.json().request.state, 'withdrawn');
});

test('an unchanged request list is answered with 304 and the detail reads back the stored action', async t => {
  const fixture = await httpsSetup(t);
  const person = await fixture.login(),
    foreign = await fixture.login('foreign');
  const list = (path, etag) =>
    fixture.request(path, { headers: { Cookie: person.cookie, ...(etag ? { 'If-None-Match': etag } : {}) } });
  const empty = await list('/api/requests');
  assert.equal(empty.status, 200);
  assert.match(empty.headers.etag, /^"[A-Za-z0-9_-]{32}"$/);
  const unchanged = await list('/api/requests', empty.headers.etag);
  assert.equal(unchanged.status, 304);
  assert.equal(unchanged.text, '');
  assert.equal(unchanged.headers['cache-control'], 'no-store');
  assert.notEqual((await list('/api/requests?offset=1')).headers.etag, empty.headers.etag, 'a tag names one page');
  assert.notEqual((await foreign.get('/api/requests')).headers.etag, empty.headers.etag, 'and one tenant');
  const request = (await person.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
  const changed = await list('/api/requests', empty.headers.etag);
  assert.equal(changed.status, 200);
  assert.equal(changed.json().requests[0].id, request.id);
  assert.equal((await list('/api/requests', changed.headers.etag)).status, 304);

  const detail = (await person.get(`/api/requests/${request.id}`)).json();
  assert.deepEqual(detail.request, request);
  assert.deepEqual(detail.action, {
    tool: 'ticket.update',
    resourceId: 'T-1',
    resourceVersion: '1',
    status: 'PREPARED',
    matchesRequest: true,
  });
  assert.equal((await foreign.get(`/api/requests/${request.id}`)).status, 404);
  assert.equal((await person.get(`/api/requests/${request.id}?x=1`)).status, 400);
  await person.post(`/api/requests/${request.id}/deny`, { digest: request.digest });
  assert.equal((await person.get(`/api/requests/${request.id}`)).json().action, undefined);
  assert.equal((await list('/api/requests', changed.headers.etag)).status, 200);
});

test('a review deadline passing changes the list revision without any write', async t => {
  // The workflow keeps the clock it was built with, so the mocked clock is installed first.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const fixture = setup(t);
  const workflow = fixture.workflow;
  const { request } = await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  const before = workflow.requestsRevision('acme');
  assert.equal(workflow.requestsRevision('acme'), before);
  assert.equal(
    workflow.requestsRevision('other'),
    before,
    'the store revision is shared; the lapsed count is per tenant',
  );
  t.mock.timers.setTime(request.expiresAt + 1);
  assert.equal(workflow.requests('acme').requests[0].state, 'expired');
  assert.notEqual(workflow.requestsRevision('acme'), before);
  assert.equal(workflow.requestsRevision('other'), before);
});

test('reads share one decoded, frozen view per committed state and still notice outside changes', async t => {
  const fixture = setup(t),
    workflow = fixture.workflow,
    store = fixture.runtime.backend;
  let reads = 0;
  const read = store.read.bind(store);
  store.read = () => {
    reads++;
    return read();
  };
  workflow.requests('acme');
  workflow.tickets('acme');
  workflow.maintenance(owner);
  workflow.data();
  assert.ok(reads <= 1, `one decode for four reads, not ${reads}`);
  assert.throws(() => {
    workflow.data().tickets['T-1'].status = 'resolved';
  }, TypeError);
  await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  reads = 0;
  assert.equal(workflow.requests('acme').total, 1, 'a committed write is visible');
  assert.equal(workflow.maintenance(owner).records, 1);
  assert.equal(reads, 0, 'and was decoded once, when the workflow answered the proposal');
  // A change made behind the workflow (as the offline tools do) is seen too, with one new decode.
  store.transaction(state => {
    state.ticketService.tickets['T-1'].title = 'Renamed';
  });
  reads = 0;
  assert.equal(workflow.tickets('acme').tickets[0].title, 'Renamed');
  assert.equal(workflow.tickets('acme').total, 1);
  assert.equal(reads, 1);
  reads = 0;
  workflow.health();
  workflow.health();
  assert.equal(reads, 2, 'a health check always performs the full verified read');
});

test('one archive rule: a request still being prepared is never offered, previewed or auto-archived', async t => {
  const fixture = setup(t, { requests: { autoArchiveAfterDays: 1 } }),
    workflow = fixture.workflow;
  const { request } = await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  await workflow.decide(reviewer, request.id, { digest: request.digest }, false);
  const candidates = () => workflow.maintenance(owner).archiveCandidates;
  assert.deepEqual(candidates(), [
    {
      taskId: `ticket:${request.id}`,
      requestId: request.id,
      ticketId: 'T-1',
      state: 'denied',
      requesterId: 'owner',
      createdAt: request.createdAt,
    },
  ]);
  fixture.runtime.backend.transaction(state => {
    Object.assign(state.ticketService.requests[request.id], { state: 'preparing', createdAt: 1 });
  });
  assert.equal(workflow.requests('acme').requests[0].state, 'review_required', 'shown as needing a new request');
  assert.deepEqual(candidates(), []);
  assert.equal(workflow.maintenance(owner).archiveCandidatesTruncated, false);
  assert.throws(() => workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }), {
    code: 'ARCHIVE_UNAVAILABLE',
  });
  assert.deepEqual(workflow.autoArchive(), { archived: 0, skipped: 0 });
});

test('enrollment refuses identifiers reserved for the service itself', () => {
  const person = { subject: 's', id: 'owner', tenantId: 'acme', roles: ['operator'] },
    token = randomBytes(32).toString('base64url');
  assert.deepEqual(validateIdentityEnrollment([person]), { operators: 1, agents: 0 });
  assert.throws(() => validateIdentityEnrollment([{ ...person, id: 'system:retention' }]), {
    code: 'IDENTITY_CONFIG_INVALID',
  });
  assert.throws(
    () =>
      validateIdentityEnrollment(
        [person],
        [{ id: 'system:agent', tenantId: 'acme', token, allowedTicketIds: ['T-1'] }],
      ),
    { code: 'IDENTITY_CONFIG_INVALID' },
  );
});

test('refusals without a signed-in person are logged once per kind and then counted', async t => {
  const events = [],
    fixture = await httpsSetup(t, { server: { onSecurityEvent: event => events.push(event) } });
  const person = await fixture.login('requester');
  for (let index = 0; index < 25; index++) assert.equal((await fixture.request('/api/tickets')).status, 401);
  for (let index = 0; index < 3; index++) assert.equal((await person.get('/api/status')).status, 403);
  const denied = events.filter(event => event.event === 'ACCESS_DENIED');
  assert.deepEqual(denied, [
    { event: 'ACCESS_DENIED', code: 'UNAUTHENTICATED' },
    ...Array(3).fill({ event: 'ACCESS_DENIED', operatorId: 'requester', tenantId: 'acme', code: 'FORBIDDEN' }),
  ]);
  // The remaining 24 are reported in one line when the window closes (here: at shutdown).
  await fixture.app.close();
  assert.deepEqual(events.at(-1), { event: 'ACCESS_DENIED', code: 'UNAUTHENTICATED', count: 24 });
});

test('one address holds only its share of the anonymous slots; signed-in people and health probes still get through', async t => {
  const fixture = await httpsSetup(t),
    person = await fixture.login();
  const { port } = new URL(fixture.origin);
  const initial = await fixture.request('/api/session'),
    cookie = initial.headers['set-cookie'][0].split(';')[0];
  let health = 0;
  const check = fixture.workflow.health.bind(fixture.workflow);
  fixture.workflow.health = () => {
    health++;
    return check();
  };
  // Sixteen sign-in posts from one address that announce a body and never send it. Four hold a
  // slot until the body deadline; the other twelve are refused at once and hold nothing.
  const answers = [];
  const held = Array.from({ length: 16 }, () => {
    const pending = httpsRequest({
      host: '127.0.0.1',
      port,
      path: '/auth/login',
      method: 'POST',
      ca: fixture.provider.ca,
      servername: 'localhost',
      agent: false,
      headers: {
        Host: `localhost:${port}`,
        Cookie: cookie,
        Origin: fixture.origin,
        'X-CSRF-Token': initial.json().csrfToken,
        'Content-Type': 'application/json',
        'Content-Length': 2,
      },
    });
    pending.on('error', () => {});
    pending.on('response', response => {
      answers.push(response.statusCode);
      response.resume();
    });
    pending.flushHeaders();
    return pending;
  });
  t.after(() => held.forEach(pending => pending.destroy()));
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.deepEqual(answers, Array(12).fill(503), 'everything beyond the per-address share is refused immediately');
  const anonymous = await fixture.request('/api/session');
  assert.equal(anonymous.status, 503, 'the same address is over its share');
  assert.equal(anonymous.json().error.code, 'BUSY');
  assert.equal((await person.get('/api/tickets')).status, 200, 'a signed-in session has reserved slots');
  for (let index = 0; index < 5; index++) assert.equal((await fixture.request('/health/ready')).status, 200);
  assert.equal(health, 1, 'readiness probes share one verified read for a short time');
  assert.equal((await fixture.request('/health/live')).status, 200);
});

test('in-flight admission: an address cannot take the anonymous slots of other addresses', () => {
  const admission = createAdmission(),
    busy = { code: 'BUSY', status: 503 };
  const one = Array.from({ length: 4 }, () => admission.enter(true, '192.0.2.1'));
  assert.throws(() => admission.enter(true, '192.0.2.1'), busy, 'a fifth anonymous request from the same address');
  // Other addresses still get their own share, up to the anonymous total of sixteen.
  const others = [];
  for (const client of ['192.0.2.2', '2001:db8:0:1::/64', '192.0.2.3'])
    for (let index = 0; index < 4; index++) others.push(admission.enter(true, client));
  assert.throws(() => admission.enter(true, '192.0.2.4'), busy, 'the anonymous half is full');
  // Signed-in people and agents use the other half whatever the anonymous load is.
  const known = Array.from({ length: 16 }, () => admission.enter(false, '192.0.2.1'));
  assert.throws(() => admission.enter(false, '192.0.2.9'), busy, 'every slot is taken');
  known.forEach(release => release());
  // A released slot is free again, and releasing twice frees it once.
  one[0]();
  one[0]();
  const again = admission.enter(true, '192.0.2.1');
  assert.throws(() => admission.enter(true, '192.0.2.1'), busy);
  assert.throws(() => admission.enter(true, '192.0.2.4'), busy);
  [again, ...one.slice(1), ...others].forEach(release => release());
  // Signed-in requests can use every slot when nobody anonymous is waiting.
  const all = Array.from({ length: 32 }, () => admission.enter(false, '192.0.2.1'));
  assert.throws(() => admission.enter(true, '192.0.2.4'), busy);
  all.forEach(release => release());
  admission.enter(true, '192.0.2.4')();
});

test('a full sign-in table gives up its oldest pending sign-in instead of refusing new ones', () => {
  const flows = new Map();
  const start = (state, client) => {
    makeRoomForSignIn(flows, client, 4, 8);
    flows.set(state, { client });
  };
  // Two addresses fill the table of eight.
  for (let index = 0; index < 4; index++) start(`a${index}`, 'address-a');
  for (let index = 0; index < 4; index++) start(`b${index}`, 'address-b');
  assert.equal(flows.size, 8);
  // A third address is not locked out: the oldest pending sign-in of all gives way.
  start('c0', 'address-c');
  assert.deepEqual([...flows.keys()], ['a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3', 'c0']);
  // At its own cap an address gives up its own oldest, not somebody else's.
  start('b4', 'address-b');
  assert.deepEqual([...flows.keys()], ['a1', 'a2', 'a3', 'b1', 'b2', 'b3', 'c0', 'b4']);
  assert.equal(flows.size, 8);
});

test('sign-in cannot be started from a signed-in session, which keeps its cookie and stays valid', async t => {
  const fixture = await httpsSetup(t),
    person = await fixture.login();
  const refused = await person.post('/auth/login', {});
  assert.equal(refused.status, 409);
  assert.equal(refused.json().error.code, 'ALREADY_SIGNED_IN');
  assert.equal(refused.headers['set-cookie'], undefined, 'the session cookie is not replaced');
  assert.equal((await person.get('/api/tickets')).status, 200);
  assert.equal((await person.get('/api/session')).json().authenticated, true);
});

test('loading the page does not spend the per-address request limit; other requests still do', async t => {
  const fixture = await httpsSetup(t, { server: { rateLimitPerMinute: 60 } });
  // Ten page loads: the page, its stylesheet and every module, 150 requests in all.
  const page = await fixture.request('/');
  const files = [...page.text.matchAll(/(?:href|src)="(\/[a-z./-]+\.(?:css|js))"/g)].map(match => match[1]);
  assert.deepEqual(files, ['/app.css', '/app.js']);
  const modules = ['/api.js', '/contract.js', '/dom.js', '/state.js', '/text.js', '/validate.js'].concat(
    ['login', 'maintenance', 'requests', 'setup', 'shared', 'tickets'].map(name => `/views/${name}.js`),
  );
  for (let load = 0; load < 10; load++)
    for (const path of ['/', ...files, ...modules])
      assert.equal((await fixture.request(path)).status, 200, `${path} on load ${load}`);
  // The limit still applies to everything else, starting from zero.
  let last;
  for (let index = 0; index < 60; index++) last = await fixture.request('/api/session');
  assert.equal(last.status, 200);
  const limited = await fixture.request('/api/session');
  assert.equal(limited.status, 429);
  assert.equal(limited.json().error.code, 'RATE_LIMITED');
  assert.equal((await fixture.request('/app.js')).status, 200, 'the page itself still loads');
});

test('idle connections are bounded per client address and dropped when they never finish TLS', async t => {
  const fixture = await httpsSetup(t),
    { port } = new URL(fixture.origin);
  const open = () =>
    new Promise((resolve, reject) => {
      const socket = connect(Number(port), '127.0.0.1', () => resolve(socket));
      socket.once('error', reject);
    });
  const closed = socket => new Promise(resolve => (socket.destroyed ? resolve() : socket.once('close', resolve)));
  const sockets = [];
  t.after(() => sockets.forEach(socket => socket.destroy()));
  for (let index = 0; index < 64; index++) sockets.push(await open());
  // The 65th connection from the same address is refused at once; others are not starved.
  const extra = await open();
  sockets.push(extra);
  const started = Date.now();
  await closed(extra);
  assert.ok(Date.now() - started < 2000, 'the connection over the per-client cap is closed immediately');
  assert.ok(sockets.slice(0, 64).every(socket => !socket.destroyed));
  // A connection that never completes its handshake is closed by the handshake timeout, not held for minutes.
  await Promise.all(sockets.slice(0, 64).map(closed));
  assert.ok(Date.now() - started < 9000, `idle sockets were closed after ${Date.now() - started} ms`);
  assert.equal((await fixture.request('/health/live')).status, 200);
});
