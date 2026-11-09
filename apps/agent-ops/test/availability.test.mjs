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
import { setup, owner, httpsSetup } from './helpers.mjs';
import { clientKey } from '../server.mjs';
import { request as httpsRequest } from 'node:https';
import { createTestIdentityProvider } from '../../../packages/agent-map/test/helpers/oidc-provider.mjs';

/** A new TLS connection every time, so a reloaded certificate is observed. */
const freshHttps = (url, ca) =>
  new Promise((resolve, reject) => {
    const request = httpsRequest(url, { ca, agent: false, rejectUnauthorized: true }, response => {
      response.resume();
      response.on('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
    request.end();
  });

const agent = id => ({ id, tenantId: 'acme', roles: ['requester'] });

test('600 cookieless session requests create no server state and a real login still works', async t => {
  const f = await httpsSetup(t, { server: { rateLimitPerMinute: 100_000 } });
  for (let index = 0; index < 600; index++) {
    const response = await f.request('/api/session');
    assert.equal(response.status, 200);
  }
  const signedIn = await f.login();
  assert.equal(signedIn.session.authenticated, true);
});

test('a pre-login cookie is signed and its CSRF token is bound to it', async t => {
  const f = await httpsSetup(t);
  const first = await f.request('/api/session'),
    second = await f.request('/api/session');
  const cookie = first.headers['set-cookie'][0].split(';')[0];
  assert.match(cookie, /^__Host-agent_ops=a\./);
  const post = (cookieValue, csrf) =>
    f.request('/auth/login', {
      method: 'POST',
      body: '{}',
      headers: { Cookie: cookieValue, Origin: f.origin, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
    });
  assert.equal((await post(cookie, second.json().csrfToken)).status, 403, "another cookie's CSRF token is refused");
  const forged = cookie.replace(/.$/, character => (character === 'A' ? 'B' : 'A'));
  assert.equal(
    (await f.request('/api/session', { headers: { Cookie: forged } })).headers['set-cookie']?.length,
    1,
    'a forged cookie is replaced',
  );
  assert.equal((await post(forged, first.json().csrfToken)).status, 403);
  assert.equal((await post(cookie, first.json().csrfToken)).status, 200);
});

test('one client can hold only a few pending sign-ins', async t => {
  const f = await httpsSetup(t);
  const statuses = [];
  for (let index = 0; index < 5; index++) {
    const initial = await f.request('/api/session'),
      cookie = initial.headers['set-cookie'][0].split(';')[0];
    statuses.push(
      (
        await f.request('/auth/login', {
          method: 'POST',
          body: '{}',
          headers: {
            Cookie: cookie,
            Origin: f.origin,
            'X-CSRF-Token': initial.json().csrfToken,
            'Content-Type': 'application/json',
          },
        })
      ).status,
    );
  }
  assert.deepEqual(statuses, [200, 200, 200, 200, 429]);
});

test('a looping requester hits its own pending cap without affecting others', async t => {
  const fixture = setup(t, { requests: { maxPendingPerRequester: 3, maxPendingPerTenant: 5 } });
  for (let index = 0; index < 3; index++)
    await fixture.workflow.propose(agent('looping-agent'), { ticketId: 'T-1', status: 'resolved' });
  await assert.rejects(fixture.workflow.propose(agent('looping-agent'), { ticketId: 'T-1', status: 'resolved' }), {
    code: 'PENDING_LIMIT_REACHED',
    status: 429,
  });
  await fixture.workflow.propose(agent('other-agent'), { ticketId: 'T-1', status: 'resolved' });
  await fixture.workflow.propose(agent('third-agent'), { ticketId: 'T-1', status: 'resolved' });
  await assert.rejects(
    fixture.workflow.propose(agent('fourth-agent'), { ticketId: 'T-1', status: 'resolved' }),
    { code: 'PENDING_LIMIT_REACHED' },
    'tenant total',
  );
});

test('review expiry is configurable and self-approval can be forbidden', async t => {
  const fixture = setup(t, { requests: { reviewExpiryMs: 60 * 60_000, forbidSelfApproval: true } });
  const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  assert.equal(request.expiresAt - request.createdAt, 60 * 60_000);
  await assert.rejects(fixture.workflow.decide(owner, request.id, { digest: request.digest }, true), {
    code: 'SELF_APPROVAL_FORBIDDEN',
    status: 403,
  });
  const done = await fixture.workflow.decide(
    { ...owner, id: 'reviewer-alice' },
    request.id,
    { digest: request.digest },
    true,
  );
  assert.equal(done.request.state, 'completed');
});

test('request policy values are validated', t => {
  for (const requests of [
    { reviewExpiryMs: 59_999 },
    { reviewExpiryMs: 24 * 60 * 60_000 + 1 },
    { forbidSelfApproval: 'yes' },
    { maxPendingPerRequester: 0 },
    { maxPendingPerTenant: 1.5 },
    { unknown: 1 },
  ]) {
    assert.throws(
      () => setup(t, { requests }),
      error =>
        ['REQUEST_POLICY_INVALID', 'INVALID_INPUT', 'FIELDS_INVALID'].includes(error.code) ||
        /INVALID/.test(error.code),
      JSON.stringify(requests),
    );
  }
});

test('TLS material reloads in place for new connections; invalid material is refused', async t => {
  const f = await httpsSetup(t);
  const next = await createTestIdentityProvider(t);
  assert.throws(() => f.app.replaceTls({ key: next.key, cert: f.provider.cert }), { code: 'TLS_CERTIFICATE_INVALID' });
  const live = new URL('/health/live', f.origin);
  assert.equal(await freshHttps(live, f.provider.ca), 200, 'refused material leaves the old certificate serving');
  f.app.replaceTls({ key: next.key, cert: next.cert });
  assert.equal(await freshHttps(live, next.ca), 200);
  await assert.rejects(freshHttps(live, f.provider.ca), 'the old certificate is no longer served');
});

test('rate-limit keys group IPv6 clients by /64 and unwrap IPv4-mapped addresses', () => {
  assert.equal(clientKey('::ffff:192.0.2.7'), '192.0.2.7');
  assert.equal(clientKey('2001:db8:1:2:aaaa::1'), clientKey('2001:db8:1:2:bbbb::2'));
  assert.notEqual(clientKey('2001:db8:1:2::1'), clientKey('2001:db8:1:3::1'));
  assert.equal(clientKey('fe80::1%en0'), clientKey('fe80::2'));
});

test('after a backward clock step the service refuses to start unless the operator accepts the skew', async t => {
  const fixture = setup(t);
  const realNow = Date.now();
  fixture.close();
  t.mock.timers.enable({ apis: ['Date'], now: realNow - 5_000 });
  assert.throws(() => fixture.reopen(), { code: 'CLOCK_INVALID' });
  fixture.close();
  fixture.reopen({ acceptClockSkewMs: 60_000 });
  const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  assert.equal(request.state, 'pending');
});

test('online retention archives old finished requests in small batches and leaves the rest', async t => {
  const fixture = setup(t, { requests: { autoArchiveAfterDays: 1 } });
  const finished = [];
  for (let index = 0; index < 3; index++) {
    const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
    await fixture.workflow.decide({ ...owner, id: 'reviewer-alice' }, request.id, { digest: request.digest }, false);
    finished.push(request.id);
  }
  const open = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  assert.deepEqual(fixture.workflow.autoArchive(), { archived: 0, skipped: 0 }, 'nothing is old enough yet');
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 2 * 24 * 60 * 60_000 });
  fixture.reopen(); // The clocks are captured at construction; reopen two days later.
  assert.deepEqual(fixture.workflow.autoArchive({ limit: 2 }), { archived: 2, skipped: 0 }, 'one small batch');
  assert.deepEqual(
    fixture.workflow.autoArchive({ limit: 2 }),
    { archived: 2, skipped: 0 },
    'the denied request and the expired one',
  );
  assert.deepEqual(fixture.workflow.autoArchive(), { archived: 0, skipped: 0 });
  const requests = fixture.workflow.requests('acme').requests;
  for (const id of [...finished, open.id]) assert.equal(requests.find(item => item.id === id).archived, true, id);
  for (const id of finished) {
    assert.ok(
      fixture.runtime.executor.findTaskFamilyArchive({ tenantId: 'acme', taskId: `ticket:${id}` }),
      'the executor holds the archive',
    );
  }
  assert.ok(
    fixture.workflow.data().audit.some(event => event.event === 'AUTO_ARCHIVED' && event.operatorId === 'retention'),
  );
});

test('online retention is off unless configured and validates its setting', t => {
  const fixture = setup(t);
  assert.deepEqual(fixture.workflow.autoArchive(), { archived: 0, skipped: 0 });
  for (const autoArchiveAfterDays of [0, 3651, 1.5]) {
    assert.throws(() => setup(t, { requests: { autoArchiveAfterDays } }), /INVALID/);
  }
});
