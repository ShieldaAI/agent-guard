import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  createOpsTelemetry,
  operationalStatus,
  prometheusStatus,
  exportActivity,
  monitoringSummary,
} from '../observability.mjs';
import { httpsSetup } from './helpers.mjs';

const operator = { id: 'owner', tenantId: 'acme', roles: ['operator'] };
const limits = {
  maxTickets: 500,
  maxRequests: 4000,
  maxBackendBytes: 1_048_576,
  maxLedgerBytes: 1_048_576,
  maxRetainedKeys: 4,
};
function fakeWorkflow(data) {
  return {
    health() {},
    data: () => data,
    maintenance: () => ({
      limits,
      usage: { tickets: 400, requests: 3800, receipts: 120, backendBytes: 1000 },
      statistics: { ledgerBytes: 900_000, ledgerByteLimit: 1_048_576 },
    }),
  };
}

test('bounded metrics retain fixed labels, expire their five-minute buckets and count no raw request fields', () => {
  let now = 1_000_000;
  const telemetry = createOpsTelemetry({ clock: () => now });
  for (let i = 0; i < 1000; i++)
    telemetry.record({
      statusCode: i % 2 ? 503 : 200,
      durationMs: 125,
      url: '/secret-path',
      headers: { authorization: 'secret-token' },
    });
  const initial = telemetry.snapshot();
  assert.equal(initial.lifetime.requests, 1000);
  assert.equal(initial.recent.serverErrors, 500);
  assert.equal(initial.recent.p95UpperBoundMs, 250);
  assert.equal(JSON.stringify(initial).includes('secret'), false);
  now += 301_000;
  assert.equal(telemetry.snapshot().recent.requests, 0);
  assert.equal(telemetry.snapshot().lifetime.requests, 1000);
  telemetry.record({ statusCode: 499, durationMs: 5000 });
  assert.equal(telemetry.snapshot().recent.statusClasses['4xx'], 1);
  now -= 1000;
  assert.equal(telemetry.snapshot().recent.requests, 0);
  assert.throws(() => createOpsTelemetry({ clock: () => NaN }));
});

test('operator status scopes workflow to its tenant and labels deployment aggregates and alerts', () => {
  const now = 1_000_000,
    telemetry = createOpsTelemetry({ clock: () => now });
  for (let i = 0; i < 20; i++) telemetry.record({ statusCode: 503, durationMs: 3000 });
  const workflow = fakeWorkflow({
    requests: {
      a: { tenantId: 'acme', state: 'unconfirmed', createdAt: now - 600_000 },
      b: { tenantId: 'acme', state: 'pending', createdAt: now, expiresAt: now + 1000 },
      foreign: { tenantId: 'foreign', state: 'unconfirmed', createdAt: 0 },
    },
    audit: [{ tenantId: 'foreign' }, { tenantId: 'acme' }],
  });
  const status = operationalStatus({
    workflow,
    operator,
    telemetry,
    keyring: { keyCount: 1, maxKeys: 4 },
    tlsExpiresAt: now + 86_400_000,
    now,
  });
  assert.equal(status.workflow.requests, 2);
  assert.equal(status.workflow.unconfirmed, 1);
  assert.equal(status.workflow.oldestUnconfirmedMs, 600_000);
  assert.equal(status.audit.retainedEvents, 1);
  assert.equal(status.audit.completeHistory, false);
  assert.equal(status.capacity.find(row => row.id === 'ledger_bytes').used, 900_000);
  for (const id of [
    'unconfirmed_outcome',
    'capacity_tickets',
    'capacity_requests',
    'capacity_ledger_bytes',
    'tls_expiry',
    'http_errors',
    'http_latency',
  ])
    assert.ok(
      status.alerts.some(alert => alert.id === id),
      id,
    );
  assert.deepEqual(status.scope, { tenantId: 'acme', workflow: 'tenant', capacity: 'deployment', http: 'deployment' });
  const metrics = prometheusStatus(status);
  assert.match(metrics, /agent_ops_tenant_unconfirmed 1/);
  assert.match(metrics, /agent_ops_capacity_used\{resource="ledger_bytes"\} 900000/);
  assert.equal(metrics.includes('acme'), false);
  assert.equal(metrics.includes('foreign'), false);
  assert.throws(() => operationalStatus({ workflow, operator: { ...operator, roles: ['reviewer'] }, telemetry, now }), {
    code: 'FORBIDDEN',
  });
  assert.throws(() => operationalStatus({ workflow, operator, telemetry, tlsExpiresAt: now, now }), {
    code: 'TLS_CERTIFICATE_EXPIRED',
  });
  const summary = monitoringSummary({
    workflow,
    telemetry,
    keyring: { keyCount: 1, maxKeys: 4 },
    tenantIdForStatistics: 'acme',
    now,
  });
  assert.equal(summary.unconfirmed, 2);
  assert.equal(summary.scope, 'deployment');
  assert.equal(JSON.stringify(summary).includes('foreign'), false);
});

test('activity snapshot minimizes allowed fields, excludes other tenants and discloses retained omissions', () => {
  const audit = Array.from({ length: 1005 }, (_, index) => ({
    tenantId: 'acme',
    at: 1000 + index,
    event: 'REQUESTED',
    requestId: `request-${index}`,
    operatorId: 'owner',
    args: { password: 'never-export-this' },
    ticketTitle: 'customer text',
  }));
  audit.push({ tenantId: 'foreign', at: 3000, event: 'REQUESTED', requestId: 'foreign-only' });
  const workflow = fakeWorkflow({ audit });
  const result = exportActivity({ workflow, operator, now: 5000 });
  const payload = JSON.parse(result.content);
  assert.equal(payload.events.length, 1000);
  assert.equal(payload.events[0].requestId, 'request-5');
  assert.equal(payload.coverage.omittedRetainedEvents, 5);
  assert.equal(payload.coverage.historicalDropCount, 'unknown');
  assert.equal(payload.coverage.earliestExportedAt, 1005);
  assert.equal(payload.coverage.latestExportedAt, 2004);
  assert.equal(payload.coverage.completeHistory, false);
  for (const forbidden of ['never-export-this', 'customer text', 'foreign-only'])
    assert.equal(result.content.includes(forbidden), false);
  assert.equal(result.digest, createHash('sha256').update(result.content).digest('hex'));
  assert.equal(result.bytes, Buffer.byteLength(result.content));
  assert.throws(() => exportActivity({ workflow, operator: { ...operator, roles: [] }, now: 5000 }), {
    code: 'FORBIDDEN',
  });
});

test(
  'HTTP status, metrics and activity exports require operator auth; activity POST requires CSRF',
  { skip: process.platform === 'win32' },
  async t => {
    const fixture = await httpsSetup(t),
      owner = await fixture.login(),
      requester = await fixture.login('requester');
    assert.equal((await fixture.request('/api/status')).status, 401);
    assert.equal((await requester.get('/api/status')).status, 403);
    assert.equal((await requester.get('/api/metrics')).status, 403);
    assert.equal((await requester.post('/api/audit/export', {})).status, 403);
    assert.equal((await owner.post('/api/audit/export', {}, { 'X-CSRF-Token': 'wrong' })).status, 403);
    const prepared = (await owner.post('/api/requests', { ticketId: 'T-1', status: 'resolved' })).json().request;
    await owner.post(`/api/requests/${prepared.id}/deny`, { digest: prepared.digest });
    const status = await owner.get('/api/status');
    assert.equal(status.status, 200);
    assert.equal(status.json().scope.tenantId, 'acme');
    assert.ok(status.json().capacity.find(row => row.id === 'ledger_bytes').used > 0);
    const metrics = await owner.get('/api/metrics');
    assert.equal(metrics.status, 200);
    assert.match(metrics.headers['content-type'], /^text\/plain/);
    assert.match(metrics.text, /agent_ops_http_requests_total/);
    assert.equal((await owner.get('/api/status?tenantId=other')).status, 400);
    const exported = await owner.post('/api/audit/export', {});
    assert.equal(exported.status, 200);
    const payload = JSON.parse(exported.json().content);
    assert.ok(payload.events.some(event => event.event === 'DENIED'));
    for (const secret of [fixture.provider.clientSecret, 'Private ticket', 'Customer delivery', 'id_token'])
      assert.equal(exported.text.includes(secret), false);
  },
);

test(
  'public readiness checks share the bounded request budget while liveness remains minimal',
  { skip: process.platform === 'win32' },
  async t => {
    const fixture = await httpsSetup(t);
    for (let i = 0; i < 180; i++) assert.equal((await fixture.request('/health/ready')).status, 200);
    assert.equal((await fixture.request('/health/ready')).status, 429);
    assert.equal((await fixture.request('/health/live')).status, 200);
  },
);

test(
  'security events contain only enrolled identifiers and fixed codes; a failed logger cannot alter auth',
  { skip: process.platform === 'win32' },
  async t => {
    const events = [],
      fixture = await httpsSetup(t, {
        server: {
          onSecurityEvent: event => {
            events.push(event);
            if (event.event === 'ACCESS_DENIED') throw Error('collector unavailable');
            if (event.event === 'SIGN_IN_FAILED') return Promise.reject(Error('async collector unavailable'));
          },
        },
      });
    const owner = await fixture.login(),
      requester = await fixture.login('requester');
    assert.equal((await requester.get('/api/status')).status, 403);
    assert.equal((await owner.get('/api/status')).status, 200);
    const status = (await owner.get('/api/status')).json();
    assert.equal(status.http.securityLog.failures, 1);
    assert.ok(status.alerts.some(alert => alert.id === 'security_log' && alert.severity === 'critical'));
    await assert.rejects(fixture.login('not-enrolled'));
    assert.ok(
      events.some(event => event.event === 'SIGN_IN_FAILED' && event.code === 'FORBIDDEN' && !event.operatorId),
    );
    assert.equal((await owner.get('/api/status')).json().http.securityLog.failures, 2);
    await owner.post('/auth/logout', {});
    fixture.app.replaceBindings(fixture.config.bindings);
    assert.ok(
      events.some(
        event => event.event === 'SIGN_IN_SUCCEEDED' && event.operatorId === 'owner' && event.tenantId === 'acme',
      ),
    );
    assert.ok(
      events.some(
        event => event.event === 'ACCESS_DENIED' && event.operatorId === 'requester' && event.code === 'FORBIDDEN',
      ),
    );
    assert.ok(events.some(event => event.event === 'SIGNED_OUT' && event.operatorId === 'owner'));
    assert.ok(events.some(event => event.event === 'IDENTITY_BINDINGS_RELOADED'));
    for (const event of events)
      assert.ok(Object.keys(event).every(key => ['event', 'operatorId', 'tenantId', 'code'].includes(key)));
    assert.equal(JSON.stringify(events).includes(fixture.provider.clientSecret), false);
    assert.equal((await owner.get('/api/status')).status, 401);
  },
);
