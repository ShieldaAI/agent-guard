import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor, ExecutorError, createInventoryObserverToken, startInventoryServer, startExecutorServer } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';

function executor(t, options = {}) {
  const value = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'installation', enrollmentGeneration: 'generation' }, ...options });
  t.after(() => value.close());
  const credentials = new Map();
  for (const tenantId of ['alpha', 'beta']) {
    credentials.set(tenantId, value.createTask({ id: `${tenantId}-task`, tenantId, principalId: `${tenantId}-principal`,
      grants: [{ tool: `${tenantId}-tool`, resources: [`https://user:${tenantId}-secret@private.invalid/`] }],
      budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100_000 } }));
  }
  return { value, credentials };
}
async function observer(t, value, options = {}) {
  const token = createInventoryObserverToken();
  const service = await startInventoryServer({ executor: value, observers: [{ token, tenantIds: ['alpha'], profile: 'core' }], ...options });
  t.after(() => service.close());
  return { ...service, token };
}
async function post(service, token = service.token, input = { tenantId: 'alpha' }, path = '/v1/inventory/snapshot') {
  const response = await fetch(service.url + path, { method: 'POST', headers: { 'content-type': 'application/json',
    ...(token === undefined ? {} : { authorization: `Bearer ${token}` }) }, body: JSON.stringify(input), redirect: 'error' });
  const text = await response.text();
  return { response, text, body: JSON.parse(text) };
}

test('observer returns a complete single-tenant snapshot with exact bounded JSON and no authority mutations', async t => {
  const { value } = executor(t);
  const service = await observer(t, value);
  assert.deepEqual(service.server.address().address, '127.0.0.1');
  const before = value.inventorySnapshot({ tenantId: 'alpha' });
  const read = LedgerStore.prototype.read;
  let reads = 0;
  const spy = t.mock.method(LedgerStore.prototype, 'read', function () { reads++; return read.call(this); });
  const auth = t.mock.method(value, 'authenticate', () => assert.fail('observer called task authentication'));
  const write = t.mock.method(LedgerStore.prototype, 'transaction', () => assert.fail('observer wrote authority'));
  const result = await post(service);
  assert.equal(reads, 1);
  spy.mock.restore(); auth.mock.restore(); write.mock.restore();
  assert.equal(result.response.status, 200);
  assert.equal(result.response.headers.get('cache-control'), 'no-store');
  assert.equal(result.response.headers.get('x-content-type-options'), 'nosniff');
  assert.match(result.response.headers.get('content-type'), /^application\/json/);
  assert.equal(Number(result.response.headers.get('content-length')), Buffer.byteLength(result.text));
  assert.equal(result.response.headers.has('access-control-allow-origin'), false);
  assert.equal(result.body.source.tenantId, 'alpha');
  assert.deepEqual(result.body.tasks.map(item => item.id), ['alpha-task']);
  assert.deepEqual(result.body.tasks, JSON.parse(JSON.stringify(before.tasks)));
  assert.equal(result.body.ledgerRevision, before.ledgerRevision);
  assert.equal(result.body.policyEpoch, before.policyEpoch);
  assert.equal(result.body.source.inventoryInstanceId, before.source.inventoryInstanceId);
  assert.notEqual(result.body.snapshotId, before.snapshotId);
  for (const canary of ['beta', 'alpha-secret', service.token]) assert.equal(result.text.includes(canary), false);
  const after = value.inventorySnapshot({ tenantId: 'alpha' });
  assert.equal(after.ledgerRevision, before.ledgerRevision);
});

test('credentials select only host-enrolled tenants; denied requests never read inventory', async t => {
  const { value, credentials } = executor(t);
  const alpha = createInventoryObserverToken(), both = createInventoryObserverToken();
  const config = [{ token: alpha, tenantIds: ['alpha'], profile: 'core' }, { token: both, tenantIds: ['alpha', 'beta', 'empty'] }];
  const service = await observer(t, value, { observers: config });
  config[0].tenantIds.push('beta'); config[1].tenantIds.length = 0; config[0].profile = 'expanded';
  const snapshot = t.mock.method(value, 'inventorySnapshot', () => assert.fail('unauthorized request reached exporter'));
  for (const tenantId of ['beta', 'unknown-tenant']) {
    const result = await post(service, alpha, { tenantId });
    assert.equal(result.response.status, 403);
    assert.deepEqual(result.body, { error: 'INVENTORY_SCOPE_DENIED' });
    assert.equal(result.text.includes(tenantId), false);
  }
  for (const token of [credentials.get('alpha').token, randomBytes(32).toString('base64url'), createInventoryObserverToken(), 'bad', '']) {
    const result = await post(service, token);
    assert.equal(result.response.status, 401);
    assert.deepEqual(result.body, { error: 'UNAUTHENTICATED' });
    assert.match(result.response.headers.get('www-authenticate'), /^Bearer /);
  }
  const missing = await fetch(`${service.url}/v1/inventory/snapshot`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId: 'alpha' }) });
  assert.equal(missing.status, 401); await missing.arrayBuffer();
  snapshot.mock.restore();
  const beta = await post(service, both, { tenantId: 'beta' });
  assert.equal(beta.response.status, 200); assert.equal(beta.body.tasks[0].id, 'beta-task');
  const empty = await post(service, both, { tenantId: 'empty' });
  assert.equal(empty.response.status, 200); assert.deepEqual(empty.body.tasks, []);
  assert.equal(empty.body.coverage.tasks.status, 'complete');
});

test('observer listener cannot administer or execute; task/admin listener cannot serve inventory', async t => {
  const { value, credentials } = executor(t);
  const service = await observer(t, value);
  const adminToken = randomBytes(32).toString('base64url');
  const admin = await startExecutorServer({ executor: value, adminToken, operatorId: 'operator' });
  t.after(() => admin.close());
  for (const route of ['/v1/admin/audit', '/v1/admin/revoke', '/v1/task/snapshot', '/v1/task/execute']) {
    const result = await post(service, service.token, {}, route);
    assert.equal(result.response.status, 403);
    assert.equal(result.body.error, 'REQUEST_DENIED');
  }
  assert.equal((await post(service, adminToken)).response.status, 401);
  assert.equal((await post(admin, credentials.get('alpha').token)).response.status, 400);
  assert.equal((await post(admin, service.token, {}, '/v1/admin/audit')).response.status, 401);
  assert.equal((await post(admin, service.token, {}, '/v1/task/snapshot')).response.status, 401);
  await assert.rejects(startExecutorServer({ executor: value, adminToken: service.token, operatorId: 'operator' }), { code: 'SERVER_CONFIG_INVALID' });
});

test('oversized output fails as a complete safe error before any snapshot bytes are sent', async t => {
  const { value } = executor(t);
  const service = await observer(t, value, { maxResponseBytes: 128 });
  const before = value.inventorySnapshot({ tenantId: 'alpha' });
  const result = await post(service);
  assert.equal(result.response.status, 413);
  assert.deepEqual(result.body, { error: 'INVENTORY_RESPONSE_TOO_LARGE' });
  assert.ok(Buffer.byteLength(result.text) <= 128);
  assert.equal(result.response.headers.get('cache-control'), 'no-store');
  assert.equal(result.text.includes('alpha'), false);
  assert.equal(value.inventorySnapshot({ tenantId: 'alpha' }).ledgerRevision, before.ledgerRevision);
});

test('synchronous generation overruns return timeout, never a late successful snapshot', async t => {
  const { value } = executor(t);
  const service = await observer(t, value, { requestTimeoutMs: 25 });
  const original = value.inventorySnapshot.bind(value);
  const slow = t.mock.method(value, 'inventorySnapshot', scope => {
    const snapshot = original(scope);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60);
    return snapshot;
  });
  const result = await post(service);
  assert.equal(result.response.status, 408);
  assert.deepEqual(result.body, { error: 'REQUEST_TIMEOUT' });
  assert.equal(result.text.includes('tasks'), false);
  slow.mock.restore();
  assert.equal((await post(service)).response.status, 200);
});

test('exporter failures use safe codes without secrets and do not disable later requests', async t => {
  const { value } = executor(t);
  const service = await observer(t, value);
  for (const error of [new Error('private-error-canary'), new ExecutorError('private-error-canary')]) {
    const mock = t.mock.method(value, 'inventorySnapshot', () => { throw error; });
    const result = await post(service);
    assert.equal(result.response.status, 503); assert.deepEqual(result.body, { error: 'INVENTORY_UNAVAILABLE' });
    mock.mock.restore();
  }
  const actual = value.inventorySnapshot({ tenantId: 'alpha' });
  for (const invalid of [{ ...actual, source: { ...actual.source, tenantId: 'beta' } }, { ...actual, profile: 'expanded' }]) {
    const mock = t.mock.method(value, 'inventorySnapshot', () => invalid);
    const result = await post(service);
    assert.equal(result.response.status, 503); assert.deepEqual(result.body, { error: 'INVENTORY_UNAVAILABLE' });
    mock.mock.restore();
  }
  assert.equal((await post(service)).response.status, 200);
  value.close();
  const closed = await post(service);
  assert.equal(closed.response.status, 503); assert.equal(closed.text.includes('STORE_'), false);
});

test('invalid observer configuration fails before listening and does not run accessors', async t => {
  const { value } = executor(t);
  const token = createInventoryObserverToken();
  assert.match(token, /^agi_v1\.[A-Za-z0-9_-]{43}$/);
  assert.notEqual(token, createInventoryObserverToken());
  const base = { executor: value, observers: [{ token, tenantIds: ['alpha'] }] };
  for (const invalid of [
    { observers: [] }, { observers: [{ token: randomBytes(32).toString('base64url'), tenantIds: ['alpha'] }] },
    { observers: [{ token, tenantIds: [] }] }, { observers: [{ token, tenantIds: ['alpha', 'alpha'] }] },
    { observers: [{ token, tenantIds: ['\u0085'] }] }, { observers: [{ token, tenantIds: ['alpha'], profile: 'manifest' }] },
    { observers: [{ token, tenantIds: ['alpha'], admin: true }] }, { observers: [...base.observers, ...base.observers] },
    { host: '0.0.0.0' }, { port: -1 }, { port: 65536 }, { maxRequestBytes: 65537 }, { maxRequestBytes: 0 },
    { maxResponseBytes: 127 }, { maxResponseBytes: 8 * 1024 * 1024 + 1 }, { requestTimeoutMs: 0 },
    { requestTimeoutMs: 60001 }, { maxConcurrentRequests: 0 }, { maxConcurrentRequests: 65 },
    { maxConnections: 0 }, { maxConnections: 257 }, { rateLimit: { maxRequests: 0, windowMs: 1000 } },
    { rateLimit: { maxRequests: 1, windowMs: 60001 } }, { rateLimit: { maxRequests: 1, windowMs: 1000, extra: true } },
  ]) await assert.rejects(startInventoryServer({ ...base, ...invalid }), { code: 'INVENTORY_SERVER_CONFIG_INVALID' });
  let accessed = false;
  await assert.rejects(startInventoryServer({ ...base, observers: [{ token, get tenantIds() { accessed = true; return ['alpha']; } }] }),
    { code: 'INVENTORY_SERVER_CONFIG_INVALID' });
  assert.equal(accessed, false);
});
