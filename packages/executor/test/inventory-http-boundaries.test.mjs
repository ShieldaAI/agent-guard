import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { DurableExecutor } from '../dist/index.js';
import { createInventoryObserverToken, startInventoryServer } from '../dist/inventory-http.js';

const route = '/v1/inventory/snapshot';
const requestBody = '{"tenantId":"tenant"}';
async function setup(t, options = {}, credentials) {
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: Buffer.alloc(32, 7), clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'observer-test', enrollmentGeneration: 'one' } });
  const token = createInventoryObserverToken();
  const observers = credentials ?? [{ token, tenantIds: ['tenant'] }];
  let service;
  try { service = await startInventoryServer({ executor, observers, ...options }); }
  catch (error) { executor.close(); throw error; }
  t.after(async () => { await service.close(); executor.close(); });
  let exports = 0;
  const original = executor.inventorySnapshot.bind(executor);
  t.mock.method(executor, 'inventorySnapshot', scope => { exports++; return original(scope); });
  return { ...service, executor, token: observers[0].token, exports: () => exports };
}
function parseResponse(bytes) {
  const text = Buffer.concat(bytes).toString('utf8');
  const boundary = text.indexOf('\r\n\r\n');
  const head = boundary === -1 ? text : text.slice(0, boundary);
  const headers = Object.fromEntries(head.split('\r\n').slice(1).map(line => {
    const colon = line.indexOf(':'); return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
  }));
  const body = boundary === -1 ? '' : text.slice(boundary + 4);
  return { status: Number(/^HTTP\/1\.[01] (\d+)/.exec(head)?.[1] ?? 0), headers, body, text };
}
function socketSession(t, url) {
  const address = new URL(url);
  const socket = connect({ host: address.hostname, port: Number(address.port) });
  const connected = once(socket, 'connect');
  const chunks = [];
  const completed = new Promise((resolve, reject) => {
    socket.on('data', bytes => chunks.push(bytes));
    socket.on('error', () => {}); // Parser rejection and deliberate disconnect may reset the socket.
    socket.once('close', () => resolve(parseResponse(chunks)));
    socket.setTimeout(3000, () => { reject(new Error('Observer failed to bound socket lifetime')); socket.destroy(); });
  });
  t.after(() => socket.destroy());
  return { socket, connected, completed };
}
function request(service, { method = 'POST', path = route, body = requestBody, headers = [], omit = [] } = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const defaults = [['Host', new URL(service.url).host], ['Authorization', `Bearer ${service.token}`],
    ['Content-Type', 'application/json'], ['Content-Length', String(bytes.length)], ['Connection', 'close']];
  const lines = defaults.filter(([key]) => !omit.includes(key.toLowerCase())).concat(headers);
  return Buffer.concat([Buffer.from(`${method} ${path} HTTP/1.1\r\n${lines.map(([key, value]) => `${key}: ${value}`).join('\r\n')}\r\n\r\n`), bytes]);
}
async function raw(t, service, options) {
  const session = socketSession(t, service.url);
  await session.connected;
  session.socket.write(request(service, options));
  const response = await session.completed;
  assert.equal(response.text.includes(service.token), false, 'Observer echoed its credential');
  return response;
}
async function post(service, token = service.token, body = { tenantId: 'tenant' }) {
  const bytes = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(`${service.url}${route}`, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'content-length': bytes.length } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.once('error', reject);
      response.once('end', () => {
        try { resolve({ status: response.statusCode, headers: new Map(Object.entries(response.headers)),
          body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch (error) { reject(error); }
      });
    });
    outgoing.once('error', reject);
    outgoing.setTimeout(3000, () => outgoing.destroy(new Error('Observer request stalled')));
    outgoing.end(bytes);
  });
}

test('observer rejects duplicate credentials and singleton headers before snapshot generation', async t => {
  const service = await setup(t);
  for (const [name, value] of [['aUtHoRiZaTiOn', `Bearer ${service.token}`], ['Content-Type', 'application/json'],
    ['Host', new URL(service.url).host], ['Content-Length', String(Buffer.byteLength(requestBody))]]) {
    const response = await raw(t, service, { headers: [[name, value]] });
    assert.ok(response.status === 0 || (response.status >= 400 && response.status < 500), response.text);
    assert.equal(service.exports(), 0);
  }
});

test('observer cannot hide a duplicate credential beyond the parsed header-count limit', async t => {
  const service = await setup(t);
  const padding = Array.from({ length: 28 }, (_, index) => [`X-Padding-${index}`, 'x']);
  const response = await raw(t, service, { headers: [...padding, ['Authorization', `Bearer ${service.token}`]] });
  assert.ok(response.status >= 400 && response.status < 500, response.text);
  assert.equal(service.exports(), 0);
});

for (const [name, body] of [
  ['invalid UTF-8', Buffer.from([0x7b, 0x22, 0xc0, 0xaf, 0x22, 0x7d])],
  ['UTF-8 byte-order mark', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(requestBody)])],
  ['duplicate tenant keys', '{"tenantId":"foreign","tenantId":"tenant"}'],
  ['escaped duplicate tenant keys', '{"tenantId":"tenant","tenant\\u0049d":"tenant"}'],
  ['additional filter', '{"tenantId":"tenant","taskIds":[]}'],
  ['client-selected profile', '{"tenantId":"tenant","profile":"core"}'],
  ['nested scope', '{"tenantId":{"id":"tenant"}}'],
  ['array body', '[{"tenantId":"tenant"}]'],
  ['trailing JSON', '{"tenantId":"tenant"}{}'],
  ['malformed string', '{"tenantId":"tenant}'],
  ['unpaired Unicode', '{"tenantId":"\\ud800"}'],
]) {
  test(`observer rejects ${name} without evaluating the inventory`, async t => {
    const service = await setup(t);
    const response = await raw(t, service, { body });
    assert.equal(response.status, 400, response.text);
    assert.equal(JSON.parse(response.body).error, 'REQUEST_INVALID');
    assert.equal(service.exports(), 0);
  });
}

test('observer accepts escaped property spelling as the same single tenant selector', async t => {
  const service = await setup(t);
  const response = await raw(t, service, { body: '{"tenant\\u0049d":"tenant"}' });
  assert.equal(response.status, 200, response.text);
  assert.equal(JSON.parse(response.body).source.tenantId, 'tenant');
  assert.equal(service.exports(), 1);
});

test('observer enforces declared and streamed request byte limits before exporting', async t => {
  const service = await setup(t, { maxRequestBytes: 32 });
  const declared = await raw(t, service, { body: '', omit: ['content-length'], headers: [['Content-Length', '4096']] });
  assert.equal(declared.status, 413, declared.text);
  assert.equal(JSON.parse(declared.body).error, 'REQUEST_TOO_LARGE');
  const streamed = await raw(t, service, { omit: ['content-length'], headers: [['Transfer-Encoding', 'chunked']],
    body: `40\r\n${'x'.repeat(64)}\r\n0\r\n\r\n` });
  assert.equal(streamed.status, 413, streamed.text);
  assert.equal(JSON.parse(streamed.body).error, 'REQUEST_TOO_LARGE');
  assert.equal(service.exports(), 0);
  assert.equal((await post(service)).status, 200);
});

test('observer refuses alternate routing, browser context, encodings and media types', async t => {
  const service = await setup(t);
  const denied = [
    { method: 'GET' }, { method: 'OPTIONS' }, { path: `${route}?tenantId=tenant` }, { path: `${route}/` },
    { path: '/v1/admin/audit' }, { path: '/v1/task/snapshot' },
    { headers: [['Origin', 'http://attacker.invalid']] }, { headers: [['Sec-Fetch-Site', 'same-origin']] },
    { headers: [['Sec-Fetch-Mode', 'navigate']] }, { headers: [['Content-Encoding', 'gzip']] },
    { omit: ['content-type'], headers: [['Content-Type', 'text/plain']] },
    { omit: ['host'], headers: [['Host', 'attacker.invalid']] },
  ];
  for (const variant of denied) {
    const response = await raw(t, service, variant);
    assert.ok(response.status >= 400 && response.status < 500, response.text);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['access-control-allow-origin'], undefined);
    assert.equal(service.exports(), 0);
  }
});

test('observer permits standalone native-fetch cors mode while rejecting browser origin metadata', async t => {
  const service = await setup(t);
  const native = await raw(t, service, { headers: [['Sec-Fetch-Mode', 'cors']] });
  assert.equal(native.status, 200, native.text);
  const browser = await raw(t, service, { headers: [['Sec-Fetch-Mode', 'cors'], ['Sec-Fetch-Site', 'same-origin']] });
  assert.equal(browser.status, 403, browser.text);
  assert.equal(service.exports(), 1);
});

test('observer refuses upgrades, expectations, CONNECT and oversized headers', async t => {
  const service = await setup(t);
  const requests = [
    { omit: ['connection'], headers: [['Connection', 'Upgrade'], ['Upgrade', 'websocket']] },
    { headers: [['Expect', '100-continue']] },
    { method: 'CONNECT', path: new URL(service.url).host },
    { headers: [['X-Oversized', 'x'.repeat(9000)]] },
  ];
  for (const options of requests) {
    const response = await raw(t, service, options);
    assert.ok(response.status === 0 || (response.status >= 400 && response.status < 500), response.text);
    assert.equal(response.text.includes('100 Continue'), false);
    assert.equal(response.text.includes('101 Switching'), false);
    assert.equal(service.exports(), 0);
  }
});

test('observer expires stalled bodies and releases request capacity for later polls', async t => {
  const service = await setup(t, { requestTimeoutMs: 200, maxConcurrentRequests: 1 });
  const stalled = socketSession(t, service.url);
  await stalled.connected;
  const seen = once(service.server, 'request');
  stalled.socket.write(request(service, { body: '{', omit: ['content-length'], headers: [['Content-Length', '24']] }));
  await seen;
  const response = await stalled.completed;
  assert.equal(response.status, 408, response.text);
  assert.equal(JSON.parse(response.body).error, 'REQUEST_TIMEOUT');
  assert.equal(service.exports(), 0);
  assert.equal((await post(service)).status, 200);
});

test('observer holds concurrency during upload and releases it when the client disconnects', async t => {
  const service = await setup(t, { maxConcurrentRequests: 1, requestTimeoutMs: 2000 });
  const stalled = socketSession(t, service.url);
  await stalled.connected;
  const seen = once(service.server, 'request');
  stalled.socket.write(request(service, { body: '{', omit: ['content-length'], headers: [['Content-Length', '24']] }));
  const [serverRequest] = await seen;
  const denied = await post(service);
  assert.equal(denied.status, 503);
  assert.equal(denied.body.error, 'INVENTORY_BUSY');
  assert.equal(service.exports(), 0);
  const serverDisconnected = once(serverRequest.socket, 'close');
  stalled.socket.destroy();
  await serverDisconnected;
  assert.equal((await post(service)).status, 200);
});

test('observer bounds incomplete-header socket lifetime and connections', async t => {
  const service = await setup(t, { maxConnections: 1, requestTimeoutMs: 200 });
  const incomplete = socketSession(t, service.url);
  await incomplete.connected;
  incomplete.socket.write('POST /v1/inventory/snapshot HTTP/1.1\r\nHost: ');
  const rejected = await raw(t, service);
  assert.notEqual(rejected.status, 200);
  assert.equal(service.exports(), 0);
  const expired = await incomplete.completed;
  assert.notEqual(expired.status, 200);
  assert.equal((await post(service)).status, 200);
});

test('observer rate limits each credential independently while counting denied scope attempts', async t => {
  const first = createInventoryObserverToken(), second = createInventoryObserverToken();
  const service = await setup(t, { rateLimit: { maxRequests: 1, windowMs: 1000 } },
    [{ token: first, tenantIds: ['tenant'] }, { token: second, tenantIds: ['tenant'] }]);
  assert.equal((await post(service, first, { tenantId: 'foreign' })).status, 403);
  const denied = await post(service, first);
  assert.equal(denied.status, 429);
  assert.equal(denied.body.error, 'INVENTORY_RATE_LIMITED');
  assert.match(denied.headers.get('retry-after'), /^\d+$/);
  // This attempt may consume the global rate budget even though this credential still has quota.
  assert.equal(service.exports(), 0);
  await delay(1050);
  assert.equal((await post(service, second)).status, 200);
  assert.equal((await post(service, first)).status, 200);
});

test('observer globally bounds unknown credential attempts and resets its fixed window', async t => {
  const service = await setup(t, { rateLimit: { maxRequests: 2, windowMs: 1000 } });
  assert.equal((await post(service, createInventoryObserverToken())).status, 401);
  assert.equal((await post(service, createInventoryObserverToken())).status, 401);
  const denied = await post(service);
  assert.equal(denied.status, 429);
  assert.equal(denied.body.error, 'INVENTORY_RATE_LIMITED');
  assert.equal(service.exports(), 0);
  await delay(1050);
  assert.equal((await post(service)).status, 200);
});

for (const [name, special] of [
  ['upgrade', service => ({ omit: ['connection'], headers: [['Connection', 'Upgrade'], ['Upgrade', 'websocket']] })],
  ['CONNECT', service => ({ method: 'CONNECT', path: new URL(service.url).host })],
  ['parser rejection', service => ({ headers: [['X-Oversized', 'x'.repeat(9000)]] })],
]) {
  test(`observer ${name} attempts consume the global request budget`, async t => {
    const service = await setup(t, { rateLimit: { maxRequests: 2, windowMs: 1000 } });
    const first = await raw(t, service, special(service));
    const second = await raw(t, service, special(service));
    assert.notEqual(first.status, 200); assert.notEqual(second.status, 200);
    const denied = await post(service);
    assert.equal(denied.status, 429);
    assert.equal(denied.body.error, 'INVENTORY_RATE_LIMITED');
    assert.equal(service.exports(), 0);
  });
}

test('closing the observer destroys active uploads, is idempotent and preserves the executor', async t => {
  const service = await setup(t, { requestTimeoutMs: 2000 });
  const stalled = socketSession(t, service.url);
  await stalled.connected;
  const seen = once(service.server, 'request');
  stalled.socket.write(request(service, { body: '{', omit: ['content-length'], headers: [['Content-Length', '24']] }));
  await seen;
  await Promise.all([service.close(), service.close()]);
  const response = await stalled.completed;
  assert.notEqual(response.status, 200);
  assert.equal(service.exports(), 0);
  assert.equal(service.executor.inventorySnapshot({ tenantId: 'tenant' }).source.tenantId, 'tenant');
});
