import assert from 'node:assert/strict';
import test from 'node:test';
import { request as httpRequest } from 'node:http';
import { constants } from 'node:fs';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MapService, createMapToken, startMapServer } from '../dist/index.js';
import { parseRequest } from '../dist/boundary.js';

const scope = () => ({ subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['team'], allTeams: false });
const assetOpensSupported = typeof constants.O_NONBLOCK === 'number' && typeof constants.O_NOFOLLOW === 'number';
async function setup(t, options = {}, read = async () => ({ sources: [] })) {
  const token = createMapToken(), inputScope = scope(), calls = [];
  const service = new MapService({ read: async (...args) => { calls.push(args); return read(...args); } });
  const server = await startMapServer({ service, credentials: [{ token, scope: inputScope }], ...options });
  t.after(() => server.close());
  const send = async (body = { operation: 'list_agents', args: {} }, headers = {}, path = '/v1/query', method = 'POST') => {
    const response = await fetch(server.url + path, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...headers },
      ...(method !== 'GET' ? { body: typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body) } : {}) });
    return { status: response.status, headers: response.headers, text: await response.text() };
  };
  return { ...server, token, inputScope, send, calls };
}
test('HTTP authenticates an immutable host scope and rejects caller scope overrides', async t => {
  const s = await setup(t);
  s.inputScope.companyId = 'attacker'; s.inputScope.tenantIds.push('hidden');
  assert.equal((await s.send()).status, 200);
  assert.deepEqual(JSON.parse(JSON.stringify(s.calls[0][0])), scope());
  assert.ok(Object.isFrozen(s.calls[0][0]));
  for (const token of ['', createMapToken(), 'agt_v1.' + 'a'.repeat(43), 'ago_v1.' + 'b'.repeat(43)]) {
    const result = await s.send(undefined, { Authorization: `Bearer ${token}` });
    assert.equal(result.status, 401); assert.equal(result.text, '{"error":"MAP_UNAUTHENTICATED"}');
    assert.equal(result.headers.get('www-authenticate'), 'Bearer realm="agent-guard-reference"');
  }
  for (const body of [{ operation: 'list_agents', args: {}, scope: scope() },
    { operation: 'list_agents', args: { companyId: 'hidden' } }, { operation: 'run_cypher', args: {} }]) {
    assert.equal((await s.send(body)).status, 400);
  }
  assert.equal(s.calls.length, 1);
});
test('bearer session discovery exposes only its mode and retains authority checks', async t => {
  const s = await setup(t);
  const response = await fetch(s.url + '/auth/session');
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), { mode: 'bearer' });
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  for (const headers of [{ Origin: 'https://attacker.example' }, { Origin: 'null' },
    { 'Sec-Fetch-Site': 'cross-site' }, { 'Proxy-Authorization': 'Bearer anything' }]) {
    const denied = await fetch(s.url + '/auth/session', { headers });
    assert.equal(denied.status, 403, JSON.stringify(headers)); await denied.arrayBuffer();
  }
  const wrongHost = await new Promise((resolve, reject) => {
    const req = httpRequest(s.url + '/auth/session', { headers: { Host: 'attacker.example' } }, res => {
      res.resume(); res.once('end', () => resolve(res.statusCode));
    }); req.on('error', reject); req.end();
  });
  assert.equal(wrongHost, 403);
  assert.equal((await s.send(undefined, {}, '/auth/session?scope=all', 'GET')).status, 403);
  assert.equal((await s.send(undefined, { Authorization: '', Cookie: '__Host-agm_session=untrusted' })).status, 401);
  assert.equal(s.calls.length, 0);
});
test('HTTP rejects malformed, ambiguous, oversized and invalid-encoding requests before querying', async t => {
  const s = await setup(t, { maxRequestBytes: 512 });
  for (const body of ['{"operation":"list_agents","operation":"get_changes","args":{}}',
    '{"operation":"list_agents","args":{"search":"a","sear\\u0063h":"b"}}',
    '[{"operation":"list_agents","args":{}}]', '{"operation":"list_agents","args":{}} trailing',
    '{"operation":"list_agents","args":{"search":NaN}}', new Uint8Array([0xff]),
    '{"operation":"list_agents","args":{"limit":1e309}}']) assert.equal((await s.send(body)).status, 400);
  assert.equal((await s.send(' '.repeat(513))).status, 413);
  assert.equal((await s.send(undefined, { 'Content-Encoding': 'gzip' })).status, 400);
  assert.equal((await s.send(undefined, { 'Content-Type': 'text/plain' })).status, 400);
  assert.equal(s.calls.length, 0);
});
test('HTTP checks origin, host, method and exact route; never enables CORS or proxy credentials', async t => {
  const s = await setup(t);
  for (const headers of [{ Origin: 'https://attacker.example' }, { Origin: 'null' },
    { 'Sec-Fetch-Site': 'cross-site' }, { 'Proxy-Authorization': 'Bearer anything' }]) {
    assert.equal((await s.send(undefined, headers)).status, 403, JSON.stringify(headers));
  }
  for (const path of ['/v1/query?scope=all', '/admin', '/mcp/']) assert.equal((await s.send(undefined, {}, path)).status, 403);
  assert.equal((await s.send(undefined, {}, '/mcp', 'GET')).status, 403);
  assert.equal((await s.send(undefined, {}, '/v1/query', 'OPTIONS')).status, 403);
  const good = await s.send(undefined, { Origin: s.url, 'Sec-Fetch-Site': 'same-origin' });
  assert.equal(good.status, 200); assert.equal(good.headers.get('access-control-allow-origin'), null);
  assert.equal(good.headers.get('cache-control'), 'no-store');
  assert.equal(good.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(s.calls.length, 1);
});
test('raw HTTP Host is checked independently of fetch normalization', async t => {
  const s = await setup(t);
  const status = await new Promise((resolve, reject) => {
    const req = httpRequest(s.url + '/v1/query', { method: 'POST', headers: { Host: 'attacker.example', Authorization: `Bearer ${s.token}`, 'Content-Type': 'application/json' } }, res => {
      res.resume(); res.once('end', () => resolve(res.statusCode));
    }); req.on('error', reject); req.end('{"operation":"list_agents","args":{}}');
  });
  assert.equal(status, 403); assert.equal(s.calls.length, 0);
});
test('raw duplicate authorization headers cannot select or combine scopes', async t => {
  const s = await setup(t);
  const result = await new Promise((resolve, reject) => {
    const body = '{"operation":"list_agents","args":{}}';
    const req = httpRequest(s.url + '/v1/query', { method: 'POST', headers: [
      'Host', new URL(s.url).host, 'Authorization', `Bearer ${s.token}`, 'Authorization', `Bearer ${createMapToken()}`,
      'Content-Type', 'application/json', 'Content-Length', String(Buffer.byteLength(body))] }, res => {
      res.resume(); res.once('end', () => resolve(res.statusCode));
    }); req.on('error', reject); req.end(body);
  });
  assert.equal(result, 401); assert.equal(s.calls.length, 0);
});
test('HTTP applies quotas, response bounds and sanitizes backend failures', async t => {
  const rate = await setup(t, { rateLimit: { maxRequests: 1, windowMs: 60_000 } });
  assert.equal((await rate.send()).status, 200); assert.equal((await rate.send()).status, 429);
  const bound = await setup(t, { maxResponseBytes: 128 });
  const oversized = await bound.send({ operation: 'get_inventory_health', args: {} });
  assert.equal(oversized.status, 413); assert.equal(oversized.text, '{"error":"MAP_RESPONSE_TOO_LARGE"}');
  const broken = await setup(t, {}, async () => { throw new Error('secret database address and credential'); });
  const failure = await broken.send(); assert.equal(failure.status, 503); assert.equal(failure.text, '{"error":"MAP_UNAVAILABLE"}');
});
test('HTTP limits simultaneous work and reports bounded query timeouts', async t => {
  let finish, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const s = await setup(t, { maxConcurrentRequests: 1 }, () => { entered(); return new Promise(resolve => { finish = resolve; }); });
  const pending = s.send(); await started;
  assert.equal((await s.send()).status, 503);
  finish({ sources: [] }); assert.equal((await pending).status, 200);
  const service = new MapService({ read: () => new Promise(() => {}) }, { queryTimeoutMs: 20 });
  const timed = await setup(t, { service, requestTimeoutMs: 1000 });
  const result = await timed.send(); assert.equal(result.status, 408); assert.equal(result.text, '{"error":"MAP_TIMEOUT"}');
});
test(assetOpensSupported ? 'viewer serves only immutable allowlisted assets with a restrictive CSP' : 'viewer rejects unsupported asset opens', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-map-assets-')); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const name of ['index.html', 'app.js', 'app.css']) await writeFile(join(dir, name), `asset ${name}`);
  await writeFile(join(dir, 'secret.txt'), 'not public');
  if (!assetOpensSupported) {
    await assert.rejects(startMapServer({ service: new MapService({ read: async () => ({ sources: [] }) }),
      credentials: [{ token: createMapToken(), scope: scope() }], viewerDirectory: dir }), { code: 'MAP_CONFIG_INVALID' });
    return;
  }
  const s = await setup(t, { viewerDirectory: dir });
  await writeFile(join(dir, 'index.html'), 'changed after startup');
  const page = await s.send(undefined, { Authorization: '' }, '/', 'GET');
  assert.equal(page.status, 200); assert.equal(page.text, 'asset index.html');
  assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
  for (const path of ['/secret.txt', '/%2e%2e/secret.txt', '/index.html?token=ignored']) assert.equal((await s.send(undefined, {}, path, 'GET')).status, 403);
  await rm(join(dir, 'app.js')); await symlink(join(dir, 'secret.txt'), join(dir, 'app.js'));
  await assert.rejects(startMapServer({ service: new MapService({ read: async () => ({ sources: [] }) }), credentials: [{ token: createMapToken(), scope: scope() }], viewerDirectory: dir }), /MAP_CONFIG_INVALID/);
  assert.equal(s.calls.length, 0);
});
test('HTTP deadline flushes a 408 for slow queries and incomplete request bodies', async t => {
  const service = new MapService({ read: () => new Promise(() => {}) }, { queryTimeoutMs: 300 });
  const s = await setup(t, { service, requestTimeoutMs: 60 });
  const result = await s.send(); assert.equal(result.status, 408); assert.equal(result.text, '{"error":"MAP_TIMEOUT"}');
  const bodyTimeout = await new Promise((resolve, reject) => {
    const req = httpRequest(s.url + '/v1/query', { method: 'POST', headers: {
      Authorization: `Bearer ${s.token}`, 'Content-Type': 'application/json', 'Content-Length': '50' } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.once('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    }); req.on('error', reject); req.flushHeaders(); req.write('{');
  });
  assert.deepEqual(bodyTimeout, { status: 408, body: '{"error":"MAP_TIMEOUT"}' });
});
test('strict parser bounds depth, node count, duplicate decoded keys and prototype-like keys', () => {
  for (const input of ['['.repeat(14) + '0' + ']'.repeat(14), JSON.stringify(Array(2050).fill(0)),
    '{"x":1,"\\u0078":2}', '{"x":1,}', '\ufeff{}']) assert.throws(() => parseRequest(Buffer.from(input)), /MAP_REQUEST_INVALID/);
  const value = parseRequest(Buffer.from('{"__proto__":{"polluted":true}}'));
  assert.equal(Object.getPrototypeOf(value), null); assert.equal({}.polluted, undefined);
});
