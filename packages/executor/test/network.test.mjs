import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createRestrictedFetch, isPublicAddress } from '../dist/index.js';
async function collector(t, handler) {
  const server = createServer(handler); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
test('address classification rejects aliases, IPv6 private and metadata addresses', () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '0.0.0.0', '::1', '::ffff:127.0.0.1', 'fe80::1', 'fc00::1', '100.64.0.1']) assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress('8.8.8.8'), true);
});
test('explicit private origin succeeds; unapproved loopback receives no request', async t => {
  let requests = 0; const origin = await collector(t, (_req, res) => { requests++; res.end('accepted'); });
  await assert.rejects(createRestrictedFetch({ allowedOrigins: [origin] })(origin), { code: 'DESTINATION_DENIED' });
  assert.equal(requests, 0);
  const response = await createRestrictedFetch({ allowedOrigins: [origin], allowPrivateOrigins: [origin] })(origin);
  assert.equal(await response.text(), 'accepted'); assert.equal(requests, 1);
});
test('307/308 responses never forward custom credentials or request bodies', async t => {
  let leaked = 0; const target = await collector(t, (_req, res) => { leaked++; res.end('bad'); });
  for (const code of [307, 308]) {
    const origin = await collector(t, (_req, res) => { res.writeHead(code, { location: target }); res.end(); });
    const fetch = createRestrictedFetch({ allowedOrigins: [origin, target], allowPrivateOrigins: [origin, target] });
    await assert.rejects(fetch(origin, { method: 'POST', headers: { 'x-api-key': 'synthetic-key' }, body: 'synthetic-secret-body' }), { code: 'REDIRECT_DENIED' });
  }
  assert.equal(leaked, 0);
});
test('response and time limits terminate upstream streams', async t => {
  let closed = false;
  const origin = await collector(t, (req, res) => { req.on('close', () => { closed = true; }); res.write('1234567890'); });
  const fetch = createRestrictedFetch({ allowedOrigins: [origin], allowPrivateOrigins: [origin], maxResponseBytes: 5, timeoutMs: 100 });
  await assert.rejects(async () => (await fetch(origin)).text());
  await new Promise(resolve => setTimeout(resolve, 20)); assert.equal(closed, true);
});

test('hostile HTTP status cannot escape the response callback and crash the credential owner', { timeout: 5000 }, async t => {
  let requests = 0;
  const origin = await collector(t, (req, res) => {
    requests++;
    res.writeHead(req.url === '/benign' ? 200 : Number(req.url.slice(1)));
    res.end('synthetic');
  });
  const module = new URL('../dist/index.js', import.meta.url).href;
  const source = `import assert from 'node:assert/strict';
    import {createRestrictedFetch} from ${JSON.stringify(module)};
    const origin = process.argv[1];
    const fetch = createRestrictedFetch({allowedOrigins:[origin],allowPrivateOrigins:[origin],timeoutMs:1000});
    for (const status of [600, 999]) await assert.rejects(fetch(origin+'/'+status), {code:'RESPONSE_INVALID'});
    assert.equal(await (await fetch(origin+'/benign')).text(),'synthetic');
    process.stdout.write('rejected hostile statuses and recovered');`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source, origin], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
  const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  assert.equal(status, 0, stderr);
  assert.equal(stdout, 'rejected hostile statuses and recovered');
  assert.equal(requests, 3);
});
