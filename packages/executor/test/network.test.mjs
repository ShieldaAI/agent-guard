import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

test('a bodyless response closes its socket even if the peer keeps sending a 205 body', { timeout: 2000 }, async t => {
  let disconnected;
  const closed = new Promise(resolve => { disconnected = resolve; });
  const origin = await collector(t, (req, res) => {
    req.socket.once('close', disconnected);
    res.writeHead(205); res.write('unsolicited bytes');
  });
  const network = createRestrictedFetch({ allowedOrigins: [origin], allowPrivateOrigins: [origin], timeoutMs: 200 });
  const response = await network(origin);
  assert.equal(response.status, 205); assert.equal(response.body, null);
  await closed;
});

test('a hostile request stream cannot indefinitely postpone size rejection during cancellation', { timeout: 2000 }, async t => {
  let requests = 0;
  const origin = await collector(t, (_req, res) => { requests++; res.end(); });
  const network = createRestrictedFetch({ allowedOrigins: [origin], allowPrivateOrigins: [origin], maxRequestBytes: 1 });
  const body = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(2)); }, cancel() { return new Promise(() => {}); } });
  await assert.rejects(network(origin, { method: 'POST', body, duplex: 'half' }), { code: 'REQUEST_TOO_LARGE' });
  assert.equal(requests, 0);
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

function tlsFixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'guard-network-tls-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const openssl = (...args) => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
  for (const name of ['ca', 'wrong-ca']) openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.pem`, '-days', '2', '-subj', `/CN=Disposable ${name}`);
  openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=127.0.0.1');
  writeFileSync(join(directory, 'extensions'), 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
  openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '2', '-extfile', 'extensions');
  return Object.fromEntries([['ca', 'ca.pem'], ['wrongCa', 'wrong-ca.pem'], ['key', 'leaf.key'], ['cert', 'leaf.pem']].map(([key, file]) => [key, readFileSync(join(directory, file), 'utf8')]));
}
async function tlsCollector(t, tls) {
  let requests = 0, connections = 0;
  const server = createHttpsServer({ key: tls.key, cert: tls.cert }, (_req, res) => { requests++; res.end('accepted'); });
  server.on('connection', () => connections++);
  server.on('tlsClientError', (_error, socket) => socket.destroy());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return { origin: `https://127.0.0.1:${server.address().port}`, counts: () => ({ requests, connections }) };
}
async function isolated(t, source, ...args) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', source, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let stdout = '', stderr = '';
  child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
  const timer = setTimeout(() => child.kill('SIGKILL'), 8000);
  try {
    const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
    assert.equal(status, 0, stderr || stdout); return stdout;
  } finally { clearTimeout(timer); }
}

test('additional CA trust is bounded and belongs only to its exact allowed HTTPS origin', { timeout: 10000 }, async t => {
  const tls = tlsFixture(t), first = await tlsCollector(t, tls), second = await tlsCollector(t, tls);
  const policy = { allowedOrigins: [first.origin, second.origin], allowPrivateOrigins: [first.origin, second.origin], timeoutMs: 1000 };
  await assert.rejects(createRestrictedFetch(policy)(first.origin), { code: 'REQUEST_FAILED' });
  await assert.rejects(createRestrictedFetch({ ...policy, additionalCaByOrigin: { [first.origin]: tls.wrongCa } })(first.origin), { code: 'REQUEST_FAILED' });
  const certificates = { [second.origin]: tls.ca };
  const trusted = createRestrictedFetch({ ...policy, additionalCaByOrigin: certificates });
  certificates[second.origin] = tls.wrongCa; // The trust configuration is copied at creation.
  await assert.rejects(trusted(first.origin), { code: 'REQUEST_FAILED' });
  assert.equal(await (await trusted(second.origin)).text(), 'accepted');
  assert.equal(first.counts().requests, 0); assert.equal(second.counts().requests, 1);
  for (const additionalCaByOrigin of [
    null, [], new Date(), 'certificate', { [first.origin]: '' }, { [first.origin]: 'not a certificate' },
    { [first.origin]: tls.ca + 'unparsed material' }, { [first.origin]: tls.ca.repeat(17) },
    { [first.origin]: ' '.repeat(262145) }, { [first.origin]: 42 },
    { ['https://elsewhere.invalid']: tls.ca }, { [first.origin + '/path']: tls.ca },
  ]) assert.throws(() => createRestrictedFetch({ ...policy, additionalCaByOrigin }), { code: 'NETWORK_CONFIG_INVALID' });
  assert.throws(() => createRestrictedFetch({ allowedOrigins: ['http://127.0.0.1'], allowPrivateOrigins: ['http://127.0.0.1'], additionalCaByOrigin: { 'http://127.0.0.1': tls.ca } }), { code: 'NETWORK_CONFIG_INVALID' });
});

test('trusted CA does not disable hostname validation or grant private network access', { timeout: 10000 }, async t => {
  const tls = tlsFixture(t), sink = await tlsCollector(t, tls);
  await assert.rejects(createRestrictedFetch({ allowedOrigins: [sink.origin], additionalCaByOrigin: { [sink.origin]: tls.ca } })(sink.origin), { code: 'DESTINATION_DENIED' });
  assert.equal(sink.counts().connections, 0);
  const module = new URL('../dist/index.js', import.meta.url).href;
  const source = `import assert from 'node:assert/strict';
    import dns from 'node:dns'; import {syncBuiltinESMExports} from 'node:module';
    dns.lookup = (host, options, callback) => callback(null, [{address:'127.0.0.1',family:4}]);
    syncBuiltinESMExports();
    const {createRestrictedFetch}=await import(${JSON.stringify(module)});
    const input=JSON.parse(process.argv[1]); const origin=input.origin.replace('127.0.0.1','wrong-host.invalid');
    const network=createRestrictedFetch({allowedOrigins:[origin],allowPrivateOrigins:[origin],additionalCaByOrigin:{[origin]:input.ca},timeoutMs:1000});
    await assert.rejects(network(origin),{code:'REQUEST_FAILED'});
    console.log('hostname rejected');`;
  assert.match(await isolated(t, source, JSON.stringify({ origin: sink.origin, ca: tls.ca })), /hostname rejected/);
  assert(sink.counts().connections > 0); assert.equal(sink.counts().requests, 0);
});

test('actual socket lookup rejects private and mixed answers and rechecks rebinding after a cancelled lookup', { timeout: 10000 }, async t => {
  const tls = tlsFixture(t), sink = await tlsCollector(t, tls);
  const module = new URL('../dist/index.js', import.meta.url).href;
  // Only the OS resolver is replaced, in a child. Node's real HTTPS socket and the production lookup gate remain in use.
  const source = `import assert from 'node:assert/strict';
    import dns from 'node:dns'; import {syncBuiltinESMExports} from 'node:module';
    const input=JSON.parse(process.argv[1]); const origin=input.origin.replace('127.0.0.1','rebind-fixture.invalid');
    let answers=[{address:'127.0.0.1',family:4}], calls=0, delayed;
    dns.lookup=(host,options,callback)=>{assert.equal(host,'rebind-fixture.invalid'); assert.equal(options.all,true); calls++; if(delayed) delayed(callback); else callback(null,answers);};
    syncBuiltinESMExports();
    const {createRestrictedFetch}=await import(${JSON.stringify(module)});
    const network=createRestrictedFetch({allowedOrigins:[origin],additionalCaByOrigin:{[origin]:input.ca},timeoutMs:300});
    for(const records of [
      [{address:'127.0.0.1',family:4}], [{address:'::1',family:6}],
      [{address:'::ffff:127.0.0.1',family:6}], [{address:'169.254.169.254',family:4}],
      [{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}],
      [{address:'127.0.0.1',family:4},{address:'8.8.8.8',family:4}]
    ]) {answers=records;await assert.rejects(network(origin),{code:'DESTINATION_DENIED'});}
    assert.equal(calls,6);
    let finishLookup; delayed=callback=>{finishLookup=callback;};
    const controller=new AbortController(); const pending=network(origin,{signal:controller.signal});
    const rejected=assert.rejects(pending,{code:'REQUEST_ABORTED'});
    while(!finishLookup) await new Promise(resolve=>setTimeout(resolve,1));
    controller.abort(); await rejected;
    // A public answer arriving after cancellation must never open a connection, including to that public address.
    finishLookup(null,[{address:'8.8.8.8',family:4}]); delayed=undefined;
    answers=[{address:'127.0.0.1',family:4}];
    await assert.rejects(network(origin),{code:'DESTINATION_DENIED'}); assert.equal(calls,8);
    // Also exercise a lookup completing after the request's own deadline.
    delayed=callback=>setTimeout(()=>callback(null,[{address:'127.0.0.1',family:4}]),400);
    await assert.rejects(network(origin),{code:'REQUEST_ABORTED'});
    await new Promise(resolve=>setTimeout(resolve,150));
    console.log('DNS policy rejected private mixed and rebound answers');`;
  assert.match(await isolated(t, source, JSON.stringify({ origin: sink.origin, ca: tls.ca })), /DNS policy rejected/);
  assert.equal(sink.counts().connections, 0); assert.equal(sink.counts().requests, 0);
});
