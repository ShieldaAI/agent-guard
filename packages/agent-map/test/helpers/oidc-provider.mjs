import { createServer, request } from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

/** Private disposable CA, HTTPS issuer and real signed ID tokens; never changes global trust. */
export async function createTestIdentityProvider(t) {
  const directory = mkdtempSync(join(tmpdir(), 'agent-map-oidc-'));
  chmodSync(directory, 0o700);
  const openssl = (...args) => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
  try {
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
      '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Agent Map Disposable Test CA');
    openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
      '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=localhost');
    writeFileSync(join(directory, 'extensions.txt'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n', { mode: 0o600 });
    openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
      '-out', 'leaf.pem', '-days', '2', '-extfile', 'extensions.txt');
  } catch (error) { rmSync(directory, { recursive: true, force: true }); throw error; }
  const ca = readFileSync(join(directory, 'ca.pem'), 'utf8');
  const cert = readFileSync(join(directory, 'leaf.pem'), 'utf8');
  const key = readFileSync(join(directory, 'leaf.key'), 'utf8');
  const signing = await generateKeyPair('RS256');
  const wrongSigning = await generateKeyPair('RS256');
  const publicKey = { ...await exportJWK(signing.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
  const clientId = 'agent-map-test', clientSecret = randomBytes(32).toString('base64url');
  const controls = { tokenDelayMs: 0, jwksDelayMs: 0, discoveryDelayMs: 0, metadata: {},
    authorizeOverrides: {}, oversizedResponse: null, oversizedBytes: 300_000,
    redirectPath: null, redirectLocation: 'https://invalid.example/redirect',
    tokenResponse: null, jwksResponse: null, rawResponse: null };
  const requests = [], codes = new Map(); let issuer, closed = false;
  const pause = (ms, response) => new Promise(resolve => {
    const done = () => { clearTimeout(timer); response.off('close', done); resolve(); };
    const timer = setTimeout(done, ms); response.once('close', done);
  });
  const json = (response, status, value) => {
    if (response.destroyed) return;
    const body = Buffer.from(JSON.stringify(value));
    response.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, 'cache-control': 'no-store' }); response.end(body);
  };
  async function authorize(authorizationUrl, overrides = {}) {
    const url = new URL(authorizationUrl);
    if (url.origin !== issuer || url.pathname !== '/authorize') throw new Error('TEST_AUTHORIZATION_INVALID');
    for (const name of ['client_id', 'redirect_uri', 'response_type', 'scope', 'code_challenge_method', 'code_challenge', 'state', 'nonce'])
      if (url.searchParams.getAll(name).length !== 1) throw new Error('TEST_AUTHORIZATION_INVALID');
    const redirect = new URL(url.searchParams.get('redirect_uri'));
    if (url.searchParams.get('client_id') !== clientId || url.searchParams.get('response_type') !== 'code' ||
        url.searchParams.get('scope') !== 'openid' || url.searchParams.get('code_challenge_method') !== 'S256' ||
        !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('code_challenge')) ||
        redirect.protocol !== 'https:' || !['127.0.0.1', 'localhost'].includes(redirect.hostname) || redirect.pathname !== '/auth/callback') throw new Error('TEST_AUTHORIZATION_INVALID');
    const code = randomBytes(32).toString('base64url');
    codes.set(code, { challenge: url.searchParams.get('code_challenge'), redirect: redirect.href,
      nonce: url.searchParams.get('nonce'), overrides });
    redirect.searchParams.set('code', code); redirect.searchParams.set('state', url.searchParams.get('state'));
    redirect.searchParams.set('iss', issuer);
    return redirect;
  }
  const server = createServer({ key, cert }, (req, res) => { void (async () => {
    const path = new URL(req.url, issuer).pathname; requests.push({ path, method: req.method });
    if (controls.rawResponse?.path === path) { const body = controls.rawResponse.body;
      res.writeHead(200, { 'content-type': 'application/json', ...controls.rawResponse.headers }); res.end(body); return; }
    if (controls.redirectPath === path) { res.writeHead(302, { location: controls.redirectLocation }); res.end(); return; }
    if (controls.oversizedResponse === path) { json(res, 200, { padding: 'x'.repeat(controls.oversizedBytes) }); return; }
    if (path === '/.well-known/openid-configuration') {
      await pause(controls.discoveryDelayMs, res);
      json(res, 200, { issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token',
        jwks_uri: issuer + '/jwks', response_types_supported: ['code'], subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        authorization_response_iss_parameter_supported: true, ...controls.metadata }); return;
    }
    if (path === '/jwks') { await pause(controls.jwksDelayMs, res); json(res, 200, controls.jwksResponse ?? { keys: [publicKey] }); return; }
    if (path === '/authorize' && req.method === 'GET') {
      res.writeHead(303, { location: (await authorize(issuer + req.url, controls.authorizeOverrides)).href }); res.end(); return;
    }
    if (path !== '/token' || req.method !== 'POST') { json(res, 404, { error: 'not_found' }); return; }
    let body = ''; for await (const chunk of req) { body += chunk; if (body.length > 16_384) { json(res, 400, { error: 'invalid_request' }); return; } }
    const form = new URLSearchParams(body);
    if ([...form.keys()].some(name => form.getAll(name).length !== 1)) { json(res, 400, { error: 'invalid_request' }); return; }
    let basicValid = false;
    if (req.headers.authorization?.startsWith('Basic ')) {
      const encoded = Buffer.from(req.headers.authorization.slice(6), 'base64').toString(), separator = encoded.indexOf(':');
      const decode = value => decodeURIComponent(value.replaceAll('+', ' '));
      basicValid = separator >= 0 && decode(encoded.slice(0, separator)) === clientId && decode(encoded.slice(separator + 1)) === clientSecret;
    }
    if (!basicValid && !(form.get('client_id') === clientId && form.get('client_secret') === clientSecret)) {
      json(res, 401, { error: 'invalid_client' }); return;
    }
    const record = codes.get(form.get('code')); codes.delete(form.get('code'));
    if (!record || form.get('grant_type') !== 'authorization_code' || form.get('redirect_uri') !== record.redirect ||
        createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== record.challenge) {
      json(res, 400, { error: 'invalid_grant' }); return;
    }
    await pause(controls.tokenDelayMs, res); if (res.destroyed) return;
    if (controls.tokenResponse !== null) { json(res, 200, controls.tokenResponse); return; }
    const overrides = record.overrides, now = Math.floor(Date.now() / 1000);
    const claims = { ...overrides.extraClaims, iss: overrides.issuer ?? issuer,
      sub: overrides.subject ?? 'reader-1', aud: overrides.audience ?? clientId, iat: now,
      exp: overrides.expiresAt === undefined ? now + 300 : Math.floor(overrides.expiresAt / 1000),
      nonce: overrides.nonce ?? record.nonce,
      ...(overrides.notBefore === undefined ? {} : { nbf: Math.floor(overrides.notBefore / 1000) }),
      ...overrides.claims };
    const alg = overrides.algorithm ?? 'RS256';
    const signingKey = alg === 'HS256' ? randomBytes(32) : overrides.badSignature ? wrongSigning.privateKey : signing.privateKey;
    const idToken = await new SignJWT(claims).setProtectedHeader({ alg, kid: overrides.keyId ?? 'test-key' }).sign(signingKey);
    json(res, 200, { access_token: 'test-access-token-not-for-browser', token_type: 'Bearer', expires_in: 300, id_token: idToken });
  })().catch(() => json(res, 400, { error: 'invalid_request' })); });
  server.on('clientError', (_error, socket) => socket.destroy());
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  issuer = `https://127.0.0.1:${server.address().port}`;
  async function close() { if (closed) return; closed = true; server.closeAllConnections();
    await new Promise(resolve => server.close(resolve)); rmSync(directory, { recursive: true, force: true }); }
  t.after(close);
  return { issuer, ca, cert, key, clientId, clientSecret, authorize, controls, requests, server, close };
}

/** HTTPS client for tests: explicit private CA, no redirects, no global trust changes. */
export function testHttps(url, { ca, method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(url, { ca, method, headers, rejectUnauthorized: true }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.once('error', reject);
      res.on('end', () => { const text = Buffer.concat(chunks).toString(); resolve({ status: res.statusCode,
        headers: res.headers, text, json: () => JSON.parse(text) }); });
    });
    req.once('error', reject); req.end(body);
  });
}
