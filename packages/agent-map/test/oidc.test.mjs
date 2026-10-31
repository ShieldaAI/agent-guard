import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { createMapOidcClient } from '../dist/oidc.js';
import { createTestIdentityProvider } from './helpers/oidc-provider.mjs';

const redirectUri = 'https://127.0.0.1:9999/auth/callback';
const configuration = (provider, extra = {}) => ({ issuer: provider.issuer, clientId: provider.clientId,
  clientSecret: provider.clientSecret, redirectUri, ca: provider.ca, ...extra });
const transaction = ({ state, nonce, codeVerifier }) => ({ state, nonce, codeVerifier });
const calls = (provider, path) => provider.requests.filter(request => request.path === path).length;
async function flow(client, provider, overrides = {}) {
  const start = await client.begin(); return { start, callback: await provider.authorize(start.authorizationUrl, overrides) };
}

test('real HTTPS OIDC discovery, PKCE, nonce and signature produce only subject and expiry', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider));
  const expiresAt = Math.floor(Date.now() / 1000) * 1000 + 240_000;
  const { start, callback } = await flow(client, provider, { subject: 'reader-exact', expiresAt,
    extraClaims: { companyId: 'attacker', tenantIds: ['other'], teamIds: ['admins'], allTeams: true, email: 'not-an-identity@example.invalid' } });
  const authorization = new URL(start.authorizationUrl);
  assert.equal(authorization.searchParams.get('scope'), 'openid');
  assert.equal(authorization.searchParams.get('code_challenge'), createHash('sha256').update(start.codeVerifier).digest('base64url'));
  assert.equal(authorization.searchParams.get('redirect_uri'), redirectUri);
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  const result = await client.complete(callback, transaction(start));
  assert.deepEqual(result, { subject: 'reader-exact', expiresAt }); assert.ok(Object.isFrozen(result));
  assert.equal(calls(provider, '/token'), 1); assert.equal(calls(provider, '/jwks'), 1);
  assert.equal(JSON.stringify(result).includes('test-access-token'), false);
  await assert.rejects(client.complete(callback, transaction(start)), { code: 'MAP_IDENTITY_INVALID' });
});

test('configured client_secret_post is supported only when advertised', async t => {
  const provider = await createTestIdentityProvider(t);
  const client = await createMapOidcClient(configuration(provider, { clientAuthMethod: 'client_secret_post' }));
  const { start, callback } = await flow(client, provider);
  assert.equal((await client.complete(callback, transaction(start))).subject, 'reader-1');
  provider.controls.metadata.token_endpoint_auth_methods_supported = ['client_secret_basic'];
  await assert.rejects(createMapOidcClient(configuration(provider, { clientAuthMethod: 'client_secret_post' })), { code: 'MAP_IDENTITY_INVALID' });
});

test('signed but invalid issuer, audience, nonce, times and subjects never authenticate', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider));
  const now = Date.now();
  for (const [name, overrides] of [
    ['issuer', { issuer: 'https://wrong.example' }], ['audience', { audience: 'another-client' }],
    ['nonce', { nonce: 'wrong-nonce' }], ['expired', { expiresAt: now - 10_000 }],
    ['not before', { notBefore: now + 60_000 }], ['future issued', { claims: { iat: Math.floor(now / 1000) + 60 } }],
    ['authorized party', { claims: { azp: 'another-client' } }], ['multiple audiences', { audience: [provider.clientId, 'other'] }],
    ['empty subject', { subject: '' }], ['oversized subject', { subject: 'x'.repeat(4097) }],
    ['invalid subject unicode', { subject: '\ud800' }], ['invalid expiration', { claims: { exp: Number.MAX_SAFE_INTEGER } }],
    ['wrong signature', { badSignature: true }], ['unknown key', { keyId: 'not-enrolled-key' }],
    ['wrong algorithm', { algorithm: 'HS256' }],
  ]) await t.test(name, async () => {
    const { start, callback } = await flow(client, provider, overrides);
    await assert.rejects(client.complete(callback, transaction(start)), { code: 'MAP_IDENTITY_INVALID' });
  });
});

test('callback authority, duplicate parameters and state are checked before credential exchange', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider));
  for (const mutate of [url => { url.hostname = 'other.example'; }, url => { url.pathname = '/other'; },
    url => { url.protocol = 'http:'; }, url => { url.hash = 'ignored'; }, url => { url.username = 'user'; },
    url => { url.searchParams.append('state', url.searchParams.get('state')); }, url => { url.searchParams.set('state', 'wrong'); },
    url => { url.searchParams.append('error', 'access_denied'); }, url => { url.searchParams.append('response', 'unexpected-jarm'); },
    url => { url.searchParams.delete('code'); }, url => { for (let i = 0; i < 17; i++) url.searchParams.append(`extra${i}`, 'x'); },
    url => { url.searchParams.set('iss', 'https://other.example'); },
  ]) {
    const { start, callback } = await flow(client, provider); mutate(callback);
    await assert.rejects(client.complete(callback, transaction(start)), { code: 'MAP_IDENTITY_INVALID' });
  }
  assert.equal(calls(provider, '/token'), 0);
  const { start, callback } = await flow(client, provider);
  callback.searchParams.set('session_state', 'harmless-provider-session'); callback.searchParams.set('authuser', '0');
  assert.equal((await client.complete(callback, transaction(start))).subject, 'reader-1');
});

test('wrong PKCE verifier or a missing ID token cannot authenticate', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider));
  const badPkce = await flow(client, provider);
  await assert.rejects(client.complete(badPkce.callback, { ...transaction(badPkce.start), codeVerifier: 'z'.repeat(43) }), { code: 'MAP_IDENTITY_INVALID' });
  provider.controls.tokenResponse = { access_token: 'private-test-access-token', token_type: 'Bearer' };
  const missing = await flow(client, provider);
  await assert.rejects(client.complete(missing.callback, transaction(missing.start)), { code: 'MAP_IDENTITY_INVALID' });
});

test('discovery pins exact issuer, algorithms, PKCE and all credential-bearing endpoints', async t => {
  const provider = await createTestIdentityProvider(t);
  for (const metadata of [{ issuer: provider.issuer + '/' }, { issuer: 'https://other.example' },
    { authorization_endpoint: 'https://other.example/authorize' }, { token_endpoint: 'https://other.example/token' },
    { jwks_uri: 'https://other.example/jwks' }, { token_endpoint: provider.issuer.replace('https:', 'http:') + '/token' },
    { token_endpoint: provider.issuer + '/token?extra=1' }, { code_challenge_methods_supported: ['plain'] },
    { id_token_signing_alg_values_supported: ['HS256'] }]) {
    provider.controls.metadata = metadata;
    await assert.rejects(createMapOidcClient(configuration(provider)), { code: 'MAP_IDENTITY_INVALID' });
  }
  assert.equal(calls(provider, '/token'), 0);
  provider.controls.metadata = { token_endpoint: 'https://explicit.example/token' };
  await createMapOidcClient(configuration(provider, { endpointOrigins: ['https://explicit.example'] }));
  assert.equal(calls(provider, '/token'), 0);
});

test('untrusted TLS fails even though the issuer is loopback', async t => {
  const provider = await createTestIdentityProvider(t), options = configuration(provider); delete options.ca;
  await assert.rejects(createMapOidcClient(options), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  assert.equal(provider.requests.length, 0);
});

test('configuration rejects insecure URLs, accessors and unsupported auth without network activity', async t => {
  const provider = await createTestIdentityProvider(t);
  for (const extra of [{ issuer: 'http://localhost' }, { issuer: provider.issuer + '/.well-known/openid-configuration' },
    { redirectUri: redirectUri.replace('https:', 'http:') }, { redirectUri: redirectUri + '?returnTo=attacker' },
    { redirectUri: 'https://127.0.0.1/other' }, { clientAuthMethod: 'none' }, { ca: 'not-a-certificate' },
    { endpointOrigins: ['http://other.example'] }, { endpointOrigins: [provider.issuer + '/path'] },
    { endpointOrigins: [provider.issuer] }, { requestTimeoutMs: 10 }, { maxResponseBytes: 2_000_000 }])
    await assert.rejects(createMapOidcClient(configuration(provider, extra)), { code: 'MAP_CONFIG_INVALID' });
  const options = configuration(provider); let invoked = false;
  Object.defineProperty(options, 'clientSecret', { get() { invoked = true; return provider.clientSecret; } });
  await assert.rejects(createMapOidcClient(options), { code: 'MAP_CONFIG_INVALID' });
  assert.equal(invoked, false); assert.equal(provider.requests.length, 0);
});

test('discovery, token and JWKS response bounds and redirects fail closed', async t => {
  const provider = await createTestIdentityProvider(t);
  provider.controls.oversizedResponse = '/.well-known/openid-configuration';
  await assert.rejects(createMapOidcClient(configuration(provider)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  provider.controls.oversizedResponse = null; provider.controls.redirectPath = '/.well-known/openid-configuration';
  await assert.rejects(createMapOidcClient(configuration(provider)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  provider.controls.redirectPath = null;
  const client = await createMapOidcClient(configuration(provider, { maxResponseBytes: 1024 }));
  for (const path of ['/token', '/jwks']) {
    provider.controls.oversizedResponse = path; const large = await flow(client, provider);
    await assert.rejects(client.complete(large.callback, transaction(large.start)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
    provider.controls.oversizedResponse = null; provider.controls.redirectPath = path;
    const redirected = await flow(client, provider);
    await assert.rejects(client.complete(redirected.callback, transaction(redirected.start)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
    provider.controls.redirectPath = null;
  }
});

test('malformed UTF-8, duplicate JSON and encoded provider responses are rejected', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider));
  for (const rawResponse of [{ path: '/token', body: '{"access_token":"first","access_token":"second","token_type":"Bearer"}' },
    { path: '/token', body: Buffer.from([0xff]) },
    { path: '/token', body: '{}', headers: { 'content-encoding': 'gzip' } }]) {
    provider.controls.rawResponse = rawResponse; const { start, callback } = await flow(client, provider);
    await assert.rejects(client.complete(callback, transaction(start)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  }
});

test('one absolute deadline covers token and subsequent JWKS retrieval', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider, { requestTimeoutMs: 10_000 }));
  const { start, callback } = await flow(client, provider);
  let elapsed = 0;
  const stages = [];
  const advance = request => {
    if (request.url === '/token') { elapsed += 4000; stages.push('token'); }
    if (request.url === '/jwks') { elapsed += 7000; stages.push('jwks'); }
  };
  // Advance only when each real HTTPS stage begins. Either stage alone fits
  // the budget, but their total does not; CPU scheduling cannot skip JWKS as
  // it could with two wall-clock sleeps competing with a short timer.
  const clock = t.mock.method(performance, 'now', () => elapsed);
  provider.server.prependListener('request', advance);
  try {
    await assert.rejects(client.complete(callback, transaction(start)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
    assert.deepEqual(stages, ['token', 'jwks']);
    assert.equal(calls(provider, '/token'), 1); assert.equal(calls(provider, '/jwks'), 1);
    assert.equal(elapsed, 11_000);
  } finally { clock.mock.restore(); provider.server.off('request', advance); }
});

test('cancellation is per exchange and cannot authenticate later or cancel another login', async t => {
  const provider = await createTestIdentityProvider(t), client = await createMapOidcClient(configuration(provider));
  const first = await flow(client, provider), second = await flow(client, provider);
  provider.controls.tokenDelayMs = 80;
  const controller = new AbortController();
  const cancelled = assert.rejects(client.complete(first.callback, transaction(first.start), controller.signal), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  const good = client.complete(second.callback, transaction(second.start));
  setTimeout(() => controller.abort(), 20);
  await cancelled; assert.equal((await good).subject, 'reader-1');
  const early = await flow(client, provider), before = calls(provider, '/token');
  await assert.rejects(client.complete(early.callback, transaction(early.start), AbortSignal.abort()), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  assert.equal(calls(provider, '/token'), before);
});

test('late DNS completion after deadline never dispatches client credentials', async t => {
  const provider = await createTestIdentityProvider(t), local = provider.issuer.replace('127.0.0.1', 'localhost');
  provider.controls.metadata = { token_endpoint: local + '/token' };
  const client = await createMapOidcClient(configuration(provider, { endpointOrigins: [local], requestTimeoutMs: 100 }));
  const { start, callback } = await flow(client, provider);
  let release;
  const mocked = t.mock.method(dns, 'lookup', (_hostname, _options, done) => { release = done; });
  syncBuiltinESMExports(); t.after(() => { mocked.mock.restore(); syncBuiltinESMExports(); });
  await assert.rejects(client.complete(callback, transaction(start)), { code: 'MAP_IDENTITY_UNAVAILABLE' });
  assert.equal(typeof release, 'function'); release(null, [{ address: '127.0.0.1', family: 4 }]);
  await new Promise(resolve => setTimeout(resolve, 20)); assert.equal(calls(provider, '/token'), 0);
});
