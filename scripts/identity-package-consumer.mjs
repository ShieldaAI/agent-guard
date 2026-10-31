import assert from 'node:assert/strict';
import test from 'node:test';
import { MapService, startMapIdentityServer } from '@shieldaai/agent-map';
import { createTestIdentityProvider, testHttps } from './oidc-provider.mjs';

// Copied with its disposable fixture into the clean tarball consumer, outside the workspace.
test('installed identity API performs verified HTTPS login and a host-scoped query', async t => {
  const provider = await createTestIdentityProvider(t);
  let reads = 0;
  const scope = { subject: 'host-reader', companyId: 'pack-test', tenantIds: ['one'], teamIds: ['blue'], allTeams: false };
  const service = new MapService({ async read(actual) { reads++; assert.deepEqual(JSON.parse(JSON.stringify(actual)), scope); return { sources: [] }; } });
  const gateway = await startMapIdentityServer({ service, companyId: 'pack-test', bindings: [{ subject: 'reader-1', scope }],
    publicOrigin: 'https://127.0.0.1:0', tls: { key: provider.key, cert: provider.cert },
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret, ca: provider.ca } });
  t.after(() => gateway.close());
  const cookies = new Map();
  async function request(path, options = {}) {
    const response = await testHttps(gateway.url + path, { ca: provider.ca, ...options,
      headers: { ...(cookies.size ? { cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; ') } : {}), ...options.headers } });
    for (const cookie of response.headers['set-cookie'] ?? []) {
      const pair = cookie.split(';')[0], at = pair.indexOf('='); cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }
  const anonymous = await request('/auth/session'); assert.equal(anonymous.status, 200);
  const login = await request('/auth/login', { method: 'POST', headers: { origin: gateway.url,
    'content-type': 'application/json', 'x-csrf-token': anonymous.json().csrfToken }, body: '{}' });
  assert.equal(login.status, 200);
  const callback = await provider.authorize(login.json().authorizationUrl);
  assert.equal((await request(callback.pathname + callback.search)).status, 303);
  const session = await request('/auth/session'); assert.equal(session.json().authenticated, true);
  const response = await request('/v1/query', { method: 'POST', headers: { origin: gateway.url,
    'content-type': 'application/json', 'x-csrf-token': session.json().csrfToken },
    body: JSON.stringify({ operation: 'list_agents', args: {} }) });
  assert.equal(response.status, 200); assert.equal(response.json().operation, 'list_agents'); assert.equal(reads, 1);
  gateway.revokeSubject('reader-1');
  assert.equal((await request('/auth/session')).json().authenticated, false);
});
