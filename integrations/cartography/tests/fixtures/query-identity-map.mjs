// The Python fixture verifies the owned disposable graph before invoking this bridge.
// No credentials, cookies or provider tokens are written to stdout/stderr.
import { readFileSync } from 'node:fs';
import { createNeo4jMapStore } from '../../../../packages/agent-map/dist/store.js';
import { MapService } from '../../../../packages/agent-map/dist/service.js';
import { startMapIdentityServer } from '../../../../packages/agent-map/dist/identity-http.js';
import { createTestIdentityProvider, testHttps } from '../../../../packages/agent-map/test/helpers/oidc-provider.mjs';

const cleanup = [];
let result = { ok: false, error: 'IDENTITY_GRAPH_CHECK_FAILED' };
try {
  const configuration = JSON.parse(readFileSync(process.env.AGENT_GUARD_TEST_NEO4J_CONFIG, 'utf8'));
  const input = JSON.parse(readFileSync(0, 'utf8'));
  const provider = await createTestIdentityProvider({ after(fn) { cleanup.push(fn); } });
  const store = createNeo4jMapStore({ uri: configuration.uri, username: configuration.username, password: configuration.password });
  cleanup.push(() => store.close());
  const subject = 'identity-test-reader';
  const server = await startMapIdentityServer({ service: new MapService(store, { clock: () => 1793350800000 }),
    publicOrigin: 'https://127.0.0.1:0', port: 0, tls: { cert: provider.cert, key: provider.key },
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret, ca: provider.ca },
    companyId: input.scope.companyId, bindings: [{ subject, scope: input.scope }] });
  cleanup.push(() => server.close());
  const cookies = new Map();
  async function send(path, method = 'GET', data, csrf) {
    const body = data === undefined ? undefined : JSON.stringify(data);
    const headers = { ...(cookies.size ? { Cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join('; ') } : {}),
      ...(method === 'POST' ? { Origin: server.url, 'Content-Type': 'application/json' } : {}),
      ...(csrf ? { 'X-CSRF-Token': csrf } : {}) };
    const response = await testHttps(server.url + path, { ca: provider.ca, method, headers, body });
    for (const header of response.headers['set-cookie'] ?? []) {
      const pair = header.split(';')[0], at = pair.indexOf('=');
      if (!pair.slice(at + 1) || /Max-Age=0(?:;|$)/.test(header)) cookies.delete(pair.slice(0, at));
      else cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }
  const anonymous = await send('/auth/session');
  if (anonymous.status !== 200 || anonymous.json().authenticated !== false) throw new Error();
  const begun = await send('/auth/login', 'POST', {}, anonymous.json().csrfToken);
  if (begun.status !== 200) throw new Error();
  const callback = await provider.authorize(begun.json().authorizationUrl, { subject,
    extraClaims: { companyId: 'wrong-company', tenantIds: ['wrong-tenant'], teamIds: ['hidden-team'], allTeams: true } });
  const authenticated = await send(callback.pathname + callback.search);
  if (authenticated.status !== 303 || authenticated.headers.location !== '/') throw new Error();
  const session = await send('/auth/session');
  if (session.status !== 200 || session.json().authenticated !== true) throw new Error();
  const csrf = session.json().csrfToken, outputs = [];
  for (const operation of input.operations) {
    const response = await send('/v1/query', 'POST', operation, csrf);
    outputs.push({ status: response.status, response: response.json() });
  }
  server.revokeSubject(subject);
  const revoked = await send('/v1/query', 'POST', { operation: 'list_agents', args: {} }, csrf);
  result = { ok: true, outputs, revokedStatus: revoked.status, revokedResponse: revoked.json() };
} catch { process.exitCode = 1; }
finally {
  for (const close of cleanup.reverse()) {
    try { await close(); } catch { result = { ok: false, error: 'IDENTITY_GRAPH_CLEANUP_FAILED' }; process.exitCode = 1; }
  }
}
process.stdout.write(JSON.stringify(result));
