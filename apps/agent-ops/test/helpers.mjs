import { mkdtempSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { createLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';
import { readLedgerKeyringPolicy } from '../../../packages/executor/dist/ledger-maintenance.js';
import { normalizeLimits } from '../limits.mjs';
import { initializeRuntime, openRuntime } from '../runtime.mjs';
import { startOpsServer } from '../server.mjs';
import { createTestIdentityProvider, testHttps } from '../../../packages/agent-map/test/helpers/oidc-provider.mjs';

export const owner = { id: 'owner', tenantId: 'acme', roles: ['requester', 'reviewer', 'operator'] };
export function setup(t, options = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-test-')));
  for (const name of ['data', 'witness', 'config']) mkdirSync(join(directory, name), { mode: 0o700 });
  const config = { ledgerDatabase: join(directory, 'data/guard.sqlite'), backendDatabase: join(directory, 'data/tickets.sqlite'),
    ledgerWitness: join(directory, 'witness/guard.sqlite'), backendWitness: join(directory, 'witness/tickets.sqlite'), keyringFile: join(directory, 'config/keys.json'),
    limits: normalizeLimits(options.limits), ...(options.requests ? { requests: options.requests } : {}) };
  if (options.mirror) {
    config.historyDirectory = join(directory, 'history');
    config.historyMirrorDirectory = join(directory, 'witness/history-mirror');
    for (const path of [config.historyDirectory, config.historyMirrorDirectory]) mkdirSync(path, { mode: 0o700 });
  }
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'initial', maxKeys: config.limits.maxRetainedKeys });
  initializeRuntime(config, options.tickets ?? [ { id: 'T-1', tenantId: 'acme', title: 'Customer delivery', status: 'open' }, { id: 'T-2', tenantId: 'other', title: 'Private ticket', status: 'open' } ]);
  let runtime = openRuntime(config, options), closed = false;
  const close = () => { if (!closed) { runtime.close(); closed = true; } };
  t.after(() => { close(); rmSync(directory, { recursive: true, force: true }); });
  return { config, directory, get runtime() { return runtime; }, get workflow() { return runtime.workflow; }, close,
    reopen(next = {}) { close(); runtime = openRuntime(config, next); closed = false; return runtime; } };
}
export async function availablePort() {
  const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
export async function httpsSetup(t, options = {}) {
  const fixture = setup(t, { ...options, mirror: options.mirror ?? true }), provider = await createTestIdentityProvider(t), port = await availablePort();
  const origin = `https://localhost:${port}`;
  const config = { workflow: fixture.workflow, recovery: fixture.runtime.recovery, publicOrigin: origin, host: '127.0.0.1', port, tls: { key: provider.key, cert: provider.cert },
    keyringPolicy: () => readLedgerKeyringPolicy({ keyringFile: fixture.config.keyringFile }),
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret, ca: provider.ca },
    bindings: [{ subject: 'owner', ...owner }, { subject: 'requester', id: 'requester', tenantId: 'acme', roles: ['requester'] },
      { subject: 'foreign', id: 'foreign', tenantId: 'other', roles: ['requester', 'reviewer', 'operator'] }], ...options.server };
  const app = await startOpsServer(config); t.after(() => app.close());
  const request = (path, options = {}) => testHttps(new URL(path, origin), { ca: provider.ca, ...options });
  async function login(subject = 'owner') {
    const initial = await request('/api/session'), anonymous = initial.headers['set-cookie'][0].split(';')[0], csrf = initial.json().csrfToken;
    const begin = await request('/auth/login', { method: 'POST', headers: { Cookie: anonymous, Origin: origin, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' }, body: '{}' });
    const callback = await provider.authorize(begin.json().authorizationUrl, { subject });
    const done = await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: anonymous } });
    if (done.status !== 303) throw new Error(`login failed: ${done.text}`);
    const cookie = done.headers['set-cookie'][0].split(';')[0];
    const session = (await request('/api/session', { headers: { Cookie: cookie } })).json();
    return { cookie, session, post: (path, value, extra = {}) => request(path, { method: 'POST', headers: { Cookie: cookie, Origin: origin, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(value) }),
      get: path => request(path, { headers: { Cookie: cookie } }) };
  }
  return { ...fixture, fixture, provider, app, origin, config, request, login };
}
