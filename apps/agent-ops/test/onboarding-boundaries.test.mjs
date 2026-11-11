import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';
import { createTestIdentityProvider } from '../../../packages/agent-map/test/helpers/oidc-provider.mjs';
import { initializeRuntime, loadConfig } from '../runtime.mjs';
import { onboard, preflight } from '../onboarding.mjs';
import { normalizeLimits, assertCapacity } from '../limits.mjs';

const test = (name, fn) =>
  nodeTest(
    name,
    {
      skip:
        process.platform === 'win32'
          ? 'Private witnessed onboarding requires POSIX; Linux is the deployment runtime.'
          : false,
    },
    fn,
  );
const seed = id => ({ id, tenantId: 'acme', title: 'Customer ticket', status: 'open' });
async function fixture(t, limits = normalizeLimits()) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-onboarding-boundary-')));
  for (const name of ['data', 'witness', 'private']) mkdirSync(join(root, name), { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const provider = await createTestIdentityProvider(t);
  const config = {
    version: 1,
    limits,
    publicOrigin: 'https://localhost:8443',
    ledgerDatabase: join(root, 'data', 'authority.sqlite'),
    backendDatabase: join(root, 'data', 'tickets.sqlite'),
    ledgerWitness: join(root, 'witness', 'authority.sqlite'),
    backendWitness: join(root, 'witness', 'tickets.sqlite'),
    keyringFile: join(root, 'private', 'keys.json'),
    tls: { key: provider.key, cert: provider.cert },
    oidc: {
      issuer: provider.issuer,
      clientId: provider.clientId,
      clientSecret: provider.clientSecret,
      ca: provider.ca,
    },
    bindings: [{ subject: 'owner', id: 'owner', tenantId: 'acme', roles: ['requester', 'reviewer', 'operator'] }],
    agents: [],
  };
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'initial', maxKeys: limits.maxRetainedKeys });
  const files = {
    keyFile: join(root, 'private', 'tls.key'),
    certFile: join(root, 'private', 'tls.pem'),
    clientSecretFile: join(root, 'private', 'oidc-secret'),
    caFile: join(root, 'private', 'ca.pem'),
  };
  for (const [path, content] of [
    [files.keyFile, provider.key],
    [files.certFile, provider.cert],
    [files.clientSecretFile, provider.clientSecret],
    [files.caFile, provider.ca],
  ])
    writeFileSync(path, content, { mode: 0o600 });
  const manifest = {
    version: 1,
    company: { id: 'acme', name: 'Fixture company' },
    publicOrigin: config.publicOrigin,
    limits,
    owner: { subject: 'owner', id: 'owner' },
    storage: { dataDirectory: join(root, 'data'), witnessDirectory: join(root, 'witness') },
    tls: { keyFile: files.keyFile, certFile: files.certFile },
    oidc: {
      issuer: provider.issuer,
      clientId: provider.clientId,
      clientSecretFile: files.clientSecretFile,
      caFile: files.caFile,
    },
  };
  const manifestFile = join(root, 'private', 'manifest.json');
  const saveManifest = () => writeFileSync(manifestFile, JSON.stringify(manifest), { mode: 0o600 });
  saveManifest();
  return {
    root,
    provider,
    config,
    manifest,
    manifestFile,
    saveManifest,
    authorityPaths: [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness],
  };
}

function almostFullSeed(limits) {
  const tickets = Array.from({ length: limits.maxTickets }, (_, i) => ({
    ...seed(`T-${String(i).padStart(158, '0')}`),
    title: '"'.repeat(240),
  }));
  const prospective = count => ({
    tickets: Object.fromEntries(tickets.slice(0, count).map(ticket => [ticket.id, { ...ticket, version: 1 }])),
    requests: {},
    receipts: {},
    limits,
  });
  let low = 0,
    high = tickets.length;
  while (low < high) {
    const count = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(JSON.stringify(prospective(count))) <= limits.maxBackendBytes) low = count;
    else high = count - 1;
  }
  assert.ok(low > 500 && low < tickets.length);
  assertCapacity(prospective(low), limits); // Ticket data alone fits; the ledger and startup metadata still need headroom.
  return tickets.slice(0, low);
}

test('near-cap seed fails before any authority files or onboarding bundle are created', async t => {
  const limits = normalizeLimits({ maxTickets: 10_000, maxBackendBytes: 1024 * 1024 });
  const f = await fixture(t, limits),
    tickets = almostFullSeed(limits),
    keyring = readFileSync(f.config.keyringFile);
  assert.throws(() => initializeRuntime(f.config, tickets), { code: 'LIMITS_BELOW_USAGE' });
  for (const path of f.authorityPaths) assert.equal(existsSync(path), false);
  assert.deepEqual(readFileSync(f.config.keyringFile), keyring);
  f.manifest.ticketsFile = join(f.root, 'private', 'tickets.json');
  writeFileSync(f.manifest.ticketsFile, JSON.stringify({ tickets }), { mode: 0o600 });
  f.saveManifest();
  const outputDirectory = join(f.root, 'prepared-company');
  assert.throws(() => onboard({ manifestFile: f.manifestFile, outputDirectory }), { code: 'LIMITS_BELOW_USAGE' });
  assert.equal(existsSync(outputDirectory), false);
  assert.equal(
    readdirSync(f.root).some(name => name.startsWith('.agent-ops-setup-')),
    false,
  );
  for (const path of f.authorityPaths) assert.equal(existsSync(path), false);
});

test('onboarding rejects a key/config bundle inside either authority custody directory', async t => {
  const f = await fixture(t);
  for (const directory of ['data', 'witness']) {
    const outputDirectory = join(f.root, directory, 'company-config');
    assert.throws(() => onboard({ manifestFile: f.manifestFile, outputDirectory }), {
      code: 'INDEPENDENT_KEY_DIRECTORY_REQUIRED',
    });
    assert.equal(existsSync(outputDirectory), false);
  }
  assert.deepEqual(readdirSync(join(f.root, 'data')), []);
  assert.deepEqual(readdirSync(join(f.root, 'witness')), []);
});

function nestedDirectory(root, length) {
  let path = root;
  while (Buffer.byteLength(path) < length) {
    const remaining = length - Buffer.byteLength(path) - 1;
    path = join(path, 'p'.repeat(Math.min(80, Math.max(1, remaining))));
    mkdirSync(path, { mode: 0o700 });
  }
  assert.equal(realpathSync(path), path);
  return path;
}

test('paths beyond offline recovery bounds fail before authority or onboarding publication', async t => {
  const f = await fixture(t),
    long = nestedDirectory(f.root, 500);
  const changed = {
    ...f.config,
    ledgerDatabase: join(long, 'authority.sqlite'),
    backendDatabase: join(long, 'tickets.sqlite'),
  };
  assert.throws(() => initializeRuntime(changed, [seed('T-1')]), { code: 'CONFIG_PATH_TOO_LONG' });
  assert.deepEqual(readdirSync(long), []);
  const report = await preflight(changed);
  assert.equal(report.checks.find(check => check.id === 'storage').code, 'CONFIG_PATH_TOO_LONG');
  const configFile = join(f.root, 'private', 'oversized-config.json');
  writeFileSync(configFile, JSON.stringify(changed), { mode: 0o600 });
  assert.throws(() => loadConfig(configFile), { code: 'CONFIG_PATH_TOO_LONG' });
  f.manifest.storage.dataDirectory = long;
  f.saveManifest();
  const outputDirectory = join(f.root, 'prepared-company');
  assert.throws(() => onboard({ manifestFile: f.manifestFile, outputDirectory }), { code: 'CONFIG_PATH_TOO_LONG' });
  assert.equal(existsSync(outputDirectory), false);
  assert.deepEqual(readdirSync(long), []);
  for (const path of f.authorityPaths) assert.equal(existsSync(path), false);
  assert.equal(
    readdirSync(f.root).some(name => name.startsWith('.agent-ops-setup-')),
    false,
  );
});

test('generated key and secret paths and mirror custody are validated before publishing a bundle', async t => {
  const f = await fixture(t),
    long = nestedDirectory(f.root, 500),
    outputDirectory = join(long, 'bundle');
  assert.throws(() => onboard({ manifestFile: f.manifestFile, outputDirectory }), { code: 'CONFIG_PATH_TOO_LONG' });
  assert.deepEqual(readdirSync(long), []);
  const invalidMirror = join(f.root, 'data', 'misplaced-mirror');
  f.manifest.storage.historyMirrorDirectory = invalidMirror;
  f.saveManifest();
  const ordinaryOutput = join(f.root, 'prepared-company');
  assert.throws(() => onboard({ manifestFile: f.manifestFile, outputDirectory: ordinaryOutput }), {
    code: 'HISTORY_MIRROR_CUSTODY_REQUIRED',
  });
  assert.equal(existsSync(ordinaryOutput), false);
  assert.equal(existsSync(invalidMirror), false);
  assert.equal(existsSync(`${f.manifest.storage.dataDirectory}-history`), false);
  for (const path of f.authorityPaths) assert.equal(existsSync(path), false);
  assert.equal(
    readdirSync(f.root).some(name => name.startsWith('.agent-ops-setup-')),
    false,
  );
});

test('preflight checks backend-only permissions and cross-store witness custody', async t => {
  const f = await fixture(t);
  const unsafe = join(f.root, 'shared-backend');
  mkdirSync(unsafe, { mode: 0o755 });
  for (const changed of [
    { backendDatabase: join(unsafe, 'tickets.sqlite') },
    { backendWitness: join(unsafe, 'witness.sqlite') },
  ]) {
    const report = await preflight({ ...f.config, ...changed });
    assert.equal(report.status, 'failed');
    assert.equal(report.checks.find(check => check.id === 'storage').status, 'failed');
    for (const path of Object.values(changed)) assert.equal(existsSync(path), false);
  }
  const backendData = join(f.root, 'backend-data');
  mkdirSync(backendData, { mode: 0o700 });
  const report = await preflight({
    ...f.config,
    backendDatabase: join(backendData, 'tickets.sqlite'),
    backendWitness: join(f.root, 'data', 'backend-witness.sqlite'),
  });
  assert.equal(report.checks.find(check => check.id === 'storage').status, 'failed');
  for (const path of f.authorityPaths) assert.equal(existsSync(path), false);
});

test('preflight performs discovery without creating missing state or mutating enrolled authority', async t => {
  const f = await fixture(t),
    initialKeyring = readFileSync(f.config.keyringFile);
  const fresh = await preflight(f.config);
  assert.equal(fresh.status, 'ready');
  assert.equal(fresh.checks.find(check => check.id === 'state').status, 'pending');
  for (const path of f.authorityPaths) assert.equal(existsSync(path), false);
  assert.deepEqual(readFileSync(f.config.keyringFile), initialKeyring);
  initializeRuntime(f.config, [seed('T-1')]);
  const paths = [...f.authorityPaths, f.config.keyringFile],
    before = paths.map(path => readFileSync(path));
  const enrolled = await preflight(f.config);
  assert.equal(enrolled.status, 'ready');
  assert.equal(enrolled.checks.find(check => check.id === 'state').status, 'passed');
  paths.forEach((path, i) => assert.deepEqual(readFileSync(path), before[i]));
  assert.ok(f.provider.requests.length > 0);
  assert.ok(
    f.provider.requests.every(
      request => request.method === 'GET' && request.path === '/.well-known/openid-configuration',
    ),
  );
});
