import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, writeFileSync, readFileSync, lstatSync, existsSync, rmSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { onboard, preflight, configureLimits, importTickets, readTicketFile } from '../onboarding.mjs';
import { parseEvidenceJson } from '../../../packages/executor/dist/evidence-json.js';
import { loadConfig, initializeRuntime, openRuntime, openMaintenance } from '../runtime.mjs';
import { normalizeLimits } from '../limits.mjs';
import { createTestIdentityProvider } from '../../../packages/agent-map/test/helpers/oidc-provider.mjs';
import { readLedgerKeyringPolicy, rotateLedgerKeyring, configureLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';
import { setup, owner } from './helpers.mjs';
const test = (name, fn) => nodeTest(name, { skip: process.platform === 'win32' ? 'Self-hosted witness custody requires POSIX.' : false }, fn);
const write = (path, value) => writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
async function onboardingFixture(t, tickets = []) {
  const provider = await createTestIdentityProvider(t), root = realpathSync(mkdtempSync(join(tmpdir(), 'ops-onboarding-')));
  for (const name of ['input', 'data', 'witness', 'config']) mkdirSync(join(root, name), { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const [file, content] of [['tls.key', provider.key], ['tls.pem', provider.cert], ['ca.pem', provider.ca], ['secret', provider.clientSecret], ['tickets.json', { tickets }]]) write(join(root, 'input', file), content);
  const manifest = { version: 1, company: { id: 'acme', name: 'Acme company' }, publicOrigin: 'https://localhost:8443',
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecretFile: join(root, 'input/secret'), caFile: join(root, 'input/ca.pem') },
    tls: { keyFile: join(root, 'input/tls.key'), certFile: join(root, 'input/tls.pem') }, owner: { id: 'owner', subject: 'owner' },
    storage: { dataDirectory: join(root, 'data'), witnessDirectory: join(root, 'witness') }, ticketsFile: join(root, 'input/tickets.json'),
    limits: { maxRetainedKeys: 8, maxRequests: 8000, maxTickets: 1000 } };
  const manifestFile = join(root, 'input/manifest.json'), outputDirectory = join(root, 'config/company'); write(manifestFile, manifest);
  return { root, provider, manifest, manifestFile, outputDirectory };
}
test('company onboarding prepares a private independent bundle, verifies OIDC discovery and initializes an empty company store', async t => {
  const fixture = await onboardingFixture(t), result = onboard(fixture);
  assert.equal(result.status, 'prepared'); assert.equal(result.tickets, 0);
  assert.equal(JSON.stringify(result).includes(fixture.provider.clientSecret), false);
  assert.equal(existsSync(join(fixture.root, 'data/authority.sqlite')), false);
  for (const name of ['config.json', 'tickets.json', 'tls.key', 'tls.pem', 'oidc-client-secret', 'keyring.json']) assert.equal(lstatSync(join(fixture.outputDirectory, name)).mode & 0o777, 0o600);
  assert.equal(lstatSync(fixture.outputDirectory).mode & 0o777, 0o700);
  const config = loadConfig(result.configFile);
  assert.equal(config.bindings[0].tenantId, 'acme'); assert.equal(config.limits.maxRequests, 8000);
  assert.equal(readLedgerKeyringPolicy({ keyringFile: config.keyringFile }).maxKeys, 8);
  const before = await preflight(config); assert.equal(before.status, 'ready', JSON.stringify(before));
  assert.equal(before.checks.find(c => c.id === 'state').status, 'pending');
  initializeRuntime(config, []);
  const after = await preflight(config); assert.equal(after.status, 'ready'); assert.equal(after.checks.find(c => c.id === 'state').status, 'passed');
  const runtime = openRuntime(config);
  try { assert.equal(runtime.workflow.tickets('acme').total, 0); } finally { runtime.close(); }
  assert.throws(() => onboard(fixture), { code: 'ONBOARDING_OUTPUT_EXISTS_OR_UNSAFE' });
});
test('onboarding rejects foreign data and mismatched TLS before publishing keys or configuration', async t => {
  const fixture = await onboardingFixture(t, [{ id: 'T-1', title: 'Other company', tenantId: 'elsewhere', status: 'open' }]);
  assert.throws(() => onboard(fixture), { code: 'IMPORT_TENANT_NOT_ENROLLED' }); assert.equal(existsSync(fixture.outputDirectory), false);
  write(join(fixture.root, 'input/tickets.json'), { tickets: [] });
  fixture.manifest.publicOrigin = 'https://wrong-company.invalid'; write(fixture.manifestFile, fixture.manifest);
  assert.throws(() => onboard(fixture), { code: 'TLS_CERTIFICATE_INVALID' }); assert.equal(existsSync(fixture.outputDirectory), false);
});
test('preflight rejects unsupported identity provider metadata and unsafe private inputs without creating authority', async t => {
  const fixture = await onboardingFixture(t), prepared = onboard(fixture), config = loadConfig(prepared.configFile);
  fixture.provider.controls.metadata = { code_challenge_methods_supported: ['plain'] };
  const result = await preflight(config); assert.equal(result.status, 'failed'); assert.equal(result.checks.find(c => c.id === 'oidc').status, 'failed');
  assert.equal(existsSync(config.ledgerDatabase), false); assert.equal(existsSync(config.backendDatabase), false);
  chmodSync(prepared.configFile, 0o644); assert.throws(() => loadConfig(prepared.configFile), { code: 'PRIVATE_FILE_REQUIRED' });
});
test('offline capacity preview is exact, preserves records and enables more than four retained rotation keys', async t => {
  const fixture = setup(t), completed = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  await fixture.workflow.decide(owner, completed.id, { digest: completed.digest }, true); fixture.close();
  const config = { ...fixture.config, bindings: [owner], limits: normalizeLimits({ maxRequests: 8000, maxRetainedKeys: 8 }) };
  assert.throws(() => openRuntime(config), { code: 'LIMITS_CHANGE_REQUIRES_OFFLINE' });
  const before = readFileSync(config.backendDatabase), preview = configureLimits(config);
  assert.equal(preview.status, 'preview'); assert.deepEqual(readFileSync(config.backendDatabase), before);
  assert.throws(() => configureLimits(config, { apply: true, digest: '0'.repeat(64) }), { code: 'MAINTENANCE_PREVIEW_STALE' });
  assert.equal(configureLimits(config, { apply: true, digest: preview.digest }).status, 'configured');
  for (let i = 1; i <= 5; i++) {
    for (const [database, witnessPath] of [[config.ledgerDatabase, config.ledgerWitness], [config.backendDatabase, config.backendWitness]]) rotateLedgerKeyring({ database, witnessPath, keyringFile: config.keyringFile, nextKeyId: `rotation-${i}` });
  }
  assert.deepEqual(readLedgerKeyringPolicy({ keyringFile: config.keyringFile }), { keyCount: 6, maxKeys: 8 });
  const runtime = openRuntime(config);
  try {
    assert.equal(runtime.workflow.requests('acme').requests[0].receipt.version, 2);
    assert.equal(runtime.workflow.tickets('acme').tickets[0].version, 2);
  } finally { runtime.close(); }
  const lower = { ...config, limits: normalizeLimits({ ...config.limits, maxRetainedKeys: 5 }) };
  assert.throws(() => configureLimits(lower), { code: 'LIMITS_BELOW_USAGE' });
  assert.equal(readLedgerKeyringPolicy({ keyringFile: config.keyringFile }).keyCount, 6);
});
test('interrupted policy change fails closed and can finish without deleting keys or authority', t => {
  const fixture = setup(t); fixture.close();
  const config = { ...fixture.config, limits: normalizeLimits({ maxRequests: 8000, maxRetainedKeys: 8 }) };
  configureLedgerKeyring({ keyringFile: config.keyringFile, maxKeys: 8 }); // First durable commit, before backend policy commit.
  assert.throws(() => openRuntime(config), { code: 'LIMITS_CHANGE_REQUIRES_OFFLINE' });
  const preview = configureLimits(config); configureLimits(config, { apply: true, digest: preview.digest });
  const runtime = openRuntime(config); runtime.close();
  assert.deepEqual(readLedgerKeyringPolicy({ keyringFile: config.keyringFile }), { keyCount: 1, maxKeys: 8 });
});
test('company import is reviewed, add-only, tenant-enrolled and stale-input bound', async t => {
  const fixture = setup(t), request = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true); fixture.close();
  const config = { ...fixture.config, bindings: [owner] }, ticketsFile = join(fixture.directory, 'config/import.json');
  write(ticketsFile, { tickets: [{ id: 'T-3', tenantId: 'acme', title: 'Company-owned data', status: 'open' }] });
  const preview = importTickets(config, { ticketsFile }); assert.equal(preview.added, 1);
  write(ticketsFile, { tickets: [{ id: 'T-3', tenantId: 'acme', title: 'Changed after preview', status: 'open' }] });
  assert.throws(() => importTickets(config, { ticketsFile, apply: true, digest: preview.digest }), { code: 'MAINTENANCE_PREVIEW_STALE' });
  const fresh = importTickets(config, { ticketsFile });
  assert.equal(importTickets(config, { ticketsFile, apply: true, digest: fresh.digest }).total, 3);
  assert.throws(() => importTickets(config, { ticketsFile }), { code: 'IMPORT_TICKET_EXISTS' });
  write(ticketsFile, { tickets: [{ id: 'T-4', tenantId: 'elsewhere', title: 'Not enrolled', status: 'open' }] });
  assert.throws(() => importTickets(config, { ticketsFile }), { code: 'IMPORT_TENANT_NOT_ENROLLED' });
  const runtime = openRuntime(config);
  try { assert.equal(runtime.workflow.tickets('acme').total, 2); assert.equal(runtime.workflow.requests('acme').requests[0].receipt.version, 2); } finally { runtime.close(); }
});
test('maintenance refuses a live owner and lowering record limits does not evict another tenant', t => {
  const fixture = setup(t), config = { ...fixture.config, limits: normalizeLimits({ maxTickets: 1 }) };
  assert.throws(() => configureLimits(config)); fixture.close();
  const before = readFileSync(config.backendDatabase);
  assert.throws(() => configureLimits(config), { code: 'LIMITS_BELOW_USAGE' }); assert.deepEqual(readFileSync(config.backendDatabase), before);
  const stores = openMaintenance(fixture.config); try { assert.equal(Object.keys(stores.backend.read().ticketService.tickets).length, 2); } finally { stores.close(); }
});
test('bounded bulk import accepts the configured 10000-ticket ceiling without weakening ordinary evidence parsing', t => {
  const fixture = setup(t, { tickets: [], limits: { maxTickets: 10000 } }); fixture.close();
  const config = { ...fixture.config, bindings: [owner] }, ticketsFile = join(fixture.directory, 'config/bulk.json');
  const tickets = Array.from({ length: 10000 }, (_, i) => ({ id: `BULK-${i}`, tenantId: 'acme', title: `Company ticket ${i}`, status: 'open' }));
  write(ticketsFile, { tickets });
  assert.throws(() => parseEvidenceJson(readFileSync(ticketsFile), 8 * 1024 * 1024));
  assert.equal(readTicketFile(ticketsFile).tickets.length, 10000);
  const preview = importTickets(config, { ticketsFile });
  assert.equal(importTickets(config, { ticketsFile, apply: true, digest: preview.digest }).added, 10000);
  const runtime = openRuntime(config);
  try { const page = runtime.workflow.tickets('acme', { offset: 9500 }); assert.equal(page.total, 10000); assert.equal(page.tickets.length, 500); } finally { runtime.close(); }
  write(ticketsFile, '{"tickets":[],"tickets":[]}'); assert.throws(() => readTicketFile(ticketsFile));
  for (const invalid of [0, 100001, 1.5, Infinity]) assert.throws(() => parseEvidenceJson(Buffer.from('{}'), 100, invalid));
});
