// Verification image only: disposable TLS over stdin, loopback IdP, private fixtures.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createTestIdentityProvider, testHttps } from '../../packages/agent-map/test/helpers/oidc-provider.mjs';
assert.equal(process.platform, 'linux'); assert.equal(process.geteuid(), 10001);
const security = readFileSync('/proc/self/status', 'utf8');
assert.match(security, /^CapEff:\s+0+$/m); assert.match(security, /^NoNewPrivs:\s+1$/m);
assert.equal(existsSync('/var/run/docker.sock'), false);
assert.throws(() => writeFileSync('/app/unexpected-write', 'fixture'), error => error.code === 'EROFS');
const tls = JSON.parse(readFileSync(0, 'utf8')), hooks = [];
const persistentFixture = process.env.AGENT_OPS_VERIFY_PERSISTENCE === '1';
const root = persistentFixture ? '/fixtures' : realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-cli-')));
const offline = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-offline-')));
let owner;
const launch = args => {
  const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_NO_WARNINGS: '1' } });
  let out = '', err = '';
  child.stdout.on('data', bytes => { out += bytes; }); child.stderr.on('data', bytes => { err += bytes; });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, out, err })); });
  return { child, done, output: () => ({ out, err }) };
};
const command = async (args, expected = 0) => {
  const task = launch(args), timer = setTimeout(() => task.child.kill('SIGKILL'), 15_000);
  try { const result = await task.done; assert.equal(result.code, expected, result.err || result.out); return result; }
  finally { clearTimeout(timer); }
};
try {
  for (const name of ['data', 'witness', 'config', 'input', 'history']) if (!existsSync(join(root, name))) mkdirSync(join(root, name), { mode: 0o700 });
  // Children can be removed and recreated to model complete primary custody
  // loss while the independently mounted witness volume survives.
  for (const name of ['data', 'history']) mkdirSync(join(root, name, 'live'), { mode: 0o700 });
  const provider = await createTestIdentityProvider({ after: fn => hooks.push(fn) }, { tls });
  const port = 8443, origin = `https://127.0.0.1:${port}`, outputDirectory = join(root, 'config', 'company');
  const configPath = join(outputDirectory, 'config.json'), manifestPath = join(root, 'input', 'onboarding.json');
  const manifest = { version: 1, company: { id: 'fixture', name: 'Disposable company' }, publicOrigin: origin,
    tls: { keyFile: join(root, 'input', 'tls.key'), certFile: join(root, 'input', 'tls.pem') },
    oidc: { issuer: provider.issuer, clientId: provider.clientId, clientSecretFile: join(root, 'input', 'oidc-secret'), caFile: join(root, 'input', 'ca.pem') },
    owner: { subject: 'owner', id: 'owner' }, storage: { dataDirectory: join(root, 'data', 'live'), witnessDirectory: join(root, 'witness'), historyDirectory: join(root, 'history', 'live') },
    ticketsFile: join(root, 'input', 'tickets.json') };
  for (const [path, content] of [[manifestPath, JSON.stringify(manifest)], [manifest.tls.keyFile, tls.key], [manifest.tls.certFile, tls.cert],
    [manifest.oidc.caFile, tls.ca], [manifest.oidc.clientSecretFile, provider.clientSecret],
    [manifest.ticketsFile, JSON.stringify({ tickets: [{ id: 'T-1', tenantId: 'fixture', title: 'Disposable ticket', status: 'open' }] })]]) writeFileSync(path, content, { mode: 0o600 });
  const cli = 'apps/agent-ops/cli.mjs', maintenance = 'packages/executor/dist/ledger-maintenance-cli.js';
  const prepared = JSON.parse((await command([cli, 'onboard', '--manifest', manifestPath, '--output-dir', outputDirectory])).out);
  assert.equal(prepared.status, 'prepared');
  const config = JSON.parse(readFileSync(configPath)), seedPath = join(outputDirectory, 'tickets.json');
  for (const path of [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness]) assert.equal(existsSync(path), false);
  await command([cli, 'onboard', '--manifest', manifestPath, '--output-dir', outputDirectory], 1);
  const preflight = JSON.parse((await command([cli, 'preflight', '--config', configPath])).out);
  assert.equal(preflight.status, 'ready'); assert.equal(preflight.checks.find(item => item.id === 'state').status, 'pending');
  const check = () => command([cli, 'check', '--config', configPath]);
  // Preflight is optional convenience; actual entry points enforce the profile.
  const invalidConfig = join(outputDirectory, 'invalid-config.json');
  writeFileSync(invalidConfig, JSON.stringify({ ...config, publicOrigin: 'https://wrong-company.invalid:8443' }), { mode: 0o600 });
  assert.match((await command([cli, 'init', '--config', invalidConfig, '--tickets', seedPath], 1)).err, /TLS_CERTIFICATE_INVALID/);
  writeFileSync(invalidConfig, JSON.stringify({ ...config, ledgerWitness: join(root, 'data', 'live', 'unsafe-witness.sqlite') }));
  assert.match((await command([cli, 'init', '--config', invalidConfig, '--tickets', seedPath], 1)).err, /INDEPENDENT_WITNESS_DIRECTORY_REQUIRED/);
  const foreignSeed = join(outputDirectory, 'foreign-tickets.json');
  writeFileSync(foreignSeed, JSON.stringify({ tickets: [{ id: 'FOREIGN', tenantId: 'elsewhere', title: 'Wrong company', status: 'open' }] }), { mode: 0o600 });
  assert.match((await command([cli, 'init', '--config', configPath, '--tickets', foreignSeed], 1)).err, /IMPORT_TENANT_NOT_ENROLLED/);
  for (const path of [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness]) assert.equal(existsSync(path), false);
  await command([cli, 'init', '--config', configPath, '--tickets', seedPath]);
  await check();
  const authorityBefore = [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness].map(path => readFileSync(path));
  await command([cli, '--config', invalidConfig], 1);
  writeFileSync(invalidConfig, JSON.stringify({ ...config, publicOrigin: 'https://wrong-company.invalid:8443' }));
  await command([cli, '--config', invalidConfig], 1);
  [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness].forEach((path, index) => assert.deepEqual(readFileSync(path), authorityBefore[index]));
  const request = (path, options = {}) => testHttps(new URL(path, origin), { ca: tls.ca, ...options });
  async function start() {
    owner = launch([cli, '--config', configPath]);
    for (let attempt = 0; attempt < 100; attempt++) {
      try { if ((await request('/health/ready')).status === 200) return; } catch { /* Process is starting. */ }
      if (owner.child.exitCode !== null) throw Error(owner.output().err);
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw Error('CLI_START_TIMEOUT');
  }
  async function stop(signal = 'SIGTERM') {
    owner.child.kill(signal); const result = await owner.done; owner = undefined;
    if (signal === 'SIGKILL') assert.equal(result.signal, 'SIGKILL'); else assert.equal(result.code, 0, result.err);
  }
  async function login() {
    const initial = await request('/api/session'), anonymous = initial.headers['set-cookie'][0].split(';')[0];
    const begin = await request('/auth/login', { method: 'POST', headers: { Cookie: anonymous, Origin: origin,
      'X-CSRF-Token': initial.json().csrfToken, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(begin.status, 200, begin.text);
    // Starting sign-in renews the pre-login cookie; the callback is bound to the renewed one.
    const renewed = begin.headers['set-cookie'][0].split(';')[0];
    assert.notEqual(renewed, anonymous);
    const callback = await provider.authorize(begin.json().authorizationUrl, { subject: 'owner' });
    const stale = await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: anonymous } });
    assert.equal(stale.status, 401, 'the callback refuses the cookie that started sign-in');
    const done = await request(`${callback.pathname}${callback.search}`, { headers: { Cookie: renewed } });
    assert.equal(done.status, 303, done.text);
    const cookie = done.headers['set-cookie'][0].split(';')[0];
    const session = (await request('/api/session', { headers: { Cookie: cookie } })).json();
    return { cookie, get: path => request(path, { headers: { Cookie: cookie } }),
      post: (path, body) => request(path, { method: 'POST', headers: { Cookie: cookie, Origin: origin,
        'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' }, body: JSON.stringify(body) }) };
  }
  async function propose(actor, status) {
    const result = await actor.post('/api/requests', { ticketId: 'T-1', status });
    assert.equal(result.status, 201, result.text); return result.json().request;
  }
  async function approve(actor, pending) {
    const result = await actor.post(`/api/requests/${pending.id}/approve`, { digest: pending.digest });
    assert.equal(result.status, 200, result.text); assert.equal(result.json().request.state, 'completed'); return result.json().request;
  }
  await start();
  await command(['deployment/production/healthcheck.mjs', configPath]);
  const first = await login(), completed = await approve(first, await propose(first, 'resolved'));
  assert.equal((await first.get('/api/tickets')).json().tickets[0].version, 2);
  const waiting = await propose(first, 'open');
  await command([cli, '--config', configPath], 1); // Sole-owner lock also blocks a second startup.
  await stop('SIGKILL');
  await start();
  assert.equal((await first.get('/api/tickets')).status, 401);
  const second = await login(), requests = (await second.get('/api/requests')).json().requests;
  assert.equal(requests.find(item => item.id === waiting.id).state, 'review_required');
  assert.equal((await second.post(`/api/requests/${waiting.id}/approve`, { digest: waiting.digest })).status, 409);
  assert.equal((await second.get('/api/tickets')).json().tickets[0].version, 2);
  await stop();
  const dataPaths = [config.ledgerDatabase, config.backendDatabase], witnesses = [config.ledgerWitness, config.backendWitness];
  const coldData = dataPaths.map(path => readFileSync(path)), currentWitness = witnesses.map(path => readFileSync(path));
  dataPaths.forEach((path, i) => { rmSync(path); writeFileSync(path, coldData[i], { mode: 0o600 }); });
  await check(); witnesses.forEach((path, i) => assert.deepEqual(readFileSync(path), currentWitness[i]));
  config.limits = { ...config.limits, maxTickets: 2500, maxRequests: 5000, maxRetainedKeys: 8,
    maxBackendBytes: 20 * 1024 * 1024, maxLedgerBytes: 20 * 1024 * 1024 };
  writeFileSync(configPath, JSON.stringify(config));
  await command([cli, 'check', '--config', configPath], 1); // A config edit does not silently change retained authority.
  const limitPreview = JSON.parse((await command([cli, 'configure-limits', '--config', configPath])).out);
  assert.equal(limitPreview.status, 'preview'); assert.equal(limitPreview.requested.maxRetainedKeys, 8);
  const limitApply = JSON.parse((await command([cli, 'configure-limits', '--config', configPath, '--apply', '--digest', limitPreview.digest])).out);
  assert.equal(limitApply.status, 'configured'); await check();
  const importPath = join(root, 'input', 'additional-tickets.json');
  writeFileSync(importPath, JSON.stringify({ tickets: Array.from({ length: 2000 }, (_, index) => ({ id: `T-${index + 2}`, tenantId: 'fixture', title: `Additional company ticket ${index + 2}`, status: 'open' })) }), { mode: 0o600 });
  const importPreview = JSON.parse((await command([cli, 'import-tickets', '--config', configPath, '--tickets', importPath])).out);
  assert.equal(importPreview.status, 'preview'); assert.equal(importPreview.added, 2000); assert.equal(importPreview.existing, 1);
  const imported = JSON.parse((await command([cli, 'import-tickets', '--config', configPath, '--tickets', importPath, '--apply', '--digest', importPreview.digest])).out);
  assert.equal(imported.status, 'imported'); assert.equal(imported.total, 2001);
  await command([cli, 'import-tickets', '--config', configPath, '--tickets', importPath, '--apply', '--digest', importPreview.digest], 1);
  const rotate = (database, witness, keyId) => command([maintenance, 'rotate', '--keyring', config.keyringFile,
    '--database', database, '--witness', witness, '--next-key-id', keyId, '--max-bytes', String(config.limits.maxLedgerBytes)]);
  for (let iteration = 1; iteration <= 4; iteration++) {
    const keyId = `rotated-${iteration}`;
    await rotate(config.ledgerDatabase, config.ledgerWitness, keyId);
    if (iteration === 1) { const partial = JSON.parse((await check()).out); assert.equal(partial.guardKeyId, keyId); assert.equal(partial.backendKeyId, 'initial'); }
    await rotate(config.backendDatabase, config.backendWitness, keyId);
  }
  const both = JSON.parse((await check()).out); assert.equal(both.guardKeyId, 'rotated-4'); assert.equal(both.backendKeyId, 'rotated-4');
  const keyPolicy = JSON.parse((await command([maintenance, 'status', '--keyring', config.keyringFile])).out);
  assert.equal(keyPolicy.keyCount, 5); assert.equal(keyPolicy.maxKeys, 8);
  await start();
  const third = await login();
  const visible = new Set();
  for (let offset = 0; offset !== null;) {
    const page = (await third.get(`/api/tickets?offset=${offset}&limit=500`)).json();
    assert.equal(page.total, 2001); assert.ok(page.tickets.length <= 500);
    page.tickets.forEach(ticket => { assert.equal(visible.has(ticket.id), false); visible.add(ticket.id); });
    offset = page.nextOffset;
  }
  assert.equal(visible.size, 2001); assert.ok(visible.has('T-2001'));
  const setup = (await third.get('/api/setup')).json();
  assert.equal(setup.company.id, 'fixture'); assert.equal(setup.data.tickets, 2001);
  assert.equal(setup.limits.maxTickets, 2500); assert.equal(setup.limits.maxRequests, 5000);
  assert.equal(setup.limits.maxRetainedKeys, 8); assert.equal(setup.keyring.keyCount, 5); assert.equal(setup.keyring.maxKeys, 8);
  assert.ok(setup.commands.every(item => item.command.includes('${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}')));
  await approve(third, await propose(third, 'open'));
  assert.equal((await third.get('/api/tickets')).json().tickets[0].version, 3);
  const previewResult = await third.post('/api/maintenance/archive/preview', { taskId: `ticket:${completed.id}` });
  assert.equal(previewResult.status, 200, previewResult.text); const preview = previewResult.json().preview;
  const archived = await third.post('/api/maintenance/archive/apply', { id: preview.id, digest: preview.digest });
  assert.equal(archived.status, 200, archived.text); assert.equal(archived.json().archivedCount, 1);
  await stop();
  const historyArgs = [cli, 'compact-history', '--config', configPath, '--tenant', 'fixture', '--limit', '100'];
  const historyPreview = JSON.parse((await command(historyArgs)).out);
  // Compaction stops before the active review in sequence order; it must not
  // advance the permanent retirement fence across that still-live task.
  assert.equal(historyPreview.status, 'preview'); assert.equal(historyPreview.count, 1); assert.deepEqual(historyPreview.blockers, []);
  const historyCommit = JSON.parse((await command([...historyArgs, '--apply', '--digest', historyPreview.digest])).out);
  assert.equal(historyCommit.status, 'compacted');
  await command([...historyArgs, '--apply', '--digest', historyPreview.digest], 1);
  const historyCheck = JSON.parse((await command([cli, 'verify-history', '--config', configPath])).out);
  assert.equal(historyCheck.status, 'verified'); assert.equal(historyCheck.segments, 1);
  const lookup = () => command([cli, 'lookup-history', '--config', configPath, '--tenant', 'fixture', '--request', completed.id]);
  const historical = JSON.parse((await lookup()).out);
  assert.equal(historical.found, true); assert.equal(historical.receipt.requestId, completed.id); assert.equal(historical.receipt.version, 2);

  for (const name of ['data', 'witness', 'keys', 'backups']) mkdirSync(join(offline, name), { mode: 0o700 });
  const custodyConfig = { version: 1, custodyDatabase: join(offline, 'data', 'custody.sqlite'),
    custodyWitness: join(offline, 'witness', 'custody.sqlite'), custodyKeyringFile: join(offline, 'keys', 'keyring.json'), backupDirectory: join(offline, 'backups') };
  const custodyPath = join(offline, 'keys', 'custody.json'); writeFileSync(custodyPath, JSON.stringify(custodyConfig), { mode: 0o600 });
  await command([maintenance, 'keygen', '--keyring', custodyConfig.custodyKeyringFile, '--key-id', 'custody-initial']);
  const custodyArgs = (operation, more = []) => [cli, 'custody', '--config', configPath, '--custody-config', custodyPath, '--operation', operation, ...more];
  async function applyCustody(operation, more = []) {
    const args = custodyArgs(operation, more), preview = JSON.parse((await command(args)).out);
    assert.equal(preview.applied, false);
    const applied = JSON.parse((await command([...args, '--apply', '--digest', preview.digest])).out);
    assert.equal(applied.applied, true); return applied;
  }
  await applyCustody('enroll');
  const firstBackup = await applyCustody('backup'); assert.ok(firstBackup.backupId);
  const managedRotation = await applyCustody('rotate', ['--key-id', 'managed-current']);
  assert.equal(managedRotation.keyId, 'managed-current'); assert.equal(managedRotation.keyCount, 6);
  const retiredKey = await applyCustody('retire', ['--key-id', 'rotated-4']);
  assert.equal(retiredKey.keyId, 'rotated-4'); assert.equal(retiredKey.keyCount, 5);
  const verifiedOld = JSON.parse((await command(custodyArgs('verify', ['--backup-id', firstBackup.backupId]))).out);
  assert.equal(verifiedOld.backupId, firstBackup.backupId);
  await command(custodyArgs('restore', ['--backup-id', firstBackup.backupId]), 1);
  await command([maintenance, 'rotate', '--keyring', config.keyringFile, '--database', config.ledgerDatabase,
    '--witness', config.ledgerWitness, '--next-key-id', 'bypass-managed-custody'], 1);
  await command([maintenance, 'rotate', '--keyring', custodyConfig.custodyKeyringFile, '--database', custodyConfig.custodyDatabase,
    '--witness', custodyConfig.custodyWitness, '--next-key-id', 'custody-current']);
  await command(custodyArgs('verify', ['--backup-id', firstBackup.backupId]));
  const currentBackup = await applyCustody('backup');
  const witnessesBeforeRecovery = witnesses.map(path => readFileSync(path));
  writeFileSync(config.backendDatabase, 'synthetic damaged database');
  const historyFile = readdirSync(config.historyDirectory).find(name => name.endsWith('.agh')); assert.ok(historyFile);
  rmSync(join(config.historyDirectory, historyFile));
  await command([cli, 'check', '--config', configPath], 1);
  await applyCustody('restore', ['--backup-id', currentBackup.backupId]);
  witnesses.forEach((path, index) => assert.deepEqual(readFileSync(path), witnessesBeforeRecovery[index]));
  await check(); assert.deepEqual(JSON.parse((await lookup()).out).receipt, historical.receipt);
  const latest = dataPaths.map(path => readFileSync(path));
  try { dataPaths.forEach((path, i) => writeFileSync(path, coldData[i])); await command([cli, 'check', '--config', configPath], 1); }
  finally { dataPaths.forEach((path, i) => writeFileSync(path, latest[i])); }
  await check();
  // A cold snapshot becomes stale with normal work. Recover later acknowledged
  // state from the current witness mirror after losing both primary domains.
  await start();
  const newestActor = await login(), newest = await approve(newestActor, await propose(newestActor, 'resolved'));
  assert.equal((await newestActor.get('/api/tickets')).json().tickets[0].version, 4);
  await stop();
  assert.match((await command(custodyArgs('restore', ['--backup-id', currentBackup.backupId]), 1)).err, /CUSTODY_RESTORE_STALE/);
  const witnessesBeforeCurrentRepair = witnesses.map(path => readFileSync(path));
  for (const directory of [manifest.storage.dataDirectory, config.historyDirectory]) {
    rmSync(directory, { recursive: true }); mkdirSync(directory, { mode: 0o700 });
  }
  await command([cli, 'check', '--config', configPath], 1);
  const recoveryArgs = [cli, 'recovery', '--config', configPath, '--operation', 'repair'];
  const repairPreview = JSON.parse((await command(recoveryArgs)).out);
  assert.equal(repairPreview.applied, false); assert.equal(repairPreview.stores, 2); assert.equal(repairPreview.historyFiles, 1);
  const repaired = JSON.parse((await command([...recoveryArgs, '--apply', '--digest', repairPreview.digest])).out);
  assert.equal(repaired.applied, true); assert.equal(repaired.historyReenrollmentRequired, true);
  witnesses.forEach((path, index) => assert.deepEqual(readFileSync(path), witnessesBeforeCurrentRepair[index]));
  const enrollHistoryArgs = [cli, 'enroll-history', '--config', configPath];
  const enrollHistory = JSON.parse((await command(enrollHistoryArgs)).out);
  await command([...enrollHistoryArgs, '--apply', '--digest', enrollHistory.digest]);
  await check(); assert.deepEqual(JSON.parse((await lookup()).out).receipt, historical.receipt);
  // Exercise ordinary concurrent reads at the deployed resource limits, then
  // overload admission without creating or resubmitting a protected effect.
  await start();
  const loadActor = await login(), beforeLoad = (await loadActor.get('/api/requests')).json();
  assert.equal((await loadActor.get('/api/tickets')).json().tickets[0].version, 4);
  assert.equal(beforeLoad.requests.find(item => item.id === newest.id).state, 'completed');
  assert.deepEqual(beforeLoad.requests.find(item => item.id === newest.id).receipt, newest.receipt);
  assert.equal(beforeLoad.requests.find(item => item.id === waiting.id).state, 'review_required', 'active review survives compaction and current repair');
  const latencyMs = [];
  for (let batch = 0; batch < 5; batch++) await Promise.all(Array.from({ length: 8 }, async () => {
    const started = performance.now(), response = await loadActor.get('/api/tickets?limit=500');
    assert.equal(response.status, 200, response.text); assert.equal(response.json().total, 2001);
    latencyMs.push(performance.now() - started);
  }));
  latencyMs.sort((a, b) => a - b);
  const p95ReadMs = latencyMs[Math.ceil(latencyMs.length * .95) - 1];
  assert.ok(p95ReadMs <= 2000, `500-row page p95 exceeded the two-second target: ${p95ReadMs}ms`);
  let rejected = 0;
  for (let batch = 0; batch < 20; batch++) await Promise.all(Array.from({ length: 8 }, async () => {
    const response = await loadActor.get('/api/tickets?limit=1');
    assert.ok([200, 429, 503].includes(response.status));
    if (response.status !== 200) { assert.ok(['RATE_LIMITED', 'BUSY'].includes(response.json().error.code)); rejected++; }
  }));
  assert.ok(rejected > 0, 'excess workload must be bounded by admission');
  assert.equal((await request('/health/ready')).status, 429, 'readiness cannot bypass expensive-request admission');
  assert.equal((await request('/health/live')).status, 200, 'minimal liveness remains available');
  await stop(); await start();
  const afterLoad = await login();
  assert.deepEqual((await afterLoad.get('/api/requests')).json(), beforeLoad);
  await stop(); await check();
  process.stdout.write(JSON.stringify({ status: 'passed', platform: process.platform, arch: process.arch, node: process.versions.node,
    companyOnboarding: true, noAuthorityBeforeInit: true, preflight: true, startupTlsAndCustodyEnforced: true,
    unenrolledSeedRefused: true, rejectedStartupLeavesAuthorityUnchanged: true, configuredLimitsRaised: true,
    rotationBeyondLegacyFourKeyDefault: true, ticketImportPreviewAndApply: true,
    bulkImportedTickets: 2000, paginatedTicketsVerified: 2001, setupCountsAndLimits: true, signedOidc: true, reviewedUpdate: true, processKillRestart: true, sessionsInvalidated: true,
    pendingReviewInvalidated: true, secondOwnerRejected: true, coldRestoreWithoutWitnessRollback: true,
    partialRotationRecoverable: true, bothStoresRotated: true, subsequentUpdate: true,
    archiveViaHttps: true, staleRestoreRejected: true, healthcheck: true, hardenedContainer: true,
    historyCompacted: true, historicalReceiptVerified: true, managedCustodyEnrolled: true,
    activeKeyRetirementWithHistoricalEscrow: true, custodySecretRotated: true,
    managedBypassRefused: true, authenticatedBackupAndRestore: true, missingHistoryRecovered: true,
    latestStateRecoveredAfterPrimaryDirectoryLoss: true, repairLeavesWitnessesUnchanged: true,
    relocatedHistoryReenrolled: true, historicalAndLatestReceiptsPreserved: true,
    persistentVolumes: persistentFixture,
    load: { tickets: 2001, concurrentClients: 8, measuredReads: latencyMs.length, pageSize: 500,
      p95ReadMs: Math.round(p95ReadMs), targetP95Ms: 2000, overloadRefusals: rejected, effectsUnchanged: true } }) + '\n');
} finally {
  if (owner) { owner.child.kill('SIGKILL'); await owner.done; }
  for (const hook of hooks.reverse()) await hook();
  rmSync(offline, { recursive: true, force: true });
  if (!persistentFixture) rmSync(root, { recursive: true, force: true });
}
