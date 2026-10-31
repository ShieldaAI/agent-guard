import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadMapIdentityConfig } from '../dist/identity-cli.js';

async function setup(t) {
  const directory = await mkdtemp(join(tmpdir(), 'agent-map-identity-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem'), file = join(directory, 'config.json');
  await writeFile(key, 'private-key-canary', { mode: 0o600 });
  await writeFile(cert, 'public-certificate', { mode: 0o644 });
  const names = ['AGM_TEST_IDENTITY_SECRET', 'AGM_TEST_GRAPH_SECRET'];
  const previous = names.map(name => process.env[name]);
  names.forEach(name => { process.env[name] = 'credential-canary-' + name; });
  t.after(() => names.forEach((name, index) => { if (previous[index] === undefined) delete process.env[name]; else process.env[name] = previous[index]; }));
  const config = { neo4j: { uri: 'bolt://127.0.0.1:7687', username: 'reader', passwordEnv: names[1] },
    publicOrigin: 'https://map.example.test', tls: { keyFile: 'key.pem', certFile: 'cert.pem' },
    oidc: { issuer: 'https://identity.example.test', clientId: 'map-client', clientSecretEnv: names[0], clientAuthMethod: 'client_secret_post' },
    companyId: 'company', bindings: [{ subject: 'provider-subject', scope: { subject: 'internal-reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['blue'], allTeams: false } }],
    viewerDirectory: '../../viewer' };
  const save = () => writeFile(file, JSON.stringify(config), { mode: 0o600 });
  await save(); return { directory, key, cert, file, config, save };
}

test('identity launcher resolves protected files and environment secrets without embedding them in configuration', async t => {
  const s = await setup(t);
  if (typeof process.getuid !== 'function') { await assert.rejects(loadMapIdentityConfig(s.file)); return; }
  const loaded = await loadMapIdentityConfig(s.file);
  assert.equal(loaded.server.tls.key, 'private-key-canary');
  assert.equal(loaded.server.oidc.clientSecret, process.env.AGM_TEST_IDENTITY_SECRET);
  assert.equal(loaded.server.oidc.clientAuthMethod, 'client_secret_post');
  assert.equal(loaded.database.password, process.env.AGM_TEST_GRAPH_SECRET);
  assert.equal(loaded.server.viewerDirectory, resolve(s.directory, '../../viewer'));
  assert.equal(JSON.stringify(s.config).includes('credential-canary'), false);
});
test('identity launcher refuses public private files, links and oversized private key inputs', async t => {
  const s = await setup(t);
  if (typeof process.getuid !== 'function') { await assert.rejects(loadMapIdentityConfig(s.file)); return; }
  await chmod(s.file, 0o644); await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_CONFIG_INVALID' });
  await chmod(s.file, 0o600); await chmod(s.key, 0o640); await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_CONFIG_INVALID' });
  await chmod(s.key, 0o600);
  const alias = join(s.directory, 'alias.pem'); await symlink(s.key, alias); s.config.tls.keyFile = alias; await s.save();
  await assert.rejects(loadMapIdentityConfig(s.file));
  await rm(alias); await link(s.key, alias); s.config.tls.keyFile = s.key; await s.save();
  await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_CONFIG_INVALID' });
  await rm(alias); await writeFile(s.key, 'x'.repeat(256 * 1024 + 1));
  await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_CONFIG_INVALID' });
});
test('identity launcher rejects missing secrets, duplicate JSON and unrecognized settings', async t => {
  const s = await setup(t);
  if (typeof process.getuid !== 'function') { await assert.rejects(loadMapIdentityConfig(s.file)); return; }
  delete process.env.AGM_TEST_IDENTITY_SECRET;
  await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_CREDENTIAL_REQUIRED' });
  process.env.AGM_TEST_IDENTITY_SECRET = 'credential-canary';
  s.config.oidc.clientSecret = 'inline-secret-canary'; await s.save();
  await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_CONFIG_INVALID' });
  await writeFile(s.file, '{"neo4j":{},"neo4j":{}}');
  await assert.rejects(loadMapIdentityConfig(s.file), { code: 'MAP_REQUEST_INVALID' });
});
test('identity launcher rejects FIFO inputs without waiting for a writer', async t => {
  const s = await setup(t);
  if (typeof process.getuid !== 'function') { await assert.rejects(loadMapIdentityConfig(s.file)); return; }
  const fifo = join(s.directory, 'input.fifo');
  assert.equal(spawnSync('mkfifo', [fifo], { encoding: 'utf8' }).status, 0);
  const script = fileURLToPath(new URL('../dist/identity-cli.js', import.meta.url));
  // A subprocess deadline makes regression failure bounded even if open() blocks.
  for (const config of [fifo, s.file]) {
    if (config === s.file) { s.config.tls.keyFile = fifo; await s.save(); }
    const result = spawnSync(process.execPath, [script, '--config', config], { encoding: 'utf8', timeout: 3000 });
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, 'MAP_START_FAILED\n');
  }
});
test('identity CLI help and failures never print provider, key or database material', async t => {
  const s = await setup(t), script = fileURLToPath(new URL('../dist/identity-cli.js', import.meta.url));
  const help = spawnSync(process.execPath, [script, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0); assert.match(help.stdout, /PRIVATE_HOST_CONFIG/);
  // Deliberately malformed TLS input fails before any listener or provider connection.
  const result = spawnSync(process.execPath, [script, '--config', s.file], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, 'MAP_START_FAILED\n');
  assert.equal(result.stdout.includes('canary'), false); assert.equal(result.stderr.includes('canary'), false);
});
