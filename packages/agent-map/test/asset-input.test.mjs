import test from 'node:test';
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { MapService, createMapToken, startMapServer, startMapIdentityServer } from '../dist/index.js';
import { createTestIdentityProvider } from './helpers/oidc-provider.mjs';

const supported = typeof constants.O_NONBLOCK === 'number' && typeof constants.O_NOFOLLOW === 'number';
const helper = fileURLToPath(new URL('./helpers/asset-input.mjs', import.meta.url));
const maximum = 4 * 1024 * 1024;
const run = promisify(execFile);
const name = value => supported ? value : `${value}: rejects unsupported asset opens`;
async function unsupported(transport) {
  if (supported) return false;
  const service = new MapService({ read: async () => ({ sources: [] }) });
  const viewerDirectory = join(tmpdir(), 'unused-assets-on-unsupported-host');
  const result = transport === 'http'
    ? startMapServer({ service, viewerDirectory, credentials: [{ token: createMapToken(),
      scope: { subject: 'test', companyId: 'company', tenantIds: ['tenant'], teamIds: [], allTeams: true } }] })
    : startMapIdentityServer({ service, viewerDirectory, publicOrigin: 'https://127.0.0.1:0', port: 0,
      tls: { key: 'unused', cert: 'unused' }, oidc: { issuer: 'https://issuer.invalid', clientId: 'client', clientSecret: 'secret' },
      companyId: 'company', bindings: [] });
  await assert.rejects(result, { code: 'MAP_CONFIG_INVALID' });
  return true;
}
async function probe(t, transport, mode) {
  const dir = await mkdtemp(join(tmpdir(), 'agent-map-asset-input-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const assets = join(dir, 'assets'); await mkdir(assets);
  let tlsFile;
  if (transport === 'https' && ['exact', 'after-open'].includes(mode)) {
    const provider = await createTestIdentityProvider(t);
    tlsFile = join(dir, 'tls.json');
    await writeFile(tlsFile, JSON.stringify({ key: provider.key, cert: provider.cert, ca: provider.ca,
      issuer: provider.issuer, clientId: provider.clientId, clientSecret: provider.clientSecret }), { mode: 0o600 });
  }
  const result = await run(process.execPath, [helper, assets, mode, transport, ...(tlsFile ? [tlsFile] : [])], {
    encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL',
  });
  assert.equal(result.stderr, '');
  return JSON.parse(result.stdout);
}

for (const transport of ['http', 'https']) {
  test(name(`${transport} assets bound a file that grows after metadata inspection`), async t => {
    if (await unsupported(transport)) return;
    const result = await probe(t, transport, 'grow');
    assert.deepEqual(result, { code: 'MAP_CONFIG_INVALID', bytes: maximum + 1, closed: true, mutated: true });
  });
  test(name(`${transport} assets reject a symlink replacing a checked regular file`), async t => {
    if (await unsupported(transport)) return;
    const result = await probe(t, transport, 'symlink');
    assert.deepEqual(result, { code: 'MAP_CONFIG_INVALID', bytes: 0, closed: false, mutated: true });
  });
  test(name(`${transport} assets reject a FIFO replacement without waiting for a writer`), async t => {
    if (await unsupported(transport)) return;
    const result = await probe(t, transport, 'fifo');
    assert.deepEqual(result, { code: 'MAP_CONFIG_INVALID', bytes: 0, closed: true, mutated: true });
  });
  test(name(`${transport} assets serve exact-limit cached content with the existing CSP`), async t => {
    if (await unsupported(transport)) return;
    const result = await probe(t, transport, 'exact');
    assert.equal(result.accepted, true, JSON.stringify(result)); assert.equal(result.status, 200);
    assert.equal(result.bytes, maximum); assert.equal(result.length, maximum); assert.equal(result.closed, true);
    assert.equal(result.digest, createHash('sha256').update(Buffer.alloc(maximum, 'x')).digest('hex'));
    assert.equal(result.servedPrivate, false); assert.match(result.csp, /script-src 'self'/);
  });
  test(name(`${transport} assets keep the opened regular file when its path is replaced`), async t => {
    if (await unsupported(transport)) return;
    const result = await probe(t, transport, 'after-open');
    assert.equal(result.accepted, true, JSON.stringify(result)); assert.equal(result.status, 200);
    assert.equal(result.bytes, Buffer.byteLength('original asset')); assert.equal(result.closed, true); assert.equal(result.mutated, true);
    assert.equal(result.digest, createHash('sha256').update('original asset').digest('hex'));
    assert.equal(result.servedPrivate, false);
  });
}
