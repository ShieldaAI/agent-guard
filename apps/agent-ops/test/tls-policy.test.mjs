import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { createServer } from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { validateCertificate, validateTls } from '../tls-policy.mjs';
import { createTestIdentityProvider } from '../../../packages/agent-map/test/helpers/oidc-provider.mjs';

test('served TLS binds the public hostname, matching private key and exact validity window', async t => {
  const provider = await createTestIdentityProvider(t),
    cert = new X509Certificate(provider.cert);
  const from = Date.parse(cert.validFrom),
    until = Date.parse(cert.validTo),
    tls = { key: provider.key, cert: provider.cert };
  assert.deepEqual(validateTls(tls, 'https://localhost:8443', from), { expiresAt: until });
  assert.equal(validateCertificate(provider.cert, 'https://127.0.0.1', until - 1).expiresAt, until);
  for (const now of [from - 1, until, until + 1, Infinity, NaN])
    assert.throws(() => validateTls(tls, 'https://localhost', now), { code: 'TLS_CERTIFICATE_INVALID' });
  assert.throws(() => validateTls(tls, 'https://foreign-company.invalid'), { code: 'TLS_CERTIFICATE_INVALID' });
  const wrongKey = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
  assert.throws(() => validateTls({ ...tls, key: wrongKey }, 'https://localhost'), { code: 'TLS_CERTIFICATE_INVALID' });
  for (const origin of ['http://localhost', 'https://localhost/path', 'https://user:secret@localhost', 'broken'])
    assert.throws(() => validateTls(tls, origin), { code: 'PUBLIC_ORIGIN_INVALID' });
});

test('the actual local health probe verifies hostname in addition to the pinned certificate', async t => {
  const provider = await createTestIdentityProvider(t),
    directory = mkdtempSync(join(tmpdir(), 'ops-health-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  let probes = 0;
  const server = createServer({ cert: provider.cert, key: provider.key }, (_req, res) => {
    probes++;
    res.writeHead(200);
    res.end('{"status":"ok"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise(resolve => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  const port = server.address().port,
    certFile = join(directory, 'cert.pem'),
    configFile = join(directory, 'config.json');
  writeFileSync(certFile, provider.cert);
  const config = { port, publicOrigin: `https://localhost:${port}`, tls: { certFile } };
  const probe = fileURLToPath(new URL('../../../deployment/production/healthcheck.mjs', import.meta.url));
  writeFileSync(configFile, JSON.stringify(config));
  await promisify(execFile)(process.execPath, [probe, configFile], { timeout: 5000 });
  assert.equal(probes, 1);
  writeFileSync(configFile, JSON.stringify({ ...config, publicOrigin: `https://foreign-company.invalid:${port}` }));
  await assert.rejects(promisify(execFile)(process.execPath, [probe, configFile], { timeout: 5000 }), { code: 1 });
  assert.equal(probes, 1, 'invalid configured hostname must fail before probing readiness');
  const foreign = await createTestIdentityProvider(t);
  writeFileSync(certFile, foreign.cert);
  writeFileSync(configFile, JSON.stringify(config));
  await assert.rejects(promisify(execFile)(process.execPath, [probe, configFile], { timeout: 5000 }), { code: 1 });
  assert.equal(probes, 1, 'a different certificate for the same hostname must fail before the HTTP request');
  server.setSecureContext({ cert: foreign.cert, key: foreign.key });
  writeFileSync(certFile, provider.cert + '\n' + foreign.ca);
  await assert.rejects(promisify(execFile)(process.execPath, [probe, configFile], { timeout: 5000 }), { code: 1 });
  assert.equal(probes, 1, 'even a trusted same-host chain cannot bypass the exact leaf pin before HTTP dispatch');
  server.setSecureContext({ cert: provider.cert, key: provider.key });
  writeFileSync(certFile, provider.cert);
  writeFileSync(configFile, JSON.stringify({ ...config, port: '443/service' }));
  await assert.rejects(promisify(execFile)(process.execPath, [probe, configFile], { timeout: 5000 }), { code: 1 });
  assert.equal(probes, 1, 'the fixed loopback probe accepts only a numeric TCP port');
});
