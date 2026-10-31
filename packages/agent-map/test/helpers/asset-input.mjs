// Isolated startup races: never modifies process-wide fs exports in the test runner.
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { spawnSync } from 'node:child_process';
import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const [directory, mode, transport, tlsFile] = process.argv.slice(2);
const tls = tlsFile ? JSON.parse(await fs.readFile(tlsFile, 'utf8')) : { key: 'unused', cert: 'unused' };
const path = join(directory, 'index.html'), privatePath = join(directory, 'private.txt');
const maximum = 4 * 1024 * 1024;
const initial = mode === 'exact' ? Buffer.alloc(maximum, 'x') : Buffer.from('original asset');
await fs.writeFile(privatePath, 'asset-boundary-private-canary');
for (const name of ['index.html', 'app.js', 'app.css']) await fs.writeFile(join(directory, name), name === 'index.html' ? initial : 'small asset');
const original = { lstat: fs.lstat, readFile: fs.readFile, open: fs.open };
let mutated = false, bytes = 0, closed = false;
async function mutate() {
  if (mutated) return;
  mutated = true;
  if (mode === 'grow') await fs.appendFile(path, Buffer.alloc(8 * 1024 * 1024, 'x'));
  else {
    await fs.rename(path, path + '.original');
    if (mode === 'fifo') {
      const made = spawnSync('mkfifo', [path], { encoding: 'utf8' });
      if (made.status !== 0) throw new Error('TEST_FIFO_FAILED');
    } else await fs.symlink(privatePath, path);
  }
}
// Old code races between lstat and readFile. The descriptor implementation races
// immediately before open, or after its size check for the growth case.
fs.lstat = async (...args) => {
  const info = await original.lstat(...args);
  if (args[0] === path && !['exact', 'after-open'].includes(mode)) await mutate();
  return info;
};
fs.readFile = async (...args) => {
  const data = await original.readFile(...args); if (args[0] === path) bytes += data.length; return data;
};
fs.open = async (...args) => {
  if (args[0] === path && ['symlink', 'fifo'].includes(mode)) await mutate();
  const file = await original.open(...args);
  if (args[0] !== path) return file;
  const stat = file.stat.bind(file), read = file.read.bind(file), close = file.close.bind(file);
  file.stat = async (...values) => { const info = await stat(...values); if (mode === 'grow') await mutate(); return info; };
  file.read = async (...values) => { const result = await read(...values); bytes += result.bytesRead; return result; };
  file.close = async () => { await close(); closed = true; };
  if (mode === 'after-open') await mutate();
  return file;
};
syncBuiltinESMExports();
const { MapService } = await import('../../dist/service.js');
const service = new MapService({ read: async () => ({ sources: [] }) });
let server;
function secureRead(url) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(url, { ca: tls.ca, rejectUnauthorized: true, agent: false }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > maximum + 1) res.destroy(new Error('TEST_RESPONSE_TOO_LARGE')); else chunks.push(chunk); });
      res.on('error', reject);
      res.once('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks), csp: res.headers['content-security-policy'] }));
    });
    req.setTimeout(3000, () => req.destroy(new Error('TEST_RESPONSE_TIMEOUT')));
    req.on('error', reject); req.end();
  });
}
try {
  if (transport === 'http') {
    const { startMapServer } = await import('../../dist/http.js');
    server = await startMapServer({ service, credentials: [{ token: 'agm_v1.' + 'a'.repeat(43),
      scope: { subject: 'test', companyId: 'company', tenantIds: ['tenant'], teamIds: [], allTeams: true } }], viewerDirectory: directory });
  } else {
    const { startMapIdentityServer } = await import('../../dist/identity-http.js');
    server = await startMapIdentityServer({ service, publicOrigin: 'https://127.0.0.1:0', port: 0, tls: { key: tls.key, cert: tls.cert },
      oidc: { issuer: tls.issuer ?? 'https://issuer.invalid', clientId: tls.clientId ?? 'client', clientSecret: tls.clientSecret ?? 'secret',
        ...(tls.ca ? { ca: tls.ca } : {}) }, companyId: 'company', bindings: [], viewerDirectory: directory });
  }
  // Startup captures immutable bytes; later writes must not change the public asset.
  if (mode === 'exact') await fs.writeFile(path, 'changed after startup');
  const response = transport === 'https' ? await secureRead(server.url + '/') : await (async () => {
    const value = await fetch(server.url + '/');
    return { status: value.status, body: Buffer.from(await value.arrayBuffer()), csp: value.headers.get('content-security-policy') };
  })();
  process.stdout.write(JSON.stringify({ accepted: true, bytes, closed, mutated, status: response.status,
    length: response.body.length, digest: createHash('sha256').update(response.body).digest('hex'),
    servedPrivate: response.body.includes('asset-boundary-private-canary'), csp: response.csp }));
} catch (error) {
  process.stdout.write(JSON.stringify({ code: error.code, bytes, closed, mutated }));
} finally { await server?.close(); }
