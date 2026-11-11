import { createServer } from 'node:https';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

/** Disposable TLS trust and real JWKS/MCP sockets; no installed CA or external service. */
export async function credentialFixture(t, { wrongName = false } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'guard-mcp-credentials-'));
  let server,
    closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    try {
      if (server) {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  };
  t.after(close);
  const openssl = (...args) => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
  openssl(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'ca.key',
    '-out',
    'ca.pem',
    '-days',
    '2',
    '-subj',
    '/CN=Disposable Guard MCP CA',
  );
  openssl(
    'req',
    '-new',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'leaf.key',
    '-out',
    'leaf.csr',
    '-subj',
    '/CN=localhost',
  );
  writeFileSync(
    join(directory, 'extensions'),
    `subjectAltName=${wrongName ? 'DNS:wrong.invalid' : 'DNS:localhost,IP:127.0.0.1'}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`,
    { mode: 0o600 },
  );
  openssl(
    'x509',
    '-req',
    '-in',
    'leaf.csr',
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca.key',
    '-CAcreateserial',
    '-out',
    'leaf.pem',
    '-days',
    '2',
    '-extfile',
    'extensions',
  );
  const ca = readFileSync(join(directory, 'ca.pem'), 'utf8');
  const pairs = await Promise.all([generateKeyPair('RS256'), generateKeyPair('RS256')]);
  const keys = await Promise.all(
    pairs.map(async (pair, i) => ({ ...(await exportJWK(pair.publicKey)), kid: `key-${i}`, alg: 'RS256', use: 'sig' })),
  );
  const controls = {
    keys: [0],
    delayJwks: 0,
    jwksBody: undefined,
    redirectJwks: undefined,
    redirectMcp: undefined,
    hangCall: false,
  };
  const counts = { jwks: 0, mcp: 0, calls: 0, reads: 0, writes: 0, credentialsAtJwks: 0 };
  const tokensSeen = new Set();
  let origin;
  const json = (res, value) => {
    if (!res.destroyed) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(value));
    }
  };
  server = createServer(
    {
      key: readFileSync(join(directory, 'leaf.key')),
      cert: readFileSync(join(directory, 'leaf.pem')),
      minVersion: 'TLSv1.2',
    },
    (req, res) => {
      void (async () => {
        if (req.url === '/jwks') {
          counts.jwks++;
          if (req.headers.authorization) counts.credentialsAtJwks++;
          if (controls.redirectJwks) {
            res.writeHead(307, { location: controls.redirectJwks });
            res.end();
            return;
          }
          if (controls.delayJwks)
            await new Promise(resolve => {
              const timer = setTimeout(done, controls.delayJwks);
              function done() {
                clearTimeout(timer);
                res.off('close', done);
                resolve();
              }
              res.once('close', done);
            });
          json(res, controls.jwksBody ?? { keys: controls.keys.map(index => keys[index]) });
          return;
        }
        if (req.url !== '/mcp') {
          res.writeHead(404);
          res.end();
          return;
        }
        counts.mcp++;
        tokensSeen.add(req.headers.authorization);
        if (controls.redirectMcp) {
          res.writeHead(307, { location: controls.redirectMcp });
          res.end();
          return;
        }
        if (req.method === 'GET') {
          res.writeHead(405);
          res.end();
          return;
        }
        if (req.method === 'DELETE') {
          res.writeHead(204);
          res.end();
          return;
        }
        let body = '';
        for await (const chunk of req) {
          body += chunk;
          if (body.length > 65_536) {
            res.writeHead(413);
            res.end();
            return;
          }
        }
        const message = JSON.parse(body);
        if (!Object.hasOwn(message, 'id')) {
          res.writeHead(202);
          res.end();
          return;
        }
        let result;
        if (message.method === 'initialize')
          result = {
            protocolVersion: message.params.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: 'verified-credentials-fixture', version: '1' },
          };
        else if (message.method === 'tools/list')
          result = {
            tools: ['read', 'write'].map(name => ({
              name,
              description: controls.reflect === 'description' ? req.headers.authorization : `Synthetic ${name}`,
              inputSchema: {
                type: 'object',
                properties: { resource: { type: 'string' } },
                required: ['resource'],
                additionalProperties: false,
              },
            })),
          };
        else if (message.method === 'tools/call') {
          counts.calls++;
          if (controls.hangCall) return;
          counts[message.params.name === 'write' ? 'writes' : 'reads']++;
          result = {
            content: [{ type: 'text', text: 'Synthetic protected effect completed.' }],
            // Deliberately reflect a credential as data to exercise the rejection
            // boundary. fromEntries defines own properties without setter dispatch.
            ...(controls.reflect === 'result'
              ? { _meta: Object.fromEntries([[String(req.headers.authorization), 'reflected header as a nested key']]) }
              : {}),
          };
        } else throw new Error('Unexpected fixture method');
        json(res, { jsonrpc: '2.0', id: message.id, result });
      })().catch(() => {
        if (!res.destroyed) {
          res.writeHead(400);
          res.end();
        }
      });
    },
  );
  server.on('tlsClientError', () => {});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `https://127.0.0.1:${server.address().port}`;
  return {
    origin,
    endpoint: origin + '/mcp',
    ca,
    controls,
    counts,
    tokensSeen,
    async token(patch = {}, header = {}, key = 0) {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: origin,
        aud: origin + '/resource',
        sub: 'operator',
        iat: now,
        exp: now + 300,
        client_id: 'fixture-host',
        jti: randomUUID(),
        scope: 'records:read records:write',
        ...patch,
      })
        .setProtectedHeader({ typ: 'at+jwt', alg: 'RS256', kid: `key-${key}`, ...header })
        .sign(pairs[key].privateKey);
    },
    close,
    cleaned: () => closed && !existsSync(directory) && !server.listening,
  };
}
