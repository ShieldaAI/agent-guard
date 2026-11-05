import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:https';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { VerifiedMcpHttpSession } from '@shieldaai/agent-guard-mcp';
import { DurableExecutor, createRestrictedFetch } from '@shieldaai/agent-guard-executor';
import { createTestIdentityProvider } from './oidc-provider.mjs';

// Executed outside the checkout against installed tarballs. The issuer fixture supplies
// a private CA/JWKS endpoint; access tokens below are signed independently with node:crypto.
test('installed MCP credentials verify HTTPS JWTs and replace authority without stale effects', async t => {
  const provider = await createTestIdentityProvider(t);
  const signing = () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const kid = randomBytes(12).toString('hex');
    return { ...pair, kid, jwk: { ...pair.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } };
  };
  let current = signing();
  provider.controls.jwksResponse = { keys: [current.jwk] };
  const validTokens = new Set();
  let calls = 0, writes = 0, requests = 0;
  const server = createServer({ key: provider.key, cert: provider.cert }, (req, res) => {
    void (async () => {
      requests++;
      if (!validTokens.has(req.headers.authorization?.slice(7))) {
        res.writeHead(401); res.end(); return;
      }
      if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
      if (req.method === 'DELETE') { res.writeHead(204); res.end(); return; }
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 65536) throw new Error('FIXTURE_REQUEST_LIMIT');
      }
      const message = JSON.parse(body);
      if (!Object.hasOwn(message, 'id')) { res.writeHead(202); res.end(); return; }
      let result;
      if (message.method === 'initialize') result = {
        protocolVersion: '2025-11-25', capabilities: { tools: {} },
        serverInfo: { name: 'installed-credential-fixture', version: '1' },
      };
      else if (message.method === 'tools/list') result = { tools: ['read', 'write'].map(name => ({
        name, inputSchema: { type: 'object', properties: { resource: { type: 'string' } },
          required: ['resource'], additionalProperties: false },
      })) };
      else if (message.method === 'tools/call') {
        calls++;
        if (message.params.name === 'write') writes++;
        result = { content: [{ type: 'text', text: 'synthetic allowed result' }] };
      } else result = {};
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }));
    })().catch(() => { res.writeHead(400); res.end(); });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  let session, executor;
  t.after(async () => {
    try { await session?.close(); }
    finally {
      executor?.close();
      server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    }
  });
  const origin = `https://127.0.0.1:${server.address().port}`;
  const endpoint = origin + '/mcp';
  const token = (overrides = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = encoded({ alg: 'RS256', typ: 'at+jwt', kid: current.kid }) + '.' + encoded({
      iss: provider.issuer, sub: 'packed-worker', aud: endpoint, scope: 'tickets:read tickets:write',
      client_id: 'packed-host', jti: randomBytes(16).toString('hex'), iat: now, exp: now + 120, ...overrides,
    });
    const value = unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), current.privateKey).toString('base64url');
    validTokens.add(value);
    return value;
  };
  const fetch = createRestrictedFetch({
    allowedOrigins: [origin, provider.issuer], allowPrivateOrigins: [origin, provider.issuer],
    additionalCaByOrigin: { [origin]: provider.ca, [provider.issuer]: provider.ca },
    timeoutMs: 3000, maxResponseBytes: 65536,
  });
  const beforeUntrusted = requests;
  await assert.rejects(() => createRestrictedFetch({
    allowedOrigins: [origin], allowPrivateOrigins: [origin], timeoutMs: 3000,
  })(endpoint));
  assert.equal(requests, beforeUntrusted);
  executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
    decisionTraces: { maxEventsPerTenant: 128 } });
  const options = {
    guard: executor, identity: { serverId: 'packed-https', principalId: 'packed-host', tenantId: 'packed-tenant' },
    endpoint, fetch,
    authorization: { issuer: provider.issuer, jwksUri: provider.issuer + '/jwks',
      audience: endpoint, subject: 'packed-worker', requiredScopes: ['tickets:read', 'tickets:write'],
      algorithms: ['RS256'] },
    tools: ['read', 'write'].map(name => ({ name, requiresApproval: true,
      resolve: args => ({ resourceId: args.resource, tenantId: 'packed-tenant' }) })),
  };
  const firstToken = token();
  session = await VerifiedMcpHttpSession.connect(options, firstToken);
  const review = () => {
    for (const tool of session.registrations) executor.approveTool(tool.name, tool.fingerprint);
  };
  review();
  const task = executor.createTask({ id: 'packed-credential-task', principalId: 'packed-host', tenantId: 'packed-tenant',
    grants: session.registrations.map(tool => ({ tool: tool.name, resources: ['ticket'] })),
    budget: { maxCalls: 8, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60000 } }).taskId;
  const prepare = name => executor.prepare(task, { tool: `mcp:packed-https:${name}`, args: { resource: 'ticket' } });
  const approve = action => executor.approve(action.id, { approverId: 'packed-reviewer', expiresAt: Date.now() + 30000 });
  const read = await prepare('read');
  await assert.rejects(() => executor.execute(task, read.id));
  assert.equal(calls, 0);
  await executor.execute(task, read.id, { approvalId: approve(read) });
  assert.equal(calls, 1);
  const stale = await prepare('write');
  const staleApproval = approve(stale);
  current = signing();
  provider.controls.jwksResponse = { keys: [current.jwk] };
  const replacementToken = token();
  await session.replaceCredential(replacementToken);
  await assert.rejects(() => executor.execute(task, stale.id, { approvalId: staleApproval }));
  await assert.rejects(() => prepare('write'));
  assert.equal(writes, 0);
  review();
  const allowed = await prepare('write');
  await executor.execute(task, allowed.id, { approvalId: approve(allowed) });
  assert.equal(writes, 1);
  const revoked = await prepare('write');
  const revokedApproval = approve(revoked);
  await session.revoke();
  await assert.rejects(() => executor.execute(task, revoked.id, { approvalId: revokedApproval }));
  assert.equal(writes, 1);
  const beforeInvalid = requests;
  await assert.rejects(() => VerifiedMcpHttpSession.connect(options, token({ aud: 'https://wrong.invalid/mcp' })));
  assert.equal(requests, beforeInvalid);
  const trace = JSON.stringify(executor.decisionTraceSnapshot({ tenantId: 'packed-tenant' }));
  for (const privateValue of [firstToken, replacementToken, provider.clientSecret, 'packed-worker', 'packed-tenant'])
    assert.equal(trace.includes(privateValue), false);
});
