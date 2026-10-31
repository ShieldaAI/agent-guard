import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection, createRestrictedMcpHttpTransport, assertVerifiedMcpClaims } from '../dist/index.js';

async function listen(t, handler) {
  const server = createServer(handler); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}/mcp`;
}
const identity = { serverId: 'remote', transportIdentity: 'test-loopback-only', principalId: 'operator', tenantId: 'acme' };
async function connect(transport) { return ManagedMcpConnection.connect({ guard: new AgentGuard(), identity, transport, limits: { requestTimeoutMs: 500 } }); }

test('real HTTP 307 cannot forward credentials or request bodies to another server', { timeout: 5_000 }, async t => {
  let attackerRequests = 0; let legitimateRequests = 0; let seenKey;
  const attacker = await listen(t, (_req, res) => { attackerRequests++; res.end('unexpected'); });
  const endpoint = await listen(t, (req, res) => { legitimateRequests++; seenKey = req.headers['x-api-key']; res.writeHead(307, { location: attacker }); res.end(); });
  const transport = createRestrictedMcpHttpTransport({ endpoint, fetch, allowInsecureLoopback: true, headers: { 'X-API-Key': 'fixture-secret' } });
  await assert.rejects(connect(transport), { code: 'CONNECTION_FAILED' });
  assert.equal(legitimateRequests, 1); assert.equal(seenKey, 'fixture-secret'); assert.equal(attackerRequests, 0);
});

test('HTTP profile accepts a benign SDK initialization and bounds streamed bytes', { timeout: 5_000 }, async t => {
  const received = [];
  const endpoint = await listen(t, async (req, res) => {
    if (req.method === 'GET') { res.writeHead(405); res.end(); return; }
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const message = JSON.parse(Buffer.concat(chunks).toString()); received.push(message.method);
    if (!Object.hasOwn(message, 'id')) { res.writeHead(202); res.end(); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: message.params.protocolVersion, capabilities: {}, serverInfo: { name: 'fixture', version: '1' } } }));
  });
  const connection = await connect(createRestrictedMcpHttpTransport({ endpoint, fetch, allowInsecureLoopback: true }));
  assert.equal(connection.status, 'ready'); await connection.close(); assert.ok(received.includes('initialize'));

  const oversized = await listen(t, (_req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('x'.repeat(128)); res.end('y'.repeat(128)); });
  await assert.rejects(connect(createRestrictedMcpHttpTransport({ endpoint: oversized, fetch, allowInsecureLoopback: true, maxResponseBytes: 64 })), { code: 'CONNECTION_FAILED' });
});

test('endpoint profile rejects plaintext remote URLs, URL credentials and fragments', () => {
  for (const endpoint of ['http://example.com/mcp', 'http://localhost/mcp', 'https://user:secret@example.com/mcp', 'https://example.com/mcp#other']) {
    assert.throws(() => createRestrictedMcpHttpTransport({ endpoint, fetch, allowInsecureLoopback: true }), { code: 'ENDPOINT_DENIED' });
  }
});

test('already verified claims must match issuer, audience, subject, scopes and lifetime', () => {
  const policy = { issuer: 'https://issuer.example', audience: 'https://mcp.example', subject: 'alice', requiredScopes: ['reports:read'] };
  const claims = { issuer: policy.issuer, audience: [policy.audience], subject: 'alice', expiresAt: 200, notBefore: 90, scopes: ['reports:read'] };
  assert.doesNotThrow(() => assertVerifiedMcpClaims(claims, policy, 100));
  for (const patch of [{ issuer: 'https://attacker.example' }, { audience: 'https://other-service.example' }, { subject: 'bob' }, { scopes: [] }, { expiresAt: 100 }, { notBefore: 101 }]) {
    assert.throws(() => assertVerifiedMcpClaims({ ...claims, ...patch }, policy, 100), { code: 'AUTHORIZATION_DENIED' });
  }
});
