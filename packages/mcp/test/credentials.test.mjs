import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { AgentGuard } from '@shieldaai/agent-guard';
import { DurableExecutor, createRestrictedFetch } from '@shieldaai/agent-guard-executor';
import { VerifiedMcpHttpSession } from '../dist/index.js';
import { credentialFixture } from './helpers/credentials.mjs';

function options(fixture, guard, patch = {}) {
  return {
    guard,
    identity: { serverId: 'remote', tenantId: 'tenant-a', principalId: 'operator' },
    endpoint: fixture.endpoint,
    authorization: {
      issuer: fixture.origin,
      jwksUri: fixture.origin + '/jwks',
      audience: fixture.origin + '/resource',
      subject: 'operator',
      requiredScopes: ['records:read', 'records:write'],
    },
    fetch: createRestrictedFetch({
      allowedOrigins: [fixture.origin],
      allowPrivateOrigins: [fixture.origin],
      additionalCaByOrigin: { [fixture.origin]: fixture.ca },
      timeoutMs: 1000,
    }),
    tools: ['read', 'write'].map(name => ({
      name,
      requiresApproval: name === 'write',
      resolve: args => ({ resourceId: args.resource, tenantId: args.resource === 'foreign' ? 'tenant-b' : 'tenant-a' }),
    })),
    limits: { requestTimeoutMs: 1000 },
    ...patch,
  };
}
function task(guard, id = 'task') {
  return guard.createTask({
    id,
    tenantId: 'tenant-a',
    principalId: 'operator',
    grants: ['read', 'write'].map(name => ({ tool: `mcp:remote:${name}`, resources: ['allowed', 'foreign'] })),
    budget: { maxCalls: 20, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000 },
  }).taskId;
}
function approveTools(guard, session) {
  for (const item of session.registrations) guard.approveTool(item.name, item.fingerprint);
}
function prepare(guard, id, name = 'read', resource = 'allowed') {
  return guard.prepare(id, { tool: `mcp:remote:${name}`, args: { resource } });
}
function approve(guard, action) {
  return guard.approve(action.id, { approverId: 'host-reviewer', expiresAt: Date.now() + 30_000 });
}
async function until(check) {
  for (let i = 0; i < 100; i++) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.fail('Fixture observation timed out');
}
const executorOptions = () => ({
  database: ':memory:',
  encryptionKey: randomBytes(32),
  decisionTraces: { maxEventsPerTenant: 100 },
});

test('real HTTPS MCP credentials enforce verified access token lifecycle and cleanup', { timeout: 20_000 }, async t => {
  const fixture = await credentialFixture(t),
    executor = new DurableExecutor(executorOptions());
  const firstToken = await fixture.token(),
    session = await VerifiedMcpHttpSession.connect(options(fixture, executor), firstToken);
  t.after(async () => {
    await session.close();
    executor.close();
  });
  approveTools(executor, session);
  const id = task(executor);
  await executor.execute(id, (await prepare(executor, id)).id);
  const write = await prepare(executor, id, 'write');
  await assert.rejects(executor.execute(id, write.id));
  assert.equal(fixture.counts.writes, 0);
  await executor.execute(id, write.id, { approvalId: approve(executor, write) });
  await assert.rejects(prepare(executor, id, 'read', 'foreign'));
  assert.equal(fixture.counts.reads, 1);
  assert.equal(fixture.counts.writes, 1);
  const stale = await prepare(executor, id, 'write');
  approve(executor, stale);
  const oldSession = session.sessionId;
  fixture.controls.keys = [1];
  const secondToken = await fixture.token({}, {}, 1);
  await session.replaceCredential(secondToken);
  assert.notEqual(session.sessionId, oldSession);
  assert.equal(fixture.counts.jwks, 2);
  await assert.rejects(executor.execute(id, stale.id));
  await assert.rejects(prepare(executor, id));
  approveTools(executor, session);
  const renewed = await prepare(executor, id, 'write');
  await assert.rejects(executor.execute(id, renewed.id));
  await executor.execute(id, renewed.id, { approvalId: approve(executor, renewed) });
  assert.equal(fixture.counts.writes, 2);
  const before = fixture.counts.calls;
  // Removed keys cannot survive the fresh verification boundary on another replacement.
  await assert.rejects(session.replaceCredential(firstToken), { code: 'AUTHORIZATION_DENIED' });
  await assert.rejects(prepare(executor, id));
  assert.equal(fixture.counts.calls, before);
  await session.replaceCredential(secondToken);
  approveTools(executor, session);
  const revoked = await prepare(executor, id);
  await session.revoke();
  await assert.rejects(executor.execute(id, revoked.id));
  await assert.rejects(session.replaceCredential(secondToken), { code: 'CONNECTION_UNAVAILABLE' });
  assert.equal(fixture.counts.calls, before);
  assert.equal(fixture.counts.credentialsAtJwks, 0);
  assert.deepEqual(fixture.tokensSeen, new Set([`Bearer ${firstToken}`, `Bearer ${secondToken}`]));
  const visible = JSON.stringify({
    inventory: session.inventory(),
    trace: executor.decisionTraceSnapshot({ tenantId: 'tenant-a' }),
    session,
  });
  for (const secret of [firstToken, secondToken, fixture.ca]) assert(!visible.includes(secret));
  await fixture.close();
  assert.equal(fixture.cleaned(), true);
});

test('a peer reflecting the bearer cannot publish metadata or return it to a task', { timeout: 10_000 }, async t => {
  const fixture = await credentialFixture(t),
    executor = new DurableExecutor(executorOptions());
  t.after(() => executor.close());
  const token = await fixture.token();
  fixture.controls.reflect = 'description';
  await assert.rejects(VerifiedMcpHttpSession.connect(options(fixture, executor), token), {
    code: 'AUTHORIZATION_DENIED',
  });
  assert.equal(fixture.counts.calls, 0);
  fixture.controls.reflect = undefined;
  const session = await VerifiedMcpHttpSession.connect(options(fixture, executor), token);
  t.after(() => session.close());
  approveTools(executor, session);
  const id = task(executor);
  const benign = await executor.execute(id, (await prepare(executor, id)).id);
  assert.equal(benign.content[0].text, 'Synthetic protected effect completed.');
  fixture.controls.reflect = 'result';
  const action = await prepare(executor, id);
  await assert.rejects(executor.execute(id, action.id), { code: 'TOOL_FAILED' });
  assert.equal(executor.execution(id, action.id).status, 'UNKNOWN');
  assert.deepEqual(session.registrations, []);
  await assert.rejects(prepare(executor, id));
  assert.equal(fixture.counts.calls, 2);
  assert(
    !JSON.stringify([session.inventory(), executor.decisionTraceSnapshot({ tenantId: 'tenant-a' })]).includes(token),
  );
});

test(
  'invalid JWT profiles cannot contact MCP and token key URLs cannot select a sink',
  { timeout: 20_000 },
  async t => {
    const fixture = await credentialFixture(t),
      guard = new AgentGuard();
    const now = Math.floor(Date.now() / 1000);
    const variants = [
      [{ iss: 'https://wrong.invalid' }],
      [{ aud: 'https://wrong.invalid' }],
      [{ sub: 'other' }],
      [{ scope: 'records:read' }],
      [{ exp: now - 1 }],
      [{ nbf: now + 30 }],
      [{ iat: now + 10 }],
      [{ exp: now + 7200 }],
      [{ client_id: '' }],
      [{ jti: '' }],
      [{ scope: ['records:read'] }],
      [{}, { typ: 'JWT' }],
      [{}, { jku: 'https://wrong.invalid/jwks' }],
      [{}, { jwk: {} }],
      [{}, { kid: 'unknown' }],
      [{}, { kid: 'key-0' }, 1],
    ];
    for (const [claims, header, key] of variants)
      await assert.rejects(
        VerifiedMcpHttpSession.connect(options(fixture, guard), await fixture.token(claims, header, key)),
        { code: 'AUTHORIZATION_DENIED' },
      );
    assert.equal(fixture.counts.mcp, 0);
    assert.equal(fixture.counts.credentialsAtJwks, 0);
    const session = await VerifiedMcpHttpSession.connect(
      options(fixture, guard),
      await fixture.token({}, { typ: 'application/at+jwt' }),
    );
    await session.close();
  },
);

test('TLS trust and hostname failures send no access token or MCP request', async t => {
  for (const wrongName of [false, true]) {
    const fixture = await credentialFixture(t, { wrongName }),
      guard = new AgentGuard();
    const fetch = createRestrictedFetch({
      allowedOrigins: [fixture.origin],
      allowPrivateOrigins: [fixture.origin],
      ...(wrongName ? { additionalCaByOrigin: { [fixture.origin]: fixture.ca } } : {}),
    });
    await assert.rejects(VerifiedMcpHttpSession.connect(options(fixture, guard, { fetch }), await fixture.token()), {
      code: 'AUTHORIZATION_DENIED',
    });
    assert.equal(fixture.counts.jwks, 0);
    assert.equal(fixture.counts.mcp, 0);
  }
});

test('replacement invalidates immediately and close during JWKS verification cannot resurrect authority', async t => {
  const fixture = await credentialFixture(t),
    executor = new DurableExecutor(executorOptions());
  const token = await fixture.token(),
    session = await VerifiedMcpHttpSession.connect(options(fixture, executor), token);
  t.after(async () => {
    await session.close();
    executor.close();
  });
  approveTools(executor, session);
  const id = task(executor),
    action = await prepare(executor, id);
  fixture.controls.delayJwks = 500;
  const replacement = session.replaceCredential(token);
  const rejection = assert.rejects(replacement, { code: 'AUTHORIZATION_DENIED' });
  await assert.rejects(executor.execute(id, action.id));
  await assert.rejects(session.replaceCredential(token), { code: 'CREDENTIAL_REPLACEMENT_PENDING' });
  await until(() => fixture.counts.jwks === 2);
  const before = fixture.counts.mcp;
  await session.revoke();
  await rejection;
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(session.status, 'closed');
  assert.equal(fixture.counts.mcp, before);
  assert.equal(fixture.counts.calls, 0);
});

test('expired credentials deny a prepared dispatch without contacting the peer', async t => {
  const fixture = await credentialFixture(t),
    executor = new DurableExecutor(executorOptions());
  const exp = Math.floor(Date.now() / 1000) + 2;
  const session = await VerifiedMcpHttpSession.connect(options(fixture, executor), await fixture.token({ exp }));
  t.after(async () => {
    await session.close();
    executor.close();
  });
  approveTools(executor, session);
  const id = task(executor),
    action = await prepare(executor, id);
  await new Promise(resolve => setTimeout(resolve, Math.max(1, exp * 1000 - Date.now() + 20)));
  const before = fixture.counts.mcp;
  await assert.rejects(executor.execute(id, action.id));
  assert.equal(fixture.counts.mcp, before);
  assert.equal(fixture.counts.calls, 0);
  assert.equal(session.status, 'quarantined');
});

test('JWKS bounds deadline and redirects fail closed without leaking bearer credentials', async t => {
  const fixture = await credentialFixture(t),
    guard = new AgentGuard();
  let leaks = 0;
  const collector = createServer((_req, res) => {
    leaks++;
    res.end('{}');
  });
  await new Promise(resolve => collector.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => collector.close(resolve)));
  const target = `http://127.0.0.1:${collector.address().port}`;
  fixture.controls.redirectJwks = target;
  await assert.rejects(VerifiedMcpHttpSession.connect(options(fixture, guard), await fixture.token()));
  assert.equal(leaks, 0);
  fixture.controls.redirectJwks = undefined;
  fixture.controls.jwksBody = { padding: 'x'.repeat(2000) };
  await assert.rejects(
    VerifiedMcpHttpSession.connect(options(fixture, guard, { maxJwksBytes: 1024 }), await fixture.token()),
  );
  fixture.controls.jwksBody = undefined;
  fixture.controls.delayJwks = 200;
  await assert.rejects(
    VerifiedMcpHttpSession.connect(options(fixture, guard, { verificationTimeoutMs: 30 }), await fixture.token()),
  );
  assert.equal(fixture.counts.mcp, 0);
  fixture.controls.delayJwks = 0;
  fixture.controls.redirectMcp = target;
  await assert.rejects(VerifiedMcpHttpSession.connect(options(fixture, guard), await fixture.token()));
  assert.equal(leaks, 0);
  assert.equal(fixture.counts.credentialsAtJwks, 0);
});

test('deadline and revocation settle despite an uncooperative fetch and late verification cannot restore registrations', async t => {
  const fixture = await credentialFixture(t),
    guard = new AgentGuard();
  const config = options(fixture, guard),
    network = config.fetch;
  let stall = false,
    release;
  config.fetch = async (input, init) => {
    const response = await network(input, init);
    if (stall && String(input).endsWith('/jwks'))
      return new Promise(resolve => {
        release = () => resolve(response);
      });
    return response;
  };
  const token = await fixture.token();
  // Leave headroom for the valid TLS handshake under parallel CI load; the replacement still must time out.
  const session = await VerifiedMcpHttpSession.connect({ ...config, verificationTimeoutMs: 1000 }, token);
  t.after(() => session.close());
  approveTools(guard, session);
  stall = true;
  await assert.rejects(session.replaceCredential(token), { code: 'AUTHORIZATION_DENIED' });
  assert.equal(session.status, 'quarantined');
  const before = fixture.counts.mcp;
  release();
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(fixture.counts.mcp, before);
  assert.equal(session.registrations.length, 0);
  release = undefined;
  const pending = session.replaceCredential(token),
    rejected = assert.rejects(pending, { code: 'AUTHORIZATION_DENIED' });
  await until(() => typeof release === 'function');
  await session.close();
  await rejected;
  release();
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(session.status, 'closed');
  assert.equal(fixture.counts.mcp, before);
});

test('a late MCP initialization after revocation cannot overwrite a newer session registry', async t => {
  const fixture = await credentialFixture(t),
    guard = new DurableExecutor(executorOptions());
  const config = options(fixture, guard),
    network = config.fetch;
  let stall = false,
    release;
  config.fetch = async (input, init) => {
    const response = await network(input, init);
    if (stall && String(input).endsWith('/mcp') && init?.method === 'POST') {
      stall = false;
      return new Promise(resolve => {
        release = () => resolve(response);
      });
    }
    return response;
  };
  const token = await fixture.token(),
    session = await VerifiedMcpHttpSession.connect(config, token);
  t.after(() => session.close());
  stall = true;
  const replacing = session.replaceCredential(token),
    rejected = assert.rejects(replacing, { code: 'AUTHORIZATION_DENIED' });
  await until(() => typeof release === 'function');
  await session.close();
  await rejected;
  const next = await VerifiedMcpHttpSession.connect(options(fixture, guard), token);
  t.after(async () => {
    await next.close();
    guard.close();
  });
  approveTools(guard, next);
  const id = task(guard, 'new-session');
  release();
  await new Promise(resolve => setTimeout(resolve, 20));
  await guard.execute(id, (await prepare(guard, id)).id);
  assert.equal(fixture.counts.reads, 1);
});

test('revoking an admitted remote call preserves UNKNOWN until trusted reconciliation and forbids replay', async t => {
  const fixture = await credentialFixture(t),
    executor = new DurableExecutor(executorOptions());
  const session = await VerifiedMcpHttpSession.connect(options(fixture, executor), await fixture.token());
  t.after(async () => {
    await session.close();
    executor.close();
  });
  approveTools(executor, session);
  const id = task(executor),
    action = await prepare(executor, id);
  fixture.controls.hangCall = true;
  const result = executor.execute(id, action.id),
    rejected = assert.rejects(result);
  await until(() => fixture.counts.calls === 1);
  await session.revoke();
  await rejected;
  assert.equal(executor.execution(id, action.id).status, 'UNKNOWN');
  assert.equal(executor.snapshot(id).concurrent, 1);
  await assert.rejects(executor.execute(id, action.id));
  assert.equal(fixture.counts.calls, 1);
  await fixture.close();
  assert.equal(fixture.cleaned(), true);
  executor.reconcile(action.id, {
    outcome: 'FAILED',
    actualCost: 0,
    reference: 'Trusted fixture handler exited without effect; HTTPS listener and all sockets terminated.',
  });
  assert.equal(executor.snapshot(id).concurrent, 0);
});
