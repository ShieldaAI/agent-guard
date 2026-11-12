import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { AgentGuard } from '@shieldaai/agent-guard';
import {
  ManagedMcpConnection,
  McpBoundaryError,
  McpBoundaryErrorCatalog,
  compileBoundedSchema,
} from '../dist/index.js';

const MIB = 1_048_576;
const identity = {
  serverId: 'documents',
  transportIdentity: 'isolated-executor:documents-v1',
  tenantId: 'acme',
  principalId: 'operator',
};
const schema = {
  type: 'object',
  properties: { size: { type: 'integer' } },
  required: ['size'],
  additionalProperties: false,
};

/** A server whose `read` tool returns a text of the requested size. */
async function fixture(t, { guardOptions = {}, limits } = {}) {
  let calls = 0;
  const server = new McpServer({ name: 'documents', version: '1' });
  server.registerTool('read', { description: 'Read a document', inputSchema: fromJsonSchema(schema) }, args => {
    calls++;
    return { content: [{ type: 'text', text: 'x'.repeat(args.size) }] };
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const guard = new AgentGuard(guardOptions);
  const connection = await ManagedMcpConnection.connect({
    guard,
    identity,
    transport: clientTransport,
    tools: [{ name: 'read', resolve: () => ({ resourceId: 'report', tenantId: 'acme' }) }],
    ...(limits ? { limits } : {}),
  });
  t.after(async () => {
    await connection.close();
    await server.close();
  });
  const approve = () => {
    for (const registration of connection.registrations) guard.approveTool(registration.name, registration.fingerprint);
  };
  approve();
  const name = connection.registrations[0].name;
  const task = () =>
    guard.createTask({
      id: crypto.randomUUID(),
      principalId: 'operator',
      tenantId: 'acme',
      grants: [{ tool: name, resources: ['report'] }],
      budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000 },
    });
  const read = async (handle, size) => guard.execute(await guard.prepare(handle, { tool: name, args: { size } }));
  return { guard, connection, server, serverTransport, approve, task, read, calls: () => calls };
}

test('the default message limit is 1 MiB: a larger result fails only its call and keeps the task', async t => {
  const f = await fixture(t);
  const handle = f.task();
  assert.equal((await f.read(handle, MIB - 4_096)).content[0].text.length, MIB - 4_096);
  await assert.rejects(f.read(handle, MIB), { code: 'TOOL_FAILED', detail: 'MCP_OPERATION_FAILED' });
  assert.equal(f.connection.status, 'ready');
  assert.equal(f.guard.snapshot(handle).revoked, false);
  assert.equal(f.calls(), 2);
});

test('limits.maxMessageBytes with a matching guard limit delivers results above 1 MiB', async t => {
  const f = await fixture(t, {
    guardOptions: { limits: { maxJsonBytes: 4 * MIB } },
    limits: { maxMessageBytes: 4 * MIB },
  });
  const handle = f.task();
  assert.equal((await f.read(handle, 3 * MIB)).content[0].text.length, 3 * MIB);
  // The raised limit is still a limit, and going over it still fails only the call.
  await assert.rejects(f.read(handle, 4 * MIB), { code: 'TOOL_FAILED', detail: 'MCP_OPERATION_FAILED' });
  assert.equal(f.connection.status, 'ready');
  assert.equal(f.guard.snapshot(handle).revoked, false);
});

test('a raised connection limit above the guard limit fails RESULT_INVALID and revokes the task', async t => {
  const f = await fixture(t, { limits: { maxMessageBytes: 4 * MIB } });
  const handle = f.task();
  await assert.rejects(f.read(handle, 2 * MIB), { code: 'RESULT_INVALID' });
  assert.equal(f.guard.snapshot(handle).revoked, true);
  assert.equal(f.connection.status, 'ready', 'the connection is unaffected');
  assert.equal(f.calls(), 1);
});

test('limits.maxMessageBytes accepts 1 MiB to 16 MiB only', async t => {
  for (const maxMessageBytes of [MIB - 1, 16 * MIB + 1, 1.5 * MIB + 0.5, 0, -1, '2097152']) {
    const [transport] = InMemoryTransport.createLinkedPair();
    await assert.rejects(
      ManagedMcpConnection.connect({ guard: new AgentGuard(), identity, transport, limits: { maxMessageBytes } }),
      { code: 'INVALID_CONFIGURATION' },
      String(maxMessageBytes),
    );
  }
  for (const maxMessageBytes of [MIB, 16 * MIB]) {
    const f = await fixture(t, { limits: { maxMessageBytes } });
    assert.equal(f.connection.status, 'ready');
  }
});

test('a transport that closes during the handshake is never reported ready', async t => {
  const server = new McpServer({ name: 'documents', version: '1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  t.after(() => server.close());
  const send = clientTransport.send.bind(clientTransport);
  let closedDuringHandshake = false;
  clientTransport.send = async (message, options) => {
    await send(message, options);
    if (message.method === 'notifications/initialized') {
      closedDuringHandshake = true;
      await clientTransport.close();
    }
  };
  // With no bindings a refresh sends nothing, so only the state check can notice the close.
  await assert.rejects(
    ManagedMcpConnection.connect({ guard: new AgentGuard(), identity, transport: clientTransport }),
    {
      code: 'CONNECTION_FAILED',
    },
  );
  assert.equal(closedDuringHandshake, true);
});

test('a superseded refresh reports CONNECTION_CHANGED whether it had started or not', async t => {
  const f = await fixture(t);
  let release;
  const hold = new Promise(resolve => {
    release = resolve;
  });
  let entered;
  const started = new Promise(resolve => {
    entered = resolve;
  });
  let lists = 0;
  f.server.server.setRequestHandler('tools/list', async () => {
    if (++lists === 1) {
      entered();
      await hold;
    }
    return { tools: [f.connection.registrations[0]?.descriptor ?? { name: 'read', inputSchema: schema }] };
  });
  // The first refresh is in flight, the second is queued, and the third supersedes both.
  const inFlight = assert.rejects(f.connection.refresh(), { code: 'CONNECTION_CHANGED' });
  await started;
  const queued = assert.rejects(f.connection.refresh(), { code: 'CONNECTION_CHANGED' });
  const latest = f.connection.refresh();
  release();
  await Promise.all([inFlight, queued, latest]);
  assert.equal(f.connection.status, 'ready');
  assert.equal(f.connection.failureReason, undefined);
  assert.equal(f.connection.registrations.length, 1);
});

test('a registry this refresh refuses reports REGISTRY_REJECTED with the specific failureReason', async t => {
  const f = await fixture(t);
  f.server.server.setRequestHandler('tools/list', () => ({
    tools: [
      { name: 'read', inputSchema: schema },
      { name: 'read', inputSchema: schema },
    ],
  }));
  await assert.rejects(f.connection.refresh(), { code: 'REGISTRY_REJECTED' });
  assert.equal(f.connection.status, 'quarantined');
  assert.equal(f.connection.failureReason, 'REGISTRY_REJECTED');
  // A malformed advertised name is the server's fault, not a host option.
  f.server.server.setRequestHandler('tools/list', () => ({ tools: [{ name: 'read\0', inputSchema: schema }] }));
  await assert.rejects(f.connection.refresh(), { code: 'REGISTRY_REJECTED' });
  assert.equal(f.connection.failureReason, 'REGISTRY_REJECTED');
});

test('McpBoundaryErrorCatalog covers exactly the McpBoundaryErrorCode union', () => {
  const source = readFileSync(new URL('../src/boundary.ts', import.meta.url), 'utf8');
  const union = [...source.match(/export type McpBoundaryErrorCode =([\s\S]*?);/)[1].matchAll(/'([A-Z_]+)'/g)].map(
    match => match[1],
  );
  assert.ok(union.length >= 30);
  assert.deepEqual(Object.keys(McpBoundaryErrorCatalog).sort(), [...union].sort());
  assert.equal(Object.isFrozen(McpBoundaryErrorCatalog), true);
  for (const [code, info] of Object.entries(McpBoundaryErrorCatalog)) {
    assert.deepEqual(Object.keys(info).sort(), ['action', 'meaning'], code);
    assert.ok(info.meaning.length > 20 && info.action.length > 20, code);
    assert.equal(Object.isFrozen(info), true, code);
    assert.equal(new McpBoundaryError(code).message, code);
  }
  // Every code thrown anywhere in the package is in the union.
  for (const file of ['authorization', 'boundary', 'credentials', 'http', 'inventory', 'managed']) {
    const text = readFileSync(new URL(`../src/${file}.ts`, import.meta.url), 'utf8');
    for (const [, code] of text.matchAll(/McpBoundaryError\('([A-Z_]+)'\)/g)) assert.ok(union.includes(code), code);
  }
});

test('each validation call has its own pattern budget, and validators do not share one', () => {
  const pattern = { type: 'array', items: { type: 'string', pattern: '^a+$' } };
  const first = compileBoundedSchema(pattern);
  const second = compileBoundedSchema(pattern);
  const text = 'a'.repeat(4_000);
  // Five strings of 4,000 characters cost 80 million units, over the 2^26 budget of one call.
  const exhausting = Array(5).fill(text);
  const affordable = Array(4).fill(text);
  assert.equal(first(exhausting), false);
  assert.equal(first(affordable), true, 'the next call starts with a full budget');
  assert.equal(second(affordable), true);
  assert.equal(second(exhausting), false);
  assert.equal(first(affordable), true, "another validator's exhausted call leaves this one untouched");
});
