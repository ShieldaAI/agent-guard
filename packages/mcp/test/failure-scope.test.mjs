import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection } from '../dist/index.js';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const schema = {
  type: 'object',
  properties: { id: { type: 'string' } },
  required: ['id'],
  additionalProperties: false,
};
const identity = {
  serverId: 'documents',
  transportIdentity: 'isolated-executor:documents-v1',
  tenantId: 'acme',
  principalId: 'operator',
};

async function fixture(t, { handler, binding = {}, limits, expose } = {}) {
  let calls = 0;
  const server = new McpServer({ name: 'documents', version: '1' });
  server.registerTool('read', { description: 'Read a report', inputSchema: fromJsonSchema(schema) }, async args => {
    calls++;
    return handler ? handler(args) : { content: [{ type: 'text', text: `public ${args.id}` }] };
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  expose?.(serverTransport);
  const guard = new AgentGuard();
  const connection = await ManagedMcpConnection.connect({
    guard,
    identity,
    transport: clientTransport,
    tools: [{ name: 'read', resolve: () => ({ resourceId: 'report', tenantId: 'acme' }), ...binding }],
    ...(limits ? { limits } : {}),
  });
  t.after(async () => {
    await connection.close();
    await server.close();
  });
  const registration = connection.registrations[0];
  guard.approveTool(registration.name, registration.fingerprint);
  const task = (budget = {}) =>
    guard.createTask({
      id: crypto.randomUUID(),
      principalId: 'operator',
      tenantId: 'acme',
      grants: [{ tool: registration.name, resources: ['report'] }],
      budget: { maxCalls: 1000, maxConcurrent: 4, maxCost: 1000, deadline: Date.now() + 60_000, ...budget },
    });
  const call = async (handle, id) =>
    guard.execute(await guard.prepare(handle, { tool: registration.name, args: { id } }));
  return { connection, call, task, calls: () => calls };
}
const text = result => result.content[0].text;

test("one task's deadline abort leaves the connection usable for another task", { timeout: 10_000 }, async t => {
  const f = await fixture(t, {
    handler: async args => {
      if (args.id === 'slow') await sleep(1_000);
      return { content: [{ type: 'text', text: args.id }] };
    },
  });
  const short = f.task({ deadline: Date.now() + 150 });
  await assert.rejects(f.call(short, 'slow'), { code: 'EXECUTION_ABORTED' });
  assert.equal(f.connection.status, 'ready');
  assert.equal(text(await f.call(f.task(), 'next')), 'next');
});

test('a request timeout fails only its own call', { timeout: 10_000 }, async t => {
  const f = await fixture(t, {
    limits: { requestTimeoutMs: 100 },
    handler: async args => {
      if (args.id === 'slow') await sleep(500);
      return { content: [{ type: 'text', text: args.id }] };
    },
  });
  await assert.rejects(f.call(f.task(), 'slow'), { code: 'TOOL_FAILED' });
  assert.equal(f.connection.status, 'ready');
  assert.equal(text(await f.call(f.task(), 'next')), 'next');
});

test('a throwing measureCost fails only its own call', { timeout: 5_000 }, async t => {
  let fail = true;
  const f = await fixture(t, {
    binding: {
      maxCost: 1,
      measureCost: () => {
        if (fail) throw new Error('meter offline');
        return 1;
      },
    },
  });
  await assert.rejects(f.call(f.task(), 'first'), { code: 'TOOL_FAILED' });
  assert.equal(f.connection.status, 'ready');
  fail = false;
  assert.equal(text(await f.call(f.task(), 'second')), 'public second');
});

test('a single oversized reply fails only its own call', { timeout: 10_000 }, async t => {
  const f = await fixture(t, {
    handler: args => ({ content: [{ type: 'text', text: args.id === 'huge' ? 'x'.repeat(1_100_000) : args.id }] }),
  });
  await assert.rejects(f.call(f.task(), 'huge'), { code: 'TOOL_FAILED' });
  assert.equal(f.connection.status, 'ready');
  assert.equal(text(await f.call(f.task(), 'next')), 'next');
  assert.equal(f.calls(), 2);
});

test(
  'an oversized message that answers no call quarantines instead of closing, and refresh recovers',
  { timeout: 10_000 },
  async t => {
    let wire;
    const f = await fixture(t, {
      expose: transport => {
        wire = transport;
      },
    });
    await wire.send({
      jsonrpc: '2.0',
      method: 'notifications/message',
      params: { level: 'info', data: 'x'.repeat(1_100_000) },
    });
    assert.equal(f.connection.status, 'quarantined');
    await f.connection.refresh();
    assert.equal(f.connection.status, 'ready');
  },
);

test('sustained traffic past the old lifetime message cap keeps working', { timeout: 20_000 }, async t => {
  // 400 calls, each one inbound reply, against at most 60 messages per 150 ms.
  const f = await fixture(t, { limits: { maxMessages: 60, messageWindowMs: 150 } });
  const handle = f.task();
  for (let batch = 0; batch < 10; batch++) {
    for (let index = 0; index < 40; index++) await f.call(handle, `${batch}-${index}`);
    await sleep(170);
  }
  assert.equal(f.connection.status, 'ready');
  assert.equal(f.calls(), 400);
});

test('message window limits are validated', async t => {
  for (const limits of [{ messageWindowMs: 0 }, { messageWindowMs: 600_001 }, { messageWindowMs: 1.5 }]) {
    await assert.rejects(fixture(t, { limits }), { code: 'INVALID_CONFIGURATION' }, JSON.stringify(limits));
  }
});
