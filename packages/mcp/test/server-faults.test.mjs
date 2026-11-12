import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection } from '../dist/index.js';

const MIB = 1_048_576;
const identity = {
  serverId: 'documents',
  transportIdentity: 'isolated-executor:documents-v1',
  tenantId: 'acme',
  principalId: 'operator',
};
const inputSchema = {
  type: 'object',
  properties: { size: { type: 'integer' }, kind: { type: 'string' }, pad: { type: 'string' } },
  required: ['size'],
  additionalProperties: false,
};
const readBinding = { name: 'read', resolve: () => ({ resourceId: 'report', tenantId: 'acme' }) };

/**
 * A hand-written server on an in-memory transport, so a test controls every byte the
 * server advertises and returns, including names and results an SDK server would refuse.
 */
function rawServer({ tools = [], prompts = [], call } = {}) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const state = { tools, prompts, call };
  const reply = (id, result) => serverTransport.send({ jsonrpc: '2.0', id, result }).catch(() => {});
  serverTransport.onmessage = message => {
    if (message.id === undefined) return;
    if (message.method === 'initialize')
      return reply(message.id, {
        protocolVersion: message.params.protocolVersion,
        capabilities: { tools: {}, prompts: {} },
        serverInfo: { name: 'raw', version: '1' },
      });
    if (message.method === 'tools/list') return reply(message.id, { tools: state.tools });
    if (message.method === 'prompts/list') return reply(message.id, { prompts: state.prompts });
    if (message.method === 'tools/call') return reply(message.id, state.call(message.params.arguments));
    return reply(message.id, {});
  };
  void serverTransport.start();
  return { clientTransport, serverTransport, state };
}
async function connect(t, server, options = {}) {
  const guard = new AgentGuard(options.guardOptions);
  const connection = await ManagedMcpConnection.connect({
    guard,
    identity,
    transport: server.clientTransport,
    tools: [readBinding],
    ...options.connection,
  });
  t.after(() => connection.close());
  return { guard, connection };
}
/** Approves the one registered tool and returns a function that calls it. */
function caller({ guard, connection }) {
  const [registration] = connection.registrations;
  guard.approveTool(registration.name, registration.fingerprint);
  const task = guard.createTask({
    id: crypto.randomUUID(),
    principalId: 'operator',
    tenantId: 'acme',
    grants: [{ tool: registration.name, resources: ['report'] }],
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  return async args => guard.execute(await guard.prepare(task, { tool: registration.name, args }));
}

test('a raised maxMessageBytes applies to a structured result checked against an output schema', async t => {
  const outputSchema = {
    type: 'object',
    properties: { text: { type: 'string' }, kind: { const: 'report' } },
    required: ['text', 'kind'],
  };
  const structured = args => ({
    content: [{ type: 'text', text: 'ok' }],
    structuredContent: { text: 'x'.repeat(args.size), kind: args.kind ?? 'report' },
  });
  const tools = [{ name: 'read', inputSchema, outputSchema }];
  const raised = await connect(t, rawServer({ tools, call: structured }), {
    guardOptions: { limits: { maxJsonBytes: 4 * MIB } },
    connection: { limits: { maxMessageBytes: 4 * MIB } },
  });
  const read = caller(raised);
  assert.equal((await read({ size: 3 * MIB })).structuredContent.text.length, 3 * MIB);
  // The output schema is still enforced on a large result, and the raised limit is still a limit.
  await assert.rejects(read({ size: 3 * MIB, kind: 'other' }), { code: 'TOOL_FAILED', detail: 'MCP_OPERATION_FAILED' });
  await assert.rejects(read({ size: 4 * MIB }), { code: 'TOOL_FAILED', detail: 'MCP_OPERATION_FAILED' });
  // Arguments keep their own 1 MiB limit.
  await assert.rejects(read({ size: 1, pad: 'x'.repeat(MIB) }), {
    code: 'RESOLUTION_FAILED',
    detail: 'ARGUMENTS_INVALID',
  });
  assert.equal(raised.connection.status, 'ready');

  const standard = await connect(t, rawServer({ tools, call: structured }));
  const readStandard = caller(standard);
  assert.equal((await readStandard({ size: MIB / 2 })).structuredContent.text.length, MIB / 2);
  await assert.rejects(readStandard({ size: MIB }), { code: 'TOOL_FAILED', detail: 'MCP_OPERATION_FAILED' });
});

test('a malformed name the server advertises is reported as a server fault, never as INVALID_CONFIGURATION', async t => {
  const read = { name: 'read', inputSchema };
  for (const name of ['bad\ud800', 'bad\0', ' ', '', 'x'.repeat(1025)]) {
    // The malformed tool is not even bound: one bad name refuses the whole registry.
    const server = rawServer({ tools: [read] });
    const { connection } = await connect(t, server);
    server.state.tools = [read, { name, inputSchema }];
    await assert.rejects(connection.refresh(), { code: 'REGISTRY_REJECTED' }, JSON.stringify(name));
    assert.equal(connection.status, 'quarantined');
    assert.equal(connection.failureReason, 'REGISTRY_REJECTED', JSON.stringify(name));
    server.state.tools = [read];
    await connection.refresh();
    assert.equal(connection.failureReason, undefined);
  }

  const prompts = [
    { name: 'summary', arguments: [{ name: 'topic\udc00' }] },
    { name: 'outline', arguments: [{ name: 'topic', required: true }] },
  ];
  const { connection } = await connect(t, rawServer({ prompts }), {
    connection: { tools: [], prompts: ['summary', 'outline'].map(name => ({ ...readBinding, name })) },
  });
  assert.deepEqual(connection.skipped, [{ kind: 'prompt', remoteName: 'summary', reason: 'SCHEMA_INVALID' }]);
  assert.deepEqual(
    connection.registrations.map(registration => registration.remoteName),
    ['outline'],
  );
  assert.equal(connection.failureReason, undefined);
});

test('failureReason is CONNECTION_UNAVAILABLE after the transport closes, and unset after close()', async t => {
  const lost = rawServer({ tools: [{ name: 'read', inputSchema }] });
  const { connection } = await connect(t, lost);
  assert.equal(connection.failureReason, undefined);
  await lost.serverTransport.close();
  for (let i = 0; i < 50 && connection.status !== 'closed'; i++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(connection.status, 'closed');
  assert.equal(connection.failureReason, 'CONNECTION_UNAVAILABLE');
  assert.equal(connection.registrations.length, 0);
  await assert.rejects(connection.refresh(), { code: 'CONNECTION_UNAVAILABLE' });

  const explicit = await connect(t, rawServer({ tools: [{ name: 'read', inputSchema }] }));
  await explicit.connection.close();
  assert.equal(explicit.connection.status, 'closed');
  assert.equal(explicit.connection.failureReason, undefined, 'an explicit close is not a failure');
});

test('an operation name too long for the guard once encoded is refused at construction', async t => {
  const refused = async (label, connection) => {
    const server = rawServer({ tools: [{ name: 'read', inputSchema }] });
    await assert.rejects(
      ManagedMcpConnection.connect({
        guard: new AgentGuard(),
        identity,
        transport: server.clientTransport,
        tools: [readBinding],
        ...connection,
      }),
      { code: 'INVALID_CONFIGURATION' },
      label,
    );
  };
  // Each of these characters is nine characters once URL-encoded.
  const wide = length => '中'.repeat(length);
  await refused('server ID alone', { identity: { ...identity, serverId: wide(500) }, tools: [] });
  await refused('server ID with a tool', { identity: { ...identity, serverId: wide(455) } });
  await refused('tool name', { tools: [{ ...readBinding, name: wide(1024) }] });
  await refused('prompt name', { tools: [], prompts: [{ ...readBinding, name: wide(500) }] });
  await refused('resource name', {
    tools: [],
    resources: [{ ...readBinding, name: wide(500), uri: 'https://example.test/report' }],
  });

  // The longest server ID that still fits registers, and can be observed.
  const serverId = wide(454);
  const { guard, connection } = await connect(t, rawServer({ tools: [{ name: 'read', inputSchema }] }), {
    connection: { identity: { ...identity, serverId } },
  });
  const [registration] = connection.registrations;
  assert.equal(registration.name, `mcp:${encodeURIComponent(serverId)}:read`);
  assert.equal(registration.name.length, 4095);
  assert.doesNotThrow(() => guard.approveTool(registration.name, registration.fingerprint));
  assert.equal(connection.inventory().operations.length, 1);
});
