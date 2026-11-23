import assert from 'node:assert/strict';
import test from 'node:test';
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import {
  aiSdkTools,
  createDispatcher,
  langChainTools,
  mcpServerTools,
  openAIAgentsTools,
  registerMcpServerTools,
  toolSpecs,
} from '../dist/index.js';
import { plain, ticketDesk, ticketSchema } from './helpers.mjs';

function setup() {
  const desk = ticketDesk();
  return { desk, dispatch: createDispatcher(desk), specs: toolSpecs(desk.guard, ['ticket.read']) };
}

test('framework adapters require the framework factory', () => {
  const { dispatch, specs } = setup();
  assert.throws(() => aiSdkTools(dispatch, specs, {}), { code: 'FACTORY_REQUIRED' });
  assert.throws(() => openAIAgentsTools(dispatch, specs, {}), { code: 'FACTORY_REQUIRED' });
  assert.throws(() => langChainTools(dispatch, specs), { code: 'FACTORY_REQUIRED' });
  assert.throws(() => registerMcpServerTools({ registerTool() {} }, dispatch, specs, {}), { code: 'FACTORY_REQUIRED' });
});

test('Vercel AI SDK: tools whose execute goes through the guard', async () => {
  const { dispatch, specs, desk } = setup();
  const wrapped = [];
  const jsonSchema = schema => {
    wrapped.push(schema);
    return { jsonSchema: schema };
  };
  const tools = aiSdkTools(dispatch, specs, { jsonSchema });
  assert.deepEqual(Object.keys(tools), ['ticket.read']);
  assert.deepEqual(plain(wrapped), [ticketSchema]);
  assert.equal(tools['ticket.read'].description, 'Read one support ticket');
  const ok = await tools['ticket.read'].execute(
    { id: '42' },
    { toolCallId: 'c1', abortSignal: new AbortController().signal },
  );
  assert.equal(ok.status, 'ok');
  const denied = await tools['ticket.read'].execute({ id: '7' }, { toolCallId: 'c2' });
  assert.equal(denied.code, 'GRANT_DENIED');
  assert.deepEqual(desk.runs, [['ticket.read', '42']]);
});

test('Vercel AI SDK: a tool named __proto__ is an ordinary key', async () => {
  const specs = [{ name: '__proto__', description: 'Odd name', inputSchema: { type: 'object' } }];
  const calls = [];
  const tools = aiSdkTools(
    async call => (calls.push(call.name), { status: 'ok', tool: call.name, actionId: 'a', result: 1 }),
    specs,
    {
      jsonSchema: schema => schema,
    },
  );
  assert.deepEqual(Object.keys(tools), ['__proto__']);
  assert.equal(Object.getPrototypeOf(tools), Object.prototype);
  assert.equal((await Object.getOwnPropertyDescriptor(tools, '__proto__').value.execute({})).status, 'ok');
  assert.deepEqual(calls, ['__proto__']);
});

test('OpenAI Agents SDK: tool configs with non-strict JSON Schema and string results', async () => {
  const { dispatch, specs } = setup();
  const configs = openAIAgentsTools(dispatch, specs, { tool: config => config });
  assert.equal(configs[0].name, 'ticket.read');
  assert.equal(configs[0].strict, false);
  assert.deepEqual(plain(configs[0].parameters), ticketSchema);
  assert.equal(JSON.parse(await configs[0].execute({ id: '42' })).status, 'ok');
  assert.equal(JSON.parse(await configs[0].execute('{"id":"7"}')).code, 'GRANT_DENIED');
  assert.equal(JSON.parse(await configs[0].execute('{"id":')).code, 'INPUT_NOT_JSON');
});

test('LangChain.js: tool functions and fields', async () => {
  const { dispatch, specs } = setup();
  const made = langChainTools(dispatch, specs, { tool: (func, fields) => ({ func, fields }) });
  assert.deepEqual(plain(made[0].fields), {
    name: 'ticket.read',
    description: 'Read one support ticket',
    schema: ticketSchema,
  });
  assert.equal(JSON.parse(await made[0].func({ id: '42' }, { signal: new AbortController().signal })).status, 'ok');
  assert.equal(JSON.parse(await made[0].func({ id: '7' })).code, 'GRANT_DENIED');
});

test('MCP server handlers: list and call, with isError on denial', async () => {
  const { dispatch, specs } = setup();
  const server = mcpServerTools(dispatch, specs);
  assert.deepEqual(plain(server.listTools()), {
    tools: [{ name: 'ticket.read', description: 'Read one support ticket', inputSchema: ticketSchema }],
  });
  const ok = await server.callTool({ name: 'ticket.read', arguments: { id: '42' } });
  assert.equal(ok.isError, false);
  assert.equal(ok.structuredContent.status, 'ok');
  const unknown = await server.callTool({ name: 'shell.exec', arguments: {} });
  assert.equal(unknown.isError, true);
  assert.equal(JSON.parse(unknown.content[0].text).code, 'TOOL_UNKNOWN');
  await assert.rejects(server.callTool(null), { code: 'INVALID_TOOL_CALL' });
});

test('a real MCP client calls guarded tools on a real MCP SDK server', async t => {
  const { dispatch, specs, desk } = setup();
  const server = new McpServer({ name: 'guarded-tickets', version: '1.0.0' });
  registerMcpServerTools(server, dispatch, specs, { fromJsonSchema });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'adapter-test', version: '1.0.0' });
  await client.connect(clientTransport);
  t.after(async () => {
    await client.close();
    await server.close();
  });
  const listed = await client.listTools();
  assert.deepEqual(
    listed.tools.map(tool => [tool.name, tool.description]),
    [['ticket.read', 'Read one support ticket']],
  );
  assert.deepEqual(listed.tools[0].inputSchema.required, ['id']);
  const ok = await client.callTool({ name: 'ticket.read', arguments: { id: '42' } });
  assert.notEqual(ok.isError, true);
  assert.equal(JSON.parse(ok.content[0].text).result.subject, 'Refund not received');
  const denied = await client.callTool({ name: 'ticket.read', arguments: { id: '7' } });
  assert.equal(denied.isError, true);
  assert.equal(JSON.parse(denied.content[0].text).code, 'GRANT_DENIED');
  assert.deepEqual(desk.runs, [['ticket.read', '42']]);
});

test('frameworks get their own unfrozen copy of each schema (LangChain writes into it)', async () => {
  const { dispatch, specs } = setup();
  assert.ok(Object.isFrozen(specs[0].inputSchema), 'the spec itself stays frozen');
  const writable = schema => {
    assert.ok(!Object.isFrozen(schema));
    schema.__absolute_uri__ = 'x';
    return schema;
  };
  aiSdkTools(dispatch, specs, { jsonSchema: writable });
  openAIAgentsTools(dispatch, specs, { tool: config => writable(config.parameters) });
  langChainTools(dispatch, specs, { tool: (func, fields) => writable(fields.schema) });
  writable(mcpServerTools(dispatch, specs).listTools().tools[0].inputSchema);
  assert.equal(specs[0].inputSchema.__absolute_uri__, undefined);
});

test('framework tools never throw host errors into the framework (which would show them to the model)', async () => {
  const backend = {
    prepare: async () => Promise.reject(new TypeError('fetch failed: connect ECONNREFUSED 10.0.0.5:8443')),
    execute: async () => null,
  };
  const dispatch = createDispatcher(backend, { onHostError: () => {} });
  const throwing = async () => {
    throw new Error('internal detail 10.0.0.5');
  };
  const specs = [{ name: 't', description: 't', inputSchema: { type: 'object' } }];
  for (const d of [dispatch, throwing]) {
    const outputs = [
      JSON.stringify(await aiSdkTools(d, specs, { jsonSchema: s => s }).t.execute({})),
      await openAIAgentsTools(d, specs, { tool: c => c })[0].execute({}),
      await langChainTools(d, specs, { tool: f => f })[0]({}),
      JSON.stringify(await mcpServerTools(d, specs).callTool({ name: 't', arguments: {} })),
    ];
    for (const text of outputs) {
      assert.match(text, /HOST_ERROR/);
      assert.doesNotMatch(text, /10\.0\.0\.5|ECONNREFUSED|internal detail/);
    }
  }
});
