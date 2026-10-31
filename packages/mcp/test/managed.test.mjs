import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection, compileBoundedSchema } from '../dist/index.js';

const schema = { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false };
const result = { content: [{ type: 'text', text: 'public' }] };
const binding = { name: 'read', resolve: args => ({ resourceId: args.id, tenantId: 'acme' }) };
const identity = { serverId: 'documents', transportIdentity: 'isolated-executor:documents-v1', tenantId: 'acme', principalId: 'operator' };
function task(guard, name, overrides = {}) {
  return guard.createTask({ id: crypto.randomUUID(), principalId: 'operator', tenantId: 'acme', grants: [{ tool: name, resources: ['report'] }],
    budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000 }, ...overrides });
}
async function fixture(t, options = {}) {
  const effects = []; const wire = [];
  const server = new McpServer({ name: 'documents', version: '1' });
  const serverTool = server.registerTool('read', { description: 'Read a report', inputSchema: fromJsonSchema(schema) }, async args => {
    effects.push(args); return options.handler ? options.handler(args) : result;
  });
  options.setup?.(server);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const originalSend = clientTransport.send.bind(clientTransport);
  clientTransport.send = async (message, sendOptions) => { wire.push(message); return originalSend(message, sendOptions); };
  await server.connect(serverTransport);
  const guard = options.guard ?? new AgentGuard();
  let connection;
  t.after(async () => { await connection?.close(); await server.close(); });
  connection = await ManagedMcpConnection.connect({ guard, identity, transport: clientTransport, tools: [binding], ...options.connection });
  const registered = connection.registrations[0];
  const handle = task(guard, registered.name);
  const approve = () => guard.approveTool(connection.registrations[0].name, connection.registrations[0].fingerprint);
  const prepare = (args = { id: 'report' }) => guard.prepare(handle, { tool: registered.name, args });
  return { guard, connection, server, serverTool, clientTransport, serverTransport, effects, wire, registered, handle, approve, prepare };
}

test('managed SDK connection requires approval, validates arguments, and dispatches a permitted call', { timeout: 5_000 }, async t => {
  const f = await fixture(t);
  assert.equal(f.connection.status, 'ready');
  await assert.rejects(f.prepare(), { code: 'TOOL_UNAPPROVED' });
  f.approve();
  await assert.rejects(f.prepare({ id: 'report', injected: true }));
  assert.equal(f.effects.length, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(await f.guard.execute(await f.prepare()))), result);
  assert.equal(f.effects.length, 1);
  assert.equal(f.wire.filter(message => message.method === 'tools/call').length, 1);
});

test('metadata notification quarantines immediately and explicit refresh needs fresh approval', { timeout: 5_000 }, async t => {
  const f = await fixture(t); f.approve(); const prepared = await f.prepare();
  await f.serverTransport.send({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  assert.equal(f.connection.status, 'quarantined');
  await assert.rejects(f.guard.execute(prepared));
  assert.equal(f.effects.length, 0);
  const oldFingerprint = f.registered.fingerprint;
  await f.connection.refresh();
  assert.notEqual(f.connection.registrations[0].fingerprint, oldFingerprint);
  await assert.rejects(f.prepare(), { code: 'TOOL_UNAPPROVED' });
  f.approve(); await f.guard.execute(await f.prepare());
  assert.equal(f.effects.length, 1);
});

test('closed session and another principal cannot use an approved connection', { timeout: 5_000 }, async t => {
  const f = await fixture(t); f.approve(); const prepared = await f.prepare();
  const other = task(f.guard, f.registered.name, { principalId: 'other' });
  await assert.rejects(f.guard.prepare(other, { tool: f.registered.name, args: { id: 'report' } }));
  await f.connection.close();
  await assert.rejects(f.guard.execute(prepared));
  assert.equal(f.effects.length, 0);
});

test('bounded schema accepts local references and rejects external, recursive and regex schemas', () => {
  const valid = compileBoundedSchema({ type: 'object', properties: { id: { $ref: '#/$defs/id' } }, required: ['id'], $defs: { id: { type: 'string', minLength: 1 } } });
  assert.equal(valid({ id: 'report' }), true); assert.equal(valid({ id: 1 }), false);
  for (const unsafe of [
    { $ref: 'https://127.0.0.1/schema' }, { $ref: 'file:///etc/passwd' },
    { $id: 'https://example.com/', type: 'string' }, { $dynamicRef: '#x' },
    { type: 'string', pattern: '(a+)+$' }, { $defs: { loop: { $ref: '#/$defs/loop' } }, $ref: '#/$defs/loop' },
  ]) assert.throws(() => compileBoundedSchema(unsafe));
});

test('unknown server requests get errors, with no advertised sampling, elicitation or roots', { timeout: 5_000 }, async t => {
  const f = await fixture(t);
  const initialization = f.wire.find(message => message.method === 'initialize');
  assert.deepEqual(Object.keys(initialization.params.capabilities), []);
  const methods = ['unknown/dangerous', 'roots/list', 'sampling/createMessage', 'elicitation/create'];
  for (const [index, method] of methods.entries()) await f.serverTransport.send({ jsonrpc: '2.0', id: 987 + index, method, params: {} });
  await new Promise(resolve => setImmediate(resolve));
  for (let index = 0; index < methods.length; index++) assert.ok(f.wire.find(message => message.id === 987 + index).error);
  assert.equal(f.effects.length, 0);
});

test('a metadata change during an in-flight call discards its result and requires review', { timeout: 5_000 }, async t => {
  let release; const paused = new Promise(resolve => { release = resolve; });
  let entered; const started = new Promise(resolve => { entered = resolve; });
  const f = await fixture(t, { handler: async () => { entered(); await paused; return result; } });
  f.approve(); const pending = f.guard.execute(await f.prepare()); const rejected = assert.rejects(pending);
  await started;
  await f.serverTransport.send({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  release(); await rejected;
  assert.equal(f.connection.status, 'quarantined');
  assert.equal(f.effects.length, 1); // Authorization cannot undo a remote side effect already in progress.
});

test('resources and prompts need explicit bindings, exact resource identity, schema and guard grants', { timeout: 5_000 }, async t => {
  const reads = []; const prompts = [];
  const setup = server => {
    server.registerResource('public-report', 'report://public', { mimeType: 'text/plain' }, uri => { reads.push(uri.href); return { contents: [{ uri: uri.href, text: 'public' }] }; });
    server.registerPrompt('summary', { argsSchema: fromJsonSchema({ type: 'object', properties: { topic: { type: 'string' } }, required: ['topic'] }) }, args => { prompts.push(args); return { messages: [{ role: 'user', content: { type: 'text', text: args.topic } }] }; });
  };
  const omitted = await fixture(t, { setup });
  assert.equal(omitted.connection.registrations.length, 1);
  assert.equal(omitted.wire.some(message => message.method === 'resources/list' || message.method === 'prompts/list'), false);
  const f = await fixture(t, { setup, connection: {
    resources: [{ name: 'report', uri: 'report://public', resolve: () => ({ resourceId: 'report', tenantId: 'acme' }) }],
    prompts: [{ name: 'summary', resolve: () => ({ resourceId: 'report', tenantId: 'acme' }) }],
  } });
  for (const registration of f.connection.registrations.filter(item => item.kind !== 'tool')) {
    f.guard.approveTool(registration.name, registration.fingerprint);
    const handle = task(f.guard, registration.name);
    const args = registration.kind === 'prompt' ? { topic: 'report' } : {};
    await assert.rejects(f.guard.prepare(handle, { tool: registration.name, args: { ...args, uri: 'file:///etc/passwd' } }));
    await f.guard.execute(await f.guard.prepare(handle, { tool: registration.name, args }));
  }
  assert.deepEqual(reads, ['report://public']); assert.equal(prompts.length, 1);
});

test('unsafe schemas are rejected at discovery before any tool side effect', { timeout: 5_000 }, async t => {
  const server = new McpServer({ name: 'unsafe', version: '1' });
  server.registerTool('read', { inputSchema: fromJsonSchema(schema) }, () => result);
  server.server.setRequestHandler('tools/list', () => ({ tools: [{ name: 'read', inputSchema: { type: 'object' }, outputSchema: { $ref: 'file:///etc/passwd' } }] }));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair(); await server.connect(serverTransport);
  t.after(() => server.close());
  await assert.rejects(ManagedMcpConnection.connect({ guard: new AgentGuard(), identity, transport: clientTransport, tools: [binding] }), { code: 'CONNECTION_FAILED' });
});

test('active widget content is rejected and quarantines the connection', { timeout: 5_000 }, async t => {
  const f = await fixture(t, { handler: () => ({ content: [{ type: 'resource', resource: { uri: 'ui://widget', mimeType: 'text/html', text: '<script>attack()</script>' } }] }) });
  f.approve(); await assert.rejects(f.guard.execute(await f.prepare()));
  assert.equal(f.connection.status, 'quarantined');
});

test('registry and incoming-message budgets fail closed', { timeout: 5_000 }, async t => {
  const f = await fixture(t, { connection: { limits: { maxMessages: 3 } } });
  await f.serverTransport.send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'first' } });
  await f.serverTransport.send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'over budget' } });
  assert.equal(f.connection.status, 'closed');
  assert.equal(f.effects.length, 0);
});

test('a discovery response racing a metadata notification cannot publish a stale registry', { timeout: 5_000 }, async t => {
  const f = await fixture(t); f.approve(); const prepared = await f.prepare();
  let release; const hold = new Promise(resolve => { release = resolve; });
  let entered; const started = new Promise(resolve => { entered = resolve; });
  f.server.server.setRequestHandler('tools/list', async () => { entered(); await hold; return { tools: [f.registered.descriptor] }; });
  const refreshing = f.connection.refresh(); const rejected = assert.rejects(refreshing, { code: 'REGISTRY_REJECTED' });
  await started;
  await f.serverTransport.send({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' });
  release(); await rejected;
  assert.equal(f.connection.status, 'quarantined'); assert.equal(f.connection.registrations.length, 0);
  await assert.rejects(f.guard.execute(prepared)); assert.equal(f.effects.length, 0);
});

test('new connection cannot inherit the prior session fingerprint or prepared action', { timeout: 5_000 }, async t => {
  const previous = await fixture(t); previous.approve(); const prepared = await previous.prepare();
  await previous.connection.close();
  const next = await fixture(t, { guard: previous.guard });
  assert.notEqual(next.connection.sessionId, previous.connection.sessionId);
  assert.notEqual(next.registered.fingerprint, previous.registered.fingerprint);
  assert.throws(() => next.guard.approveTool(next.registered.name, previous.registered.fingerprint));
  await assert.rejects(next.guard.execute(prepared));
  next.approve(); await next.guard.execute(await next.prepare());
  assert.equal(previous.effects.length, 0); assert.equal(next.effects.length, 1);
});

test('removed tools stay unavailable after refresh', { timeout: 5_000 }, async t => {
  const f = await fixture(t); f.approve();
  f.server.server.setRequestHandler('tools/list', () => ({ tools: [] }));
  await f.connection.refresh();
  assert.equal(f.connection.registrations.length, 0);
  await assert.rejects(f.prepare()); assert.equal(f.effects.length, 0);
});

test('discovery entry cap rejects an oversized catalog', { timeout: 5_000 }, async t => {
  await assert.rejects(fixture(t, {
    setup: server => server.registerTool('other', { inputSchema: fromJsonSchema({ type: 'object' }) }, () => result),
    connection: { limits: { maxEntries: 1 } },
  }), { code: 'CONNECTION_FAILED' });
});

test('authorization revoked after preparation blocks actual SDK dispatch', { timeout: 5_000 }, async t => {
  let authorized = true;
  const f = await fixture(t, { connection: { authorize: () => { if (!authorized) throw new Error('private issuer details'); } } });
  f.approve(); const prepared = await f.prepare(); authorized = false;
  await assert.rejects(f.guard.execute(prepared));
  assert.equal(f.connection.status, 'quarantined'); assert.equal(f.effects.length, 0);
  assert.equal(f.wire.filter(message => message.method === 'tools/call').length, 0);
});
