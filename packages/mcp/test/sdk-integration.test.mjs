import test from 'node:test';
import assert from 'node:assert/strict';
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { AgentGuard, GuardError } from '@shieldaai/agent-guard';
import { registerMcpTool } from '../dist/index.js';

const inputSchema = { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false };
const publicResult = { content: [{ type: 'text', text: 'Public report' }] };
const plain = value => JSON.parse(JSON.stringify(value));
const isCode = expected => error => {
  assert.ok(error instanceof GuardError);
  assert.equal(error.code, expected);
  assert.equal(error.message, expected);
  return true;
};
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

// Both endpoints run the official SDK. Only the transport's send method is observed;
// requests still pass through its linked transport, protocol handlers and schemas.
async function fixture(t, { handler = () => publicResult, registration = {}, budget = {} } = {}) {
  const wireCalls = []; const effects = [];
  const server = new McpServer({ name: 'documents', version: '1.0.0' });
  const serverTool = server.registerTool('read', {
    description: 'Read a report', inputSchema: fromJsonSchema(inputSchema),
    annotations: { readOnlyHint: true }, _meta: { 'test/revision': 1 },
  }, async (args, context) => {
    effects.push(plain(args));
    return handler(args, context);
  });
  const client = new Client({ name: 'guard-integration', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) => {
    if (message.method === 'tools/call') wireCalls.push(plain(message.params));
    return send(message, options);
  };
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const guard = new AgentGuard();
  const bridge = { callTool: (request, { signal }) => client.callTool(request, { signal }) };
  async function register() {
    const listed = await client.listTools();
    assert.equal(listed.tools.length, 1);
    return registerMcpTool(guard, {
      serverId: 'documents', tool: listed.tools[0], client: bridge,
      resolve: args => {
        if (typeof args.id !== 'string') throw new TypeError('Expected a report ID');
        return { resourceId: args.id, tenantId: args.id === 'foreign-report' ? 'other' : 'acme' };
      },
      ...registration,
    });
  }
  const tool = await register();
  const task = guard.createTask({
    id: 'task', principalId: 'operator', tenantId: 'acme',
    grants: [{ tool: tool.name, resources: ['report', 'foreign-report'] }],
    budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000, ...budget },
  });
  const prepare = (id = 'report') => guard.prepare(task, { tool: tool.name, args: { id } });
  const approve = () => guard.approveTool(tool.name, tool.fingerprint);
  return { guard, task, tool, prepare, approve, register, client, server, serverTool, wireCalls, effects };
}

test('SDK tools/list registration and both approvals gate actual tools/call dispatch', { timeout: 5_000 }, async t => {
  const f = await fixture(t, { registration: { requiresApproval: true } });
  await assert.rejects(f.prepare(), isCode('TOOL_UNAPPROVED'));
  f.approve();
  await assert.rejects(f.prepare('ungranted-report'), isCode('GRANT_DENIED'));
  await assert.rejects(f.prepare('foreign-report'), isCode('TENANT_DENIED'));
  const prepared = await f.prepare();
  await assert.rejects(f.guard.execute(prepared), isCode('APPROVAL_REQUIRED'));
  assert.equal(f.wireCalls.length, 0);
  assert.equal(f.effects.length, 0);
  assert.equal(f.guard.snapshot(f.task).calls, 0);

  const approvalId = f.guard.approve(prepared, { approverId: 'reviewer', expiresAt: Date.now() + 30_000 });
  assert.deepEqual(plain(await f.guard.execute(prepared, { approvalId })), publicResult);
  assert.deepEqual(f.wireCalls.map(({ name, arguments: args }) => ({ name, arguments: args })), [
    { name: 'read', arguments: { id: 'report' } },
  ]);
  assert.deepEqual(f.effects, [{ id: 'report' }]);
  await assert.rejects(f.guard.execute(prepared, { approvalId }), isCode('ACTION_USED'));
  assert.equal(f.effects.length, 1);
});

test('SDK metadata refresh invalidates prepared calls and requires a new fingerprint approval', { timeout: 10_000 }, async t => {
  for (const [field, updates] of [
    ['description', { description: 'Export a report' }],
    ['annotations', { annotations: { destructiveHint: true } }],
    ['input schema', { paramsSchema: fromJsonSchema({ ...inputSchema, properties: { id: { type: 'string', minLength: 2 } } }) }],
    ['output schema', { outputSchema: fromJsonSchema({ type: 'object', properties: { status: { type: 'string' } } }) }],
    ['custom metadata', { _meta: { 'test/revision': 2 } }],
  ]) await t.test(field, async t => {
    const f = await fixture(t);
    f.approve();
    const prepared = await f.prepare();
    f.serverTool.update(updates);
    const replacement = await f.register();
    assert.notEqual(replacement.fingerprint, f.tool.fingerprint);
    await assert.rejects(f.guard.execute(prepared), isCode('TOOL_CHANGED'));
    await assert.rejects(f.prepare(), isCode('TOOL_UNAPPROVED'));
    assert.throws(() => f.guard.approveTool(replacement.name, f.tool.fingerprint), isCode('TOOL_CHANGED'));
    assert.equal(f.wireCalls.length, 0);
    assert.equal(f.effects.length, 0);
    f.guard.approveTool(replacement.name, replacement.fingerprint);
    assert.equal((await f.prepare()).action.toolFingerprint, replacement.fingerprint);
  });
});

test('SDK re-registration with unchanged metadata still invalidates earlier prepared calls', { timeout: 5_000 }, async t => {
  const f = await fixture(t);
  f.approve();
  const prepared = await f.prepare();
  const replacement = await f.register();
  assert.equal(replacement.fingerprint, f.tool.fingerprint);
  await assert.rejects(f.guard.execute(prepared), isCode('TOOL_CHANGED'));
  await assert.rejects(f.prepare(), isCode('TOOL_UNAPPROVED'));
  f.guard.approveTool(replacement.name, replacement.fingerprint);
  await f.guard.execute(await f.prepare());
  assert.equal(f.wireCalls.length, 1);
  assert.equal(f.effects.length, 1);
});

test('SDK cancellation reaches the server handler and failed calls retain the full reservation', { timeout: 5_000 }, async t => {
  const entered = deferred(); const cancelled = deferred();
  const f = await fixture(t, {
    registration: { maxCost: 4 }, budget: { maxCost: 4 },
    handler: (_args, { mcpReq: { signal } }) => new Promise(resolve => {
      signal.addEventListener('abort', () => {
        cancelled.resolve(signal.aborted);
        resolve(publicResult);
      }, { once: true });
      entered.resolve();
    }),
  });
  f.approve();
  const prepared = await f.prepare();
  const pending = f.guard.execute(prepared);
  const rejected = assert.rejects(pending, isCode('EXECUTION_ABORTED'));
  await entered.promise;
  assert.equal(f.guard.snapshot(f.task).reserved, 4);
  f.guard.revokeTask(f.task);
  assert.equal(await cancelled.promise, true);
  await rejected;
  assert.equal(f.effects.length, 1);
  assert.equal(f.guard.snapshot(f.task).spent, 4);
  assert.equal(f.guard.snapshot(f.task).reserved, 0);
  assert.equal(f.guard.snapshot(f.task).concurrent, 0);
  await assert.rejects(f.guard.execute(prepared), isCode('ACTION_USED'));
});

test('SDK cancellation settles the client before a server that ignores cancellation finishes', { timeout: 5_000 }, async t => {
  const entered = deferred(); const release = deferred(); const finished = deferred();
  let serverFinished = false;
  const f = await fixture(t, {
    handler: async () => {
      entered.resolve();
      await release.promise;
      serverFinished = true;
      finished.resolve();
      return publicResult;
    },
  });
  f.approve();
  const pending = f.guard.execute(await f.prepare());
  const rejected = assert.rejects(pending, isCode('EXECUTION_ABORTED'));
  try {
    await entered.promise;
    f.guard.revokeTask(f.task);
    await rejected;
    assert.equal(f.guard.snapshot(f.task).concurrent, 0);
    assert.equal(serverFinished, false);
  } finally {
    release.resolve();
    await finished.promise;
  }
  assert.equal(serverFinished, true);
  assert.equal(f.effects.length, 1);
});

test('SDK tool-level error results preserve isError and remain charged', { timeout: 5_000 }, async t => {
  const f = await fixture(t, {
    handler: () => { throw new Error('Fixture report unavailable'); },
    registration: { maxCost: 3 }, budget: { maxCost: 3 },
  });
  f.approve();
  const result = await f.guard.execute(await f.prepare());
  assert.equal(result.isError, true);
  assert.equal(result.content[0].type, 'text');
  assert.equal(f.effects.length, 1);
  assert.equal(f.guard.snapshot(f.task).spent, 3);
  await assert.rejects(f.prepare(), isCode('COST_BUDGET_EXCEEDED'));
});

test('SDK protocol failures are redacted, charged and never retried', { timeout: 5_000 }, async t => {
  const f = await fixture(t, { registration: { maxCost: 3 }, budget: { maxCost: 3 } });
  f.server.server.setRequestHandler('tools/call', async () => { throw new Error('private provider detail'); });
  f.approve();
  const prepared = await f.prepare();
  await assert.rejects(f.guard.execute(prepared), isCode('TOOL_FAILED'));
  await assert.rejects(f.guard.execute(prepared), isCode('ACTION_USED'));
  assert.equal(f.wireCalls.length, 1);
  assert.equal(f.effects.length, 0);
  assert.equal(f.guard.snapshot(f.task).spent, 3);
  assert.equal(f.guard.snapshot(f.task).reserved, 0);
  assert.equal(f.guard.snapshot(f.task).concurrent, 0);
});

test('SDK measured cost settles the reservation and the remaining budget blocks dispatch', { timeout: 5_000 }, async t => {
  const entered = deferred(); const release = deferred(); let measured = 0;
  const f = await fixture(t, {
    handler: async () => { entered.resolve(); await release.promise; return { ...publicResult, _meta: { fixtureUsage: 2 } }; },
    registration: { maxCost: 5, measureCost: result => { measured++; return result._meta.fixtureUsage; } },
    budget: { maxCost: 6 },
  });
  f.approve();
  const prepared = await f.prepare();
  const pending = f.guard.execute(prepared);
  await entered.promise;
  assert.equal(f.guard.snapshot(f.task).reserved, 5);
  assert.equal(measured, 0);
  release.resolve();
  await pending;
  assert.equal(measured, 1);
  assert.equal(f.guard.snapshot(f.task).spent, 2);
  assert.equal(f.guard.snapshot(f.task).reserved, 0);
  await assert.rejects(f.prepare(), isCode('COST_BUDGET_EXCEEDED'));
  assert.equal(f.wireCalls.length, 1);
  assert.equal(f.effects.length, 1);
});

test('SDK invalid measured cost revokes the task and retains the declared upper bound', { timeout: 5_000 }, async t => {
  const f = await fixture(t, {
    registration: { maxCost: 2, measureCost: () => 3 }, budget: { maxCost: 10 },
  });
  f.approve();
  await assert.rejects(f.guard.execute(await f.prepare()), isCode('COST_REPORT_INVALID'));
  await assert.rejects(f.prepare(), isCode('TASK_REVOKED'));
  assert.equal(f.guard.snapshot(f.task).spent, 2);
  assert.equal(f.guard.snapshot(f.task).reserved, 0);
  assert.equal(f.effects.length, 1);
});

test('SDK cost extractor failure remains charged and cannot leak its exception', { timeout: 5_000 }, async t => {
  const f = await fixture(t, {
    registration: { maxCost: 2, measureCost: () => { throw new Error('private billing detail'); } }, budget: { maxCost: 2 },
  });
  f.approve();
  await assert.rejects(f.guard.execute(await f.prepare()), isCode('TOOL_FAILED'));
  assert.equal(f.guard.snapshot(f.task).spent, 2);
  assert.equal(f.guard.snapshot(f.task).reserved, 0);
  assert.equal(f.effects.length, 1);
});
