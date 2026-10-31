import test from 'node:test';
import assert from 'node:assert/strict';
import { DurableExecutor, ExecutorClient, startExecutorServer, createModelTool, createExecutorModelProvider } from '../dist/index.js';

test('provider requests use authenticated executor admission and sensitive families cannot call an external model', async t => {
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: Buffer.alloc(32) });
  let providerCalls = 0;
  const definition = createModelTool({ name: 'model.complete', model: 'fixture', tenantId: 'tenant', recipient: 'provider', maxCost: 5, maxOutputTokens: 10,
    complete: async (prompt, options) => { providerCalls++; assert.equal(options.maxOutputTokens, 10); return { response: { text: `accepted:${prompt}`, inputTokens: 1, outputTokens: 2 }, actualCost: 3 }; } });
  executor.approveTool(definition.name, executor.registerTool(definition));
  const options = { id: 'task', tenantId: 'tenant', principalId: 'host', grants: [{ tool: definition.name, resources: ['fixture'] }],
    allowedRecipients: ['provider'], budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 8, deadline: Date.now() + 60_000 } };
  const credential = executor.createTask(options);
  const server = await startExecutorServer({ executor, adminToken: 'A'.repeat(43), operatorId: 'operator' });
  t.after(async () => { await server.close(); executor.close(); });
  const provider = createExecutorModelProvider({ client: new ExecutorClient({ endpoint: server.url, token: credential.token }), tool: definition.name, model: 'fixture', maxOutputTokens: 10 });
  assert.equal((await provider.complete('hello')).text, 'accepted:hello');
  assert.deepEqual(await Array.fromAsync(provider.stream('world')), ['accepted:world']);
  await assert.rejects(provider.complete('over budget')); assert.equal(providerCalls, 2);
  assert.equal(executor.snapshot('task').spent, 6);
  executor.createTask({ ...options, id: 'sensitive' }, { sensitive: true });
  await assert.rejects(executor.prepare('sensitive', { tool: definition.name, args: { prompt: 'private', maxOutputTokens: 10 } }), { code: 'SENSITIVE_EGRESS_DENIED' });
  assert.equal(providerCalls, 2);
});

test('cancellation during asynchronous policy prevents admission and later replay', async t => {
  let unblock; let entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  let hold = false; let effects = 0;
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: Buffer.alloc(32), policy: async () => {
    if (hold) { entered(); await new Promise(resolve => { unblock = resolve; }); } return 'allow';
  } }); t.after(() => executor.close());
  const fp = executor.registerTool({ name: 'work', description: 'work', resolve: () => ({ resourceId: 'item', tenantId: 'tenant' }), execute: () => { effects++; return { value: true }; } });
  executor.approveTool('work', fp);
  executor.createTask({ id: 'task', principalId: 'host', tenantId: 'tenant', grants: [{ tool: 'work', resources: ['item'] }], budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
  const action = await executor.prepare('task', { tool: 'work', args: null });
  hold = true; const pending = executor.execute('task', action.id); await waiting;
  executor.cancel('task', action.id); unblock(); await assert.rejects(pending);
  await assert.rejects(executor.execute('task', action.id), { code: 'ACTION_USED' });
  assert.equal(effects, 0); assert.equal(executor.snapshot('task').calls, 0);
});
