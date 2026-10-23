import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard } from '@shieldaai/agent-guard';
import { mcpToolName, registerMcpTool } from '../dist/index.js';

function task(guard, name) {
  return guard.createTask({ id: 'task', principalId: 'operator', tenantId: 'a',
    grants: [{ tool: name, resources: ['report'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
}
function registration(effects, overrides = {}) {
  return { serverId: 'documents', tool: { name: 'read', description: 'Read a report', inputSchema: { type: 'object' } },
    client: { async callTool(request, { signal }) { effects.push(request); assert.ok(signal instanceof AbortSignal); return { text: 'public' }; } },
    resolve: (args) => ({ resourceId: args.id, tenantId: 'a' }), ...overrides };
}

test('MCP approval and scoped execution mediate the actual client call', async () => {
  const effects = []; const guard = new AgentGuard();
  const tool = registerMcpTool(guard, registration(effects)); const handle = task(guard, tool.name);
  await assert.rejects(guard.prepare(handle, { tool: tool.name, args: { id: 'report' } }));
  assert.equal(effects.length, 0);
  guard.approveTool(tool.name, tool.fingerprint);
  const prepared = await guard.prepare(handle, { tool: tool.name, args: { id: 'report' } });
  assert.deepEqual(JSON.parse(JSON.stringify(await guard.execute(prepared))), { text: 'public' });
  assert.deepEqual(JSON.parse(JSON.stringify(effects)), [{ name: 'read', arguments: { id: 'report' } }]);
  await assert.rejects(guard.prepare(handle, { tool: tool.name, args: { id: 'other' } }));
  assert.equal(effects.length, 1);
});

test('MCP annotations and schemas change the fingerprint and stop prepared calls', async () => {
  const effects = []; const guard = new AgentGuard(); const config = registration(effects);
  const before = registerMcpTool(guard, config); const handle = task(guard, before.name);
  guard.approveTool(before.name, before.fingerprint);
  const prepared = await guard.prepare(handle, { tool: before.name, args: { id: 'report' } });
  const after = registerMcpTool(guard, { ...config, tool: { ...config.tool, annotations: { destructiveHint: true } } });
  assert.notEqual(before.fingerprint, after.fingerprint);
  await assert.rejects(guard.execute(prepared));
  await assert.rejects(guard.prepare(handle, { tool: after.name, args: { id: 'report' } }));
  assert.equal(effects.length, 0);
  guard.approveTool(after.name, after.fingerprint);
  await guard.execute(await guard.prepare(handle, { tool: after.name, args: { id: 'report' } }));
  assert.equal(effects.length, 1);
});

test('namespaces are unambiguous and scalar arguments never reach MCP', async () => {
  assert.notEqual(mcpToolName('a:b', 'c'), mcpToolName('a', 'b:c'));
  const effects = []; const guard = new AgentGuard(); const tool = registerMcpTool(guard, registration(effects));
  guard.approveTool(tool.name, tool.fingerprint); const handle = task(guard, tool.name);
  await assert.rejects(guard.prepare(handle, { tool: tool.name, args: 'invalid' }));
  assert.equal(effects.length, 0);
});
