import assert from 'node:assert/strict';
import { AgentGuard, GuardError, GuardErrorCode, type GuardOptions, type Json } from '@shieldaai/agent-guard';
import { registerMcpTool, type McpToolClient } from '@shieldaai/agent-guard-mcp';
import { runConformance, scenarioCatalog, type GuardLike } from '@shieldaai/agent-guard-scenarios';

const calls: Array<{ name: string; arguments: Record<string, Json> }> = [];
const client: McpToolClient = {
  async callTool(request, { signal }) {
    assert.equal(signal.aborted, false);
    calls.push(request);
    return { content: [{ type: 'text', text: 'Public report' }] };
  },
};
const guard = new AgentGuard();
const registered = registerMcpTool(guard, {
  serverId: 'packed-documents',
  tool: { name: 'read', inputSchema: { type: 'object' } },
  client,
  resolve(args) {
    assert.equal(typeof args.id, 'string');
    return { resourceId: args.id as string, tenantId: 'pack-test' };
  },
});
guard.approveTool(registered.name, registered.fingerprint);
const task = guard.createTask({
  id: 'packed-consumer', principalId: 'host', tenantId: 'pack-test',
  grants: [{ tool: registered.name, resources: ['public-report'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
await assert.rejects(
  guard.prepare(task, { tool: registered.name, args: { id: 'private-report' } }),
  error => error instanceof GuardError && error.code === GuardErrorCode.GRANT_DENIED,
);
assert.equal(calls.length, 0);
const args = { id: 'public-report' };
const prepared = await guard.prepare(task, { tool: registered.name, args });
args.id = 'private-report';
assert.deepEqual(JSON.parse(JSON.stringify(await guard.execute(prepared))), { content: [{ type: 'text', text: 'Public report' }] });
assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ name: 'read', arguments: { id: 'public-report' } }]);
assert.equal(Object.isFrozen(calls[0]?.arguments), true);

const createGuard = (options: GuardOptions): GuardLike => new AgentGuard(options);
const report = await runConformance({ createGuard });
assert.equal(report.passed, true, JSON.stringify(report));
assert.equal(report.scenarioCount, scenarioCatalog.length);
assert.equal(report.caseCount, scenarioCatalog.length * 2);
console.log('Packed declarations and README examples compiled; MCP dispatch and all conformance scenarios passed.');
