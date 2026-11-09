import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, GuardError } from '@shieldaai/agent-guard';

function guardWith({ resolve, parse, execute }) {
  const guard = new AgentGuard();
  const fingerprint = guard.registerTool({ name: 'call', description: 'fixture',
    resolve: resolve ?? (() => ({ resourceId: 'one', tenantId: 'acme' })),
    ...(parse ? { parse } : {}), execute: execute ?? (() => ({ value: 'ok' })) });
  guard.approveTool('call', fingerprint);
  const task = guard.createTask({ id: 't', principalId: 'p', tenantId: 'acme', grants: [{ tool: 'call', resources: ['one'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
  return { guard, task };
}
const coded = code => Object.assign(new Error('server said: secret-value'), { code });

test('a flattened resolution failure keeps the adapter code as a safe detail', async () => {
  const { guard, task } = guardWith({ resolve: () => { throw coded('IDENTITY_DENIED'); } });
  const error = await guard.prepare(task, { tool: 'call', args: {} }).catch(caught => caught);
  assert.ok(error instanceof GuardError);
  assert.equal(error.code, 'RESOLUTION_FAILED');
  assert.equal(error.detail, 'IDENTITY_DENIED');
  assert.deepEqual(error.cause, { code: 'IDENTITY_DENIED' });
  assert.equal(JSON.stringify({ ...error, message: error.message }).includes('secret-value'), false);
});

test('argument and tool failures carry details; aborts do not', async () => {
  let f = guardWith({ parse: () => { throw coded('SCHEMA_MISMATCH'); } });
  assert.equal((await f.guard.prepare(f.task, { tool: 'call', args: {} }).catch(e => e)).detail, 'SCHEMA_MISMATCH');
  f = guardWith({ execute: () => { throw coded('MCP_OPERATION_FAILED'); } });
  const error = await f.guard.execute(await f.guard.prepare(f.task, { tool: 'call', args: {} })).catch(e => e);
  assert.equal(error.code, 'TOOL_FAILED'); assert.equal(error.detail, 'MCP_OPERATION_FAILED');
});

test('unsafe or accessor codes never become a detail', async () => {
  let reads = 0;
  for (const thrown of [coded('lower-case'), coded('HAS SPACE'), coded('X'.repeat(65)), coded(42), 'string error', null,
    Object.defineProperty(new Error('x'), 'code', { get() { reads++; return 'GETTER_CODE'; } })]) {
    const { guard, task } = guardWith({ resolve: () => { throw thrown; } });
    const error = await guard.prepare(task, { tool: 'call', args: {} }).catch(e => e);
    assert.equal(error.code, 'RESOLUTION_FAILED'); assert.equal(error.detail, undefined); assert.equal(error.cause, undefined);
  }
  assert.equal(reads, 0, 'the accessor was never invoked');
});
