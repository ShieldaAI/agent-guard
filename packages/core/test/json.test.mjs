import test from 'node:test';
import assert from 'node:assert/strict';
import { immutableJson, canonicalJson, InvalidJsonError } from '../dist/json.js';
import { AgentGuard } from '../dist/index.js';

test('byte limits count UTF-8, escaped strings, keys and container punctuation exactly', () => {
  for (const value of [
    null, false, true, -0, 1e100, '', 'é💾', '\ud800', '\n"\\',
    [], {}, [false, null, 1], { 'é\n': ['💾', { '\ud800': '\u0000' }] },
  ]) {
    const expected = Buffer.byteLength(canonicalJson(immutableJson(value)));
    assert.doesNotThrow(() => immutableJson(value, 64, 100_000, expected));
    assert.throws(() => immutableJson(value, 64, 100_000, expected - 1), InvalidJsonError);
  }
});

test('oversized requests stop traversal before processing their remaining values', async () => {
  let reads = 0;
  const remainder = new Proxy({ value: 'must not be inspected' }, {
    getOwnPropertyDescriptor(target, property) {
      reads++;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  const guard = new AgentGuard();
  const task = guard.createTask({
    id: 'bounded', principalId: 'operator', tenantId: 'tenant', grants: [],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  const shared = 'x'.repeat(64 * 1024);
  await assert.rejects(guard.prepare(task, {
    tool: 'unused', args: { large: Array(64).fill(shared), remainder },
  }), error => error.code === 'INVALID_JSON');
  assert.equal(reads, 0);
  assert.equal(guard.snapshot(task).calls, 0);
});

test('large aliased JSON input is rejected within a small normalization budget', () => {
  const shared = 'x'.repeat(64 * 1024);
  assert.throws(() => immutableJson(Array(10_000).fill(shared)), InvalidJsonError);
  assert.throws(() => immutableJson({ ['x'.repeat(1_048_576)]: 0 }), InvalidJsonError);
});

test('an oversized tool result retains the full charge and revokes its task', async () => {
  const guard = new AgentGuard();
  const shared = 'x'.repeat(64 * 1024);
  const fingerprint = guard.registerTool({
    name: 'oversized', description: 'Synthetic oversized result', maxCost: 2,
    resolve: (_args, task) => ({ resourceId: 'one', tenantId: task.tenantId }),
    execute: () => ({ value: Array(10_000).fill(shared), actualCost: 0 }),
  });
  guard.approveTool('oversized', fingerprint);
  const task = guard.createTask({
    id: 'result', principalId: 'operator', tenantId: 'tenant',
    grants: [{ tool: 'oversized', resources: ['one'] }],
    budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 4, deadline: Date.now() + 60_000 },
  });
  await assert.rejects(guard.execute(await guard.prepare(task, { tool: 'oversized', args: {} })),
    error => error.code === 'RESULT_INVALID');
  assert.equal(guard.snapshot(task).spent, 2);
  assert.equal(guard.snapshot(task).reserved, 0);
  assert.equal(guard.snapshot(task).concurrent, 0);
  await assert.rejects(guard.prepare(task, { tool: 'oversized', args: {} }), error => error.code === 'TASK_REVOKED');
});
