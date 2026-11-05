import assert from 'node:assert/strict';
import { AgentGuard, GuardError } from '@shieldaai/agent-guard';

// Synthetic records only. The trusted host supplies identity and ownership.
const guard = new AgentGuard();
let handlerCalls = 0;
const fingerprint = guard.registerTool({
  name: 'records.archive',
  description: 'Archive one synthetic record',
  requiresApproval: true,
  parse(args) {
    if (!args || typeof args !== 'object' || Array.isArray(args) ||
        Object.keys(args).length !== 1 || typeof args.recordId !== 'string') {
      throw new Error('Expected one recordId');
    }
    return { recordId: args.recordId };
  },
  resolve: args => ({ resourceId: args.recordId, tenantId: 'demo-company' }),
  execute: args => {
    handlerCalls++;
    return { value: { recordId: args.recordId, status: 'archived' } };
  },
});
guard.approveTool('records.archive', fingerprint);
const task = guard.createTask({
  id: 'archive-demo', principalId: 'demo-operator', tenantId: 'demo-company',
  grants: [{ tool: 'records.archive', resources: ['record-A'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

async function expectDenied(label, code, operation, expectedCalls) {
  await assert.rejects(operation, error => error instanceof GuardError && error.code === code);
  assert.equal(handlerCalls, expectedCalls);
  console.log(`DENIED ${label}: ${code}; handler calls: ${handlerCalls}`);
}

await expectDenied('ungranted resource', 'GRANT_DENIED', () =>
  guard.prepare(task, { tool: 'records.archive', args: { recordId: 'record-B' } }), 0);
const prepared = await guard.prepare(task, {
  tool: 'records.archive', args: { recordId: 'record-A' },
});
await expectDenied('without approval', 'APPROVAL_REQUIRED', () => guard.execute(prepared), 0);

// A real host authenticates the reviewer before calling approve().
const approvalId = guard.approve(prepared, {
  approverId: 'fixture-reviewer', expiresAt: Date.now() + 30_000,
});
const result = await guard.execute(prepared, { approvalId });
assert.equal(result.recordId, 'record-A');
assert.equal(result.status, 'archived');
assert.equal(handlerCalls, 1);
console.log(`ALLOWED approved record-A: ${result.status}; handler calls: ${handlerCalls}`);
await expectDenied('replay', 'ACTION_USED', () => guard.execute(prepared, { approvalId }), 1);
console.log('All assertions passed. In-process fixtures; no API key or external side effects.');
