import { AgentGuard } from '@shieldaai/agent-guard';

const guard = new AgentGuard();
const effects = [];
const fingerprint = guard.registerTool({
  name: 'records.delete', description: 'Delete one record', requiresApproval: true,
  resolve: args => ({ resourceId: args.recordId, tenantId: 'demo' }),
  execute: args => { effects.push(args.recordId); return { value: { deleted: args.recordId } }; },
});
// These administration calls belong to the trusted application, never the model.
guard.approveTool('records.delete', fingerprint);
const task = guard.createTask({
  id: 'cleanup', principalId: 'operator', tenantId: 'demo',
  grants: [{ tool: 'records.delete', resources: ['record-A'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
const args = { recordId: 'record-A' };
const prepared = await guard.prepare(task, { tool: 'records.delete', args });
args.recordId = 'record-B'; // The prepared invocation is already an immutable snapshot.
const approvalId = guard.approve(prepared, { approverId: 'human-reviewer', expiresAt: Date.now() + 30_000 });
console.log(await guard.execute(prepared, { approvalId }));
console.log('Recorded effects:', effects);
try { await guard.execute(prepared, { approvalId }); }
catch (error) { console.log('Replay denied:', error.code); }
