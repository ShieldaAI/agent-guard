// How a model's tool calls go through the guard: one dispatcher function, a denial returned
// to the model as an ordinary tool result, and an action that waits for a person.
//
// Run: npm run build, then node examples/agent-loop.mjs
// No API key is needed. `scriptedModel` stands in for a model: replace it with your
// provider's client and keep `dispatch` and `review` as they are.
import { AgentGuard, isGuardError } from '@shieldaai/agent-guard';

// --- Your application (the host): tools, the task and what it may touch. ---
const tickets = new Map([
  ['42', { subject: 'Refund not received', status: 'open' }],
  ['7', { subject: 'Another customer', status: 'open' }],
]);
const guard = new AgentGuard();
const tools = [
  {
    name: 'ticket.read',
    description: 'Read one support ticket',
    resolve: args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' }),
    execute: args => ({ value: tickets.get(args.id) }),
  },
  {
    name: 'ticket.close',
    description: 'Close one support ticket',
    requiresApproval: true,
    resolve: args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' }),
    execute: args => {
      tickets.get(args.id).status = 'closed';
      return { value: { closed: args.id } };
    },
  },
];
for (const tool of tools) guard.approveTool(tool.name, guard.registerTool(tool));

// This piece of work may read and close ticket 42, and nothing else.
const task = guard.createTask({
  id: 'triage-42',
  principalId: 'support-agent',
  tenantId: 'acme',
  grants: [
    { tool: 'ticket.read', resources: ['ticket:42'] },
    { tool: 'ticket.close', resources: ['ticket:42'] },
  ],
  budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

// Prepared actions that wait for a person. A real host keeps these where its review screen reads them.
const waiting = new Map();

// --- The dispatcher: the only function the model-facing code is given. ---
// It never hands out the guard, the task or approve(). Whatever the model asks for, the
// answer is a plain value to send back as the tool result.
async function dispatch(call) {
  try {
    const prepared = await guard.prepare(task, { tool: call.name, args: call.input });
    if (prepared.requiresApproval) {
      waiting.set(prepared.id, prepared);
      return { status: 'waiting_for_approval', actionId: prepared.id };
    }
    return { status: 'ok', result: await guard.execute(prepared) };
  } catch (error) {
    // A denial is not a crash: the model reads the code and carries on.
    if (isGuardError(error)) return { status: 'denied', code: error.code };
    throw error;
  }
}

// --- The review step: called by your own interface after a signed-in person decided. ---
// The reviewer sees `prepared.action`: the exact tool, arguments and resource that will run.
async function review(actionId, approverId, approved) {
  const prepared = waiting.get(actionId);
  waiting.delete(actionId);
  if (!prepared) return { status: 'denied', code: 'UNKNOWN_ACTION' };
  if (!approved) return { status: 'refused_by_reviewer' }; // Never approved, so it can never run.
  try {
    const approvalId = guard.approve(prepared, { approverId, expiresAt: Date.now() + 30_000 });
    return { status: 'ok', result: await guard.execute(prepared, { approvalId }) };
  } catch (error) {
    if (isGuardError(error)) return { status: 'denied', code: error.code };
    throw error;
  }
}

// --- A stand-in for the model. It read a hostile ticket and now also wants ticket 7. ---
const scriptedModel = [
  { name: 'ticket.read', input: { id: '42' } }, // inside the grant: runs
  { name: 'ticket.read', input: { id: '7' } }, // outside the grant: denied, nothing runs
  { name: 'ticket.export', input: { to: 'attacker@example.com' } }, // not a registered tool: denied
  { name: 'ticket.close', input: { id: '42' } }, // inside the grant, but a person must approve
];

for (const call of scriptedModel) {
  const result = await dispatch(call);
  console.log(`${call.name} ${JSON.stringify(call.input)} ->`, JSON.stringify(result));
  if (result.status === 'waiting_for_approval') {
    const { action } = waiting.get(result.actionId);
    console.log(`  reviewer sees: ${action.tool} on ${action.resourceId}`);
    console.log('  after approval ->', JSON.stringify(await review(result.actionId, 'alice', true)));
  }
}
console.log('ticket 42 is now', tickets.get('42').status, '| ticket 7 is still', tickets.get('7').status);
