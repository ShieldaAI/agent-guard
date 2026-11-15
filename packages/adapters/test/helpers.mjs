import { AgentGuard } from '@shieldaai/agent-guard';
import { registerApprovedTools, taskBudget, jsonSchemaParser } from '../dist/index.js';

export const ticketSchema = {
  type: 'object',
  properties: { id: { type: 'string', pattern: '^[0-9]+$' } },
  required: ['id'],
  additionalProperties: false,
};

/** A guard with three ticket tools and one task that may read and close ticket 42 only. */
export function ticketDesk(options = {}) {
  const tickets = new Map([
    ['42', { subject: 'Refund not received', status: 'open' }],
    ['7', { subject: 'Another customer', status: 'open' }],
  ]);
  const runs = [];
  const guard = new AgentGuard(options.guard ?? {});
  const resolve = args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' });
  const tools = [
    {
      name: 'ticket.read',
      description: 'Read one support ticket',
      inputSchema: ticketSchema,
      parse: jsonSchemaParser(ticketSchema),
      resolve,
      execute: args => {
        runs.push(['ticket.read', args.id]);
        return { value: tickets.get(args.id) ?? null };
      },
    },
    {
      name: 'ticket.close',
      description: 'Close one support ticket',
      inputSchema: ticketSchema,
      parse: jsonSchemaParser(ticketSchema),
      requiresApproval: true,
      resolve,
      execute: args => {
        runs.push(['ticket.close', args.id]);
        tickets.get(args.id).status = 'closed';
        return { value: { closed: args.id } };
      },
    },
    {
      name: 'ticket.explode',
      description: 'A handler that throws after starting',
      inputSchema: ticketSchema,
      resolve,
      execute: () => {
        runs.push(['ticket.explode']);
        throw new Error('boom');
      },
    },
  ];
  const fingerprints = registerApprovedTools(guard, tools);
  const task = guard.createTask({
    id: options.taskId ?? 'triage-42',
    principalId: 'support-agent',
    tenantId: 'acme',
    grants: [
      { tool: 'ticket.read', resources: ['ticket:42'] },
      { tool: 'ticket.close', resources: ['ticket:42'] },
      { tool: 'ticket.explode', resources: ['ticket:42'] },
    ],
    budget: taskBudget({ maxCalls: options.maxCalls ?? 10, ttlMs: 60_000 }),
  });
  return { guard, task, tickets, runs, fingerprints };
}

/** A deep copy with ordinary prototypes, for comparing frozen guard values. */
export const plain = value => JSON.parse(JSON.stringify(value));
