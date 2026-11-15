// An MCP server whose tools are behind Agent Guard, for any MCP client: Claude Code, Claude
// Desktop, Cursor, VS Code. The client sees two ticket tools; every call it makes is checked
// against one task's grants, and closing a ticket waits for a person.
//
// Run: npm run build, then
//   node examples/mcp-guarded-server.mjs --self-test     (offline: an in-memory MCP client)
//   claude mcp add guarded-tickets -- node "$PWD/examples/mcp-guarded-server.mjs"
//
// Over stdio, standard output belongs to the protocol, so this server logs to standard error.
// Pending approvals are printed there; this example approves nothing on its own. A real host
// shows them in its own review screen and calls approvals.approve() after signing the reviewer in.
import { AgentGuard } from '@shieldaai/agent-guard';
import {
  ApprovalQueue,
  createDispatcher,
  jsonLinesDecisionLogger,
  jsonSchemaParser,
  registerApprovedTools,
  registerMcpServerTools,
  taskBudget,
  toolSpecs,
} from '@shieldaai/agent-guard-adapters';
import { pathToFileURL } from 'node:url';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';

const tickets = new Map([
  ['42', { subject: 'Refund not received', status: 'open' }],
  ['7', { subject: 'Another customer', status: 'open' }],
]);
const ticketArgs = {
  type: 'object',
  properties: { id: { type: 'string', pattern: '^[0-9]+$', description: 'The ticket number' } },
  required: ['id'],
  additionalProperties: false,
};
const resolve = args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' });

export function createGuardedServer({ log = line => process.stderr.write(`${line}\n`) } = {}) {
  const guard = new AgentGuard({
    onDecision: jsonLinesDecisionLogger({ write: log, fields: { service: 'guarded-tickets' } }),
  });
  registerApprovedTools(guard, [
    {
      name: 'ticket_read',
      description: 'Read one support ticket by number',
      inputSchema: ticketArgs,
      parse: jsonSchemaParser(ticketArgs),
      resolve,
      execute: args => ({ value: tickets.get(args.id) ?? null }),
    },
    {
      name: 'ticket_close',
      description: 'Close one support ticket by number. A person must approve each close.',
      inputSchema: ticketArgs,
      parse: jsonSchemaParser(ticketArgs),
      requiresApproval: true,
      resolve,
      execute: args => {
        tickets.get(args.id).status = 'closed';
        return { value: { closed: args.id } };
      },
    },
  ]);
  // The client's session is one task: ticket 42 only, at most 20 calls, for one hour.
  const task = guard.createTask({
    id: 'mcp-session',
    principalId: 'mcp-client',
    tenantId: 'acme',
    grants: [
      { tool: 'ticket_read', resources: ['ticket:42'] },
      { tool: 'ticket_close', resources: ['ticket:42'] },
    ],
    budget: taskBudget({ maxCalls: 20, ttlMs: 60 * 60_000 }),
  });
  const approvals = new ApprovalQueue({
    onPending: entry =>
      log(`Waiting for approval: ${entry.tool} on ${entry.action.resourceId} (action ${entry.actionId})`),
  });
  const dispatch = createDispatcher({ guard, task }, { approvals });
  const server = new McpServer({ name: 'guarded-tickets', version: '1.0.0' });
  registerMcpServerTools(server, dispatch, toolSpecs(guard, ['ticket_read', 'ticket_close']), { fromJsonSchema });
  return { server, approvals, tickets };
}

async function selfTest() {
  const { Client, InMemoryTransport } = await import('@modelcontextprotocol/client');
  const logged = [];
  const { server, approvals, tickets: store } = createGuardedServer({ log: line => logged.push(line) });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'self-test', version: '1.0.0' });
  await client.connect(clientTransport);
  const show = async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    let body;
    try {
      body = JSON.parse(result.content[0].text);
    } catch {
      // The MCP SDK checks the advertised schema before the guard sees the call.
      console.log(`${name} ${JSON.stringify(args)} -> refused by the MCP SDK's own schema check`);
      return undefined;
    }
    console.log(`${name} ${JSON.stringify(args)} -> ${body.status}${body.code ? ` ${body.code}` : ''}`);
    return body;
  };
  console.log('tools:', (await client.listTools()).tools.map(tool => tool.name).join(', '));
  await show('ticket_read', { id: '42' });
  await show('ticket_read', { id: '7' });
  await show('ticket_read', { id: '42; DROP TABLE' });
  const waiting = await show('ticket_close', { id: '42' });
  const outcome = await approvals.approve(waiting.actionId, { approverId: 'alice' });
  console.log(`approved by alice -> ${outcome.status}; ticket 42 is ${store.get('42').status}`);
  console.log(`decisions logged: ${logged.filter(line => line.startsWith('{')).length}`);
  await client.close();
  await server.close();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes('--self-test')) await selfTest();
  else {
    const { StdioServerTransport } = await import('@modelcontextprotocol/server/stdio');
    const { server } = createGuardedServer();
    await server.connect(new StdioServerTransport());
    process.stderr.write('guarded-tickets MCP server ready on stdio\n');
  }
}
