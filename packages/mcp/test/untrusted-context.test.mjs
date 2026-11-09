import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection } from '../dist/index.js';

const identity = {
  serverId: 'helpdesk',
  transportIdentity: 'isolated-executor:helpdesk-v1',
  tenantId: 'acme',
  principalId: 'operator',
};
async function connect(t, options) {
  const server = new McpServer({ name: 'helpdesk', version: '1' });
  server.registerTool(
    'ticket',
    {
      description: 'Read a customer ticket',
      inputSchema: fromJsonSchema({ type: 'object', additionalProperties: false }),
    },
    async () => ({ content: [{ type: 'text', text: 'customer text' }] }),
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const guard = new AgentGuard();
  const connection = await ManagedMcpConnection.connect({
    guard,
    identity,
    transport: clientTransport,
    tools: [{ name: 'ticket', resolve: () => ({ resourceId: 'ticket', tenantId: 'acme' }) }],
    ...options,
  });
  t.after(async () => {
    await connection.close();
    await server.close();
  });
  const registration = connection.registrations[0];
  guard.approveTool(registration.name, registration.fingerprint);
  const task = guard.createTask({
    id: 'task',
    principalId: 'operator',
    tenantId: 'acme',
    grants: [{ tool: registration.name, resources: ['ticket'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  await guard.execute(await guard.prepare(task, { tool: registration.name, args: {} }));
  return guard.snapshot(task).untrusted;
}

test('a connection marked readsUntrusted taints the family after any call; the default does not', async t => {
  assert.equal(await connect(t, { readsUntrusted: true }), true);
  assert.equal(await connect(t, {}), false);
  await assert.rejects(connect(t, { readsUntrusted: 'yes' }));
});
