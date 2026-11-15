// One model turn, in the format of five provider APIs, through the same guard. The model asks
// to read ticket 42 (allowed), read ticket 7 (outside the task) and close ticket 42 (needs a
// person). Each provider gets the same three answers in its own shape.
//
// Run: npm run build, then node examples/model-adapters.mjs
// No API key: the model's turn is written out by hand in each provider's response format.
// With a real client, pass the response content where the scripted one is used below.
import { AgentGuard } from '@shieldaai/agent-guard';
import {
  ApprovalQueue,
  anthropicToolResults,
  anthropicTools,
  bedrockToolResults,
  bedrockTools,
  createDispatcher,
  geminiFunctionResponses,
  geminiTools,
  jsonSchemaParser,
  openAIChatToolMessages,
  openAIChatTools,
  openAIResponsesToolOutputs,
  openAIResponsesTools,
  registerApprovedTools,
  taskBudget,
  toolSpecs,
} from '@shieldaai/agent-guard-adapters';

const ticketArgs = {
  type: 'object',
  properties: { id: { type: 'string', pattern: '^[0-9]+$' } },
  required: ['id'],
  additionalProperties: false,
};

function newSession() {
  const guard = new AgentGuard();
  const resolve = args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' });
  registerApprovedTools(guard, [
    {
      name: 'ticket_read',
      description: 'Read one support ticket',
      inputSchema: ticketArgs,
      parse: jsonSchemaParser(ticketArgs),
      resolve,
      execute: args => ({ value: { id: args.id, subject: 'Refund not received' } }),
    },
    {
      name: 'ticket_close',
      description: 'Close one support ticket',
      inputSchema: ticketArgs,
      parse: jsonSchemaParser(ticketArgs),
      requiresApproval: true,
      resolve,
      execute: args => ({ value: { closed: args.id } }),
    },
  ]);
  const task = guard.createTask({
    id: 'triage-42',
    principalId: 'support-agent',
    tenantId: 'acme',
    grants: [
      { tool: 'ticket_read', resources: ['ticket:42'] },
      { tool: 'ticket_close', resources: ['ticket:42'] },
    ],
    budget: taskBudget({ maxCalls: 10, ttlMs: 60_000 }),
  });
  const approvals = new ApprovalQueue();
  return {
    approvals,
    dispatch: createDispatcher({ guard, task }, { approvals }),
    specs: toolSpecs(guard, ['ticket_read', 'ticket_close']),
  };
}

const calls = [
  ['ticket_read', { id: '42' }],
  ['ticket_read', { id: '7' }],
  ['ticket_close', { id: '42' }],
];
const summary = text => {
  const body = typeof text === 'string' ? JSON.parse(text) : text;
  return body.code ? `${body.status} ${body.code}` : body.status;
};

const providers = {
  'Anthropic Messages': async ({ dispatch, specs }) => {
    void anthropicTools(specs); // `tools` for messages.create()
    const content = calls.map(([name, input], i) => ({ type: 'tool_use', id: `toolu_${i}`, name, input }));
    return (await anthropicToolResults(content, dispatch)).map(block => summary(block.content));
  },
  'OpenAI Responses': async ({ dispatch, specs }) => {
    void openAIResponsesTools(specs);
    const output = calls.map(([name, input], i) => ({
      type: 'function_call',
      call_id: `call_${i}`,
      name,
      arguments: JSON.stringify(input),
    }));
    return (await openAIResponsesToolOutputs(output, dispatch)).map(item => summary(item.output));
  },
  'OpenAI Chat Completions': async ({ dispatch, specs }) => {
    void openAIChatTools(specs);
    const toolCalls = calls.map(([name, input], i) => ({
      id: `call_${i}`,
      type: 'function',
      function: { name, arguments: JSON.stringify(input) },
    }));
    return (await openAIChatToolMessages(toolCalls, dispatch)).map(message => summary(message.content));
  },
  'Google Gemini': async ({ dispatch, specs }) => {
    void geminiTools(specs);
    const functionCalls = calls.map(([name, args], i) => ({ id: `fc_${i}`, name, args }));
    return (await geminiFunctionResponses(functionCalls, dispatch)).map(part =>
      summary(part.functionResponse.response),
    );
  },
  'Amazon Bedrock Converse': async ({ dispatch, specs }) => {
    void bedrockTools(specs);
    const content = calls.map(([name, input], i) => ({ toolUse: { toolUseId: `tu_${i}`, name, input } }));
    return (await bedrockToolResults(content, dispatch)).map(block => summary(block.toolResult.content[0].json));
  },
};

for (const [provider, run] of Object.entries(providers)) {
  const session = newSession();
  const answers = await run(session);
  // The reviewer approves the waiting close in the host's own screen.
  const [pending] = session.approvals.pending();
  const approved = await session.approvals.approve(pending.actionId, { approverId: 'alice' });
  console.log(`${provider.padEnd(24)} ${answers.join(' | ')} | after approval: ${approved.status}`);
}
