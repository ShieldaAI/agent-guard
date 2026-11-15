# Connect Agent Guard to your model or framework

This guide shows the few lines that route a model's tool calls through Agent Guard for each
supported provider API and agent framework. They all use
[`@shieldaai/agent-guard-adapters`](../../packages/adapters/README.md) and the same three
pieces:

1. **Tool specs** from the guard's approved registrations: `toolSpecs(guard, names)`. The
   model is shown exactly the definition you approved, and a tool changed since its approval
   is not shown at all (`TOOL_NOT_APPROVED`).
2. **A dispatcher**: `createDispatcher({ guard, task }, { approvals })`. It is the only thing
   the model-facing code gets. Every call comes back as an outcome: `ok`, `denied`,
   `waiting_for_approval` or `failed`.
3. **An approval queue** your own code reads: `approvals.pending()`, then
   `approvals.approve(actionId, { approverId })` or `approvals.reject(actionId)` after your
   own sign-in check.

Everything below assumes this setup, taken from
[`examples/model-adapters.mjs`](../../examples/model-adapters.mjs):

```js
import { AgentGuard } from '@shieldaai/agent-guard';
import { ApprovalQueue, createDispatcher, jsonSchemaParser, registerApprovedTools, taskBudget, toolSpecs }
  from '@shieldaai/agent-guard-adapters';

const guard = new AgentGuard();
registerApprovedTools(guard, myTools); // each with inputSchema and parse: jsonSchemaParser(inputSchema)
const task = guard.createTask({
  id: 'triage-42', principalId: user.id, tenantId: user.tenantId,
  grants: [{ tool: 'ticket_read', resources: ['ticket:42'] }, { tool: 'ticket_close', resources: ['ticket:42'] }],
  budget: taskBudget({ maxCalls: 20, ttlMs: 10 * 60_000 }),
});
const approvals = new ApprovalQueue();
const dispatch = createDispatcher({ guard, task }, { approvals });
const specs = toolSpecs(guard, ['ticket_read', 'ticket_close']);
```

Take `principalId` and `tenantId` from your own sign-in, never from what the model says.

## Provider APIs

Each provider has two functions: one turns specs into that API's `tools`, the other runs the
tool calls of one model response and returns the items to send back. Calls of one response run
one after another by default; pass `{ parallel: true }` to run them together.

### Anthropic Messages API (Claude)

```js
import Anthropic from '@anthropic-ai/sdk';
import { anthropicTools, anthropicToolResults } from '@shieldaai/agent-guard-adapters';

const client = new Anthropic();
const tools = anthropicTools(specs);
const messages = [{ role: 'user', content: 'Triage ticket 42.' }];
for (let turn = 0; turn < 10; turn += 1) {
  const message = await client.messages.create({ model: 'claude-opus-5-5', max_tokens: 2048, tools, messages });
  messages.push({ role: 'assistant', content: message.content });
  if (message.stop_reason !== 'tool_use') break;
  messages.push({ role: 'user', content: await anthropicToolResults(message.content, dispatch) });
}
```

Denials come back with `is_error: true`, so Claude treats them as failed tool calls and reads
the guidance in the message.

### OpenAI Responses API

```js
import OpenAI from 'openai';
import { openAIResponsesTools, openAIResponsesToolOutputs } from '@shieldaai/agent-guard-adapters';

const client = new OpenAI();
const tools = openAIResponsesTools(specs); // { strict: true } only for schemas written for strict mode
let input = [{ role: 'user', content: 'Triage ticket 42.' }];
for (let turn = 0; turn < 10; turn += 1) {
  const response = await client.responses.create({ model: 'gpt-5', tools, input });
  const outputs = await openAIResponsesToolOutputs(response.output, dispatch);
  if (outputs.length === 0) break;
  input = [...input, ...response.output, ...outputs];
}
```

Arguments that are not valid JSON are answered with `INPUT_NOT_JSON`; nothing runs.

### OpenAI Chat Completions and compatible APIs

Groq, Mistral, Together, Fireworks, OpenRouter, vLLM, LM Studio and Ollama accept the same
format.

```js
import { openAIChatTools, openAIChatToolMessages } from '@shieldaai/agent-guard-adapters';

const completion = await client.chat.completions.create({ model, messages, tools: openAIChatTools(specs) });
const message = completion.choices[0].message;
messages.push(message, ...(await openAIChatToolMessages(message.tool_calls, dispatch)));
```

### Google Gemini

```js
import { GoogleGenAI } from '@google/genai';
import { geminiTools, geminiFunctionResponses } from '@shieldaai/agent-guard-adapters';

const ai = new GoogleGenAI({});
const config = { tools: geminiTools(specs) };
const response = await ai.models.generateContent({ model: 'gemini-3-pro', contents, config });
const parts = await geminiFunctionResponses(response.functionCalls, dispatch);
contents.push(response.candidates[0].content, { role: 'user', parts });
```

Specs are sent as `parametersJsonSchema`, so the schema is plain JSON Schema.

### Amazon Bedrock Converse

```js
import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { bedrockTools, bedrockToolResults } from '@shieldaai/agent-guard-adapters';

const toolConfig = { tools: bedrockTools(specs) };
const response = await bedrock.send(new ConverseCommand({ modelId, messages, toolConfig }));
const content = response.output.message.content;
messages.push(response.output.message, { role: 'user', content: await bedrockToolResults(content, dispatch) });
```

## Agent frameworks

Framework adapters take the framework's own factory function, so the adapters package never
depends on, or pins, a framework version. The framework runs its own loop; each tool function
goes through the dispatcher.

### Vercel AI SDK

```js
import { generateText, jsonSchema, stepCountIs } from 'ai';
import { aiSdkTools } from '@shieldaai/agent-guard-adapters';

const result = await generateText({
  model, prompt: 'Triage ticket 42.',
  tools: aiSdkTools(dispatch, specs, { jsonSchema }),
  stopWhen: stepCountIs(8),
});
```

Works the same with `streamText`. The tool's output is the outcome object.

### OpenAI Agents SDK

```js
import { Agent, run, tool } from '@openai/agents';
import { openAIAgentsTools } from '@shieldaai/agent-guard-adapters';

const agent = new Agent({ name: 'Support', instructions, tools: openAIAgentsTools(dispatch, specs, { tool }) });
const result = await run(agent, 'Triage ticket 42.');
```

### LangChain.js and LangGraph.js

```js
import { tool } from '@langchain/core/tools';
import { createReactAgent } from '@langchain/langgraph/prebuilt';
import { langChainTools } from '@shieldaai/agent-guard-adapters';

const tools = langChainTools(dispatch, specs, { tool });
const agent = createReactAgent({ llm, tools }); // or model.bindTools(tools), or new ToolNode(tools)
```

### Approvals inside a framework's loop

A framework's tool function usually has to return a final answer. Two choices:

- Return at once (the default). The model reads `waiting_for_approval` and tells the user;
  when the reviewer approves, `approvals.approve()` resolves with the result, which you add to
  the conversation on the next turn.
- Wait for the reviewer: `createDispatcher({ guard, task }, { approvals, waitForApproval: {
  timeoutMs: 120_000 } })`. The tool call stays open until a person decides; an unanswered
  action is denied with `APPROVAL_TIMEOUT` and dropped. Notify reviewers from
  `new ApprovalQueue({ onPending })`.

## Offer guarded tools to an MCP client

To give Claude Code, Claude Desktop, Cursor or VS Code tools that go through the guard, serve
them from an MCP server. [`examples/mcp-guarded-server.mjs`](../../examples/mcp-guarded-server.mjs)
is a complete one:

```js
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { registerMcpServerTools } from '@shieldaai/agent-guard-adapters';

const server = new McpServer({ name: 'guarded-tickets', version: '1.0.0' });
registerMcpServerTools(server, dispatch, specs, { fromJsonSchema });
await server.connect(new StdioServerTransport());
```

```sh
claude mcp add guarded-tickets -- node /path/to/examples/mcp-guarded-server.mjs
```

The same server works for the Claude Agent SDK, which accepts stdio MCP servers in its
`mcpServers` option (`{ type: 'stdio', command: 'node', args: ['/path/to/server.mjs'] }`).

Over stdio, standard output belongs to the protocol: log to standard error. With an older MCP
SDK, or a server you wire by hand, `mcpServerTools(dispatch, specs)` gives `listTools()` and
`callTool()` handlers for `tools/list` and `tools/call`.

This is the opposite direction from [`@shieldaai/agent-guard-mcp`](../../packages/mcp/README.md),
which puts the tools of an existing MCP server behind the guard for your own agent.

## The durable executor

Use the executor instead of the in-process guard by changing only the dispatcher:

```js
import { executorBackend, executorClientBackend } from '@shieldaai/agent-guard-adapters';

const dispatch = createDispatcher(executorBackend(executor, 'triage-42'), { approvals }); // same process
const remote = createDispatcher(executorClientBackend(taskClient), { approvals });       // task token
```

A remote executor issues approvals through its admin API; run the action with
`approvals.complete(actionId, { approvalId })`.

## Logs and metrics

```js
import { combineDecisionHooks, jsonLinesDecisionLogger, openTelemetryDecisionHook } from '@shieldaai/agent-guard-adapters';

const guard = new AgentGuard({
  onDecision: combineDecisionHooks(
    jsonLinesDecisionLogger({ fields: { service: 'support' } }),
    openTelemetryDecisionHook({ meter: metrics.getMeter('support'), activeSpan: () => trace.getActiveSpan() }),
  ),
});
```

See the [audit log guide](audit-log.md) for what each decision contains.

## Which versions are checked

The repository's tests run every provider shape, the MCP adapter against the MCP TypeScript
SDK 2.4 with a real client and server, and both examples. Before this release the framework
adapters were also run against `ai` 7.0 (a full `generateText` loop), `@openai/agents` 0.22
(`tool().invoke`), `@langchain/core` 1.4 with `@langchain/langgraph` 1.7 (`tool()` and
`ToolNode`) and Zod 4.6, and the provider outputs were type-checked against
`@anthropic-ai/sdk` 1.8, `openai` 7.57, `@google/genai` 3.3 and
`@aws-sdk/client-bedrock-runtime` 3.1169. `scripts/verify-adapters-real-packages.mjs` repeats
that check against whatever versions you install.
