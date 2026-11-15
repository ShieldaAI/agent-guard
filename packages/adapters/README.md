# @shieldaai/agent-guard-adapters

Connect [Agent Guard](https://github.com/ShieldaAI/agent-guard) to your model provider or
agent framework in a few lines. Every tool call the model makes goes through the guard; a
denial comes back as an ordinary tool result the model can read; an action that needs a
person waits in an approval queue your own code controls.

No third-party runtime dependencies. Framework adapters take the framework's own factory
function as an argument, so this package never pins a framework version.

| Works with | Functions |
| --- | --- |
| Anthropic Messages API (Claude) | `anthropicTools`, `anthropicToolResults` |
| OpenAI Responses API | `openAIResponsesTools`, `openAIResponsesToolOutputs` |
| OpenAI Chat Completions and compatible APIs (Groq, Mistral, vLLM, Ollama, OpenRouter, ...) | `openAIChatTools`, `openAIChatToolMessages` |
| Google Gemini (`@google/genai`) | `geminiTools`, `geminiFunctionResponses` |
| Amazon Bedrock Converse | `bedrockTools`, `bedrockToolResults` |
| Vercel AI SDK (`ai` 5 or later) | `aiSdkTools` |
| OpenAI Agents SDK (`@openai/agents`) | `openAIAgentsTools` |
| LangChain.js and LangGraph.js (`@langchain/core` 0.3 or later) | `langChainTools` |
| Any MCP client (Claude Code, Claude Desktop, Cursor, VS Code): serve guarded tools over MCP | `registerMcpServerTools`, `mcpServerTools` |
| Zod, Valibot, ArkType (Standard Schema) | `standardSchemaParser` |
| OpenTelemetry, JSON log shippers | `openTelemetryDecisionHook`, `jsonLinesDecisionLogger`, `DecisionStats` |

To put the tools of an existing MCP *server* behind the guard (the other direction), use
[`@shieldaai/agent-guard-mcp`](https://www.npmjs.com/package/@shieldaai/agent-guard-mcp).

## Install

```sh
npm install @shieldaai/agent-guard @shieldaai/agent-guard-adapters
```

Node.js 22 or newer, ESM. Install the same version of both packages.

## Example: Claude with an approval step

```ts
import { AgentGuard } from '@shieldaai/agent-guard';
import {
  ApprovalQueue,
  anthropicToolResults,
  anthropicTools,
  createDispatcher,
  defineTool,
  jsonSchemaParser,
  registerApprovedTools,
  taskBudget,
  toolSpecs,
} from '@shieldaai/agent-guard-adapters';

const guard = new AgentGuard();
const ticketArgs = {
  type: 'object',
  properties: { id: { type: 'string', pattern: '^[0-9]+$' } },
  required: ['id'],
  additionalProperties: false,
} as const;

// 1. Your tools. The JSON Schema the model sees is also enforced, by jsonSchemaParser,
// and defineTool types the arguments that resolve and execute receive.
type TicketArgs = { id: string };
const ticket = (args: TicketArgs) => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' });
registerApprovedTools(guard, [
  defineTool({
    name: 'ticket_read',
    description: 'Read one support ticket',
    inputSchema: ticketArgs,
    parse: jsonSchemaParser<TicketArgs>(ticketArgs),
    resolve: ticket,
    execute: args => ({ value: { id: args.id, subject: 'Refund not received' } }),
  }),
  defineTool({
    name: 'ticket_close',
    description: 'Close one support ticket',
    inputSchema: ticketArgs,
    parse: jsonSchemaParser<TicketArgs>(ticketArgs),
    requiresApproval: true,
    resolve: ticket,
    execute: args => ({ value: { closed: args.id } }),
  }),
]);

// 2. One task per piece of work: these tools, on ticket 42 only.
const task = guard.createTask({
  id: 'triage-42',
  principalId: 'support-agent',
  tenantId: 'acme',
  grants: [
    { tool: 'ticket_read', resources: ['ticket:42'] },
    { tool: 'ticket_close', resources: ['ticket:42'] },
  ],
  budget: taskBudget({ maxCalls: 10, ttlMs: 5 * 60_000 }),
});

// 3. The dispatcher is the only thing the model-facing code gets.
const approvals = new ApprovalQueue();
const dispatch = createDispatcher({ guard, task }, { approvals });

// What you pass as `tools` in messages.create(): the approved definitions, nothing else.
const tools = anthropicTools(toolSpecs(guard, ['ticket_read', 'ticket_close']));

// 4. For each assistant message, run its tool_use blocks and send the results back.
const assistantContent = [
  { type: 'tool_use', id: 'toolu_1', name: 'ticket_read', input: { id: '42' } },
  { type: 'tool_use', id: 'toolu_2', name: 'ticket_read', input: { id: '7' } },
  { type: 'tool_use', id: 'toolu_3', name: 'ticket_close', input: { id: '42' } },
];
const results = await anthropicToolResults(assistantContent, dispatch);
// toolu_1: ok. toolu_2: denied, GRANT_DENIED (is_error). toolu_3: waiting_for_approval.
console.log(tools.length, results.map(result => JSON.parse(result.content).status));

// 5. In your review screen, after signing the reviewer in:
for (const pending of approvals.pending()) {
  const outcome = await approvals.approve(pending.actionId, { approverId: 'alice@example.com' });
  console.log(pending.action.tool, outcome.status); // ticket_close ok
}
```

With a real client, `assistantContent` is `message.content` from
`anthropic.messages.create({ model, tools, messages })`, and the results go back as
`{ role: 'user', content: results }`. Each provider has the same pair of functions.

## What the model receives

Every call returns one of four outcomes. `outcomeForModel()` is what the provider adapters
send; it carries no task, tenant or principal identifiers and never echoes the arguments.

| `status` | Meaning | Sent to the model |
| --- | --- | --- |
| `ok` | The tool ran. | `{ status, result }` |
| `denied` | Nothing ran. | `{ status, code, detail?, retryable, message }` — the message tells the model what to do next, for example not to retry with another ID |
| `waiting_for_approval` | Held for a person; nothing ran yet. | `{ status, actionId, message }` |
| `failed` | The handler started and failed, or the result was lost: the effect is unknown. | `{ status, code, detail?, retryable: false, message }` |

Denials and failures are flagged as errors to the provider (`is_error`, `isError`, and
Bedrock's `status: 'error'` with `includeStatus: true`). If host code throws (a broken
backend, a network failure to a remote executor), the model gets `HOST_ERROR` with no detail
and the error goes to the dispatcher's `onHostError` hook; the other calls of the turn still
return their results. Run `npx agent-guard-explain GRANT_DENIED` to see what any code means.

## Approvals

`ApprovalQueue` holds actions that need a person. The model-facing dispatcher can only add
to it. `approve(actionId, { approverId })` and `reject(actionId)` are host calls: make them
only after your own sign-in check, and show the reviewer `pending.action`, which is exactly
what will run.

- **Return at once (default).** The model gets `waiting_for_approval`; when the reviewer
  approves, `approve()` resolves with the result, which you can add to the conversation.
- **Wait.** `createDispatcher(target, { approvals, waitForApproval: { timeoutMs: 120_000 } })`
  holds the call open until a person decides, for frameworks whose tool function must return
  the final result. Unanswered actions are denied with `APPROVAL_TIMEOUT`.
- **Remote executor.** With `executorClientBackend(client)` approvals come from the
  executor's admin API; `complete(actionId, { approvalId })` runs the action with one.

## Framework adapters

```js
// Vercel AI SDK
import { generateText, jsonSchema, stepCountIs } from 'ai';
const tools = aiSdkTools(dispatch, toolSpecs(guard, names), { jsonSchema });
await generateText({ model, tools, stopWhen: stepCountIs(8), prompt });

// OpenAI Agents SDK
import { Agent, run, tool } from '@openai/agents';
const agent = new Agent({ name: 'Support', tools: openAIAgentsTools(dispatch, specs, { tool }) });

// LangChain.js / LangGraph.js
import { tool } from '@langchain/core/tools';
const tools = langChainTools(dispatch, specs, { tool }); // bindTools, ToolNode, createReactAgent

// An MCP server that offers guarded tools to Claude Code, Cursor, ...
import { McpServer, fromJsonSchema } from '@modelcontextprotocol/server';
registerMcpServerTools(server, dispatch, specs, { fromJsonSchema });
```

These adapters are checked against `ai` 7, `@openai/agents` 0.22, `@langchain/core` 1.4 with
`@langchain/langgraph` 1.7, the MCP TypeScript SDK 2.4, and (for types) `@anthropic-ai/sdk`
1.8, `openai` 7.57, `@google/genai` 3.3 and `@aws-sdk/client-bedrock-runtime` 3.1169.

## Tools, schemas and budgets

- `toolSpecs(guard, names)` reads name, description and schema from the guard's approved
  registrations, so the model sees exactly what you approved. A tool changed since its
  approval throws `TOOL_NOT_APPROVED` instead of reaching the model unreviewed.
- `registerApprovedTools(guard, tools, { pinned })` registers and approves tools defined in
  your code. Pass fingerprints from a checked-in file as `pinned` and a changed or unpinned
  definition fails start-up with `TOOL_PIN_MISMATCH` until someone updates the pins.
- `jsonSchemaParser(schema)` turns the tool's JSON Schema into its `parse`, so arguments are
  enforced, not just described. Unsupported keywords (such as `$ref`) throw when the parser
  is built, never silently at call time, and so is a `pattern` with a quantified group that
  contains a quantifier, such as `(a+)+`, which can take exponential time on model input
  (opt out with `allowNestedQuantifiers: true`). A mismatch reaches the model as `ARGUMENT_INVALID`
  with a safe hint such as `SCHEMA_REQUIRED`; the failing value is never repeated.
- `standardSchemaParser(zodSchema)` does the same with Zod, Valibot or ArkType.
- `defineTool<Args>({ parse, resolve, execute })` types the arguments `resolve` and `execute`
  receive from what `parse` returns (`jsonSchemaParser<Args>(schema)`, or a Zod schema through
  `standardSchemaParser`). It changes nothing at runtime.
- `taskBudget({ maxCalls, ttlMs })` fills in the rest of a budget: one call at a time, no cost.

## Policies

Composable rules for the guard's `policy` option. The most restrictive answer wins.

```js
const guard = new AgentGuard({
  policy: combinePolicies(
    denyTools(['payments.refund']),                       // switched off during an incident
    requireApprovalForExternal(),                         // anything leaving the system
    requireApprovalAfterUntrusted({ except: ['web.read'] }),
    withinHours({ timeZone: 'Europe/Kyiv', from: 9, to: 18, tools: ['db.migrate'] }),
  ),
});
```

Also `denyWhen(predicate)`, `requireApprovalWhen(predicate)` and `requireApprovalForTools(names)`.

Budgets are per task. To limit a tool across tasks, for example at most 20 emails per tenant
per hour however many tasks run, use `RateLimiter`:

```js
const limiter = new RateLimiter([{ tools: ['mail.send'], max: 20, windowMs: 3_600_000, per: 'tenant' }]);
const guard = new AgentGuard({ policy: limiter.policy, onDecision: limiter.hook });
```

Calls are counted when they are dispatched, so denied calls never use the allowance. The
count is kept in memory in one process, and calls already past the check when the limit is
reached still run, so it can exceed `max` by the number of calls in flight.

## Telemetry

```js
import { metrics, trace } from '@opentelemetry/api';
const stats = new DecisionStats();
const guard = new AgentGuard({
  onDecision: combineDecisionHooks(
    openTelemetryDecisionHook({ meter: metrics.getMeter('support'), activeSpan: () => trace.getActiveSpan() }),
    jsonLinesDecisionLogger({ fields: { service: 'support' } }),
    stats.hook,
  ),
});
```

The counter `agent_guard.decisions` has low-cardinality attributes only (operation, outcome,
code, tool, untrusted). Span events add task and action IDs; resource, tenant, principal and
approver IDs only with `includeIdentifiers: true`. Decisions never include arguments or results.

## Other backends

`createDispatcher` takes `{ guard, task }` for the core guard, `executorBackend(executor,
taskId)` for the durable executor in the same process, or `executorClientBackend(client)` for
an executor reached with a task token. Any object with `prepare` and `execute` works.

## Limits

The adapters add no authority: every decision is still the guard's. They do not detect
prompt injection, and they cover only calls routed through the dispatcher. See
[support and limits](https://github.com/ShieldaAI/agent-guard/blob/main/docs/support-and-limits.md).

Licensed under Apache-2.0.
