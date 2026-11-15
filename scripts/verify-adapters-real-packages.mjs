// Runs the framework adapters against the real framework packages, and type-checks the
// provider adapters against the official provider SDKs. Not part of `npm test`: it needs
// those packages, which are not dependencies of this repository.
//
//   node scripts/verify-adapters-real-packages.mjs <empty directory> --install
//   node scripts/verify-adapters-real-packages.mjs <directory where they are installed>
//
// --install runs `npm install --ignore-scripts` of the latest versions in that directory.
// Build first (npm run build).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { trustedNpmCli } from './trusted-npm.mjs';

const PACKAGES = [
  'ai',
  '@openai/agents',
  '@langchain/core',
  '@langchain/langgraph',
  'zod',
  '@anthropic-ai/sdk',
  'openai',
  '@google/genai',
  '@aws-sdk/client-bedrock-runtime',
  'typescript',
  '@types/node',
];
const repo = fileURLToPath(new URL('..', import.meta.url));
if (!process.argv[2] || process.argv[2].startsWith('--')) {
  console.error('Usage: node scripts/verify-adapters-real-packages.mjs <directory> [--install]');
  process.exit(2);
}
const frameworks = resolve(process.argv[2]);
if (process.argv.includes('--install')) {
  mkdirSync(frameworks, { recursive: true });
  if (!existsSync(join(frameworks, 'package.json')))
    writeFileSync(join(frameworks, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  const installed = spawnSync(
    process.execPath,
    [trustedNpmCli(), 'install', '--ignore-scripts', '--no-audit', '--no-fund', ...PACKAGES],
    { cwd: frameworks, stdio: 'inherit' },
  );
  if (installed.status !== 0) process.exit(installed.status ?? 1);
}
const require = createRequire(join(frameworks, 'package.json'));
const version = name =>
  JSON.parse(readFileSync(join(frameworks, 'node_modules', name, 'package.json'), 'utf8')).version;
console.log(PACKAGES.map(name => `${name}@${version(name)}`).join(' '));
const fw = name => import(pathToFileURL(require.resolve(name)).href);
const ag = await import(pathToFileURL(join(repo, 'packages/core/dist/index.js')).href);
const ad = await import(pathToFileURL(join(repo, 'packages/adapters/dist/index.js')).href);

function desk() {
  const guard = new ag.AgentGuard();
  const schema = {
    type: 'object',
    properties: { id: { type: 'string' } },
    required: ['id'],
    additionalProperties: false,
  };
  const runs = [];
  const resolveTicket = args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' });
  ad.registerApprovedTools(guard, [
    {
      name: 'ticket_read',
      description: 'Read one support ticket',
      inputSchema: schema,
      parse: ad.jsonSchemaParser(schema),
      resolve: resolveTicket,
      execute: args => (runs.push(args.id), { value: { id: args.id, subject: 'Refund' } }),
    },
    {
      name: 'ticket_close',
      description: 'Close one support ticket',
      inputSchema: schema,
      parse: ad.jsonSchemaParser(schema),
      requiresApproval: true,
      resolve: resolveTicket,
      execute: args => (runs.push(`close ${args.id}`), { value: { closed: args.id } }),
    },
  ]);
  const task = guard.createTask({
    id: 't',
    principalId: 'p',
    tenantId: 'acme',
    grants: [
      { tool: 'ticket_read', resources: ['ticket:42'] },
      { tool: 'ticket_close', resources: ['ticket:42'] },
    ],
    budget: ad.taskBudget({ maxCalls: 10, ttlMs: 60_000 }),
  });
  const approvals = new ad.ApprovalQueue({
    onPending: entry => setImmediate(() => approvals.approve(entry.actionId, { approverId: 'alice' })),
  });
  const dispatch = ad.createDispatcher({ guard, task }, { approvals, waitForApproval: { timeoutMs: 5000 } });
  return { runs, dispatch, specs: ad.toolSpecs(guard, ['ticket_read', 'ticket_close']) };
}
const parse = value => (typeof value === 'string' ? JSON.parse(value) : value);

// ---- Vercel AI SDK: a full generateText loop with a scripted model.
{
  const { generateText, jsonSchema, stepCountIs } = await fw('ai');
  const test = await fw('ai/test');
  const Mock = test.MockLanguageModelV4 ?? test.MockLanguageModelV3;
  const d = desk();
  const usage = {
    inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
    outputTokens: { total: 1, text: 1, reasoning: 0 },
  };
  const toolCalls = (...calls) => ({
    content: calls.map(([toolCallId, toolName, input]) => ({ type: 'tool-call', toolCallId, toolName, input })),
    finishReason: { unified: 'tool-calls', raw: 'tool_use' },
    usage,
    warnings: [],
  });
  const steps = [
    toolCalls(['c1', 'ticket_read', '{"id":"42"}'], ['c2', 'ticket_read', '{"id":"7"}']),
    toolCalls(['c3', 'ticket_close', '{"id":"42"}']),
    { content: [{ type: 'text', text: 'done' }], finishReason: { unified: 'stop', raw: 'stop' }, usage, warnings: [] },
  ];
  const offered = [];
  const model = new Mock({
    doGenerate: async options => {
      offered.push(options.tools?.map(tool => tool.name));
      return steps.shift();
    },
  });
  const result = await generateText({
    model,
    tools: ad.aiSdkTools(d.dispatch, d.specs, { jsonSchema }),
    stopWhen: stepCountIs(5),
    prompt: 'triage',
  });
  const outputs = result.steps.flatMap(step =>
    step.toolResults.map(r => [r.toolName, r.output.status, r.output.code ?? null]),
  );
  assert.deepEqual(outputs, [
    ['ticket_read', 'ok', null],
    ['ticket_read', 'denied', 'GRANT_DENIED'],
    ['ticket_close', 'ok', null],
  ]);
  assert.deepEqual(d.runs, ['42', 'close 42']);
  assert.deepEqual(offered[0], ['ticket_read', 'ticket_close']);
  assert.equal(result.text, 'done');
  console.log('ai generateText loop: PASS');
}

// ---- OpenAI Agents SDK: real tool() objects invoked the way the runner invokes them.
{
  const { tool, RunContext } = await fw('@openai/agents');
  const d = desk();
  const tools = ad.openAIAgentsTools(d.dispatch, d.specs, { tool });
  assert.equal(tools[0].type, 'function');
  assert.equal(tools[0].name, 'ticket_read');
  assert.equal(tools[0].strict, false);
  assert.deepEqual(tools[0].parameters.required, ['id']);
  const context = new RunContext({});
  assert.equal(parse(await tools[0].invoke(context, '{"id":"42"}')).status, 'ok');
  assert.equal(parse(await tools[0].invoke(context, '{"id":"7"}')).code, 'GRANT_DENIED');
  assert.equal(parse(await tools[1].invoke(context, '{"id":"42"}')).status, 'ok');
  assert.deepEqual(d.runs, ['42', 'close 42']);
  console.log('@openai/agents tool().invoke: PASS');
}

// ---- LangChain.js: real tool() with JSON Schema, plus a LangGraph ToolNode.
{
  const { tool } = await fw('@langchain/core/tools');
  const { AIMessage } = await fw('@langchain/core/messages');
  const { ToolNode } = await fw('@langchain/langgraph/prebuilt');
  const d = desk();
  const tools = ad.langChainTools(d.dispatch, d.specs, { tool });
  assert.equal(tools[0].name, 'ticket_read');
  assert.equal(JSON.parse(await tools[0].invoke({ id: '42' })).status, 'ok');
  assert.equal(JSON.parse(await tools[0].invoke({ id: '7' })).code, 'GRANT_DENIED');
  const node = new ToolNode(tools);
  const out = await node.invoke({
    messages: [
      new AIMessage({
        content: '',
        tool_calls: [
          { id: 'a', name: 'ticket_read', args: { id: '42' } },
          { id: 'b', name: 'ticket_close', args: { id: '42' } },
        ],
      }),
    ],
  });
  assert.deepEqual(
    out.messages.map(message => JSON.parse(message.content).status),
    ['ok', 'ok'],
  );
  assert.deepEqual(d.runs, ['42', '42', 'close 42']);
  console.log('@langchain/core tool() + LangGraph ToolNode: PASS');
}

// ---- Standard Schema with real Zod.
{
  const { z } = await fw('zod');
  const parseTicket = ad.standardSchemaParser(z.object({ id: z.string().regex(/^\d+$/) }).strict());
  assert.deepEqual(parseTicket({ id: '42' }), { id: '42' });
  assert.throws(() => parseTicket({ id: 'x' }), { code: 'SCHEMA_MISMATCH' });
  console.log('zod standardSchemaParser: PASS');
}

// ---- Provider SDK types: every adapter output must be assignable to the SDK's own type.
{
  const adapters = join(repo, 'packages/adapters/dist/index.js').replaceAll('\\', '/');
  const source = [
    "import type Anthropic from '@anthropic-ai/sdk';",
    "import type OpenAI from 'openai';",
    "import type { Tool as GeminiSdkTool, Part, FunctionCall } from '@google/genai';",
    "import type { Tool as BedrockSdkTool, ContentBlock } from '@aws-sdk/client-bedrock-runtime';",
    `import * as ad from '${adapters}';`,
    'declare const specs: readonly ad.ToolSpec[];',
    'declare const dispatch: ad.Dispatcher;',
    'const aTools: Anthropic.Messages.ToolUnion[] = ad.anthropicTools(specs);',
    'declare const aMessage: Anthropic.Messages.Message;',
    'const aResults: Anthropic.Messages.ToolResultBlockParam[] = await ad.anthropicToolResults(aMessage.content, dispatch);',
    "const aNext: Anthropic.Messages.MessageParam = { role: 'user', content: aResults };",
    'const rTools: OpenAI.Responses.Tool[] = ad.openAIResponsesTools(specs);',
    'declare const response: OpenAI.Responses.Response;',
    'const rOut: OpenAI.Responses.ResponseInputItem[] = await ad.openAIResponsesToolOutputs(response.output, dispatch);',
    'const cTools: OpenAI.Chat.ChatCompletionTool[] = ad.openAIChatTools(specs);',
    'declare const completion: OpenAI.Chat.ChatCompletion;',
    'const cMsgs: OpenAI.Chat.ChatCompletionMessageParam[] = await ad.openAIChatToolMessages(completion.choices[0]!.message.tool_calls, dispatch);',
    'const gTools: GeminiSdkTool[] = ad.geminiTools(specs);',
    'declare const calls: FunctionCall[] | undefined;',
    'const gParts: Part[] = await ad.geminiFunctionResponses(calls, dispatch);',
    'const bTools: BedrockSdkTool[] = ad.bedrockTools(specs);',
    'declare const bContent: ContentBlock[];',
    'const bResults: ContentBlock[] = await ad.bedrockToolResults(bContent, dispatch);',
    'export { aTools, aNext, rTools, rOut, cTools, cMsgs, gTools, gParts, bTools, bResults };',
  ].join('\n');
  writeFileSync(join(frameworks, 'agent-guard-adapters-check.mts'), source);
  writeFileSync(
    join(frameworks, 'agent-guard-adapters-tsconfig.json'),
    JSON.stringify({
      compilerOptions: {
        target: 'ES2022',
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        strict: true,
        noEmit: true,
        skipLibCheck: true,
        types: ['node'],
      },
      files: ['agent-guard-adapters-check.mts'],
    }),
  );
  const tsc = spawnSync(
    process.execPath,
    [join(frameworks, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'agent-guard-adapters-tsconfig.json'],
    { cwd: frameworks, encoding: 'utf8' },
  );
  assert.equal(tsc.status, 0, tsc.stdout + tsc.stderr);
  console.log('provider SDK types (Anthropic, OpenAI Responses and Chat, Gemini, Bedrock): PASS');
}
