// Blocked calls through every adapter. Matching an SDK's types proves the shape of a result,
// not its meaning: these tests prove that a denied call and a call waiting for a person run
// nothing, and that every adapter reports them to the model as blocked, never as a success.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ApprovalQueue,
  aiSdkTools,
  anthropicToolResults,
  bedrockToolResults,
  createDispatcher,
  geminiFunctionResponses,
  langChainTools,
  mcpServerTools,
  openAIAgentsTools,
  openAIChatToolMessages,
  openAIResponsesToolOutputs,
  toolSpecs,
} from '../dist/index.js';
import { ticketDesk } from './helpers.mjs';

const parse = value => (typeof value === 'string' ? JSON.parse(value) : value);

/**
 * Each adapter, driven the way its provider or framework drives it, for one tool call.
 * Returns what the model is sent, and the format's own error flag (null when the format has none).
 */
const ADAPTERS = {
  'Anthropic Messages': async (dispatch, specs, name, input) => {
    const [block] = await anthropicToolResults([{ type: 'tool_use', id: 'toolu_1', name, input }], dispatch);
    return { sent: parse(block.content), error: block.is_error === true };
  },
  'OpenAI Responses': async (dispatch, specs, name, input) => {
    const output = [{ type: 'function_call', call_id: 'call_1', name, arguments: JSON.stringify(input) }];
    const [item] = await openAIResponsesToolOutputs(output, dispatch);
    return { sent: parse(item.output), error: null };
  },
  'OpenAI Chat Completions': async (dispatch, specs, name, input) => {
    const calls = [{ id: 'call_1', type: 'function', function: { name, arguments: JSON.stringify(input) } }];
    const [message] = await openAIChatToolMessages(calls, dispatch);
    return { sent: parse(message.content), error: null };
  },
  'Google Gemini': async (dispatch, specs, name, input) => {
    const [part] = await geminiFunctionResponses([{ id: 'fc_1', name, args: input }], dispatch);
    return { sent: part.functionResponse.response, error: null };
  },
  'Amazon Bedrock Converse': async (dispatch, specs, name, input) => {
    const content = [{ toolUse: { toolUseId: 'tu_1', name, input } }];
    const [block] = await bedrockToolResults(content, dispatch, { includeStatus: true });
    return { sent: block.toolResult.content[0].json, error: block.toolResult.status === 'error' };
  },
  'Vercel AI SDK': async (dispatch, specs, name, input) => {
    const tools = aiSdkTools(dispatch, specs, { jsonSchema: schema => schema });
    return { sent: await tools[name].execute(input, { toolCallId: 'c1' }), error: null };
  },
  'OpenAI Agents SDK': async (dispatch, specs, name, input) => {
    const tool = openAIAgentsTools(dispatch, specs, { tool: config => config }).find(t => t.name === name);
    return { sent: parse(await tool.execute(JSON.stringify(input))), error: null };
  },
  'LangChain.js': async (dispatch, specs, name, input) => {
    const tools = langChainTools(dispatch, specs, { tool: (func, fields) => ({ func, name: fields.name }) });
    return { sent: parse(await tools.find(t => t.name === name).func(input)), error: null };
  },
  'MCP server': async (dispatch, specs, name, input) => {
    const result = await mcpServerTools(dispatch, specs).callTool({ name, arguments: input });
    assert.deepEqual(parse(result.content[0].text), result.structuredContent, 'text and structured content agree');
    return { sent: result.structuredContent, error: result.isError };
  },
};

function setup(dispatcherOptions = {}) {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue();
  const dispatch = createDispatcher(desk, { approvals, ...dispatcherOptions });
  return { desk, approvals, dispatch, specs: toolSpecs(desk.guard, ['ticket.read', 'ticket.close']) };
}

/** What every blocked answer must look like to the model, whatever the adapter. */
function assertBlocked(sent, status, code) {
  assert.equal(sent.status, status);
  if (code !== undefined) assert.equal(sent.code, code);
  assert.notEqual(sent.status, 'ok');
  assert.equal('result' in sent, false, 'a blocked call carries no result');
  assert.equal(typeof sent.message, 'string');
}

for (const [adapter, run] of Object.entries(ADAPTERS)) {
  test(`${adapter}: a denied call runs nothing and reaches the model as denied`, async () => {
    const { desk, approvals, dispatch, specs } = setup();
    const { sent, error } = await run(dispatch, specs, 'ticket.read', { id: '7' });
    assertBlocked(sent, 'denied', 'GRANT_DENIED');
    assert.equal(sent.retryable, false);
    if (error !== null) assert.equal(error, true, 'the format marks it as an error');
    assert.deepEqual(desk.runs, []);
    assert.deepEqual(approvals.pending(), []);
  });

  test(`${adapter}: a call that needs approval runs nothing until a person approves it`, async () => {
    const { desk, approvals, dispatch, specs } = setup();
    const { sent, error } = await run(dispatch, specs, 'ticket.close', { id: '42' });
    assertBlocked(sent, 'waiting_for_approval');
    assert.equal(typeof sent.actionId, 'string');
    if (error !== null) assert.equal(error, false, 'waiting is not a failure');
    assert.deepEqual(desk.runs, []);
    const [pending] = approvals.pending();
    assert.equal(pending.actionId, sent.actionId);
    assert.equal(pending.action.resourceId, 'ticket:42');
    // A rejection still runs nothing; only an approval runs the action, exactly once.
    approvals.reject(pending.actionId);
    assert.deepEqual(desk.runs, []);
    const second = await run(dispatch, specs, 'ticket.close', { id: '42' });
    const outcome = await approvals.approve(second.sent.actionId, { approverId: 'alice' });
    assert.equal(outcome.status, 'ok');
    assert.deepEqual(desk.runs, [['ticket.close', '42']]);
  });

  test(`${adapter}: a call that waits for a person and is rejected reaches the model as denied`, async () => {
    const desk = ticketDesk();
    // The reviewer rejects as soon as the action starts waiting.
    const approvals = new ApprovalQueue({ onPending: entry => approvals.reject(entry.actionId) });
    const dispatch = createDispatcher(desk, { approvals, waitForApproval: { timeoutMs: 5_000 } });
    const specs = toolSpecs(desk.guard, ['ticket.read', 'ticket.close']);
    const { sent, error } = await run(dispatch, specs, 'ticket.close', { id: '42' });
    assertBlocked(sent, 'denied', 'APPROVAL_REJECTED');
    if (error !== null) assert.equal(error, true);
    assert.deepEqual(desk.runs, []);
  });

  test(`${adapter}: a call whose wait for a person runs out reaches the model as denied`, async () => {
    const { desk, approvals, dispatch, specs } = setup({ waitForApproval: { timeoutMs: 20 } });
    const { sent, error } = await run(dispatch, specs, 'ticket.close', { id: '42' });
    assertBlocked(sent, 'denied', 'APPROVAL_TIMEOUT');
    if (error !== null) assert.equal(error, true);
    assert.deepEqual(desk.runs, []);
    assert.deepEqual(approvals.pending(), [], 'the timed-out action is dropped');
  });
}
