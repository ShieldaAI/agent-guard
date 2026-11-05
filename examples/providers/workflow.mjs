import { GuardError, immutableJson } from '@shieldaai/agent-guard';
import { TICKET_TOOLS, TASK_TEXT, SYSTEM_TEXT } from './protected-ticket.mjs';

export class WorkflowError extends Error {
  constructor(code) { super(code); this.name = 'WorkflowError'; this.code = code; }
}
const fail = code => { throw new WorkflowError(code); };
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function bounded(value, bytes) {
  try { return immutableJson(value, 24, 10_000, bytes); } catch { return fail('INVALID_OR_OVERSIZED_JSON'); }
}
function exactKeys(value, allowed) { if (Object.keys(value).some(key => !allowed.includes(key))) fail('INVALID_PROTOCOL'); }
function directCaller(caller) {
  if (caller === undefined || caller === null) return;
  if (!object(caller) || caller.type !== 'direct' || Object.keys(caller).length !== 1) fail('UNSUPPORTED_CALLER');
}

function decodeOpenAI(response) {
  if (!object(response) || response.status !== 'completed' || !Array.isArray(response.output)) fail('INCOMPLETE_RESPONSE');
  const calls = [];
  for (const item of response.output) {
    if (!object(item)) fail('INVALID_PROTOCOL');
    if (item.type === 'function_call') {
      exactKeys(item, ['type', 'id', 'call_id', 'name', 'arguments', 'status', 'caller', 'async', 'namespace']);
      directCaller(item.caller);
      if (item.namespace !== undefined || (item.async !== undefined && item.async !== false)) fail('UNSUPPORTED_CALLER');
      if ((item.status !== undefined && item.status !== 'completed') || !identifier(item.call_id) || !identifier(item.name) || typeof item.arguments !== 'string') fail('INVALID_PROTOCOL');
      let args;
      try { args = JSON.parse(item.arguments); } catch { fail('INVALID_ARGUMENT_JSON'); }
      calls.push({ id: item.call_id, name: item.name, args });
    } else if (item.type === 'message') {
      if (item.role !== 'assistant' || item.status !== 'completed' || !Array.isArray(item.content) || item.content.some(part =>
        !object(part) || !['output_text', 'refusal'].includes(part.type) || typeof (part.text ?? part.refusal) !== 'string')) fail('INVALID_PROTOCOL');
    } else if (item.type !== 'reasoning') fail('UNSUPPORTED_TOOL_OR_CONTENT');
  }
  return { calls, history: response.output };
}
function decodeAnthropic(response) {
  if (!object(response) || response.role !== 'assistant' || !['tool_use', 'end_turn'].includes(response.stop_reason) || !Array.isArray(response.content)) fail('INCOMPLETE_RESPONSE');
  const calls = [];
  for (const block of response.content) {
    if (!object(block)) fail('INVALID_PROTOCOL');
    if (block.type === 'tool_use') {
      exactKeys(block, ['type', 'id', 'name', 'input', 'caller']);
      directCaller(block.caller);
      if (!identifier(block.id) || !identifier(block.name) || !object(block.input)) fail('INVALID_PROTOCOL');
      calls.push({ id: block.id, name: block.name, args: block.input });
    } else if (block.type === 'text') {
      if (typeof block.text !== 'string') fail('INVALID_PROTOCOL');
    } else if (block.type === 'thinking') {
      if (typeof block.thinking !== 'string' || typeof block.signature !== 'string') fail('INVALID_PROTOCOL');
    } else if (block.type === 'redacted_thinking') {
      if (typeof block.data !== 'string') fail('INVALID_PROTOCOL');
    } else fail('UNSUPPORTED_TOOL_OR_CONTENT');
  }
  if ((response.stop_reason === 'tool_use') !== (calls.length > 0)) fail('INVALID_PROTOCOL');
  return { calls, history: { role: 'assistant', content: response.content } };
}

function errorResult(error) {
  return { ok: false, error: error instanceof GuardError || error instanceof WorkflowError ? error.code : 'HOST_OPERATION_FAILED' };
}

/** Build the complete provider request from host-selected controls and the current conversation. */
export function ticketRequest(provider, model, history, maxOutputTokens) {
  if (provider === 'openai') return {
    model, instructions: SYSTEM_TEXT, input: history, stream: false, store: false,
    include: ['reasoning.encrypted_content'], max_output_tokens: maxOutputTokens, parallel_tool_calls: true,
    tools: TICKET_TOOLS.map(tool => ({ type: 'function', name: tool.name, description: tool.description,
      parameters: tool.schema, strict: true, allowed_callers: ['direct'], async: false })),
  };
  if (provider === 'anthropic') return {
    model, system: SYSTEM_TEXT, messages: history, stream: false, max_tokens: maxOutputTokens,
    tools: TICKET_TOOLS.map(tool => ({ name: tool.name, description: tool.description,
      input_schema: tool.schema, strict: true, allowed_callers: ['direct'] })),
  };
  fail('INVALID_CONFIGURATION');
}

/** A completed-response client-tool loop. Transport and review are trusted host callbacks. */
export async function runTicketWorkflow({ provider, model, transport, host, review, signal,
  maxTurns = 6, maxCallsPerTurn = 4, maxOutputTokens = 1024,
  maxResponseBytes = 65_536, maxHistoryBytes = 262_144, timeoutMs = 15_000 } = {}) {
  if (!['openai', 'anthropic'].includes(provider) || typeof model !== 'string' || !model.trim() || model.length > 128 ||
      typeof transport !== 'function' || !host || (review !== undefined && typeof review !== 'function')) fail('INVALID_CONFIGURATION');
  for (const [value, min, max] of [[maxTurns, 1, 12], [maxCallsPerTurn, 1, 8], [maxOutputTokens, 16, 4096],
    [maxResponseBytes, 256, 262_144], [maxHistoryBytes, 4096, 1_048_576], [timeoutMs, 1, 60_000]]) {
    if (!Number.isSafeInteger(value) || value < min || value > max) fail('INVALID_CONFIGURATION');
  }
  host.claim();
  const controller = new AbortController();
  const cancel = () => controller.abort(new WorkflowError('WORKFLOW_ABORTED'));
  const revoke = () => { try { host.revoke(); return true; } catch { return false; } };
  controller.signal.addEventListener('abort', revoke, { once: true });
  signal?.addEventListener('abort', cancel, { once: true });
  const end = performance.now() + timeoutMs;
  const timeout = () => controller.abort(new WorkflowError('WORKFLOW_TIMEOUT'));
  const timer = setTimeout(timeout, timeoutMs);
  if (signal?.aborted) cancel();
  const check = () => {
    // Timers cannot preempt synchronous callbacks or a chain of resolved promises.
    if (!controller.signal.aborted && performance.now() >= end) timeout();
    if (controller.signal.aborted) throw controller.signal.reason;
  };
  async function wait(operation) {
    check();
    let onAbort;
    const aborted = new Promise((_, reject) => {
      onAbort = () => reject(controller.signal.reason);
      controller.signal.addEventListener('abort', onAbort, { once: true });
    });
    try {
      const result = await Promise.race([Promise.resolve().then(() => { check(); return operation(); }), aborted]);
      check();
      return result;
    } finally { controller.signal.removeEventListener('abort', onAbort); }
  }
  const history = [{ role: 'user', content: TASK_TEXT }];
  const seen = new Set();
  const outcomes = [];
  const confirmedActions = [];
  let terminalError;
  try {
    for (let turn = 0; turn < maxTurns; turn++) {
      check();
      const request = bounded(ticketRequest(provider, model, history, maxOutputTokens), maxHistoryBytes);
      let incoming;
      try { incoming = await wait(() => transport(request, { signal: controller.signal })); }
      catch { check(); fail('PROVIDER_TRANSPORT_FAILED'); }
      const response = bounded(incoming, maxResponseBytes);
      const decoded = provider === 'openai' ? decodeOpenAI(response) : decodeAnthropic(response);
      if (decoded.calls.length > maxCallsPerTurn) fail('TOO_MANY_TOOL_CALLS');
      // Validate the whole batch before preparing or dispatching its first action.
      for (const call of decoded.calls) {
        if (seen.has(call.id)) fail('DUPLICATE_CALL_ID');
        seen.add(call.id);
      }
      if (provider === 'openai') history.push(...decoded.history);
      else history.push(decoded.history);
      bounded(history, maxHistoryBytes);
      if (!decoded.calls.length) return { provider, turns: turn + 1, outcomes, history: bounded(history, maxHistoryBytes) };
      const prepared = [];
      let invalidBatch = false;
      for (const call of decoded.calls) {
        try { prepared.push(await wait(() => host.prepare(call))); }
        catch (error) { check(); prepared.push(errorResult(error)); invalidBatch = true; }
      }
      const results = [];
      for (let index = 0; index < decoded.calls.length; index++) {
        check();
        const call = decoded.calls[index];
        let result;
        if (invalidBatch) result = prepared[index].ok === false ? prepared[index] : { ok: false, error: 'BATCH_NOT_EXECUTED' };
        else {
          const action = prepared[index];
          let submitted = false;
          try {
            let approvalId;
            if (action.requiresApproval) {
              if (!review) fail('REVIEW_REQUIRED');
              const request = host.reviewRequest(action);
              const decision = await wait(() => review(request, { signal: controller.signal }));
              check();
              if (decision?.approved === false) {
                // Observing a host rejection cannot turn it into an admitted action.
                try { host.reviewDenied?.(action); } catch { /* Optional observation is best effort. */ }
                fail('REVIEW_DENIED');
              }
              approvalId = host.approve(action, decision);
            }
            check();
            const value = await wait(() => {
              submitted = true;
              return host.execute(action, approvalId);
            });
            result = bounded({ ok: true, value }, 8192);
            confirmedActions.push({ actionId: action.id, tool: action.action.tool });
          } catch (error) {
            // The caller cannot infer the backend outcome from a thrown error, even a timeout.
            // Stop the batch and provider loop; only the host can reconcile a submitted action.
            if (submitted && host.deniedBeforeDispatch?.(error) !== true) {
              const incident = new WorkflowError('TOOL_OUTCOME_UNCONFIRMED');
              incident.actionId = action.id; // For the host's operator, never sent to the provider.
              throw incident;
            }
            check(); result = errorResult(error);
          }
        }
        const safeResult = bounded(result, 8192);
        outcomes.push({ callId: call.id, tool: call.name, ...safeResult });
        results.push(provider === 'openai'
          ? { type: 'function_call_output', call_id: call.id, output: JSON.stringify(safeResult) }
          : { type: 'tool_result', tool_use_id: call.id, content: JSON.stringify(safeResult), is_error: !safeResult.ok });
      }
      if (provider === 'openai') history.push(...results);
      else history.push({ role: 'user', content: results });
      bounded(history, maxHistoryBytes);
    }
    fail('TURN_LIMIT_EXCEEDED');
  } catch (error) {
    const incident = error instanceof WorkflowError ? error : new WorkflowError('HOST_OPERATION_FAILED');
    // A later provider failure must not erase already-confirmed operations from the host's view.
    if (confirmedActions.length) incident.confirmedActions = immutableJson(confirmedActions);
    terminalError = incident;
    throw incident;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
    controller.signal.removeEventListener('abort', revoke);
    if (!revoke()) {
      if (terminalError) terminalError.cleanupCode = 'TASK_REVOCATION_UNCONFIRMED';
      else {
        const incident = new WorkflowError('TASK_REVOCATION_UNCONFIRMED');
        if (confirmedActions.length) incident.confirmedActions = immutableJson(confirmedActions);
        throw incident;
      }
    }
  }
}
