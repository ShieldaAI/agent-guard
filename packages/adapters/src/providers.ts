import type { Dispatcher, ToolCall } from './dispatcher.js';
import { adapterDenial, hostErrorOutcome, isErrorOutcome, outcomeForModel, type DispatchOutcome } from './outcomes.js';

/**
 * Calls the dispatcher and never throws: a dispatcher from `createDispatcher` already turns
 * host errors into outcomes, and for any other dispatcher a throw becomes a HOST_ERROR outcome
 * (effect unknown), so one broken call cannot lose the rest of a model turn or reach the model.
 */
export async function safeDispatch(
  dispatch: Dispatcher,
  call: ToolCall,
  signal?: AbortSignal,
): Promise<DispatchOutcome> {
  try {
    return await dispatch(call, signal === undefined ? {} : { signal });
  } catch {
    return hostErrorOutcome(call.name, 'execute');
  }
}
import { objectSchema, plainJson, type ObjectSchema, type PlainJson, type ToolSpec } from './tools.js';
import { AdapterError } from './errors.js';

/** Options shared by every `*ToolResults` function. */
export interface RunOptions {
  /** Passed to each dispatch. */
  signal?: AbortSignal;
  /**
   * Run the calls of one model turn at the same time. Default false: one after another, in the
   * order the model sent them, which is what a task with `maxConcurrent: 1` expects.
   */
  parallel?: boolean;
  /** Receives each outcome with the provider's call ID, for example to track waiting actions. */
  onOutcome?: (outcome: DispatchOutcome, callId: string) => void;
}

type Job = { id: string; call: ToolCall | undefined; tool: string };

async function runAll(dispatch: Dispatcher, jobs: readonly Job[], options: RunOptions = {}) {
  if (typeof dispatch !== 'function') throw new AdapterError('INVALID_OPTIONS');
  const run = async (job: Job): Promise<DispatchOutcome> => {
    const outcome =
      job.call === undefined
        ? adapterDenial(job.tool, 'INPUT_NOT_JSON')
        : await safeDispatch(dispatch, job.call, options.signal);
    try {
      options.onOutcome?.(outcome, job.id);
    } catch {
      // Hooks observe only.
    }
    return outcome;
  };
  if (options.parallel === true) return Promise.all(jobs.map(run));
  const outcomes: DispatchOutcome[] = [];
  for (const job of jobs) outcomes.push(await run(job));
  return outcomes;
}

/** Parses provider argument text. Returns undefined when it is not JSON. Empty text means `{}`. */
export function parseToolArguments(text: unknown): unknown {
  if (typeof text !== 'string') return text ?? {};
  if (text.trim() === '') return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}
function textJob(id: string, name: string, args: unknown): Job {
  const input = parseToolArguments(args);
  return { id, tool: name, call: input === undefined ? undefined : { id, name, input } };
}
function serialized(outcome: DispatchOutcome): string {
  return JSON.stringify(outcomeForModel(outcome));
}
function list<T>(value: unknown): readonly T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

// ---------------------------------------------------------------- Anthropic Messages API

/** A tool for the Anthropic Messages API `tools` parameter. */
export interface AnthropicTool {
  name: string;
  description: string;
  input_schema: ObjectSchema;
}
/** Tools in the Anthropic Messages API format. */
export function anthropicTools(specs: readonly ToolSpec[]): AnthropicTool[] {
  return specs.map(spec => ({
    name: spec.name,
    description: spec.description,
    input_schema: objectSchema(spec.inputSchema),
  }));
}
/** A `tool_result` content block for the next user message. */
export interface AnthropicToolResult {
  type: 'tool_result';
  tool_use_id: string;
  content: string;
  is_error?: true;
}
/**
 * Runs every `tool_use` block of an assistant message through the dispatcher and returns the
 * `tool_result` blocks, in order. Send them as the content of the next `user` message.
 * Denials and failures are marked `is_error`.
 */
export async function anthropicToolResults(
  content: readonly unknown[],
  dispatch: Dispatcher,
  options?: RunOptions,
): Promise<AnthropicToolResult[]> {
  const blocks = list<{ type?: unknown; id?: unknown; name?: unknown; input?: unknown }>(content).filter(
    block => block?.type === 'tool_use' && typeof block.id === 'string' && typeof block.name === 'string',
  );
  const jobs = blocks.map(block => ({
    id: block.id as string,
    tool: block.name as string,
    call: { id: block.id as string, name: block.name as string, input: block.input ?? {} },
  }));
  const outcomes = await runAll(dispatch, jobs, options);
  return outcomes.map((outcome, index) => ({
    type: 'tool_result',
    tool_use_id: jobs[index]!.id,
    content: serialized(outcome),
    ...(isErrorOutcome(outcome) ? { is_error: true as const } : {}),
  }));
}

// ---------------------------------------------------------------- OpenAI Responses API

/** A function tool for the OpenAI Responses API. */
export interface OpenAIResponsesTool {
  type: 'function';
  name: string;
  description: string;
  parameters: ObjectSchema;
  strict: boolean;
}
/**
 * Tools in the OpenAI Responses API format. `strict` defaults to false because strict mode
 * needs every property required and `additionalProperties: false`; turn it on only for
 * schemas written that way.
 */
export function openAIResponsesTools(
  specs: readonly ToolSpec[],
  options: { strict?: boolean } = {},
): OpenAIResponsesTool[] {
  return specs.map(spec => ({
    type: 'function',
    name: spec.name,
    description: spec.description,
    parameters: objectSchema(spec.inputSchema),
    strict: options.strict === true,
  }));
}
/** A `function_call_output` item for the next request's `input`. */
export interface OpenAIFunctionCallOutput {
  type: 'function_call_output';
  call_id: string;
  output: string;
}
/** Runs every `function_call` item of a response's `output` and returns the `function_call_output` items. */
export async function openAIResponsesToolOutputs(
  output: readonly unknown[],
  dispatch: Dispatcher,
  options?: RunOptions,
): Promise<OpenAIFunctionCallOutput[]> {
  const items = list<{ type?: unknown; call_id?: unknown; name?: unknown; arguments?: unknown }>(output).filter(
    item => item?.type === 'function_call' && typeof item.call_id === 'string' && typeof item.name === 'string',
  );
  const jobs = items.map(item => textJob(item.call_id as string, item.name as string, item.arguments));
  const outcomes = await runAll(dispatch, jobs, options);
  return outcomes.map((outcome, index) => ({
    type: 'function_call_output',
    call_id: jobs[index]!.id,
    output: serialized(outcome),
  }));
}

// ---------------------------------------------------------------- OpenAI Chat Completions API

/** A function tool for the OpenAI Chat Completions API (and compatible APIs: Groq, Mistral, vLLM, Ollama, ...). */
export interface OpenAIChatTool {
  type: 'function';
  function: { name: string; description: string; parameters: ObjectSchema; strict?: boolean };
}
/** Tools in the Chat Completions format. */
export function openAIChatTools(specs: readonly ToolSpec[], options: { strict?: boolean } = {}): OpenAIChatTool[] {
  return specs.map(spec => ({
    type: 'function',
    function: {
      name: spec.name,
      description: spec.description,
      parameters: objectSchema(spec.inputSchema),
      ...(options.strict === true ? { strict: true } : {}),
    },
  }));
}
/** A `tool` role message answering one tool call. */
export interface OpenAIChatToolMessage {
  role: 'tool';
  tool_call_id: string;
  content: string;
}
/** Runs every entry of an assistant message's `tool_calls` and returns one `tool` message for each. */
export async function openAIChatToolMessages(
  toolCalls: readonly unknown[] | null | undefined,
  dispatch: Dispatcher,
  options?: RunOptions,
): Promise<OpenAIChatToolMessage[]> {
  const calls = list<{ id?: unknown; type?: unknown; function?: { name?: unknown; arguments?: unknown } }>(
    toolCalls,
  ).filter(
    call =>
      typeof call?.id === 'string' &&
      (call.type ?? 'function') === 'function' &&
      typeof call.function?.name === 'string',
  );
  const jobs = calls.map(call => textJob(call.id as string, call.function!.name as string, call.function!.arguments));
  const outcomes = await runAll(dispatch, jobs, options);
  return outcomes.map((outcome, index) => ({
    role: 'tool',
    tool_call_id: jobs[index]!.id,
    content: serialized(outcome),
  }));
}

// ---------------------------------------------------------------- Google Gemini API

/** A tool entry for the Gemini API (`@google/genai`) `config.tools`. */
export interface GeminiTool {
  functionDeclarations: { name: string; description: string; parametersJsonSchema: ObjectSchema }[];
}
/** Tools in the Gemini format, as one entry with every function declaration. */
export function geminiTools(specs: readonly ToolSpec[]): GeminiTool[] {
  return [
    {
      functionDeclarations: specs.map(spec => ({
        name: spec.name,
        description: spec.description,
        parametersJsonSchema: objectSchema(spec.inputSchema),
      })),
    },
  ];
}
/** A `functionResponse` part for the next `user` content. */
export interface GeminiFunctionResponsePart {
  functionResponse: { id?: string; name: string; response: { [key: string]: PlainJson } };
}
/**
 * Runs each function call (`response.functionCalls`, or the `functionCall` of each part) and
 * returns `functionResponse` parts in order. Calls without an ID are matched by position.
 */
export async function geminiFunctionResponses(
  functionCalls: readonly unknown[] | null | undefined,
  dispatch: Dispatcher,
  options?: RunOptions,
): Promise<GeminiFunctionResponsePart[]> {
  const calls = list<{ id?: unknown; name?: unknown; args?: unknown; functionCall?: unknown }>(functionCalls)
    .map(entry => (entry && typeof entry === 'object' && 'functionCall' in entry ? entry.functionCall : entry))
    .filter(
      (call): call is { id?: unknown; name: string; args?: unknown } =>
        call !== null && typeof call === 'object' && typeof (call as { name?: unknown }).name === 'string',
    );
  const jobs = calls.map((call, index) => {
    const id = typeof call.id === 'string' ? call.id : `#${index}`;
    return { id, tool: call.name, call: { id, name: call.name, input: call.args ?? {} } };
  });
  const outcomes = await runAll(dispatch, jobs, options);
  return outcomes.map((outcome, index) => {
    const call = calls[index]!;
    return {
      functionResponse: {
        ...(typeof call.id === 'string' ? { id: call.id } : {}),
        name: call.name,
        response: plainJson(outcomeForModel(outcome)) as { [key: string]: PlainJson },
      },
    };
  });
}

// ---------------------------------------------------------------- Amazon Bedrock Converse API

/** A tool for the Bedrock Converse API `toolConfig.tools`. */
export interface BedrockTool {
  toolSpec: { name: string; description: string; inputSchema: { json: ObjectSchema } };
}
/** Tools in the Bedrock Converse format. */
export function bedrockTools(specs: readonly ToolSpec[]): BedrockTool[] {
  return specs.map(spec => ({
    toolSpec: { name: spec.name, description: spec.description, inputSchema: { json: objectSchema(spec.inputSchema) } },
  }));
}
/** A `toolResult` content block for the next `user` message. */
export interface BedrockToolResult {
  toolResult: { toolUseId: string; content: [{ json: PlainJson }]; status?: 'success' | 'error' };
}
/**
 * Runs every `toolUse` block of an assistant message and returns the `toolResult` blocks.
 * Bedrock accepts `status` only for some model families (Anthropic Claude, Amazon Nova), so it
 * is added only with `includeStatus: true`; the outcome's own `status` field is always there.
 */
export async function bedrockToolResults(
  content: readonly unknown[],
  dispatch: Dispatcher,
  options?: RunOptions & { includeStatus?: boolean },
): Promise<BedrockToolResult[]> {
  const uses = list<{ toolUse?: { toolUseId?: unknown; name?: unknown; input?: unknown } }>(content)
    .map(block => block?.toolUse)
    .filter(
      (use): use is { toolUseId: string; name: string; input?: unknown } =>
        typeof use?.toolUseId === 'string' && typeof use.name === 'string',
    );
  const jobs = uses.map(use => ({
    id: use.toolUseId,
    tool: use.name,
    call: { id: use.toolUseId, name: use.name, input: use.input ?? {} },
  }));
  const outcomes = await runAll(dispatch, jobs, options);
  return outcomes.map((outcome, index) => ({
    toolResult: {
      toolUseId: jobs[index]!.id,
      content: [{ json: plainJson(outcomeForModel(outcome)) }],
      ...(options?.includeStatus === true ? { status: isErrorOutcome(outcome) ? 'error' : 'success' } : {}),
    },
  }));
}
