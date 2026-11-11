import { GuardError, type Json, type ToolDefinition } from '@shieldaai/agent-guard';
import { ExecutorClient } from './client.js';

export interface ModelResult {
  text: string;
  inputTokens?: number;
  outputTokens?: number;
  cost?: number;
  outputComplete?: boolean;
}
export interface ModelToolOptions {
  name: string;
  model: string;
  tenantId: string;
  recipient: string;
  maxCost: number;
  maxOutputTokens: number;
  maxPromptChars?: number;
  /** Host-owned provider and credentials; actualCost is in the executor's integer units. */
  complete(
    prompt: string,
    options: { maxOutputTokens: number; signal: AbortSignal },
  ): Promise<{ response: ModelResult; actualCost?: number }>;
}
/** Each dispatch reserves the tool's maximum cost in the executor before calling the credential owner. */
export function createModelTool(options: ModelToolOptions): ToolDefinition {
  const {
    name,
    model,
    tenantId,
    recipient,
    complete,
    maxCost,
    maxOutputTokens,
    maxPromptChars: maxPrompt = 131_072,
  } = options;
  if (
    typeof complete !== 'function' ||
    !Number.isSafeInteger(maxPrompt) ||
    maxPrompt < 1 ||
    !Number.isSafeInteger(maxOutputTokens) ||
    maxOutputTokens < 1
  )
    throw new GuardError('INVALID_INPUT');
  const callProvider = complete.bind(options);
  return {
    name,
    description: `Bounded provider request for ${model}`,
    maxCost,
    metadata: { model, tenantId, recipient, maxOutputTokens, maxPromptChars: maxPrompt },
    parse(value) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new GuardError('ARGUMENT_INVALID');
      const input = value as Record<string, Json>;
      if (
        Object.keys(input).some(key => !['prompt', 'maxOutputTokens'].includes(key)) ||
        typeof input.prompt !== 'string' ||
        input.prompt.length > maxPrompt ||
        !Number.isSafeInteger(input.maxOutputTokens) ||
        Number(input.maxOutputTokens) < 1 ||
        Number(input.maxOutputTokens) > maxOutputTokens
      )
        throw new GuardError('ARGUMENT_INVALID');
      return value;
    },
    resolve: () => ({ resourceId: model, tenantId, external: true, recipient }),
    async execute(args, context) {
      const input = args as { prompt: string; maxOutputTokens: number };
      const result = await callProvider(input.prompt, {
        maxOutputTokens: input.maxOutputTokens,
        signal: context.signal,
      });
      const { text, inputTokens, outputTokens, cost, outputComplete } = result.response;
      if (
        typeof text !== 'string' ||
        text.length > 1_048_576 ||
        (outputComplete !== undefined && outputComplete !== true) ||
        (cost !== undefined && (!Number.isFinite(cost) || cost < 0))
      )
        throw new GuardError('RESULT_INVALID');
      for (const value of [inputTokens, outputTokens])
        if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) throw new GuardError('RESULT_INVALID');
      // Provider SDK responses can carry request headers and internal diagnostics alongside the public result.
      const value = {
        text,
        model,
        ...(inputTokens === undefined ? {} : { inputTokens }),
        ...(outputTokens === undefined ? {} : { outputTokens }),
        ...(cost === undefined ? {} : { cost }),
        ...(outputComplete === undefined ? {} : { outputComplete }),
      };
      return { value, ...(result.actualCost === undefined ? {} : { actualCost: result.actualCost }) };
    },
  };
}

/** Structurally implements SafeCall Node's Provider without coupling the two packages. Streaming is buffered. */
export function createExecutorModelProvider(options: {
  client: ExecutorClient;
  tool: string;
  model: string;
  maxOutputTokens: number;
}): {
  model: string;
  complete(prompt: string, params?: Record<string, unknown>): Promise<ModelResult>;
  stream(prompt: string, params?: Record<string, unknown>): AsyncIterable<string>;
} {
  const complete = async (prompt: string, params: Record<string, unknown> = {}): Promise<ModelResult> => {
    const signal = params.signal instanceof AbortSignal ? params.signal : undefined;
    const maxOutputTokens = params.maxTokens ?? options.maxOutputTokens;
    const action = await options.client.prepare(
      options.tool,
      { prompt, maxOutputTokens: maxOutputTokens as number },
      signal,
    );
    const result = await options.client.execute(action.id, signal ? { signal } : {});
    if (
      !result ||
      typeof result !== 'object' ||
      Array.isArray(result) ||
      typeof (result as { text?: unknown }).text !== 'string'
    )
      throw new GuardError('RESULT_INVALID');
    return result as unknown as ModelResult;
  };
  return {
    model: options.model,
    complete,
    async *stream(prompt, params) {
      yield (await complete(prompt, params)).text;
    },
  };
}
