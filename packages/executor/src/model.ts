import { GuardError, type Json, type ToolDefinition } from '@shieldaai/agent-guard';
import { ExecutorClient } from './client.js';

export interface ModelResult { text: string; inputTokens?: number; outputTokens?: number; cost?: number; outputComplete?: boolean }
export interface ModelToolOptions {
  name: string; model: string; tenantId: string; recipient: string;
  maxCost: number; maxOutputTokens: number; maxPromptChars?: number;
  /** Host-owned provider and credentials; actualCost is in the executor's integer units. */
  complete(prompt: string, options: { maxOutputTokens: number; signal: AbortSignal }): Promise<{ response: ModelResult; actualCost?: number }>;
}
/** Each dispatch reserves the tool's maximum cost in the executor before calling the credential owner. */
export function createModelTool(options: ModelToolOptions): ToolDefinition {
  const maxPrompt = options.maxPromptChars ?? 131_072;
  if (!Number.isSafeInteger(maxPrompt) || maxPrompt < 1 || !Number.isSafeInteger(options.maxOutputTokens) || options.maxOutputTokens < 1) throw new GuardError('INVALID_INPUT');
  return {
    name: options.name, description: `Bounded provider request for ${options.model}`, maxCost: options.maxCost,
    metadata: { model: options.model, recipient: options.recipient, maxOutputTokens: options.maxOutputTokens, maxPromptChars: maxPrompt },
    parse(value) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new GuardError('ARGUMENT_INVALID');
      const input = value as Record<string, Json>;
      if (Object.keys(input).some(key => !['prompt', 'maxOutputTokens'].includes(key)) || typeof input.prompt !== 'string' || input.prompt.length > maxPrompt ||
          !Number.isSafeInteger(input.maxOutputTokens) || Number(input.maxOutputTokens) < 1 || Number(input.maxOutputTokens) > options.maxOutputTokens) throw new GuardError('ARGUMENT_INVALID');
      return value;
    },
    resolve: () => ({ resourceId: options.model, tenantId: options.tenantId, external: true, recipient: options.recipient }),
    async execute(args, context) {
      const input = args as { prompt: string; maxOutputTokens: number };
      const result = await options.complete(input.prompt, { maxOutputTokens: input.maxOutputTokens, signal: context.signal });
      if (typeof result.response.text !== 'string' || result.response.text.length > 1_048_576 || result.response.outputComplete === false) throw new GuardError('RESULT_INVALID');
      for (const value of [result.response.inputTokens, result.response.outputTokens]) if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) throw new GuardError('RESULT_INVALID');
      return { value: { ...result.response, model: options.model } as Json, ...(result.actualCost === undefined ? {} : { actualCost: result.actualCost }) };
    },
  };
}

/** Structurally implements SafeCall Node's Provider without coupling the two packages. Streaming is buffered. */
export function createExecutorModelProvider(options: { client: ExecutorClient; tool: string; model: string; maxOutputTokens: number }): {
  model: string;
  complete(prompt: string, params?: Record<string, unknown>): Promise<ModelResult>;
  stream(prompt: string, params?: Record<string, unknown>): AsyncIterable<string>;
} {
  const complete = async (prompt: string, params: Record<string, unknown> = {}): Promise<ModelResult> => {
    const signal = params.signal instanceof AbortSignal ? params.signal : undefined;
    const maxOutputTokens = params.maxTokens ?? options.maxOutputTokens;
    const action = await options.client.prepare(options.tool, { prompt, maxOutputTokens: maxOutputTokens as number }, signal);
    const result = await options.client.execute(action.id, signal ? { signal } : {});
    if (!result || typeof result !== 'object' || Array.isArray(result) || typeof (result as { text?: unknown }).text !== 'string') throw new GuardError('RESULT_INVALID');
    return result as unknown as ModelResult;
  };
  return { model: options.model, complete, async *stream(prompt, params) { yield (await complete(prompt, params)).text; } };
}
