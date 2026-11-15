import type { Dispatcher } from './dispatcher.js';
import { adapterDenial, isErrorOutcome, outcomeForModel, type DispatchOutcome } from './outcomes.js';
import { parseToolArguments, safeDispatch } from './providers.js';
import { objectSchema, plainJson, type ObjectSchema, type PlainJson, type ToolSpec } from './tools.js';
import { AdapterError } from './errors.js';

// Framework adapters take the framework's own factory (`jsonSchema` from `ai`, `tool` from
// `@openai/agents` or `@langchain/core/tools`) as an argument, so this package never depends
// on, or pins, any of them.

function factory<T extends (...args: never[]) => unknown>(value: T | undefined): T {
  if (typeof value !== 'function') throw new AdapterError('FACTORY_REQUIRED');
  return value;
}
function signalOf(value: unknown): AbortSignal | undefined {
  if (value === null || typeof value !== 'object') return undefined;
  const record = value as { abortSignal?: unknown; signal?: unknown };
  const signal = record.abortSignal ?? record.signal;
  return signal instanceof AbortSignal ? signal : undefined;
}

// ---------------------------------------------------------------- Vercel AI SDK

/** One tool in the shape the AI SDK (`ai` 5 or later) accepts in `tools`. */
export interface AiSdkTool {
  description: string;
  inputSchema: unknown;
  execute: (input: unknown, options?: { abortSignal?: AbortSignal; toolCallId?: string }) => Promise<PlainJson>;
}
/**
 * Tools for `generateText` / `streamText` from the Vercel AI SDK. Pass `jsonSchema` from `ai`.
 * Each tool's `execute` goes through the dispatcher, so the AI SDK's own loop
 * (`stopWhen`, `maxSteps`) runs every call through the guard. A denial is returned as the
 * tool's output, which the model reads like any result.
 *
 * ```js
 * import { generateText, jsonSchema, stepCountIs } from 'ai';
 * const tools = aiSdkTools(dispatch, toolSpecs(guard, ['ticket.read']), { jsonSchema });
 * await generateText({ model, tools, stopWhen: stepCountIs(5), prompt });
 * ```
 */
export function aiSdkTools(
  dispatch: Dispatcher,
  specs: readonly ToolSpec[],
  options: { jsonSchema: (schema: ObjectSchema) => unknown },
): Record<string, AiSdkTool> {
  const jsonSchema = factory(options?.jsonSchema);
  const tools: Record<string, AiSdkTool> = {};
  for (const spec of specs) {
    tools[spec.name] = {
      description: spec.description,
      inputSchema: jsonSchema(objectSchema(spec.inputSchema)),
      async execute(input, executeOptions) {
        const signal = signalOf(executeOptions);
        const outcome = await safeDispatch(
          dispatch,
          {
            name: spec.name,
            input,
            ...(executeOptions?.toolCallId === undefined ? {} : { id: executeOptions.toolCallId }),
          },
          signal,
        );
        return plainJson(outcomeForModel(outcome));
      },
    };
  }
  return tools;
}

// ---------------------------------------------------------------- OpenAI Agents SDK

/** What `tool()` from `@openai/agents` is called with. */
export interface OpenAIAgentsToolConfig {
  name: string;
  description: string;
  parameters: ObjectSchema;
  strict: false;
  execute: (input: unknown, context?: unknown, details?: unknown) => Promise<string>;
}
/**
 * Tools for the OpenAI Agents SDK (`@openai/agents`). Pass its `tool` function. Schemas are
 * passed as non-strict JSON Schema; arguments are enforced by the guard and the tool's
 * `parse`, not by the SDK. For a person's approval inside a run, give the dispatcher
 * `waitForApproval`, or let the model see `waiting_for_approval` and resume later.
 */
export function openAIAgentsTools<T>(
  dispatch: Dispatcher,
  specs: readonly ToolSpec[],
  options: { tool: (config: OpenAIAgentsToolConfig) => T },
): T[] {
  const tool = factory(options?.tool);
  return specs.map(spec =>
    tool({
      name: spec.name,
      description: spec.description,
      parameters: objectSchema(spec.inputSchema),
      strict: false,
      async execute(input, _context, details) {
        const signal = signalOf(details);
        const parsed = parseToolArguments(input);
        const outcome =
          parsed === undefined
            ? adapterDenial(spec.name, 'INPUT_NOT_JSON')
            : await safeDispatch(dispatch, { name: spec.name, input: parsed }, signal);
        return JSON.stringify(outcomeForModel(outcome));
      },
    }),
  );
}

// ---------------------------------------------------------------- LangChain.js / LangGraph.js

/** The second argument of `tool()` from `@langchain/core/tools`. */
export interface LangChainToolFields {
  name: string;
  description: string;
  schema: ObjectSchema;
}
/**
 * Tools for LangChain.js and LangGraph.js (`@langchain/core` 0.3 or later, which accepts JSON
 * Schema). Pass `tool` from `@langchain/core/tools`. Works with `bindTools`, `createReactAgent`
 * and `ToolNode`.
 */
export function langChainTools<T>(
  dispatch: Dispatcher,
  specs: readonly ToolSpec[],
  options: { tool: (func: (input: unknown, config?: unknown) => Promise<string>, fields: LangChainToolFields) => T },
): T[] {
  const tool = factory(options?.tool);
  return specs.map(spec =>
    tool(
      async (input, config) => {
        const signal = signalOf(config);
        const outcome = await safeDispatch(dispatch, { name: spec.name, input }, signal);
        return JSON.stringify(outcomeForModel(outcome));
      },
      { name: spec.name, description: spec.description, schema: objectSchema(spec.inputSchema) },
    ),
  );
}

// ---------------------------------------------------------------- Model Context Protocol server

/** An MCP `tools/call` result. */
export interface McpCallToolResult {
  content: { type: 'text'; text: string }[];
  structuredContent: { [key: string]: PlainJson };
  isError: boolean;
  [key: string]: unknown;
}
/**
 * Handlers for an MCP server that offers guarded tools to any MCP client (Claude Code, Claude
 * Desktop, Cursor, VS Code, ...). Wire `listTools` to `tools/list` and `callTool` to
 * `tools/call` of your MCP server. Every call from the client then goes through the guard.
 * Unknown tool names are refused by the guard (TOOL_UNKNOWN), never run.
 */
export function mcpServerTools(
  dispatch: Dispatcher,
  specs: readonly ToolSpec[],
): {
  listTools(): { tools: { name: string; description: string; inputSchema: ObjectSchema }[] };
  callTool(params: { name: string; arguments?: unknown }, extra?: { signal?: AbortSignal }): Promise<McpCallToolResult>;
} {
  if (typeof dispatch !== 'function') throw new AdapterError('INVALID_OPTIONS');
  const listed = specs.map(spec => ({
    name: spec.name,
    description: spec.description,
    inputSchema: objectSchema(spec.inputSchema),
  }));
  return {
    listTools: () => ({ tools: listed.map(tool => ({ ...tool })) }),
    async callTool(params, extra) {
      if (params === null || typeof params !== 'object' || typeof params.name !== 'string')
        throw new AdapterError('INVALID_TOOL_CALL');
      const signal = signalOf(extra);
      const outcome: DispatchOutcome = await safeDispatch(
        dispatch,
        { name: params.name, input: params.arguments ?? {} },
        signal,
      );
      const body = plainJson(outcomeForModel(outcome)) as { [key: string]: PlainJson };
      return {
        content: [{ type: 'text', text: JSON.stringify(body) }],
        structuredContent: body,
        isError: isErrorOutcome(outcome),
      };
    },
  };
}

/** The part of an MCP SDK `McpServer` used by `registerMcpServerTools`. */
export interface McpServerLike {
  registerTool(
    name: string,
    config: { description: string; inputSchema: unknown },
    handler: (args: unknown, extra?: { signal?: AbortSignal }) => Promise<McpCallToolResult>,
  ): unknown;
}
/**
 * Registers guarded tools on an `McpServer` from the MCP TypeScript SDK. Pass the SDK's
 * `fromJsonSchema` (SDK 2) so the server advertises each tool's approved JSON Schema. Each
 * `tools/call` from the client then goes through the dispatcher.
 */
export function registerMcpServerTools(
  server: McpServerLike,
  dispatch: Dispatcher,
  specs: readonly ToolSpec[],
  options: { fromJsonSchema: (schema: ObjectSchema) => unknown },
): void {
  const fromJsonSchema = factory(options?.fromJsonSchema);
  if (server === null || typeof server !== 'object' || typeof server.registerTool !== 'function')
    throw new AdapterError('INVALID_OPTIONS');
  const handlers = mcpServerTools(dispatch, specs);
  for (const spec of specs) {
    server.registerTool(
      spec.name,
      { description: spec.description, inputSchema: fromJsonSchema(objectSchema(spec.inputSchema)) },
      (args, extra) => handlers.callTool({ name: spec.name, arguments: args }, extra),
    );
  }
}
