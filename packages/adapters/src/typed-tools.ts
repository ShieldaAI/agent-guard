import type { Action, Json, ResolvedAction, TaskIdentity, ToolDefinition, ToolResult } from '@shieldaai/agent-guard';

/**
 * A tool definition whose `resolve` and `execute` receive typed arguments. `parse` must
 * produce them; `defineTool` returns an ordinary `ToolDefinition` and changes nothing at
 * runtime. Use it with `jsonSchemaParser<Args>(schema)` or `standardSchemaParser(zodSchema)`.
 */
export interface TypedToolDefinition<Args extends Json> extends Omit<ToolDefinition, 'parse' | 'resolve' | 'execute'> {
  parse(input: Json): Args;
  resolve(args: Args, task: Readonly<TaskIdentity>): ResolvedAction;
  execute(
    args: Args,
    context: { signal: AbortSignal; action: Readonly<Action>; task: Readonly<TaskIdentity> },
  ): Promise<ToolResult> | ToolResult;
}

/** Types a tool's arguments from its `parse`. Identity at runtime. */
export function defineTool<Args extends Json>(definition: TypedToolDefinition<Args>): ToolDefinition {
  return definition as unknown as ToolDefinition;
}
