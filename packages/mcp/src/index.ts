import { AgentGuard, type Json, type ResolvedAction, type TaskIdentity } from '@shieldaai/agent-guard';

/** A JSON tool definition obtained from tools/list. All fields are fingerprinted. */
export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema: Json;
  [key: string]: Json | undefined;
}

/** Host-supplied bridge to an MCP SDK client. The host owns the connection and credentials. */
export interface McpToolClient {
  callTool(
    request: { name: string; arguments: Record<string, Json> },
    options: { signal: AbortSignal },
  ): Promise<Json>;
}

export interface McpRegistration {
  serverId: string;
  tool: McpToolDescriptor;
  client: McpToolClient;
  resolve(args: Record<string, Json>, task: Readonly<TaskIdentity>): ResolvedAction;
  requiresApproval?: boolean;
  controlPlane?: boolean;
  maxCost?: number;
  /** Read verified usage from the result. Without this callback, charge the full maxCost. */
  measureCost?: (result: Json) => number;
}

export interface RegisteredMcpTool {
  readonly name: string;
  readonly fingerprint: string;
}

export function mcpToolName(serverId: string, toolName: string): string {
  if (!serverId.trim() || !toolName.trim()) throw new TypeError('Server and tool names must be nonempty.');
  return `mcp:${encodeURIComponent(serverId)}:${encodeURIComponent(toolName)}`;
}

function argumentsObject(args: Json): Record<string, Json> {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    throw new TypeError('MCP tool arguments must be a JSON object.');
  }
  // Array.isArray does not exclude readonly arrays from the Json union.
  return args as Record<string, Json>;
}

/**
 * Register without approving. A host must explicitly approve the returned fingerprint.
 * Call this again when tools/list changes; previously prepared calls are invalidated.
 */
export function registerMcpTool(guard: AgentGuard, registration: McpRegistration): RegisteredMcpTool {
  const { serverId, tool, client, resolve, requiresApproval, controlPlane, maxCost, measureCost } = registration;
  const serverToolName = tool.name;
  const name = mcpToolName(serverId, serverToolName);
  const callTool = client.callTool.bind(client);
  const metadata: Record<string, Json> = {};
  for (const key of Object.keys(tool)) {
    const value = tool[key];
    if (value !== undefined) Object.defineProperty(metadata, key, { value, enumerable: true });
  }
  const fingerprint = guard.registerTool({
    name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema,
    metadata,
    ...(requiresApproval === undefined ? {} : { requiresApproval }),
    ...(controlPlane === undefined ? {} : { controlPlane }),
    ...(maxCost === undefined ? {} : { maxCost }),
    resolve: (args, task) => resolve(argumentsObject(args), task),
    async execute(args, { signal }) {
      const value = await callTool({ name: serverToolName, arguments: argumentsObject(args) }, { signal });
      return measureCost === undefined ? { value } : { value, actualCost: measureCost(value) };
    },
  });
  return Object.freeze({ name, fingerprint });
}
