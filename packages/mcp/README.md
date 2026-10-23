# @shieldaai/agent-guard-mcp

Register an MCP tool with the same execution boundary used by `@shieldaai/agent-guard`. Node.js 22+, ESM. Experimental alpha.

```ts
import { AgentGuard } from '@shieldaai/agent-guard';
import { registerMcpTool } from '@shieldaai/agent-guard-mcp';

const guard = new AgentGuard();
const registered = registerMcpTool(guard, {
  serverId: 'documents',
  tool: { name: 'read', description: 'Read a report', inputSchema: { type: 'object' } },
  client: {
    async callTool(request, { signal }) {
      signal.throwIfAborted();
      // Replace this fixture with your SDK/transport call and forward the signal.
      return { content: [{ type: 'text', text: 'Public report' }] };
    },
  },
  resolve(args) {
    if (typeof args.id !== 'string') throw new Error('Invalid arguments');
    // In production, resolve ownership from your trusted resource service.
    return { resourceId: args.id, tenantId: 'acme' };
  },
});
guard.approveTool(registered.name, registered.fingerprint);
```

Grant tasks access to `registered.name`, then use `guard.prepare(task, { tool: registered.name, args })` and `guard.execute(prepared)`. Calling the underlying client directly bypasses the guard.

Names include escaped server and tool identifiers. Every supplied descriptor field is included in fingerprint metadata. Register again when `tools/list` changes and explicitly approve the new fingerprint. Re-registration invalidates earlier prepared calls even when metadata is unchanged. The adapter never approves a tool automatically.

The client interface is a small host-supplied bridge, not a dependency on a particular MCP SDK version. The host must validate arguments, resolve tenant/resource/recipient semantics, forward cancellation and prevent unguarded transport access. The alpha covers registered `tools/call` operations, not all MCP protocol methods or `resources/read`. Tool metadata approval does not authenticate a server or verify its implementation.

For an already connected official SDK v2 `Client`, the bridge is:

```js
// sdk is your connected @modelcontextprotocol/client Client.
const { tools } = await sdk.listTools();
const descriptor = tools.find(tool => tool.name === 'read');
if (!descriptor) throw new Error('Required MCP tool is missing');

const registered = registerMcpTool(guard, {
  serverId: 'documents',
  tool: descriptor,
  client: {
    callTool(request, { signal }) {
      return sdk.callTool(request, { signal });
    },
  },
  resolve: resolveReportFromTrustedStore,
});
// Review the descriptor and trusted resolver, then explicitly approve its fingerprint.
```

The SDK's [client guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/clients/calling.md) documents this v2 signature. Older SDK versions may put request options in a different argument position; adapt the bridge for your installed SDK. SDK types permit broader values than this package's JSON contract, so TypeScript hosts must narrow descriptor and result data at that boundary. The guard validates and copies registered metadata and execution results at runtime.

Check `isError` on returned MCP results: tool-level errors remain MCP results and are charged normally. A rejected SDK request becomes a redacted `TOOL_FAILED` error; cancellation becomes `EXECUTION_ABORTED`. Neither is retried automatically. Forwarding cancellation requests cooperative server cancellation. The SDK can reject the local request before a remote handler finishes, so guard concurrency and reservation settlement track the bridge promise, not proof that remote work stopped. Remote effect, concurrency and cost limits require server-side enforcement.

Optional `maxCost` reserves a trusted upper bound. `measureCost(result)` can return verified actual usage; without it the full bound is charged. Provider-side maximum-cost enforcement remains the host's responsibility.

Core JSON limits also apply to MCP results: the full result envelope must fit within 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Large base64 images or embedded resources can exceed that limit; resolve large content through bounded host-controlled resources instead. An oversized result becomes `RESULT_INVALID` and revokes the task after the remote call has occurred.

Apache-2.0. See the [repository threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md).

Cost budgets, declared maxima and reported usage use nonnegative safe integer units chosen by the host (for example, microcurrency units). Fractional values and unsafe integers are rejected.

Integration coverage uses the official `@modelcontextprotocol/client` and `@modelcontextprotocol/server` 2.4.0 packages over their linked `InMemoryTransport`. Tests cover actual `tools/list` and `tools/call`, metadata changes, denied dispatch, both approval layers, cancellation, server failures and cost settlement. The SDK packages are development dependencies only. HTTP, stdio, authentication and remote-server behavior are outside this integration test's coverage.
