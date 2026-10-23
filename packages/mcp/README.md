# @shieldaai/agent-guard-mcp

Register an MCP tool with the same execution boundary used by `@shieldaai/agent-guard`. Node.js 22+, ESM. Experimental alpha; prepared for npm publication, not yet published.

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

Optional `maxCost` reserves a trusted upper bound. `measureCost(result)` can return verified actual usage; without it the full bound is charged. Provider-side maximum-cost enforcement remains the host's responsibility.

Apache-2.0. See the [repository threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md).

Cost budgets, declared maxima and reported usage use nonnegative safe integer units chosen by the host (for example, microcurrency units). Fractional values and unsafe integers are rejected.
