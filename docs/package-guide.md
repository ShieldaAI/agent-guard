# Package guide

Agent Guard is five npm packages. Most projects start with the first and add
others when they need them. Install the same version of each.

## Which package do I need?

| I want to ... | Use | Needs |
| --- | --- | --- |
| Control which tools an agent can call, on which resources, with approvals and budgets | [`@shieldaai/agent-guard`](#the-guard) (the guard) | Node.js 22+ |
| Put the tools of a Model Context Protocol (MCP) server behind the same checks | [`@shieldaai/agent-guard-mcp`](#mcp-adapter) with the guard or the executor | Node.js 22+ |
| Keep budgets, revocations and used approvals across restarts, or serve an agent in another process | [`@shieldaai/agent-guard-executor`](#the-executor) (the executor) | Node.js 22.13+ |
| Run untrusted code with no network and no host credentials | The executor's `/sandbox` subpath and the [Docker isolation profile](../deployment/README.md) | Node.js 22.13+, Docker |
| Give an agent memory with provenance, quarantine and rollback | The executor's memory tools | Node.js 22.13+ |
| Test that my integration denies the hostile cases and allows the ordinary ones | [`@shieldaai/agent-guard-scenarios`](#scenarios) | Node.js 22+ |
| See which agents exist and what they can reach | [`@shieldaai/agent-map`](#agent-map-experimental) (experimental) | Node.js 22.13+, Neo4j, the Cartography collector |

Each package's limits are in [support and limits](support-and-limits.md).

## The guard

```sh
npm install @shieldaai/agent-guard
```

```js
import { AgentGuard } from '@shieldaai/agent-guard';

const guard = new AgentGuard();
const fingerprint = guard.registerTool({
  name: 'report.read', description: 'Read one report',
  resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
  execute: args => ({ value: `Report ${args.id}` }),
});
guard.approveTool('report.read', fingerprint);
```

The guard runs inside your application and keeps its state in memory. Continue
with the [tool-permissions walkthrough](guides/tool-permissions.md), which adds
a task, a denial, an approval and a refused replay.

## MCP adapter

```sh
npm install @shieldaai/agent-guard @shieldaai/agent-guard-mcp
```

```js
import { AgentGuard } from '@shieldaai/agent-guard';
import { registerMcpTool } from '@shieldaai/agent-guard-mcp';

const guard = new AgentGuard();
const tool = registerMcpTool(guard, {
  serverId: 'docs',
  tool: { name: 'read', description: 'Read a document', inputSchema: { type: 'object' } },
  client: { callTool: async () => ({ content: [{ type: 'text', text: 'Hello' }] }) }, // your MCP SDK client
  resolve: args => ({ resourceId: String(args.id), tenantId: 'acme' }),
});
guard.approveTool(tool.name, tool.fingerprint); // the tool is now 'mcp:docs:read'
```

This wraps one tool of a client you already have. To let the adapter own the
connection, pin reviewed tool definitions and stop calls when the server's tool
list changes, use `ManagedMcpConnection`; see the
[MCP README](../packages/mcp/README.md) and the
[verified MCP credentials guide](guides/verified-mcp-credentials.md).

## The executor

```sh
npm install @shieldaai/agent-guard-executor
```

```js
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

// ':memory:' is for trying it out. In production use a file and a key you keep safe.
const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
const { taskId, token } = executor.createTask({
  id: 'report-task', principalId: 'user-7', tenantId: 'acme', grants: [],
  budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
executor.close();
```

The executor applies the guard's rules and stores its state in an encrypted
file. Each task gets a token, so an agent in another process can call it over
HTTP while your application keeps the administration object. See the
[executor README](../packages/executor/README.md).

## Scenarios

```sh
npm install @shieldaai/agent-guard @shieldaai/agent-guard-scenarios
```

```js
import { runConformance } from '@shieldaai/agent-guard-scenarios';

const report = await runConformance();
console.log(report.passed, report.passedCases, report.caseCount); // true 26 26
```

Thirteen scenarios, each with a hostile and an ordinary case. They use made-up
data and need no API key. [Scenarios](scenarios.md) describes each one and how
to run them against your own wrapper.

## Agent Map (experimental)

```sh
npm install @shieldaai/agent-map
npx agent-guard-map --help
```

Agent Map is a read-only service that answers questions about an inventory of
agents. It needs a host configuration file, a Neo4j database and the Cartography
collector, so start with the [agent cartography guide](guides/agent-cartography.md).
It can change in a minor release.

## Related projects

For validating what a model returns, see SafeCall for
[Node.js](https://github.com/GuardianMesh/llm-safecall-node#readme) and
[Python](https://github.com/GuardianMesh/llm-safecall#readme). For dependency
advisories, see [Security Watch](https://github.com/ShieldaAI/security-watch#readme).
