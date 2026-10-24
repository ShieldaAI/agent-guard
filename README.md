# Shielda Agent Guard

TypeScript packages for controlling the tools an agent can execute. Register a tool, grant a task access to specific resources, and route execution through one guard. Destructive operations can require approval of the exact action before it runs.

**Status: experimental alpha.** The packages use the npm scope `@shieldaai`. The core has no third-party runtime dependencies and requires Node.js 22 or newer. It controls registered calls within one process. It is not an OS sandbox or a universal prompt-injection detector.

| Package | Purpose |
|---|---|
| [`@shieldaai/agent-guard`](packages/core) | Scoped task grants, delegation, tenant checks, approvals, shared sensitivity, secret scanning and budget admission |
| [`@shieldaai/agent-guard-mcp`](packages/mcp) | Register MCP tools with explicit metadata approval and host-defined resource resolution |
| [`@shieldaai/agent-guard-scenarios`](packages/scenarios) | Ten versioned scenarios, each with malicious and benign test cases |

## Install the alpha

```sh
npm install @shieldaai/agent-guard@alpha
```

Add `@shieldaai/agent-guard-mcp@alpha` when integrating MCP tools, or
`@shieldaai/agent-guard-scenarios@alpha` to run the scenario catalog. Both depend on
the matching core version. Configuration lives in your application: register tools,
create task grants, and provide an authenticated approval flow where needed.

The `alpha` tag points to `0.1.0-alpha.1`; `latest` remains on the earlier `0.1.0-alpha.0`. The packages remain experimental; use `@alpha` or an exact version explicitly.

## Run locally

```sh
git clone https://github.com/ShieldaAI/agent-guard.git
cd agent-guard
npm ci --ignore-scripts
npm run check
npm run demo
npm run pack
```

The demo uses in-memory fixtures and needs no API key, environment file, or external
service. `npm run pack` creates installable tarballs in `artifacts/`. For local builds,
install the three tarballs together into a separate project. `npm run check` also tests
packed packages in a clean temporary consumer, so workspace links cannot hide missing
distribution files.

## Approve and execute an action

```ts
import { AgentGuard } from '@shieldaai/agent-guard';

const guard = new AgentGuard();
const fingerprint = guard.registerTool({
  name: 'records.delete',
  description: 'Delete one record',
  requiresApproval: true,
  resolve: args => {
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Invalid arguments');
    const recordId = (args as { readonly recordId?: unknown }).recordId;
    if (typeof recordId !== 'string') throw new Error('Invalid arguments');
    return { resourceId: recordId, tenantId: 'acme' };
  },
  execute: async (args, { signal }) => {
    // Replace with your service call; the service must also check authorization.
    signal.throwIfAborted();
    return { value: { deleted: args } };
  },
});
guard.approveTool('records.delete', fingerprint);

const task = guard.createTask({
  id: 'cleanup-1', principalId: 'operator-42', tenantId: 'acme',
  grants: [{ tool: 'records.delete', resources: ['record-A'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
const prepared = await guard.prepare(task, {
  tool: 'records.delete', args: { recordId: 'record-A' },
});

// Authenticate the reviewer in your approval UI before calling approve().
const approvalId = guard.approve(prepared, {
  approverId: 'reviewer-7', expiresAt: Date.now() + 30_000,
});
const result = await guard.execute(prepared, { approvalId });
```

The model receives a dispatcher that selects the host-owned task, not the guard instance, task-creation APIs or approval APIs. An `approverId` string records a host-authenticated identity; it does not authenticate the person by itself. Resolve tenants and resources from trusted service data. Tool schemas are fingerprinted but are not automatically validated as JSON Schema: the trusted resolver validates arguments before execution.

## Protections and boundaries

The [scenario catalog](docs/scenarios.md) covers unknown tools/resources, delegation, protected administration, sensitive-data export, exact-action approvals, MCP metadata drift, secret and canary scanning, revocation and failed checks, tenant isolation and budgets.

All mandatory checks must pass. Custom policy can add restrictions but cannot override a missing grant, required approval, revoked task, tenant mismatch or exhausted budget. The same stored invocation is approved and executed; changing the original arguments does not change it.

State is in memory. Use one guard instance for a task tree. Restarting loses approval consumption and usage history; separate processes do not share them. Production deployments needing durable, distributed enforcement require a protected state service and resource-side idempotency. Cancellation is cooperative through `AbortSignal`; arbitrary code cannot be forcibly stopped. Cost bounds require a trusted adapter to enforce a provider-side maximum and report actual usage. An execution error can occur after a side effect and must not trigger an automatic retry.

Cost values must be nonnegative safe integers in a consistent host-defined unit, such as microcurrency units. Fractional amounts and unsafe integers are rejected to avoid rounding errors in admission and accounting.

Start with the [threat model](docs/threat-model.md) and [API contract](docs/api-contract.md) when integrating the guard. The [architecture](docs/architecture.md) explains the implementation; [release instructions](docs/releasing.md) cover publishing the packages.

The [release review](docs/quality-review.md) records known issues, test results and verification of the published `0.1.0-alpha.1` packages. See the [changelog](CHANGELOG.md) for the changes in this release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports should include a minimal fixture and an assertion about actual effects. Report security vulnerabilities through [private vulnerability reporting](https://github.com/ShieldaAI/agent-guard/security/advisories/new), following [SECURITY.md](SECURITY.md).

Licensed under [Apache-2.0](LICENSE). Copyright 2026 ShieldaAI contributors.
