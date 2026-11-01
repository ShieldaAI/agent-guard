# Shielda Agent Guard

TypeScript packages for controlling the tools an agent can execute. Register a tool, grant a task access to specific resources, and route execution through one guard. Destructive operations can require approval of the exact action before it runs.

**Status: experimental alpha.** The packages use the npm scope `@shieldaai`. The core has no third-party runtime dependencies and requires Node.js 22 or newer. It controls registered calls within one process. It is not an OS sandbox or a universal prompt-injection detector.

| Package | Purpose |
|---|---|
| [`@shieldaai/agent-guard`](packages/core) | Scoped task grants, delegation, tenant checks, approvals, shared sensitivity, secret scanning and budget admission |
| [`@shieldaai/agent-guard-mcp`](packages/mcp) | Register MCP tools with explicit metadata approval and host-defined resource resolution |
| [`@shieldaai/agent-guard-executor`](packages/executor) | Experimental durable executor, authenticated task API, governed memory, restricted network and Docker workload isolation |
| [`@shieldaai/agent-guard-scenarios`](packages/scenarios) | Twelve versioned scenarios, each with malicious and benign test cases |
| [`@shieldaai/agent-map`](packages/agent-map) | Experimental scoped HTTP/MCP reference service for Cartography inventory, with a private React/Cytoscape viewer |

The optional [Agent Map](packages/agent-map/README.md) reads published inventory
without participating in execution. It provides team-scoped evidence, access
explanations, snapshot changes and freshness through the same HTTP/MCP contract.
See the [Cartography plan](docs/cartography-integration-plan.md) for milestone
status and the [viewer](apps/agent-map/README.md) for local preview instructions.
The [pilot runbook](deployment/cartography/RUNBOOK.md) adds a real synthetic
observer-to-viewer deployment, private backups, fresh-graph recovery, operational
difference reports and reproducible performance/rollback checks.
The isolated pilot passed recovery, graph-load and provisional admission-latency
checks. The runbook records the workloads, measured limits and remaining company
rollout gates.

The [source lifecycle command](deployment/cartography/SOURCE-LIFECYCLE.md) explicitly
replaces an enrolled generation after an executor restore or clone. It retires
the old source from current views, blocks republishing it, and preserves the
replacement decision through backup and reconstruction.

Company browser access now has a dedicated [OIDC/HTTPS endpoint](deployment/cartography/IDENTITY.md)
with host-assigned scopes, short-lived sessions, CSRF protection and revocation.
Its private launcher/configuration is separate from the local bearer/MCP service.
Real company-provider enrollment and trusted-certificate browser checks remain
deployment steps; the implementation is tested with disposable HTTPS identities.

An opt-in [single-account AWS collector](deployment/cartography/AWS.md) now fills
the role/user/bucket metadata used by cloud joins. It verifies the exact caller,
publishes complete captures atomically, and shares the observer worker's lock
and polling loop. A separate enrollment flag adds bounded IAM policy capture and
S3 candidate edges with unknown assessments. The scoped API/viewer ties these
candidates to each visible task's execution and resource bindings, retaining
conditions, freshness and unresolved coverage. Live account enrollment remains
a deployment step.

## Install the alpha

```sh
npm install @shieldaai/agent-guard@alpha
```

Add `@shieldaai/agent-guard-mcp@alpha` when integrating MCP tools, or
`@shieldaai/agent-guard-scenarios@alpha` to run the scenario catalog. Both depend on
the matching core version. Configuration lives in your application: register tools,
create task grants, and provide an authenticated approval flow where needed.

The [0.1.0-alpha.2 release notes](docs/releases/0.1.0-alpha.2.md) describe the next
five-package alpha and its publication status. The packages remain experimental;
use `@alpha` or an exact version explicitly. A package's `latest` tag does not
establish production readiness. The viewer and Python Cartography integration
are separate source components, not npm packages in this release.

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
install the workspace tarballs together into a separate project. `npm run check` also tests
packed packages in a clean temporary consumer, so workspace links cannot hide missing
distribution files.

The synthetic [SafeCall/executor integration](examples/safecall-executor.mjs) uses
the Node SafeCall package installed in the caller's environment, or accepts its
local built entry point: `node examples/safecall-executor.mjs /absolute/path/to/llm-safecall-node/dist/index.js`.
It exercises buffered output validation and actual authenticated budget admission
without cloud credentials. See the [implementation status](docs/implementation-status.md)
for checked features and remaining protected-release gates.

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

The model receives a dispatcher that selects the host-owned task, not the guard instance, task-creation APIs or approval APIs. An `approverId` string records a host-authenticated identity; it does not authenticate the person by itself. Resolve tenants and resources from trusted service data. Tool schemas are fingerprinted but are not automatically validated as JSON Schema: use a trusted `parse` function to validate/normalize arguments before resolution. Bind mutable resources with `resourceVersion` and compare the version again at the actual effect.

## Protections and boundaries

The [scenario catalog](docs/scenarios.md) covers unknown tools/resources, delegation, protected administration, sensitive-data export, exact-action approvals, MCP metadata drift, secret and canary scanning, revocation and failed checks, tenant isolation, budgets, normalized typed arguments and resource-version checks. Catalog 1.2.0 runs twenty-four paired malicious and benign cases. A trusted handler must compare the approved resource version atomically with the actual effect.

All mandatory checks must pass. Custom policy can add restrictions but cannot override a missing grant, required approval, revoked task, tenant mismatch or exhausted budget. The same stored invocation is approved and executed; changing the original arguments does not change it.

The embedded core keeps state in memory. Use one guard instance for a task tree. Restarting loses approval consumption and usage history; separate processes do not share them. The new [executor package](packages/executor/README.md) adds a single-owner encrypted SQLite ledger, scoped authenticated interfaces and conservative crash recovery. It is experimental and does not provide distributed enforcement. Cancellation is cooperative through `AbortSignal`; cost bounds require a trusted adapter to enforce a provider-side maximum and report actual usage. An execution error can occur after a side effect and must not trigger an automatic retry. The separate [Docker profile](deployment/README.md) terminates isolated workloads at resource/time limits; its full platform release gate remains open.

Cost values must be nonnegative safe integers in a consistent host-defined unit, such as microcurrency units. Fractional amounts and unsafe integers are rejected to avoid rounding errors in admission and accounting.

Start with the [threat model](docs/threat-model.md) and [API contract](docs/api-contract.md) when integrating the guard. The [architecture](docs/architecture.md) explains the implementation; [release instructions](docs/releasing.md) cover publishing the packages.

The [release review](docs/quality-review.md) preserves verification of the published
`0.1.0-alpha.1` packages. See the [0.1.0-alpha.2 notes](docs/releases/0.1.0-alpha.2.md)
and [changelog](CHANGELOG.md) for the next release's scope and remaining gates.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports should include a minimal fixture and an assertion about actual effects. Report security vulnerabilities through [private vulnerability reporting](https://github.com/ShieldaAI/agent-guard/security/advisories/new), following [SECURITY.md](SECURITY.md).

Licensed under [Apache-2.0](LICENSE). Copyright 2026 ShieldaAI contributors.
