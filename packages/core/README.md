# @shieldaai/agent-guard

Experimental TypeScript executor for registered agent tools. Node.js 22+, ESM, no third-party runtime dependencies. Package scope: `@shieldaai`.

The trusted host registers and approves tool metadata, creates scoped task handles, and approves sensitive actions. The model receives only a constrained dispatcher. `prepare()` snapshots immutable JSON; `execute()` rechecks current grants, bound tenant context, policy, tool registration, sensitivity, approval and budgets before invoking the stored handler.

```ts
import { AgentGuard } from '@shieldaai/agent-guard';

const guard = new AgentGuard();
const fingerprint = guard.registerTool({
  name: 'read-public-report', description: 'Read the approved public report',
  resolve: () => ({ resourceId: 'report-1', tenantId: 'acme' }),
  execute: () => ({ value: 'Public fixture report' }),
});
guard.approveTool('read-public-report', fingerprint);
const task = guard.createTask({
  id: 'research-1', principalId: 'operator-1', tenantId: 'acme',
  grants: [{ tool: 'read-public-report', resources: ['report-1'] }],
  budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
const prepared = await guard.prepare(task, { tool: 'read-public-report', args: {} });
console.log(await guard.execute(prepared));
```

Task identity and resource ownership must come from the host, not model assertions. Child grants can only narrow parent authority. An action can dispatch once, even without a human approval requirement. Errors after a handler starts do not prove that no side effect occurred.

Custom policies receive a frozen task snapshot. If its counters or shared sensitivity change while policy evaluation is pending, preparation/execution rejects with `POLICY_STATE_CHANGED` before dispatch. The host may retry through a fresh evaluation; the rejection consumes neither approval nor budget. Policies that consult external mutable state need their own coordination. Use the built-in budget fields for atomic call, concurrency and cost admission.

All state is in memory. The library is not a sandbox, distributed permission service or durable budget ledger. Handlers must cooperate with cancellation and enforce any declared maximum provider cost. Literal outbound scanning does not cover arbitrary encodings or split values. JSON Schemas are fingerprinted; validate tool arguments in the resolver.

Normalized JSON values, including request/result envelopes and tool metadata, are capped at 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Account for the enclosing fields when sizing arguments or results. Oversized results reject with `RESULT_INVALID` and revoke the task after the handler has run.

See the [full API](https://github.com/ShieldaAI/agent-guard/blob/main/docs/api-contract.md), [threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md) and [working approval example](https://github.com/ShieldaAI/agent-guard/blob/main/examples/basic.mjs).

Apache-2.0. Copyright 2026 ShieldaAI contributors.

Cost budgets, declared maxima and reported usage use nonnegative safe integer units chosen by the host (for example, microcurrency units). Fractional values and unsafe integers are rejected.
