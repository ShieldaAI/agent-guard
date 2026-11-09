# @shieldaai/agent-guard

**Version 0.1.0** is the first non-prerelease version. It makes no 1.x API
compatibility or long-term-support promise. The
[release notes](https://github.com/ShieldaAI/agent-guard/blob/main/docs/releases/0.1.0.md)
record the verified scope, known limits and post-release follow-ups.

Control which tools an AI agent can call and on which resources, with task-scoped grants, tenant checks, approvals and budgets. Experimental TypeScript library; Node.js 22+, ESM, no third-party runtime dependencies. Package scope: `@shieldaai`.

Install with `npm install @shieldaai/agent-guard`. For MCP integration,
persistent execution or model response validation, see the
[package selection guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md).

Every `GuardError.code` is documented in the [error catalog](https://github.com/ShieldaAI/agent-guard/blob/main/docs/errors.md)
and in the exported `GuardErrorCatalog` (meaning, whether a retry is safe, typical cause).
When core flattens an adapter error into `RESOLUTION_FAILED`, `ARGUMENT_INVALID` or
`TOOL_FAILED`, a safe uppercase adapter code is kept as `error.detail` (and `cause.code`).

The stable API is the root entry: `AgentGuard`, `GuardError`, `GuardErrorCode`,
`GuardErrorCatalog`, `InvalidJsonError` and the exported types. Building blocks for executor and adapter
authors (`PolicyAdmission`, `assertActionAuthority`, `containsLiteralSecret`,
`canonicalJson`, `digestJson`, `immutableJson`) live in
`@shieldaai/agent-guard/internal`, which has no semver guarantees. Their root
aliases still work but are deprecated and will be removed in 0.3.

Try the [allow, deny and approval walkthrough](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/tool-permissions.md)
for a complete local example with assertions about actual handler calls.

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

Custom policies receive a frozen task snapshot. If its counters or shared sensitivity change while policy evaluation is pending, the stale decision is discarded and the policy is evaluated again on a fresh snapshot, so parallel calls on one task work under a custom policy. Re-evaluations on one task take turns. After `maxPolicyAttempts` evaluations (constructor option, 1–16, default 5) with continuing changes, the call fails with `POLICY_STATE_CHANGED` before dispatch; that failure consumes neither approval nor budget. Set `maxPolicyAttempts: 1` for the earlier single-evaluation behaviour. Policies that consult external mutable state need their own coordination. Use the built-in budget fields for atomic call, concurrency and cost admission.

Preparations and executions share capacity for eight unresolved policy callbacks per task family and 64 per guard. A full pool rejects with `POLICY_BUSY` and starts no additional callback. Policy waits end at the task deadline (`TASK_EXPIRED`) or after 30 seconds (`POLICY_TIMEOUT`), whichever comes first. Pass the third policy parameter's `context?.signal` to cancellable I/O. Revocation and policy replacement also abort waiting evaluations. A callback that ignores cancellation keeps its slot until it settles. A tenant allowed to create many root families can exhaust the shared pool, so hosts should limit incoming requests and root creation per tenant. Synchronous JavaScript still runs on the host event loop.

The host owns the lifetime of prepared action handles. Keep a bounded review queue and discard handles when review ends. Each action holds up to four live approval IDs (`ACTION_APPROVAL_LIMIT`), any one of which authorizes that same action. Expired approvals free space on the next approval, and dispatch clears every approval for the action. The guard keeps a set of all task IDs issued during its lifetime to prevent reuse.

All state is in memory. The library is not a sandbox, distributed permission service or durable budget ledger. Handlers must cooperate with cancellation and enforce any declared maximum provider cost. Literal outbound scanning does not cover arbitrary encodings or split values. JSON Schemas are fingerprinted. Supply a synchronous `parse` to validate and normalize arguments before resource resolution.

The guard checks the task's tool grant and control-plane permission before calling the tool's parser or resource resolver. A resolver for a granted tool can still receive an unauthorized resource ID. Keep lookups read-only, scope them to the authenticated tenant, and enforce the resolved version at the actual effect.

Normalized JSON values, including request/result envelopes and tool metadata, are capped at 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Account for the enclosing fields when sizing arguments or results. The guard rejects JavaScript proxies before triggering their traps. Oversized results reject with `RESULT_INVALID` and revoke the task after the handler has run.

Use a reliable host clock. If time moves behind a value the guard has already observed, time-dependent operations fail with `CLOCK_INVALID` until the clock catches up. Revocation still works during rollback.

Cost budgets, declared maxima and reported usage use nonnegative safe integer units chosen by the host (for example, microcurrency units). Fractional values and unsafe integers are rejected.

See the [full API](https://github.com/ShieldaAI/agent-guard/blob/main/docs/api-contract.md), [threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md) and [working approval example](https://github.com/ShieldaAI/agent-guard/blob/main/examples/basic.mjs).

Apache-2.0. Copyright 2026 ShieldaAI contributors.
