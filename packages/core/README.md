# @shieldaai/agent-guard

Agent Guard decides whether an AI agent may make a tool call: your code registers the tools and gives each piece of agent work a task with grants and a budget, and the guard checks every call against them before your handler runs. It stops calls to tools or resources the task was not given, calls into another tenant, risky actions nobody approved, sensitive data sent to outside recipients, and work past a budget or deadline.

```sh
npm install @shieldaai/agent-guard
```

Node.js 22 or later, ESM, TypeScript types included, no runtime dependencies.

## Quick example

```ts
import { AgentGuard, isGuardError, type Json } from '@shieldaai/agent-guard';

// Arguments come from the model, so read them as untrusted JSON.
function reportId(args: Json): string {
  const id =
    args !== null && typeof args === 'object' && !Array.isArray(args)
      ? (args as { readonly [key: string]: Json }).id
      : undefined;
  if (typeof id !== 'string') throw new Error('id must be a string');
  return id;
}

const guard = new AgentGuard();

// The host registers a tool and approves its definition once.
const fingerprint = guard.registerTool({
  name: 'read-report',
  description: 'Read one report',
  resolve: args => ({ resourceId: reportId(args), tenantId: 'acme' }),
  execute: args => ({ value: `Contents of ${reportId(args)}` }),
});
guard.approveTool('read-report', fingerprint);

// The host creates a task for one piece of agent work.
const task = guard.createTask({
  id: 'research-1',
  principalId: 'alice',
  tenantId: 'acme',
  grants: [{ tool: 'read-report', resources: ['report-1'] }],
  budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

// Each call the agent asks for is prepared (checked), then executed.
const prepared = await guard.prepare(task, { tool: 'read-report', args: { id: 'report-1' } });
console.log(await guard.execute(prepared)); // Contents of report-1

// A report the task was not granted is refused before the handler runs.
try {
  await guard.prepare(task, { tool: 'read-report', args: { id: 'report-2' } });
} catch (error) {
  if (isGuardError(error)) console.log(error.code); // GRANT_DENIED
}
```

The [tool permissions walkthrough](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/tool-permissions.md) builds a complete allow, deny and approval flow step by step.

## Concepts

**Host.** The host is your trusted application code. It creates the guard, registers tools, creates tasks and records approvals. The model never calls these methods: it only proposes a tool name and arguments, which the host passes to `prepare()`.

**Tool.** A tool is something the agent can ask for. You register it with a name, a description and two callbacks: `resolve` looks up which resource and tenant a call would touch, and `execute` does the work. An optional `parse` validates and normalizes the arguments first; the guard does not validate arguments against `inputSchema` itself.

**Task.** A task is one piece of agent work: who it is for, what it may use and for how long. `createTask()` returns a handle that you pass to `prepare()`. Only that object works; a copy with the same ID does not.

**Grant.** A grant, `{ tool, resources }`, lets a task call one tool on the listed resource IDs. `'*'` grants every resource of that tool. A call outside the grants fails with `GRANT_DENIED`.

**Tenant.** The tenant is the customer or workspace that owns a resource. A task belongs to one tenant, and `resolve` reports the tenant of the resource a call would touch. If they differ, the call fails with `TENANT_DENIED`.

**Principal.** The principal is the user or service the agent acts for, as authenticated by the host. It is passed to your callbacks and recorded in the decision log, and child tasks keep it.

**The two approvals.** `approveTool(name, fingerprint)` approves a tool definition once: registering a tool returns a fingerprint of its definition, and the tool cannot be called until the host approves that fingerprint. Registering it again produces a new registration that needs a new approval. `approve(prepared, …)` approves one exact action: one call with these arguments on this resource, for a limited time.

## Delegation

A task can hand part of its work to a sub-agent. A child task may only hold what its parent holds: the same or fewer resources and recipients, the same or a smaller budget, the same or an earlier deadline. The child's calls also count against the parent's budget.

```js
const parentStatus = guard.snapshot(task);
const child = guard.delegateTask(task, {
  id: 'research-1-summary',
  grants: [{ tool: 'read-report', resources: ['report-1'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: parentStatus.budget.deadline },
});
guard.revokeTask(task); // also revokes the child
```

Asking for more fails with `DELEGATION_DENIED`, and `error.detail` says which limit was exceeded: `GRANT_EXCEEDS_PARENT`, `RECIPIENT_EXCEEDS_PARENT`, `CONTROL_PLANE_EXCEEDS_PARENT`, `BUDGET_EXCEEDS_PARENT` or `DEADLINE_EXCEEDS_PARENT`.

## Approvals

A call needs a person's approval when its tool is registered with `requiresApproval: true`, when the policy returns `require_approval`, or when the tool requires it after the task read outside content. `prepared.requiresApproval` says so.

```js
const prepared = await guard.prepare(task, { tool: 'delete-ticket', args: { id: 'T-7' } });
if (prepared.requiresApproval) {
  // Show prepared.action (tool, arguments, resource) to a reviewer, then record the decision.
  const approvalId = guard.approve(prepared, { approverId: 'bob', expiresAt: Date.now() + 5 * 60_000 });
  await guard.execute(prepared, { approvalId });
}
```

An approval covers only the prepared action it was given for, works once and ends at `expiresAt`, which may not be later than the task deadline. A prepared action runs at most once, with or without approval. If `resolve` returns a `resourceVersion`, that version is part of the approved action; your handler must compare it with the real resource when it writes.

## Budgets

Every task has a budget: `maxCalls`, `maxConcurrent`, `maxCost` and a `deadline` in milliseconds. A tool declares `maxCost`, which is reserved before the call runs. The handler may return `actualCost` (zero up to `maxCost`) to be charged less; otherwise the full `maxCost` is charged, also when the handler fails. Costs are nonnegative whole numbers in a unit you choose, such as millionths of a currency unit.

`guard.snapshot(task)` returns the calls made, calls in flight, cost spent and reserved, the budget and whether the task is revoked. At the deadline, and on `revokeTask()`, handlers in flight receive an abort signal.

## Sensitive data and outside-content labels

These rules use labels that your `resolve` callback and tool definitions supply. The guard enforces the labels; it does not inspect content or detect prompt injection.

- **External sends.** When `resolve` returns `external: true`, it must also return a `recipient` that is listed in the task's `allowedRecipients`, or the call fails with `RECIPIENT_DENIED`.
- **Sensitive data.** When a call whose `resolve` returned `sensitive: true` runs, the task and every task delegated from the same root are marked sensitive. External calls then fail with `SENSITIVE_EGRESS_DENIED`.
- **Secrets.** Strings listed in the `secretValues` option may not appear in the arguments of an external call (`SECRET_EGRESS_DENIED`). The match is literal: encoded or split values are not found.
- **Outside content.** Register a tool with `readsUntrusted: true` when it returns text that people outside your trust boundary can write, such as email, web pages or customer tickets. Once such a tool has run, every tool in the task and in tasks delegated from the same root follows its `untrustedContext` setting: `'allow'` (the default), `'require_approval'` or `'deny'` (`UNTRUSTED_CONTEXT_DENIED`). An approval given before the outside content was read no longer works (`APPROVAL_CONTEXT_CHANGED`). `untrustedContextDefault` sets the mode for tools that do not choose one.

## Policies

A policy is an optional function, `(action, task, context) => 'allow' | 'deny' | 'require_approval'`, that runs for every prepare and execute after the built-in checks. It can deny a call or require approval; it cannot allow what the built-in checks refuse. It may be asynchronous: pass `context.signal` to cancellable I/O.

The policy sees a frozen snapshot of the task. If the task's counters change while the policy is deciding, for example because a parallel call finished, the decision is discarded and the policy runs again, up to `maxPolicyAttempts` times; after that the call fails with `POLICY_STATE_CHANGED` without using an approval or budget. `setPolicy()` replaces the policy and fails actions prepared under the old one with `POLICY_CHANGED`.

## The decision log

`onDecision` receives one event for every prepare, approve and execute, whether allowed or refused. An event carries identifiers and the error code only, never arguments or results, so it is safe to write to your log. The hook cannot change an outcome.

```js
const audited = new AgentGuard({
  onDecision: event => console.log(JSON.stringify({ at: new Date().toISOString(), ...event })),
});
// {"at":"…","operation":"prepare","outcome":"denied","taskId":"triage-42","untrusted":false,
//  "tenantId":"acme","principalId":"agent-1","tool":"delete-ticket","code":"GRANT_DENIED"}
```

`outcome` is `allowed` or `denied` for prepare and approve, and `succeeded`, `denied` or `failed` for execute. `failed` means the handler started, so its effect is unknown.

## Limits

| Limit | Default | Range | Option |
| --- | --- | --- | --- |
| Size of one JSON value | 1 MiB | 64 KiB to 64 MiB | `limits.maxJsonBytes` |
| Values in one JSON value | 100,000 | 1,000 to 10,000,000 | `limits.maxJsonNodes` |
| JSON nesting | 64 levels | fixed | |
| Live approvals per prepared action | 4 | 1 to 64 | `limits.maxApprovalsPerAction` |
| Policy evaluations in flight, whole guard | 64 | 1 to 1,024 | `limits.maxPolicyEvaluations` |
| Policy evaluations in flight, one task family | 8 | 1 to 1,024 | `limits.maxPolicyEvaluationsPerFamily` |
| Time for one policy evaluation | 30 s | 100 ms to 300 s | `limits.policyTimeoutMs` |
| Policy evaluations for one call | 5 | 1 to 16 | `maxPolicyAttempts` |
| Length of an identifier | 4,096 characters | fixed | |

The JSON limits apply to each value the guard copies: a tool definition, task options, a `prepare` request (the arguments plus the tool name), parsed arguments and a tool result. Size is measured as compact UTF-8 JSON. Arguments over a limit fail `prepare()` with `INVALID_JSON` before any of your callbacks run. A result over a limit fails `execute()` with `RESULT_INVALID` and revokes the task, because the handler has already run and its result cannot be delivered; raise `limits.maxJsonBytes` if your tools return large documents.

A task family is a root task and everything delegated from it. When the policy slots are full, a call fails with `POLICY_BUSY`; a policy that is too slow fails with `POLICY_TIMEOUT`, or with `TASK_EXPIRED` if the task deadline comes first.

## Errors

Every refusal is a `GuardError` with a stable `code`. `GuardErrorCatalog[code]` gives its meaning, whether a retry is safe and what to do next; the [error reference](https://github.com/ShieldaAI/agent-guard/blob/main/docs/errors.md) lists all codes. Errors never contain arguments, results or policy messages.

```js
import { GuardErrorCatalog, isGuardError } from '@shieldaai/agent-guard';

try {
  await guard.execute(prepared);
} catch (error) {
  if (!isGuardError(error)) throw error;
  console.log(error.code, GuardErrorCatalog[error.code].cause);
}
```

Use `isGuardError()` rather than `instanceof`: it also recognizes errors from a second installed copy of this package. When one of your callbacks throws an error whose `code` is an uppercase identifier, the guard keeps it as `error.detail` on `ARGUMENT_INVALID`, `RESOLUTION_FAILED` or `TOOL_FAILED`.

`TOOL_FAILED`, `EXECUTION_ABORTED`, `RESULT_INVALID` and `COST_REPORT_INVALID` are raised after the handler started. The effect may have happened, so check your backend before trying again.

`EXECUTION_ABORTED` with `error.detail === 'EFFECT_COMMITTED'` means the handler returned normally after the task was revoked or expired: the guard takes the effect as done and withholds the result. A handler that is aborted before it performs its effect must therefore throw (for example `signal.throwIfAborted()`), not return; the call then fails with `EXECUTION_ABORTED` and no detail.

## See what changed before approving again

Registering a tool again withdraws its approval. Before you approve the new definition, ask the guard what changed:

```js
const fingerprint = guard.registerTool(changedDefinition);
const review = guard.toolChanges('read-report');
// review.status: 'first_approval' | 'unchanged' | 'changed' | 'unavailable'
for (const change of review.changes) {
  // change.path is a JSON Pointer such as /description or /inputSchema/properties/path/maxLength
  console.log(change.kind, change.path, JSON.stringify(change.before), JSON.stringify(change.after), change.hints);
}
// Approve only against the comparison the reviewer read.
guard.approveTool('read-report', fingerprint, { reviewedAgainst: review.approvedFingerprint ?? null });
```

- The comparison covers the fingerprinted fields: name, description, schema, metadata and flags. It never shows a change in what `parse`, `resolve` or `execute` do.
- `hints` (`INSTRUCTION_TEXT`, `HIDDEN_CHARACTERS`, `SCHEMA_FIELD_ADDED`, `SCHEMA_LOOSENED`, `FLAG_LOOSENED`) are heuristics for the reviewer. They block nothing, and an empty list does not mean a change is safe.
- The values are the tool's own text. Show them as data: escape them in any page, and do not hand them to a model as instructions.
- A definition over `limits.maxToolDefinitionBytes` (64 KiB by default) is approved by fingerprint only, and `toolChanges` reports `unavailable` instead of a diff.
- The guard keeps approved definitions in memory. The executor keeps them in its ledger, so the comparison survives a restart.

## Long-running hosts

- `retireTask(task)` revokes a finished task and frees its ID and memory. The guard remembers the ID of every task until it is retired.
- `unapproveTool(name)` and `unregisterTool(name)` withdraw a tool.
- `toolChanges(name)` shows what a re-registered tool changed since it was last approved; see below.
- `executeDetailed(prepared)` returns the value together with the charged cost and the action ID, for receipts.
- Deadlines use `Date.now()` by default. If the system clock steps backward, time-dependent calls fail with `CLOCK_INVALID` until it catches up; pass `clock: monotonicClock` to avoid this. Revocation works even then.
- The guard holds a prepared action only while your code holds its handle. Keep a bounded review queue and drop handles when a review ends.

## What your handlers receive

Arguments and results are copied, frozen and given no prototype, so a hostile `__proto__` key cannot reach your code. Read fields directly (`args.id`), use `Object.hasOwn(args, 'id')` instead of `args.hasOwnProperty('id')`, and print with `JSON.stringify(value)`. Copy with `structuredClone(value)` if you need a mutable object.

## What it does not do

- It is not a sandbox. Handlers run in your process with your privileges, and nothing stops code that calls a backend without going through the guard.
- It keeps all state in memory, in one process. For state that survives a restart, use the executor, [`@shieldaai/agent-guard-executor`](https://github.com/ShieldaAI/agent-guard/blob/main/packages/executor/README.md).
- It does not authenticate anyone. The host supplies the principal, the tenant and the owner of each resource; do not take them from the model.
- It does not detect prompt injection or classify content. Sensitivity and outside-content rules follow the labels you supply.
- It does not undo anything. An error after a handler started does not mean the effect did not happen.
- It cannot interrupt a handler. Handlers must honour the abort signal and enforce the declared `maxCost` at the provider.
- It does not replace authorization in your backends. `resolve` can be asked about a resource the task may not use, so keep it read-only and scoped to the task's tenant.
- It does not limit how many tasks a tenant creates. Limit incoming requests in the host.

## Stable API

The package follows semantic versioning for its root entry: `AgentGuard`, `GuardError`, `GuardErrorCode`, `GuardErrorCatalog`, `isGuardError`, `InvalidJsonError`, `monotonicClock` and the exported types. `@shieldaai/agent-guard/internal` holds building blocks for the executor and adapters and may change in any release.

## Related

- [Choosing a package](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md): the Model Context Protocol (MCP) adapter, the executor and the conformance scenarios.
- [API reference](https://github.com/ShieldaAI/agent-guard/blob/main/docs/api-contract.md) and [threat model](https://github.com/ShieldaAI/agent-guard/blob/main/docs/threat-model.md).
- [Risks covered](https://github.com/ShieldaAI/agent-guard/blob/main/docs/risks.md), mapped to the OWASP list of risks for agentic applications.
- [Runnable approval example](https://github.com/ShieldaAI/agent-guard/blob/main/examples/basic.mjs).

Apache-2.0. Copyright 2026 ShieldaAI contributors.
