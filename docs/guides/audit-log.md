# Audit log: record every decision

To answer "what did the agent try, and what was it allowed to do?" you need a
record of each decision. The guard reports every decision to a function you
supply. The executor keeps recent events and a receipt for each action.

## What you will achieve

A log with one line for each `prepare`, `approve` and `execute`, including
denials, that is safe to store: it holds identifiers and error codes, never
arguments or results.

## Prerequisites

- Node.js 22 or later
- `npm install @shieldaai/agent-guard`
- The [tool-permissions walkthrough](tool-permissions.md), for tools, tasks and
  approvals

## 1. Pass `onDecision` to the guard

Save this as `audit-log.mjs`:

```js
import { AgentGuard } from '@shieldaai/agent-guard';

const log = [];
const guard = new AgentGuard({
  // Called once per decision. Write the event to your own log.
  onDecision: event => log.push({ at: new Date().toISOString(), ...event }),
});

const fingerprint = guard.registerTool({
  name: 'ticket.close',
  description: 'Close one ticket',
  requiresApproval: true,
  resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
  execute: args => ({ value: { id: args.id, status: 'closed' } }),
});
guard.approveTool('ticket.close', fingerprint);
const task = guard.createTask({
  id: 'triage-42',
  principalId: 'agent-1',
  tenantId: 'acme',
  grants: [{ tool: 'ticket.close', resources: ['ticket-7'] }],
  budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
```

The event has no timestamp of its own, so the hook adds one.

## 2. Make a denied call and an approved call

Add to the end of the file:

```js
// One denied call, then one approved call.
await guard.prepare(task, { tool: 'ticket.close', args: { id: 'ticket-9' } }).catch(() => {});
const prepared = await guard.prepare(task, { tool: 'ticket.close', args: { id: 'ticket-7' } });
const approvalId = guard.approve(prepared, { approverId: 'reviewer-3', expiresAt: Date.now() + 30_000 });
await guard.execute(prepared, { approvalId });

for (const { at, actionId, ...event } of log) console.log(JSON.stringify(event));
```

The last line leaves out the timestamp and the random action ID so the output
is the same on every run. Keep both in a real log.

## What you should see

Run `node audit-log.mjs`:

```text
{"operation":"prepare","outcome":"denied","taskId":"triage-42","untrusted":false,"tenantId":"acme","principalId":"agent-1","tool":"ticket.close","code":"GRANT_DENIED"}
{"operation":"prepare","outcome":"allowed","taskId":"triage-42","untrusted":false,"tenantId":"acme","principalId":"agent-1","tool":"ticket.close","resourceId":"ticket-7"}
{"operation":"approve","outcome":"allowed","taskId":"triage-42","untrusted":false,"tenantId":"acme","principalId":"agent-1","tool":"ticket.close","resourceId":"ticket-7","approverId":"reviewer-3"}
{"operation":"execute","outcome":"succeeded","taskId":"triage-42","untrusted":false,"tenantId":"acme","principalId":"agent-1","tool":"ticket.close","resourceId":"ticket-7"}
```

## What the event contains

| Field | Meaning |
| --- | --- |
| `operation` | `prepare`, `approve` or `execute` |
| `outcome` | `allowed` or `denied` for `prepare` and `approve`. For `execute`: `succeeded`, `denied` (the handler did not start) or `failed` (the handler started; the effect may have happened). |
| `taskId`, `tenantId`, `principalId` | The task the call was made under |
| `untrusted` | Whether the task family had read outside content at that moment |
| `tool` | The tool name, when the tool is registered |
| `actionId` | The prepared action's ID. Absent when `prepare` was denied. |
| `resourceId` | The resource `resolve` named. Absent when `prepare` was denied. |
| `approverId` | The reviewer, on a successful `approve` |
| `code` | The error code, when the outcome is `denied` or `failed` |

Things to know:

- The event never contains arguments, results or the reason a policy gave. If
  you need the arguments, log them yourself, and decide first whether they may
  hold private data.
- The hook cannot change a decision. If it throws, the guard ignores the error.
- The hook runs inside the call, so keep it fast. Push to a queue and write to
  disk or the network elsewhere.
- Only `prepare`, `approve` and `execute` are reported. Log `createTask`,
  `revokeTask` and `registerTool` in your own code where you call them.
- A call made with an unknown task handle is refused with `INVALID_TASK` and
  produces no event, because there is no task to report.
- The events are an operational record. They are not signed.

## With the executor

The executor has no `onDecision`. It gives you three other sources.

| Source | Contains | Keeps |
| --- | --- | --- |
| `audit({ tenantId? })` | State changes with task and action IDs: `TASK_CREATED`, `ACTION_PREPARED`, `ACTION_APPROVED`, `ACTION_ADMITTED`, `ACTION_SETTLED`, `OUTCOME_UNKNOWN`, `TASK_REVOKED` and others. Denied calls are not included. | The most recent 256 events per tenant, 1,000 in total, in the ledger |
| `execution(taskId, actionId)` | The receipt of one action: its status and the cost charged | 64 settled receipts per task family by default, in the ledger |
| Decision traces | Every decision including denials, with the error code and duration. Tenant, task and action appear as opaque references, not raw IDs. | In memory for one hour by default; lost on restart |

```js
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({
  database: ':memory:', // use a file in production
  encryptionKey: randomBytes(32),
  decisionTraces: {}, // turn decision traces on
});
const fingerprint = executor.registerTool({
  name: 'ticket.close',
  description: 'Close one ticket',
  resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
  execute: args => ({ value: { id: args.id, status: 'closed' } }),
});
executor.approveTool('ticket.close', fingerprint);
const { taskId } = executor.createTask({
  id: 'triage-42',
  principalId: 'agent-1',
  tenantId: 'acme',
  grants: [{ tool: 'ticket.close', resources: ['ticket-7'] }],
  budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

await executor.prepare(taskId, { tool: 'ticket.close', args: { id: 'ticket-9' } }).catch(() => {});
const prepared = await executor.prepare(taskId, { tool: 'ticket.close', args: { id: 'ticket-7' } });
await executor.execute(taskId, prepared.id);

for (const event of executor.audit({ tenantId: 'acme' })) console.log('audit', event.sequence, event.event);
console.log('receipt', executor.execution(taskId, prepared.id).status);
for (const event of executor.decisionTraceSnapshot({ tenantId: 'acme' }).events) {
  console.log('trace', event.event, event.outcome, event.code);
}
executor.close();
```

```text
audit 4 TASK_CREATED
audit 5 ACTION_PREPARED
audit 6 ACTION_ADMITTED
audit 7 ACTION_SETTLED
receipt SUCCEEDED
trace deny DENIED GRANT_DENIED
trace prepare PREPARED OK
trace admit ADMITTED OK
trace settle SUCCEEDED OK
```

The audit sequence starts at 4 here because the first three events
(`EXECUTOR_STARTED`, `TOOL_REGISTERED`, `TOOL_APPROVED`) belong to the host, not
to a tenant. Call `audit()` without a tenant to see them.

### Keep a complete history

`audit()` is a window over recent events. To keep everything:

1. Poll `audit()` on a timer, more often than your busiest tenant produces 256
   events.
2. Store each event you have not seen, using `sequence` to tell.
3. If the next `sequence` is not the last one plus one, events were dropped
   between polls. Record the gap and poll more often.

To export decision traces to your own system, use `exportDecisionTraces`; see
the [decision traces guide](decision-traces.md).

## What can go wrong

| You see | Cause | Fix |
| --- | --- | --- |
| No events at all | `onDecision` was passed to a different guard than the one handling calls, or it is not a function (the constructor then throws `INVALID_INPUT`). | Pass the hook to the guard you call `prepare` on. |
| A denied `prepare` has no `resourceId` | Denied `prepare` events never carry the resource. | Expected. Use `tool` and `code`. |
| Gaps in `sequence` from `audit()` | More events arrived between polls than the window holds. | Poll more often, or raise `maxRecentEventsPerTenant` (up to 1,000). |
| `execution()` returns `status: 'PRUNED'` | The receipt was trimmed. `outcome` says whether it succeeded while the stub is kept; a later read may have no `outcome`. | Export receipts you need to keep, or raise `maxReceiptsPerFamily`. |
| Decision traces are empty after a restart | They are kept in memory only. | Export them regularly. |

Field-level detail is in the [API contract](../api-contract.md).
