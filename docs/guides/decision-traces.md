# Record decision traces without customer data

A decision trace is a short record of what the executor decided for each tool call:
prepared, approved, refused, run, or unknown. It contains no tool arguments, results, tool
names or customer identifiers, so you can send it to a monitoring system that must not
hold customer data.

## What you will achieve

- Tracing turned on for an executor.
- A list of decisions for one tenant, read from host code.
- Those decisions handed to your own exporter, with a clear answer on whether the hand-off
  worked.

## Prerequisites

- Node.js 22.13 or later, and this repository built (`npm ci --ignore-scripts`, then
  `npm run build`).
- A host that uses the executor (`@shieldaai/agent-guard-executor`). The sample creates a
  throwaway one.

## Steps

### 1. Turn tracing on

Pass `decisionTraces` when you create the executor. `{}` uses the defaults.

| Option | Default | Range |
| --- | --- | --- |
| `maxEventsPerTenant` | 256 | 1 to 4,096 |
| `maxTenants` | 64 | 1 to 256 |
| `retentionMs` | 3,600,000 (one hour) | 1 to 86,400,000 |

### 2. Read and export the trace

Save this as `traces-demo.mjs` in the repository root and run `node traces-demo.mjs`. It
makes one allowed call and one refused call, prints the trace, and exports it.

```js
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({
  database: ':memory:',
  encryptionKey: randomBytes(32),
  decisionTraces: { maxEventsPerTenant: 256, maxTenants: 64, retentionMs: 3_600_000 },
});

const fingerprint = executor.registerTool({
  name: 'reports.read',
  description: 'Read one report',
  resolve: args => ({ resourceId: String(args.id), tenantId: 'company-a' }),
  execute: () => ({ value: { title: 'Quarterly report' } }),
});
executor.approveTool('reports.read', fingerprint);
executor.createTask({
  id: 'report-task',
  principalId: 'report-app',
  tenantId: 'company-a',
  grants: [{ tool: 'reports.read', resources: ['report-1'] }],
  budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

// One allowed call and one refused call.
const allowed = await executor.prepare('report-task', { tool: 'reports.read', args: { id: 'report-1' } });
await executor.execute('report-task', allowed.id);
await executor.prepare('report-task', { tool: 'reports.read', args: { id: 'report-2' } }).catch(() => {});

// Read the trace for one tenant.
const snapshot = executor.decisionTraceSnapshot({ tenantId: 'company-a', limit: 100 });
for (const event of snapshot.events) console.log(event.sequence, event.event, event.outcome, event.code);

// Hand the buffered events to your own exporter.
const result = await executor.exportDecisionTraces(
  { tenantId: 'company-a' },
  async (batch, { signal }) => {
    // Send `batch` to your log pipeline here and stop when `signal` aborts.
  },
  { timeoutMs: 5_000 },
);
console.log(result);

executor.close();
```

### 3. Wire it into your host

- Call `decisionTraceSnapshot` and `exportDecisionTraces` only from host code, after you
  have authenticated the caller and decided which tenant it may see.
- Run exports on your own schedule. The executor starts no timer and picks no destination.
- At the destination, drop duplicates by `sessionRef`, `tenantRef` and `sequence`.
- When a reviewer says no, call `executor.recordReviewDecision(actionId, 'denied')` so the
  refusal appears in the trace. It changes nothing else.

## What you should see

```text
1 prepare PREPARED OK
2 admit ADMITTED OK
3 settle SUCCEEDED OK
4 deny DENIED GRANT_DENIED
{ status: 'exported', count: 4 }
```

## What an event contains

| Field | Meaning |
| --- | --- |
| `sequence` | A counter per tenant. It restarts when the executor restarts. |
| `sessionRef` | A random id for this run of the executor. |
| `time` | Wall-clock time of the event, in milliseconds. |
| `event`, `outcome` | What happened. See the next table. |
| `code` | `OK`, or a fixed error code that explains a refusal or error. |
| `tenantRef`, `taskRef`, `actionRef` | Pseudonyms for the tenant, task and action. |
| `policyRevision`, `toolRevision` | Revision numbers of the policy and tool definition in force. |
| `durationMs` | Elapsed time for the step. |

The three references are keyed hashes. They stay the same across restarts for the same
ledger and key, and they cannot authenticate a caller or approve anything. Timing and
patterns of decisions can still be sensitive, so limit who can read exported traces.

| `event` / `outcome` | Meaning |
| --- | --- |
| `prepare` / `PREPARED` | The action was checked and stored. Code `REVIEW_REQUIRED` means it needs a person's approval. |
| `deny` / `DENIED` | The call was refused before it ran. The code names the check that refused it. |
| `review` / `APPROVED` | The host issued an approval. The approval has not been used yet. |
| `review` / `DENIED` | The host recorded a reviewer's refusal with `recordReviewDecision`. |
| `admit` / `ADMITTED` | Budget was reserved and any approval was used up. The tool is about to run. |
| `settle` / `SUCCEEDED` | The tool returned a valid result and it was stored. |
| `unknown` / `UNKNOWN` | The tool started but its outcome is not known. A person must reconcile it. Code `RECOVERY_UNKNOWN` marks work found unfinished after a restart. |
| `error` / `ERROR` | The caller got an error after the tool was admitted. The effect may still have happened. |
| `cancel` / `CANCELLED` | A prepared action was canceled before it ran. |
| `cancel` / `CANCEL_REQUESTED` | Cancellation was requested after the action had started. The work may not have stopped. |
| `reconcile` / `SUCCEEDED` or `FAILED` | An operator recorded the real outcome of unknown work. |

A tool that throws produces `unknown` / `UNKNOWN` followed by `error` / `ERROR`.

## What a snapshot contains

`decisionTraceSnapshot({ tenantId, taskId?, afterSequence?, limit? })` returns:

| Field | Meaning |
| --- | --- |
| `sessionRef`, `tenantRef` | The same references the events carry. |
| `events` | The matching events, oldest first. |
| `nextSequence` | The last sequence returned. Pass it as `afterSequence` to continue. Use it together with `sessionRef`. |
| `retained` | How many events match after `afterSequence`, before `limit` is applied. |
| `dropped`, `expired` | Events lost for this tenant because the buffer was full or because they aged out. |
| `exported`, `exportFailures` | Export totals for this tenant. |
| `accepting` | `true` once this tenant has a buffer. |

The counters cover the whole tenant even when you filter by `taskId`.
`decisionTraceStatistics()` returns `tenants` and `tenantCapacityDrops` across all
tenants, so do not show it to a tenant.

## What an export returns

`exportDecisionTraces({ tenantId }, sink, { timeoutMs })` calls your `sink` once with the
buffered events. `timeoutMs` defaults to 5,000 and can be 1 to 60,000.

| `status` | Meaning |
| --- | --- |
| `exported` | Your sink finished. Those events are removed from the buffer. Events recorded during the export stay. |
| `failed` | Your sink threw. The events stay for the next attempt. |
| `timeout` | Your sink did not finish in time. Its `signal` was aborted and the events stay. |
| `busy` | An earlier export for this tenant is still running. Nothing was started. |
| `empty` | There was nothing to export. Your sink was not called. |

## Limits

- **Traces live in memory.** They are lost when the executor closes or the process dies.
  The ledger and its audit records are separate and durable.
- **Delivery is best effort.** An event can be lost (buffer full, aged out, process loss)
  or delivered twice (the destination accepted a batch but the sink then failed).
- **A full buffer drops the oldest event** for that tenant. Once `maxTenants` tenants have
  buffers, events for further tenants are not recorded.
- **Losing a trace never changes a decision.** Tracing and export do not block, repeat or
  undo a tool call.
- **A call for an unknown task is not traced.** It cannot be assigned to a tenant.

## What can go wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `TRACE_DISABLED` | The executor was created without `decisionTraces`. | Add the option. `{}` uses the defaults. |
| `events` is empty and `accepting` is `false` | Nothing has been recorded for this tenant in this run. | Check the tenant id. |
| `accepting` stays `false` for a busy tenant | All `maxTenants` buffers are taken. `decisionTraceStatistics().tenantCapacityDrops` goes up. | Raise `maxTenants`. |
| `dropped` goes up | Events arrive faster than you export them. | Export more often or raise `maxEventsPerTenant`. |
| Every export returns `busy` | An earlier sink never finished and ignored its `signal`. | Make the sink stop when `signal` aborts. |
| The destination has duplicates | A batch was accepted, then the sink failed or timed out, and the retry sent it again. | Drop duplicates by `sessionRef`, `tenantRef` and `sequence`. |
