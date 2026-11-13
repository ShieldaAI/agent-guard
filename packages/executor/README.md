# @shieldaai/agent-guard-executor

The durable executor for Agent Guard: it authorizes AI-agent tool calls and keeps tasks,
budgets, revocations, used approvals and outcomes in an encrypted SQLite ledger, so they
survive a restart. It serves agents through a task-scoped HTTP API, and a prepared call
runs at most once.

In this document, **the guard** is the core package
([`@shieldaai/agent-guard`](https://github.com/ShieldaAI/agent-guard/blob/main/packages/core/README.md)),
**the executor** is this package, and **the host** is your trusted application code.
If you do not need state that survives a restart, use the guard alone; see the
[package guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md).

## Install

```sh
npm install @shieldaai/agent-guard-executor
```

Requires Node.js 22.13 or newer. No account or hosted service is needed.

## Quick example

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor, startExecutorServer } from '@shieldaai/agent-guard-executor';

// In production, use a private database directory and a persistent protected key.
const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });

// 1. The host registers a tool and approves its exact definition.
const fingerprint = executor.registerTool({
  name: 'report.read',
  description: 'Read a public report',
  parse(value) {
    if (value !== null) throw new Error('Expected null');
    return null;
  },
  resolve: () => ({ resourceId: 'public', tenantId: 'acme' }),
  execute: () => ({ value: 'Public report' }),
});
executor.approveTool('report.read', fingerprint);

// 2. The host creates a task: who it acts for, what it may call, and its budget.
const credential = executor.createTask({
  id: 'report-task',
  principalId: 'user-7',
  tenantId: 'acme',
  grants: [{ tool: 'report.read', resources: ['public'] }],
  budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});

// 3. A call is prepared, then executed once.
const action = await executor.prepare('report-task', { tool: 'report.read', args: null });
console.log(await executor.execute('report-task', action.id)); // 'Public report'

// 4. Agents get only a task token and the server URL, never the executor object.
const server = await startExecutorServer({
  executor,
  adminToken: randomBytes(32).toString('base64url'),
  operatorId: 'authenticated-operator',
});
console.log(credential.taskId, server.url);
await server.close();
executor.close();
```

## Keeping state across a restart

Give the executor a file instead of `:memory:` and a key you keep:

```js
const executor = new DurableExecutor({
  database: '/var/lib/my-service/guard/ledger.sqlite', // the directory is yours, mode 0700, real path
  encryptionKey, // the same 32 bytes at every start, from your secret store
});
```

| After a restart | |
| --- | --- |
| Kept | Tasks, budgets and what was spent, revocations, sensitivity marks, used approvals, receipts of finished calls. |
| Done again by your code | `registerTool` and `approveTool` for every tool: tools are code. The ledger keeps each approved definition, so `toolChanges(name)` shows what changed since the last approval before you approve again. |
| Done again by a person | Any action that was prepared or approved but had not run. Executing it fails with `POLICY_CHANGED`; prepare it again and have it reviewed. |
| Left for an operator | A call that was running when the process stopped is `UNKNOWN`. It is never retried; settle it with `reconcile`. |

[`examples/restart.mjs`](https://github.com/ShieldaAI/agent-guard/blob/main/examples/restart.mjs)
shows all of this in one runnable file. The directory rules are under
[Operations](#operations).

## Import paths

| Path | Contents | Stability |
| --- | --- | --- |
| `@shieldaai/agent-guard-executor` | `DurableExecutor`, task server, `ExecutorClient`, tool adapters, network policy, model tool | semver |
| `…/sandbox` | Docker sandbox, artifact broker, build provenance | semver |
| `…/ops` | keyring, key custody, recovery, ledger format | semver |
| `…/pilot` | pilot review verification | semver |
| `…/inventory` | inventory observer, host manifest, MCP inventory | experimental |
| `…/internal` | building blocks for the Agent Ops app | no guarantee |

The ledger format also follows semantic versioning: every 1.x executor opens and migrates a
ledger written by `0.1.0-alpha.3` or later. A ledger newer than the running build is refused
with `STORE_FORMAT_UNSUPPORTED` and left unchanged. Downgrade is not supported.
`executor.ledgerFormat()` reports `{ formatVersion, schema, features }`.

## Tasks and tokens

A **task** is one unit of agent work: a principal, a tenant, a list of grants (tool plus
resources), optional allowed recipients and a budget. `createTask()` returns
`{ taskId, token }`. The token is 32 random bytes; give it to the agent through a channel
only that agent can read.

- `delegateTask(parentId, options)` creates a child task. A child can hold only what every
  ancestor holds, and its calls count against every ancestor's budget.
- `createTask(options, { sourceTaskId })` starts a new root that shares the source task's
  family, labels and revocation. A set of tasks linked this way is a **task family**.
- `revokeTask(taskId)` denies the task and everything derived from it, quarantines the
  memory those tasks wrote and aborts their running handlers.
- `markSensitive(taskId)` labels the family as holding sensitive data, which blocks
  external sends.

`DurableExecutor` is the host's administration object. Never hand it to untrusted code.
Agents reach it through `startExecutorServer()`, which listens on `127.0.0.1` only:

- Task routes (`/v1/task/prepare`, `execute`, `execution`, `snapshot`, `cancel`,
  `delegate`) take the task token as a bearer credential and derive identity from it.
- Admin routes (`/v1/admin/create-task`, `action`, `approve`, `revoke`, `reconcile`,
  `audit`) take the separate `adminToken`. The approver identity is the `operatorId` the
  host configured, never a request field.
- `ExecutorClient` wraps the task routes. It refuses plaintext HTTP to a remote host and
  redirects, bounds responses, and asks for cancellation when its signal aborts.

The server has no browser login, OAuth or public TLS listener. For a remote agent, put
your own authenticated transport in front of it. Use one executor per SQLite file on a
local filesystem: a second owner is refused, and there is no distributed mode.

A tool's handler runs in the host process. Arguments pass the tool's `parse`, then
`resolve` names the resource, tenant, recipient and `resourceVersion` the call touches.
The executor applies the guard's checks (grant, tenant, recipient, deadline, sensitivity,
budget) and then your optional `policy`, which can only tighten them. Changing the policy
or a tool's definition invalidates every action prepared before the change.
`unapproveTool(name)` withdraws a tool's approval; `unregisterTool(name)` removes the tool
and its ledger record, and actions already prepared for it fail with `TOOL_CHANGED`.

`approveTool(name, fingerprint, { approverId, reviewedAgainst })` records the approved
definition in the ledger with the time, the approver and the fingerprint it replaced.
`toolChanges(name)` compares the current registration with that record, also after a
restart, and returns the changed fields with old and new values, heuristic hints and the
recorded `approval`. It covers the definition (name, description, schema, metadata, flags),
never what the handler does; its values are the tool's own text and must be shown as data.
Definitions over `maxToolDefinitionBytes` (64 KiB by default) are approved by fingerprint
only. Details are in the [API contract](../../docs/api-contract.md#what-changed-in-a-tool-definition).

## Approvals

A call needs a human approval when the tool sets `requiresApproval`, the policy returns
`require_approval`, or the family has read outside content and the tool's
`untrustedContext` is `require_approval`. `execute()` then fails with `APPROVAL_REQUIRED`
until the host approves that exact action.

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
const fingerprint = executor.registerTool({
  name: 'refund.send',
  description: 'Send a refund',
  requiresApproval: true,
  maxCost: 5,
  resolve: () => ({ resourceId: 'order-17', tenantId: 'acme' }),
  execute: () => ({ value: 'sent', actualCost: 3 }),
});
executor.approveTool('refund.send', fingerprint);
executor.createTask({
  id: 'refund-task',
  principalId: 'user-7',
  tenantId: 'acme',
  grants: [{ tool: 'refund.send', resources: ['order-17'] }],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 5, deadline: Date.now() + 60_000 },
});
const action = await executor.prepare('refund-task', { tool: 'refund.send', args: { amount: 3 } });

// Read the action back from the ledger and show that to the reviewer.
const stored = executor.preparedAction(action.id);
console.log(stored.action.tool, stored.action.args, stored.action.resourceId, stored.digest);

const approvalId = executor.approve(action.id, {
  approverId: 'reviewer-2',
  expiresAt: Date.now() + 30_000,
});
try {
  console.log(await executor.execute('refund-task', action.id, { approvalId }));
} catch {
  // The handler may have run. Look at the receipt before doing anything else.
  if (executor.execution('refund-task', action.id).status === 'UNKNOWN') {
    // After checking the refund backend, record what really happened.
    executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 0, reference: 'refund-api:8841' });
  }
}
executor.close();
```

**Always use the read-back.** An agent can describe one action and hand over the ID of
another. `preparedAction(actionId)`, or `POST /v1/admin/action` with `{ "actionId" }`,
returns the stored tool, arguments, resource, recipient, digest and status for that ID:
what would actually run.

An approval is bound to the action's digest, is used once, and expires at `expiresAt`,
which cannot be later than the task's deadline. One action can hold
`maxApprovalsPerAction` unused approvals (default 4). For a tool whose `untrustedContext`
is `require_approval` or `deny`, an approval given before the family read outside content
is refused afterwards with `APPROVAL_CONTEXT_CHANGED`. When the
reviewer says no, call `cancel(taskId, actionId)` so that an earlier approval cannot be
used; `recordReviewDecision(actionId, 'denied')` only records the refusal in the decision
traces. A restart withdraws every tool approval and every prepared action: review them
again.

## Unknown outcomes and reconciliation

An action moves through `PREPARED`, then `RUNNING` (admitted, budget reserved, approval
used), then `SUCCEEDED`, `FAILED` or `UNKNOWN`. Admission is one ledger commit and
settlement is another. Ledgers written by earlier versions may also show `ADMITTED`, which
means the same as `RUNNING`.

What `execute()` throws tells you whether the handler started:

- **Before the handler starts**, the error is the executor's own refusal (`APPROVAL_REQUIRED`,
  `TOOL_CHANGED`, `CALL_BUDGET_EXCEEDED`, `STORE_CAPACITY_EXCEEDED` and so on). Nothing ran.
- **After it starts**, an error thrown by your handler is always `TOOL_FAILED`. If the
  thrown error has a safe uppercase `code`, it is kept as `detail`; the message stays in
  the host. A handler cannot make its error look like an executor decision.
- `EXECUTION_ABORTED` means the call was cancelled, revoked or ran past its deadline.
  With `detail: 'EFFECT_COMMITTED'` the handler finished, but the result is withheld. Do
  not retry it. The receipt is `SUCCEEDED`, with one exception: if the settlement itself
  could not be written, the error also has `ledgerError` and the receipt is `UNKNOWN` or
  still `RUNNING`.
- `RESULT_INVALID` and `COST_REPORT_INVALID` mean the handler returned something
  malformed. Both also revoke the task.
- The built-in tools keep their documented codes (see [Error codes](#error-codes)) for
  refusals they raise themselves. An error thrown by a callback you gave them (the model
  tool's `complete`, the outbound tool's `credential`, the sandbox tool's `onResult`, the
  artifact broker's `clock`) is `TOOL_FAILED` like any handler error, whatever its code.

After `TOOL_FAILED`, `EXECUTION_ABORTED` without a detail, or a crash, the receipt is
`UNKNOWN`: the effect may or may not have happened. The executor never retries, refunds or
releases the reservation by itself. Check the backend, then call
`reconcile(actionId, { outcome, actualCost, reference })`. The reference is stored as a
hash, and a second settlement is refused. On restart, every action that was `RUNNING`
becomes `UNKNOWN`. This is not exactly-once delivery to a remote system; use the
backend's idempotency keys or status API where it has them.

`execution(taskId, actionId)` returns the receipt: `{ id, status, charged?, reconciliation? }`.
Use it when a response was lost. Starting a new action instead can repeat an effect.
`listExecutions({ tenantId })` lists a tenant's `UNKNOWN` work for an operator.

`cancel(taskId, actionId)` retires a prepared action or asks a running handler to stop
through its `signal`. Cancellation is cooperative: an effect the backend already accepted
is not undone.

If the ledger itself cannot be written while a call is failing, the caller still gets the
error that explains the call, with the store error attached as `error.ledgerError`. The
action then stays `RUNNING`, and `reconcile()` accepts it once that call has returned.
`cancel()` stops the running handler even when its own ledger write fails.

**A revocation the ledger could not record.** `revokeTask()` also stops the running
handlers and denies the task in this process when its ledger write fails. It then throws
`OPERATION_FAILED` with `detail: 'REVOCATION_NOT_DURABLE'` and the store error as `cause`;
`POST /v1/admin/revoke` answers 503 with
`{ "error": "OPERATION_FAILED", "retryable": true, "detail": "REVOCATION_NOT_DURABLE" }`.
The executor records the revocation with its next ledger write that succeeds and tries
once more in `close()`. Calling `revokeTask()` again is always safe and returns normally
once the revocation is in the ledger. What remains: if no write succeeds before the
process exits, the revocation is lost, and after a restart the task is valid again until
it expires. So treat this error as "not revoked yet": repeat the call until it succeeds,
and do not restart the process in between if you can avoid it.

## Budgets

A task's `budget` has `maxCalls`, `maxConcurrent`, `maxCost` and `deadline` (clock
milliseconds). Costs are integers in a unit you choose. A tool declares `maxCost`; the
executor reserves that amount on the task and every ancestor at admission, and the handler
may return a smaller `actualCost`. With no `actualCost`, the full `maxCost` is charged.

- Budgets are never reset. Calls, spending and reservations survive a restart.
- An `UNKNOWN` action keeps its reservation and its concurrency slot until reconciled.
- `snapshot(taskId)` returns `{ calls, concurrent, spent, reserved, sensitive, untrusted }`.
- The deadline is checked again just before the handler is called. A call that expires
  while being persisted settles `FAILED` at zero cost, and the handler does not run.
- The backend or provider must enforce the declared maximum: the executor counts what the
  handler reports.

A system clock that steps backward makes the next start fail with `CLOCK_INVALID`. After
checking the host clock, start once with `acceptClockSkewMs`; the executor records
`CLOCK_SKEW_ACCEPTED` and continues.

## Memory

`registerMemoryTools()` registers `memory.read` and `memory.write` and returns their
fingerprints for you to approve. Grants name exact entry IDs.

- A write names the version it expects (`ifVersion`). If the entry changed, the call fails
  with `MEMORY_VERSION_CHANGED` and settles `FAILED` at zero cost, because nothing was
  written.
- A read returns a labelled, versioned envelope. Reading a sensitive entry makes the
  reader's family sensitive.
- Content written by a family that has read outside content is marked `untrusted`, and
  reading it marks the reader's family the same way. `importMemory({ …, untrusted: true })`
  sets the mark on content the host imports.
- `importMemory()` is the host's own write. Imported entries are sensitive unless you pass
  `sensitive: false`.
- `quarantineMemory(tenantId, entryId)` blocks an entry and every entry derived from it.
  It fails with `MEMORY_UNAVAILABLE` if the tenant has no such entry.
- `rollbackMemory(tenantId, entryId, version)` appends an old version as the newest one.
  It never lowers sensitivity. History is kept; quarantine is the only form of deletion.

Labels follow data only through these tools and through `sourceTaskId` handoffs. A file
the agent reads some other way carries no label, so label imported workspaces at the
session boundary.

## Sandbox

`@shieldaai/agent-guard-executor/sandbox` runs a command over selected copies of workspace
files in a Docker container that is non-root, read-only, without capabilities and without
network. It needs a Linux Docker daemon; on macOS and Windows that means a local Linux VM.

- `createSandboxTool(options)` returns a tool that puts every run behind the executor:
  the approval is bound to the exact bytes copied into the container, and a changed input
  needs a new review.
- `ArtifactBroker` signs a receipt for each input, export, stdout and stderr with the
  tenant, content hash, sensitivity and source tasks. Stream receipts cover the exact bytes
  written (`stdoutBase64`, `stderrBase64`). Raw input is sensitive unless the host says
  otherwise.
- `admitBuildArtifact()` admits an externally built file only with a signed attestation
  that matches the host's `buildPolicy`. See the
  [build artifact guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/build-artifact-admission.md).
- Exports are reviewed by hash and written with `writeReviewedExports()`.

One path rule applies to inputs, exports, receipts, build policy and the private-file
adapter: a relative path of at most 240 UTF-8 bytes, in NFC, with `/` separators, no `.` or
`..` segment, no control character or any of `\ : * ? " < > |`, no Windows device name,
and no two paths in a list that differ only by case. Paths are checked before anything
runs. Symbolic links and hard-linked files are refused.

Windows needs a fixed local drive and Windows PowerShell; follow the
[deployment profiles](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/README.md)
before enabling it there. The sandbox is not a networked coding-agent session, and a
signature does not make untrusted content trustworthy.

## Inventory (experimental)

`@shieldaai/agent-guard-executor/inventory` exports a read-only picture of what one tenant's
tasks may do: grants, budgets, usage, delegation and tool approval state. It is
experimental: the API may change in a minor release, and it makes no promise about
admission latency while it is polled frequently.

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import { createInventoryObserverToken, startInventoryServer } from '@shieldaai/agent-guard-executor/inventory';

const executor = new DurableExecutor({
  database: ':memory:',
  encryptionKey: randomBytes(32),
  inventory: { companyId: 'acme', sourceId: 'executor-eu-1', enrollmentGeneration: 'enrollment-1' },
});
// Direct, synchronous read for the host.
console.log(executor.inventorySnapshot({ tenantId: 'acme' }).ledgerRevision);

// Separate loopback listener for a collector, with its own credential.
const token = createInventoryObserverToken();
const observer = await startInventoryServer({
  executor,
  observers: [{ token, tenantIds: ['acme'], profile: 'core' }],
});
const response = await fetch(`${observer.url}/v1/inventory/snapshot`, {
  method: 'POST',
  redirect: 'error',
  headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
  body: JSON.stringify({ tenantId: 'acme' }),
});
console.log(response.status);
await observer.close();
executor.close();
```

- A snapshot covers exactly one tenant and is complete: there are no filters or pages. A
  limit that is exceeded fails with `INVENTORY_LIMIT_EXCEEDED`; nothing is truncated.
- Snapshots contain no credentials, arguments, results, memory or events. Resource and
  recipient identifiers are keyed hashes unless `inventory.referenceMode` is `'raw'`.
  Task, principal and tool names are visible, so keep secrets out of identifiers.
- Reading a snapshot runs no policy, parser or handler and changes nothing in the ledger.
- `ledgerRevision` is the ledger-wide commit counter. An observer scoped to one tenant can
  see that writes happened for other tenants, but not what they were or for whom.
- Observer tokens cannot call task or admin routes, and task tokens cannot read inventory.
- `validateInventoryManifest()` and `composeInventorySnapshot()` add host-declared agents,
  deployments and resource bindings (`profile: 'host'`); `loadInventoryManifestFile()`
  reads the manifest from a private file. `composeMcpInventorySnapshot()` adds MCP
  connection state (`profile: 'host-mcp'`). A manifest can describe, never grant.
- All listeners of one executor share one worker and must use the same `workerScheduling`
  and `reuseUnchangedMs`; a different value is refused with `INVENTORY_CONFIG_INVALID`.
- After a restore, clone, key rotation or change of profile, use a new
  `enrollmentGeneration`.

The [cartography guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/agent-cartography.md)
and the [inventory contract](https://github.com/ShieldaAI/agent-guard/blob/main/docs/agent-cartography-contract.md)
describe the manifest versions, the observer's HTTP rules and the collector.

## Built-in tools and adapters

Each of these returns a `ToolDefinition` for the host to register and approve.
`publicToolDefinition(tool)` returns only the metadata that is safe to show a model.

- `createPrivateFileTools({ directory, tenantId, resourcePrefix })`: `.read` and `.write`
  for a private directory the executor owns. A prepared call is bound to the file's
  version and rechecked at dispatch; writes need approval by default and are atomic. Keep
  the directory out of every sandbox workspace.
- `createHttpGetTool()`: fixed, host-approved JSON URLs behind agent-facing aliases, with
  an optional ETag bound at preparation.
- `createOutboundJsonTool()`: sends `{ recipient, payload }` to one configured endpoint.
  The credential comes from a host callback after admission and never reaches the agent.
  Writes are never retried.
- `createModelTool()`: a fixed model, tenant and recipient with a host provider callback;
  each request reserves its cost first. `createExecutorModelProvider()` adapts it to a
  provider interface.
- `createRestrictedFetch(policy)`: a `fetch` limited to exact origins. It checks resolved
  addresses, refuses private addresses unless listed, ignores proxy settings, never follows
  redirects, and bounds bytes and time.

## Operations

**Ledger and key.** The ledger is one SQLite file whose contents are AES-256-GCM
encrypted with the 32-byte key you supply. The key, the clock and the host administrator
are trusted. Losing the key makes the ledger unreadable. On Linux and macOS the directory
must be yours with mode `0700` and the file yours with mode `0600`; on Windows you must
set an equivalent ACL yourself, because Node cannot check it. Name the directory by its
real path: a symbolic link anywhere in it is refused with `STORE_DIRECTORY_UNSAFE`, and on
macOS `/tmp` and `/var` are links (use `fs.realpathSync`).

**Rollback detection.** Restoring an old copy of the database would bring back revoked
authority. When you create a ledger on Linux or macOS, pass
`rollbackWitness: { path, mode: 'create' }` (then `mode: 'resume'`) to pair it with a
second private SQLite file kept outside the backup domain; a restored older database is
then refused. With `recovery: 'mirror'` the witness also holds a full encrypted copy from
which a lost ledger can be rebuilt. See the
[rollback guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/ledger-rollback.md).

**Headroom.** A commit that would take the ledger past `maxLedgerBytes` fails with
`STORE_CAPACITY_EXCEEDED`. Operations that only add state (new task, preparation,
approval, admission, memory write, registration of a new or changed tool) are refused
earlier, at a soft limit below the bound (`detail: 'SOFT_LIMIT'`). The space in between is
reserved so that revoke, cancel, settlement, marking `UNKNOWN`, reconcile, `unapproveTool`,
`unregisterTool` and startup recovery always fit; if even the reserve is full, those
writes drop the oldest half of the recent events to make room. Free space by archiving
finished task families.

Registering a tool the ledger already records with the same fingerprint is never refused
for space: the first such `registerTool()` after a start writes nothing, so a process can
always register its tools again; a repeated one withdraws the approval and ends what was
prepared for the tool. While the
ledger is past the soft limit the executor still starts, revokes, reconciles and archives,
but it admits no new call until space is freed or `maxLedgerBytes` is raised.

**Retention.** Settled receipts are kept per task family and per tenant. A tenant's
traffic evicts only its own oldest receipts. Only the two ledger-wide bounds in the
[limits table](#limits) evict across tenants, and then from the tenant holding the most.
An evicted receipt leaves a small stub and reads as `status: 'PRUNED'` with its `outcome`
and charge; when the stub has gone too but the settlement is still among the recent
events, it reads as `PRUNED` without an outcome. After that, `execution()` fails with
`INVALID_PREPARED`. Budgets and unresolved reservations are never evicted.

**Events.** `audit({ tenantId })` returns recent metadata events, oldest first, without
arguments or results. Each tenant has its own ring, and memory events belong to their
tenant. Events without a tenant (executor start, tool registration and approval, policy
change) have a separate ring that tenant traffic never evicts. Each event has a
`sequence`; a gap means events were evicted. Poll and store them yourself if you need a
complete history; see the
[audit log guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/audit-log.md).

**Task-family lifecycle.** When a workflow is finished, the host can retire and then
archive its whole family: `previewTaskFamilyRetirement(scope)` returns counts, blockers
and a `reviewDigest`; `retireTaskFamily()` and `archiveTaskFamily()` take that digest.
Archiving frees live capacity, keeps an encrypted archive and permanently reserves the
task IDs. `UNKNOWN` work must be reconciled first. `maintenanceStatistics({ tenantId })`
reports counts and ledger size. Details are in the
[API contract](https://github.com/ShieldaAI/agent-guard/blob/main/docs/api-contract.md).
`numberedTaskId(namespace, n)` builds sequential IDs (`ticket:<namespace>-<n>`) that
archive to one marker per namespace instead of one per task.

**Decision traces.** With `decisionTraces: {}` the executor keeps a volatile,
pseudonymous record of decisions per tenant. Read it with `decisionTraceSnapshot()` or
`exportDecisionTraces()`; see the
[decision trace guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/decision-traces.md).

### Keys, custody and recovery

`@shieldaai/agent-guard-executor/ops` and the `agent-guard-ledger` command manage keys
offline, on Linux or macOS, with every ledger owner stopped.

- `createLedgerKeyring`, `loadLedgerKey`, `rotateLedgerKeyring` and `rotateLedgerKey` keep
  ledger keys in a private keyring file and re-encrypt a ledger under a new key. Old keys
  are kept so that an interrupted rotation can be finished.
- `manageLedgerCustody` adds key escrow, verified encrypted backups, restore, managed
  rotation and key retirement. Each change is previewed first and applied with the
  preview's digest.
- `manageLedgerRecovery` turns on the recovery mirror, or rebuilds a lost ledger from its
  witness mirror.
- After a key rotation, inventory and trace references change: use a new
  `enrollmentGeneration`.

The [operations runbook](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/production/README.md)
and the [custody procedure](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/production/custody.md)
give the full sequences.

### Command-line tools

`agent-guard-ledger` takes absolute paths only. Each directory that holds a keyring,
ledger, witness, config or backup must be yours with mode `0700` and no symbolic link in
its path; each file must be yours with mode `0600`.

On success a command prints one JSON line on stdout and exits 0. On failure it exits 1,
prints the error code alone on the first stderr line, and prints a one-line hint on the
second line when one applies (wrong arguments, a missing file or directory, wrong
permissions, a ledger that is still owned). Output never contains a key, a path or config
content.

| Command | What it does |
| --- | --- |
| `keygen --keyring PATH --key-id ID [--max-keys N]` | Create a keyring. Never replaces one. |
| `configure --keyring PATH --max-keys N` | Change the key limit. |
| `status --keyring PATH [--database PATH [--witness PATH] [--max-bytes N]]` | Show the key count and limit, and which key opens the ledger. |
| `rotate --keyring PATH --database PATH --next-key-id ID [--witness PATH] [--max-bytes N]` | Re-encrypt the ledger under a new key. Repeat with the same `--next-key-id` after an interruption. |
| `recovery enroll\|repair --config PATH [--apply --digest HASH]` | Turn on the recovery mirror, or rebuild a lost ledger from its witness mirror. |
| `custody OPERATION --config PATH [--key-id ID \| --backup-id ID] [--apply --digest HASH]` | Managed key custody and backups. |

`recovery` and `custody` preview first: without `--apply` they change nothing and print a
`digest`. Run the same command again with `--apply --digest <that digest>` to act. If
anything changed in between, the command refuses with `CUSTODY_PREVIEW_CHANGED` or
`RECOVERY_PREVIEW_CHANGED`.

| Custody operation | Extra flag | Effect |
| --- | --- | --- |
| `enroll` | | Put the listed ledgers under custody and escrow their keys. |
| `status` | | Report key, store and backup counts. Read-only. |
| `backup` | | Write a verified, encrypted backup of every listed ledger. |
| `verify` | `--backup-id` | Check one backup. Read-only. |
| `restore` | `--backup-id` | Replace the ledgers with a backup. The replaced files are kept in the backup directory. |
| `rotate` | `--key-id` | Issue a new key and re-encrypt every listed ledger. |
| `retire` | `--key-id` | Remove an unused key from the runtime keyring. It stays in escrow. |
| `recover` | | Finish an interrupted rotate, retire or restore. |

Recovery config file (`--config`, mode `0600`):

```json
{
  "version": 1,
  "keyringFile": "/srv/guard/keys/keyring.json",
  "stores": [
    {
      "id": "authority",
      "database": "/srv/guard/data/ledger.sqlite",
      "witnessPath": "/srv/guard/witness/ledger.sqlite"
    }
  ]
}
```

Custody config file:

```json
{
  "version": 1,
  "keyringFile": "/srv/guard/keys/keyring.json",
  "custodyKeyringFile": "/srv/offline/custody-keyring.json",
  "custodyDatabase": "/srv/custody/catalog.sqlite",
  "custodyWitness": "/srv/custody-witness/catalog.sqlite",
  "backupDirectory": "/srv/backups",
  "stores": [
    {
      "id": "authority",
      "database": "/srv/guard/data/ledger.sqlite",
      "witnessPath": "/srv/guard/witness/ledger.sqlite"
    }
  ]
}
```

Both files take exactly these members, and each store exactly `id`, `database` and
`witnessPath`, all distinct. The runtime keyring, the custody keyring, the custody
database, its witness, the backup directory, and the ledger and witness directories must
all be separate directories, none inside another. Create the custody keyring with
`keygen`; it must share no key with the runtime keyring. The command line cannot back up or
repair ledgers that have exported task history; use `manageLedgerCustody` and
`manageLedgerRecovery` with a `history` adapter for those.

`agent-guard-pilot-review --policy PATH --candidate PATH --bundle PATH [--rehearsal]`
verifies a pilot evidence bundle and prints one JSON line. On failure it exits 1 with a
code on the first stderr line and one sentence on the second: `PILOT_ARGUMENT_INVALID`,
`PILOT_INPUT_UNAVAILABLE`, `PILOT_INPUT_UNSAFE`, `PILOT_INPUT_TOO_LARGE`,
`PILOT_INPUT_CHANGED` or `PILOT_INPUT_INVALID` (the sentence names the policy, build or
bundle file), or `PILOT_REVIEW_INVALID` followed by `Failed check <NAME>: …`.
`verifyPilotReview()` from `…/pilot` throws the same `PILOT_REVIEW_INVALID` with the check
name in `error.detail`. See the
[pilot review guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/pilot-review.md).

## Limits

A limit that is reached fails closed with the code shown; nothing is silently dropped
except evicted receipts and recent events, as described under
[Operations](#operations).

### Executor

| Limit | Default | Range or note |
| --- | --- | --- |
| `maxLedgerBytes` (decoded ledger) | 16 MiB | 1 MiB to 64 MiB; `STORE_CAPACITY_EXCEEDED` |
| Reserve below `maxLedgerBytes` | 1 MiB | an eighth of `maxLedgerBytes`, at most 1 MiB |
| `maxRecords` (tasks, actions, approvals, tools, memory entries: each) | 10,000 | 1 or more; `CAPACITY_EXCEEDED`, or `MEMORY_LIMIT` for memory entries |
| Identifier length (task, tool, tenant, approver, reference) | 4,096 characters | fixed |
| Delegation depth | 64 tasks | `LINEAGE_INVALID` |
| Tasks in one task's provenance | 1,000 | `PROVENANCE_LIMIT` |
| `maxTasksPerFamily` | 64 | 1 to `maxRecords` ÷ 4; `FAMILY_TASK_LIMIT` |
| `maxTaskBytesPerFamily` | 256 KiB | up to 1 MiB; `FAMILY_TASK_BYTES_LIMIT` |
| `maxPendingActionsPerFamily` (unsettled actions) | 32 | 1 to `maxRecords` ÷ 4; `FAMILY_PENDING_LIMIT` |
| `maxPendingBytesPerFamily` | 256 KiB | up to 1 MiB; `FAMILY_PENDING_BYTES_LIMIT` |
| `maxApprovalsPerAction` | 4 | 1 to 64; `ACTION_APPROVAL_LIMIT` |
| `maxPolicyAttempts` | 5 | 1 to 16; `POLICY_STATE_CHANGED` |
| Policy checks waiting | 8 per family, 64 in total | `POLICY_BUSY` |
| Policy wait | 30 seconds | or the task deadline; `POLICY_TIMEOUT` |
| `acceptClockSkewMs` | off | 1 to 86,400,000 ms |
| `maxReceiptsPerFamily` (settled receipts) | 64 | 1 to 4,096 |
| Settled receipts per tenant | 256 | `maxReceiptsPerFamily` if larger; at most `maxRecords` ÷ 2 |
| Settled receipts, all tenants | 2 MiB | an eighth of `maxLedgerBytes`; also the `maxRecords` action table |
| Pruned-receipt stubs per family | 256 | fixed |
| Pruned-receipt stubs per tenant | 1,024 | never more than the all-tenant total, so fewer when `maxLedgerBytes` is under 4 MiB |
| Pruned-receipt stubs, all tenants | 4,096 | one per 4 KiB of `maxLedgerBytes`, 256 to 4,096 |
| `maxRecentEventsPerTenant` | 256 | 16 to 1,000; also the size of the system ring |
| Recent events, all tenants | 1,000 | fixed |
| Memory value | 65,536 bytes | `MEMORY_LIMIT` |
| Versions per memory entry | 128 | `MEMORY_LIMIT` |
| Memory written by one family | 256 writes, 512 KiB | `FAMILY_MEMORY_LIMIT` |
| Memory entries one family has read | 1,000 | `MEMORY_LIMIT` |
| Decision traces: events per tenant | 256 | 1 to 4,096 |
| Decision traces: tenants | 64 | 1 to 256 |
| Decision traces: retention | 1 hour | 1 ms to 24 hours |
| Decision trace export timeout | 5 seconds | 1 ms to 60 seconds |
| Archives | 4,096 | 256 MiB of ciphertext in total, 16 MiB decoded each |
| Archived task and memory markers | 65,536 | fixed |
| `listExecutions` page | 25 | 1 to 100 |

### Task server, client and adapters

| Limit | Default | Range or note |
| --- | --- | --- |
| Server `maxRequestBytes` | 256 KiB | `REQUEST_TOO_LARGE` |
| Server `requestTimeoutMs` | 10 seconds | `REQUEST_TIMEOUT` |
| Server `maxConnections` | 64 | 1 to 4,096 |
| Server `maxActiveRequests` | 32 | 1 to 1,024; an eighth (at least 1) is kept for admin routes, so task routes get 28 by default; `REQUEST_RATE_LIMITED` |
| Server `requestsPerMinutePerCredential` | 600 | 1 to 1,000,000; counts each task token and the admin token, and is checked before the ledger is read; an unknown token is refused uncounted; `REQUEST_RATE_LIMITED` |
| Server `requestsPerMinute` | 6,000 | 1 to 1,000,000; counts task-route requests that authenticated; admin routes and requests refused for a limit or a bad token are not counted; `REQUEST_RATE_LIMITED` |
| `ExecutorClient` response | 2 MiB | fixed |
| Restricted fetch `maxResponseBytes` | 1 MiB | `RESPONSE_LIMIT` |
| Restricted fetch `maxRequestBytes` | 256 KiB | `REQUEST_TOO_LARGE` |
| Restricted fetch `timeoutMs` | 20 seconds | `REQUEST_ABORTED` or `RESPONSE_FAILED` |
| Private-file tool `maxBytes` | 1 MiB | up to 16 MiB |
| Model tool `maxPromptChars` | 131,072 | 1 or more |
| Model tool response text | 1,048,576 characters | `RESULT_INVALID` |

### Sandbox

| Limit | Default | Range or note |
| --- | --- | --- |
| Path length | 240 UTF-8 bytes | `SANDBOX_PATH_INVALID`, `ADAPTER_PATH_INVALID`, `ARTIFACT_INVALID`; `BUILD_PROVENANCE_INVALID` in build policy |
| Paths per list (inputs, exports) | 256 | `PATH_COUNT` |
| Input receipts per call | 256, 8 MiB together | `ARTIFACT_RECEIPT_LIMIT` |
| One receipt | 256 KiB, 4,096 JSON values, depth 16 | `ARTIFACT_INVALID` |
| Artifact size | 64 MiB | fixed |
| Profile `memoryMb` | 256 | 64 to 4,096 |
| Profile `cpus` | 1 | 0.1 to 8 |
| Profile `pidsLimit` | 64 | 16 to 512 |
| Profile `timeoutMs` | 30 seconds | 100 ms to 10 minutes; `SANDBOX_TIMEOUT` |
| Profile `maxOutputBytes` | 1 MiB | 1 byte to 16 MiB; `SANDBOX_OUTPUT_LIMIT` |
| Entries in an export archive | 4,096 | `SANDBOX_ARCHIVE_INVALID` |

### Inventory

| Limit | Value |
| --- | --- |
| Tasks, tools per snapshot | 10,000 each |
| Grants per task | 2,048 |
| Selectors per grant, recipients per task | 1,024 |
| Resource selectors per snapshot | 100,000 |
| Snapshot size | 8 MiB, 500,000 JSON values |
| Identifier length | 4,096 code points |
| Manifest size | 2 MiB, 200,000 JSON values |
| Manifest agents, deployments | 1,000 each |
| Manifest bindings | 10,000 of each kind, 128 actions per resource binding |
| Manifests per listener | 1,024 |
| MCP readers, selected connections | 1,024, 128 |
| MCP operations | 256 and 2 MiB per connection, 10,000 in total |
| Observer credentials | 128, with 1,024 tenants each |
| Observer `maxRequestBytes` | 16 KiB (1 byte to 64 KiB) |
| Observer `maxResponseBytes` | 8 MiB (128 bytes to 8 MiB) |
| Observer `requestTimeoutMs` | 10 seconds (10 ms to 60 seconds) |
| Observer `maxConcurrentRequests` | 4 (1 to 64) |
| Observer `maxConnections` | 32 (1 to 256) |
| Observer `rateLimit` | 60 requests per 60 seconds (1 to 10,000 per 10 ms to 60 seconds) |
| Observer request headers | 8 KiB |
| Observation queue per executor | 4 jobs; `INVENTORY_BUSY` |
| `reuseUnchangedMs` | off (0 to 60,000 ms) |

### Offline tools

| Limit | Value |
| --- | --- |
| Keys per keyring (`maxKeys`) | 4 (1 to 64) |
| Config file | 32,768 bytes |
| Stores per custody or recovery config | 1 to 16 |
| Store `id` | 128 characters: letters, digits, `_`, `-` |
| Store paths | 512 bytes, absolute |
| Files per backup | 20,000 |
| Backup manifest | 16 MiB |
| Custody catalog records | 100,000 |

## Error codes

Every public method of `DurableExecutor` and of the offline tools throws only a
`GuardError` (a code the guard defines) or an `ExecutorError` (a code this package
defines), with one exception: a write that fails inside SQLite (a full disk, an I/O error)
surfaces SQLite's own error. `ExecutorClient` can also reject with the error of its
`fetch` or with the caller's abort reason, and `startExecutorServer()` with Node's listen
error. Both error
classes have a `code`; some have a `detail`, a second safe uppercase word that narrows the
cause, and a `cause`. The `code` and the `detail` never contain a path, key or request
data. The `cause` is the original error and can: an operating-system error names the file
it failed on, so do not send a `cause` to an agent. The guard's codes, their HTTP statuses
and which are retryable are listed in the
[error catalog](https://github.com/ShieldaAI/agent-guard/blob/main/docs/errors.md).

Over HTTP the body is `{ "error": code, "retryable": boolean }`. `retryable` is true only
when repeating the same request later cannot repeat an effect. The status is 401 for an
unknown token, 403 for a denial, 404 for an unknown task or action, 409 for changed state,
429 for capacity, 503 for a store, policy or tool failure and 400 for a malformed request.
`ExecutorClient` errors carry the same `code` and `retryable`. Codes that are not in the
catalog are sent as `OPERATION_FAILED`. One response also has a `detail`:
`POST /v1/admin/revoke` answers `OPERATION_FAILED` with `"retryable": true` and
`"detail": "REVOCATION_NOT_DURABLE"` when the ledger could not record the revocation (see
[Unknown outcomes](#unknown-outcomes-and-reconciliation)).

| Code | Meaning |
| --- | --- |
| `INVALID_INPUT`, `INVALID_JSON` | A host argument is malformed, or is not bounded JSON. |
| `INVALID_TASK`, `INVALID_PREPARED` | Unknown task; unknown action, or one that is not this task's. |
| `TOOL_UNKNOWN`, `TOOL_UNAPPROVED`, `TOOL_CHANGED` | The tool is not registered, not approved, or not the definition that was prepared or approved. |
| `POLICY_CHANGED`, `POLICY_STATE_CHANGED`, `POLICY_BUSY` | The policy changed after preparation; the task changed during every policy attempt; too many checks are waiting. |
| `APPROVAL_REQUIRED`, `APPROVAL_INVALID`, `APPROVAL_USED`, `APPROVAL_EXPIRED`, `APPROVAL_CONTEXT_CHANGED`, `ACTION_APPROVAL_LIMIT` | Approval states, described under [Approvals](#approvals). |
| `ACTION_USED` | The action was already admitted, settled or cancelled. |
| `TASK_REVOKED`, `TASK_EXPIRED`, `UNAUTHENTICATED` | The task or an ancestor is revoked or past its deadline; the token is not valid. |
| `TOOL_FAILED`, `EXECUTION_ABORTED`, `RESULT_INVALID`, `COST_REPORT_INVALID` | The handler started; see [Unknown outcomes](#unknown-outcomes-and-reconciliation). |
| `RECONCILIATION_INVALID` | The action is not waiting for reconciliation, or the evidence is malformed. |
| `OPERATION_FAILED` | From `revokeTask()`, with `detail: 'REVOCATION_NOT_DURABLE'`: the task is denied in this process but the ledger did not record it yet. Repeat the call. |
| `CAPACITY_EXCEEDED`, `FAMILY_*_LIMIT` | A record or family limit from the [limits table](#limits). |
| `MEMORY_VERSION_CHANGED`, `MEMORY_UNAVAILABLE`, `MEMORY_LIMIT`, `FAMILY_MEMORY_LIMIT` | Memory tools: stale version; missing, quarantined or archived entry; size limits. |
| `CLOCK_INVALID` | The clock failed or moved backward. |
| `STORE_CONFIG_INVALID` | `database`, `encryptionKey`, `maxLedgerBytes` or `rollbackWitness` is not valid. |
| `STORE_UNAVAILABLE`, `STORE_WITNESS_UNAVAILABLE` | The ledger did not open. `detail`: `LOCKED` (another owner has it), `KEY_MISMATCH` (it does not authenticate under this key: a wrong key, or changed ciphertext), `CORRUPT`, `WITNESS_MISMATCH`, `MIRROR_MISMATCH`, `LEDGER_MISSING`, `FILE_MISSING`, `FILE_EXISTS`. |
| `STORE_DIRECTORY_UNSAFE`, `STORE_FILE_UNSAFE` | The location is not private. `detail`: `DIRECTORY_MISSING`, `DIRECTORY_UNSAFE`, `FILE_UNSAFE` and similar. |
| `STORE_CAPACITY_EXCEEDED` | The ledger is full. `detail`: `SOFT_LIMIT` or `HARD_LIMIT`. |
| `STORE_CORRUPT`, `STORE_CLOSED`, `STORE_FORMAT_UNSUPPORTED` | The ledger changed underneath the executor; the executor is closed; the ledger is from a newer build. |
| `EXECUTIONS_ACTIVE` | `close()` was called while handlers are running. |
| `INVENTORY_*`, `TRACE_*` | Inventory and decision-trace configuration, scope and limits. |
| `ADAPTER_*` | Built-in file and HTTP tools: bad argument or path, changed file or binding, HTTP status or content type. From `prepare()` an argument or path error arrives as `ARGUMENT_INVALID` with the adapter code as `detail`, for example `ADAPTER_PATH_INVALID`. |
| `DESTINATION_DENIED`, `DNS_FAILED`, `REDIRECT_DENIED`, `REQUEST_ABORTED`, `REQUEST_TOO_LARGE`, `RESPONSE_INVALID`, `RESPONSE_LIMIT`, `RESPONSE_FAILED` | The restricted fetch. Thrown from your own handler, these arrive as `TOOL_FAILED` with the code as `detail`. |
| `SANDBOX_*`, `ARTIFACT_*`, `WORKSPACE_INPUT_*`, `BUILD_PROVENANCE_INVALID` | Sandbox, receipts and build admission; a bad path in a build policy is `BUILD_PROVENANCE_INVALID`. `SANDBOX_DOCKER_FAILED` carries a category such as `DAEMON_UNAVAILABLE` or `IMAGE_NOT_FOUND`; `SANDBOX_CLEANUP_FAILED` keeps the run's error as `cause`. |
| `KEYRING_*`, `LEDGER_KEY_UNAVAILABLE`, `CUSTODY_*`, `RECOVERY_*`, `MAINTENANCE_CONFIG_*` | Offline tools. `detail` names the reason, for example `LOCKED` or `FILE_MISSING`. |
| `PILOT_REVIEW_INVALID` | Pilot review failed; `detail` is the check. |

## License

Apache-2.0. See [LICENSE](https://github.com/ShieldaAI/agent-guard/blob/main/LICENSE).
