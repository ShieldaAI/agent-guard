# API contract

The host owns `AgentGuard`. Give the model only a dispatcher, never administration methods or opaque handles. Authority is stored by object identity inside one guard instance. All state is in memory and lasts for that instance's lifetime.

The signatures and limits below describe the current source checkout. For a published version, consult its release notes and installed declarations.

Exports from `@shieldaai/agent-guard`:

```ts
type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };
interface Capability {
  tool: string;
  resources: readonly string[];
}
interface Budget {
  maxCalls: number;
  maxConcurrent: number;
  maxCost: number;
  deadline: number;
}
interface TaskOptions {
  id: string;
  principalId: string;
  tenantId: string;
  grants: readonly Capability[];
  budget: Budget;
  allowedRecipients?: readonly string[];
  allowControlPlane?: boolean;
}
interface TaskIdentity {
  id: string;
  principalId: string;
  tenantId: string;
}
interface TaskHandle {
  readonly id: string;
}
interface ResolvedAction {
  resourceId: string;
  tenantId: string;
  external?: boolean;
  recipient?: string;
  sensitive?: boolean;
  resourceVersion?: string;
}
interface ToolDefinition {
  name: string;
  description: string;
  inputSchema?: Json;
  metadata?: Json;
  requiresApproval?: boolean;
  controlPlane?: boolean;
  // Nonnegative safe integer cost units; the adapter enforces its provider-side bound.
  maxCost?: number;
  parse?(input: Json): Json;
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction;
  execute(
    args: Json,
    context: {
      signal: AbortSignal;
      action: Readonly<Action>;
      task: Readonly<TaskIdentity>;
    },
  ): Promise<ToolResult> | ToolResult;
}
interface ToolResult {
  value: Json;
  actualCost?: number;
}
interface Action extends ResolvedAction {
  tool: string;
  args: Json;
  toolFingerprint: string;
  policyVersion: number;
}
interface TaskSnapshot extends TaskIdentity {
  sensitive: boolean;
  calls: number;
  concurrent: number;
  spent: number;
  reserved: number;
}
type PolicyDecision = 'allow' | 'deny' | 'require_approval';
type Policy = (
  action: Readonly<Action>,
  task: Readonly<TaskSnapshot>,
  context?: Readonly<{ signal: AbortSignal }>,
) => PolicyDecision | Promise<PolicyDecision>;
interface GuardOptions {
  policy?: Policy;
  secretValues?: readonly string[];
  clock?: () => number; // milliseconds; default Date.now. monotonicClock() never steps backward.
  maxPolicyAttempts?: number; // 1-16, default 5
  onDecision?: (event: Readonly<GuardDecision>) => void; // observes only; a throwing hook is ignored
  untrustedContextDefault?: 'allow' | 'require_approval' | 'deny'; // default 'allow'
  limits?: {
    maxApprovalsPerAction?: number;
    maxPolicyEvaluations?: number;
    maxPolicyEvaluationsPerFamily?: number;
    policyTimeoutMs?: number;
  }; // defaults 4, 64, 8, 30,000
}
interface GuardDecision {
  operation: 'prepare' | 'approve' | 'execute';
  outcome: 'allowed' | 'denied' | 'succeeded' | 'failed';
  taskId: string;
  tenantId: string;
  principalId: string;
  tool?: string;
  actionId?: string;
  resourceId?: string;
  approverId?: string;
  code?: string;
}
interface TaskStatus extends TaskSnapshot {
  budget: Readonly<Budget>;
  revoked: boolean;
}
interface ExecutionResult {
  readonly value: Json;
  readonly charged: number;
  readonly actionId: string;
}
interface PreparedAction {
  readonly id: string;
  readonly digest: string;
  readonly action: Readonly<Action>;
  readonly requiresApproval: boolean;
}
class GuardError extends Error {
  readonly code: string;
}
class AgentGuard {
  constructor(options?: GuardOptions);
  registerTool(tool: ToolDefinition): string; // Returns the fingerprint. Approval is a separate step.
  approveTool(name: string, fingerprint: string): void;
  createTask(options: TaskOptions): TaskHandle;
  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle;
  revokeTask(task: TaskHandle): void;
  retireTask(task: TaskHandle): void; // revokes, then forgets the task so its ID and memory are freed
  unapproveTool(name: string): void;
  unregisterTool(name: string): void;
  setPolicy(policy: Policy): void; // Invalidates existing prepared actions and approvals.
  prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction>;
  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string;
  execute(prepared: PreparedAction, options?: { approvalId?: string }): Promise<Json>;
  executeDetailed(prepared: PreparedAction, options?: { approvalId?: string }): Promise<ExecutionResult>;
  snapshot(task: TaskHandle): Readonly<TaskStatus>;
}
// Internal SPI from '@shieldaai/agent-guard/internal' (no semver guarantees; the root
// aliases are deprecated). Shared by executor implementations; AgentGuard manages its own pool.
class PolicyAdmission {
  assertCapacity(familyId: string): void;
  evaluate(
    policy: Policy,
    action: Readonly<Action>,
    snapshot: Readonly<TaskSnapshot>,
    scope: { familyId: string; taskIds: readonly string[]; remainingMs: number },
  ): Promise<'allow' | 'require_approval'>;
  revokeTask(taskId: string): void;
  invalidate(reason: 'TASK_REVOKED' | 'POLICY_CHANGED'): void;
}
```

## Execution rules

### Grants and tool registration

Tool names and resource grants match exactly. The resource `*` is an explicit wildcard. Every grant in the task's ancestry must allow an operation. Child tasks inherit their principal and tenant; their grants, recipients, control-plane authority and budgets cannot exceed the parent's limits. Task IDs must be unique within a guard instance.

The host must approve tool metadata before preparing or executing a call. Fingerprints cover the description, schema and security configuration. Re-registering a tool invalidates its existing prepared actions, even if the metadata is unchanged. Approving metadata does not verify the implementation's safety.

### Prepared actions and policy

The guard clones and freezes finite, plain JSON values. It rejects cycles, accessors, JavaScript proxies and other exotic objects. Each normalized envelope is limited to 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Proxy rejection happens before inspecting the proxy's properties or prototype.

Preparation checks tool-level grants and control-plane permission before calling the tool's parser or resolver. An optional synchronous `parse` validates and normalizes arguments once. The guard freezes its result for resource resolution, approval and dispatch. Invalid parser output produces `ARGUMENT_INVALID`. Invalid resolver output produces `RESOLUTION_FAILED`. A resolver for a granted tool may receive an out-of-scope resource ID, so keep lookups read-only and tenant-scoped.

`resourceVersion` is an opaque host-supplied value bound into the action and its
approval. The handler must compare it with current state at the actual effect; the
core cannot perform an external compare-and-swap. Do not expose raw secrets or
guessable secret-content digests in prepared metadata. The executor's private-file
and sandbox adapters use private keyed versions for this reason. Parser code and
resolver closures remain trusted implementation: re-register tools when they change.

Both preparation and execution apply the mandatory checks. Custom policy may add restrictions; it cannot relax them. If policy throws or returns an invalid decision, the call is denied. Without a custom policy, an action is allowed only if every mandatory check passes.

After awaiting policy, the guard rechecks the policy version, grants, revocation, tool approval, tenant, sensitivity and deadline. If a counter or shared sensitivity value in the supplied task snapshot has changed, the decision is discarded and the policy is evaluated again on a fresh snapshot. Re-evaluations on one task take turns (first attempts stay parallel). After `maxPolicyAttempts` evaluations (`GuardOptions`, integer 1–16, default 5) the call fails with `POLICY_STATE_CHANGED`. That failure starts no handler and consumes no approval or budget. Each evaluation takes a policy slot and is bounded by the task deadline. The snapshot check, final reservations, approval consumption and handler invocation run without an intervening asynchronous pause.

This check covers the supplied local snapshot. It cannot coordinate external mutable state or other tasks that a custom policy reads through a closure. Grants cannot be changed in place, administration APIs must remain with the trusted host, and the core does not require a remote policy service.

Preparation and execution share capacity for eight outstanding policy evaluations per task family and 64 per guard. When either limit is full, the next evaluation rejects with `POLICY_BUSY` before starting another callback. Forward `context?.signal` to policy I/O. A waiting call rejects at the task deadline with `TASK_EXPIRED`, or after 30 seconds with `POLICY_TIMEOUT`, whichever comes first. Revoking a task or ancestor and replacing the policy also abort affected waits. A callback keeps its slot until it settles, even if it ignores cancellation. Synchronous work still occupies the host event loop. Limit request rates and root task creation per tenant, because multiple families can fill the shared pool.

### Approval and dispatch

Each prepared action can run at most once. A required approval is bound to that action and its policy and tool revisions. It must expire no later than the task deadline and is consumed immediately before dispatch. Only trusted host code may approve actions or tool metadata.

The guard stores up to four live approvals on each exact prepared action. A fifth rejects with `ACTION_APPROVAL_LIMIT`. Expired records free space when the host next approves that action. Any single valid approval suffices. Dispatch consumes the action and clears all of its approvals. Dropping the action handle makes its records eligible for garbage collection. The host should bound its own review queue.

### Sensitive data and outbound calls

Outbound tools require an explicitly allowed recipient. Parent and descendant tasks share a sensitive flag. Once a trusted resolver marks the context sensitive, external sends are denied. The flag is set before dispatch and cannot be cleared.

For external actions the guard scans outbound argument object keys and string values at every depth for configured literal secrets or canaries. A match produces `SECRET_EGRESS_DENIED` without the argument value. Encoded or split data can evade literal matching.

### Budgets and cancellation

Before dispatch, budget admission updates every ancestor synchronously. Calls count attempts that reach a handler. A failed call or an uncertain side effect is not automatically retried or refunded.

Capacity is checked in two phases.

- **Preparation and approval** (`prepare`, `approve`): authority gates and _permanent_ capacity apply. Permanent capacity is the call count and spent cost, which only grow.
- **Dispatch** (`execute`): additionally enforces _transient_ capacity, meaning concurrent calls and cost reserved by calls still in flight.

So a call in flight does not refuse another preparation or lose a reviewer's approval. The approved action is refused at dispatch (`CONCURRENCY_EXCEEDED` or `COST_BUDGET_EXCEEDED`) until capacity frees, and its approval stays usable until it expires. The internal `assertActionAuthority` (from `@shieldaai/agent-guard/internal`) takes `phase: 'prepare' | 'dispatch'`; the default is `dispatch`.

The embedded guard remembers its highest observed clock reading. A lower reading yields `CLOCK_INVALID` on time-dependent operations until the clock catches up. Revocation remains available during rollback. This prevents an observed expiry from becoming valid again within that guard instance.

Budget `maxCost`, tool `maxCost` and reported `actualCost` use nonnegative safe integers in the same unit chosen by the host, such as microcurrency units. Fractional values and unsafe integers are rejected. The guard reserves `maxCost` and then settles the charge using `actualCost`, which must not exceed the reservation. If usage is omitted, it charges `maxCost`. An invalid or excessive cost report fails the call and revokes the task, charging the full reservation. The host must enforce the provider's actual cost ceiling.

Concurrency stays reserved until the registered handler's promise settles, including after cancellation. Revocation or a task or ancestor deadline signals cancellation through `AbortSignal`; it cannot forcibly stop arbitrary code. The guard also checks the clock when a result settles, so a handler that blocks the timer cannot return a successful result after its deadline. There is no hard process timeout.

An MCP client may settle its request before the remote server stops working. Local accounting therefore cannot bound the remaining remote work. An error after invocation does not prove that no side effect occurred.

## Packages

### Governed memory

These methods belong to the trusted `DurableExecutor` host. They are not model
tools or task-client administration operations:

```ts
importMemory(entry: {
  id: string; tenantId: string; origin: string; value: Json;
  sensitive?: boolean; trusted?: boolean;
}): void;
registerMemoryTools(prefix?: string): Readonly<{ read: string; write: string }>;
quarantineMemory(tenantId: string, entryId: string): void;
rollbackMemory(tenantId: string, entryId: string, version: number): void;
```

`registerMemoryTools()` defaults to the `memory` prefix and returns fingerprints,
which the host must approve separately as `memory.read` and `memory.write`.
Register and approve the tools again after reopening an executor. Grants name
entry IDs; each lookup uses the task's authenticated tenant, so identical IDs in
different tenants name different records. Delegated tasks use their inherited
tenant and narrowed grants.

| Tool           | Exact arguments            | Successful value from `execute()`                                                                        |
| -------------- | -------------------------- | -------------------------------------------------------------------------------------------------------- |
| `memory.read`  | `{ id }`                   | `{ id, tenantId, origin, value, version, sensitive, trusted, parentIds, quarantined: false, familyId? }` |
| `memory.write` | `{ id, value, ifVersion }` | `{ id, version, sensitive, trusted: false }`                                                             |

Extra argument fields are rejected. Use `ifVersion: 0` to create an entry and the
current positive version to replace it. Reads and writes bind a version during
preparation and check it again at execution. An unavailable/quarantined entry or
stale version during preparation yields `RESOLUTION_FAILED`; an execution-time
version change yields `MEMORY_VERSION_CHANGED`. A race with quarantine can yield
`MEMORY_UNAVAILABLE`. These handler failures follow the durable executor's normal
uncertain-result accounting; inspect the execution receipt and reconcile before
retrying.

Host imports append versions, default to sensitive and untrusted, and cannot
lower an existing entry's sensitivity. Tool writes are always untrusted and
inherit family sensitivity and known memory-read lineage. Neither text nor the
`trusted` metadata field grants permission or approves an action. Route reuse
through the governed read/import paths; unrelated raw copies do not acquire
provenance automatically.

Quarantine marks all versions of the named entry and its known descendants in
that tenant unavailable. It persists across reopening. Rollback appends a new
version with the selected old value; it preserves all known parent IDs and never
lowers sensitivity. A missing or quarantined rollback source yields
`MEMORY_UNAVAILABLE`. Rollback cannot undo quarantine; a deliberate host import
can append a replacement record, so the operator must separately review its
content and provenance. History remains encrypted and retained rather than erased.

Values are limited to 64 KiB of canonical JSON, each entry to 128 versions, and
task-family memory history to 256 writes and 512 KiB of stored records. The host's
configured record limit also bounds the number of entries. Exhaustion yields
`MEMORY_LIMIT` or `FAMILY_MEMORY_LIMIT`; it does not silently drop history. See the
[executor guide](../packages/executor/README.md) for source-task handoffs and
reconciliation.

### Durable receipts and recent events

`execution(taskId, actionId)` returns the action's status. Settled receipts are
kept per task family (`maxReceiptsPerFamily`, default 64). Shared count and byte
caps then remove receipts from the family with the most retained receipts,
oldest first, so one tenant's traffic does not evict another tenant's receipts.
Pruning runs on the next preparation, approval or task creation.

A pruned settled receipt returns `{ id, status: 'PRUNED', outcome, charged?,
reconciliation? }`, where `outcome` is `SUCCEEDED` or `FAILED`. Treat it like the
outcome: it is not an unknown effect, and it never permits a retry. These stubs
are bounded (256 per family, 1,024 in total, busiest family trimmed first). Once a
stub is gone too, the call returns `INVALID_PREPARED`, as before. Archiving a
family moves its stubs into the encrypted archive. Expired or invalidated
preparations are deleted without a stub.

`audit({ tenantId? })` returns recent metadata events, not a complete history.
Each tenant keeps at most `maxRecentEventsPerTenant` events (16–1,000, default
256). Host events without a tenant share their own bucket. The total stays at
1,000, trimmed from the busiest tenant first. Events carry a strictly increasing
`sequence`. A host that needs a durable audit trail polls and exports events, and
treats a sequence gap as evicted events. Events recorded before this version have
no `tenantId` or `sequence`.

The new ledger fields are additive. Older executors ignore them, so no schema
change is needed.

### Task-family retirement and archival

The following `DurableExecutor` methods are host-only. They add no task/admin HTTP
routes. An application must authenticate its maintenance operator and choose the
authorized tenant before calling them:

```ts
previewTaskFamilyRetirement(scope: { tenantId: string; taskId: string }): TaskFamilyRetirementPreview;
retireTaskFamily(scope: { tenantId: string; taskId: string; expectedDigest: string }): TaskFamilyRetirementResult;
archiveTaskFamily(scope: { tenantId: string; taskId: string; expectedDigest: string }): TaskFamilyArchiveReceipt;
verifyTaskFamilyArchive(scope: { tenantId: string; archiveId: string }): TaskFamilyArchiveReceipt;
findTaskFamilyArchive(scope: { tenantId: string; taskId: string }): TaskFamilyArchiveReceipt | null;
listExecutions(scope: {
  tenantId: string; statuses?: readonly ExecutionStatus[]; limit?: number; cursor?: string;
}): ExecutionList;
maintenanceStatistics(scope: { tenantId: string }): MaintenanceStatistics;
```

The preview selects the **whole family**, including delegated tasks and linked
root handoffs, from any member's task ID. It returns `tenantId`, `taskId`,
`familyId`, ledger `revision`, `reviewDigest`, `retired`, bounded `counts`,
`retirementBlockers` and `archiveBlockers`. Counts cover tasks, retained actions,
prepared/unresolved actions, memory entries and memory versions. Arguments, bearer
hashes, memory values and encryption keys are absent. The digest is bound to this
executor instance, exact scope and ledger revision. Any intervening ledger write
or process restart invalidates it with `LIFECYCLE_PREVIEW_STALE`. The host should
also impose its own review expiry and user binding.

Retirement refuses `ADMITTED`, `RUNNING` or `UNKNOWN` effects, active handlers and
outstanding reservations (`FAMILY_UNRESOLVED_WORK` / `FAMILY_ACTIVE_WORK`). It does
not reconcile or refund work. On success, one transaction revokes every family
member, cancels prepared actions as zero-cost failures, quarantines the family's
known memory and descendants, and records retirement. Waiting policy evaluations
are canceled; ignored cancellation cannot produce a later dispatch. Request a
fresh preview after retirement before archiving.

Archival requires explicit retirement (`FAMILY_NOT_RETIRED`) and repeats every
check in the commit transaction. Cross-family task references, other families'
recorded reads/derived memory, and mixed ownership of one memory history yield
`FAMILY_EXTERNAL_REFERENCE`. Shared references are never silently detached. An
independent reader family can be retired/archived before its source family;
cycles or mixed histories remain blocked. Use linked handoffs for work whose
provenance and lifetime should remain one family.

The archive retains the available task budgets, counters, revocation and ancestry,
family labels, actions/arguments, approval records, memory and relevant retained
audit events. Previously pruned history is not reconstructed. A fresh random key
encrypts each archive with AES-256-GCM; that key and the exact ciphertext digest
remain inside the main encrypted, authenticated ledger. The archive blob,
catalog, non-reuse markers and removal of live records commit in the same SQLite
transaction, including the rollback witness when enabled. Failure leaves live
authority intact. Outer ledger-key rotation preserves existing archives; future
archives receive independently generated keys.

Receipts contain identity, timestamps, counts, ciphertext SHA-256/byte length and
decimal-string root usage totals (`rootUsage.calls` / `spent`), without private
contents or keys. `verifyTaskFamilyArchive()` authenticates and decrypts the blob
internally before returning its receipt. Missing/substituted evidence fails closed
(`STORE_ARCHIVE_UNAVAILABLE` / `ARCHIVE_INVALID`). `findTaskFamilyArchive()` finds
and verifies a receipt from **any original member ID**, or returns `null` for an
unknown/foreign tenant scope. Use it to recover after the SDK archive committed
but the application did not yet save its business receipt. The application must
keep its own backend operation/receipt mapping and make that final update idempotent.

Archived task IDs can never be reused in this ledger, even under another tenant
(`DUPLICATE_TASK`). Archived memory names cannot be recreated in their original
tenant (`MEMORY_UNAVAILABLE`); new names or a separate tenant remain possible.
Old task credentials and artifact provenance cannot regain authority. Ordinary
task snapshots, execution lookup and inventory no longer expose archived records.
The archive APIs expose only bounded receipt metadata.

Limits are **4,096 archives**, **65,536 combined task/memory non-reuse markers**,
**256 MiB of archive ciphertext**, and **16 MiB of decoded state per archive**.
The main ledger's configured bound still applies and may be reached sooner.
`ExecutorOptions.maxLedgerBytes` defaults to 16 MiB and accepts safe integers
from 1 MiB through 64 MiB. It bounds decoded snapshot bytes rather than SQLite
file size; opening a larger retained snapshot under a smaller limit fails before
recovery mutation. Increasing it does not change archive or record-count bounds.
Neither archives nor markers are automatically evicted. Exhaustion rejects with
`ARCHIVE_CAPACITY_EXCEEDED`, `STORE_ARCHIVE_CAPACITY` or
`STORE_CAPACITY_EXCEEDED`, without deleting live state. Logical live-record
capacity is reclaimed; this is not secure erasure, unlimited retention or an
automatic authority reset. Keep the main ledger, archives and independent witness
within the documented backup/custody procedure.

The Agent Ops [reviewed company-history profile](guides/company-history.md) can
export authenticated single-root ticket families to immutable encrypted segments
before removing their local archive rows. Permanent namespace fences preserve
task-ID non-reuse; legacy IDs and unresolved sequence gaps retain individual
markers. This internal offline protocol is not a general SDK compaction API:
delegated or memory-bearing families remain subject to the limits above.
`findTaskFamilyArchive()` reports `ARCHIVE_EXPORTED` for an exported identity;
the host's history lookup verifies its external evidence. Lifecycle authority
changes use ledger schema 2, which older schema-1-only binaries must reject.
Schema-3 stores with native recovery mirroring keep that stronger format through
all lifecycle mutations; history mirroring never downgrades them to schema 2.

Execution listing defaults to `UNKNOWN`, with 25 items and a maximum of 100.
Valid status filters use `ExecutionStatus`; results contain action/task IDs, tool,
status, charged cost when present and `reservedMaximum`, never arguments/results.
`nextCursor` is authenticated and bound to tenant, filter, process and revision.
Mutation yields `LIFECYCLE_CURSOR_STALE`; refresh from the first page instead of
silently skipping work. Invalid/mismatched cursors yield `LIFECYCLE_CURSOR_INVALID`.
Statistics expose the selected tenant's live/retired/archive counts plus
the fixed global retention limits and deployment-wide `ledgerBytes` and
`ledgerByteLimit`. These byte fields describe the decoded live snapshot, not
SQLite or external-history disk usage. Maintenance reference scans stop at 100,000
records with `LIFECYCLE_LIMIT_EXCEEDED`; they never return a partial safe preview.

### Executor inventory (experimental)

The optional executor package exposes `inventorySnapshot({ tenantId })` only on
the trusted `DurableExecutor` host object. Enable it with constructor
`inventory: { companyId, sourceId, enrollmentGeneration, referenceMode? }`.
`referenceMode` defaults to `opaque`; `raw` is an explicit host choice for reviewed
non-secret resource aliases and recipients. This does not add a task/admin HTTP
route or an `ExecutorClient` operation. The host must select the authorized tenant.

The readonly `InventorySnapshot` implements the
[version-1 core schema](../schemas/agent-guard-inventory-v1.schema.json). It contains
all live-ledger tasks in the tenant, normalized grants and referenced tool records,
including revoked/expired tasks and unavailable handlers. Delegation and provenance
are separate edges. Tool fingerprint strings are bare SHA-256 hex; unavailable
definition flags are `null`. Other enrichment coverage is `not_collected`.

When any tool declares an outside-content label (`readsUntrusted`, `untrustedContext`,
`sendsExternal`) or any task family is `untrusted`, the snapshot uses the
[version-2 schema](../schemas/agent-guard-inventory-v2.schema.json) instead: every task
adds `untrusted`, and every tool adds the three labels, `null` when undeclared or
unregistered. A v2 snapshot also carries `untrustedContextDefault`, the executor's mode
for tools that set none, so a reader can work out each tool's effective mode. v2 is a
`$ref` envelope over v1; every other shape is unchanged. A
collector that only knows v1 refuses v2 rather than dropping the fields. Without
those labels the output is exactly v1. A host snapshot composed with a
[manifest v3](../schemas/agent-guard-inventory-manifest-v3.schema.json) is always v2,
since only the v2 schema accepts that manifest; the lifted fields are `untrusted: false`
and `null` labels.

Manifest v3 is manifest v2 plus a required `directAccess` list: paths the host says
act without the guard. Each entry has an opaque `id`, a declared `deploymentId`, a
`kind` (`shell`, `database`, `network`, `sdk`, `mcp` or `other`), an opaque
`targetRef` or `null`, and a `description` of at most 1,024 characters. At most 32
entries per deployment and 1,000 in total. `[]` means the host declared none; the
map reports it as `none_declared`, never as checked or safe.

One synchronous ledger read produces an immutable, detached snapshot. Export does
not run authorization callbacks or change ledger revision, budgets, approvals or
audit. Observation timestamps use wall time, independent of the execution clock.
The random ledger identity persists across restarts and additive schema-1 migration;
the snapshot ID changes per export. Rotate enrollment after restore/clone, key
changes or reference-mode changes. See the
[executor guide](../packages/executor/README.md#inventory-for-the-trusted-host) for
data minimization, limits and lifecycle requirements.

| Error code                 | Meaning                                                      |
| -------------------------- | ------------------------------------------------------------ |
| `INVENTORY_DISABLED`       | No inventory enrollment configured.                          |
| `INVENTORY_CONFIG_INVALID` | Invalid enrollment or reference mode.                        |
| `INVENTORY_SCOPE_INVALID`  | Missing/invalid tenant or attempted filtering.               |
| `INVENTORY_STATE_INVALID`  | State cannot be represented by the inventory contract.       |
| `INVENTORY_LIMIT_EXCEEDED` | Complete output exceeds a record, work or byte limit.        |
| `INVENTORY_CLOCK_INVALID`  | Observation time cannot be encoded as a valid UTC timestamp. |

Store errors such as `STORE_CLOSED` or `STORE_CORRUPT` are preserved. Error messages
contain stable codes, not source values. Failure never returns a truncated snapshot.

### Observer HTTP (experimental)

`startInventoryServer({ executor, observers, ...limits })` returns a loopback `url`,
the Node `server` and an idempotent async `close()`. Each `InventoryObserverCredential`
has an independent `token` from `createInventoryObserverToken()`, fixed `tenantIds`
and optional host-selected `profile: 'core' | 'host' | 'host-mcp'` (default `core`). A host
credential requires a valid entry in `manifests` for every permitted tenant. The sole route is
`POST /v1/inventory/snapshot`, with `Authorization: Bearer agi_v1.…` and exactly
one JSON property, `tenantId`. The tenant must be enrolled for that credential;
task filters and profile overrides are invalid. Configuration is detached at
startup and cannot be changed by a request.

The optional trusted-host `workerScheduling` setting is `'default'` (unchanged
native priority) or `'linux-background'`. The latter requires Linux and verifies
the worker's own native thread before lowering its priority by up to five nice
levels (`min(19, initial nice + 5)`); no raised priority or `CAP_SYS_NICE` is required. Exact native
identity and priority readback must succeed before the listener starts, otherwise
startup fails with `INVENTORY_SCHEDULING_UNAVAILABLE`. Concurrent listeners sharing
an executor must agree on the policy; conflicts fail with the same code, and
replacement workers retain the selected policy. This does not assign a guaranteed
priority to V8 helper/GC threads or guarantee latency. Caller-selected PIDs and
priority values are not accepted, and no scheduling metadata is exposed by HTTP.
Non-Linux hosts retain default behavior and refuse the explicit Linux policy.

Success returns the complete `InventorySnapshot` directly with an exact encoded
content length and `Cache-Control: no-store`. The listener authenticates independently
of task/admin HTTP and exposes no authority mutations. Its default limits are 16 KiB
request bodies, 8 MiB responses, a 10-second deadline, four active requests,
32 connections and 60 attempts per credential per minute, plus a global quota.
See the [observer guide](../packages/executor/README.md#observer-http-transport)
for configurable bounds, strict parsing and remote TLS bridge requirements.

| HTTP status | Error codes                                                                     |
| ----------- | ------------------------------------------------------------------------------- |
| 400         | `REQUEST_INVALID`                                                               |
| 401         | `UNAUTHENTICATED` (Bearer challenge; no credential details)                     |
| 403         | `REQUEST_DENIED`, `INVENTORY_SCOPE_DENIED`                                      |
| 408         | `REQUEST_TIMEOUT`                                                               |
| 413         | `REQUEST_TOO_LARGE`, `INVENTORY_RESPONSE_TOO_LARGE`, `INVENTORY_LIMIT_EXCEEDED` |
| 429         | `INVENTORY_RATE_LIMITED`, with `Retry-After`                                    |
| 431         | `REQUEST_TOO_LARGE` for parser header overflow                                  |
| 503         | `INVENTORY_BUSY`, `INVENTORY_UNAVAILABLE`, or a safe exporter availability code |

Errors are bounded `{ "error": "CODE" }` JSON without task data. Store and unexpected
internal failures map to `INVENTORY_UNAVAILABLE`. Startup validation uses
`INVENTORY_SERVER_CONFIG_INVALID`; socket bind failures retain Node's error code.
Slow/disconnected sockets may close without a body. Deadlines are checked after
synchronous generation and serialization before success; they cannot interrupt
JavaScript work. Snapshot byte-limit failures send no partial snapshot. A collector
must reject incomplete responses and unexpected redirects.

### Host manifest (experimental)

`validateInventoryManifest(value: unknown): InventoryManifest` returns a detached,
deeply frozen configuration. The standalone
[manifest schema](../schemas/agent-guard-inventory-manifest-v1.schema.json) is closed
at every level. Its envelope is `{schemaVersion: 1, evidenceKind: 'host_asserted',
source, manifestId, revision, observedAt, agents, deployments, taskBindings,
resourceBindings, executionBindings}`. The full source tuple fixes company,
installation, enrollment, ledger instance and tenant. Bindings use exact task IDs,
deployment IDs, tool names and exported resource references; local wildcards cannot
be bound to external resources. Resource kinds/scopes and actions are explicit.
Static execution identities require a supported exact AWS ARN, while dynamic and
unknown selection require `identity: null`.

`composeInventorySnapshot(core: InventorySnapshot, manifest: InventoryManifest):
HostInventorySnapshot` validates both inputs, checks source equality and referenced
entities, and returns `profile: 'host'` with the manifest and complete manifest
coverage. It assigns a fresh snapshot ID/time while preserving every core task,
tool, grant, budget, counter, authority revision and component capture timestamp.
Unassigned tasks remain present. The manifest's separate observation time/revision
does not claim an atomic snapshot or grant runtime permissions.

The observer composes its own fresh executor snapshot with its startup-validated
manifest only for host-profile credentials. Requests cannot supply or override a
manifest. Core-profile credentials never receive host metadata. Invalid runtime
bindings fail the host request with a safe availability error; they do not disable
core observation or mutate authority. Manifests are configuration outside the
ledger. Replace the observer to install an updated version.

`loadInventoryManifestFile(path: string): InventoryManifest` (from
`@shieldaai/agent-guard-executor/inventory`) reads one manifest from a private file and
returns the result of `validateInventoryManifest`. The path must be absolute and come from
host configuration. The file must be a regular file with one link, owned by the process
user, with no group or other permission bits, at most 2 MiB of UTF-8 JSON with no
duplicate object member; a symbolic link is refused. It is read once, synchronously, at
the call: later edits need a host restart. File problems throw
`INVENTORY_MANIFEST_FILE_INVALID`; a platform without POSIX ownership and permissions
throws `INVENTORY_MANIFEST_FILE_UNSUPPORTED`; content problems keep the validation codes
below. No message includes file content.

Manifest validation uses `INVENTORY_MANIFEST_INVALID`,
`INVENTORY_MANIFEST_LIMIT_EXCEEDED`, `INVENTORY_MANIFEST_REFERENCE_INVALID` and
`INVENTORY_MANIFEST_SOURCE_MISMATCH`. Invalid core input uses
`INVENTORY_SNAPSHOT_INVALID`; combined-output limits use
`INVENTORY_LIMIT_EXCEEDED`. All messages omit source values. See the
[host binding guide](../packages/executor/README.md#host-owned-manifest-and-bindings)
for supported reference syntax, numeric/size limits and enrollment lifecycle.

### MCP inventory (experimental)

`ManagedMcpConnection.inventory(): McpConnectionInventory` exposes a closed
version-1 observation: host identity with opaque transport reference, manager
session ID, inventory revision, authorization epoch, descriptor metadata revision,
state, metadata state, observation time and bounded operations. Only `ready`
has current operations; all other states have an empty list. This synchronous
method does not consult the transport, authorization, policies or resolvers.

The executor exports `validateMcpConnectionInventory`, `validateMcpInventorySources`
and `composeMcpInventorySnapshot(host, sources): McpInventorySnapshot`.
Sources have exact `{tenantId, connectionId, source: {inventory()}}` configuration.
The `host-mcp` profile requires a manifest and `mcp: {observedAt, connections}`.
Each expected connection is either `{connectionId, status: 'observed', inventory}`
or `{connectionId, status: 'unavailable', reason}`. Reasons are `missing`,
`capture_failed`, `changed`, `scope_mismatch` or `registration_mismatch`.
Coverage records complete/partial/unavailable observations with their own time.

Composition validates the host envelope, reads only bound sources in the tenant,
checks before/after observations and matches exported operations to registered
core tool fingerprints. It preserves all authority fields. Optional failures
omit current operation evidence; no previous ready registry is carried forward.
The HTTP `mcpSources` option captures host readers at startup and is used only by
`host-mcp` credentials. See the [composition guide](../packages/executor/README.md#mcp-inventory-composition)
for bounds and the [connection schema](../schemas/agent-guard-mcp-inventory-v1.schema.json)
for the full allowlist.

### Published packages

- `@shieldaai/agent-guard`: core above.
- `@shieldaai/agent-guard-mcp`: thin registered-tool adapter for a host-supplied MCP client, without a separate policy engine or automatic metadata approval.
- `@shieldaai/agent-guard-scenarios`: versioned scenario catalog plus executable conformance checks over the public core API. Synthetic effects only.
- `@shieldaai/agent-guard-executor`: experimental durable executor with an encrypted ledger, task and inventory HTTP servers, and Docker workload isolation.
- `@shieldaai/agent-map`: experimental read-only reference service over Cartography inventory.

The trusted resolver runs during preparation. Execution checks its bound resource and tenant context; it does not query changing ownership again. A handler/resource service must revalidate mutable ownership or resource versions before performing an effect.

Each normalized JSON value is limited to 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Bytes are counted during traversal, including escaped strings, keys and punctuation, so oversized inputs are rejected before constructing their complete serialization. The limit applies to complete request/result envelopes, metadata and other normalized structures, including the prepared-action digest envelope. Leave room for enclosing fields when sizing payloads. A malformed or oversized handler result produces `RESULT_INVALID`, charges the declared maximum and revokes that task; the operation may already have performed an effect.

## Optional inventory reference service

`@shieldaai/agent-map` consumes published Cartography inventory independently of
executor admission. Its [public contract](../packages/agent-map/README.md) defines
twelve read-only operations, shared by `POST /v1/query` and the official SDK MCP
endpoint at `POST /mcp`. The host maps distinct `agm_v1` credentials to immutable
company, tenant and team scope; request arguments cannot select a broader scope.
The local viewer uses the same operations and retains its credential only in
page memory.

Neo4j reads use fixed parameterized templates, property/relationship allowlists,
visibility filtering before materialization, explicit bounds and a publication
pointer recheck. Hidden and absent entities return the same lookup error. Team
responses omit source-wide revisions and hidden delegation/family identifiers;
shared graph nodes do not grant visibility to their other neighbors. Snapshot
comparisons apply the same scope to historical evidence and expose retention
gaps. Arbitrary Cypher, database procedures, mutations, executor dispatch and
subscription methods are unavailable through this interface.

Two of the operations are discovery leads for a reader with `allTeams: true`.
`list_undeclared_activity {sourceId, kind?, offset?, limit?}` lists the tasks or caller
principals of one source that no manifest task binding assigns to a declared agent, and
`get_inventory_health` reports their count per source as `undeclaredActivity`.
`list_unclaimed_identities {offset?, limit?}` lists the IAM roles and users of the
enrolled AWS collections whose exact ARN no declared execution binding names, as
candidates with `assessment: unknown`. A missing, stale or inconsistent collection reads
`unknown` and lists nothing. Both use their own bounded store reads, load no graph
nodes, and are subject to the same publication recheck. A team-scoped reader receives
`{visibility: 'all_teams_required', status: 'not_visible', note}` with no names and no
counts, and the store is not read. A failed count leaves `get_inventory_health`
answering with `undeclaredActivity.status: 'unknown'`. Neither operation creates an
agent or affects admission. The [package contract](../packages/agent-map/README.md#discovery)
has the fields and limits.

Every access result remains evidence: matching a grant or an exact cloud binding
does not establish effective permission. Explanations preserve unknown live
policy, arguments, approvals, backend authorization and out-of-scope ancestry.
The reference service remains optional and experimental. Company browser access
uses a separate `startMapIdentityServer` HTTPS boundary and the same `MapService`.
The [identity guide](../deployment/cartography/IDENTITY.md) documents its private
launcher and deployment contract. An exact issuer/client and verified signed
subject select a host-defined `ReadScope`; provider groups/email/team claims never
create scope. The host binding's `subject` is the issuer subject; `scope.subject`
may be an explicit internal reader alias. Every binding must match the configured
company. Request arguments, proxy identity headers and bearer credentials cannot
override this mapping.

GET `/auth/session` returns the explicit authentication mode. The bearer listener
returns only `{mode: 'bearer'}`. The HTTPS listener returns `mode: 'oidc'`,
`authenticated`, a session-bound CSRF token and an ISO expiry time. It sets opaque
Secure/HttpOnly/host-only cookies; it never returns provider tokens or claims.
POST `/auth/login`, `/auth/logout` and `/v1/query` require the same Origin, session
cookie and `X-CSRF-Token`. Login/logout accept only `{}`; query retains the existing
operation envelope. Login returns the configured provider's authorization URL;
GET `/auth/callback` consumes a browser-bound one-use PKCE/state/nonce transaction,
rotates the session and redirects only to `/` or `/?auth_error=1`. Cookie-based
MCP and caller-selected redirects are unavailable.

Sessions expire within fifteen minutes and no later than the ID token, with
monotonic deadlines as well as wall-clock checks. Login/anonymous sessions last
at most five minutes. `replaceBindings`, `revokeSubject` and `invalidateSessions`
are trusted-host methods, never HTTP routes; each invalidates all sessions and
pending logins, including results of in-flight queries. Logout affects only the
local browser session. Restart reloads private configuration and drops all
sessions. There is no provider refresh token, distributed session store, or IdP
global logout. Existing bearer HTTP/MCP behavior remains a separate local boundary.

The isolated [pilot tooling](../deployment/cartography/RUNBOOK.md) now exercises
real collection, scoped HTTP reads, private backup and fresh-graph reconstruction,
and executor admission while the graph/observer/reference processes are stopped.
Reconstruction preserves logical entity/source/snapshot identity and regenerates
physical projection IDs into a new working archive. It refuses an occupied Guard
graph and never reads or restores authority-ledger files. Packaged operational
reports retain only bounded per-label difference counts and opaque graph IDs for
30 days with pruning on each report write. Operators must apply retention cleanup
if reporting stops. Reports are neither raw inventory exports nor complete execution logs.
The corrected pilot admission stress benchmark passed its provisional latency
target after bounded per-snapshot reference caching; representative deployment
measurements remain required.
Organization-specific SSO/TLS, live cloud-account validation and rollout review
remain explicit deployment gates.

The Python collector's optional `--aws-enrollment` mode captures metadata for one
explicit commercial account, checking STS account and exact caller ARN before
inventory reads. It requires three named temporary credential values and uses
five fixed read APIs with bounded HTTPS responses, pagination and a process
deadline. It exports only allowlisted IAM role/user and general-purpose S3 bucket
identity/region metadata by default. A separate `includeIamPolicyEvidence: true`
enrollment flag permits bounded `GetAccountAuthorizationDetails` collection and
minimized S3 candidate edges. See the [AWS guide](../deployment/cartography/AWS.md) for the config and
operational limits.

One atomic graph transaction updates canonical provider metadata and scoped
`GuardAwsCollection`/`G_AWS_OBSERVED` membership. Failure leaves the last complete
capture unchanged. Missing members become unresolved without deleting shared
provider nodes; managed joins independently check capture freshness and provider
consistency before Guard publication. Legacy unmanaged provider joins retain
their existing rules. AWS refresh runs within the existing observer lock owner
on a separate monotonic cadence, with safe failure output and continued Guard
polling. This remains inventory evidence and never participates in admission.

Opt-in `policyEvidence` carries schema/mapping version, a census digest, bounded
counts, per-principal status and candidate relationships for the three packaged
S3 mappings. The publication boundary validates the complete allowlisted shape
and references against the same capture. Raw policies and condition values stay
in the worker. All candidates have unknown assessments and bucket-summary scope;
boundaries and unsupported expressions suppress the principal's candidates.
The atomic transaction replaces only owned `G_AWS_POLICY_CANDIDATE` relationships,
including their removal after a successful opt-out. Shared `CAN_*` edges remain
untouched. Missing evidence is never a denial.

The reference API exposes these observations through optional
`MapProjection.policyEvidence` records. `get_agent_access` returns
`data.policyEvidence`; `explain_access` returns it under `externalEvidence`;
`find_agents_with_access` filters it to the requested action and exact task/binding.

For a read focused on one agent, the store also runs the reverse direction and sets
`MapProjection.identityScope`: for each static execution identity, every collected
bucket in the same account the identity has a candidate on, compared with the buckets
that tool's own grants bind for that deployment. `get_agent_access` returns it as
`data.outsideGuard.identityScope`, one record per execution binding with `status`
`broader_than_grants`, `matches_grants` or `unknown` (with a `reason`), the bound
bucket names, and `extraResources` (bucket, relationship, condition flag and keys).
More than 500 candidate buckets for one identity leaves the comparison incomplete:
`unknown` with reason `truncated` and `truncated: true`, still listing the first 100
buckets. An identity row too large to keep reads the same, with no bucket list. Only identity policies are
evaluated, so extra buckets are candidates; a bucket policy, SCP or permission
boundary can still remove the access, and `matches_grants` does not mean safe. The
comparison is per bucket, not per action: an identity that can write a bucket the tool
only declares reading still reads `matches_grants`.

For `get_agent_access`, the same one-agent read also loads the in-scope delegation
ancestors of the agent's tasks (only their task records, stopping at the first ancestor
outside the reader's scope, and only if they fit the read's remaining node, edge and byte
budget; otherwise none, with the flag note `delegation_ancestors_not_loaded`) and asks, for each tool the agent holds a `*` grant on,
whether any in-scope binding of that tool is marked confidential or restricted (up to
five, as evidence). Both follow the team-wide visibility rules: a binding is in a team
reader's scope only when a task of an in-scope agent holds an exact grant on it, so a `*`
grant alone reads `unknown` for private data to a team reader. `get_agent_access` uses them for `data.boundaryFlags`.
`dangerous_three` reports whether a live task can:

- read private data: a granted binding marked `confidential` or `restricted`, or a task
  that is already sensitive (a task without a boolean `sensitive` makes this leg and its
  declared sends `unknown`);
- read outside content: a granted tool with `readsUntrusted: true`, or an untrusted task.
  Only an explicit `readsUntrusted: false` rules a tool out, since a resolver can mark any
  call untrusted;
- send out: a granted tool with `sendsExternal: true`. The core refuses those sends when
  the effective recipient set (intersected over every ancestor) is empty or the task is
  sensitive, so either makes that tool's contribution `absent`. An undeclared or
  unregistered tool may send without marking the call external and stays `unknown`.

Each leg is `present`, `absent` or `unknown`. The status is `exposed` when all three are
present and a declared sending tool's effective mode (`untrustedContext`, else the
executor's `untrustedContextDefault`) is `allow`; `mitigated` when every possible sender
uses `require_approval` or `deny`; `unknown` when no leg is known to be absent but one
(or the mode of a possible sender) is unknown; and `absent` otherwise. The agent's status is its worst live task (ranked
exposed, unknown, mitigated, absent, so a mitigated task never hides an unknown one), and
`taskId`, `legs` and `evidence` all describe that task. Evidence lists up to eight items
per leg (and for mitigation), so every present leg keeps some; `evidenceTruncated` says
when items were left out. Revoked and expired tasks (expiry judged at the snapshot's `generatedAt`, including through a
delegation ancestor, and revocation also through a handoff source, as the executor checks)
don't count; an agent with no live task is `unknown` with the note
`no_live_tasks`. Other notes:

- `ancestor_evidence_outside_visible_scope`: a parent or handoff source is outside a team
  reader's scope.
- `delegation_parent_missing`: an all-teams reader's read lacks a recorded parent or source.
- `delegation_not_recorded`: an import from before `delegated`/`derived` existed.
- `delegation_depth_exceeded`: a recorded parent or source lies more than 16 links away.
- `delegation_ancestors_not_loaded`: no room was left in the read for the ancestors.
- `delegation_evidence_ambiguous`: a task has more than one parent or handoff source.
- `task_liveness_unverified`: a `revoked` or `deadline` on the chain is missing, or the
  snapshot time does not parse.
- `flags_limit_exceeded` / `flags_timeout`: the flag alone ran out of work or time; the rest
  of `get_agent_access` still answers.

In every delegation and liveness case above the task may have a revoked or expired
ancestor, so it is never `absent`: at most `unknown`.

`list_agents` with `includeFlags: true` adds `boundaryFlags.dangerousThree` to the page it
returns, computed by a second read of only those agents under the one-agent rules, so a
badge matches `get_agent_access` (when a read has no room for an agent's ancestors, that
read reports `unknown` instead). Filtering with `flag: 'dangerous_three'` (everything
but `absent`) or `flagStatus` needs every agent's flags, so it reads the full scoped
graph and is bounded by the store's node limit.
If that second read exceeds the store's limits or fails, the listing still answers: every
agent on the page gets `dangerousThree: unknown`, and the response adds
`flagsUnavailable` (`flags_limit_exceeded`, `flags_timeout` or `flags_read_unavailable`).
The page flags use what is left of the query's time and their own work budget, so a
slow or large page degrades its flags, not the listing. `flag` with `flagStatus: absent`
is a contradiction and returns `MAP_REQUEST_INVALID`.
`get_agent_inventory` does not load this boundary evidence.

`list_resources` and `get_resource_access` read the reverse identity evidence for the
buckets that visible bindings map to: at most 32 identities (the rest report
`not_evaluated`) and 100 buckets per identity (more is `truncated`, so `unknown`). A record
whose bucket list was cut keeps resources `unknown`, since it may reach buckets it no
longer names. Each resource row gets `outsideGuard`:

- `yes`: a declared direct path targets its host resource, or a tool identity has a
  candidate on its bucket that the tool's own live grants don't bind.
  `get_resource_access` lists them under `data.outsideGuard`: at most 100 identity rows
  (one per execution binding and relationship) and 100 declared paths, with
  `identitiesTruncated` and `directAccessTruncated`.
- `none_found`: only for an S3-backed resource whose bucket the AWS collection resolved,
  when every visible execution binding has a reach record, every visible deployment declared its
  direct paths (and a `found` deployment has entries), every declared path has a target
  this read can match, every visible granted tool has an execution identity that was
  evaluated in the bucket's own AWS account, and nothing in the source lies outside the
  reader's scope.
- `unknown` otherwise, with `unknownReasons`: `binding_ambiguous`, `resource_not_collected`
  (the AWS collection has not resolved the bucket, so no identity was compared with it),
  `direct_access_undeclared`,
  `direct_access_untargeted` (a path with no target, such as a shell),
  `direct_access_target_unresolved`, `execution_identity_undeclared`,
  `identity_scope_unknown`, `identity_scope_other_account` (candidates are collected per
  account, so an identity elsewhere was never compared and a cross-account bucket policy
  could still let it in), `identity_scope_not_collected[_for_resource]` (always for a
  non-S3 resource), `outside_visible_scope` and `reach_not_evaluated`. A team reader gets
  `outside_visible_scope` whenever any deployment or task of the source is outside its
  scope, so `none_found` is mostly an all-teams answer. A task assigned to several
  deployments needs an execution binding for each granted tool on every one of them.
  Reach has its own work budget, shared by the rows of one response: when judging a
  resource would exceed that budget or the time left, the rest of the response is still
  returned, and that resource and every later row read `unknown` with the single reason
  `reach_not_evaluated` and empty lists; rows judged earlier keep their status. Reach is judged within the resource's own source: identities and
  paths of other sources are not compared. It is never proof that no path exists.

A manifest v3 `targetRef` must name a host resource declared in `resourceBindings`;
anything else is declared with `targetRef: null`. In `get_agent_access`, each declared
path has `targetStatus`: `none`, `visible`, or `outside_visible_scope` when the target is
a resource outside the reader's scope; the `targetRef` is then withheld (`null`) in the
response, its graph and `get_changes`. Past 20,000 in-scope targets the check falls back
to the resources this read holds, which can only withhold more.

A tool's own binding covers a bucket-level candidate only when it binds the whole bucket;
a bucket bound only as an object or prefix gives `unknown` with reason
`binding_narrower_than_candidate`, since the candidate may reach past it. Grants of
revoked or expired tasks (revoked through any ancestor or handoff source, expired through a
delegation ancestor) don't count as
bound; a grant whose task's chain this read cannot finish gives `unknown` with reason
`grant_lineage_unknown`, as does a task or ancestor without a boolean `revoked` or (on the
delegation chain) a numeric `deadline`, or a snapshot time that does not parse. Tools that
share one role share one
probe; a one-agent read evaluates at most 8 distinct identities (the rest are
`not_evaluated`). Each execution binding lists at most 100 extra buckets (with all their
relationships). A cut list sets `truncated: true` and the note `bucket_list_shortened`,
and keeps its status: the comparison was complete, only the listing is shorter. The same
applies when lists are dropped because the records pass 1 MiB in one read (or what is left
of the read's 4 MiB budget after 64 KiB of headroom), when the read's final copy does not
fit with them, and when the `get_agent_access` response does not fit its
size limit with the lists: they are shortened to 25, 5, then no entries before the
response is refused. If even the bare records do not fit the read, it answers without
identity scope (`not_evaluated`). If comparing grants with
identities needs more work than one read allows, the read answers without it: every
execution binding reads `unknown` with reason `not_evaluated`, and resources read
`unknown` (`identity_scope_not_collected`).

A team reader's `identityScope` names only buckets that a binding reachable from an
in-scope agent maps to. Any other bucket (another team's, or one no binding maps) is
replaced by the note `evidence_outside_visible_scope`, with no name or count, and the
status stays `broader_than_grants`. A tool with a `*` grant reports `unknown` with
reason `wildcard_grant`, since there is no narrower grant to compare its identity with.
Each record has stable entity IDs for `taskId`, `deploymentId`,
`executionBindingId`, `resourceBindingId`, `identityId` and `resourceId` (the last
two may be null for unresolved bindings), plus `action`, `status`, `reason`,
`observedAt`, `assessment: unknown`, and `candidates`. A complete record has zero
or one candidate with `relationship`, `hasCondition`, `conditionKeys` and
`resourceScope: bucket_summary`. An empty complete record uses `reason: no_candidate`
and does not mean denial. Noncomplete records contain no candidates and retain a
fixed unavailable/not-collected reason. Policy coverage is reported separately
from snapshot freshness.

The reader derives at most 512 pairs per request through visible exact task,
deployment, grant, tool and binding paths. It validates the company/tenant/account
collection, provider ownership and timestamps, current membership, candidate
hash/time and original cloud links. Current and enrolled cloud-age limits both
apply; the reader repeats its bounded observation before returning. Another
deployment's identity, another collector's candidate and shared `CAN_*` edges
cannot satisfy the pair. No raw provider documents, condition values, account-wide
policy hashes or counts are exposed. The HTTP and MCP tools share this contract.
Custom stores' supplied records receive closed-shape and exact-path validation.
Complete records require singular owning-agent, tool and binding links and unique
task/grant and grant/selector pairs. Multiple distinct grants/selectors are valid;
an ambiguous binding can only be reported as noncomplete evidence without candidates.

Policy evidence is live at query time and never attached to previous projections.
`get_changes` explicitly returns `policyHistory: not_collected`, and excludes this
layer from inventory snapshot diffs. The viewer uses separate unknown-assessment
cards and dashed candidate edges; it retains original object/prefix bindings and
independent observation times. No policy observation changes executor authority.

### Inventory source lifecycle

The trusted host can explicitly supersede an inventory generation after its
successor is completely published and archived. Both exact five-field source
identities must share company, native source ID and tenant, use the same profile,
and have different enrollment generations. A private pending/completed journal
and atomic graph tombstone fence old-generation publication and survive recovery.
Normal reference operations exclude superseded sources; concurrent supersession
invalidates the whole read. There is no reference HTTP/MCP lifecycle mutation API.
See the [operational contract](../deployment/cartography/SOURCE-LIFECYCLE.md).
