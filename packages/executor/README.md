# Agent Guard executor

**Version 0.1.0** is the first non-prerelease version. It makes no 1.x API
compatibility or long-term-support promise. The
[release notes](https://github.com/ShieldaAI/agent-guard/blob/main/docs/releases/0.1.0.md)
record the verified scope, known limits and post-release follow-ups.

The inventory observer (`startInventoryServer()`) is **experimental** in 0.1.0.
It makes no admission-latency promise under frequent polling; see the release notes.

Persist AI agent tool approvals and budget admission across restarts, with
authenticated task APIs. For the in-memory core and MCP integration, see the
[package selection guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/package-guide.md).

An additive Apache-2.0 package for a single trusted host: encrypted transactional
authorization state, task-scoped HTTP credentials, typed adapters, governed memory,
and a local Docker sandbox. Requires Node.js 22.13 or newer. No account or hosted
service is required. Install with
`npm install @shieldaai/agent-guard-executor`, or build the workspace tarballs.

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor, startExecutorServer } from '@shieldaai/agent-guard-executor';

// In production, use a private database directory and a persistent protected key.
const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
const fingerprint = executor.registerTool({
  name: 'report.read', description: 'Read a public report',
  parse(value) {
    if (value !== null) throw new Error('Expected null');
    return null;
  },
  resolve: () => ({ resourceId: 'public', tenantId: 'acme' }),
  execute: () => ({ value: 'Public report' }),
});
executor.approveTool('report.read', fingerprint);
const credential = executor.createTask({
  id: 'report-task', principalId: 'user-7', tenantId: 'acme',
  grants: [{ tool: 'report.read', resources: ['public'] }],
  budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
});
const server = await startExecutorServer({ executor,
  adminToken: randomBytes(32).toString('base64url'), operatorId: 'authenticated-operator',
});
// Give the agent only credential.token and server.url through an isolated channel.
// Keep executor, administrator token, encryption key and provider credentials private.
console.log(credential.taskId, server.url);
await server.close();
executor.close();
```

## Authority and transport

`DurableExecutor` is an administration object; never expose it to untrusted code.
The reference server binds only `127.0.0.1`. Task bearer credentials authenticate a
single task. Preparation, execution, snapshots, cancellation and narrowed delegation
derive identity from that token. Administration uses a separate secret; approval
identity is configured by the authenticated host, not accepted from request bodies.
Browser-origin requests, unknown paths, oversized JSON and WebSocket upgrades are
rejected. No browser login, OAuth server, public TLS listener or automatic token
renewal is included. Deploy remote clients only through a separately protected,
authenticated transport. Local loopback alone is not agent isolation.

`ExecutorClient` exposes only task operations. It refuses remote plaintext HTTP and
redirects, bounds responses, and requests cancellation when an execution signal is
aborted. Cancellation is cooperative; already accepted backend effects cannot be
retracted. A canceled preparation cannot later dispatch.

For an `APPROVAL_REQUIRED` response, show the exact prepared action to the authenticated
reviewer. On a dispatch error or lost response, call `client.execution(action.id)` to
inspect the task's retained status. If it is `UNKNOWN`, stop and give the action ID to
the operator for backend reconciliation. Starting a new action can repeat an effect.
Task responses carry fixed denial codes. Backend exception text stays on the executor side.
When the reviewer refuses a prepared action, the trusted host calls
`executor.cancel(taskId, action.id)` to retire it and prevent dispatch with an
earlier approval. `recordReviewDecision(action.id, 'denied')` only records the review.

Mandatory grant, tenant, recipient, deadline, sensitivity and integer budget gates
are shared with the embedded core. Arguments pass a trusted `ToolDefinition.parse`
before resource resolution. `resourceVersion` is bound into the prepared action;
the resource adapter must recheck it at the effect boundary. Custom policy can only
tighten these gates. Changing a policy or registering a tool invalidates old work.
The executor accepts up to eight unresolved policy checks per task family and 64 per
instance. A saturated scope returns `POLICY_BUSY`. Each caller waits up to 30 seconds
or its task deadline, whichever comes first. Policy code receives an abort signal.
A callback that keeps running after cancellation occupies its slot until it settles.
A decision becomes stale only if the task's own snapshot (counters or shared
sensitivity) changed while the policy ran; writes by other tasks or tenants never
invalidate it. A stale decision is evaluated again on fresh state. Re-evaluations on
one task take turns, up to `maxPolicyAttempts` (1–16, default 5); after that the call
fails with `POLICY_STATE_CHANGED`. Without a custom policy, no decision can be stale.

## Durable admission and recovery

Use one executor owner per SQLite file on a local filesystem. A second owner fails
closed under SQLite's process lock. A transaction rechecks authority, consumes one
approval, reserves every ancestor budget and records admission before dispatch.
The state sequence is `PREPARED -> ADMITTED -> RUNNING -> SUCCEEDED/FAILED/UNKNOWN`.
Immediately before calling the handler, the executor checks the task and approval
deadlines again. Expiry during persistence settles as `FAILED` with a consumed
admission, zero charge and no handler call.
Generic handler failure or process loss after admission is `UNKNOWN`: no automatic
retry, refund or concurrency release. `reconcile()` requires operator evidence that
work ended, an exact outcome and bounded actual cost. Its evidence reference is
hashed into the record; repeating settlement is rejected. This is not exactly-once
remote delivery. Use backend idempotency/status APIs where available.

On restart, consumed calls, revocations, labels and reservations survive, but tool
approvals and outstanding preparations must be reviewed again. Backward clock
movement fails closed. Missing cost charges the declared maximum; invalid or overrun
cost revokes the task and keeps the uncertain reservation. Backend/provider limits
must enforce the declared maximum; estimates are not invoice guarantees.

Ledger contents, including retained arguments, are AES-256-GCM encrypted with an
operator-supplied 32-byte key. Keep the stable key and backups outside guest access.
POSIX directories must be canonical, owner-only; files must be private regular files
without hard links. Windows ACL provisioning remains the operator's responsibility
and requires platform validation. The host administrator, clock, key store, SQLite
runtime and encryption-key backup are trusted. Losing the key makes state unreadable;
restoring an old database can roll back authority and must not be used as recovery.

If a database or its volume may be restored independently, enable
`rollbackWitness` when provisioning a **new** POSIX ledger. It pairs the exact
encrypted state with a private second SQLite file that remains current across
database restores. If a pre-revocation copy is substituted, the executor refuses
to open even with the correct encryption key. See the
[restore and rollback procedure](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/ledger-rollback.md)
for setup, failure handling and the crucial requirement that the witness stay
outside the data backup/restore domain.

Live ledger state defaults to 16 MiB. The trusted host may set `maxLedgerBytes`
to an integer from 1 MiB through 64 MiB. It bounds the decoded full snapshot,
not SQLite file size; larger snapshots increase synchronous memory and I/O work.
Opening existing state above the configured bound fails before recovery mutates it.
Increasing this limit does not raise task, action, family or archive count limits.
Family-wide pending action/byte and delegated-task
caps prevent one task from filling shared storage through preparation/delegation.
Expired or invalidated preparations and approvals are pruned. Terminal records have
bounded retention; cumulative budgets and unresolved reservations are retained.
The audit keeps the latest 1,000 metadata events, without arguments, results or raw
reconciliation evidence. Task and action IDs are host-controlled audit metadata;
avoid putting secrets in IDs. There is no automatic quota reset or distributed-worker
support. Use the host-only task-family lifecycle APIs below for bounded archival;
never delete active authority state to recover quota.

Offline Linux/macOS maintenance is available through `agent-guard-ledger` and
`createLedgerKeyring`, `readLedgerKeyring`, `readLedgerKeyringPolicy`,
`configureLedgerKeyring`, `loadLedgerKey`, `rotateLedgerKeyring` and `rotateLedgerKey`. The loader authenticates existing state and refuses missing
or mismatched authority. Rotation preserves the complete plaintext ledger and
atomically updates its witness. The private keyring stages a new key before rekeying,
retains old keys for interruption recovery, and defaults to four retained keys.
An explicit `maxKeys` at creation or `configureLedgerKeyring({ keyringFile, maxKeys })`
persists a validated limit from 1 through 64. `agent-guard-ledger configure --keyring
PATH --max-keys N` performs the same atomic offline update. Lowering below the retained
key count fails; this policy command never removes keys. Legacy schema-1 keyrings keep their four-key
default until configured. `readLedgerKeyringPolicy` and CLI `status` return only
`keyCount` and `maxKeys` (plus the selected key ID when a database is specified). Stop
the sole owner, rotate each store using the same next key ID, verify, then restart.
Never use first enrollment as recovery. Returned key buffers belong to the trusted
host caller and should be erased after creating the executor. Maintenance
`LedgerKeyOptions.maxBytes` and `rotateLedgerKey({ ..., maxBytes })` accept the
configured store byte cap (default 16 MiB, 1024-byte minimum, 64 MiB ceiling); the CLI
uses `--max-bytes N`. Set it consistently when loading and rotating larger stores.
A smaller cap refuses oversized existing state before mutation.

Outer-key-derived inventory and trace references change during rotation; receipts
report `observationReenrollmentRequired: true`. Use a new inventory
`enrollmentGeneration` and a new trace collection epoch before resuming exports.
The [Linux operations runbook](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/production/README.md)
includes private key custody, two-store commands, backup/restore, supported bounds
and interrupted-rotation handling. The CLI prints redacted JSON, never key material.

`manageLedgerCustody` adds reviewed offline enrollment, cold snapshots, full verification,
current-witness restore, managed rotation, active-ring retirement and interrupted-operation
recovery. Retirement preserves all historical keys in independently encrypted escrow; it
never destroys secrets or claims to enumerate off-host backups. Managed source ledgers
carry a schema-2 custody binding, and runtime key loading rejects a rolled-back unmarked
ring. Restore never rewrites witnesses or accepts an older snapshot after they advance.
A host adapter must derive the complete encrypted external-history closure from authenticated
store heads. See the [custody procedure](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/production/custody.md)
for exact preview/apply commands, offline key separation, capacity bounds and recovery limits.

For exact-current primary-storage recovery, `LedgerWitness.recovery: 'mirror'` enables
schema-3 witnessed state whose encrypted payload, archive/catalog mutations and rekeying
are mirrored in the paired SQLite transaction. The witness is SQLite's physical main
database so its super-journal survives primary-directory loss. `manageLedgerRecovery`
provides exact preview/apply enrollment or repair; repair preserves current witnesses
and source identities and requires surviving witnesses, keys and the complete external
history mirror. Mirrored mode cannot be removed or written by schema-1/2 readers.
See the [native recovery procedure](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/production/custody.md#repair-the-latest-committed-state-after-primary-storage-loss).

For optional diagnostics without raw task/action identifiers, enable
`decisionTraces` on the executor. `decisionTraceSnapshot()` and
`exportDecisionTraces()` expose bounded tenant-scoped events through host-only APIs.
Export is explicit and runs outside admission; exporter failure never retries a
tool effect. Buffers are volatile and can lose events through expiry, capacity or
process loss. The [decision trace guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/decision-traces.md)
describes the pseudonymous fields, access boundary, counters and export guarantees.

## Adapters and integrations

### Inventory for the trusted host

**Experimental in 0.1.0.** On hosted runners, admission latency during 250 ms
polling has passed and failed the 10% overhead gate on identical code, so 0.1.0
makes no latency promise under frequent polling. Keep Cartography's default
300-second collection interval.

Enable the optional exporter with host-controlled enrollment configuration:

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor, type InventorySnapshot } from '@shieldaai/agent-guard-executor';

// This in-memory example has no durable identity after close. A real installation
// uses its existing private SQLite path and persistent protected encryption key.
const executor = new DurableExecutor({
  database: ':memory:', encryptionKey: randomBytes(32),
  inventory: { companyId: 'acme', sourceId: 'executor-eu-1', enrollmentGeneration: 'enrollment-1' },
});
// Register tools and create tasks through the normal host APIs before exporting.
const snapshot: InventorySnapshot = executor.inventorySnapshot({ tenantId: 'acme' });
console.log(JSON.stringify(snapshot));
executor.close();
```

`inventorySnapshot()` is synchronous and reads the encrypted ledger once. Its
deeply immutable result contains all retained tasks for exactly one tenant,
including expired and revoked tasks, and only persisted tool registrations named
by those tasks' grants. An empty tenant has a complete empty inventory. Unknown
granted tools remain unresolved references. There are no task filters or pagination.
The host chooses the tenant; this administration method is not an authentication
boundary. Task/admin HTTP handlers and `ExecutorClient` do not expose it. Use the
separate scoped observer listener below for collector access.

The version-1 core profile reports normalized grants, budgets, usage, distinct
delegation and provenance edges, family sensitivity and registration/approval
state. Fingerprints use bare SHA-256 hex in the wire contract. After restart,
persisted tool records have `registered: false`, reset approval and `null` live
flags until registration. MCP, host manifest and cloud coverage are `not_collected`.
Declared grants and these flags describe configuration; they are not an execution
authorization decision. Provenance does not inherit the source task's grants or
budgets.

Snapshots omit credentials and hashes, approval/action records, arguments, results,
memory, audit records, tool descriptions, schemas and arbitrary metadata. Resource
and recipient identifiers are tenant-scoped HMAC references by default, derived
from the protected ledger key and enrollment. The exact resource wildcard `*`
is preserved. Equal references remain joinable across snapshots and restarts;
resource and recipient namespaces are separate. Task, principal, family and tool
names remain visible, so host-controlled identifiers must contain no secrets.
Set `inventory.referenceMode: 'raw'` only for reviewed non-secret resource aliases
and recipients that are intended for export; raw mode does not redact those values.

Every ledger now gets an encrypted random `inventoryInstanceId`. Existing schema-1
ledgers receive it once in an atomic additive migration, advancing revision once
without changing authority. It survives restart and previous schema-1 reader/writer
round trips; a fresh ledger gets a fresh ID. Clones and restored backups retain the
ID, so explicitly rotate `enrollmentGeneration` and reenroll the collector after
restore/clone, encryption-key changes or reference-mode changes. The exporter cannot
detect every restore. Never restore authority state merely to repair inventory.

Export invokes no policy, parser, resolver, execution or authorization-clock
callbacks, and changes no counters, approvals, audit events or revision. Generation
timestamps use observation wall time, independently of the authorization clock.
Each export has a new snapshot ID. Limits include 10,000 tasks/tools, 2,048 normalized
grants per task, 1,024 selectors per grant/recipients per task, 100,000 total resource
selectors, 500,000 JSON values and at most 8 MiB encoded JSON (with small serializer
headroom). Exceeding a limit throws `INVENTORY_LIMIT_EXCEEDED`; nothing is truncated.
Disabled export, invalid configuration/scope, inconsistent state and invalid
observation time have stable `INVENTORY_*` error codes without source values.
The direct `inventorySnapshot()` API remains synchronous and has no interruptible
time limit. The HTTP observer described below uses a private worker. Neither API
provides a per-poll latency guarantee. See the repository's Cartography integration plan and
canonical `schemas/agent-guard-inventory-v1.schema.json` for the consumer contract.

The [Cartography pilot runbook](../../deployment/cartography/RUNBOOK.md) supplies
an isolated live observer/collector/reference exercise, private archive backup and
fresh-graph reconstruction, minimized operational differences and representative
query/publication benchmarks. Its synthetic executor continues admitting allowed
calls and denying forbidden resources while the graph and observer/reference
services are stopped. Graph reconstruction never reads or restores an authority
ledger. The Python/Neo4j pilot remains optional and outside execution admission.

### Host-owned manifest and bindings

`validateInventoryManifest(value)` checks and freezes host-authored configuration
against the version-1 or version-2 manifest contract. `composeInventorySnapshot(core, manifest)`
validates both inputs and produces a separate `HostInventorySnapshot` with
`profile: 'host'`. The original core snapshot stays unchanged. The manifest is
configuration owned by the trusted operator; it is never read from tool metadata,
model output, request parameters or a request-selected file.

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor, validateInventoryManifest, composeInventorySnapshot } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
  inventory: { companyId: 'acme', sourceId: 'executor-eu-1', enrollmentGeneration: 'host-enrollment-1' } });
executor.createTask({ id: 'report-task', principalId: 'application-caller', tenantId: 'acme', grants: [],
  budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
const core = executor.inventorySnapshot({ tenantId: 'acme' });
const manifest = validateInventoryManifest({
  schemaVersion: 1, evidenceKind: 'host_asserted', source: core.source,
  manifestId: 'host-config', revision: 1, observedAt: new Date().toISOString(),
  agents: [{ id: 'report-agent', name: 'Report agent', ownerId: 'operator', teamId: 'reports' }],
  deployments: [{ id: 'deployment-1', agentId: 'report-agent', environment: 'production' }],
  taskBindings: [{ taskId: 'report-task', deploymentId: 'deployment-1' }],
  resourceBindings: [], executionBindings: [],
});
const composed = composeInventorySnapshot(core, manifest);
console.log(composed.profile, composed.manifest.revision, composed.ledgerRevision);
executor.close();
```

All five source fields must match exactly, including tenant, enrollment generation
and persistent ledger identity. Every property is allowlisted. Names, owner/team
IDs and environment labels are host-reviewed metadata; keep secrets out of them.
No manifest field can set grants, budgets, sensitivity, revocation or approval.
Version-2 resource sensitivity is a host inventory label; it cannot change the
executor's task/family sensitivity or data-handling policy.
Tasks without a binding remain in the complete inventory, without an inferred
agent or deployment. Unknown fields, duplicate/conflicting bindings, missing
references and mismatched source identities fail rather than being discarded.

| Manifest collection | Binding semantics |
| --- | --- |
| `agents` | Explicit agent ID, name, nullable owner/team IDs. Independent of caller principals. |
| `deployments` | Explicit deployment ID, agent ID and nullable environment. |
| `taskBindings` | One deployment per bound task; the task must exist in this snapshot. |
| `resourceBindings` | One mapping per `(tool, resourceRef)`, with exact AWS target, actions and scope. |
| `executionBindings` | One mapping per `(deploymentId, tool)`; optional connection ID and static, dynamic or unknown execution identity. |

Version 2 adds a company authority, a bounded owner directory, agent purpose and
lifecycle, explicit assigned/unassigned/unknown ownership, deployment/build
references, resource sensitivity/destination/dependency metadata and an opaque
credential-reference catalog. A generic host resource may represent a repository,
database, queue, service or storage resource without requiring AWS. These targets
are scoped observations and never receive inferred AWS permission edges.

Use the [company cartography guide](../../docs/guides/agent-cartography.md) and
`node examples/agent-cartography.mjs` for the complete version-2 path through the
authenticated observer. The exact closed fields and compatibility rules are in
[`agent-guard-inventory-manifest-v2.schema.json`](../../schemas/agent-guard-inventory-manifest-v2.schema.json).
Credential, runtime, build and destination references use tenant-scoped opaque
identifiers, never secret bytes or credential URLs. Keep display names and purpose
free of secrets. Ownership is metadata; a team name or owner record cannot grant
Map visibility or executor access.

`resourceRef` is the exact **exported** selector under that tool's grant, including
its opaque value in the default mode. Obtain it from a trusted core snapshot and
store it in the host configuration; do not substitute a raw alias or match by
display name. Unmatched references fail composition. `*` remains a local selector
and cannot be mapped to an external resource. Target bucket, object and prefix
scopes remain distinct; a prefix requires an explicit trailing-slash prefix ARN
and `scope: 'prefix'`. Actions are explicit service-qualified names without
wildcards. Nothing in these bindings establishes that a backend action is allowed.

Version 1 supports the `aws`, `aws-cn` and `aws-us-gov` partitions, with exact ARN,
region and account consistency. Static execution identities are IAM roles/users
or STS assumed-role sessions, using the global identity ARN formats described in
[AWS's identifier reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html).
Dynamic/unknown selection requires `identity: null`; a caller principal is never
substituted for an execution identity. S3 ARNs omit the account, so their explicit
`accountId` is only a host ownership assertion. No AWS lookup, IAM policy evaluation
or provider-inventory join occurs. Connection IDs are host assertions, not evidence
of a live MCP connection. MCP/cloud coverage remains uncollected.

Composition preserves tasks, tools, grants, counters, ledger revision, policy epoch
and their capture timestamps, and invokes no executor callbacks. The composed
snapshot receives a new ID and generation time; manifest coverage records its own
`observedAt`. These are separate observations, not an atomic capture. Keep a stable
`manifestId` and increment `revision` whenever associations change. The graph
collector checks this revision independently of the ledger, rejecting rollback or
different associations at the same revision. It pins the profile for the enrolled
source: rotate `enrollmentGeneration` before changing a published core source to
host, changing manifest identity, or performing the restore/key changes described
above. The core permission content cannot change at an unchanged ledger revision.

Manifest limits are 2 MiB, 200,000 JSON values, 1,000 agents/deployments, 10,000 of
each binding type and 128 actions per resource binding. Composed output still has
the 8 MiB/500,000-value snapshot cap. Invalid configuration returns stable
`INVENTORY_MANIFEST_*` errors without source values; invalid core input returns
`INVENTORY_SNAPSHOT_INVALID`. No partial or silently downgraded host snapshot is
returned. See `schemas/agent-guard-inventory-manifest-v1.schema.json` and run
`node examples/inventory-manifest.mjs` after building for a complete synthetic
resource/identity binding and observer example.

### MCP inventory composition

`composeMcpInventorySnapshot(hostSnapshot, sources)` adds MCP observations to a
validated host snapshot and returns an immutable `profile: 'host-mcp'` snapshot.
Each source is `{ tenantId, connectionId, source: managedConnection }`, where the
host-owned `source.inventory()` is synchronous. Connection IDs match non-null
`manifest.executionBindings[].connectionId` values. Only sources selected by both
tenant and manifest are called; only explicitly bound operation names are exported.
Core tools must be registered with matching fingerprints for those operations.
Missing operations after descriptor removal remain absent.

`validateMcpInventorySources(value)` captures reader methods and freezes the
registry; `validateMcpConnectionInventory(value)` validates and detaches a closed
connection observation. These helpers require no MCP runtime dependency. Limits
are 1,024 configured readers, 128 selected connection IDs, 256 operations and
2 MiB per connection, 10,000 composed operations, and 8 MiB overall. Data accessors
and unknown fields are rejected. Readers must return synchronous data; exceptions,
malformed data and Promise results become safe `capture_failed` records.

Composition reads selected connections before and after projection. A change
other than capture time produces an unavailable `changed` record. Other reasons
are `missing`, `scope_mismatch` and `registration_mismatch`. Unavailable records
contain no old registry or error text. Coverage is `complete` when every expected
connection was observed (including closed/quarantined connections), `partial`
when some were observed, and `unavailable` when none were observed. An empty
expected set is complete. Coverage describes observation, not operational health.

The new snapshot preserves core authority and prior component capture times,
adding its own timestamp and snapshot ID. It does not claim an atomic capture
across executor, host configuration and MCP state. No connection observation can
grant access, approve a tool or change execution state. Keep reader implementations
bounded and free of side effects; the managed connection's inventory method is
designed for this use.

For HTTP delivery, use a credential with `profile: 'host-mcp'`, supply its tenant
manifest and pass `mcpSources` to `startInventoryServer()`. The listener captures
the registry at startup, while each request reads current connection state.
Missing optional sources can publish fresh core state with unavailable MCP
coverage. Core and host credentials never invoke MCP readers. Changing profile
for graph ingestion requires a new enrollment generation. See the runnable
SDK/executor bridge at `integrations/cartography/tests/fixtures/mcp-executor.mjs`.

### Observer HTTP transport

`startInventoryServer()` opens a separate listener on `127.0.0.1`. Its only route
is `POST /v1/inventory/snapshot` with an exact JSON body `{ "tenantId": "acme" }`.
Configure independent credentials with fixed tenant allowlists; a request selects
one permitted tenant and always returns that tenant's complete core inventory.
`profile` is host-controlled and supports `core` (the default), `host` or `host-mcp`. Request filters,
profile overrides and duplicate JSON keys are rejected.

For a host-profile credential, supply `manifests: [validatedManifest, ...]` to
`startInventoryServer()` and set that credential's `profile: 'host'`. Every tenant
in its allowlist must have exactly one manifest. Up to 1,024 manifests with an
aggregate 8 MiB/500,000-value configuration cap are accepted. The listener validates
and copies them at startup, then checks bindings against each fresh core snapshot.
Replace the listener to install a new manifest revision. Core credentials continue
to receive only core data; a missing or stale host binding fails the host request
without falling back to core or changing authorization state.

```ts
import { randomBytes } from 'node:crypto';
import { DurableExecutor, createInventoryObserverToken, startInventoryServer } from '@shieldaai/agent-guard-executor';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
  inventory: { companyId: 'acme', sourceId: 'executor-eu-1', enrollmentGeneration: 'enrollment-1' } });
const token = createInventoryObserverToken();
const observer = await startInventoryServer({ executor,
  observers: [{ token, tenantIds: ['acme'], profile: 'core' }],
});
try {
  const response = await fetch(`${observer.url}/v1/inventory/snapshot`, {
    method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'acme' }),
  });
  if (!response.ok) throw new Error('Inventory collection failed');
  const snapshot = await response.json();
  console.log(snapshot);
} finally { await observer.close(); executor.close(); }
```

The token helper generates 32 random bytes in the `agi_v1.` namespace. Task and
admin credentials cannot authenticate here, and observer credentials cannot call
execution or administration routes. Tokens are hashed for comparison; credential
and tenant configuration is copied at startup. Keep tokens outside agent workloads,
request URLs and logs. To revoke or rotate a credential, close its listener and
start a replacement with the new host configuration. Closing the listener aborts
its sockets and is idempotent; it does not close or modify the executor.

Requests require one Bearer authorization header and JSON content type. The server
rejects browser Origin/Fetch-Site metadata, duplicate singleton headers, compression,
unexpected Host values, query strings, upgrades, CONNECT and Expect requests.
Standalone `Sec-Fetch-Mode: cors` is accepted for Node's native `fetch`; other fetch
metadata and modes are rejected.
Responses use `Cache-Control: no-store`, exact content lengths and no CORS headers.
Authorization failures reveal no task or tenant contents and never invoke export.

| Option | Default | Accepted range |
| --- | --- | --- |
| `maxRequestBytes` | 16 KiB | 1 byte–64 KiB |
| `maxResponseBytes` | 8 MiB | 128 bytes–8 MiB |
| `requestTimeoutMs` | 10,000 | 10–60,000 |
| `maxConcurrentRequests` | 4 | 1–64 |
| `maxConnections` | 32 | 1–256 |
| `rateLimit.maxRequests` | 60 | 1–10,000 |
| `rateLimit.windowMs` | 60,000 | 10–60,000 |

At most 128 credentials with 1,024 unique tenants each are supported, with an 8 MiB
aggregate configuration cap. Headers are capped at 8 KiB. Fixed-window rate limits apply per credential, including invalid
scope/body attempts; a shared limit also bounds all attempts, using the configured
request count times the credential count, capped at 10,000. Quota failures return
429 with `Retry-After`; full request capacity returns 503. Slow or disconnected
clients hold a concurrency slot until their response finishes or closes.

The server waits for a private worker to become ready before opening its listener
(startup is bounded to five seconds). Observer listeners for one executor share
one worker and a four-job queue, counting the running job. `maxConcurrentRequests`
still bounds each listener's HTTP connections doing request/response work; setting
it above four does not increase the shared observation queue. Queue exhaustion
returns 503 `INVENTORY_BUSY`. Closing one listener leaves other listeners usable;
closing the last listener waits for worker termination. An unverified termination
leaves observation unavailable for that executor instead of starting another worker.

The trusted host can explicitly select a Linux background scheduling policy:

```js
const observer = await startInventoryServer({
  executor,
  observers: [{ token, tenantIds: ['tenant'] }],
  workerScheduling: 'linux-background',
});
```

The default `workerScheduling: 'default'` leaves native priorities unchanged.
`linux-background` synchronously verifies the worker's own Linux native thread
identity and lowers its priority by up to five nice levels, capped at nice 19
(`min(19, initial nice + 5)`). This is a fixed policy, not a caller-supplied value.
It never raises priority or requires `CAP_SYS_NICE`. Startup refuses with
`INVENTORY_SCHEDULING_UNAVAILABLE` if Linux `/proc` identity, the priority operation,
or exact readback cannot be verified; there is no fallback to default scheduling.
Listeners sharing an executor must select the same policy, and replacement workers
retain it. The policy applies to that native worker thread; it does not promise a
priority for every V8 helper or GC thread. Lower priority can delay observation,
so qualify both admission overhead and polling cadence for the selected deployment
without changing request deadlines, quotas or memory limits. The setting is not an
observer credential or request option. Qualification must bind the exact runtime
and policy; historical measurements do not qualify a changed implementation.

Each dispatched request captures fresh encrypted state and verifies its current
witness and recovery mirror on the owning thread. The worker authenticates and
decodes that captured state, projects the tenant's inventory, composes the host
profile and serializes the response. It receives detached key copies and validated
primitive tool flags, with no database handle or tool callbacks. Key copies are
zeroed after use. No authority or response is cached between polls. The snapshot
and its timestamp describe the capture point; a concurrent later mutation appears
in a later snapshot. MCP callbacks remain on the owning thread: two full lifecycle
digests bracket MCP projection, while only manifest-selected operations are
transferred. Their aggregate transfer is capped at 8 MiB and 10,000 operations,
in addition to the existing per-connection validation and final snapshot limits.

The worker's V8 old-generation heap ceiling is
`128 + 32 * ceil(maxLedgerBytes / MiB)` MiB (640 MiB at the default 16 MiB ledger
limit; 2,176 MiB at 64 MiB), plus a 32 MiB young-generation ceiling. These are
ceilings, not reserved memory or whole-process RSS limits. Budget for the host,
one worker, an encrypted state copy, detached registration metadata (bounded to
four times the ledger byte cap), MCP inputs and response copies together. A small
container memory limit can terminate the process before a V8 ceiling is reached;
raising `maxLedgerBytes` requires workload-specific memory validation. A legal
byte count alone does not guarantee that every adversarial JSON shape fits the
available memory. The reference Agent Ops service does not start this observer.

The server checks the entire serialized snapshot before sending success. A response
cap failure returns 413 with `INVENTORY_RESPONSE_TOO_LARGE`, without a partial
snapshot. The deadline spans upload, capture, queuing, worker generation,
serialization and writing. Timeout or disconnect discards pending output and
terminates running worker work; its slot is retained until termination is verified.
Owning-thread SQLite checks and MCP callbacks remain synchronous and cannot be
preempted, so elapsed time is checked again after those stages. An overdue snapshot
returns 408 and a stalled response is closed; clients must reject incomplete bodies.
Inventory's record/work bounds still apply.
The [isolated pilot benchmark](../../deployment/cartography/RUNBOOK.md#performance-gate)
measures admission with and without actual HTTP inventory polling. Its recorded
[30 October 2026 result](../../deployment/cartography/validation/admission-2026-10-30.json)
for 100 tasks and 1,000 grants passed the provisional 10% p95 admission regression
target after bounded snapshot-local reference caching. That historical result
does not establish acceptance of the current candidate; the
[6 November candidate record](../../docs/validation/cartography-pilot-2026-11-06.json)
retains later successes, failures and measurement qualifications. A passing smoke
check does not certify the separate 10% acceptance target. The 250 ms stress
cadence is distinct from the collector's five-minute default; representative
deployment measurements are still required. The cache never persists snapshots
or changes references.

For a central company collector, use an operator-configured authenticated TLS
bridge restricted to this route. Preserve the observer's loopback Host header and
never expose the executor database or admin listener. The example does not provide
remote TLS, certificate issuance or automatic polling.
Run `node examples/inventory-export.mjs` after building the repository for a
synthetic end-to-end snapshot without printing credentials.

### Existing execution integrations

`createRestrictedFetch` enforces exact origins and checks all resolved addresses in
the socket's DNS callback. Non-public IPv4/IPv6 addresses require an explicit origin
exception. Requests bypass proxy environment settings, never follow redirects, and
bound request/response bytes and elapsed time. TLS certificate verification remains
enabled. There is no automatic OAuth discovery or credential refresh. Supply this
fetch to the managed MCP HTTP transport and keep credential issuance outside model
authority. MCP's managed connection separately gates descriptor changes, bounded
local schemas, session identity, resources/prompts and unsupported capabilities.

`createModelTool` keeps a fixed model, tenant, recipient and host provider callback.
The executor reserves each request before invoking that callback. The callback owns
credentials and must honor output/cost limits. `createExecutorModelProvider`
implements the SafeCall Node provider shape; retries and repairs each traverse a
new executor admission. Its stream is buffered. SafeCall's own buffered mode then
validates the final output before releasing it. Sensitive task families cannot send
to an external model, even when its recipient is normally allowed.

`registerMemoryTools()` returns separately approvable read/write fingerprints.
Grants name exact entry IDs. Reads return a versioned envelope; source text never
grants authority. Host imports default to sensitive and untrusted. Writes inherit
family sensitivity and known read lineage, and are always untrusted. Exact versions
prevent stale writes. Host `quarantineMemory()` propagates to known descendants;
`rollbackMemory()` appends a version without lowering sensitivity. Quarantine is the
available logical deletion mechanism; encrypted history remains retained. Family
memory history is bounded to 512 KiB/256 writes, and each entry to 128 versions.
Use `createTask(options, {sourceTaskId})` for a new root handoff with shared labels.
Source edges persist across restart; revoking a source blocks derived authority and
quarantines its known memory descendants. Historical expiry alone does not erase
provenance or prevent an operator-authorized new task from importing old data.
Unmediated file reads, arbitrary summaries and independent roots do not automatically
carry labels; label imported workspaces conservatively at the session boundary.

The Docker launcher runs selected copies in a nonroot, read-only, capability-free,
network-disabled Linux container, also usable through a local Linux VM on macOS or
Windows. It returns bounded artifacts for separate hash-bound review and export.
See [deployment profiles](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/README.md).
This is not yet a complete networked coding-agent session. Never describe this
experimental implementation as certified isolation on all three platforms.

`ArtifactBroker` signs tenant, content hashes, sensitivity and transitive source
lineage for files, stdout and stderr. Raw input defaults to sensitive. Verified
imports into fresh roots keep labels and reject revoked sources even after restart.
`createSandboxTool` binds approval to the actual bytes copied into the guest.
A changed input requires a fresh review. Both the raw Docker launcher and the
governed tool reject path traversal through symbolic links and hard-linked
files. On Linux, file capture requires procfs at `/proc`. On Windows, use a
fixed local drive and Windows PowerShell with permission to compile the
file-handle helper. Hosted CI exercises the native file reader; full Windows
Docker isolation remains a candidate profile requiring deployment verification. Follow the
[Windows preflight and failure procedure](https://github.com/ShieldaAI/agent-guard/blob/main/deployment/README.md#windows-preflight-and-failure-handling)
and pass its native file-reader and full platform checks before enabling it.
The tool applies the executor's budget, forwards cancellation, and retains
complete results with the host.
Only bounded logs and artifact references reach the model. Reviewed exports require
exact hashes and preserve a signed sidecar. Host signing keys and classification
decisions must stay outside agent authority; the raw launcher does not provide this
provenance contract. A signature does not make untrusted content trustworthy.

For externally built inputs, configure `ArtifactBroker` with a host-owned
`buildPolicy` and call `admitBuildArtifact`. It verifies an Ed25519 DSSE
signature and pins the file bytes, tenant, path, builder identity, build type
and reported source dependency. The governed sandbox requires signed receipts
for every selected input. Version-2 root and derived receipts bind the policy
digest so a changed enrollment rejects old imports. See the
[build artifact admission guide](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/build-artifact-admission.md).

For an enrolled deployment, `agent-guard-pilot-review --policy policy.json --candidate candidate.bin --bundle evidence.json` verifies the build, operator observations and independent approval locally. The package also exports `verifyPilotReview`. [Scope, signing and file formats](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/pilot-review.md)

## Verification and supported profiles

`npm run check` builds all packages, runs adversarial/benign tests and installs the
tarballs into a clean consumer. Executor tests use actual SQLite, process exits,
HTTP collectors, scoped credentials and versioned memory. The optional Docker tests
must run without skips for platform evidence. The platform workflow records runtime
metadata and refuses a missing pinned image.

The [candidate verification record](https://github.com/ShieldaAI/agent-guard/blob/main/docs/validation/guarded-input-review-2026-11-05.json)
records 44/44 platform checks on macOS arm64 and 44/44 with the executor running as
a Linux arm64 process inside Colima against its native daemon, each with zero skips.
An offline installed consumer exercised approved raw and attested inputs through
the actual Docker runtime. A separate disposable Linux VM exercised three abrupt
guest interruptions against the exact packaged executor and recovered consistent
ledger/witness pairs. The host and physical storage remained powered.

Native Windows runtime verification remains a prerequisite for Windows rollout.
The bounded offline sandbox, single-owner durable executor and documented MCP and
provider adapters form the implemented project profiles. A complete networked
coding-agent session and distributed execution require additional implementation.
Deployments enroll their own trusted builders, credentials and endpoints and set
their retention and recovery procedures. An independent security review can inform
a deployment's assurance decision. Physical storage durability and backup custody
need validation on the storage and backup system that deployment uses.

## Task-family lifecycle

For a completed workflow, the trusted host can retire and archive its entire task
family. This includes delegates and roots linked with `sourceTaskId`. Authenticate
the maintenance operator before choosing the tenant; these methods are not exposed
through task/admin HTTP or `ExecutorClient`.

```ts
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import { randomBytes } from 'node:crypto';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
executor.createTask({
  id: 'completed-task', principalId: 'operator', tenantId: 'acme', grants: [],
  budget: { maxCalls: 0, maxConcurrent: 0, maxCost: 0, deadline: Date.now() + 60_000 },
});
const scope = { tenantId: 'acme', taskId: 'completed-task' };
const beforeRetirement = executor.previewTaskFamilyRetirement(scope);
if (beforeRetirement.retirementBlockers.length) throw new Error('Resolve unfinished work first');
executor.retireTaskFamily({ ...scope, expectedDigest: beforeRetirement.reviewDigest });
const beforeArchive = executor.previewTaskFamilyRetirement(scope);
if (beforeArchive.archiveBlockers.length) throw new Error('Resolve retained references first');
const receipt = executor.archiveTaskFamily({ ...scope, expectedDigest: beforeArchive.reviewDigest });
console.log(receipt.archiveId, executor.findTaskFamilyArchive(scope)?.archiveId);
executor.close();
```

Use a private on-disk ledger and persistent protected key for actual retention.
Previews contain bounded counts and blockers, never arguments or keys. An
intervening ledger write or restart invalidates the digest; the host also owns
review expiry and user binding. Retirement revokes the whole family and cancels
preparations. Active or uncertain effects must first end and, when `UNKNOWN`, be
reconciled using backend evidence. A timeout alone never permits archival.

Archive writes and live-record removal are atomic. Each archive has a fresh
encryption key held only in the main encrypted ledger, authenticated ciphertext
and permanent task-ID non-reuse markers. Existing memory names are also retired
within their tenant so they cannot be recreated with weaker labels. The archive
retains budgets, counters, provenance and available evidence; it cannot recover
history previously pruned by normal retention. `verifyTaskFamilyArchive()` returns
only verified receipt metadata. If the application loses its archive response,
`findTaskFamilyArchive({ tenantId, taskId })` recovers the receipt from any original
family member, allowing its separate backend bookkeeping to finish idempotently.

External task/memory references and mixed memory histories block archival. Retire
and archive independent dependents first; cycles or shared histories remain
blocked. Linked handoffs are preferable when work should share a lifecycle.
Archived task APIs and inventory no longer expose those records, and signed
artifacts referring to archived tasks cannot reopen authority.

Live task/action capacity is reclaimed. Retention remains finite: at most 4,096
archives, 65,536 combined task/memory markers, 256 MiB of archive ciphertext and
16 MiB decoded state per archive. The configured main-ledger bound (16 MiB by default) also
applies. Limits fail closed without evicting identities or resetting spent
budgets. This is logical archival, not secure erasure or physical SQLite shrinking.

Agent Ops adds a separate, reviewed offline
[company-history protocol](https://github.com/ShieldaAI/agent-guard/blob/main/docs/guides/company-history.md)
for its single-root ticket profile. It exports authenticated evidence before
reclaiming local archives and uses permanent namespace fences to prevent reuse.
It does not compact delegated or memory-bearing SDK families. Legacy identities
and unresolved sequence gaps retain individual markers. Lifecycle mutations
upgrade authority to schema 2 so old schema-1-only readers cannot ignore these
protections after a binary downgrade.

For operator recovery, `listExecutions({ tenantId })` lists `UNKNOWN` work with
bounded metadata and authenticated revision-bound pagination; `statuses` can
select other states, and `limit` is 1–100 (default 25). A changed revision requires
restarting pagination. `maintenanceStatistics({ tenantId })` reports scoped live,
retired and archive counts, plus deployment-wide decoded `ledgerBytes` and
`ledgerByteLimit`. See the [exact API](https://github.com/ShieldaAI/agent-guard/blob/main/docs/api-contract.md#task-family-retirement-and-archival)
for shapes, errors and conservative reference rules.

## Concrete file and HTTP adapters

`createPrivateFileTools({ directory, tenantId, resourcePrefix })` returns `.read` and
`.write` tool definitions for an existing executor-owned private directory. Tool
arguments contain portable relative paths, never tenant or authority fields. The
resource is exactly `resourcePrefix/path`; writes require approval by default.
Prepared reads and writes bind a per-tool-instance keyed HMAC version, including
absence, then recheck it at dispatch. This opaque value prevents offline guessing
of secret content before approval. Approved reads return the content SHA-256 only
after sensitivity is set. Writes stage and fsync a private temporary file, recheck
the target version and atomically rename it. Paths with traversal,
case aliases, symlinks, hardlinks or device/socket entries are rejected; UTF-8 data
has a configurable byte limit. Reads are sensitive by default.

Keep this directory separate from every guest-mounted workspace and inaccessible to
untrusted processes. POSIX ownership/private modes are checked. Windows operators
must provision an equivalent owner-only ACL; portable Node filesystem APIs do not
verify Windows ACLs. The path checks and atomic rename do not protect against a
hostile process running as the executor's own UID or a host administrator. They are
not a portable `openat` filesystem sandbox. Files generated in the container should
first pass the separate hash-bound review/export flow.

`createHttpGetTool` maps agent-facing resource aliases to fixed host-approved JSON
URLs through `createRestrictedFetch`. Exact resources and full endpoint recipients
must be granted. Optional strong ETags are bound at preparation, sent with `If-Match`
and verified against the actual response. Without an ETag, the response is current
untrusted remote data, not a prepared content snapshot. This outbound action remains
subject to sensitive-egress policy; resources declared sensitive fail that gate.

`createOutboundJsonTool` sends the fixed envelope `{ recipient, payload }` to one
host-configured endpoint. The agent cannot provide routing, tenant or credential
fields. Its trusted `parsePayload` validates/transforms input exactly once during
preparation; resolution and execution only validate the already-normalized object.
A host credential callback runs only after executor admission, and its version must
match the prepared configuration. Credentials stay out of public tool metadata and
returned receipts. Optional `expectedETag` sends `If-Match`; the destination must
honor that precondition. Responses expose acceptance status rather than a reflected
body. Writes are never automatically retried: errors and uncertain receipts require
executor outcome reconciliation.

All adapters return `ToolDefinition` objects for host registration/approval.
`publicToolDefinition` returns only `PublicToolDefinition` metadata for clients,
excluding executable handlers and credential callbacks. Private HTTP origins require
explicit host network-policy configuration; redirects and proxy-environment routing
remain disabled.
