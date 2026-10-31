# Agent Guard executor (unreleased alpha)

An additive Apache-2.0 package for a single trusted host: encrypted transactional
authorization state, task-scoped HTTP credentials, typed adapters, governed memory,
and a local Docker sandbox. Requires Node.js 22.13 or newer. No account or hosted
service is required. Build and install the local workspace tarballs; this package
has not been published by this change.

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

Mandatory grant, tenant, recipient, deadline, sensitivity and integer budget gates
are shared with the embedded core. Arguments pass a trusted `ToolDefinition.parse`
before resource resolution. `resourceVersion` is bound into the prepared action;
the resource adapter must recheck it at the effect boundary. Custom policy can only
tighten these gates. Changing a policy or registering a tool invalidates old work.

## Durable admission and recovery

Use one executor owner per SQLite file on a local filesystem. A second owner fails
closed under SQLite's process lock. A transaction rechecks authority, consumes one
approval, reserves every ancestor budget and records admission before dispatch.
The state sequence is `PREPARED -> ADMITTED -> RUNNING -> SUCCEEDED/FAILED/UNKNOWN`.
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

Storage is bounded to 16 MiB. Family-wide pending action/byte and delegated-task
caps prevent one task from filling shared storage through preparation/delegation.
Expired or invalidated preparations and approvals are pruned. Terminal records have
bounded retention; cumulative budgets and unresolved reservations are retained.
The audit keeps the latest 1,000 metadata events, without arguments, results or raw
reconciliation evidence. Task and action IDs are host-controlled audit metadata;
avoid putting secrets in IDs. There is no automatic quota reset, key rotation or
distributed-worker support. Plan an operator-controlled retention/archival policy
before reaching capacity; never delete active authority state to recover quota.

## Adapters and integrations

### Inventory for the trusted host

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
The API is synchronous and has no interruptible time limit or measured polling
latency guarantee yet. See the repository's Cartography integration plan and
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
against the version-1 manifest contract. `composeInventorySnapshot(core, manifest)`
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

The server serializes and checks the entire snapshot before sending success. A
response cap failure returns 413 with `INVENTORY_RESPONSE_TOO_LARGE`, without a
partial snapshot. The deadline spans upload, generation, serialization and writing.
It is checked after synchronous generation: an overdue snapshot returns 408, but
JavaScript execution itself cannot be interrupted. A stalled response is closed;
clients must reject incomplete bodies. Inventory's record/work bounds still apply.
The [isolated pilot benchmark](../../deployment/cartography/RUNBOOK.md#performance-gate)
measures admission with and without actual HTTP inventory polling. Its recorded
100-task/1,000-grant workload passed the provisional 10% p95 admission regression
target after bounded snapshot-local reference caching: 25.103 ms without
inventory versus 25.961 ms at a 250 ms polling cadence (+3.42%). Preparation
p95 increased 25.85% and is recorded separately. This stress cadence is distinct
from the collector's five-minute default; representative deployment measurements
are still required. The cache never persists snapshots or changes references.

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
unreleased implementation as certified isolation on all three platforms.

`ArtifactBroker` signs tenant, content hashes, sensitivity and transitive source
lineage for files, stdout and stderr. Raw input defaults to sensitive. Verified
imports into fresh roots keep labels and reject revoked sources even after restart.
`createSandboxTool` binds selected input versions, uses the executor's approval and
budget admission, forwards cancellation, and retains complete results with the host.
Only bounded logs and artifact references reach the model. Reviewed exports require
exact hashes and preserve a signed sidecar. Host signing keys and classification
decisions must stay outside agent authority; the raw launcher does not provide this
provenance contract. A signature does not make untrusted content trustworthy.

## Verification and remaining release gates

`npm run check` builds all packages, runs adversarial/benign tests and installs the
tarballs into a clean consumer. Executor tests use actual SQLite, process exits,
HTTP collectors, scoped credentials and versioned memory. The optional Docker tests
must run without skips for platform evidence. The platform workflow records runtime
metadata and refuses a missing pinned image.

The protected-release gate still requires native Linux and Windows host isolation
results, a complete reference coding-agent integration, independent security review,
artifact admission beyond pinned sandbox images, and reviewed retention/recovery
operations. Distributed execution is a later milestone. The implementation makes no
claim to detect every prompt injection or prevent every agent attack.

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
