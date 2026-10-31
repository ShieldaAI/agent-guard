# Alpha API contract

The host owns `AgentGuard`. Give the model only a dispatcher, never administration methods or opaque handles. Authority is stored by object identity inside one guard instance. All state is in memory and lasts for that instance's lifetime.

Exports from `@shieldaai/agent-guard`:

```ts
type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };
interface Capability { tool: string; resources: readonly string[] }
interface Budget { maxCalls: number; maxConcurrent: number; maxCost: number; deadline: number }
interface TaskOptions {
  id: string; principalId: string; tenantId: string;
  grants: readonly Capability[]; budget: Budget;
  allowedRecipients?: readonly string[];
  allowControlPlane?: boolean;
}
interface TaskIdentity { id: string; principalId: string; tenantId: string }
interface TaskHandle { readonly id: string }
interface ResolvedAction {
  resourceId: string; tenantId: string;
  external?: boolean; recipient?: string; sensitive?: boolean;
  resourceVersion?: string;
}
interface ToolDefinition {
  name: string; description: string; inputSchema?: Json; metadata?: Json;
  requiresApproval?: boolean; controlPlane?: boolean;
  // Nonnegative safe integer cost units; the adapter enforces its provider-side bound.
  maxCost?: number;
  parse?(input: Json): Json;
  resolve(args: Json, task: Readonly<TaskIdentity>): ResolvedAction;
  execute(args: Json, context: {
    signal: AbortSignal; action: Readonly<Action>; task: Readonly<TaskIdentity>
  }): Promise<ToolResult> | ToolResult;
}
interface ToolResult { value: Json; actualCost?: number }
interface Action extends ResolvedAction {
  tool: string; args: Json; toolFingerprint: string; policyVersion: number;
}
interface TaskSnapshot extends TaskIdentity {
  sensitive: boolean; calls: number; concurrent: number; spent: number; reserved: number;
}
type PolicyDecision = 'allow' | 'deny' | 'require_approval';
type Policy = (action: Readonly<Action>, task: Readonly<TaskSnapshot>) => PolicyDecision | Promise<PolicyDecision>;
interface GuardOptions { policy?: Policy; secretValues?: readonly string[]; clock?: () => number }
interface PreparedAction {
  readonly id: string; readonly digest: string;
  readonly action: Readonly<Action>; readonly requiresApproval: boolean;
}
class GuardError extends Error { readonly code: string }
class AgentGuard {
  constructor(options?: GuardOptions);
  registerTool(tool: ToolDefinition): string; // Returns the fingerprint. Approval is a separate step.
  approveTool(name: string, fingerprint: string): void;
  createTask(options: TaskOptions): TaskHandle;
  delegateTask(parent: TaskHandle, options: Omit<TaskOptions, 'principalId' | 'tenantId'>): TaskHandle;
  revokeTask(task: TaskHandle): void;
  setPolicy(policy: Policy): void; // Invalidates existing prepared actions and approvals.
  prepare(task: TaskHandle, request: { tool: string; args: Json }): Promise<PreparedAction>;
  approve(prepared: PreparedAction, options: { approverId: string; expiresAt: number }): string;
  execute(prepared: PreparedAction, options?: { approvalId?: string }): Promise<Json>;
  snapshot(task: TaskHandle): Readonly<TaskSnapshot>;
}
```

## Execution rules

### Grants and tool registration

Tool names and resource grants match exactly. The resource `*` is an explicit wildcard. Every grant in the task's ancestry must allow an operation. Child tasks inherit their principal and tenant; their grants, recipients, control-plane authority and budgets cannot exceed the parent's limits. Task IDs must be unique within a guard instance.

The host must approve tool metadata before preparing or executing a call. Fingerprints cover the description, schema and security configuration. Re-registering a tool invalidates its existing prepared actions, even if the metadata is unchanged. Approving metadata does not verify the implementation's safety.

### Prepared actions and policy

The guard accepts finite, plain JSON values, then clones and freezes them. It rejects cycles, accessors, exotic objects and inputs that exceed the size or depth limits below. An optional trusted synchronous `parse` validates and normalizes arguments exactly once before resolution; parser failure produces `ARGUMENT_INVALID`. The normalized result is cloned/frozen and used for approval and dispatch. It also validates and stores the resolver's result. Changing caller-owned arguments cannot change the stored invocation.

`resourceVersion` is an opaque host-supplied value bound into the action and its
approval. The handler must compare it with current state at the actual effect; the
core cannot perform an external compare-and-swap. Do not expose raw secrets or
guessable secret-content digests in prepared metadata. The executor's private-file
and sandbox adapters use private keyed versions for this reason. Parser code and
resolver closures remain trusted implementation: re-register tools when they change.

Both preparation and execution apply the mandatory checks. Custom policy may add restrictions; it cannot relax them. If policy throws or returns an invalid decision, the call is denied. Without a custom policy, an action is allowed only if every mandatory check passes.

After awaiting policy, the guard rechecks the policy version, grants, revocation, tool approval, tenant, sensitivity and deadline. If a counter or shared sensitivity value in the supplied task snapshot has changed, it rejects with `POLICY_STATE_CHANGED`. This rejection starts no handler and consumes no approval or budget, so the host may retry with a fresh evaluation. The snapshot check, final reservations, approval consumption and handler invocation run without an intervening asynchronous pause.

This check covers the supplied local snapshot. It cannot coordinate external mutable state or other tasks that a custom policy reads through a closure. Grants cannot be changed in place, administration APIs must remain with the trusted host, and the core does not require a remote policy service.

### Approval and dispatch

Each prepared action can run at most once. A required approval is bound to that action and its policy and tool revisions. It must expire no later than the task deadline and is consumed immediately before dispatch. Only trusted host code may approve actions or tool metadata.

### Sensitive data and outbound calls

Outbound tools require an explicitly allowed recipient. Parent and descendant tasks share a sensitive flag. Once a trusted resolver marks the context sensitive, external sends are denied. The flag is set before dispatch and cannot be cleared.

The guard scans each outbound string value for configured literal secrets or canaries and omits argument values from errors. The scanner does not cover arbitrary encodings or secrets split across values.

### Budgets and cancellation

Before dispatch, budget admission updates every ancestor synchronously. Calls count attempts that reach a handler. A failed call or an uncertain side effect is not automatically retried or refunded.

Budget `maxCost`, tool `maxCost` and reported `actualCost` use nonnegative safe integers in the same unit chosen by the host, such as microcurrency units. Fractional values and unsafe integers are rejected. The guard reserves `maxCost` and then settles the charge using `actualCost`, which must not exceed the reservation. If usage is omitted, it charges `maxCost`. An invalid or excessive cost report fails the call and revokes the task, charging the full reservation. The host must enforce the provider's actual cost ceiling.

Concurrency stays reserved until the registered handler's promise settles, including after cancellation. Revocation or a task or ancestor deadline signals cancellation through `AbortSignal`; it cannot forcibly stop arbitrary code. The guard also checks the clock when a result settles, so a handler that blocks the timer cannot return a successful result after its deadline. There is no hard process timeout.

An MCP client may settle its request before the remote server stops working. Local accounting therefore cannot bound the remaining remote work. An error after invocation does not prove that no side effect occurred.

## Packages

### Executor inventory (unreleased)

The optional executor package exposes `inventorySnapshot({ tenantId })` only on
the trusted `DurableExecutor` host object. Enable it with constructor
`inventory: { companyId, sourceId, enrollmentGeneration, referenceMode? }`.
`referenceMode` defaults to `opaque`; `raw` is an explicit host choice for reviewed
non-secret resource aliases and recipients. This does not add a task/admin HTTP
route or an `ExecutorClient` operation. The host must select the authorized tenant.

The readonly `InventorySnapshot` implements the
[version-1 core schema](../schemas/agent-guard-inventory-v1.schema.json). It contains
all retained tasks in the tenant, normalized grants and referenced tool records,
including revoked/expired tasks and unavailable handlers. Delegation and provenance
are separate edges. Tool fingerprint strings are bare SHA-256 hex; unavailable
definition flags are `null`. Other enrichment coverage is `not_collected`.

One synchronous ledger read produces an immutable, detached snapshot. Export does
not run authorization callbacks or change ledger revision, budgets, approvals or
audit. Observation timestamps use wall time, independent of the execution clock.
The random ledger identity persists across restarts and additive schema-1 migration;
the snapshot ID changes per export. Rotate enrollment after restore/clone, key
changes or reference-mode changes. See the
[executor guide](../packages/executor/README.md#inventory-for-the-trusted-host) for
data minimization, limits and lifecycle requirements.

| Error code | Meaning |
| --- | --- |
| `INVENTORY_DISABLED` | No inventory enrollment configured. |
| `INVENTORY_CONFIG_INVALID` | Invalid enrollment or reference mode. |
| `INVENTORY_SCOPE_INVALID` | Missing/invalid tenant or attempted filtering. |
| `INVENTORY_STATE_INVALID` | State cannot be represented by the inventory contract. |
| `INVENTORY_LIMIT_EXCEEDED` | Complete output exceeds a record, work or byte limit. |
| `INVENTORY_CLOCK_INVALID` | Observation time cannot be encoded as a valid UTC timestamp. |

Store errors such as `STORE_CLOSED` or `STORE_CORRUPT` are preserved. Error messages
contain stable codes, not source values. Failure never returns a truncated snapshot.

### Observer HTTP (unreleased)

`startInventoryServer({ executor, observers, ...limits })` returns a loopback `url`,
the Node `server` and an idempotent async `close()`. Each `InventoryObserverCredential`
has an independent `token` from `createInventoryObserverToken()`, fixed `tenantIds`
and optional host-selected `profile: 'core' | 'host' | 'host-mcp'` (default `core`). A host
credential requires a valid entry in `manifests` for every permitted tenant. The sole route is
`POST /v1/inventory/snapshot`, with `Authorization: Bearer agi_v1.…` and exactly
one JSON property, `tenantId`. The tenant must be enrolled for that credential;
task filters and profile overrides are invalid. Configuration is detached at
startup and cannot be changed by a request.

Success returns the complete `InventorySnapshot` directly with an exact encoded
content length and `Cache-Control: no-store`. The listener authenticates independently
of task/admin HTTP and exposes no authority mutations. Its default limits are 16 KiB
request bodies, 8 MiB responses, a 10-second deadline, four active requests,
32 connections and 60 attempts per credential per minute, plus a global quota.
See the [observer guide](../packages/executor/README.md#observer-http-transport)
for configurable bounds, strict parsing and remote TLS bridge requirements.

| HTTP status | Error codes |
| --- | --- |
| 400 | `REQUEST_INVALID` |
| 401 | `UNAUTHENTICATED` (Bearer challenge; no credential details) |
| 403 | `REQUEST_DENIED`, `INVENTORY_SCOPE_DENIED` |
| 408 | `REQUEST_TIMEOUT` |
| 413 | `REQUEST_TOO_LARGE`, `INVENTORY_RESPONSE_TOO_LARGE`, `INVENTORY_LIMIT_EXCEEDED` |
| 429 | `INVENTORY_RATE_LIMITED`, with `Retry-After` |
| 431 | `REQUEST_TOO_LARGE` for parser header overflow |
| 503 | `INVENTORY_BUSY`, `INVENTORY_UNAVAILABLE`, or a safe exporter availability code |

Errors are bounded `{ "error": "CODE" }` JSON without task data. Store and unexpected
internal failures map to `INVENTORY_UNAVAILABLE`. Startup validation uses
`INVENTORY_SERVER_CONFIG_INVALID`; socket bind failures retain Node's error code.
Slow/disconnected sockets may close without a body. Deadlines are checked after
synchronous generation and serialization before success; they cannot interrupt
JavaScript work. Snapshot byte-limit failures send no partial snapshot. A collector
must reject incomplete responses and unexpected redirects.

### Host manifest (unreleased)

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

Manifest validation uses `INVENTORY_MANIFEST_INVALID`,
`INVENTORY_MANIFEST_LIMIT_EXCEEDED`, `INVENTORY_MANIFEST_REFERENCE_INVALID` and
`INVENTORY_MANIFEST_SOURCE_MISMATCH`. Invalid core input uses
`INVENTORY_SNAPSHOT_INVALID`; combined-output limits use
`INVENTORY_LIMIT_EXCEEDED`. All messages omit source values. See the
[host binding guide](../packages/executor/README.md#host-owned-manifest-and-bindings)
for supported reference syntax, numeric/size limits and enrollment lifecycle.

### MCP inventory (unreleased)

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

The trusted resolver runs during preparation. Execution checks its bound resource and tenant context; it does not query changing ownership again. A handler/resource service must revalidate mutable ownership or resource versions before performing an effect.

Each normalized JSON value is limited to 1 MiB of canonical UTF-8 JSON, 100,000 nodes and 64 levels of depth. Bytes are counted during traversal, including escaped strings, keys and punctuation, so oversized inputs are rejected before constructing their complete serialization. The limit applies to complete request/result envelopes, metadata and other normalized structures, including the prepared-action digest envelope. Leave room for enclosing fields when sizing payloads. A malformed or oversized handler result produces `RESULT_INVALID`, charges the declared maximum and revokes that task; the operation may already have performed an effect.

## Optional inventory reference service

`@shieldaai/agent-map` consumes published Cartography inventory independently of
executor admission. Its [public contract](../packages/agent-map/README.md) defines
six read-only operations, shared by `POST /v1/query` and the official SDK MCP
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
