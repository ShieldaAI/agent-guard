# Changelog

## 1.0.0 — Unreleased

The first stable release. The last published version was `0.1.0-alpha.3`; this entry
covers everything since then, which is why it is long. The
[release notes](docs/releases/1.0.0.md) are the short version: what 1.0 contains, its
known limits and the upgrade steps from `0.1.0-alpha.3`.
The inventory observer and Agent Map remain experimental, and running the observer on
one logical CPU with 250 ms polling is not supported.

The entry is grouped by package. Within a group, removals and changes come first, then
additions, then fixes.

### Core

- Remove (core, executor): the root aliases the alphas exported for the internal SPI and
  for names that live on subpaths. Import `PolicyAdmission`, `assertActionAuthority`,
  `containsLiteralSecret`, `canonicalJson`, `digestJson` and `immutableJson` from
  `@shieldaai/agent-guard/internal`, and the sandbox, inventory, pilot and operator names
  from `@shieldaai/agent-guard-executor/sandbox`, `/inventory`, `/pilot` and `/ops`.

- Change (core): each check reuses per-task authority views built at task creation;
  `assertActionAuthority` (`/internal`) also accepts the precomputed form. Every public
  method and type is documented, and `GuardErrorCatalog` causes say what to do next.
- Change (core): `DELEGATION_DENIED` carries a `detail` naming the exceeded limit
  (`GRANT_`, `RECIPIENT_`, `CONTROL_PLANE_`, `BUDGET_` or `DEADLINE_EXCEEDS_PARENT`), and
  `EXECUTION_ABORTED` carries `EFFECT_COMMITTED` when the handler had finished.
- Change: the internal SPI moves to `@shieldaai/agent-guard/internal` (no semver
  guarantees): `PolicyAdmission`, `assertActionAuthority`, `containsLiteralSecret`,
  `AuthorityPhase`, `AuthorityState`, `canonicalJson`, `digestJson` and
  `immutableJson`. The root no longer exports them. First-party packages import from `/internal`. The root
  entry also exports `InvalidJsonError`.
- Add (core): `limits.maxJsonBytes` (64 KiB to 64 MiB, default 1 MiB) and
  `limits.maxJsonNodes` set the JSON size limits for arguments, results and tool metadata.
  A result over the limit still fails `RESULT_INVALID` and revokes the task.
- Add (core, executor, MCP; opt-in): an outside-content flag. Tools can declare
  `readsUntrusted`, `untrustedContext` (`allow` / `require_approval` / `deny`) and
  `sendsExternal` (`false` enforced); a resolver can add `untrusted: true` per call. A
  family that dispatches such a call is marked `untrusted` for good (persisted in the
  ledger). Then `require_approval` tools need a review, a pre-read approval fails with
  `APPROVAL_CONTEXT_CHANGED`, and `deny` tools fail with `UNTRUSTED_CONTEXT_DENIED`.
  `snapshot()`, policies and `onDecision` see the flag; MCP connections can be marked
  `readsUntrusted`. Defaults are unchanged (`allow`), and tools that set none of the
  labels keep their fingerprints.
- Add (core API shape for 1.0): `executeDetailed()` returns `{ value, charged,
  actionId }`; `retireTask()` revokes and forgets a task, bounding memory and task IDs
  in long-running guards; `unapproveTool()` and `unregisterTool()`; an `onDecision`
  audit hook (identifiers only; it cannot change an outcome); `snapshot()` adds
  `budget` and `revoked`; a `limits` option for the previously fixed approval and
  policy bounds; and `monotonicClock`. The default clock stays `Date.now`.
- Add: an error catalog. `GuardErrorCatalog` documents every `GuardErrorCode` with its
  meaning, whether a retry is safe and the typical cause, and `docs/errors.md` is
  generated from it (a test fails on drift). Flattened adapter errors keep a safe
  uppercase adapter code as `GuardError.detail` and `cause.code`.
  `McpBoundaryError.code` is now typed as `McpBoundaryErrorCode`.
- Fix (core): arguments just under the JSON limit no longer fail `INVALID_JSON` after
  `resolve` and the policy have run.
- Fix (core): a clock failure after the handler ran reports `EXECUTION_ABORTED` and is
  audited as failed, not `CLOCK_INVALID` audited as denied.
- Fix: a call in flight no longer refuses `prepare()` or `approve()` with
  `CONCURRENCY_EXCEEDED`/`COST_BUDGET_EXCEEDED`, in core and in the durable
  executor. Transient capacity (concurrent calls, reserved cost) is enforced at
  dispatch; permanent capacity (calls, spent cost) still refuses preparation.
  `assertActionAuthority` gains an optional `phase` (default `dispatch`).

- Docs (core): examples for delegation and the `onDecision` log, and a note on the frozen,
  prototype-less values handlers receive. Examples no longer import deprecated root names.

### MCP adapter

- Change (mcp): a non-object argument value now fails with `ARGUMENTS_INVALID`, like a
  schema mismatch; `INVALID_ARGUMENTS` is removed. `REGISTRY_CHANGED` is new.
- Add (mcp): `McpBoundaryErrorCatalog` (meaning and next step for each code) and
  `limits.maxMessageBytes` (1 to 16 MiB) on managed connections.
- Add (mcp): each registration has a `descriptorDigest` that stays the same across
  connections and refreshes while the server advertises the same definition, so a host can
  store it at review and compare it before approving. `failureReason` gives the code behind
  the last quarantine. `VerifiedMcpHttpSession` exposes `skipped` and `failureReason` and
  accepts `readsUntrusted`; `registerMcpTool` passes the outside-content labels through.
- Report the installed package version from the MCP client (`agent-guard-mcp`) and
  the Agent Map MCP server instead of hard-coded strings.
- Fix (mcp): `limits.maxMessageBytes` also applies to a structured result checked against a
  tool's output schema. A malformed name advertised by the server is reported as
  `REGISTRY_REJECTED` or `SCHEMA_INVALID`, never `INVALID_CONFIGURATION`.
  `VerifiedMcpHttpSession.connect()` checks identity, bindings and limits before any network
  call. A server ID or binding name whose encoded operation name exceeds 4,096 characters is
  refused at construction. `failureReason` is `CONNECTION_UNAVAILABLE` after the transport
  closes unexpectedly.
- Fix (mcp): identifiers the inventory cannot report are refused at construction;
  `connect()` never reports a connection ready after its transport closed; a superseded
  `refresh()` always rejects with `CONNECTION_CHANGED`; the schema pattern budget is no
  longer module-global.
- Fix (mcp): a tool schema `pattern` using a regex modifier group such as `(?i:a)` could
  hang the host or skip the backtracking check; those forms are refused.
- Fix (mcp): a binding's explicit `readsUntrusted: false` is passed to the registration
  instead of being dropped. The tool fingerprint changes for bindings that set it.
- Fix: the MCP schema profile accepts common real-world tool schemas. The 2019-09 and
  2020-12 dialect URIs are accepted, `format` is an annotation, `uniqueItems` uses
  linear canonical-JSON equality, and `pattern` is accepted when its backtracking is
  bounded (with a per-value length cap and a per-validation work budget). A schema
  outside the profile now skips only that operation, listed in `connection.skipped`
  with its reason, instead of rejecting the server's whole registry.
- Fix: a managed MCP connection no longer quarantines on a failure that belongs to
  one call. An abort, deadline, timeout, JSON-RPC error reply, invalid or oversized
  result, resource mismatch or throwing `measureCost` now fails only that call.
  Connection-level failures still quarantine. The inbound message limit is now a
  sliding window (`maxMessages` per `messageWindowMs`, default 10,000 per 10 s)
  instead of a lifetime cap, and exceeding it quarantines instead of closing, so
  `refresh()` recovers. An oversized or malformed message that answers no pending
  call also quarantines instead of closing. A reflected protected value still
  closes the connection.
- Docs (mcp, core): record `descriptorDigest` per server, not per remote name alone; a
  handler aborted before its effect must throw, because returning normally under abort is
  reported as `EXECUTION_ABORTED` with detail `EFFECT_COMMITTED`.

### Executor

- Fix (executor): on Node 22, `agent-guard-ledger` and `agent-guard-pilot-review` no longer
  print Node's "SQLite is an experimental feature" warning between their error code and
  hint; other warnings are printed as before.
- Change (executor): a tool handler's error is always `TOOL_FAILED` (its safe code in
  `detail`) or `EXECUTION_ABORTED`; built-in tools keep their codes, and a memory version
  race settles `FAILED` at zero cost. Every public method throws only `GuardError` or
  `ExecutorError`; a store that cannot open says why in `detail` (`LOCKED`,
  `KEY_MISMATCH`, `CORRUPT`).
- Change (executor): the numbered task ID scheme that lifecycle export fences rely on is
  now a documented executor feature, `numberedTaskId()` and `NUMBERED_TASK_PREFIX`,
  instead of an Agent Ops convention string-built in two places. Persisted formats
  are unchanged.
- Change (executor exports): the root keeps the executor, task server and client,
  adapters, network and model tools. Sandbox, inventory (experimental), pilot review
  and operator tooling move to `/sandbox`, `/inventory`, `/pilot` and `/ops`, and
  Agent Ops building blocks to `/internal` (no semver). The root no longer
  exports the moved names (see the removal entry above).
  agent-map adds `/oidc` and `/identity-http`. Application sources now import
  packages by name only, and a test fails on any `dist/` import from `apps/`.
- Change: the durable executor task server returns HTTP statuses by kind (401, 403,
  404, 409, 429, 503, otherwise 400) instead of 400 for every denial, and the error
  body adds `retryable`. `ExecutorClient` accepts these statuses and exposes
  `retryable` on its errors. Older clients see the new statuses as
  `EXECUTOR_REQUEST_DENIED`; upgrade client and server together.
- Add (executor): `DurableExecutor.knowsToken()`; the `AuditEvent` type is exported.
- Add (executor): `unregisterTool`, `unapproveTool` and `maxApprovalsPerAction`.
  Admission and dispatch are one commit.
- Add (executor): `preparedAction(actionId)` and `POST /v1/admin/action` return the stored
  tool, arguments, resource, digest and status of an action, so a review screen shows what
  an action ID denotes from the ledger rather than from the party asking for approval.
- Add (executor): `loadInventoryManifestFile(path)` on the `/inventory` subpath loads a
  reviewed host manifest from a private file (owner-only, read once at startup, POSIX
  only), so declaring an agent is a file change and a restart. See
  [declare agents from a file](docs/guides/agent-cartography.md#declare-agents-from-a-file).
- Add (executor ledger format): ledgers carry an explicit `formatVersion` and a
  `features` list, kept current at each commit. A migration registry brings older
  layouts forward at open, inside the exclusive startup transaction, so the witness
  and mirror update in the same commit. A newer layout is refused unchanged
  (`STORE_FORMAT_UNSUPPORTED`). `executor.ledgerFormat()` and Agent Ops `check`
  report the format. The optional ledger fields are now real types instead of casts.
  Committed fixture ledgers written by `0.1.0-alpha.3`, `0.1.0` and the pre-format
  0.2 build (plain and witnessed) must open, keep counters, receipts and tokens, and
  still reconcile an uncertain effect. Policy: 1.x opens every ledger from
  `0.1.0-alpha.3` on; downgrade is not supported.
- Add whole-family retirement and encrypted archival, scoped execution listing,
  exact ID tombstones and crash-safe archival receipt discovery.
- Add offline, retryable ledger key rotation with independent rollback witnesses
  and a protected multi-key ring.
- Add managed offline key escrow, authenticated complete backups, active-key
  retirement and schema-3 current-state repair without witness rollback.
- Fix (executor): `revokeTask()` whose ledger write fails throws `OPERATION_FAILED` with
  `detail: 'REVOCATION_NOT_DURABLE'`; the executor records the revocation with its next
  successful ledger write and tries again in `close()`. `POST /v1/admin/revoke` answers 503
  with `"retryable": true` and that `detail` instead of 400 `REQUEST_INVALID`. Before, a
  restart silently undid such a revocation even when later writes succeeded.
- Fix (executor): an error thrown by a host callback inside a built-in tool (model
  `complete`, outbound `credential`, sandbox `onResult`, artifact broker `clock`) is always
  `TOOL_FAILED` with the error's code as `detail`; it can no longer surface as an executor
  decision such as `TASK_REVOKED`.
- Fix (executor): the task server checks rate limits before the ledger is read, so a
  credential over its limit costs no ledger read; requests refused for a limit or a bad
  token no longer count against `requestsPerMinute`. `registerTool()` for a tool the ledger
  already records unchanged is no longer refused at the soft limit, and the first such
  registration after a start writes nothing. `unapproveTool()` and `unregisterTool()` may
  use the ledger reserve, like `revokeTask()`.
- Fix (executor): the ledger reserves headroom so revoke, cancel, settlement and
  reconcile always commit (growth stops at a soft limit); receipts, stubs and recent
  events are retained per tenant, so one tenant cannot evict another's; `reconcile`
  accepts an action stranded in flight.
- Fix (executor sandbox): the sandbox, artifact receipts, build policy and the
  private-file adapter share one path rule (240 UTF-8 bytes, NFC, 256 paths); the archive
  reader carries long names; sandbox failures are coded and keep the original error;
  stream receipts sign the exact bytes written.
- Fix (executor ledger tools): errors keep the original cause with a safe `detail`;
  failed backup, restore and repair steps clean up and can be retried; custody and
  recovery validate the store shape; both CLIs print the code, then a plain hint.
- Fix (executor): ledger and archive decryption pin the AES-GCM nonce and tag lengths. Node
  22 and 24 accepted a truncated authentication tag; Node 26 already refused it.
- Fix (executor): memory written by a family that read outside content is marked
  `untrusted`, and reading it marks the reader's family, so `untrustedContext` rules follow
  content through governed memory. `importMemory` accepts `untrusted: true`.
- Fix (executor): an action pruned while its policy evaluation was pending failed with a
  raw `TypeError`; it now fails with `INVALID_PREPARED`.
- Fix (executor): the `host-mcp` inventory profile rejected every schema-2 host snapshot
  (outside-content labels in use, or a v3 manifest).
- Fix (executor): a sandbox command that exits non-zero returns its exit code and output
  instead of failing the export step, which left the action `UNKNOWN`.
- Fix (executor task server): tokens are authenticated before they are counted, so unknown
  tokens no longer spend the shared request window; administration routes keep reserved
  in-flight slots and are not counted in the server-wide window, so `revoke` stays reachable
  at the limit.
- Fix (executor): a task whose provenance or ancestry would pass the bounds that
  authentication and revocation rely on is refused at creation; a clock failure after an
  effect settled reports `EXECUTION_ABORTED` with `EFFECT_COMMITTED`; `audit()` no longer
  throws when the event ring exceeds 1 MiB; `ACTION_APPROVAL_LIMIT` and `numberedTaskId`'s
  `INVALID_INPUT` are `GuardError`s.
- Fix (executor): archived task families no longer leave token hashes in memory; an
  unknown maintenance CLI flag reports `MAINTENANCE_ARGUMENT_INVALID`.
- Fix (executor): an operator can accept a bounded backward clock step once at
  startup (`acceptClockSkewMs`, Agent Ops `--accept-clock-skew`), recorded as
  `CLOCK_SKEW_ACCEPTED`; without it a backward step still fails closed. A handler that
  completes after cancellation, revocation or its deadline now fails with
  `EXECUTION_ABORTED` and `detail: 'EFFECT_COMMITTED'`, so the caller knows the effect
  happened. The executor and the `/ops` key tools share one 1 MiB minimum ledger size.
- Fix (executor ledger): when `ROLLBACK` itself fails, the store keeps the original
  transaction error instead of replacing it, and closes so an unknown transaction
  state is never read.
- Fix (executor task server): bearer authentication uses an in-memory token index, so
  malformed and unknown tokens are refused without decrypting the ledger, and a valid
  one is found in O(1) instead of a scan over every task. The server adds
  per-credential and server-wide request rates, an in-flight request cap and a
  connection cap (`REQUEST_RATE_LIMITED`, 429).
- Fix: in the durable executor, one tenant's traffic no longer evicts another
  tenant's receipts or audit events. Settled receipts are kept per task family
  (`maxReceiptsPerFamily`, default 64), and shared caps prune the busiest family
  first. A pruned receipt now returns `status: 'PRUNED'` with its settled `outcome`
  instead of `INVALID_PREPARED`, which resolves the lost-response case. Audit
  events are kept per tenant (`maxRecentEventsPerTenant`, default 256; total
  still 1,000) and carry `tenantId` and a gap-detecting `sequence`.
  `audit({ tenantId })` filters by tenant. The ledger change is additive.
- Fix: in the durable executor, another task's or tenant's writes no longer make a
  call fail with `POLICY_STATE_CHANGED` while its policy is awaited. The check now
  compares the task's own policy inputs (counters, shared sensitivity), as the API
  contract describes, instead of the global ledger revision. Same-task changes are
  re-evaluated with the same bounded, turn-taking retry as core
  (`ExecutorOptions.maxPolicyAttempts`). Without a custom policy, no check applies.
- Fix: parallel calls on one task now work under a custom policy. A policy decision
  made on a snapshot that changed while it ran is re-evaluated on fresh state, not
  rejected outright. Re-evaluations on a task take turns, and the count is bounded by
  the new `maxPolicyAttempts` option (1–16, default 5; `1` keeps the old behaviour).
  The final checks and dispatch still run without an intervening await.
- Perf (executor ledger): `LedgerStore.read()` caches the last verified ciphertext and
  its decoded state. Each read still fetches the row and runs every witness and mirror
  check, but when the bytes are unchanged it returns a detached copy without
  decrypting, parsing or re-walking the ledger. With 1,000 tasks, read-bound calls
  such as `snapshot()` take about half the time (3.6 ms to 1.8 ms); prepare and
  execute are unchanged because the write path dominates. Read results stay fresh,
  detached and mutable as before, and `close()` drops the decrypted cache.

### Scenarios

- Change (scenarios): the source is split into one module per scenario group plus a runner;
  catalog 1.3.0 and the public API are unchanged.
- Add (scenarios): catalog 1.3.0 adds S13, sends after reading outside content, for
  thirteen scenarios and twenty-six cases. Adapters must support the outside-content
  labels to pass it.
- Fix: scenarios recognize rejections with the new `isGuardError()` brand check
  instead of `instanceof GuardError`, so a guard from a second installed copy of core
  passes conformance. `ConformanceReport.catalogVersion` is typed as `string`.

### Inventory observer (experimental)

- Add (inventory v2): `untrustedContextDefault`, the executor's mode for tools without
  their own, so readers can work out effective modes. The collector projects it onto
  `GuardTool`, and adds `delegated` and `derived` to `GuardTask` so a reader knows a
  parent or handoff source exists without learning which.
- Add (host manifest v3): `agent-guard-inventory-manifest-v3.schema.json` adds a
  required `directAccess` list, where the host declares paths that act without the
  guard (shell, database, network, SDK, MCP, other). Entries have opaque ids and target
  references, a 1,024-character description, and at most 32 per deployment (1,000 in
  total). `[]` is the host's claim of none, not a check. The executor validates v3 and
  composes it into a v2 snapshot. The collector projects `GuardDirectAccess` nodes and
  a per-deployment `direct_access_status`. The map adds
  `get_agent_access.outsideGuard.directAccess` with status `found`, `none_declared` or
  `unknown`; an older manifest always reads as `unknown`. The collector's authority
  hash now ignores neutral v2 fields, so moving a host to manifest v3 at the same
  ledger revision is not refused as `REVISION_CONTENT_CONFLICT`.
- Add (inventory schema v2): when outside-content labels are in use, executor
  snapshots use `agent-guard-inventory-v2.schema.json`, a `$ref` envelope over v1
  that adds `untrusted` on tasks and the three labels on tools. Otherwise the output
  stays byte-identical v1. The Cartography collector validates v2 (resolving v1
  locally, never over the network) and projects the fields onto `GuardTool` and
  `GuardTask`; a v1-only collector fails closed on v2. A generator and drift test
  keep the v2 file in sync with v1.
- Fix (executor inventory): listeners of one executor must agree on `reuseUnchangedMs`;
  the manifest file loader accepts the same 200,000-value manifests as the validator.
- Perf (inventory observer, experimental): an identical poll within
  `reuseUnchangedMs` (opt-in; off by default) returns the previous observation
  instead of re-projecting, keyed by the ledger ciphertext, registry, scope, profile
  and manifest. `host-mcp` is never reused. Unchanged 500-task polls drop from about
  4.2 ms to 0.25 ms; continuously written ledgers see no change.

### Agent Map and viewer (experimental)

- Change (agent map): `MAP_TIMEOUT` answers 504 when the whole request had arrived and the
  read (or, at sign-in, the identity provider) ran out of time. It stays 408 when the request
  itself did not arrive in time. The error body is unchanged.
- Change (agent map, viewer): the demo is built as its own file, `demo.js`, which the page
  fetches only when a reader opens the demo (`app.js` went from 897 KB to 815 KB). The
  directory given as `viewerDirectory` must now hold four files: `index.html`, `app.js`,
  `demo.js` and `app.css`.
- Change (viewer): the viewer's error class is `ViewerError`; it was named `ReferenceError`,
  like the JavaScript built-in.
- Fix (viewer): refreshing the agent list, or returning to a company page, keeps the
  current rows on screen while the same list is read again, so the page keeps its height,
  scroll position and keyboard focus. A different filter or page still shows "Loading
  agents…".
- Fix (viewer): after a company page returns and its session check passes, the scroll
  position is put back even in browsers that scroll to the refocused element (WebKit on
  Linux).
- Change (agent map): `get_agent_access` and `get_agent_inventory` answer for an agent with
  more than 512 policy pairs (policy coverage `unknown / limit_exceeded`); an `Expect`
  header other than `100-continue` gets 417; every MCP tool and parameter has its own
  description; `@shieldaai/agent-map/service` exports the service without the store or
  servers. The service and store are split into one module per operation and read phase.
- Change (viewer): the security sections lead each agent; every status, reason and field
  shows in plain words; long identifiers are shortened with a copy button; filters
  collapse and the sidebar stays in view; a "What am I looking at?" panel explains the
  map; a company session keeps its place when the tab is hidden and warns a minute before
  expiry; the demo runs the real service in the page. The viewer source is formatted and
  split into views and components.
- Upgrade note (agent map): projections imported before this change have no
  `delegated` or `derived` on tasks. Until the source publishes again, their boundary flags
  never read `absent` (the status is at most `unknown`) and identity scope reports
  `grant_lineage_unknown` for every granted tool. The new `untrusted_context_default`
  appears once as a changed tool field.
- Add (agent map): two discovery leads for all-teams readers, to help find agents the
  manifest does not declare. `list_undeclared_activity` lists tasks and caller principals
  that ran through an enrolled executor and belong to no declared agent, and
  `get_inventory_health` adds their count per source as `undeclaredActivity`.
  `list_unclaimed_identities` lists IAM roles and users of the enrolled AWS accounts that
  no declared agent's execution binding names, as candidates; a missing, stale or
  inconsistent collection reads `unknown`. A team-scoped reader gets a note without names
  or counts. A failed count never fails health. The viewer has a Discovery tab. No
  infrastructure, code or network scanning is added.
- Add (agent map): the "dangerous three" boundary flag. `get_agent_access` returns
  `boundaryFlags` with whether a live task can read private data, read outside content
  and send out, each leg `present`, `absent` or `unknown` with evidence, and a status of
  `exposed`, `mitigated`, `unknown` or `absent`. Only explicit `false` labels rule a tool
  out; a sensitive task or empty recipients stop only declared external sends.
  `list_agents` adds the status for the returned page with `includeFlags` (one extra
  read of those agents), and filters with `flag`/`flagStatus`. `get_agent_access` now also
  loads the in-scope delegation ancestors of the agent's tasks (after its own nodes, only
  if they fit) and asks which in-scope bindings of `*`-granted tools are sensitive, so list
  and detail agree.
- Add (agent map): outside-guard reach for resources. `list_resources` rows get
  `outsideGuard` (`yes`, `none_found`, `unknown` with reasons); `get_resource_access`
  lists the tool identities and declared direct paths that reach the resource. A manifest
  v3 `targetRef` must now name a declared host resource. A team reader's identity scope
  names only buckets mapped by in-scope bindings; anything else is a note without a
  count. `get_changes` reports
  declared direct paths under the new `outside_guard` change kind, labelled declared.
- Add (agent map): `get_agent_access.outsideGuard.identityScope` compares what each
  static tool identity can reach with what that tool's grants bind. For a read
  focused on one agent, the store reads every bucket in the account the identity has
  an IAM identity-policy candidate on and lists the unbound ones (`broader_than_grants`),
  or reports `matches_grants`; anything missing, stale, malformed or over 500 buckets is
  `unknown` with a reason. Each tool lists at most 100 extra buckets; a cut list is marked
  `truncated` and keeps its status. Only identity policies are evaluated, so results are
  candidates. The candidate layer already covers every bucket; the collector adds only the
  task `delegated` and `derived` facts used to check task liveness.
- Implement the Agent Map/Cartography catalog for agents, owners, permissions,
  host-bound resources, opaque credential references, relationships and retained
  before/after changes, with scoped pagination and accessible browser workflows.
- Fix (viewer): when a company page returns from the background under a different session
  (a new sign-in, possibly by someone else), everything read under the previous session is
  cleared and the map opens afresh with a notice. Before, the open agent and the owner and
  environment suggestions of the previous session stayed on screen. A company workspace is
  covered from the moment the page is hidden until the session check on return has passed;
  it keeps its layout, scroll position and keyboard focus.
- Fix (viewer): Discovery marks an AWS account whose collection is stale and no longer
  gives the all-clear for it; an agent whose policy evidence was not loaded shows "not
  evaluated", never "0" or an empty list; the owner and environment filters accept any typed
  value again; connecting no longer shows an empty inventory for one frame; Discovery and
  Changes pick the first source when health arrives late; a graph property named like a
  built-in (`constructor`, `__proto__`) no longer breaks the evidence panel.
- Fix (agent map): `get_agent_inventory` reports `counts.policies` and the `policies`
  section `total` as `null`, not `0`, when policy evidence was not evaluated; `100 Continue`
  is no longer sent to HTTP/1.0 clients. Owners in `get_agent_inventory` no longer carry
  `agentCount` and `resourceCount`; invalid store options throw `MAP_CONFIG_INVALID`; an
  unmet `Expect` header is 417. Neo4j 5.23 or later is required.
- Fix (agent map): listings no longer read policy evidence and lookups read only their own
  pairs, so the 512-pair policy limit no longer fails them; health and
  `find_agents_with_access` report policy coverage `unknown / limit_exceeded` past it. Store
  limits are configurable (`maxNodes` up to 10,000; defaults unchanged). Full-graph reads
  are estimated to work up to roughly 150 agents by default and roughly 800 at the maximum;
  limits above the defaults have not been run against a Neo4j database.
- Fix (agent map): `get_agent_access` returns its evidence with `graphStatus: too_large`
  when the graph exceeds the display cap; `find_agents_with_access` reaches its documented
  limit and returns `truncated: true` when its work budget runs out.
- Fix (agent map): the identity endpoint ignores other applications' cookies; ID token
  `iat`/`nbf` may be up to 5 seconds ahead (`oidc.clockToleranceSeconds`); `Expect:
  100-continue` is answered; names sort in code-point order; `get_changes` accepts
  `changeKind: inventory` and shows renamed agents under their current name; evidence rows
  carry allowlisted properties only; launchers print `MAP_START_FAILED <code>: <hint>` and
  accept `--version`.
- Fix (viewer): the workspace opens on the agent listing alone and shows health separately
  with a retry; a failed selection is no longer highlighted; duplicate requests on connect
  and on the Permissions tab are gone; owner and resource searches wait 300 ms.
- Fix (agent map): `list_resources` judges outside-guard reach for the returned page only.
- Fix (agent map): the store's relationship query no longer scans every node in the
  database; it starts from the snapshot. Neo4j plan tests now check the boundary reads
  (one-agent, page-of-agents and full flags, outside-guard, summary and history, for team
  and all-teams readers) for cartesian products and all-node scans.

### Agent Ops and deployment

- Change (Agent Ops review screen): the review opens with a plain sentence of the effect,
  shows who asked (person or agent) and when, and counts down to expiry. Approval is two
  steps with Deny first; a denial can carry a reason; a requester can withdraw a pending
  request. New requests appear without a manual refresh, the session survives a tab
  switch, and Approve is not offered on your own request when self-approval is forbidden.
  The client is split into ES modules that share one contract with the service.
- Add (Agent Ops): opt-in online retention. With `requests.autoArchiveAfterDays`, the
  service archives the executor task families of finished requests older than that,
  10 per minute, through the operator's retire-then-archive path; blocked requests are
  skipped. History compaction stays offline.
- Add company onboarding, TLS/OIDC preflight, add-only reviewed ticket imports,
  an operator Setup view and paging for larger company datasets.

- Add the single-owner Linux Agent Ops service with durable ticket updates,
  authenticated OIDC approvals, scoped agent proposals and receipt-only recovery.
- Add hardened Docker Compose deployment, recovery runbooks, real-service browser
  checks and a Linux production-profile CI job.
- Add reviewed company-history compaction with permanent retirement fences,
  independent encrypted history mirrors and exact receipt lookup.
- Add authenticated operational status, bounded metrics, minimized activity
  exports and explicit distinction between readable storage and enrolled recovery.
- Make self-hosted ticket/request capacity, live-store byte limits and retained
  key limits safely configurable through reviewed offline policy changes.
- Enforce startup TLS/custody checks, remove unused runtime package managers,
  and add dependency inventory, production-image comparison and three-browser CI.
- Stop history growth before it exceeds the backup/recovery closure limit,
  reserve capacity for interrupted compaction and expose operator capacity alerts.
- Fix (Agent Ops): an unconfirmed request with no receipt can be closed as not applied even
  after another request changed its ticket; the close-out evidence shows the ticket as
  reviewed beside the ticket as it is now, and a preview taken before the ticket changed is
  refused with `CLOSE_OUT_STALE`. An approval whose outcome the executor has not recorded,
  no longer holds, or reports in an unrecognised form stays unconfirmed and is never marked
  failed; a request is never marked failed while a receipt for it exists. Reconcile and
  close-out accept an executor action left running or admitted.
- Fix (Agent Ops): one client address holds at most 4 of the 16 request slots for clients
  that are not signed in; when the sign-in table is full a new sign-in replaces the oldest
  pending one (`LOGIN_CAPACITY_REACHED` is no longer returned); the page and its files no
  longer count against the per-address request limit; `POST /auth/login` from a signed-in
  session answers `409 ALREADY_SIGNED_IN`; approve and deny answer `409 REVIEW_STALE` when
  the request no longer matches the reviewed fingerprint or its stored action is gone.
  `deployment/production/verify-cli.mjs` uses the cookie renewed by `POST /auth/login`.
- Fix (Agent Ops service): TLS handshake and idle timeouts, a per-address connection cap,
  in-flight slots reserved for signed-in sessions, cached readiness, one state decode per
  revision, aggregated anonymous refusal events, reserved `system:` actor ids and one
  archive rule. The production image ships only the modules the service imports.
- Fix (Agent Ops): a backend refusal that provably happened before any effect
  (authorization revoked, ticket changed, storage or clock refusal) ends the request as
  failed or "target changed" with a recorded cause instead of "Outcome unconfirmed". An
  operator can close a stuck unconfirmed request as not applied after reviewing evidence
  that no receipt exists (`POST /api/requests/:id/close-out`).
- Fix (Agent Ops): at the per-address sign-in cap the oldest pending sign-in is replaced
  instead of answering 429; `sessionTtlMs`, `rateLimitPerMinute` and `signInFlowsPerClient`
  are bounded configuration keys. A sign-in page left open past five minutes renews its
  cookie and retries. Non-browser clients must use the cookie set by `POST /auth/login`.
- Fix (Agent Ops): `compact-history --apply` compacts exactly the reviewed batch; history
  files with a wrong mode, owner or link count report `HISTORY_EVIDENCE_INVALID`; history
  segments decrypt only with a 12-byte nonce and a full 16-byte tag; agent proposals outside
  the ticket allowlist get the same 403 whether or not the ticket exists; an unparseable
  request target answers 400, not 503.
- Fix (Agent Ops): 5xx answers log one `REQUEST_FAILED` event with a safe cause; requests
  and the activity log keep a cause code; `START_FAILED` names the failing step and
  configuration key. The UI reloads after a definitive refusal instead of blanking, and
  "Review required" reads "Needs a new request". TLS alerts say to reload with SIGHUP.
- Fix (Agent Ops): refusing a self-approval answers 409 instead of 403, which signed the
  reviewer out.
- Fix (Agent Ops): anonymous `GET /api/session` no longer creates server-side
  sessions, so cookieless traffic can't exhaust the session table and block sign-in.
  Pre-login state is a signed five-minute cookie with a derived CSRF token, and each
  client address may hold at most four pending sign-ins. The rate limiter keys IPv6
  by /64 and drops the oldest window when full instead of refusing new clients.
  New `requests` settings add per-requester (50) and per-tenant (1,000) pending
  caps, configurable review expiry (default unchanged at 5 minutes) and opt-in
  `forbidSelfApproval`. `SIGHUP` now also reloads TLS material without a restart.

### Collector

- Change (collector): `agent-guard-recovery` and `agent-guard-map-report` are installed
  commands; the collector, lifecycle and recovery commands take the same archive, lock and
  Neo4j options; the lifecycle
  command no longer creates a mistyped archive directory (`--create`); `neo4j` and
  `referencing` are declared dependencies; the unused permission-mapping file is no longer
  bundled. Archive bookkeeping uses an in-memory index, each snapshot is schema-validated
  once per process, and imports no longer issue cleanup statements that could not match.
- Change (collector): every command reports failures as `{"status":"failed","code":…}`
  with specific Neo4j and path codes and a `--verbose` flag (lifecycle and recovery errors
  were `{"error":…}`); `pilot_benchmark` is no longer in the wheel.
- Patch the Python Cartography OAuthLib dependency and add locked cross-platform
  advisory checks; retain explicit, secret-free benchmark failure diagnostics.
- Fix (collector): every command that names an archive locks `<archive directory>.lock`
  beside it, so commands on one archive exclude each other from any working directory;
  `--lock-file` is held in addition and no longer has a default (a file import without it
  still locks `.agent-guard-cartography.lock` in the working directory).
- Fix (collector): a newly collected snapshot that the graph refuses as older than its
  published view (`GENERATED_AT_ROLLBACK`, `REVISION_ROLLBACK`) is reported and no longer
  kept as a pending receipt, so an executor clock step-back cannot exhaust a source's
  pending allowance. Archive retention removes only published receipts; `discard --reviewed`
  can remove a receipt whose outcome was never confirmed, and refuses one whose file is
  unsafe or unreadable instead of deleting it as damaged. The running collector notices
  mode, owner and link changes to archive files and never prunes a file that changed since
  it was indexed. `agent-guard-map-report` reports failures as JSON with the specific code.
  A snapshot whose `ledgerRevision` or `policyEpoch` is not a true integer is rejected.
- Fix (collector): the archive prunes the oldest published snapshots early
  (`ARCHIVE_RETENTION_SHORTENED`) instead of failing every source when full;
  `--archive-retention-seconds` is new; `--watch` warns or refuses at startup when sources,
  interval and retention cannot fit. With defaults the archive holds two sources.
- Fix (collector): pending receipts are capped per source (`--archive-max-pending`), listed
  and discarded with `agent-guard-recovery pending` / `discard --reviewed`; a foreign or damaged
  file fails only its own source and is named; backup, restore and the new `agent-guard-recovery
  replay` accept the archive limit flags.
- Fix (collector): at an unchanged ledger revision a capture older than the published one
  is refused (`GENERATED_AT_ROLLBACK`); SIGTERM stops `--watch` cleanly; the AWS worker's
  process group is signalled only while its leader is unreaped.

### Documentation, tests and repository

- Docs: the README shows how to connect the guard to a model (one dispatcher function) and
  maps the repository's folders; the release notes open with what 1.0 contains; the
  executor README has a "Keeping state across a restart" section; `CONTRIBUTING.md` starts
  with setup and how to run one test. New runnable examples `examples/agent-loop.mjs` and
  `examples/restart.mjs`, and an [examples guide](examples/README.md). The documents no
  longer say approvals survive a restart: budgets, revocations and used approvals do, and
  an action that had not run is reviewed again. The `POLICY_CHANGED` catalog text says so.
- Release preflight requires every `release-state.json` evidence entry to be a
  committed repository file.

- Docs: the README is rewritten around the problem, how the guard works, what it stops and
  what it does not; new [glossary](docs/glossary.md), [docs index](docs/README.md) and
  [standards and further reading](docs/standards.md); the risk table gains a "does not
  cover" column. The dated evidence files, archived plans and reviews, and the notes for
  unpublished versions are removed from the repository.
- Docs: package READMEs, the API contract, threat model, architecture, scenarios, support
  and limits, the package guide and every guide are rewritten for first-time readers; new
  guides for [delegation](docs/guides/delegation.md) and the
  [audit log](docs/guides/audit-log.md); the inventory formats have a reference page.
- Docs: [risks mapped to the OWASP Top 10 for Agentic Applications](docs/risks.md), with
  the package that handles each, and a plain statement of
  [how agents get onto the map](docs/guides/agent-cartography.md#how-agents-get-onto-the-map):
  only by being declared in a host manifest (the discovery leads above only point at
  candidates).
- Docs: one [Support and limits](docs/support-and-limits.md) page replaces the
  protection design, assessment, acceptance and production-readiness documents;
  earlier plans and reviews are removed from the repository; `releasing.md` is cut to a
  checklist, commands and rollback; the README gains a tested five-minute example
  and a maturity table (stable / experimental / reference app); the threat model
  covers Agent Ops; the API contract drops "Alpha". New releases link CI runs
  instead of committing dated evidence JSON. A test checks every relative Markdown
  link in the repository.
- Test: seeded property tests for `canonicalJson`/`digestJson` (stable under key
  order, round-trip, injective across 3,000 generated values, no cross-type digest
  collisions) and model-based tests of budgets and reservations under random
  interleavings, in core (60 seeds) and the durable executor (25 seeds, with
  reconciliation and restart). Both model tests fail when reservation release is
  broken. They use a small seeded generator instead of a new dependency.

## 0.1.0-alpha.3 — 2026-11-05

- Harden policy admission, approval expiry, cancellation, task authentication,
  response validation and bounded callback capacity.
- Bind approved sandbox inputs to the bytes actually staged; reject unsafe
  workspace paths and add an opt-in independent rollback witness.
- Add scoped MCP credential management, signed build and pilot evidence,
  provider outcome evaluation and operator-study tooling.
- Clarify Agent Map authorization, stale-result handling, recovery and mobile
  navigation; fix installed command launchers.
- Publish protection requirements, design, engineering review and reproducible
  validation evidence. SDK publication remains experimental and does not certify
  a production deployment.

## 0.1.0-alpha.2 — 2026-11-04

Published all five npm packages under the `alpha` tag. The release notes cover
registry verification and the workaround for the two Agent Map command shortcuts
on macOS.

- Correct Windows test paths and close the pilot's SQLite owner before deleting
  its fixture directory. Resolve native filesystem aliases in release root
  validation while retaining nested-directory and dirty-checkout rejection.
- Fix the local pilot launcher's configuration-file race by opening one
  nonblocking, no-follow descriptor before validating private metadata. Cover
  FIFO replacement and keep Node 22 runtime warnings separate from exact test
  assertions about safe application diagnostics.
- Reject staged graph projections where duplicate memberships or endpoint edges
  conceal missing relationships. Validate distinct nodes and expected endpoint
  pairs as well as totals before changing the published snapshot.
- Open private difference-report files nonblocking and revalidate descriptor
  ownership, permissions, link count and size. Reject FIFO replacements and
  same-inode safety changes without leaving an open descriptor.
- Reduce cold Neo4j planning cost for scoped policy checks by expressing the
  binding proof as correlated short paths. Preserve exact scope/identity checks,
  all duplicate-edge guards and the five-second read deadline; cover every guard
  with a committed-change regression and make refresh-clock tests deterministic.
- Bound bearer reference-launcher configuration reads on the opened regular-file
  descriptor. Reject named pipes before reading and cap files that grow after
  metadata inspection; preserve regular-file symlinks and safe startup errors.
- Clear company viewer evidence and abort sibling reads immediately on any
  HTTP 401/403, regardless of denial-body framing, size or completion. Keep
  ordinary error handling and bounded response parsing unchanged.
- Reject nonregular Cartography input files before reading so named pipes cannot
  stall import/enrollment startup. Preserve regular-file symlinks and input limits;
  align lifecycle identifiers with the shared whitespace/BOM validation rule.
- Preserve original task/tool and visible MCP observation times in Agent Map
  freshness, including historical snapshots; recomposition cannot renew old
  evidence. Keep missing timestamps unknown and reject malformed core coverage.
- Preserve resource case through Cartography's S3 bucket-summary matcher while
  retaining case-insensitive actions. Correct both invented Allow candidates and
  candidates suppressed by mismatched Deny resources; refresh existing captures
  and Guard joins to replace previously published evidence.
- Reject BOM-only or mixed-whitespace enrollment identifiers consistently across
  observer, cloud-join and AWS collection configuration; preserve nonblank values.
- Reject non-ASCII digits in Cartography cloud account enrollment, including
  revalidated `CloudScope` objects, to match the AWS collector and inventory
  schemas. Add six regression cases and installed-wheel checks; document the
  existing graph-replay size limits.
- Bound each disposable Neo4j readiness handshake to two seconds using the
  driver's acquisition deadline. Verify silent-peer timeout and successful
  retry/query behavior without relaxing the overall startup deadline.
- Enforce archive file-count capacity before new writes and reserve snapshot/
  receipt capacity together. Align standalone and embedded inventory schemas
  with TypeScript validation for token boundaries and blank Unicode identifiers.
- Fix Cartography receipt replay bypassing archive lifecycle/recovery fences;
  incomplete reconstruction now also blocks collector work and archive pruning
  before evidence changes. Added CLI replay and concurrent source-retirement
  regression coverage.

- Add explicit source-generation supersession with a private transition journal,
  graph publication fences, active-source reads and bounded retirement after a
  grace period. Preserve replacement decisions through backup/replay and reject
  incomplete lifecycle or recovery state.
- Reject complete policy evidence from custom map stores when owning-agent or
  grant/tool/selector links are missing or ambiguous. Preserve valid multiple
  grants and explicit unavailable evidence. Add real-Neo4j regressions for team,
  deployment and identity changes between policy reads.
- Expose scoped IAM policy candidates through the existing reference HTTP/MCP
  API and viewer. Verify exact task/deployment/binding paths, collection ownership,
  provider consistency and independent freshness; bound and recheck reads.
  Preserve original object/prefix scope, unresolved coverage and unknown
  assessments. Add condition/timestamp cards and dashed graph edges, while
  excluding live policy evidence from historical snapshot comparisons.
- Add explicit opt-in IAM identity-policy evidence to AWS collection. Resolve
  complete user/group/role/managed-policy references, bound policy bytes and mapper
  work, and suppress candidates for unresolved boundaries or unsupported policies.
  Atomically replace owned S3 candidate edges with minimized condition metadata,
  preserving shared Cartography relationships. Keep assessments unknown and raw
  policy documents inside the capture worker.
- Add explicit single-account AWS metadata collection with exact caller checking,
  frozen temporary credentials, bounded verified HTTPS exchanges and an owned
  deadline-limited worker. Atomically publish pinned Cartography role/user/bucket
  schemas and collection membership; preserve shared provider nodes while making
  removed or changed evidence unresolved. Coordinate hourly AWS refresh inside
  the existing observer lock owner, isolate failures and emit safe receipts.
  Add offline SDK/transport, orchestration and real-Neo4j tests. Live enrollment
  remains deployment work.
- Add a dedicated company OIDC/HTTPS Agent Map endpoint and private launcher.
  Verified signed identities select explicit host-owned scopes; bounded code/PKCE
  exchanges, server-side sessions, CSRF, logout and revocation protect browser
  reads. The viewer discovers authentication mode and clears rejected/expired
  sessions. Add disposable HTTPS provider, packaged-client and real-Neo4j scope
  checks. Company provider enrollment and trusted-browser rollout remain separate.
- Add an isolated Cartography pilot with authenticated loopback Compose, real
  exporter/observer/collector/reference wiring, private versioned archive backups,
  fresh-graph replay and executor rollback checks. Add minimized 30-day difference
  reports, gated graph-load and admission-under-polling benchmarks, safe CI evidence artifacts
  and an operational runbook. Bound repeated opaque-reference hashing to each
  snapshot; the corrected admission benchmark passes its 10% target after this
  change, with earlier failed evidence retained. Company identity/cloud rollout
  remains an explicit deployment gate; the pilot creates no public service or
  scheduled cloud sync.
- Add the optional Agent Map reference service and React/Cytoscape viewer:
  host-defined company/tenant/team scope, bounded fixed Neo4j reads, equivalent
  HTTP/MCP evidence, focused graphs, conservative access explanations, exact
  potential-access lookup, snapshot differences and component freshness.
  Validate hidden/shared/moved ownership against disposable Neo4j; keep all
  inventory outside executor admission. Company SSO/TLS deployment remains pilot work.
- Add a bounded, enrolled observer collector with serialized polling, private
  snapshot/health receipts, restart replay and scoped retention. Join host AWS
  references to fresh, exact provider inventory with explicit unresolved evidence
  and preserved object/prefix scope; package the pinned S3 permission mapping.
- Add managed MCP inventory with lifecycle and descriptor drift revisions, opaque
  transport references, bounded host-mcp snapshot composition and observer delivery.
  Cartography projects connection/operation evidence with replay checks and explicit
  unavailable records; inventory never grants or approves execution.
- Add validated host-owned inventory manifests, immutable host-profile composition,
  explicit deployment/resource/execution bindings and independently versioned
  Cartography metadata projections. Host assertions never widen executor authority.
- Add a separate loopback inventory observer with namespaced credentials, fixed
  tenant scopes, bounded requests/responses, deadlines, quotas and concurrency
  limits; verify HTTP snapshots against the independent Cartography contract.
- Add the opt-in executor inventory exporter: persistent ledger identity with
  atomic legacy migration, immutable tenant snapshots, opaque resource references,
  strict bounds and independent TypeScript/Python contract checks for Cartography.
- Add the experimental `@shieldaai/agent-guard-executor` workspace: encrypted SQLite
  admission, task/admin authentication, conservative crash recovery, scoped model
  dispatch, versioned private files, restricted HTTP and governed memory.
- Add typed argument normalization and resource-version binding to the shared core;
  extend the conformance catalog to twelve paired scenarios (catalog 1.2.0).
- Add managed MCP connections with session-bound approval, bounded local schemas,
  metadata quarantine, explicit resources/prompts and restricted HTTP transport.
- Add a pinned-image Docker workload profile with bounded copy-in, isolated Linux
  execution and separately reviewed exports. Real macOS/Linux-VM tests pass; native
  Linux/Windows host runs and independent review remain protected-release gates.
- Add platform CI, clean packaged-consumer checks and adversarial recovery,
  transport, memory, adapter and isolation tests. Package publication does not
  certify the full native platform isolation or company deployment boundary.

## 0.1.0-alpha.1 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag. The [GitHub prerelease](https://github.com/ShieldaAI/agent-guard/releases/tag/v0.1.0-alpha.1) includes the verified tarballs and checksums.

- Check deadlines again when a handler result settles, so synchronous work cannot return success
  after its deadline while the cancellation timer is waiting to run.
- Enforce the canonical JSON byte limit during normalization instead of building an oversized
  serialization before rejecting it.
- Disable persisted CI checkout credentials, bound workflow runtimes, and add CodeQL, dependency review and Dependabot configuration.
- Clarify package selection and the local demo setup; no provider credentials are needed.
- Reject custom policy decisions when their supplied task snapshot changes during evaluation, before a handler runs or an approval is consumed.
- Strengthen scenario catalog 1.1.0 to detect premature dispatch and incorrect cost settlement; bound asynchronous conformance cases with configurable timeouts.
- Exercise the MCP bridge against the official SDK v2.4.0 and document the difference between local request cancellation and remote work stopping.
- Remove obsolete build output and rebuild packages before packing.
- Compile packed public types and README examples, execute a packaged MCP consumer, and require a clean committed checkout with aligned versions before publication.

These changes are not included in the earlier `0.1.0-alpha.0` packages.

## 0.1.0-alpha.0 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag.

- Initial TypeScript execution core for explicitly registered tools and scoped task trees.
- Immutable prepared actions, exact approvals, tenant and recipient gates, shared sensitivity, literal secret scanning and atomic local budgets.
- MCP client bridge with explicit approval of tool metadata.
- Ten versioned protective scenarios with malicious and benign executable fixtures.
- Package-consumer verification, CI, threat model and release documentation.

This alpha is experimental and keeps state in one process. See the threat model for deployment requirements and limitations.
