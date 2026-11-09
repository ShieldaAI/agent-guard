# Changelog

## 0.1.0 — Unreleased candidate

Publication is held for the Node HIGH review and final candidate acceptance,
including the unresolved admission-performance gate. See the
[candidate release notes](docs/releases/0.1.0.md). No stable npm version or GitHub
release is claimed by this entry.

- Perf (inventory observer, experimental): an identical poll within
  `reuseUnchangedMs` (default 1,000 ms; 0 disables) returns the previous observation
  instead of re-projecting, keyed by the ledger ciphertext, registry, scope, profile
  and manifest. `host-mcp` is never reused. Unchanged 500-task polls drop from about
  4.2 ms to 0.25 ms; continuously written ledgers see no change.
- Perf (executor ledger): `LedgerStore.read()` caches the last verified ciphertext and
  its decoded state. Each read still fetches the row and runs every witness and mirror
  check, but when the bytes are unchanged it returns a detached copy without
  decrypting, parsing or re-walking the ledger. With 1,000 tasks, read-bound calls
  such as `snapshot()` take about half the time (3.6 ms to 1.8 ms); prepare and
  execute are unchanged because the write path dominates. Read results stay fresh,
  detached and mutable as before, and `close()` drops the decrypted cache.
- Docs: one [Support and limits](docs/support-and-limits.md) page replaces the
  protection design, assessment, acceptance and production-readiness documents;
  earlier plans and reviews move to `docs/archive/`; `releasing.md` is cut to a
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
- Fix (executor task server): bearer authentication uses an in-memory token index, so
  malformed and unknown tokens are refused without decrypting the ledger, and a valid
  one is found in O(1) instead of a scan over every task. The server adds
  per-credential and server-wide request rates, an in-flight request cap and a
  connection cap (`REQUEST_RATE_LIMITED`, 429).
- Fix: scenarios recognize rejections with the new `isGuardError()` brand check
  instead of `instanceof GuardError`, so a guard from a second installed copy of core
  passes conformance. `ConformanceReport.catalogVersion` is typed as `string`.
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
- Change: the durable executor task server returns HTTP statuses by kind (401, 403,
  404, 409, 429, 503, otherwise 400) instead of 400 for every denial, and the error
  body adds `retryable`. `ExecutorClient` accepts these statuses and exposes
  `retryable` on its errors. Older clients see the new statuses as
  `EXECUTOR_REQUEST_DENIED`; upgrade client and server together.
- Change: the internal SPI moves to `@shieldaai/agent-guard/internal` (no semver
  guarantees): `PolicyAdmission`, `assertActionAuthority`, `containsLiteralSecret`,
  `AuthorityPhase`, `AuthorityState`, `canonicalJson`, `digestJson` and
  `immutableJson`. The root aliases still work, are marked `@deprecated`, and will
  be removed in 0.3. First-party packages now import from `/internal`. The root
  entry also exports `InvalidJsonError`.
- Fix (Agent Ops): anonymous `GET /api/session` no longer creates server-side
  sessions, so cookieless traffic can't exhaust the session table and block sign-in.
  Pre-login state is a signed five-minute cookie with a derived CSRF token, and each
  client address may hold at most four pending sign-ins. The rate limiter keys IPv6
  by /64 and drops the oldest window when full instead of refusing new clients.
  New `requests` settings add per-requester (50) and per-tenant (1,000) pending
  caps, configurable review expiry (default unchanged at 5 minutes) and opt-in
  `forbidSelfApproval`. `SIGHUP` now also reloads TLS material without a restart.
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
- Fix: a call in flight no longer refuses `prepare()` or `approve()` with
  `CONCURRENCY_EXCEEDED`/`COST_BUDGET_EXCEEDED`, in core and in the durable
  executor. Transient capacity (concurrent calls, reserved cost) is enforced at
  dispatch; permanent capacity (calls, spent cost) still refuses preparation.
  `assertActionAuthority` gains an optional `phase` (default `dispatch`).

- Make self-hosted ticket/request capacity, live-store byte limits and retained
  key limits safely configurable through reviewed offline policy changes.
- Add company onboarding, TLS/OIDC preflight, add-only reviewed ticket imports,
  an operator Setup view and paging for larger company datasets.

- Add the single-owner Linux Agent Ops service with durable ticket updates,
  authenticated OIDC approvals, scoped agent proposals and receipt-only recovery.
- Add whole-family retirement and encrypted archival, scoped execution listing,
  exact ID tombstones and crash-safe archival receipt discovery.
- Add offline, retryable ledger key rotation with independent rollback witnesses
  and a protected multi-key ring.
- Add hardened Docker Compose deployment, recovery runbooks, real-service browser
  checks and a Linux production-profile CI job.
- Add reviewed company-history compaction with permanent retirement fences,
  independent encrypted history mirrors and exact receipt lookup.
- Stop history growth before it exceeds the backup/recovery closure limit,
  reserve capacity for interrupted compaction and expose operator capacity alerts.
- Add managed offline key escrow, authenticated complete backups, active-key
  retirement and schema-3 current-state repair without witness rollback.
- Add authenticated operational status, bounded metrics, minimized activity
  exports and explicit distinction between readable storage and enrolled recovery.
- Enforce startup TLS/custody checks, remove unused runtime package managers,
  and add dependency inventory, production-image comparison and three-browser CI.
- Patch the Python Cartography OAuthLib dependency and add locked cross-platform
  advisory checks; retain explicit, secret-free benchmark failure diagnostics.
- Implement the Agent Map/Cartography catalog for agents, owners, permissions,
  host-bound resources, opaque credential references, relationships and retained
  before/after changes, with scoped pagination and accessible browser workflows.

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
  a production deployment. [Release notes](docs/releases/0.1.0-alpha.3.md)

## 0.1.0-alpha.2 — 2026-11-04

Published all five npm packages under the `alpha` tag. The release notes cover
registry verification and the workaround for the two Agent Map command shortcuts
on macOS. [Release notes](docs/releases/0.1.0-alpha.2.md)

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

These changes are not included in the earlier `0.1.0-alpha.0` packages. See the [release review](docs/archive/quality-review.md) for test results and registry verification.

## 0.1.0-alpha.0 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag.

- Initial TypeScript execution core for explicitly registered tools and scoped task trees.
- Immutable prepared actions, exact approvals, tenant and recipient gates, shared sensitivity, literal secret scanning and atomic local budgets.
- MCP client bridge with explicit approval of tool metadata.
- Ten versioned protective scenarios with malicious and benign executable fixtures.
- Package-consumer verification, CI, threat model and release documentation.

This alpha is experimental and keeps state in one process. See the threat model for deployment requirements and limitations.
