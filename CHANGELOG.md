# Changelog

## Unreleased — agent security hardening

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
  transport, memory, adapter and isolation tests. These source changes are not yet
  published; the existing alpha release remains unchanged.

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

These changes are not included in the earlier `0.1.0-alpha.0` packages. See the [release review](docs/quality-review.md) for test results and registry verification.

## 0.1.0-alpha.0 — 2026-10-24

Published all three packages under `@shieldaai` with the `alpha` dist-tag.

- Initial TypeScript execution core for explicitly registered tools and scoped task trees.
- Immutable prepared actions, exact approvals, tenant and recipient gates, shared sensitivity, literal secret scanning and atomic local budgets.
- MCP client bridge with explicit approval of tool metadata.
- Ten versioned protective scenarios with malicious and benign executable fixtures.
- Package-consumer verification, CI, threat model and release documentation.

This alpha is experimental and keeps state in one process. See the threat model for deployment requirements and limitations.
