# Production readiness acceptance

Status: **P0 implementation complete; final production acceptance pending**.
The configurable self-hosted profile, durable approvals, archival, key custody
and exact-current recovery are implemented. Final acceptance requires all
recorded candidate gates to pass and the upstream Node HIGH security prealert
review described below.
The final history-capacity guard passed the full local suite, hosted platform
matrix and Linux image verification. The evidence record retains pending and
failed checks explicitly. No final
production score or new production release is asserted. Earlier construction
scores and alpha release checks do not establish acceptance of this candidate.

The target is at least **9.5/10 independently in every R1–R10 category**, with no
open critical or high security defect, broken supported workflow, misleading
success state, or unverified required recovery step. A numerical average cannot
compensate for a failing category. Findings remain open until the actual entry
point and rejection/recovery path have been exercised on the candidate.

## Product and deployment boundary

Agent Guard is Apache-2.0 software. Companies operate their own installation and
provide their own records, identity provider, credentials, TLS and storage. The
product acceptance review must not require a customer to disclose those inputs
to the maintainer. Disposable local fixtures exercise the same interfaces and
protocols; their evidence must remain explicitly labeled synthetic.

The product consists of the five public SDK packages, the read-only Agent Map,
and the single-owner Linux Agent Ops deployment. Public SDK checks cover the
advertised Node/platform matrix. The operations deployment supports one owner,
conditional local ticket changes, OIDC identities and separately retained
rollback witnesses. It must fail closed when that boundary is violated. A normal
in-process handler still trusts its host; isolated code and hostile MCP peers
must use their documented isolation profiles. No distributed quota, HA, live
Jira/Linear connector or universal model-resistance claim follows from this
profile.

Company rollout checks in [the existing acceptance checklist](protection-acceptance.md#deployment-validation-checklist)
remain separate: enroll real identities/tools and paths, test the company's
storage/backup custody, route alerts, size resources, and validate its operators
and model/provider integration. A product release does not certify an unknown
installation. Conversely, a fixture does not count as a completed company study,
paid live-provider trial or independent human security assessment.

## Required evidence

| Category | Required behavior and evidence |
| --- | --- |
| R1 · Goal and tool misuse | Every supported effect crosses trusted registration, capability/resource checks and backend scope enforcement. Test allowed effects and malicious resource/tool substitutions at the real backend; documents identify all ambient bypass assumptions. |
| R2 · Identity and delegation | Signed OIDC verification, explicit tenant/role bindings, protected agent credentials, revocation/session expiry, delegated scope narrowing and backend tenant isolation. Reject forged, stale, swapped and cross-tenant identities; reload/restart invalidates sessions. |
| R3 · Exact approval | Show target, before/after state, version, deadline and digest; bind authenticated reviewer and exact execution. Stale, denied, replayed, changed and interrupted decisions cannot create another effect. Browser evidence and durable receipts agree. |
| R4 · Secrets, data and egress | Private canonical files, bounded strict parsing, encrypted state, verified TLS/OIDC egress, secret-free browser/API/errors and scoped exports. Actual startup enforces private custody and certificate identity even when preflight is skipped. |
| R5 · Tool and artifact supply chain | Locked dependencies, immutable isolation/deployment images, verified artifact/peer admission and quarantine on change, exact installed-package checks, current advisories, dependency inventory, and hosted checks attributable to the reviewed source. |
| R6 · Isolated code execution | Registered production profiles enforce privilege, mounts, network and resource limits. Benign execution, hostile inputs, exact approved capture, termination and cleanup run through installed packages; required supported platform checks cannot silently skip. |
| R7 · Governed memory and context | Provenance, scoped retrieval/delegation, quarantine and source revocation survive restart. Archival/compaction preserves integrity and permanent denial of retired identities; missing or altered history cannot silently restore authority. |
| R8 · Budgets, history and recovery | Atomic reservations and backend receipts, no speculative retry of unknown effects, safe long-term retention, review-bound offline changes, recoverable key rotation/active-ring retirement, authenticated cold backup and current-witness restore. Exercise crash phases, rollback, capacity pressure and fresh-container persistent storage. |
| R9 · UX and operations | Clear self-hosted setup and company data import; scoped lists, empty/error/stale/session states; keyboard/mobile and Chromium/Firefox/WebKit checks; explicit unknown outcomes; authenticated status/activity export; bounded metrics, capacity/TLS alerts and actionable recovery runbooks. Inventory observations remain distinct from grants and confirmed effects. |
| R10 · Evaluation and release controls | Requirement-to-test traceability, current full suite and tarball consumers, real Linux service/browser evidence, source/image identification, current hosted CI/CodeQL/dependency checks, usable upgrade/rollback/support instructions and honest distinctions between synthetic tests and company/provider evidence. |

Each category uses five review dimensions: requirements, design/defaults,
implementation, verification, and operational clarity, each worth at most two
points. Full marks require evidence for both normal and failure behavior. An
unimplemented requirement is a blocker, not a small deduction. Residual minor
limitations need a written rationale; no score is inferred from test totals.

The review uses the authentication, session, configuration, cryptography and
logging concerns in [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
as additional review prompts. It is not an ASVS certification or a substitute
for a deployment-specific assessment.

## Implemented P0 behavior

Companies supply their own OIDC issuer/client/subjects, TLS, private storage and
ticket records. [Onboarding](../deployment/production/README.md#company-onboarding)
creates a fresh private bundle atomically, reports the exact callback URL and
creates no authority before explicit initialization. Empty company data is valid;
fixtures and hosted accounts are not required. Preflight explains missing setup,
and actual startup independently enforces TLS, file custody and tenant enrollment.

[Capacity settings](../deployment/production/README.md#reviewed-capacity-changes-and-ticket-imports)
have bounded integer ranges. Offline preview/apply binds an exact digest;
persisted policy must match configuration, and a decrease cannot discard existing
records or keys. Storage capacity never increases an agent's grants or budget.
Add-only company imports bind exact bytes and tenant enrollment, retain existing
ticket versions/receipts and provide paginated results.

The durable reference workflow binds a signed-in reviewer's decision to the exact
ticket/version/change/deadline. Restart, stale review, denial and replay cannot
repeat the effect. Unknown outcomes remain explicit until trusted reconciliation.
Task retirement preserves permanent identity fences. The supported ticket
profile compacts completed history into authenticated immutable segments while
retaining live and uncertain work.
The global 10,000-segment closure ceiling is enforced before compaction intent
or task archival, including one reserved slot for interrupted work. Existing
over-cap history refuses startup without changing authority. Operators see
committed/reserved capacity and 80%/95% warning thresholds.

[Managed custody](../deployment/production/custody.md) supports complete registered
store groups, authenticated cold backups, recoverable rotation and active-key
retirement with historical escrow. New stores mirror exact-current encrypted
state in independent witness custody, and history mirrors are durable before
head advancement. Reviewed repair can recreate lost primary directories without
rewinding witnesses, task identities or spent authority. Legacy stores need
explicit enrollment. Setup distinguishes enrolled recovery from unverified legacy
state; neither label claims that a backup or company recovery drill occurred.

[Operations guidance](../deployment/production/monitoring.md) covers authenticated
status/activity, bounded metrics and security events, capacity/TLS alerts, unknown
receipts, and recovery actions. [Agent Map planning](production-plan.md#p1--extend-agent-map-and-cartography-inventory)
extends the existing inventory with ownership, permissions and relationships.
Observed inventory is never presented as an effective grant or confirmed effect.

## Requirement-to-test traceability

The paths below identify representative normal and failure coverage, not an
exhaustive list or a substitute for the full suite. All paths are relative to the
repository root. Tests use disposable synthetic identities, records and keys.

| Category | Direct verification |
| --- | --- |
| R1 | `packages/core/test/security.test.mjs`, `packages/executor/test/executor.test.mjs`, `apps/agent-ops/test/workflow.test.mjs`: scoped registration, backend effects, substitution, denial and replay. |
| R2 | `packages/agent-map/test/oidc.test.mjs`, `identity-http.test.mjs`, `packages/mcp/test/credentials.test.mjs`, Ops `server.test.mjs`: signed identity, tenant/role narrowing, credential lifecycle and restart invalidation. |
| R3 | Ops `workflow.test.mjs`, `server.test.mjs`, `check-browser-service.mjs`: exact authenticated review, stale/changed/denied decisions, receipts and unknown-result reconciliation. |
| R4 | Ops `onboarding-boundaries.test.mjs`, `tls-policy.test.mjs`; executor `network.test.mjs`, `workspace-input.test.mjs`; Map `asset-input.test.mjs`: canonical private paths, bounded parsing, TLS identity, origin restrictions and no secret forwarding. |
| R5 | `scripts/check-packages.mjs`, `scripts/trusted-npm.test.mjs`, executor artifact/build-admission tests, `deployment/production/check-images.mjs`, dependency workflows and CodeQL's open-alert gate. Upstream Node applicability remains unassessed. |
| R6 | `scripts/verify-platform.mjs`, `scripts/verify-mcp-isolation.mjs`, executor sandbox/approved-input tests: actual Linux isolation, exact capture, credential custody, termination and cleanup; the dedicated hosted gate refuses skipped runtime checks. |
| R7 | Executor `memory.test.mjs`, `lifecycle.test.mjs`; Ops `retention.test.mjs`, `history-recovery.test.mjs`: provenance/revocation, descendant and unknown-work fences, immutable history integrity and interrupted transitions. |
| R8 | Executor `capacity.test.mjs`, `recovery.test.mjs`, `ledger-maintenance.test.mjs`, `ledger-custody.test.mjs`, `ledger-recovery.test.mjs`; Ops custody/history and `history-capacity.test.mjs` tests, plus `deployment/production/check-linux.mjs`: atomic reservations, crash phases, stale-backup refusal, rotation/retirement, current primary-loss repair, shared recovery-capacity bounds and unchanged witnesses. |
| R9 | Ops onboarding/limits/observability/recovery-status tests, `check-browser.mjs`, `check-browser-service.mjs`, Map `check-browser.mjs`: setup, empty/stale/error/mobile/keyboard states, explicit uncertain outcomes, data import, policy explanations and accessible operation. |
| R10 | `npm run check`, all five installed tarball consumers, the actual alpha.3 upgrade/downgrade-fence consumer, hosted platform/browser/Linux/isolation/security gates, and the dated validation record linked below. |

## Recorded candidate verification

The [dated evidence record](validation/production-readiness-2026-11-06.json)
identifies source revisions, image IDs, command results and hashes. It separates
the runtime candidate from subsequent documentation or Python integration changes.
It is the authoritative index for exact hosted run status; a workflow definition
alone is not passing evidence.

- The final local runtime check passed **1,093/1,093 tests, zero skips**, plus the
  installed-package and public README/type consumers. Actual published alpha.3
  state upgrades preserve spent authority; the old reader refuses new semantics.
- Hosted Linux Node 22/24/26, macOS Node 24 and Windows Node 24 checks passed for
  runtime commit `53acbde`. The separate Linux isolation gate passed **44/44**, zero
  skips, and every MCP lifecycle/cleanup observation.
- Hardened persistent-volume Linux checks passed locally on ARM64 and hosted on
  AMD64. Production and verification images share **4,327 application entries**;
  the two test-only fixtures are explicitly excluded from production. Both
  architectures share the same application manifest. Runtime package-manager
  files and shims are absent.
- Both Linux runs imported 2,000 company records, verified 2,001 paginated tickets,
  recovered current state after primary-directory loss, retained historical and
  latest receipts, and reopened in a fresh container with read-only config/history.
  At eight clients and 40 measured 500-row reads, p95 was **156 ms on local ARM64**
  and **226 ms on hosted AMD64**, within the 2,000 ms test target. Each overload
  run refused 27 reads through the documented rate/busy responses without effects.
- Local Chromium, Firefox and WebKit runs covered 25 Ops contract states, 14 real
  HTTPS/OIDC service states and 13 Map states per engine: **156 accessibility
  scans**, zero axe violations or page errors. These are repeated automated
  scenarios, not 156 distinct human tasks. Selected screenshots were reviewed;
  graph label fitting was corrected and checked in all three engines. The mock
  threshold alerts were subsequently aligned with the real server and all three
  contract engines rerun; runtime application code was unchanged. All three
  hosted browser jobs also passed on `53acbde`. A final CI transport follow-up
  changes only the reviewed Ubuntu package mirror; its hosted result is tracked
  separately in the evidence index.
- The Python integration passed **928 unit and 143 authenticated Neo4j tests**,
  package builds and the installed consumer. Four locked platform selections
  each audited 194 packages with zero known vulnerabilities. The archived
  dependency notice remains recorded in the
  [Python evidence](validation/cartography-python-2026-11-06.json).
- CodeQL analyzed the runtime candidate and its **Unresolved security alerts**
  gate passed with zero open alerts for the PR merge ref. The
  [triage record](validation/codeql-triage-2026-11-06.md) documents the fixes and
  two reviewed loopback-healthcheck false positives. Default-branch alerts are
  not claimed closed before merge.

## Remaining acceptance and operational limits

**R5 acceptance is pending; its production score is withheld.** The
[official Node security prealert](https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/november-2026-security-releases.md)
announces HIGH issues in all supported Node release lines without identifying
features or fixed versions. This does not establish that Agent Guard is
exploitable, but application non-applicability cannot yet be established. Empty
npm or Alpine findings do not clear native Node exposure. The
[dated dependency review](../deployment/production/advisories-2026-11-06.md)
also records two builder-only moderate findings and their restricted-input
assumptions; those findings are not dismissed or included in the runtime tree.

To close R5, review each published issue, adopt the applicable fixed immutable
Node image or record evidence-backed non-applicability, and refresh exact-image
inventories, advisories, installed-package checks, supported-platform checks and
Linux recovery evidence. Final hosted gates must pass for the reviewed source.
The target score remains an acceptance objective, not a number assigned to make
unfinished work appear complete.

The supported operational boundary remains material:

- One owner on local Linux POSIX storage; no HA, distributed quota or live
  third-party ticket connector is certified by the bundled backend.
- Current repair requires surviving independent witnesses/mirrors and keys.
  A simultaneous loss or rollback of those domains cannot be repaired by this
  protocol. Process crashes and file-loss fixtures do not prove physical
  power-loss durability on a company's storage controller.
- Sustainable ticket history is the documented single-root, no-memory profile.
  Collected ticket-history closure is bounded to **10,000 segments** for backup,
  mirror enrollment and exact-current repair. Use a reviewed replacement adapter
  before that ceiling; surviving mirrors alone do not remove it. Other SDK
  archives retain finite safe-stop limits, and full-chain verification grows with
  history. Raising capacity is not a memory/latency guarantee for every
  maximum-sized combination.
- Historical escrow remains necessary for retained evidence/backups. Active-key
  retirement does not destroy every off-host historical copy or find backups
  outside the enrolled catalog.
- Automated browser/accessibility checks and visual inspection provide product
  regression evidence. They are not a representative human usability study,
  live provider evaluation or acceptance of an unknown company installation.
- Cartography's admission benchmark smoke has a strict polling-cadence gate.
  Preserve failed attempts and measured overhead; passing smoke must not be
  described as achieving the separate 10% performance acceptance target. The
  final hosted smoke passed its correctness/stress gates with **15.19%** measured
  admission overhead. One current local full run observed **1.64%** overhead and
  passed its numeric gate, but unrelated CPU-heavy work was active; it is
  explicitly not quiescent acceptance evidence. Both observations and earlier
  failed attempts remain in the [pilot record](validation/cartography-pilot-2026-11-06.json).
  This deliberate 250 ms observer stress profile does not establish production
  latency or a deployment-wide 10% guarantee; the collector defaults to five minutes.

The old [construction assessment](protection-assessment.md),
[P0 implementation record](production-p0-review.md), and
[onboarding implementation record](self-hosted-onboarding-review.md) retain their
original scope and dates. They are useful historical evidence, not completion
proof for this candidate.
