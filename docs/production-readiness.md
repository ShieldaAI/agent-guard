# Production readiness acceptance

Scope note: the candidate results below describe the recorded P0 revisions.
The subsequent [agent cartography expansion](agent-cartography-review.md) has its
own contract and verification. Earlier source fingerprints and scores do not
automatically certify that expansion or remove the release hold below.

The subsequent 0.1.0 observer acceptance profile requires native Linux/cgroup v2,
one selected logical CPU, one-CPU bandwidth quota with a 100 ms period and zero
burst, 512 MiB memory, no extra swap and 128 PIDs. The new configured candidate
also explicitly selects `workerScheduling: 'linux-background'`: only the observer
worker's native main-thread priority is lowered by up to five nice points, capped at 19,
with verified readback and unchanged owner priority. No GC/helper-thread priority
change is claimed. Generic SDK/CLI defaults remain unchanged. The controlled exact-source
`e4e42f` run passed the unchanged 10% gate at 7.2766% overhead, with 1,200 effects,
149 polls and no failed/skipped polls. Quota-only native runs failed at 13.31–14.89%;
the Colima-affined failure also remains evidence. The later `9709f70` constrained
run failed cadence and overhead; an `a91028c` pass used unchanged runtime bytes.
Neither result establishes the prior failure's cause or a timing fix. See the
[one-CPU record](validation/one-cpu-observer-2026-11-06.json) and
[required observer-service resource configuration](../deployment/cartography/RUNBOOK.md#matching-the-observer-owning-service).
This profile belongs to a company's observer-owning executor, not the reference
Agent Ops service, which does not start an observer. It reserves neither an
exclusive nor physical core and does not guarantee an unknown deployment's latency.
Those prior runs used default worker scheduling and cannot qualify the new mode;
the later `1ef859c` default-mode failures remain retained as well.
Exact `ba7deb6` then passed both predeclared runs of the configured profile:
**5.457% and 9.280% overhead**, all 1,200 effects in each, 135/152 polls, zero failed
or skipped polls, verified controls and cleanup. These results do not replace
the ordinary full graph/admission qualification, which remains incomplete.

The current candidate adds one cooperative yield to the public task HTTP server's
prepare/execute routes after bounded JSON parsing and before fresh second
authentication. Fresh authority checks, the original monotonic body deadline,
transport guards and the immutable validated route remain enforced; fixed
`REQUEST_TIMEOUT` errors do not cause automatic retries. No resource cap,
immediate first poll, cadence or acceptance gate changes. This is scoped HTTP
scheduling, not a fairness or real-time guarantee for all SDK embeddings.
On `1ef859c`, its 98 focused checks and full local check passed: **1,283/1,283 tests,
zero skips, plus installed consumers**; all 11 hosted CI jobs also passed with
platform skips recorded. Its CodeQL unresolved-alert gate failed on the temporary
Windows experiment registration trigger. The subsequent direct core serializer
and explicit background-worker candidate's first combined local run passed 1,306 of 1,307 tests with
zero skips; one copied CLI fixture lacked the new helper, and packaging was not
reached. Its minimal copy-list correction passed the focused regression; the
second full check passed **1,307/1,307 tests, zero skips, plus installed consumers**.
On `ba7deb6`, all 11 hosted CI jobs passed, including 195 browser accessibility
scans and the required 45 Linux isolation checks without skips. The ordinary full
workflow failed at graph database readiness before graph measurements or admission;
the PR pilot failed earlier with only `PILOT_FAILED` and no report. Current CodeQL
alert 23 remained open despite successful analysis. The manual experiment now
selects only the fixed reviewed historical commit; its new scan is pending.

The startup follow-up fixes a separately reproduced Neo4j option-parser edge by
prefixing the complete generated random password, preserving all 256 random bits.
It also retains bounded, secret-free failure evidence before owned-resource
cleanup. Historical failure causes remain unproven. Its full local Python sequence
passed lint/formatting, **1,022 unit tests and 150 authenticated Neo4j integration
tests**, verified cleanup, package builds and isolated installed-wheel checks.
New hosted/full graph/admission verification and CodeQL remain pending.
The controlled exact-`9709f70` Windows serial experiment
passed the previously failing cases and installed consumers; the maintained
Windows-only test launcher subsequently passed on `1ef859c`. Prior failures
remain evidence and their underlying cause is unproven. The Node HIGH hold remains;
these results authorize no publication, merge, tag or production acceptance.

Recorded P0 status: **Candidate verification passed; production acceptance held for Node HIGH review**.
The configurable self-hosted profile, durable approvals, archival, key custody
and exact-current recovery are implemented. Final acceptance requires all
recorded candidate gates to pass and the upstream Node HIGH security prealert
review described below. R5 remains withheld. All six ordinary hosted workflows
passed for the reviewed harness follow-up `a8c2d16`, including integration,
packaging and the installed consumer. The
[current CI record](validation/production-readiness-ci-2026-11-06-a8c2d16.json)
and [integration follow-up](validation/cartography-readiness-followup-2026-11-06-a8c2d16.json)
bind those results to the exact source. The production application and admission
performance inputs are unchanged from `fef2e37`.
The [retained failure record](validation/cartography-readiness-failure-2026-11-06-1a612c9.json)
identifies `1a612c9`: five workflows passed, including all 11 CI jobs, while
Cartography integration reported 142 passed and one failed. Its nested owned
Neo4j runner did not become ready before its deadline; no connection/authentication
or container diagnostic establishes the underlying cause. The follow-up retains
safe failure diagnostics, enforces the existing deadline after probes and requires
verified cleanup. Resources, timeouts and recovery assertions were not relaxed.
Its passing result closes current verification; it does not explain the earlier
timeout or guarantee that fixture startup can never fail.
The verified [ledger-decoder candidate](validation/ledger-decoder-2026-11-06.json),
`fef2e37`,
uses private normalization of a freshly parsed graph; authenticated reads,
witness checks and transactions remain unchanged. Its full local check passed
**1,116/1,116 tests, zero skips**, plus installed consumers. Image comparison
found only the compiled decoder module changed, and hardened Linux recovery
passed. All six ordinary hosted workflows and the candidate's one predeclared,
uninstrumented full performance run passed. Admission p95 overhead was **6.44%**
against the unchanged 10% gate, with 1,200 exact effects, 109 successful polls,
no failed or skipped intervals, and complete cleanup.
The [exact CI record](validation/production-readiness-ci-2026-11-06-fef2e37.json)
binds all eight artifact digests and the tested merge tree to this source.
`4b2cdc9` and `ab56766` records remain historical evidence.
The evidence record retains earlier failed checks and current holds explicitly. No aggregate
production score or new production release is asserted. Earlier construction
scores and alpha release checks do not establish acceptance of this candidate.
Prior full and smoke performance runs missed isolated polling intervals despite
correct effects and cleanup. Diagnostic runs `42194605365` and `42199037007`
measured **11.35%** and **14.37%** overhead respectively; both are ineligible as
acceptance evidence. The second completed 249 polls without skips and attributed
66% of measured stack observations to decode/reviver work. That is not exact CPU
time, and the earlier rare stalls were not reproduced.

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

## Internal category judgment

The [reviewed five-dimension rubric](validation/production-category-review-2026-11-06.json)
records subjective internal engineering judgments for the documented profile.
These are not statistical confidence, external certification or a guarantee of
safety. **The every-category target remains unmet: R5 is withheld**;
there is no aggregate production score.

| Category | Judgment / 10 |
| --- | --- |
| R1 · Goal and tool misuse | 9.7 |
| R2 · Identity and delegation | 9.8 |
| R3 · Exact approval | 9.8 |
| R4 · Secrets, data and egress | 9.7 |
| R5 · Tool and artifact supply chain | **Withheld — Node HIGH applicability** |
| R6 · Isolated code execution | 9.7 |
| R7 · Governed memory and context | 9.8 |
| R8 · Budgets, history and recovery | 9.6 |
| R9 · UX and operations | 9.6 |
| R10 · Evaluation and release controls | 9.7 |

The linked review gives each dimension's evidence and deductions. The passing
follow-up restores current R10 verification while retaining its 1.8/2 verification
dimension and the earlier unexplained fixture timeout. Company rollout,
representative human usability and paid provider trials remain separate deployment
validation; they are not fabricated or counted as completed product evidence.

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

## Recorded candidate and baseline verification

The [dated evidence record](validation/production-readiness-2026-11-06.json)
identifies source revisions, image IDs, command results and hashes. It separates
the runtime candidate from subsequent documentation or Python integration changes.
It is the authoritative index for exact hosted run status; a workflow definition
alone is not passing evidence.

- The current `fef2e37` candidate passed **1,116/1,116 local tests, zero skips**,
  plus all installed-package consumers. The [decoder record](validation/ledger-decoder-2026-11-06.json)
  identifies its exact 411-file source fingerprint and private implementation
  boundary. No authenticated read, witness/mirror check or transaction was removed.
- All six ordinary workflows passed on `fef2e37`. CI `42202786641` passed all 11
  jobs, including Linux Node 22/24/26, macOS Node 24 and Windows Node 24. Its
  ordinary Node 24 suite passed 1,108 of 1,116 tests with eight optional container
  skips; the separate required Linux isolation gate passed **44/44**, zero skips,
  including the real MCP lifecycle and cleanup checks. All eight CI artifact ZIP
  digests were verified against GitHub metadata and bind to the exact head.
  The tested PR merge and head have the same Git tree; the
  [current CI record](validation/production-readiness-ci-2026-11-06-fef2e37.json)
  retains the source, job and artifact evidence.
- Hardened persistent-volume Linux recovery passed locally on ARM64 and hosted
  on AMD64. Each production/verification image pair shares **4,327 application
  entries**, with manifest SHA-256
  `f67ab3054649d983fcdc534d7ca94414add7f0aa4728b1daceb1d25d2f1bd8fa`.
  Only `/app/packages/executor/dist/store.js` changed from the prior reviewed
  application tree; dependency entries are unchanged. Architecture-specific base
  images remain distinct. Package-manager files and shims are absent, and the
  two verification-only fixtures are excluded from production.
- Both current Linux runs imported 2,000 records, verified 2,001 paginated tickets,
  recovered latest state after primary-directory loss without rewinding witnesses,
  preserved historical and latest receipts, and reopened in a fresh container
  with read-only config/history. Rotation, retirement, cold restore and uncertain
  receipt recovery passed. At eight clients and 40 measured 500-row reads, p95
  was **83 ms on local ARM64** and **114 ms on hosted AMD64**, within the 2,000 ms
  test target. Both overload runs refused 27 reads without effects. These service
  checks are separate from admission-overhead acceptance and do not certify
  customer storage or physical power-loss behavior.
- Chromium, Firefox and WebKit each passed 25 Ops contract states, 14 real
  HTTPS/OIDC service states and 13 Map states: **156 accessibility scans**, zero
  axe violations or page errors. These are repeated automated scenarios, not
  156 distinct human tasks. Both expiry/navigation regressions passed in every
  engine; expired approval controls disappear on the existing expiry tick and
  navigation stays operable.
  All three signed Ubuntu archive steps passed. Earlier visual review, graph
  fitting corrections, installation bottlenecks and the reproduced navigation
  race remain in the historical browser records.
- The one predeclared full run `42202792736` used the unchanged ABBA workload,
  250 ms serial polling and enforced 10% gate, with diagnostics and CPU profiling
  disabled. Admission p95 changed from **31.63 ms to 33.67 ms (6.44%)**; all 1,200
  effects and charged calls matched, all 109 polls completed without skips or
  failures, and resources closed. The 10,000-task/100,000-grant graph profile
  passed publication/query gates. Verified artifact hashes and compressed raw
  reports are retained in the [decoder record](validation/ledger-decoder-2026-11-06.json).
  An [independent raw-sample recomputation](validation/ledger-decoder-full-gate-verification-2026-11-06.json)
  matched every original gate without discarded samples or relaxed conditions.
  This is one passing candidate run, not a universal latency guarantee.
- Cartography integration, the ordinary smoke pilot, Python audit, dependency
  review and CodeQL all passed on `fef2e37`. The historical Python evidence
  retains 928 unit and 143 authenticated Neo4j tests, locked platform audits and
  the archived dependency notice; current workflow IDs are in the dated index.
- CodeQL run `42202786742` passed both analyses and the **Unresolved security
  alerts** gate. A fresh query found zero open alerts for `refs/pull/8/merge` and
  five separately scoped open alerts on `main` (#15, #7, #6, #5 and #4).
  The [triage record](validation/codeql-triage-2026-11-06.md) retains the fixes and
  reviewed loopback-healthcheck false positives. Default-branch closure is not
  claimed before merge.
- The [prior exact CI record](validation/production-readiness-ci-2026-11-06-4b2cdc9.json)
  and the immutable prior-index link in the dated index preserve `4b2cdc9`,
  `ab56766` and older observations. They are not substituted for current candidate
  evidence. Earlier cadence failures and both ineligible diagnostic runs remain
  recorded below and in their original reports.
- The subsequent documentation-only head `1a612c9` passed CI `42204781351`
  (all 11 jobs), smoke `42204781403`, CodeQL `42204781357`, dependency review
  `42204781519` and Python audit `42204781376`. Integration `42204781372`
  passed 928 unit tests, then failed one nested Neo4j readiness setup among
  143 integration tests; packaging and the installed consumer were skipped.
  The previous `fef2e37` integration passed all 143 tests in 196.42 seconds;
  this attempt finished with 142 passes and one failure in 304.83 seconds.
  These timings do not identify a cause. Full-log hashes, the safe exact error
  excerpt and comparison are in the [failure record](validation/cartography-readiness-failure-2026-11-06-1a612c9.json).
  The reviewed follow-up `a8c2d16` passed all six ordinary workflows. Its
  [integration record](validation/cartography-readiness-followup-2026-11-06-a8c2d16.json)
  retains exact counts, packaging/installed-consumer results and cleanup evidence.
  The [runner change record](validation/neo4j-readiness-diagnostics-2026-11-06.json)
  identifies the unchanged bounds and stronger failure reporting/cleanup checks.

## Remaining acceptance and operational limits

**Current integration/R10 verification passed.** The earlier timeout occurred
before the nested recovery assertions, and its underlying cause remains unknown.
The follow-up passed the required integration, packaging and installed-consumer
gates with stricter cleanup and deadline checks. A recurrence must be investigated
using the retained safe diagnostics; the historical failure is not erased or
reclassified as a proven resource-contention issue.

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
Linux recovery evidence for any changed source/image. The prior `fef2e37`
candidate gates and current follow-up review remain recorded. R5 is withheld,
so the every-category target is unmet.

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
  earlier hosted smoke passed its correctness/stress gates with **24.41%** measured
  admission overhead. One earlier local full run observed **1.64%** overhead and
  passed its numeric gate, but unrelated CPU-heavy work was active; it is
  explicitly not quiescent acceptance evidence. A subsequent unchanged full
  acceptance run in a separate GitHub job passed the enforced 10% gate at
  **5.18%** overhead: 1,200 exact effects, 129 successful polls, no missed cadence,
  and all resources closed. Its 10,000-task/100,000-grant graph profile also passed
  publication and query limits. All observations and earlier failed attempts
  remain in the [pilot record](validation/cartography-pilot-2026-11-06.json).
  A subsequent docs-only rerun missed two polling intervals in each polling
  phase despite correct effects and cleanup. That failure remains in the history;
  the earlier full-profile pass did not waive it. The profiled projection cost
  is corrected by a private finalizer for newly constructed output; input
  validation, authenticated reads, output equivalence and exact caps remain
  enforced. Differential and boundary tests pass. The optimized full run still
  missed one interval, and the checkout-only follow-up smoke missed two.
  Baseline `4b2cdc9` pilot run `42195606557` passed smoke; it does not waive the
  `c38cf47` full-profile or `8cabb88` smoke cadence failures. Bounded, opt-in
  request/export/GC/event-loop diagnostics preserve every gate and are explicitly
  ineligible as acceptance evidence. The completed `f6dec31` and `ee0d589`
  diagnostic runs measured **11.35%** and **14.37%** overhead and failed their
  numeric targets. The second had no cadence misses but did not reproduce the
  earlier rare stalls. The new decoder candidate `fef2e37` passed its one
  predeclared, uninstrumented full run under the same workload and gates at
  **6.44%** overhead. This does not erase earlier failures or establish their
  precise cause.
  This deliberate 250 ms observer stress profile is bounded evidence on the
  recorded runner, not a deployment-wide latency guarantee; the collector
  defaults to five minutes.

The old [construction assessment](protection-assessment.md),
[P0 implementation record](production-p0-review.md), and
[onboarding implementation record](self-hosted-onboarding-review.md) retain their
original scope and dates. They are useful historical evidence, not completion
proof for this candidate.
