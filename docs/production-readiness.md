# Production readiness acceptance

Status: **implementation and verification in progress**. No production score is
assigned to this candidate yet. Earlier construction scores and alpha release
checks do not establish acceptance of the changed source tree.

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

## Candidate work and open verification

- Implement safe reusable history capacity with authenticated exported evidence,
  permanent retirement fences and recoverable offline transitions.
- Implement managed cold backups and active-key retirement with retained escrow;
  do not claim that a filesystem scan proves all off-host backups were found.
- Close the primary-data-loss recovery gap: cold checkpoints become stale after
  subsequent authority changes. Add an exact-current encrypted recovery mirror
  in independent witness custody, including archive/catalog and immutable history
  closure. Verify primary loss and interrupted repair without rewinding witnesses.
- Complete operational status, minimized activity snapshots, security events,
  metrics/alerts and clear operator guidance.
- Verify mandatory startup TLS/custody and tenant-enrolled initialization.
- Run the full current candidate suite, installed-package checks, three-browser
  walkthroughs and persistent-volume Linux recovery. Review screenshots.
- Retain current dependency audits and software inventory, then obtain hosted
  checks for the exact source revision. A configured workflow is not a passing run.
- Review all changes against this matrix, record remaining limitations and score
  each category only after the authoritative checks finish.

The old [construction assessment](protection-assessment.md),
[P0 implementation record](production-p0-review.md), and
[onboarding implementation record](self-hosted-onboarding-review.md) retain their
original scope and dates. They are useful historical evidence, not completion
proof for this candidate.
