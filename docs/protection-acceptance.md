# Defensive-project acceptance criteria

This review assesses the construction of Agent Guard as a defensive project.
The target is at least **9.6/10 in each of R1–R10**, with the scope and evidence
in the [engineering scorecard](protection-assessment.md). Penetration testing
and an enrolled company deployment are outside this construction review.

Each category receives five engineering judgments, worth up to two points each.
The dimensions are requirements, design and defaults, implementation, regression
verification, and operational/API clarity. A full two points requires coherent
behavior and evidence for the documented profile. A 1.9 records minor polish or
an explicit residual limitation. A 1.8 records a bounded verification gap. A
material missing behavior scores at most 1.5. Scores express review judgment,
with a written reason for every deduction.

Every category must independently reach 9.6. An unresolved critical
implementation defect, unsafe supported default, misleading success state or
broken ordinary workflow blocks acceptance regardless of the arithmetic.
The evidence must include an ordinary successful path and the documented
rejection/recovery behavior. Tests of a checker establish its behavior, while
the corresponding implementation must also be exercised through its normal entry
point. Test totals alone do not set the score.

Keep measured platform results, model-evaluation results and deployment results
at their recorded scope. Native Windows execution, representative human studies,
live provider behavior, physical storage failure and company enrollment retain
their explicit validation status. The deployment checklist below supports a
future deployment decision.

## Reviewed construction candidate

The [final construction record](validation/project-quality-review-2026-11-05.json)
records a minimum engineering score of **9.7/10**, 919 passing workspace tests
and ten browser states. Every category meets the 9.6 target in this rubric.

The [replacement package record](validation/guarded-input-candidate-6a3697aadbb0293d3f2a79ca48d8a99057cf1d9138428489202a7bfea4a3679c.json)
identifies the five npm tarballs and the static viewer used for construction
review. Use its digest only when enrolling that exact review candidate. The
[alpha.3 release](releases/0.1.0-alpha.3.md) has its own source commit, package
digests and fresh verification; it includes later release-check refinements.
The replacement archive SHA-256 is
`58e9a24b7492058cf2e71e3f76beb97500f8b5e99c8b2d8b0069cb7dc1de17a5`.

The original candidate allowed an isolated guest to read a synthetic file
outside its workspace when a directory changed during capture. A separate
replacement of a regular file after approval could change the bytes sent to
Docker. Withdraw the original candidate from pilots with mutable workspace
inputs. These findings affect R3, R4 and R6.

In the replacement, file capture constrains each path lookup, and the broker
checks the approved version against the exact buffers it sends to the guest.
Installed-package tests covered raw and signed files. Replacing an input after
approval produced zero Docker calls. An unchanged input reached the guest and
returned the approved bytes. macOS enforces the file lookup in the kernel,
and Linux retains directory descriptors while opening each component.
[Apple open(2)](https://github.com/apple/darwin-xnu/blob/main/bsd/man/man2/open.2)
and [Linux open(2)](https://man7.org/linux/man-pages/man2/open.2.html).

The platform, study and admission CLIs now run when launched through a directory
alias. A regression checks that invalid inputs produce a failing exit code and
that the platform checker replaces a stale passing result. The
[preceding runtime verification record](validation/guarded-input-review-2026-11-05.json)
records 917 workspace tests and 44 platform tests on each of macOS and the
local Linux VM, all with zero skips. Three abrupt guest shutdowns on a separate
Linux VM exercised SQLite recovery. A revocation acknowledged to the caller
survived reboot and blocked the protected operation. Native Windows tests and
physical storage failure tests are still outstanding.
The [compiled-package comparison](validation/project-runtime-comparison-2026-11-05.json)
verifies that those runtime files match the final candidate. Its 919-test
construction record and updated browser checks are linked above.

## Earlier evidence

The [original package manifest](validation/protection-96-candidate-2026-11-05.json)
and [original verification record](validation/protection-96-verification-2026-11-05.json)
identify the superseded candidate. Its [public paired evaluation](validation/protection-96-provider-2026-11-05.json)
bound writes to the reviewed operation and checked that attack text reached
the client. Credential-free controls over six private draft policies also
passed. The enrolled model, disclosure approval, billing limits and actual
provider responses remain outstanding. The
[operator study scorer](../scripts/score-operator-study.mjs) checks a
facilitator's observations against separate backend evidence. The operator
packet still has zero completed sessions.

GitHub also retains Cartography CI artifacts named `cartography-pilot-evidence`.
The [inspected run](https://github.com/ShieldaAI/agent-guard/actions/runs/41926803979)
used a disposable database and fixture identities, and its verification report
identifies the profile as `synthetic-live-pilot`. Count these results toward
integration coverage. The company pilot requires the enrolled deployment,
reviewer and backend observations described below.

## Deployment validation checklist

| Category | Additional evidence required on the enrolled target |
| --- | --- |
| R1 · Goal and tool misuse | Inventory every callable tool, raw SDK, shell, credential and egress route available to the agent. Demonstrate a malicious cross-resource request produces no backend read/write, an unmediated route is unavailable, and an authorized task still completes. |
| R2 · Identity and delegation | Authenticate distinct production-equivalent test identities in two tenants. Attempt identity substitution, parent/child scope expansion and reuse after revocation. Verify tenant and task at the backend. Demonstrate one allowed delegation. |
| R3 · Approval | Use the actual host-authenticated review interface. Record the shown target, version, deadline and digest; try stale, denied, swapped and replayed decisions. Exactly one authorized conditional change may commit. |
| R4 · Secrets and egress | Use dedicated test credentials and canaries. Exercise every enabled outbound path, including redirects, private/mixed DNS and an unauthorized recipient; verify at the sink and in results, logs and traces. Confirm the allowed recipient receives only the approved data. |
| R5 · Supply chain | Enroll the real builder/key and image identities. Admit a verified artifact and reviewed peer; swap bytes, signing key, peer generation or descriptor. Confirm the changed candidate is quarantined or rejected until independently approved. |
| R6 · Code execution | On **each advertised host profile**, execute hostile and benign code in the deployed container/VM settings. Inspect guest privilege, mounts and interfaces, test resource limits, terminate the guest, restart the VM and verify cleanup. If the product includes a networked coding client, test the complete client/broker path. |
| R7 · Memory and context | Persist permitted data, retrieve it via delegation, quarantine the source and attempt reuse/egress via each enabled handoff or import. Verify provenance and revocation survive restart and rollback does not make a foreign record accessible. |
| R8 · Recovery and spend | Test actual backend idempotency, provider-side limits, concurrent admission and loss of a write receipt. Check reservation and confirmed effect counts after recovery. Try a pre-revocation restore against the deployed backup system; establish independent custody of the latest state where a [rollback witness](guides/ledger-rollback.md) is used. |
| R9 · Human UX and operations | Run the [representative-operator study](guides/operator-usability-check.md) on the same integration with the enrolled cohort, facilitator, and distinct backend observer. Retain denominators, accessibility findings and unsafe decisions; any wrong approval, unsafe retry or disclosure blocks acceptance. |
| R10 · Field effectiveness and rollout | Pre-enroll both provider trial policies, independent corpus review, budget authorization and per-pair utility/safety criteria. Run the [model-selected trial gate](guides/model-selected-provider-trials.md), reconcile usage, and retain the [company pilot review](guides/pilot-review.md) plus independent security review. Rehearsals and injected transports are ineligible. |

The company pilot verifier intentionally covers a **single read-only path**.
Its receipt cannot approve code execution, arbitrary tools or all rows in this
matrix. Conversely, unit tests of the verifier do not prove that a company pilot
occurred. A platform excluded from a small pilot remains unverified for the
broader product; do not present exclusions as evidence of safety.

**Handoff for the deployment owner:** supply paths to the enrolled manifest,
candidate/build attestation, scoped test endpoint or signed observations, operator
study enrollment and completed receipts, both reviewed provider trial policies
with authorized budgets, and the independent review. Do not put bearer tokens,
private signing keys, API keys or customer data into chat or repository evidence.
