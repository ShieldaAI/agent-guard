# Agent Guard engineering assessment

**The defensive-project target is met at a minimum of 9.7/10 across all ten
categories.** This is a structured engineering judgment under the
[construction rubric](protection-acceptance.md). It covers requirements,
design/defaults, implementation, functional regression evidence and operator/API
clarity for the documented single-owner and guard-mediated profiles.

This scope follows the request to build and review a defensive security project
without a penetration test. Earlier assessment notes treated a company pilot
and representative field results as completion gates. Those activities remain
in the [deployment checklist](protection-acceptance.md#deployment-validation-checklist),
with their evidence status preserved. These scores express review judgment
about construction quality.

The scores and runtime comparisons below are bound to the recorded construction
snapshot, before the alpha.3 version bump and release-check refinements. The
[alpha.3 release notes](../releases/0.1.0-alpha.3.md) link the exact published commit,
its subsequent fixes and fresh release verification. Historical package equality
is not a claim that the release archive has the same bytes.

## Category scores

Each dimension has a maximum of two points. A full score means the specified
behavior is implemented coherently and verified within its stated profile.
Every deduction is described below. An unresolved critical defect or broken
ordinary workflow blocks acceptance regardless of the total.

| Category | Requirements | Design/defaults | Implementation | Verification | API/UX clarity | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| R1 · Goal and tool misuse | 2 | 2 | 2 | 2 | 2 | **10.0** |
| R2 · Identity and delegation | 2 | 2 | 2 | 2 | 2 | **10.0** |
| R3 · Exact approval | 2 | 2 | 2 | 1.8 | 2 | **9.8** |
| R4 · Data, secrets and egress | 2 | 2 | 2 | 2 | 2 | **10.0** |
| R5 · Tool and artifact supply chain | 2 | 2 | 2 | 2 | 2 | **10.0** |
| R6 · Isolated code execution | 2 | 2 | 2 | 1.8 | 2 | **9.8** |
| R7 · Governed memory and context | 2 | 2 | 2 | 1.8 | 2 | **9.8** |
| R8 · Budgets and recovery | 2 | 2 | 2 | 2 | 2 | **10.0** |
| R9 · Operational evidence and UX | 2 | 2 | 2 | 1.8 | 1.9 | **9.7** |
| R10 · Evaluation and rollout controls | 2 | 2 | 2 | 2 | 1.9 | **9.9** |

R3, R6 and R7 retain a 0.2 verification deduction for the native Windows
file-capture and artifact-import paths. Windows implementation and compilation
exist, with a required native test procedure. Runtime behavior has been verified
on macOS arm64 and a Linux arm64 process inside Colima. The core, ticket approval
and ledger-memory operations have direct regression coverage.

R9 retains a 0.2 deduction because browser verification samples Chromium and
keyboard interactions, and 0.1 because dense graph labels require the
accessible node selector and evidence panel for some details. R10 retains a 0.1
deduction because advanced enrollment requires several guides and manual assembly
of policy, signatures and evidence files.

## Evidence and normal workflows

The [requirements and protection design](protection-design.md) map all ten
categories to their boundaries and acceptance behavior. The
[final verification record](../validation/project-quality-review-2026-11-05.json)
binds the scores to source and package identities, test counts and reviewed
screenshots. Three focused engineering reviews and a final reconciliation
covered the implementation and its normal entry points.

| Category | Checked behavior and evidence |
| --- | --- |
| R1 | Registered tools execute within trusted grants and resource resolution. Unknown requests have no effect, and useful tasks succeed. [Core](../../packages/core/test/security.test.mjs), [provider workflow](../../scripts/provider-ticket.test.mjs). |
| R2 | Child scope narrows parent authority, tenant identity comes from the host, and revocation follows ancestry. [Core identity and delegation](../../packages/core/test/security.test.mjs), [durable API](../../packages/executor/test/executor.test.mjs). |
| R3 | Tenant, arguments, version, expiry and staged bytes bind one approval. Enter denies, and explicit confirmation returns a backend-confirmed change. [Review workflow](../../examples/providers/review-ticket.mjs), [staged-file regression](../../packages/executor/test/sandbox-staged-input-version.test.mjs). |
| R4 | Sensitivity persists across reuse, output is minimized, and host-held credentials and restricted network paths enforce recipients. [Credentials](../../packages/mcp/test/credentials.test.mjs), [network](../../packages/executor/test/network.test.mjs), [artifacts](../../packages/executor/test/artifacts.test.mjs). |
| R5 | Metadata generations, image digests, artifact bytes, enrolled builders and source policies are checked. Reviewed replacements succeed. [MCP lifecycle](../../packages/mcp/test/managed.test.mjs), [build imports](../../packages/executor/test/build-artifact-import.test.mjs). |
| R6 | Real guest commands use selected bounded files and the documented privilege, network and resource restrictions. [Runtime](../../packages/executor/test/sandbox.test.mjs), [file capture](../../packages/executor/test/workspace-input.test.mjs), [isolated MCP](../../scripts/mcp-isolation.test.mjs). |
| R7 | Tenant-local IDs, permitted child reads, sensitivity, rollback and transitive quarantine survive reopening. [Memory regressions](../../packages/executor/test/memory.test.mjs), [exact API](../api-contract.md#governed-memory). |
| R8 | Admission reserves capacity before effects; unresolved work retains accounting; committed revocation survives reboot. [Capacity](../../packages/executor/test/capacity.test.mjs), [recovery](../../packages/executor/test/recovery.test.mjs), [witness](../guides/ledger-rollback.md). |
| R9 | Filter failures hide stale matches, refresh recovers, authentication loss clears inventory, mobile views remain accessible, and policy evidence appears once. [Browser workflow](../../apps/agent-map/check-browser.mjs), [auth](../../apps/agent-map/test/auth.test.mjs), [traces](../../packages/executor/test/traces.test.mjs). |
| R10 | Evaluation accounts for safe completion, effects, control runs, planned rows and usage, and binds rollout evidence to its inputs. [Evaluation](../../scripts/provider-evaluation.test.mjs), [trial checker](../../scripts/provider-trials.test.mjs), [pilot verifier](../../packages/executor/test/pilot-review.test.mjs). |

The final workspace check passed **919 tests with zero skips**, plus the clean
installed-package consumers. Browser verification covered ten states and four
mobile views with zero axe violations and zero page errors. The
[desktop explanation](../validation/project-ux-desktop-2026-11-05.png) and
[mobile recovery screen](../validation/project-ux-recovery-2026-11-05.png) were visually
reviewed.

The preceding matching backend runtime passed 44/44 platform checks each on
macOS and Linux, three exact-package Linux VM shutdown/recovery cases, 72 public
offline provider cases and 120 private draft control cases. Cartography's
recorded 916 unit tests and 143 Neo4j tests cover its unchanged integration.
The final package comparison verifies that all 104 compiled package files,
including 52 JavaScript files, match that runtime. The viewer changes received
fresh browser verification.

## Fixes delivered in this review

- Stale ledger restoration fails closed with the independently retained rollback
  witness enabled.
- Workspace capture prevents a directory replacement from selecting an outside
  file, and approval checks the buffers actually staged for execution.
- Provider evaluation binds a write to the reviewed operation and checks that
  the client received the relevant input before crediting a completed trial.
- Validation CLIs execute through directory aliases and replace stale evidence
  when an invocation fails.
- The viewer clears stale filtered results, offers an accurate recovery action,
  keeps mobile navigation visible and renders policy evidence once.
- The memory API documents operator authority, arguments, results, errors and
  recovery. Additional tests cover tenant isolation and reopening.

## Earlier implementation findings

| Failure reproduced | Correction and observed behavior |
| --- | --- |
| An expired destructive approval regained authority when wall time moved backwards. The example reviewer could also return an expiry later than the one shown, and synchronous work could outlast the workflow timer. | Core rejects a backward clock; the ticket host fixes the review window on first display; elapsed-time checks precede workflow dispatch. SQLite dispatch also rechecks the task and approval after its admission commit. Late reviews produced zero writes. |
| An ungranted tool reached trusted parsing/resolution callbacks; a parser could accidentally mutate the registration through its receiver. Proxy traps could run during plain-JSON validation. | Check coarse tool/control-plane scope before callbacks; detach parsers from internal state; reject proxies before traversing them. The authorized path still works. |
| A stalled policy started 128 callbacks for 128 proposals in one family despite a one-call task budget. None of the callers settled on revocation. | With the fix, eight callbacks started, all 128 callers settled, and no handler ran. Both executors bound the policy pool by family and globally. Timeouts do not recycle a slot if a callback is still outstanding. |
| A credential revoked while a task HTTP request body streamed could still read protected state. A malicious MCP peer could return the host's bearer in metadata or a result. | Reauthenticate at the request boundary after input completes. The verified MCP session closes before decoded strings/keys containing the enrolled raw token can reach SDK consumers. Pin model provider and output projection; bound expanded MCP schemas before code generation. |
| A tool could commit a ticket write, lose its response, and leave the provider loop running. A subsequent provider failure could also hide a confirmed write. | Stop on unconfirmed submission, preserve its host action ID and earlier confirmed actions, and consult the backend receipt. A genuine pre-dispatch budget refusal stays distinguishable. Two provider adapters now test exactly one write and no subsequent provider request after a lost response. |
| A dismissed terminal review could accept a buffered confirmation without Enter. Provider schemas exposed a foreign record ID; a probe distinguished it from a missing record. | Require a live terminal and an explicitly submitted line. Schema exposes a bounded ID format; resolution is scoped to the trusted tenant. Foreign/missing probes now have the same public result and no protected read. |
| A rejected bearer session left old inventory on screen, the demo could invent matches for unsupported queries, and evidence labels failed contrast checks. | Clear protected data and outstanding queries on rejected auth, label unsupported/unknown results, invalidate stale results on edits, and improve contrast. The built application was exercised in Chromium, including a real scoped API session and forced 401. |

See the [local verification record](../validation/protection-review-2026-11-05.json)
for exact test totals, runtime profiles and evaluation outcomes. Test populations
overlap; do not add the focused and full suites together. Guide: [run the examples
and packed consumers](../../README.md#run-locally), [run the platform gate](../guides/mcp-isolation-acceptance.md),
[run the disposable Neo4j checks](../../integrations/cartography/README.md),
[evaluate both provider protocols](../guides/provider-outcome-evaluation.md), and
[reproduce the browser checks](../../apps/agent-map/README.md).

## Deployment-specific validation

Native Windows runtime execution, representative operator studies, live provider
trials, company identity and builder enrollment, and physical storage/backup
validation remain open for their respective deployments. Existing templates,
verifiers and procedures are available.

The host must authenticate reviewers, mediate every protected effect, restrict
credentials, resolve resources within the tenant and enforce backend versions
and cost ceilings. Host compromise, independent ledgers and unmediated execution
paths remain outside the documented enforcement boundary. Review the
[deployment checklist](protection-acceptance.md#deployment-validation-checklist)
when choosing an actual deployment.
