# Local pilot validation evidence

These reports were produced on 30–31 October 2026 with synthetic fixtures. They
record local implementation checks, not a hosted CI run, native platform
certification, live AWS validation or an organization deployment.

- [publication-report-review-2026-10-31.md](publication-report-review-2026-10-31.md):
  graph publication rejects duplicate relationships concealing missing edges;
  private report reads reject FIFO replacement and descriptor safety changes.
  Five regression cases, full suite/package verification and independent review.
  The [recovery result](publication-report-recovery-2026-10-31.json) records
  restored content, scoped reads and preserved executor authority. The refreshed
  [100-source benchmark](publication-report-benchmark-2026-10-31.json) passed
  every unchanged gate, including the cold first query in the measurements.
- [launcher-policy-review-2026-10-30.md](launcher-policy-review-2026-10-30.md):
  bounded bearer-launcher inputs and reduced policy-query planning cost with
  unchanged authorization checks/deadlines; 15 added regression/control cases,
  deterministic refresh-clock checks and final package/suite verification.
  Initial failures are retained with the measured diagnosis. The
  [planner comparison](launcher-policy-planner-2026-10-30.json) and
  [recovery result](launcher-policy-recovery-2026-10-30.json) record minimized
  timing and scoped reconstruction evidence. The refreshed
  [100-source benchmark](launcher-policy-benchmark-2026-10-30.json) passed all
  unchanged gates and retains its cold first query.
- [auth-input-review-2026-10-30.md](auth-input-review-2026-10-30.md):
  company-session clearing on malformed or stalled authentication-denial responses,
  nonblocking regular-file inputs and lifecycle identifier parity; 32 added
  regression cases, full suite/package verification and independent reviews.
  The [recovery result](auth-input-recovery-2026-10-30.json) verifies scoped reads,
  four-snapshot replay, restored content and preserved executor authority.
- [freshness-policy-review-2026-10-30.md](freshness-policy-review-2026-10-30.md):
  original observation freshness, S3 policy resource-case and enrollment parity
  corrections; 49 added regression cases, full suite/package verification and
  independent reviews. The [recovery result](freshness-policy-recovery-2026-10-30.json)
  and [100-source benchmark](freshness-policy-benchmark-2026-10-30.json) passed
  against the corrected implementation, using unchanged performance thresholds.
- [integration-review-2026-10-30.md](integration-review-2026-10-30.md):
  cloud account enrollment and disposable readiness deadline corrections, eight
  regressions, independent query/identity/recovery audits, final suite results
  and package verification. Records the initial database startup failure as well
  as the successful rerun. The
  [recovery result](integration-review-recovery-2026-10-30.json) records the
  fresh collection, scoped reads, backup/replay and executor outage checks.
- [contract-capacity-review-2026-10-30.md](contract-capacity-review-2026-10-30.md):
  archive quota and Python/TypeScript contract corrections, regression and
  installed-package verification, recovery and refreshed synthetic load evidence.
  The [recovery result](contract-capacity-recovery-2026-10-30.json) and
  [100-source benchmark](contract-capacity-benchmark-2026-10-30.json) passed against
  the final code; the benchmark uses the original thresholds and includes cold reads.
- [replay-fence-review-2026-10-30.md](replay-fence-review-2026-10-30.md):
  receipt-replay fence correction, preservation of incomplete recovery evidence,
  actual CLI and concurrent source-retirement regressions, installed-package
  checks and updated local acceptance results. The
  [operational result](replay-fence-recovery-2026-10-30.json) records the fresh
  collection/query/backup/replay and inventory-outage pilot.
- [source-lifecycle-review-2026-10-30.md](source-lifecycle-review-2026-10-30.md):
  audit correction and implementation of the missed source-generation replacement
  requirement, durable lifecycle/recovery behavior, final regression results and
  explicit 9/10 local acceptance checklist. The
  [operational pilot result](lifecycle-recovery-2026-10-30.json) verifies collection,
  scoped queries, backup/replay and executor operation during inventory outage.
- [verification-followup-2026-10-30.md](verification-followup-2026-10-30.md):
  subsequent audit, custom-store validation fix, deterministic OIDC deadline
  regression, real-Neo4j concurrent-change tests and fresh suite results.
  [recovery-followup-2026-10-30.json](recovery-followup-2026-10-30.json) records
  the follow-up scoped collection, backup/replay and executor outage checks.
- [policy-reference-review-2026-10-30.md](policy-reference-review-2026-10-30.md):
  scoped policy API/viewer acceptance rubric, regression and installed-package
  verification, reproduction commands and remaining company rollout checks.
  The [browser screenshot](policy-reference-viewer-2026-10-30.jpg) shows the built
  viewer's synthetic conditional-candidate example.
- [benchmark-2026-10-30.json](benchmark-2026-10-30.json): passed the 100-source, 10,000-task, 100,000-grant
  graph publication and bounded HTTP query acceptance gates. Includes cold reads.
- [recovery-2026-10-30.json](recovery-2026-10-30.json): passed actual observer/collector/reference scope
  checks, private backup and fresh-graph replay, with executor authority preserved
  and expected admission/denial behavior while inventory services were stopped.
- [admission-2026-10-30.json](admission-2026-10-30.json): current independent-client
  measurement after bounded snapshot-local reference caching. The unchanged 10%
  admission latency gate passed at **+3.42%**, with correctness and cleanup passing.
  Preparation alone rose 25.85%; all stage timings are retained.
- [admission-before-reference-cache-2026-10-30.json](admission-before-reference-cache-2026-10-30.json):
  preserved independent-client measurement before that implementation change.
  The provisional 10% admission latency gate failed at **+15.63%**, with correctness
  and cleanup passing. The subsequent run used the same 250 ms polling cadence,
  workload, measurement method, phase order and threshold.
- [admission-initial-superseded-2026-10-30.json](admission-initial-superseded-2026-10-30.json): preserved preliminary measurement,
  **excluded from acceptance evidence**. The workload client shared the server
  event loop, so its original passing ratio could omit polling delay before
  request initiation. The raw report is retained to document this methodological
  correction; its `passed` field describes only the superseded implementation.

Reproduction commands, workloads, timing definitions and limitations are in the
[runbook](../RUNBOOK.md). Reports contain timing/count/identity metadata only;
credentials, raw inventory, authority ledgers and archive bundles are excluded.
