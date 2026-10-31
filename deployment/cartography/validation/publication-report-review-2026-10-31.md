# Publication integrity and private report validation

Date: 31 October 2026. All repository milestones in the Cartography integration
plan are implemented. This pass tested that implementation and corrected two
reproduced validation defects: aggregate graph counts could conceal missing
relationships, and a private report reader could block on a replaced file.
Final correctness, delivery, recovery and capacity checks passed. The assessment
is **9/10 on the documented local acceptance checklist**.

## Graph publication correction

Publication previously compared total relationship counts with the expected
counts. Removing one expected relationship and duplicating another left those
totals unchanged. Real Neo4j fault injection reproduced acceptance of both an
incomplete `G_ACTS_AS` projection and an incomplete `G_IN_SNAPSHOT` membership
set: both new rejection tests failed against the old implementation.

The [publisher](../../../integrations/cartography/src/agent_guard_cartography/graph.py)
now checks distinct snapshot members as well as membership totals. For each
relationship type it counts distinct expected endpoint pairs and retains the
total-edge check. Every expected pair must exist, and the total must equal the
number of unique pairs; together these require exactly one edge per pair.
The correction adds no database round trips and leaves publication deadlines,
source locking, lifecycle fences and compare-and-set behavior unchanged.

The [two regression cases](../../../integrations/cartography/tests/integration/test_snapshots.py)
each assert exactly one removed and one duplicated relationship. Rejection must
preserve the previous publication pointer and mark the attempted projection
failed. These cases and three existing publication/cleanup controls passed
against a new disposable Neo4j database: **5 passed in 11.22 seconds**.
The final two cases were strengthened to compare the full original source
state except its staging lock counter, the original visible tasks, and another
tenant's full source state and visible tasks. Both passed on another disposable
database in **10.70 seconds**, after the full suite below. Test counts overlap.
This protects staging validation; it does not make a database writable by an
untrusted administrator tamper-proof.

## Private report correction

The [report reader](../../../integrations/cartography/src/agent_guard_cartography/reference_report.py)
checked path metadata before a blocking file open. Replacing that file with a
named pipe after the check blocked before the subsequent inode comparison;
the pre-fix reproduction timed out after two seconds. Changing the same inode's
permissions or hardlink count after the path check was also accepted.

Reads now use `O_NONBLOCK` and revalidate regular-file type, owner, private
permissions, allowed link count and size on the opened descriptor. The existing
device/inode comparison, bounded read and unconditional close remain in place.
Interrupted report publication still supports its explicitly allowed two-link
recovery state. There is no blocking fallback on unsupported hosts.

Three [regression cases](../../../integrations/cartography/tests/unit/test_reference_report.py)
cover FIFO replacement in a deadline-bounded subprocess, same-inode permission
changes and hardlink changes. The latter two also verify descriptor cleanup.
The combined archive/lifecycle/recovery/report suite passed **151 tests in
8.91 seconds**, including all **46 report tests**. Separate review of the
correction reran the report suite successfully and found no additional blocker.
These focused counts overlap the full suite.

## Independent boundary review

The HTTP/identity/reference/viewer review passed **168 focused tests**, with no
failures or skips. It covered trusted company/tenant/team scope, session
revocation, ambiguous headers, bounded strict JSON parsing, scoped graph reads
and pointer rechecks, and immediate viewer invalidation on authentication loss.
No additional defect was reproduced. Archive quota/ownership/recovery fences
and publication/lifecycle/cloud-join boundaries were also inspected. Internal
agent reviews do not replace independent deployment review.

## Verification

- `npm run check`: **707 JavaScript tests passed**, zero failures/skips, plus
  the installed identity HTTPS consumer, packed declarations and README
  examples, executor/HTTP/MCP/policy consumers and viewer build. JavaScript
  sources were unchanged by the subsequent Python corrections.
- Final Python unit suite: **916 passed in 17.62 seconds**.
- Full disposable Neo4j suite: **143 passed in 208.84 seconds**. The final
  strengthened isolation assertions also passed in the focused run above.
- Ruff lint/format: **68 files passed**; locked dependency validation passed.
- Wheel/source-archive builds, rebuilding the wheel from the final source archive
  and the isolated installed Python consumer passed. The consumer checks schemas,
  collector/archive/recovery/report/lifecycle APIs and offline AWS policy capture.
- **Five new regression cases**: three report-reader cases and two real-Neo4j
  balanced missing/duplicate relationship cases.
- The [operational recovery pilot](publication-report-recovery-2026-10-31.json)
  passed in **44.284 seconds**: four snapshots replayed, all three reader scopes
  checked, restored graph content and snapshot pointers matched, and executor
  authority and operation survived collection and inventory rollback.
- The [refreshed acceptance benchmark](publication-report-benchmark-2026-10-31.json)
  passed every unchanged gate: **100 sources, 10,000 tasks, 100,000 grants**,
  **128,201 nodes / 481,100 relationships**, and **100 successful requests**.
  Agent-access/explanation p95 was **0.171 / 0.262 seconds**; maximum per-source
  publication was **7.315 seconds**, with a **100.625-second** serial batch.
  The first cold request took **2.118 seconds** and remains in the measurements.
  The thresholds remain two seconds for query p95 and 120 seconds per source
  for publication. This synthetic host-inventory workload does not establish
  large-company IAM-policy capacity or production latency.
- All owned disposable-test/pilot containers and pilot volumes/networks were
  removed. `git diff --check` and local documentation link checks passed.

## Assessment and remaining gates

Assessment: **9/10 on the existing local acceptance checklist**, preserving the
[nine local gates and enrolled-deployment gate](source-lifecycle-review-2026-10-30.md#acceptance-assessment).
This is an implementation checklist, not a security probability or production
certification. Approved AWS enrollment, company IdP/trusted TLS, representative
deployed workloads and independent rollout review remain outstanding.

Provider-neutral OIDC remains the selected sign-in integration. No live company
AWS or IdP was contacted. Browser appearance and native Linux/Windows host
certification were not revalidated. Executor admission latency was not remeasured;
its code path is unchanged. Verification used macOS arm64, Node 26.12.0, Python
3.13.10, locked Cartography 0.144.0 and pinned Neo4j Community 5.26.32.

## Reproduction and scope

From the repository root:

```sh
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30' npm run check
```

Then from `integrations/cartography`, using the locked environment:

```sh
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
uv lock --check
.venv/bin/python scripts/test-disposable-neo4j.py -- -q
uv build
uv build --wheel dist/agent_guard_cartography-0.1.0a1.tar.gz --out-dir dist/from-sdist
uv run --isolated --no-project --python .venv/bin/python --with ./dist/from-sdist/agent_guard_cartography-0.1.0a1-py3-none-any.whl python scripts/check-installed.py
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-integrity-review-recovery.json
.venv/bin/python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /tmp/agent-guard-integrity-review-benchmark.json
```

Use new output paths. Finish JavaScript builds before running Python suites
that invoke built Node packages. Run the benchmark without competing test jobs.
The database runners create and clean up only their own disposable resources.
