# Source-generation lifecycle implementation review

Date: 30 October 2026. Scope: explicit source-generation replacement in the
[Cartography integration plan](../../../docs/cartography-integration-plan.md#source-generation-lifecycle-milestone).
This audit found an overlooked requirement in the earlier completion claims:
publishing a restored or cloned executor under a new generation left the old
source visible and protected indefinitely. The new lifecycle command closes
that gap. All local verification gates below passed. The assessment is **9/10
on the explicit acceptance checklist**; enrolled company deployment remains
unverified.

The subsequent [receipt-replay audit](replay-fence-review-2026-10-30.md) found and
fixed a missed normal publication path around the archive fence. It supersedes
the corresponding completeness claim here and records updated regression
results; this report's other results remain historical evidence.

## Implementation

The host supplies exact predecessor and successor identities with the same
company, native source, tenant and profile, and a different enrollment generation.
The command requires complete published graph endpoints and matching confirmed
archive evidence before staging a private durable intent. Under the shared
ingestion lock, an atomic graph transaction records supersession and clears old
active pointers. It preserves audit pointers and an idempotent receipt. The
archive then completes its journal. Unknown outcomes require the same command
to be retried; pending journals block conflicting transitions and unsafe backup.

Old generations cannot import even a previously published snapshot, nor finish
an in-flight publication. Reference queries exclude retired sources and reject
reads whose captured source set changes before final validation. Collector
maintenance applies a grace period and
bounded cleanup even when predecessors have left the enrollment queue. It
preserves source tombstones, receipts, provider inventory and other scopes.

Backup includes connected completed transitions and their recovery anchors.
Fresh-graph reconstruction replays snapshots and then ordered transitions with
their original times. An interrupted replay leaves a durable marker that blocks
normal archive reuse. Chains and converging predecessors are supported without
reactivating old sources. Neither lifecycle nor reconstruction changes executor
authority. See the [operator guide](../SOURCE-LIFECYCLE.md) and
[transition example](../../../integrations/cartography/examples/source-transition.json).

## Verification

- `npm run check`: **693 JavaScript tests passed, zero failures or skips**,
  plus the installed identity HTTPS consumer. Packed declarations, README
  examples, HTTP/MCP and policy contract checks passed.
- Python unit suite: **799 passed**.
- Disposable Neo4j integration suite: **118 passed** in 173.57 seconds.
- Ruff lint and formatting passed for **63 Python files**; lock validation passed.
- Wheel/source archive builds, rebuilding the wheel from the source archive,
  and isolated installed consumer passed, including the lifecycle entry point,
  journal roundtrip and retired-source archive fence.
- Operational observer/collector/reference and recovery pilot: **passed** in
  **48.737 seconds**, with three scope checks, four confirmed snapshots replayed,
  matching logical content and snapshot pointers, unchanged executor authority,
  and allowed/denied execution with inventory services stopped. The
  [safe result artifact](lifecycle-recovery-2026-10-30.json) records this regression
  pilot; lifecycle-chain reconstruction is covered separately by the Neo4j case.
- Separate code review covered transition preflight, publication fences,
  archive/recovery ordering, maintenance orchestration and reader behavior.
  No remaining concrete blocker was identified before the final suites. The
  operator guide was also corrected to require stopping the watch collector
  before acquiring its shared lock and restarting with successor enrollment.
- Disposable test/pilot databases and pilot volumes/networks were removed;
  `git diff --check` passed.

The first full Neo4j run passed 117 cases and rejected an inconsistent new
cross-tenant fixture: its source tenant changed but embedded task tenants did
not. The fixture now updates both. Production validation was not weakened;
the final rerun passed all intended retention and isolation assertions.

The lifecycle integration cases use actual Neo4j transactions for missing/failed
successors, conflicting/repeated transitions, staging/publication races, reader
visibility and retention. A separate recovery case owns a fresh disposable
database and verifies a four-source chain with converging predecessors through
backup, restore and reconstruction. It checks original tombstone times,
old-source replay fences, active visibility and provider-node preservation.

## Acceptance assessment

Assessment: **9/10**. Each row below is one acceptance point. This is a local
implementation checklist, not a measured
security probability or independent deployment certification.

| Gate | Evidence | Result |
| --- | --- | --- |
| Exact transition scope | Closed bounded input; exact source/profile metadata; new generation required. | Verified locally |
| Safe preflight | Published complete graph endpoints and matching confirmed archived projections required before intent. | Verified locally |
| Atomic replacement | Ordered source locks, cleared active pointers, retained tombstone and original idempotent receipt. | Verified locally |
| Old-generation fences | Known/new snapshot rejection and publication-time recheck; normal archive writes blocked. | Verified locally |
| Scoped reader behavior | Active-source filtering and whole-read failure across supersession, including team/all-team readers. | Verified locally |
| Interrupted-operation safety | Pending intents, exact retry, topology conflict checks and interrupted-replay marker. | Verified locally |
| Bounded retention | Completed journal/graph provenance, grace period and per-cycle cap; shared nodes and other scopes preserved. | Verified locally |
| Durable reconstruction | Connected lifecycle evidence, ordered replay, original timestamps and rebuilt archive fences. | Verified locally |
| Delivery and regressions | Full JavaScript/Python suites, installed packages, operator documentation and operational recovery pilot. | Verified locally |
| Enrolled company rollout | Approved AWS identity, real company IdP/trusted TLS, representative workload and independent deployment review. | Not performed |

## Reproduction and limits

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
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-lifecycle-recovery.json
```

Use a new pilot output filename. Complete npm builds before Python integration
and pilot runs, which invoke the built Node packages. The disposable runner owns
and removes its database. Tests used macOS arm64, Node 26.12.0, Python 3.13.10,
locked Cartography 0.144.0 and pinned Neo4j Community 5.26.32.

No live AWS or company IdP was contacted. This pass did not rerun browser visual
checks, native Linux/Windows certification or performance benchmarks. Existing
benchmark reports retain their original scope. Lifecycle is an explicit operator
action under the single-worker lock; it provides neither automatic discovery nor
distributed fencing. Recovery anchors and journals consume bounded archive
capacity and are not discarded automatically to admit additional generations.
