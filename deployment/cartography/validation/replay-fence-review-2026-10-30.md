# Cartography receipt replay verification

Date: 30 October 2026. The plan audit found no further repository milestone.
This pass audited the implemented lifecycle, collector and reference boundaries
and found a concrete defect in normal receipt replay. The fix and all local
verification gates passed. Assessment: **9/10 on the documented local acceptance
checklist**, with enrolled company deployment still unverified.

## Defect and fix

`publish_receipt()` loaded an existing archive receipt and called graph import
without the archive checks applied by `store()`. With a pending predecessor
transition or interrupted-recovery marker, ordinary replay could still publish
to the graph even though new snapshot storage was fenced. Both cases were
reproduced before the fix. The graph's completed-supersession fence remained
effective; the missed cases occur before that graph decision or during partial
reconstruction.

The archive now exposes shared recovery/source publication preflight. Collection
and receipt replay run it before observer requests, graph mutations or failure
bookkeeping. Expected rejection leaves confirmed archive receipts unchanged.
Collector startup checks recovery state before optional AWS collection, pruning
and source retirement; direct archive pruning also refuses incomplete recovery.
The CLI may still verify database connectivity before opening the archive.

An active successor may continue collecting or replaying receipts while its
predecessor transition is pending. Controlled reconstruction retains its private
write allowance, imports snapshots before lifecycle records, and clears the
durable marker only on completion. There is no new schema or credential change.
The [operator guide](../SOURCE-LIFECYCLE.md) documents these distinctions.

## Regression evidence

- Twelve new unit cases cover collection/replay against recovery, pending and
  completed lifecycle fences, byte-preserved evidence, allowed successor replay,
  collector startup with optional AWS work, and pruning refusal.
- Four actual CLI cases target pending and confirmed receipts under both recovery
  and pending-transition fences. They assert rejection, unchanged source and
  snapshot graph properties, and identical archive file contents.
- Two deterministic real-Neo4j races cover team-scoped and all-team readers.
  A separate session commits the supersession graph state after initial source
  selection. Both retained projections are read before the final source check;
  the only accepted outcome is the actual `MAP_UNAVAILABLE` error, without a
  partial response. No sleeps or production test hooks are used. Existing tests
  separately exercise the production supersession transaction.
- The installed Python consumer now verifies both receipt-replay fences.
- Independent read-only reviews found no additional milestone or blocking issue
  in the final fix. Cross-profile retirement remains an explicit unsupported
  operation, rather than an unimplemented promise of the current lifecycle API.

## Final validation

- `npm run check`: **693 JavaScript tests passed**, zero failures or skips,
  plus the installed identity HTTPS consumer. Packed declarations, README
  examples, HTTP/MCP and policy contract checks passed.
- Full Python unit suite after the fix: **811 passed** in 12.99 seconds.
- Full disposable Neo4j integration suite: **124 passed** in 175.10 seconds,
  including all four CLI fence cases and both concurrent-retirement cases.
- Ruff lint/format: passed for **64 Python files**. Locked dependencies validated.
- Wheel and source archive builds, and wheel rebuilt from the source archive:
  passed. Isolated installed consumer: passed, including both replay fences.
- Operational collection/query/recovery pilot: **passed in 46.311 seconds**,
  including three scope checks, four confirmed snapshots replayed, equal logical
  graph content and snapshot pointers, unchanged authority, and allowed/denied
  execution with inventory services stopped. See the
  [safe result artifact](replay-fence-recovery-2026-10-30.json).
- Disposable test/pilot containers and pilot volumes/networks were removed.
  `git diff --check` passed.

## Assessment and remaining work

Assessment: **9/10**. The
[source-lifecycle acceptance rubric](source-lifecycle-review-2026-10-30.md#acceptance-assessment)
defines nine repository gates and one enrolled company rollout gate. This is a
local implementation checklist, not a numerical security guarantee. This report
supersedes earlier claims that every normal archive publication path already
enforced the lifecycle/recovery fence.

The remaining deployment work still requires the approved live AWS identity,
actual company IdP and trusted TLS configuration, representative workload and
independent deployment review. No live AWS or company IdP was contacted. No new
browser inspection, native platform certification or performance measurement is
claimed; prior benchmark artifacts retain their original scope.

## Reproduction

Run from the repository root:

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
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-replay-fence-pilot.json
```

Use a new pilot output path. Complete npm builds before Python integration/pilot
runs, which invoke built Node packages. Tests use macOS arm64, Node 26.12.0,
Python 3.13.10, locked Cartography 0.144.0 and the pinned Neo4j Community 5.26.32
image. Disposable runners own their databases and cleanup.
