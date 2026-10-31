# Archive capacity and inventory contract verification

Date: 30 October 2026. The repository milestones remain implemented; live company
enrollment is still outstanding. This pass audited archive/collector bounds,
AWS evidence semantics and the TypeScript-to-Python inventory contract. It found
and fixed two classes of reproducible defect. All final verification gates passed.
Assessment: **9/10 on the documented local acceptance checklist**; enrolled
company deployment remains unverified.

## Archive capacity

The archive checked its existing file count before writing a new file, without
reserving the additional entry. At `max_snapshots=1`, five health records could
be accepted even though the file limit was four. Reopening then failed with
`ARCHIVE_LIMIT_EXCEEDED`. A separate predictable-capacity failure could create a
snapshot while leaving insufficient room for its receipt.

New files now reserve committed file slots before creation. Atomic replacements
reuse their slot and still account for temporary write bytes. A new snapshot
preflights the combined snapshot and receipt count/bytes before writing either.
Unexpected interruption still preserves the existing exact-content orphan retry
protocol; capacity preflight is not a replacement for crash recovery.
Archives already beyond their configured quota still require an explicit capacity
increase or operator reconciliation; the fix does not delete existing evidence.

Four regression cases cover rejected overflow with unchanged evidence,
replacement/reopen at capacity, insufficient slots for a snapshot pair, and
one-byte-short versus exact combined-byte capacity. The failure cases were
reproduced before the corresponding fixes. The installed consumer also exercises
overflow rejection, updates at the cap and reopening. Independent review found
no blocker in the fix.

## Shared inventory contract

Python JSON Schema validation accepted an AWS action or S3 account identifier
with a final newline that the TypeScript manifest validator rejected. The region
pattern had the same standalone-schema issue, although Python's semantic ARN
validation already rejected that case. Portable absolute-end checks now enforce
the intended token boundaries in both standalone and embedded definitions.
Independent review caught the same issue in core tool fingerprints; they now
require exactly 64 hexadecimal characters with an absolute end check. Timestamp
patterns also use ASCII digits and absolute ends in all three schemas, so plain
schema validation agrees even without an optional format checker. Public Python
timestamp validation already rejected these malformed timestamps.

A second differential case used a BOM-only identifier: TypeScript treated it as
blank while Python's schema accepted it. The three canonical schemas now use an
explicit whitespace union matching the existing TypeScript validators. Nonblank
identifiers containing newlines remain valid. BOM inside an ARN is rejected by
both schemas and Python's semantic check, matching TypeScript. These changes tighten malformed
input acceptance without changing inventory versions or granting authority.
Previously accepted malformed files are preserved and rejected on replay under
the corrected contract; the TypeScript producer did not emit these inputs.

Twenty-five new regression cases exercise the actual built TypeScript validators, standalone
schemas and Python public validators. Canonical schema copies remain identical
in packaged wheels. The AWS capture/policy/publication audit found no concrete
blocker; its focused offline tests passed 171 cases without contacting AWS.

## Final validation

- Final `npm run check`: **693 JavaScript tests passed**, zero failures/skips,
  plus the installed identity HTTPS consumer, packed declarations/README examples
  and scoped HTTP/MCP/policy contract checks.
- Full Python unit suite after the final fingerprint/timestamp corrections:
  **840 passed** in 15.48 seconds.
- Full disposable Neo4j integration suite against the final code: **124 passed**
  in 180.07 seconds.
- Ruff lint/format: passed for **65 Python files**. Lock validation passed.
- Wheel/source archive builds and rebuilding the wheel from the source archive:
  passed. Isolated installed consumer: passed with exact packaged-schema equality,
  capacity boundaries, lifecycle/replay fences and offline AWS capture checks.
- Operational recovery pilot: **passed in 48.688 seconds**, including three
  scoped reads, four snapshots replayed, equal logical graph content and snapshot
  pointers, unchanged executor authority, and allowed/denied execution with
  inventory services stopped. See the
  [safe pilot result](contract-capacity-recovery-2026-10-30.json).
- Synthetic graph benchmark: **passed** with 100 sources, 10,000 tasks and
  100,000 grants (128,201 nodes / 481,100 relationships). All 100 HTTP requests
  succeeded. Maximum per-source publication was **8.441 seconds** against the
  unchanged 120-second gate; the serial batch took **108.579 seconds**. Query
  p95 was **0.164 seconds** for agent access and **0.237 seconds** for explanations
  against the unchanged 2-second gate. The **1.979-second** cold first request
  remains included. See the [complete result](contract-capacity-benchmark-2026-10-30.json).
  The isolated database used 4 CPUs / 4 GiB; no other task test processes ran
  concurrently. This measures synthetic host inventory, not live AWS or
  representative policy-heavy query load. The admission benchmark was not repeated.
- Disposable test/benchmark/pilot containers and pilot volumes/networks were
  removed. `git diff --check` passed.

## Assessment and remaining gates

Assessment: **9/10**. The existing
[acceptance checklist](source-lifecycle-review-2026-10-30.md#acceptance-assessment)
distinguishes nine local implementation gates from enrolled company deployment.
Its score is not a statistical confidence estimate or production certification.

Approved AWS enrollment, actual company IdP/trusted TLS, representative deployed
workload and independent deployment review remain outstanding. No live AWS or
company IdP was contacted. This pass does not certify native Linux/Windows or
claim a new browser inspection. Earlier validation artifacts retain their stated
scope and are not overwritten.

## Reproduction

From the repository root:

```sh
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30' npm run check
```

Then, from `integrations/cartography`, with the locked environment:

```sh
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
uv lock --check
.venv/bin/python scripts/test-disposable-neo4j.py -- -q
uv build
uv build --wheel dist/agent_guard_cartography-0.1.0a1.tar.gz --out-dir dist/from-sdist
uv run --isolated --no-project --python .venv/bin/python --with ./dist/from-sdist/agent_guard_cartography-0.1.0a1-py3-none-any.whl python scripts/check-installed.py
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-contract-capacity-pilot.json
.venv/bin/python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /tmp/agent-guard-contract-capacity-benchmark.json
```

Use new output paths. Complete JavaScript builds before Python integration and
pilot runs, which invoke the built Node packages. Disposable runners own their
databases and cleanup. Run the benchmark after other test processes finish;
its isolated Neo4j instance reserves 4 CPUs and 4 GiB. Verification used macOS
arm64, Node 26.12.0, Python 3.13.10, locked Cartography 0.144.0 and the pinned
Neo4j Community 5.26.32 image.
