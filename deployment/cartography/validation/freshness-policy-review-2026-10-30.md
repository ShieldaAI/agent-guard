# Freshness and policy matching verification

Date: 30 October 2026. The Cartography implementation plan has no remaining
repository milestone. This pass audited the implemented boundaries and corrected
three defects in reference freshness, policy resource matching and enrollment
validation. The functional suites and operational recovery pilot passed.
The graph acceptance benchmark also passed its unchanged thresholds.

## Original observation freshness

Host/MCP composition preserves original component observation times while
advancing the snapshot's generation time. The reference reader instead used the
new generation time for tasks/tools and the new capture time for MCP. A reproduced
October 1 observation recomposed on October 30 was reported as zero seconds old
and fresh, although its original timestamps remained available in the graph.

The reader now obtains bounded, validated task/tool capture timestamps from each
exact snapshot, independently for current and historical projections. Absent
legacy metadata retains known completeness with unknown/stale age; malformed or
oversized present metadata rejects the read. Current capture metadata is included
in the final source-consistency check.

MCP freshness uses the oldest capture or observation among authorized visible
connections; unavailable connections have only a failure capture time. A missing,
malformed or excessively future required timestamp makes that
component's age unknown instead of inheriting a fresh sibling's timestamp.
Hidden connections cannot affect the visible result. Normal managed MCP exports
timestamp each observation; unchanged connection metadata does not itself make
an observation stale. Snapshot generation freshness remains separate.

Six new Node regressions failed against the previous build. Five additional
Neo4j cases verify stale observations after recomposition, hidden-connection
isolation, separate current/history timestamps, and missing/malformed/oversized
stored metadata. All pass with the correction. Executor authority and inventory
schemas are unchanged.

## Policy resource case

The pinned Cartography S3 matcher retries a resource match against the bucket
portion using a case-insensitive regex. This could map an uppercase bucket or
ARN component to a lowercase bucket, inventing an Allow candidate or suppressing
a valid candidate through a mismatched Deny resource. The local reducer already
compiled resources case-sensitively, but the fallback discarded that setting.

The adapter now protects the pre-slash resource regex with a scoped
case-sensitive group that survives the upstream split/recompilation. Direct
clauses and wildcard/escaped-literal behavior remain supported, and actions stay
case-insensitive. The pinned dependency and mapping/schema versions are unchanged;
all results remain unknown-assessment bucket summaries. AWS documents lowercase
ARN service names in its [policy validation checks](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html)
and lowercase S3 bucket names in its [bucket naming rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html).

Eighteen new unit cases cover Allow/Deny, direct and object-level resources,
uppercase ARN/bucket variants, wildcards and mixed-case actions. Before the fix,
12 failed and six controls passed. Two additional real-Neo4j regressions verify
the corrected reduction through refreshed publication and scoped reference reads.
Independent review also checked 19 direct/fallback matcher comparisons.

Previously published candidates require a newer successful AWS capture and a
fresh Guard collection to replace their evidence and joins. Upgrading code alone
does not recompute them; raw policy documents are deliberately absent from the
graph. This requirement is documented in the [AWS guide](../AWS.md). No live AWS
capture was performed.

## Enrollment parity

Observer, cloud-join and AWS enrollment validators accepted BOM-only identifiers
that the inventory schema rejects. They now require a nonblank character under
the shared Python-whitespace-plus-BOM rule, while preserving nonblank identifiers
unchanged. Dictionary and public dataclass inputs use the same checks.

Fifteen rejection regressions failed before the fix; three positive cases verify
preservation, including mixed whitespace/BOM strings. All 18 now pass. The
installed-wheel consumer also rejects malformed cloud enrollment identifiers.
This was unusable configuration acceptance, with no demonstrated authorization
bypass.

## Validation

Independent reviews found no additional blocker in the corrections. The broader
collector/transport/archive/publication and AWS publication audits found no other
reproducible defect; the focused private-report transport/storage suite passed
43 tests. Focused checks are subsets of the full totals below.

- `npm run check`: **699 JavaScript tests passed**, zero failures/skips, plus
  installed identity HTTPS, packed declarations/README examples, and scoped
  HTTP/MCP/policy consumer checks.
- Full Python unit suite: **884 passed** in **16.66 seconds**.
- Full disposable Neo4j suite: **131 passed** in **219.02 seconds**.
- **49 regression cases added**: six Node, 36 Python unit and seven Neo4j cases.
- Ruff lint/format: **66 Python files passed**; lock validation passed.
- Wheel/source builds, wheel rebuilt from the source archive, and the isolated
  installed Python consumer: passed.
- Recovery pilot: **passed in 46.785 seconds**. Three scoped reads, four replayed
  snapshots, equal logical graph content and snapshot pointers, unchanged
  executor authority, and allowed/denied execution with inventory stopped. See
  the [safe recovery result](freshness-policy-recovery-2026-10-30.json).
- Graph benchmark: **passed** with 100 sources, 10,000 tasks and 100,000 grants
  (128,201 nodes / 481,100 relationships). All 100 HTTP requests succeeded.
  Query p95 was **0.183 seconds** for agent access and **0.255 seconds** for
  explanations against the unchanged **2-second** gate. The **1.865-second**
  cold first request is retained. Maximum per-source publication was **8.918
  seconds** against **120 seconds**; serial batch time was **105.415 seconds**.
  See the [complete benchmark result](freshness-policy-benchmark-2026-10-30.json).
  The database used 4 CPUs / 4 GiB, with other task test processes finished.
  This measures synthetic host inventory, not a live AWS or policy-heavy workload.
- Owned test/benchmark/pilot containers and pilot volumes/networks were removed;
  `git diff --check` passed.

The first JavaScript run after implementation exposed three fixture issues:
literal-object comparison with immutable output, an unsupported `undefined`
fake graph value, and a policy expiry clock tied to call counts. The fixtures now
match actual output/missing-value shapes, and time advances at the actual policy
recheck query. The expiry assertion still requires whole-read rejection after
two policy reads. The final full run passed with the same implementation bounds.

## Assessment and remaining gates

Assessment: **9/10 on the existing local acceptance checklist**. Its
[nine local gates and outstanding enrolled-deployment gate](source-lifecycle-review-2026-10-30.md#acceptance-assessment)
are an implementation checklist, not a security probability or production
certification. Approved AWS enrollment, actual company IdP/trusted TLS,
representative deployed workloads and independent rollout review remain open.

This pass used synthetic fixtures and contacted no live AWS account or company
IdP. The admission benchmark, native Linux/Windows and browser appearance were not
revalidated. Earlier artifacts retain their stated scope. Verification
used macOS arm64, Node 26.12.0, Python 3.13.10, locked Cartography 0.144.0 and the
pinned Neo4j Community 5.26.32 image.

## Reproduction

From the repository root:

```sh
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30' npm run check
```

Then, from `integrations/cartography`, using the locked environment:

```sh
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
uv lock --check
.venv/bin/python scripts/test-disposable-neo4j.py -- -q
uv build
uv build --wheel dist/agent_guard_cartography-0.1.0a1.tar.gz --out-dir dist/from-sdist
uv run --isolated --no-project --python .venv/bin/python --with ./dist/from-sdist/agent_guard_cartography-0.1.0a1-py3-none-any.whl python scripts/check-installed.py
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-boundary-review-pilot.json
.venv/bin/python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /tmp/agent-guard-boundary-review-benchmark.json
```

Use new output paths. Finish JavaScript builds before Python suites/pilot runs
that invoke built Node packages. Run the benchmark after the other test processes
finish; its owned Neo4j instance reserves 4 CPUs and 4 GiB. The disposable runners
own their databases and cleanup.
