# Launcher inputs and policy query planning review

Date: 30 October 2026. All Cartography repository milestones remain implemented.
This pass audited observer/export composition, AWS capture and policy reduction,
reference/identity boundaries, and local operational paths. It corrected two
reproduced input defects in the bearer reference launcher, excessive policy-query
planning cost, and a timing-sensitive integration test.
Final suites, package checks, recovery and the acceptance benchmark passed.
The local acceptance assessment is **9/10**; company deployment remains a separate gate.

## Reproduced defects and correction

The bearer launcher checked configuration size with `stat(path)` and then used
unbounded `readFile(path)`. A FIFO with no writer blocked startup until the test
parent killed it. A deterministic real-file test appended data after the metadata
check: the old launcher read **262,146 bytes**, exceeding the **131,072-byte**
configuration limit. Parsing rejected the oversized buffer only after it had
already been materialized. Neither finding demonstrated an authorization bypass
or credential disclosure.

The [launcher](../../../packages/agent-map/src/cli.ts) now opens with nonblocking
mode, checks the opened descriptor for a regular file, and reads at most the
limit plus one byte. It closes that same descriptor on success or failure.
Directories, named pipes and oversized/growing files fail before service startup;
exact-limit files and symlinks to regular files remain accepted. CLI failures
still print only `MAP_START_FAILED`. The original `readFile` implementation was
not shown to leak descriptors; cleanup assertions verify the new reader.

Five named tests were added: regular symlink compatibility, exact-limit startup,
FIFO rejection, nonregular/oversized rejection, and growth-after-stat bounds.
The FIFO and growth cases failed against the old built launcher. All seven CLI
tests pass against the correction, including authenticated-service startup,
unauthenticated-query rejection and shutdown from the existing test.

The launcher now explicitly requires nonblocking-open support and fails closed
when that capability is absent. The [guide](../../../packages/agent-map/README.md)
documents this requirement and the POSIX pilot profile. Independent review caught
tests that assumed POSIX facilities in every CI job; the final tests instead assert
safe rejection on unsupported hosts before attempting symlinks or `mkfifo`, and
label those branches explicitly. This session ran the POSIX cases on macOS;
native Windows execution and its unsupported-host branch were not certified.
A separate simulated-capability probe confirmed rejection before file open when
nonblocking support is absent; it does not establish native Windows support.

## Policy refresh test clock

The first full disposable-Neo4j run finished with **130 passed and one failed**
in **199.50 seconds**. The Deny resource-case refresh test expected complete
evidence but received unavailable evidence. Its fixture froze the query clock
before a second graph import, while that import used the later wall clock for
cloud observations. Crossing a second boundary made those observations appear
to come from the future relative to the test's query.

A diagnostic run forced the cloud clock one second past the fixture clock.
The Deny case reproduced `unavailable/changed`. The Allow case separately reached
`MAP_TIMEOUT` before evidence assertions on that fresh database. The planning
investigation below addressed these timeouts. No production deadline was increased
and no assertion was removed to pass them.

The [refresh test](../../../integrations/cartography/tests/integration/test_policy_reference_queries.py)
now controls only the cloud observation clock, first asserts rejection using the
old query clock, and then reads at the refresh time. Both Allow and Deny retain
their original exact candidate, condition, unknown-assessment and redaction
assertions. A separate review confirmed that production code, global clocks and
request deadlines remain unchanged.

## Policy query planning

A second full run passed both corrected clock cases but failed the shared-tool
policy case: **130 passed, one failed in 259.71 seconds**. A focused policy run
then produced **17 passed and five `MAP_TIMEOUT` failures in 118.73 seconds**,
including the shared-tool case. Independent fake-driver probes ruled out simple
row/property reordering as the cause; the reader already normalizes both.

An [owned-database planner experiment](launcher-policy-planner-2026-10-30.json) compared the original query, a diagnostic
control omitting the binding proof, and the equivalent nested proof. The control
was never used in production. All variants used the same valid synthetic probe
and returned identical minimized rows. Measured `EXPLAIN` elapsed/server-availability
times were **4,469/4,420 ms** for the original, **642/611 ms** for the control,
and **1,331/1,277 ms** for the nested proof. Connection setup was 19 ms; the
policy-free base read took 3,141 ms. These measurements identify substantial cold
planning cost within the unchanged five-second whole-read budget. They are one
controlled local comparison, not a latency guarantee or representative load test.

The [policy reader](../../../packages/agent-map/src/policy-reader.ts) now expresses
the binding proof as correlated short paths instead of one large cycle. The
provider query, projected columns and row limit remain unchanged. Independent
review verified every exact identity/scope/team/tool/resource/action predicate
and all ten duplicate-relationship guards. The implemented query exactly matches
the measured nested variant. The experiment's separate 30-second diagnostic
ceiling only allowed measurement; the production deadline remains five seconds.

Ten new real-Neo4j race cases duplicate each protected relationship after the
first policy read. They require the second proof to change from true to false,
unchanged source pointers, exactly one mutation, and `MAP_UNAVAILABLE` for the
whole response. Existing team/deployment/identity races remain included. This
checks that reducing planning cost preserves the authorization-path checks.
The corrected policy suite passed **all 32 cases in 162.99 seconds** on a new
disposable database, with no warm-up outside the tests and the production
five-second limit unchanged.

## Independent audit evidence

- Observer/export/MCP composition: **226 tests passed**, plus **801 differential
  manifest-validation probes** with zero TypeScript/Python acceptance mismatches.
  Reviewed tenant filtering, immutable authority snapshots, credential separation,
  response bounds, timeout/disconnect cleanup and metadata drift checks.
- AWS capture/configuration/policy: **210 tests passed**. Two real-process probes
  verified owned descendant termination after success and timeout; four conflicting
  framing probes rejected responses before reading bodies and closed transport.
  Caller matching, fixed endpoints, policy completeness and output/work limits
  had no additional concrete finding. No live AWS account was contacted.
- Reference HTTP/identity/store/OIDC: **83 focused tests passed**; review found no
  additional blocker in scope/pointer rechecks, issuer/audience/nonce/PKCE,
  endpoint bounds, session revocation and disconnect handling.
- Collector/report/archive/recovery: **177 focused tests passed**.
- A separate review of the launcher correction passed all seven CLI tests and
  five fault-injection controls for descriptor cleanup after metadata errors,
  nonregular files, declared oversize, read failures and malformed JSON.

Focused test counts above overlap the full suites; they are not extra suite
totals. Differential and fault-injection probes are supplemental local experiments.
Internal agent reviews do not replace independent deployment review.

## Verification

- `npm run check` after both production corrections: **707 JavaScript tests passed**, zero failures/skips, plus
  the installed identity HTTPS consumer, packed declarations/README examples,
  scoped HTTP/MCP/policy consumers and viewer build. The final unsupported-host
  test branches were included, with the supported POSIX cases exercised locally.
- Full Python unit suite after final production changes: **913 passed** in **18.10 seconds**.
- Full disposable Neo4j suite after the corrections: **141 passed** in
  **204.88 seconds**, including all policy and duplicate-edge races.
- Ruff lint/format passed for **68 Python files**; lock validation passed.
- **15 named regression/control cases added**: five launcher cases and ten
  real-Neo4j duplicate-edge races; two existing refresh-clock cases were strengthened.
- Wheel/source builds, wheel rebuilt from the final source archive and isolated
  installed Python consumer passed.
- The [recovery pilot](launcher-policy-recovery-2026-10-30.json) passed in
  **49.269 seconds**: four snapshots replayed, all three reader scopes checked,
  restored graph content and snapshot pointers matched, and executor authority
  and operation survived collection and rollback.
- The [refreshed acceptance benchmark](launcher-policy-benchmark-2026-10-30.json)
  passed all unchanged gates: **100 sources, 10,000 tasks, 100,000 grants**,
  **128,201 nodes / 481,100 relationships**, and **100 successful requests**.
  Agent-access/explanation p95 was **0.207 / 0.303 seconds**; maximum per-source
  publication was **7.493 seconds**, with a **101.873-second** serial batch.
  The first cold request took **2.225 seconds** and remains in the measurements.
  This synthetic host-inventory workload complements the single-probe policy
  planner experiment; neither establishes large-company IAM-policy capacity.
- No owned disposable-test/pilot containers, pilot volumes or pilot networks
  remained. `git diff --check` and updated documentation link checks passed.

## Assessment and remaining gates

Assessment: **9/10 on the existing local acceptance checklist**, with the
[nine local gates and enrolled-deployment gate](source-lifecycle-review-2026-10-30.md#acceptance-assessment)
retaining their stated scope. It is not a security probability or production
certification. Approved AWS enrollment, company IdP/trusted TLS, representative
deployed workloads and independent rollout review remain outstanding.

Provider-neutral OIDC remains the selected sign-in integration. No live company
AWS or IdP was contacted. Browser appearance and native Linux/Windows host
certification were not performed. Executor admission latency was not remeasured;
its code path is unchanged. Verification used macOS arm64, Node 26.12.0, Python 3.13.10,
locked Cartography 0.144.0 and pinned Neo4j Community 5.26.32.

## Reproduction

From the repository root:

```sh
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30' npm run check
node --test packages/agent-map/test/cli.test.mjs
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
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-transport-audit-pilot.json
.venv/bin/python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /tmp/agent-guard-transport-audit-benchmark.json
```

Use a new pilot output path. Finish JavaScript builds before Python suites and
pilot runs that invoke built Node packages. Disposable runners own their databases
and clean up only resources belonging to their runs.
