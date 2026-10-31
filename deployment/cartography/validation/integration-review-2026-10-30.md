# Cartography integration verification follow-up

Date: 30 October 2026. All repository milestones in the integration plan are
implemented. This pass audited and tested the existing implementation, fixed two
validation/test-helper defects, and documented a recovery limit. Final checks
passed. Assessment: **9/10 on the documented local acceptance checklist**;
company deployment validation remains outstanding.

## Corrections and regression evidence

Cloud enrollment used Python's `\d{12}` to validate account IDs. It accepted
Arabic-Indic, fullwidth and mixed decimal digits, while the AWS collector and
inventory schemas require twelve ASCII digits. The validator now uses
`[0-9]{12}` with `fullmatch`, including when revalidating a public `CloudScope`
object. All six new rejection cases failed before the fix and pass afterward;
the complete cloud module has 47 passing tests. The installed-wheel consumer
also checks both input forms. Valid ASCII account IDs are unchanged. This was
invalid configuration acceptance, with no demonstrated authorization bypass.

The first full Neo4j run ended with **123 passed and one failed in 280.99
seconds**. The lifecycle recovery test's second disposable database did not
complete a Bolt handshake within its 120-second readiness window. Its setup
failure preceded the child recovery assertions. The other integration tests
passed and the runner removed its owned containers.

Investigation found a separate, reproducible timing gap: `connection_timeout=2`
bounds TCP connection establishment, while the installed Neo4j driver used its
default 60-second acquisition deadline for the Bolt handshake. The readiness
helper now sets `connection_acquisition_timeout=2` as well. A real local socket
test accepts the Bolt preamble but withholds the response; simulated pre-fix
behavior failed the regression at 5.52 seconds when the peer's safety close
fired. The corrected test returns within its four-second assertion bound. A
second test verifies retry followed by a successful consumed readiness query.
Both final focused tests passed in 2.53 seconds. The 120-second startup limit,
database isolation, test assertions and recovery requirements remain unchanged.
The underlying cause of the earlier database startup failure is undetermined;
the handshake correction alone does not establish its cause. A fresh full
integration run subsequently passed all 124 tests.

The runbook now states the existing graph-replay limits: **256 MiB and 4,096
snapshots**. Larger explicit backup/inspect/restore API limits do not expand
graph-replay capacity. No larger-bundle recovery support is claimed.

## Review and final validation

Independent agent reviews found no additional blocker in scoped access queries,
historical ownership, custom-store policy consistency, lifecycle rechecks,
OIDC/HTTPS scope and expiry, revocation/cancellation, or atomic recovery and replay
fences. Their focused service/store, identity/HTTP/MCP and recovery suites passed
97, 71 and 42 tests respectively; those are subsets of the totals below.
The account-ID fix also passed independent review.

- `npm run check`: **693 JavaScript tests passed**, zero failures/skips, plus
  the installed identity HTTPS consumer, packed declarations/README examples and
  scoped HTTP/MCP/policy contract checks.
- Full Python unit suite: **848 passed** in 16.76 seconds. Eight regressions
  were added in this pass: six enrollment cases and two readiness tests.
- Fresh full disposable Neo4j suite: **124 passed** in **187.18 seconds**.
- Ruff lint/format: passed for **66 Python files**. Lock validation passed.
- Wheel/source builds, rebuilding a wheel from the source archive, and the
  isolated installed consumer: passed. Packaged validation includes the new
  account-ID checks and existing schema equality, archive/replay/lifecycle and
  offline AWS checks.
- Operational recovery pilot: **passed in 47.574 seconds**. It verified three
  scoped reads, four replayed snapshots, equal logical graph content and snapshot
  pointers, preserved executor authority, and allowed/denied execution while
  inventory services were stopped. See the
  [safe recovery result](integration-review-recovery-2026-10-30.json).
- Owned disposable containers and pilot containers/volumes/networks were removed.
  `git diff --check` passed.

## Assessment and limits

The [existing acceptance checklist](source-lifecycle-review-2026-10-30.md#acceptance-assessment)
has nine verified local implementation gates and one outstanding enrolled
deployment gate: **9/10**. This is a scoped checklist, not a security probability
or production certification. Approved AWS enrollment, company IdP/trusted TLS,
representative deployed workloads and independent rollout review remain required.

This pass used synthetic fixtures and contacted no live AWS account or company
IdP. It did not repeat the graph/admission benchmarks, browser inspection, or
native Linux/Windows validation. Earlier performance artifacts retain their
stated scope. Verification used macOS arm64, Node 26.12.0, Python 3.13.10, locked
Cartography 0.144.0 and the pinned Neo4j Community 5.26.32 image.

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
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-integration-review-pilot.json
```

Use a new pilot output path. Complete JavaScript builds before Python integration
and pilot runs, which invoke the built Node packages. Disposable runners create
their own databases and perform ownership-checked cleanup.
