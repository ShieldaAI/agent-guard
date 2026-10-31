# Authentication loss and local-input verification

Date: 30 October 2026. The Cartography plan has no open repository implementation
milestone. This pass audited the viewer, permission reference service and
lifecycle/recovery paths, then corrected three concrete defects. Final functional
verification and the operational recovery pilot passed. The documented local acceptance assessment remains **9/10**;
enrolled company rollout remains outstanding.

## Authentication denial clears company evidence

The viewer parsed response framing and JSON before preserving HTTP status.
An empty, HTML, malformed, oversized or unreadable 401/403 response therefore
became a generic viewer error with status zero. Company-session invalidation
did not run: cached evidence remained and a sibling request could still resolve
with previous-session data. This was reproduced for both 401 and 403.

The viewer now treats those response statuses as authentication loss immediately
after receiving headers. It cancels the body without waiting for cancellation,
uses a fixed safe error, and aborts transport. The existing company-session path
closes sibling requests, clears workspace evidence and discards queued results.
Ordinary non-authentication errors retain their behavior and successful responses
retain their parsing limits. Server authorization was not bypassed by the defect.

Three added tests cover eleven denial-body variants under both statuses, evidence
clearing/sibling cancellation, and ordinary 404/413/429/503 controls. Both new
authentication regression tests failed before the fix. Independent review also
verified native `Response` cancellation edge cases, native fetch against stalled
401/403 loopback responses, and the React callback that clears workspace state.
The [viewer guide](../../../apps/agent-map/README.md) documents the behavior.

## Local JSON inputs cannot wait on a FIFO writer

Snapshot, observer-enrollment, expected-source/cloud-scope and lifecycle-transition
loaders limited bytes but used blocking file opens. All four were reproduced
waiting indefinitely on a named pipe with no writer. These reads precede the
ingestion lock, so the issue stalled startup without holding that shared lock.

A shared reader now opens with nonblocking mode, checks that the opened descriptor
is a regular file, and closes it on success or failure. This checks the same
descriptor that will be read. Callers retain their existing byte limits, JSON
validation and stable diagnostics. Regular files and symlinks to regular files
remain accepted. Private AWS enrollment and archive permission/path rules are
unchanged. Named pipes, devices and directories are rejected before reading.

Hosts without nonblocking-open support fail with the existing public read/config
error rather than a raw attribute exception; no blocking fallback was introduced.
This feature-absence path was tested by simulation, not native Windows execution.

The input-file tests cover four actual FIFO cases using isolated, bounded child
processes, eight regular/symlink cases, six source/cloud JSON and exact-byte-boundary
cases, and four unsupported-feature error/no-open cases. The original four FIFO
cases failed before the reader change. Independent review additionally verified
descriptor cleanup on success, FIFO rejection, and injected stat/open-wrapper/read
failures. The installed-wheel consumer now loads its inventory fixtures through
the public file loader, exercising the packaged helper.

## Lifecycle identifier parity

Transition validation still accepted BOM-only source identifiers that observer
enrollment and the inventory contract reject. It now uses the same whitespace
plus BOM nonblank rule, preserving nonblank identifiers unchanged. Six rejection
cases failed before the fix; one positive case verifies exact preservation.
Graph preflight already rejected unusable identities, so no wrong-scope graph
mutation was demonstrated. Existing lifecycle scope/equality checks remain intact.

## Verification

Independent audits found no additional blocker in source lifecycle, retention,
replay, permission-reference explanations or policy binding validation. Focused
service/store/policy and lifecycle/archive/recovery suites passed 160 and 152
tests respectively; these are subsets of the full totals below. The corrections
received separate review.

- `npm run check`: **702 JavaScript tests passed**, zero failures/skips, plus
  the installed identity HTTPS consumer, packed declarations/README examples,
  scoped HTTP/MCP/policy consumers and viewer build.
- Full Python unit suite: **913 passed** in **19.65 seconds**.
- Full disposable Neo4j suite: **131 passed** in **194.67 seconds**. The final
  unsupported-feature guard leaves the tested POSIX path unchanged.
- **32 named regression cases added**: three viewer tests and 29 Python cases;
  the viewer tests include the denial-body/status matrix described above.
- Ruff lint/format passed for **68 Python files**; lock validation passed.
- Wheel/source builds, wheel rebuilt from the source archive, and isolated
  installed Python consumer passed.
- The [operational recovery pilot](auth-input-recovery-2026-10-30.json) passed in
  **51.867 seconds**: four snapshots replayed, three scope checks passed, restored
  logical graph content and snapshot pointers matched, and collection/rollback
  preserved executor authority and operation.
- No disposable-test or pilot containers, pilot volumes or pilot networks remained
  after verification. `git diff --check` passed.

## Assessment and remaining gates

Assessment: **9/10 on the existing local acceptance checklist**. Its
[nine verified local gates and one enrolled-deployment gate](source-lifecycle-review-2026-10-30.md#acceptance-assessment)
are a scoped implementation checklist, not a security probability or production
certification. Approved AWS enrollment, company IdP/trusted TLS, representative
deployed workloads and independent rollout review remain required.

This pass used synthetic fixtures and local test services; no live AWS account
or company IdP was contacted. Graph/admission benchmarks, browser appearance,
and native Linux/Windows were not revalidated. Earlier performance artifacts,
including the [latest graph benchmark](freshness-policy-benchmark-2026-10-30.json),
retain their stated scope. Verification used macOS arm64, Node 26.12.0, Python
3.13.10, locked Cartography 0.144.0 and pinned Neo4j Community 5.26.32.

## Reproduction

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
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-followup-audit-pilot.json
```

Use a new pilot output path. Finish JavaScript builds before Python suites and
pilot runs that invoke built Node packages. Disposable runners own their databases
and clean up only resources belonging to their runs.
