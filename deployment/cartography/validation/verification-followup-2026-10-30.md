# Cartography implementation verification follow-up

Date: 30 October 2026. All repository milestones in the
[implementation plan](../../../docs/cartography-integration-plan.md) were already
believed complete. The subsequent [source-generation lifecycle audit](source-lifecycle-review-2026-10-30.md)
found and implemented a missed retirement requirement; it supersedes that completion
claim. This earlier pass audited and tested the implementation, fixed one custom-store
validation gap, and strengthened the regression suite.

## Changes and evidence

Complete policy records from custom `MapStore` implementations previously passed
service validation with missing or ambiguous deployment-to-agent links or
duplicated grant/tool/selector relationships. The default Neo4j reader already
rejected those paths. The service now requires singular owning-agent and tool
links, plus unique task/grant and grant/selector pairs. Distinct valid grants and
selectors remain supported. Explicit unavailable evidence still carries no
candidates. Seven negative tests reproduced the gap against the old build;
nine new tests cover rejection and compatibility.

Three additional tests execute the real Neo4j policy queries while a second
session commits a change to the agent's team, the deployment's owning agent, or
the execution identity. A test-only driver wrapper coordinates the mutation
after the first query is fully consumed. Another visible agent keeps source
selection unchanged. The tests assert that the source pointers stay identical,
the real binding proof changes from true to false, and the reader returns only
`MAP_UNAVAILABLE`, with no partial view. They use no timing sleeps or production
hooks and can write only to the marked disposable database.

The full JavaScript run also exposed an existing timing-sensitive OIDC deadline
test: CPU scheduling could expire its short timer before JWKS retrieval. The
client correctly rejected the exchange. The test now advances a controlled
monotonic clock at real HTTPS token and JWKS request arrivals: each stage fits
the configured budget independently, while the combined duration exceeds it.
It requires both requests and rejection, preserving the shared-deadline check
without relying on wall-clock sleeps. Production timeout behavior is unchanged.
The targeted OIDC suite passed all 28 tests.

Separate agent reviews covered the reference reader/service/HTTP/MCP boundary
and collector/archive/recovery/AWS publication. No additional concrete blocker
was found after the custom-store fix.

## Verification

- `npm run check`: **692 JavaScript tests passed, zero failures or skips**,
  plus the installed identity HTTPS consumer. Build, packed declarations,
  README examples, HTTP/MCP and policy contract checks passed.
- Python unit suite: **713 passed**.
- Disposable Neo4j integration suite: **103 passed** in 257.52 seconds,
  including all three new concurrent-change regressions.
- Ruff lint and formatting: passed for **58 Python files**.
- Wheel and source archive builds, rebuilding the wheel from the source archive,
  and isolated installed Python consumer: passed.
- Operational pilot against the final build: **passed** in 79.714 seconds,
  including three scoped observer/collector/reference queries,
  backup/replay into a fresh database, logical content and snapshot-pointer
  equality, unchanged executor authority, and allowed/denied execution with
  inventory services stopped. See the [safe result artifact](recovery-followup-2026-10-30.json).
- Disposable test databases were removed. `git diff --check` passed.

The [original review](policy-reference-review-2026-10-30.md#reproduction) records
the full reproduction commands and pinned sandbox/Neo4j images. The operational
check additionally runs from `integrations/cartography`:

```sh
.venv/bin/python scripts/run-pilot.py --output /tmp/agent-guard-pilot-verification.json
```

Use a new output filename. Finish JavaScript builds/package checks before
running the Python integration or pilot scripts, which invoke the built Node
packages. This pass used macOS arm64, Node 26.12.0, Python 3.13.10, locked
Cartography 0.144.0 and the pinned Neo4j Community 5.26.32 image. No live AWS or
company identity provider was contacted.

## Acceptance assessment

The assessment remains **9/10 under the original explicit acceptance rubric**:
nine repository implementation gates verified, with enrolled company rollout
and independent deployment review outstanding. This is a checklist assessment,
not a measured security probability or production certification. The previously
listed real-Neo4j concurrent-mutation coverage gap is now closed. No new browser,
native platform certification or production-scale capacity measurement is claimed
by this pass; the prior viewer screenshot and pilot benchmark retain their
original scope.
