# Scoped policy reference implementation review

Date: 30 October 2026. Scope: the scoped policy reference milestone in the
[Cartography integration plan](../../../docs/cartography-integration-plan.md#scoped-policy-reference-projection-milestone).
Validation used synthetic fixtures on macOS arm64, Node 26.12.0, Python 3.13.10,
locked Cartography 0.144.0 and disposable Neo4j Community 5.26.32 at the digest
in [neo4j-image.txt](../../../integrations/cartography/neo4j-image.txt).

The subsequent [source-generation lifecycle audit](source-lifecycle-review-2026-10-30.md)
found a missed retirement requirement and supersedes this report's earlier claim
that policy reference was the final repository milestone. The results below
remain historical evidence for their stated scope.

Assessment: **9/10 against the acceptance rubric below**. Nine implementation
gates passed local verification. The remaining point is an enrolled company
deployment and independent rollout review, which were not performed here.
No known blocking code defect remained after the final tests and agent review.

## Acceptance rubric

Each row is one acceptance point. This is an explicit implementation checklist,
not a statistical confidence estimate or independent security certification.

| Gate | Evidence | Result |
| --- | --- | --- |
| Exact caller and binding scope | Reader, service and viewer require the visible task/deployment/grant/tool/resource/execution path. Hidden and nonexistent targets are equivalent; sibling deployments cannot lend identities. | Verified locally |
| Owned provider provenance | Exact AWS account, ARN, collection identity, provider membership, capture and policy hashes are checked. Foreign/shared edges, duplicates and corrupt evidence cannot produce candidates. | Verified locally |
| Freshness and concurrent change | The tighter host/enrollment age limit applies independently of inventory age. Repeated reads compare provider evidence and exact binding/agent/team proof, then reclassify freshness. | Verified locally |
| Minimized output | Public records contain only scoped references, mapped actions, condition key names, observation times and explicit unknown assessments. Raw policies, condition values, global hashes and counts stay out. | Verified locally |
| Bounded work and responses | Fixed read-only queries, at most 512 pairs, planning and query-parameter caps, raw row/byte caps on both reads, and existing transaction/output deadlines. Overflow fails without partial output. | Verified locally |
| Conservative permission semantics | Conditional candidates remain unknown; empty results never become denials. Boundaries, unsupported actions/policies, disabled collection, stale or changed evidence remain explicit. Original object/prefix scope is retained. | Verified locally |
| API and history compatibility | Existing operations expose filtered evidence over HTTP and official MCP dispatch. Custom stores may omit the optional field. History omits live evidence and reports policy history as not collected. | Verified locally |
| Packaged delivery | Installed npm consumers compile the new exported types and exercise the scoped policy contract. Wheel, source archive, rebuilt wheel and isolated Python consumer pass. | Verified locally |
| User-visible behavior and regressions | Browser inspection, React rendering and Cytoscape tests cover candidate cards/edges, conditions, independent time and unresolved states. Full JavaScript/Python and real-Neo4j suites exercise the integration. | Verified locally |
| Enrolled company rollout | Approved live AWS identity, actual company IdP/trusted TLS, representative workload and independent deployment review. | Not performed |

## Verification record

- `npm run check`: **683 tests passed, zero failures or skips**, plus one installed
  identity HTTPS consumer test. Build, declaration/example compilation, packaged
  MCP/HTTP and policy evidence contract checks also passed. Linux sandbox cases
  ran using the pinned Alpine image, not a skipped Docker path.
- `python -m pytest tests/unit -q`: **713 passed**.
- `python scripts/test-disposable-neo4j.py -- -q`: **100 passed** in 140.91 seconds
  against a fresh disposable database, including 17 new policy reference cases.
- `ruff check .` and `ruff format --check .`: passed for **58 Python files**.
- `uv build`, a wheel rebuilt from the source archive, and an isolated installed
  `scripts/check-installed.py` consumer: passed.
- Built viewer inspected in the in-app browser using the synthetic demo.
  Research displays a conditional candidate and original object scope; Finance
  displays an unresolved permissions boundary. The saved
  [browser screenshot](policy-reference-viewer-2026-10-30.jpg) shows the candidate view.
- Separate agent code review found no remaining concrete blocker in the final
  reader/service boundary. Review fixes include full edge cardinality checks,
  same-query binding/agent/team proof, second-read byte bounds, Unicode ordering
  compatible with Python, and support for valid long unsupported host actions.

One full integration pass exposed an inconsistent new fixture: the deployment's
tool changed while its observed MCP inventory still contained the previous tool.
The existing validator correctly rejected it. The fixture now updates both and
asserts that each visible deployment retains its own distinct policy candidate.
No validator was weakened. Earlier fixture-clock and JSON property-order test
issues were also corrected without relaxing production checks.

## Reproduction

From the repository root, install the locked dependencies and run:

```sh
AGENT_GUARD_SANDBOX_IMAGE='alpine@sha256:bbfcd601d7cd20d35bb0b8b866ad1a8a0d107ca3e1c20870c75c5ce2c1186d30' npm run check
```

Then, from `integrations/cartography`, using the locked `.venv` and `uv`:

```sh
.venv/bin/python -m pytest tests/unit -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/test-disposable-neo4j.py -- -q
uv build
uv build --wheel dist/agent_guard_cartography-0.1.0a1.tar.gz --out-dir dist/from-sdist
uv run --isolated --no-project --python .venv/bin/python --with ./dist/from-sdist/agent_guard_cartography-0.1.0a1-py3-none-any.whl python scripts/check-installed.py
```

Run the JavaScript build/check before Python integration tests: the real Node
consumer needs its built packages. Do not rebuild/remove those packages while
the integration suite is running. The Neo4j runner owns and removes its database.

## Remaining limits

No live AWS account or company identity provider was contacted. Native Windows
and Linux release certification and representative deployed policy-query load
were not newly measured here. The previous metadata pilot benchmark is not a
new benchmark of this policy projection. At this review's completion, concurrent
team/path changes had mocked transition coverage; normal binding proofs and
provider-corruption behavior executed against real Neo4j. Concurrent-mutation
coverage in real Neo4j was subsequently added and verified in the
[follow-up audit](verification-followup-2026-10-30.md), which also fixed a
custom-store validation gap and records updated suite and recovery results.
The existing [AWS rollout gates](../AWS.md#validation-and-remaining-rollout-work)
remain required. All candidate assessments remain unknown; request-time backend
authorization still decides whether an operation is permitted.
