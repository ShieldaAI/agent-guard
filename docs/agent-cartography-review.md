# Agent cartography implementation review

The P1 catalog extends the existing company-operated collector, graph, scoped Map
API and viewer. It adds agents and accountable owners, deployments and credential
references, declared permissions, connected resources, relationships and retained
permission-related changes. See the [company guide](guides/agent-cartography.md)
and [versioned contract](agent-cartography-contract.md) for enrollment and fields.

## Requirement coverage

| Requirement | Implemented behavior | Verification entry points |
| --- | --- | --- |
| Agents and owners | Stable agent identities, purpose, lifecycle, assigned/unassigned/unknown ownership, source-scoped owner directory and accountable resource owners. Legacy metadata remains unknown without inventing facts. | Executor `inventory-cartography.test.mjs`; Map `inventory-v2.test.mjs`; Python `test_manifest_v2.py`. |
| Permissions | Retained grants, exact selectors, approval-required tool flags and current policy candidates retain their distinct evidence types and capture times. Generic resource actions never acquire an inferred AWS policy result. | Map service/policy-reader tests; live `test_manifest_v2_graph.py`; viewer policy tests. |
| Resources and relationships | AWS targets and opaque company resources, scope, sensitivity, dependencies, deployment bindings, credential lifecycle and readable relationship endpoints. Names do not replace stable identities. | Actual observer export through Python validation, Neo4j publication and Map queries; reference and duplicate rejection tests. |
| Permission changes | Authorized current/previous comparisons with safe before/after fields, relationship additions/removals, permission/ownership/binding filters and affected visible agents. Paging includes authorized totals. | Map diff tests; live ownership-transfer, team-transfer and missing-baseline cases; browser comparison walkthrough. |
| Company isolation | Tenant, source generation and trusted team scope apply before counting, paging, traversing or comparing. Shared owners, credentials and dependency endpoints cannot expand visibility. | Neo4j query and historical-scope regressions; forged/unmapped identity and session tests. |
| Upgrade and recovery | Version-1 compatibility, closed version-2 schemas, revision/content fences, downgrade rejection, atomic publication, private archive reconstruction and scoped retirement. | Unit/schema contracts and actual database interruption, reopen, archive and cleanup checks. |
| Clear UI | Agents/Owners/Resources indexes, structured details, optional focused graph, readable evidence labels, loading/empty/error/retry states, mobile and keyboard access. Large graphs do not block paged details. | Three-engine browser walkthrough; automated accessibility scans; screenshot review; slow-service request queue and stale-session tests. |

## Security and evidence boundaries

Collection is read-only and does not resolve or execute tools, mint grants, approve
actions or write executor authority. Tests compare ledger revision, task authority,
usage and effects before and after actual authenticated collection. New host
metadata cannot assign viewer roles or team visibility.

Secret fields and credential-bearing reference values are rejected by closed
schemas and opaque-reference validation. Display names, purpose and identifiers
remain trusted-host nonsecret metadata; this is not a general content classifier.
Companies retain their own reference mapping, source credentials, IdP and data.

The resource index contains host-bound resources. Unmapped selectors remain in
agent permissions and are not evidence of no access. Comparisons show net changes
between retained snapshots, not every intermediate event. Approval events,
request-time decisions, backend receipts and external IAM policy history remain
explicitly not collected by this catalog. Current Agent Ops/backend evidence is a
separate workflow. Credential lifecycle and runtime/build references are captured
host assertions, not proof of live authentication or runtime attestation.

Automated checks and visual review do not establish a human operator study, an
independent security audit or acceptance of an unknown company deployment. The
existing production-release acceptance gates remain separate from this feature.
