# Agent Guard production implementation plan

This plan extends the published alpha.3 foundation with a complete operator
workflow and a broader agent inventory. The engineering assessment and its
recorded construction evidence remain in [protection-assessment.md](protection-assessment.md).
Deployment acceptance follows the actual enabled tools, identities, backends and
host profile.

The implemented reference profile and its measured checks are recorded in the
[P0 verification review](production-p0-review.md). Use the
[Linux runbook](../deployment/production/README.md) for installation and recovery.
The [self-hosted onboarding review](self-hosted-onboarding-review.md) records the
subsequent configurable limits, company setup and data-import verification.

## P0 · Operator approval and recovery

Deliver one vertically integrated ticket workflow using a single durable executor
owner, an authenticated operator service and a persistent backend receipt store.
The operator application lives in `apps/agent-ops`. Its server owns identities,
tenant scopes, roles, credentials, preparation, review decisions and execution.
The static browser interface displays server-provided state and submits explicit
operator decisions.

| Capability | Required behavior | Exit evidence |
| --- | --- | --- |
| Sign-in and scope | Display the authenticated operator, tenant, roles and session expiry. Clear protected state on authentication loss. Recheck permission for each operation on the server. | Allowed operator signs in. Expired/revoked access returns to sign-in and exposes no prior workspace. |
| Prepare a change | Select an available ticket and target status. Resolve the tenant, current version and permitted action on the host. | A prepared request contains immutable target, change, version, digest and expiry. Preparation alone has no ticket effect. |
| Review and submit | Display the exact prepared values. Approval submits that action once. Denial retires the prepared request. Changed or expired requests require fresh preparation. | One approved change produces one correlated backend receipt. Denied, expired and stale requests produce no unauthorized change. |
| Requests and recovery | Keep pending, declined, expired, running, confirmed, failed and unconfirmed outcomes distinct. Provide receipt lookup and evidence-based reconciliation. | A lost response and process restart retain the original operation identity. Receipt reconciliation confirms the original effect without resubmission. |
| Maintenance | Preview archival eligibility and exclusions before applying a bound plan. Provide operator-readable key-rotation prerequisites and recovery guidance. | Active, unresolved and still-referenced records stay protected. A changed preview cannot authorize a different archival operation. Rotation preserves readable state and the documented recovery boundary. |
| Usability | Use semantic controls, visible focus, keyboard navigation, mobile layouts and explicit loading, empty and error states. Render external text inertly. | Ordinary approval, denial, expiry, missing receipt, reconciliation and maintenance flows pass browser checks and visual review. |

Persist the action-to-backend-operation binding before dispatch. The backend must
perform the conditional change and record its idempotency receipt atomically.
Keep unresolved execution reservations until the backend outcome and termination
are established. Operator messages must derive confirmed success from a bound
receipt. Keep application administration secrets and ledger keys on the host.

Production onboarding must identify the installed version, persistent paths,
identity source, operator grants, backend credentials, TLS boundary, retention
policy, cost ceilings and backup/restore ownership. Provide a preflight that
fails with an actionable result when a required dependency is unavailable.
Validate a fresh installation and a restart with the intended storage and secret
manager before enabling the workflow for company users.

The release checklist records the supported authentication and hosting profiles
explicitly. Additional identity providers, proxy modes, native operating systems
and multiple executor owners require their own implementation and verification.

The implementation now includes the static operator interface and a reference
HTTPS service using OIDC, encrypted witnessed SQLite stores, role-bound decisions
and backend receipts. See the [operator application](../apps/agent-ops/README.md)
and [Linux deployment runbook](../deployment/production/README.md) for the supported
single-owner profile and capacity limits. This implementation does not complete
the P1 inventory expansion below.

Two repeatable browser checks distinguish their evidence sources:

| Check | Exercised behavior | Evidence boundary |
| --- | --- | --- |
| [UI contract walkthrough](../apps/agent-ops/check-browser.mjs) | Review, denial, lost HTTP response, receipt absence, recovery, expiry, restart-required review, blocked archival, role loss and service failure. | Synthetic API responses; includes explicit no-resubmission assertions. |
| [Integrated service walkthrough](../apps/agent-ops/check-browser-service.mjs) | Browser OIDC sign-in, preparation, exact approval, durable receipt, denial, post-commit failure and receipt reconciliation, archival and sign-out. | Real local HTTPS service and encrypted witnessed stores with a disposable local IdP and controlled post-commit failure. |

Run either script with an existing tools directory containing `playwright` and
`axe-core`, and optionally a directory for screenshots and JSON results:

```sh
node apps/agent-ops/check-browser.mjs /path/to/browser-tools /path/to/evidence
node apps/agent-ops/check-browser-service.mjs /path/to/browser-tools /path/to/evidence
```

The checks cover keyboard activation, three mobile workspace views, automated
WCAG A/AA checks and visual screenshots; the service check also covers the
desktop/mobile sign-in failure recovery page. They do not represent a human
operator cohort, a customer IdP deployment or paid live-provider trials.

## P1 · Extend Agent Map and Cartography inventory

Extend the existing exporter, observer collector, Cartography projections,
scoped `MapService` queries and Agent Map viewer. Reuse the established tenant,
source-generation and immutable snapshot boundaries described in the
[Cartography integration plan](cartography-integration-plan.md). The following
coverage is planned work; each row needs a versioned schema, an authoritative
source and scoped query behavior before it is presented as collected evidence.

| Inventory area | Information and relationships to add or complete |
| --- | --- |
| Agents and ownership | Stable agent identity, accountable owner/team, purpose, lifecycle state and source of ownership. Keep unresolved or unassigned ownership visible. |
| Identities and deployments | Host assertions linking agents to runtime deployments, service identities, tenant/account, environment, approved build and workload generation. Record the binding authority and observation time. |
| Tasks and tools | Task ancestry, purpose, deadlines, enabled tool descriptors, implementation versions, resource resolvers and execution bindings. Retain the effective revision used for each observation. |
| MCP connections | Enrolled peer identity, transport reference, approved metadata generation, lifecycle state, tool/resource/prompt availability and drift/quarantine status. |
| Grants and approvals | Declared task grants, resource/action limits, reviewer roles, prepared-action references, approval status/expiry and consumption. Publish minimized observation records with explicit provenance. |
| Permission evidence | Distinguish declared grants, mapped policy candidates, observed request-time decisions and backend-confirmed effects. Preserve conditions, explicit denials, unsupported evaluation, missing evidence and independent capture times. |
| Resources | Exact resource identities, ownership, tenant/account, scope and object/prefix boundaries, sensitivity labels, source dependencies and approved destinations. |
| Credential references | Opaque host-owned credential references, intended issuer/audience, permitted recipients, lifecycle/expiry and rotation status. Secret bytes, bearer tokens, private keys and credential-bearing URLs stay outside snapshots, graph properties, browser state and reports. |
| Provenance and freshness | Build and artifact lineage, source generation, signed claims, capture/publication times, collection coverage, retention gaps, quarantine and supersession. |
| Drift and revocation | Changes to tools, bindings, grants, policy, peers and credential generations. Display affected agents/tasks and the observed revocation state, with links to the responsible operator workflow. |

Discovery creates inventory observations. Execution authority comes from the
trusted host's current authorization path. A collected agent or graph edge must
never create a grant, approve a tool/action, expand a tenant scope or imply that
an operation is currently permitted. Permission labels must identify their
evidence type and limitations. An absent relationship retains an unknown or
uncollected state where collection is incomplete.

Current executor inventory describes retained live authority. Archival removes
live task, family and action rows while preserving an encrypted private archive
and digest tombstones. Planned history views may expose minimized archive counts,
references and retirement provenance through scoped maintenance observations.
They must not reintroduce archived tasks as active authority or copy archived
arguments, secret keys or private payloads into the graph.

Implement the inventory expansion in this order.

1. Define the versioned export fields, source ownership and redaction rules for
   each relationship. Keep stable identities and generation retirement compatible
   with existing snapshots and restored sources.
2. Add bounded collection and atomic projection using the existing observer and
   Cartography pipeline. Retain independent component watermarks and explicit
   collection errors.
3. Extend the current scoped query contract and accessible evidence panels.
   Start from one agent, resource or changed binding. Provide impact views for
   owners, drift and revocation while retaining the exact supporting observations.
4. Validate joins, hidden tenants, shared provider resources, missing data,
   retirement, reload and restored-source behavior. Check that each presentation
   label follows from the collected evidence and that inventory operations have
   no executor effect.

## Deployment validation and expansion

The self-hosted profile now has configurable, persisted retention and byte limits,
company onboarding and reviewed data imports. The default values remain unchanged;
changing them requires an offline preview and apply, with no eviction of retained
authority. Reviewed [business-history compaction](guides/company-history.md) and
[managed key retirement and current-state recovery](../deployment/production/custody.md)
now cover the selected ticket profile. Preserve complete history and registered
backup dependencies; neither process authorizes discarding unresolved outcomes.
Configure and test external durable audit retention, monitoring, alert routing and
off-host witness custody. These operations must preserve unresolved outcomes and
revocation history; capacity relief must never recreate previously spent authority.

Use the [operator study](guides/operator-usability-check.md) on the actual
approval, sign-in, inventory and receipt-recovery workflow. Enroll the build and
deployment before collecting representative observations. Browser automation
provides functional and automated accessibility evidence. Human observations
remain separately identified, with complete planned denominators.

Use the [model-selected trial procedure](guides/model-selected-provider-trials.md)
for each supported provider/model configuration with an approved budget and
reviewed synthetic records. Keep exact configuration, outcomes, usage receipts
and unresolved cases. Validate backend-specific idempotency, cancellation, cost
limits, secret rotation and backup recovery before expanding the enabled tool
set or deployment topology.

Maintain a release-specific readiness record linking source and package hashes,
supported profiles, operational owners, checks performed and remaining limits.
Historical construction and platform records retain their original scope.
