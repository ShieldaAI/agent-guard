# Company agent cartography

Agent Map gives a company a read-only inventory of its agents, accountable owners,
declared permissions, resources, deployments, MCP connections and permission-related
changes. Each company operates its own collector, graph and identity provider.
No hosted maintainer account or customer data submission is required.

## Connect your catalog

1. Deploy the current collector and Map service using the existing
   [Cartography runbook](../../deployment/cartography/RUNBOOK.md) and
   [company sign-in guide](../../deployment/cartography/IDENTITY.md).
2. Enroll each executor source and tenant with the trusted host. Obtain its exact
   source identity and exported resource selectors from a core inventory snapshot.
3. Provide a private, operator-reviewed version-2 host manifest. Use the
   [runnable example](../../examples/agent-cartography.mjs) and
   [closed schema](../../schemas/agent-guard-inventory-manifest-v2.schema.json).
   Supply agent/owner names, purpose and lifecycle, deployment details, resource
   bindings, and credential references from company-owned systems.
4. Validate the manifest with `validateInventoryManifest`, then enroll it in the
   existing authenticated observer with profile `host` or `host-mcp`. Collection
   composes the company's assertions with the executor's actual declared grants;
   no resolver or execution callback is invoked.
5. Publish through the enrolled collector. Sign in as an authorized viewer and
   inspect Agents, Owners and Resources. Verify a known agent, a known resource,
   and an intentionally hidden team before expanding access.

For a disposable example after building the repository:

```sh
node examples/agent-cartography.mjs
```

The example emits a synthetic version-2 snapshot through a real authenticated
observer. It uses no company credential, cloud API or effectful tool. Production
hosts retain their own source identity, key custody and reviewed configuration.

## What to provide

Use a stable agent ID independently of task IDs or caller identities. Assign an
owner from the owner directory and retain the separate team field used by existing
visibility bindings. Mark ownership `unassigned` only when the company source
explicitly confirms it; use `unknown` when the source cannot establish ownership.
Version-1 records remain readable and do not acquire invented version-2 details.

Resource bindings join an exact exported `(tool, selector)` to an AWS target or a
generic host resource. Names are display labels, never join keys. Preserve exact
versus prefix scope. Resource dependencies are observations between enrolled
bindings; only visible endpoints appear in relationships. A dependency does not
grant access to its target.

Credential references describe intended issuer/audience/recipient, lifecycle,
expiry and rotation status. Reference values must have the form `opaque:` plus
64 lowercase hexadecimal digits. Generate them on the trusted host with a
tenant-scoped keyed hash or an equivalent stable opaque mapping; retain that
mapping under company custody. Never put tokens, private keys, passwords,
credential-bearing URLs or request payloads in the manifest. Names and purpose
are also operator-reviewed nonsecret metadata, not automatically sanitized text.

Every version-2 record retains the source, tenant, assertion authority, manifest
revision and capture time. Runtime/build references and sensitivity labels are
host assertions. They do not attest a running binary or change execution policy.

## Read the map

Start with an agent or resource, then inspect its structured evidence and
relationships. Indexes page within your authorized scope. Shared resources,
owners and credential references cannot reveal agents in another hidden team.
The focused graph supplements accessible lists and tables; a large graph does
not require rendering the entire company inventory.

The evidence labels have distinct meanings:

| Label | Meaning |
| --- | --- |
| Declared permission | A retained task grant with its exact tool/resource selectors and task constraints. It is not a current backend authorization decision. |
| Policy candidate | A separately collected mapped cloud relationship, with its conditions, freshness and known limitations. |
| Host assertion | Company-provided ownership, deployment, resource or credential metadata. |
| Unknown / not collected | The available source cannot establish that fact; this is not proof of no access. |

Approval events, request-time authorization decisions and backend receipt history
are explicitly not collected by this catalog. Current task gates can explain a
known blocker; a clear gate never means a future action will succeed. Use Agent
Ops and the trusted execution/backend audit workflow for actual approvals and
receipts.

## Review permission changes

Compare the current publication with its retained predecessor. Inspect safe
before/after fields, added/removed relationships and the visible affected agents.
Filters can focus on permissions, ownership or bindings. Ownership transfers,
grant edits, resource remapping, deployment credentials and MCP drift are separate
observations. A removed grant is not a claim that every ambient access path was
revoked, and a new graph edge is not proof of effective permission expansion.

Comparison is a net difference between retained snapshots, not a complete event
log. A missing baseline is a coverage gap. Current cloud policy evidence does not
create policy history. Changes hidden by current team visibility are not exposed
through names, old values, relationships or counts.

## Change and recover the catalog safely

Keep the manifest ID stable and increment its revision whenever content changes.
Upgrade collector/query readers before publishing version 2. Publication rejects
same-revision content changes and a version-2-to-version-1 downgrade within a
source generation. An older reader must fail on unsupported data, not strip it.
Retained snapshots, supersession fences and the existing source recovery workflow
continue to govern restoration. Use the reviewed source-generation replacement
procedure for an intentional protocol reset; do not edit graph rows or reuse a
retired source to bypass a fence.

Keep independently captured timestamps intact. A fresh collection of old host
metadata does not make the metadata fresh. Validate the company's actual catalog
source, IdP bindings, retention, backup and operator workflow before rollout.
