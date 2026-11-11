# Company agent cartography

Agent Map gives a company a read-only inventory of its agents, accountable owners,
declared permissions, resources, deployments, MCP connections and permission-related
changes. Each company operates its own collector, graph and identity provider.
No hosted maintainer account or customer data submission is required.

## How agents get onto the map

**An agent appears on the map only when a person lists it in the host manifest.** Nothing
discovers agents automatically. Everything else the collector reads is evidence attached
to agents that a manifest already declared.

| Way to find an agent | Status | What it gives you |
| --- | --- | --- |
| Declare it in the host manifest | **Supported. The only way an agent is created.** | The agent, its owner and team, deployments, resource and execution bindings, credential references and (manifest v3) paths that act without the guard. You can declare an agent that has never run a task. |
| Runtime observation through the executor | Evidence only | Tasks, grants, tools and caller principals of each enrolled executor. A task is linked to an agent only if the manifest's `taskBindings` names it. |
| MCP inventory | Evidence only | Connections and operations for execution bindings the manifest declared. It does not list other MCP servers or tools. |
| AWS collection | Evidence only | IAM roles, IAM users and S3 buckets of one enrolled account, joined to the ARNs your manifest names, plus optional S3 policy candidates. |
| Snapshot file import | Supported for a sandbox | `agent-guard-cartography --snapshot FILE --expected-source FILE --neo4j-uri URI` (with `NEO4J_PASSWORD` set) imports one prepared snapshot, including the agents its manifest declares. |
| Scanning infrastructure for agents (Bedrock, SageMaker, Lambda, containers, Kubernetes, other clouds) | Not available | |
| Scanning code or repositories (agent frameworks, MCP configuration files) | Not available | |
| Scanning the network or running processes | Not available | |
| Listing identity-provider or SaaS apps (OAuth apps, service accounts) | Not available | |
| Importing from a CSV, CMDB or service catalog | Not available | |

What this means in practice:

- **The map is as complete as your manifest.** It is an inventory of declared agents, not
  a discovery tool. It has no figure for how much of your fleet it covers.
- **An undeclared agent is not listed as an agent**, even if it runs tasks through the
  guard. Its tasks, grants and principal are in the graph, but `list_agents`,
  `list_resources` and the per-agent views do not show them. An all-teams reader can still
  see such a task as a changed entity in `get_changes`, or query it by ID with
  `explain_access`.
- **A declared agent stays listed** until someone edits the manifest, whether or not it
  still runs.
- **Declaring is manual and needs host code.** Outside the sandbox snapshot import, there
  is no command, configuration file or viewer form for it: your trusted host builds the manifest and passes it to
  `startInventoryServer({ manifests })`, and a change means restarting that host.
- **Each executor is enrolled by hand**, up to 128 sources per collector.

To keep the map accurate, generate the manifest from the system that deploys your agents,
review it whenever an agent is added or retired, and compare it now and then with a list
you trust, such as your IAM roles or your deployment inventory.

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
   bindings, and credential references from company-owned systems. To also record
   paths that act without the guard (an ops shell, a direct database connection),
   use [manifest v3](../../schemas/agent-guard-inventory-manifest-v3.schema.json)
   and list them in `directAccess`; `[]` declares none.
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
