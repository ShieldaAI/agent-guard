# Company agent cartography

Agent Map gives a company a read-only inventory of its agents, accountable owners,
declared permissions, resources, deployments, MCP connections and permission-related
changes. Each company operates its own collector, graph and identity provider.
No hosted maintainer account or customer data submission is required.

## How agents get onto the map

**An agent appears on the map only when a person lists it in the host manifest.** Nothing
adds an agent automatically. Two discovery views point at what the manifest may be
missing, so a person can decide whether to declare it; they never create an agent.

| Way to find an agent | Status | What it gives you |
| --- | --- | --- |
| Declare it in the host manifest | **Supported. The only way an agent is created.** | The agent, its owner and team, deployments, resource and execution bindings, credential references and (manifest v3) paths that act without the guard. You can declare an agent that has never run a task. The manifest can be built in host code or [loaded from a reviewed file](#declare-agents-from-a-file). |
| Activity nobody declared (through the executor) | **Discovery lead, all-teams readers** | Tasks and caller principals that ran through an enrolled executor and belong to no declared agent: a count per source in `get_inventory_health`, and the list in `list_undeclared_activity`. |
| Unclaimed cloud identities (AWS collection) | **Discovery lead, all-teams readers** | IAM roles and users of an enrolled AWS account that no declared agent's execution binding names, in `list_unclaimed_identities`. Candidates, not findings. |
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

- **The map is as complete as your manifest.** It is an inventory of declared agents. The
  discovery views give leads, but there is still no figure for how much of your fleet the
  map covers.
- **An undeclared agent is not listed as an agent**, even if it runs tasks through the
  guard. `list_agents`, `list_resources` and the per-agent views do not show it. Its tasks
  and callers appear in the undeclared-activity view below.
- **A declared agent stays listed** until someone edits the manifest, whether or not it
  still runs.
- **Declaring is manual.** A person writes the manifest, in host code or in a reviewed
  file the host loads at startup. There is no viewer form for it, and a change means
  restarting that host.
- **Each executor is enrolled by hand**, up to 128 sources per collector.

To keep the map accurate, generate the manifest from the system that deploys your agents,
review it whenever an agent is added or retired, and work through the two discovery views
below after each change.

### Find what the manifest is missing

Both views are read-only, grant or block nothing, and are shown only to a reader with
all-teams visibility: what they list belongs to no team. A team-scoped reader gets one
fixed note with no names and no counts, and the same note whether or not anything would
be listed. In the viewer they are on the **Discovery** tab.

**Activity nobody declared.** `get_inventory_health` adds `undeclaredActivity` to each
source: how many tasks, and how many caller principals, ran through that executor without
belonging to a declared agent. `list_undeclared_activity` (`sourceId`, `kind` of `tasks`
or `principals`) lists them a page at a time.

- A task is undeclared when no manifest `taskBindings` entry assigns it to a deployment of
  a declared agent. A caller is undeclared when none of its tasks is assigned.
- `parentDeclared: true` marks a task whose direct parent is assigned. That is usually a
  sub-task of a declared agent that only lacks its own binding, not an unknown agent.
- A source enrolled without a manifest counts every task, and says `manifest:
  not_collected`.
- Counting stops at 10,000 per source; the result is then marked as a minimum. If the
  count cannot be read, health still answers and the count reads `unknown`.
- Limit: only activity that goes through an enrolled executor is seen. An agent that does
  not use the guard leaves nothing here.

**Unclaimed cloud identities.** `list_unclaimed_identities` lists the IAM roles and users
of your enrolled AWS accounts whose exact ARN no declared agent's execution binding names.

- These are candidates to review, not findings. Most IAM roles are not agents, and the
  map cannot tell which are.
- An account whose collection is missing, older than the enrolled age limit, or
  inconsistent reads `unknown`, and none of its identities is listed. With no AWS account
  collected at all, the whole answer is `unknown`, never an empty list.
- `bindingsWithoutIdentity: true` means some declared execution binding names no
  identity, so a listed role may be the one it uses.
- Limits: role assumption, instance profiles and federation are not followed, and only
  enrolled AWS accounts are collected (IAM roles and users, nothing else).

Still not available: scanning infrastructure, code, networks or identity providers, and
importing from a CSV, CMDB or service catalog. A coverage figure (declared agents against
observed callers and identities) is also later work.

### Declare agents from a file

`loadInventoryManifestFile(path)` from `@shieldaai/agent-guard-executor/inventory` loads a
reviewed manifest file, so adding an agent is a file change and a restart, not a code
change. It is the manual route for an agent the discovery views turned up, including one
that has never run a task:

```js
import { loadInventoryManifestFile, startInventoryServer } from '@shieldaai/agent-guard-executor/inventory';

const observer = await startInventoryServer({
  executor,
  observers: [{ token, tenantIds: ['example-tenant'], profile: 'host' }],
  manifests: [loadInventoryManifestFile('/etc/agent-guard/manifest.json')],
});
```

A minimal file declares the agent, its owner and nothing else
([examples/agent-manifest.example.json](../../examples/agent-manifest.example.json)):

```json
{
  "schemaVersion": 2,
  "evidenceKind": "host_asserted",
  "source": {
    "companyId": "example-company",
    "sourceId": "company-host",
    "enrollmentGeneration": "catalog-1",
    "inventoryInstanceId": "00000000-0000-4000-8000-000000000001",
    "tenantId": "example-tenant"
  },
  "authorityId": "platform-team",
  "manifestId": "company-catalog",
  "revision": 1,
  "observedAt": "2026-11-11T00:00:00.000Z",
  "owners": [{ "id": "finance-team", "name": "Finance team", "kind": "team" }],
  "credentialReferences": [],
  "agents": [
    {
      "id": "invoice-agent",
      "name": "Invoice assistant",
      "ownerId": "finance-team",
      "teamId": "finance",
      "purpose": "Drafts supplier invoices for review",
      "lifecycleState": "active",
      "ownershipStatus": "assigned",
      "ownershipSource": "platform-team"
    }
  ],
  "deployments": [],
  "taskBindings": [],
  "resourceBindings": [],
  "executionBindings": []
}
```

- **`source` must be your executor's own.** Copy it from
  `executor.inventorySnapshot({ tenantId }).source`; the example values will not match and
  the observer will refuse the snapshot. One file covers one tenant.
- **Keep the file private.** It must be a regular file owned by the user the host runs as,
  with no group or other access (`chmod 600`), at most 2 MiB. A symbolic link, a second
  hard link, invalid UTF-8, invalid JSON or a duplicate member is refused with
  `INVENTORY_MANIFEST_FILE_INVALID`. Never put secrets in it.
- **The path comes from your host's configuration**, as an absolute path. Never take it
  from a request, a task or an agent.
- **It is read once.** The host keeps the validated copy; an edit takes effect when you
  restart the host. Raise `revision` whenever the content changes.
- **The content gets the same checks as a manifest built in code**
  (`validateInventoryManifest`), with the same error codes.
- Limit: POSIX only. On Windows the loader throws `INVENTORY_MANIFEST_FILE_UNSUPPORTED`;
  build the manifest in host code there.

## Connect your catalog

1. Deploy the current collector and Map service using the existing
   [Cartography runbook](../../deployment/cartography/RUNBOOK.md) and
   [company sign-in guide](../../deployment/cartography/IDENTITY.md).
2. Enroll each executor source and tenant with the trusted host. Obtain its exact
   source identity and exported resource selectors from a core inventory snapshot.
3. Provide a private, operator-reviewed version-2 host manifest, in host code or as a
   [file loaded at startup](#declare-agents-from-a-file). Use the
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
