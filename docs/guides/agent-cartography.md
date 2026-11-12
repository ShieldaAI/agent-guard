# Put your agents on the Agent Map

Agent Map is a read-only inventory of your company's agents: who owns each one, where it
runs, which tools and resources its tasks were given, and what changed. This guide shows
how to declare an agent so it appears there.

Agent Map is experimental. You run every part of it yourself; nothing is sent to a hosted
service. It grants and blocks nothing.

## What you will achieve

- A manifest file that declares one agent and its owner.
- A host that serves that manifest, together with the executor's tasks and tools, to a
  collector.
- A clear picture of what the map shows and what it cannot see.

## Prerequisites

- Node.js 22.13 or later, and this repository built:

  ```sh
  npm ci --ignore-scripts
  npm run build
  ```

- A host that uses the executor (`@shieldaai/agent-guard-executor`). The sample below
  creates a throwaway one.
- Linux or macOS. Loading a manifest from a file does not work on Windows.
- To see the map in a browser you also need Docker, Python 3.13 and `uv`. The
  [Cartography runbook](../../deployment/cartography/RUNBOOK.md) lists exact versions.

## Steps

### 1. Run the example

```sh
node examples/agent-cartography.mjs
```

It builds a manifest in code, starts a local observer and prints the snapshot a collector
would receive. It uses made-up data and no cloud account.

### 2. Write a manifest file

Copy [examples/agent-manifest.example.json](../../examples/agent-manifest.example.json). It
declares one agent, "Invoice assistant", and its owner, "Finance team".

Change these parts:

- **`source`** must be your executor's own. Step 3 shows how to read it. The example
  values will not match yours.
- **`agents` and `owners`**: one entry per agent and per owner. Give each agent an `id`
  that stays the same for its whole life; do not reuse a task id or a caller name.
- **`deployments`, `taskBindings`, `resourceBindings`, `executionBindings`**: add these
  when you want the map to show where an agent runs and what its tools reach.

The [data format reference](../agent-cartography-contract.md) lists every field and limit.
To also record paths that act without the guard, such as an operations shell or a direct
database connection, use manifest version 3 and its `directAccess` list.

Make the file private. The loader refuses a file that other users can read:

```sh
chmod 600 /etc/agent-guard/manifest.json
```

### 3. Serve the manifest from your host

Save this as `map-demo.mjs` in the repository root and run `node map-demo.mjs`. It does
what a real host does at startup, using a temporary copy of the example file.

```js
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import {
  createInventoryObserverToken,
  loadInventoryManifestFile,
  startInventoryServer,
} from '@shieldaai/agent-guard-executor/inventory';

// An executor enrolled for inventory. A real host uses its own database and key.
const executor = new DurableExecutor({
  database: ':memory:',
  encryptionKey: randomBytes(32),
  inventory: { companyId: 'example-company', sourceId: 'company-host', enrollmentGeneration: 'catalog-1' },
});

// Copy the example manifest and give it this executor's source.
const manifest = JSON.parse(readFileSync('examples/agent-manifest.example.json', 'utf8'));
manifest.source = executor.inventorySnapshot({ tenantId: 'example-tenant' }).source;
const file = join(mkdtempSync(join(tmpdir(), 'agent-map-')), 'manifest.json');
writeFileSync(file, JSON.stringify(manifest, null, 2), { mode: 0o600 });

// Load the private file and serve it to a collector.
const token = createInventoryObserverToken();
const observer = await startInventoryServer({
  executor,
  observers: [{ token, tenantIds: ['example-tenant'], profile: 'host' }],
  manifests: [loadInventoryManifestFile(file)],
});

// Ask for a snapshot the way the collector does.
const response = await fetch(`${observer.url}/v1/inventory/snapshot`, {
  method: 'POST',
  headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
  body: JSON.stringify({ tenantId: 'example-tenant' }),
});
const snapshot = await response.json();
console.log(snapshot.profile, snapshot.manifest.agents.map(agent => agent.name));

await observer.close();
executor.close();
```

In your own host, keep three things from this sample: the `inventory` option on the
executor, `loadInventoryManifestFile` with an absolute path from your configuration, and
`startInventoryServer`. Give the token to the collector only. Never put it in a URL or a
log.

### 4. Start the collector, the map service and the viewer

Follow the [Cartography runbook](../../deployment/cartography/RUNBOOK.md) to run the
collector and the map service, and the
[company sign-in guide](../../deployment/cartography/IDENTITY.md) to let people sign in
with your identity provider. Enroll each executor and tenant with the collector by hand.
One collector accepts up to 128 enrollments.

### 5. Check the map

Sign in to the viewer and open **Agent inventory**, **Owners** and **Resources**. Before
you give more people access, confirm three things: an agent you know is listed, a resource
you know is listed, and a reader from another team cannot see a team you meant to hide.

### 6. Keep the manifest current

When an agent is added, retired or changes owner, edit the file, raise `revision` and
restart the host. The file is read once at startup. Then open the **Discovery** view and
work through [what the manifest is missing](#find-what-the-manifest-is-missing).

## What you should see

Step 1 prints one line of JSON that starts with `{"coverage":` and contains
`"profile":"host"`.

Step 3 prints:

```text
host [ 'Invoice assistant' ]
```

After step 5, the viewer lists the agents your manifest declares, each with its owner.

## What can go wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `INVENTORY_DISABLED` | The executor was created without the `inventory` option. | Add `inventory: { companyId, sourceId, enrollmentGeneration }`. |
| `INVENTORY_MANIFEST_FILE_INVALID` | The file is readable by other users, is not owned by the user the host runs as, is a symbolic link or has a second hard link, is over 2 MiB, is not valid UTF-8 JSON, repeats a field name, or the path is not absolute. | Use a regular file with `chmod 600`, owned by the host's user, and pass its absolute path. |
| `INVENTORY_MANIFEST_FILE_UNSUPPORTED` | The host runs on Windows. | Build the manifest in host code and pass it through `validateInventoryManifest`. |
| `INVENTORY_MANIFEST_INVALID` | A field is missing, unknown or malformed, or an id is used twice. | Compare the file with the [data format reference](../agent-cartography-contract.md). |
| `INVENTORY_MANIFEST_REFERENCE_INVALID` | An entry names an owner, agent, deployment or binding that is not declared. | Declare the missing entry or correct the id. |
| `INVENTORY_SERVER_CONFIG_INVALID` at startup | An observer has profile `host` or `host-mcp` but no manifest covers one of its tenants. | Pass one manifest per tenant in `manifests`. |
| The observer answers `503` with `INVENTORY_UNAVAILABLE` | Most often the manifest's `source` is not the executor's, or a binding names a task, tool or resource the executor does not have. | Run `composeInventorySnapshot(executor.inventorySnapshot({ tenantId }), manifest)` in host code. It throws the specific code. |
| The collector refuses the snapshot with `MANIFEST_CONTENT_CONFLICT` | The manifest changed but `revision` did not. | Raise `revision`. |
| An agent runs tasks but is not on the map | Nobody declared it. | Add it to the manifest. Its tasks show up under Discovery until you do. |
| A team-scoped reader sees one fixed note under Discovery | Discovery is for readers who can see all teams. | Ask a reader with all-teams access. |

## How agents get onto the map

**An agent appears on the map only when a person lists it in the host manifest.** Nothing
adds an agent automatically.

| Source | What it gives you |
| --- | --- |
| The host manifest | The agent, its owner and team, deployments, bindings, credential references and declared paths around the guard. This is the only way an agent is created. You can declare an agent that has never run a task. |
| The executor | Tasks, grants, tools and callers. A task is linked to an agent only if `taskBindings` names it. |
| MCP inventory | The state of the Model Context Protocol (MCP) connections that the manifest's execution bindings name. It does not find other MCP servers. |
| AWS collection | IAM roles, IAM users and S3 buckets of one enrolled account, joined to the ARNs the manifest names. See the [AWS guide](../../deployment/cartography/AWS.md). |
| A snapshot file | For a sandbox, the collector can import one prepared snapshot. See the [collector README](../../integrations/cartography/README.md#file-import-into-a-dedicated-sandbox). |

Agent Map does not scan infrastructure, code, repositories, networks or running
processes. It does not list identity-provider or SaaS apps, and it does not import from a
CSV, CMDB or service catalog.

The map is as complete as your manifest and gives no figure for how much of your fleet
it covers. A declared agent stays listed until someone removes it, whether or not it still
runs. To keep the manifest accurate, generate it from the system that deploys your agents.

## Declare agents from a file

`loadInventoryManifestFile(path)` from `@shieldaai/agent-guard-executor/inventory` loads a
manifest file, so adding an agent is a file change and a restart, not a code change. One
file covers one tenant. Take the path from your host's own configuration, never from a
request, a task or an agent. Never put secrets in the file: names and purposes are shown
to readers as written.

## Find what the manifest is missing

Two views point at agents you may not have declared. They are leads for a person to
review. They never create an agent, and only a reader with all-teams access sees them.

| View | What it lists | What it cannot see |
| --- | --- | --- |
| Undeclared activity | Tasks and callers that ran through an enrolled executor and belong to no declared agent. | An agent that does not use the guard. |
| Unclaimed cloud identities | IAM roles and users of your enrolled AWS accounts that no declared agent's execution binding names. | Role assumption, instance profiles, federation, and accounts you have not enrolled. |

A task marked `parentDeclared: true` is usually a sub-task of a declared agent that lacks
its own binding. Most IAM roles are not agents. An account whose collection is missing or
out of date reads `unknown`; it is never shown as an empty list.

The operations behind these views are `get_inventory_health`,
`list_undeclared_activity` and `list_unclaimed_identities`. The
[Agent Map package README](../../packages/agent-map/README.md#discovery) documents their
fields and limits.

## Read the map

Each fact carries a label that says where it came from:

| Label | Meaning |
| --- | --- |
| Declared permission | A grant on a task, with its exact tool and resources. It is what the task was given, not a statement that a call will succeed. |
| Policy candidate | A cloud relationship collected separately from AWS, with its conditions and age. |
| Host assertion | Something your manifest says: ownership, deployment, resource or credential details. |
| Unknown / not collected | The map has no source for this fact. It does not mean "no access". |

The map does not collect approvals, individual allow or deny decisions, or backend
receipts. For those, use the executor's audit records.

The **Changes** view shows the difference between the current snapshot and the previous
one. It is not a log of every event, and a removed grant does not prove that every other
way to reach the resource is closed.

For the viewer, see the [viewer README](../../apps/agent-map/README.md). For queries,
limits and capacity, see the [Agent Map package README](../../packages/agent-map/README.md).
For general limits of Agent Guard, see [Support and limits](../support-and-limits.md).
