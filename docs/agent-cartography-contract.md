# Inventory data formats

This is the reference for the two JSON formats behind Agent Map: the **host manifest**, in
which your company declares its agents, and the **inventory snapshot**, in which the
executor reports the tasks and tools it holds. It also covers the Model Context Protocol
(MCP) connection record that a snapshot can carry.

**Experimental.** These formats and the `@shieldaai/agent-guard-executor/inventory`
functions that read them are not covered by semantic versioning. They can change in a
minor release.

Both formats describe what exists. Nothing in them grants a permission, approves an
action or changes what the guard allows. Terms such as host, tenant and task family are
defined in the [glossary](glossary.md).

The executor produces a snapshot for one tenant. The host writes a manifest for the same
tenant. `composeInventorySnapshot(core, manifest)` checks one against the other and
returns a snapshot that contains both. The [Agent Map guide](guides/agent-cartography.md)
walks through it.

## Value types

Every format uses the same basic types. All objects are closed: an unknown field is an
error, and every field listed in this document is required unless it says otherwise.
"or `null`" means the field must be present and may hold `null`.

| Type | Rule |
| --- | --- |
| Identifier | A string that is not blank, has no NUL character and is at most 4,096 characters. |
| Display name | An identifier of at most 256 characters. |
| Description | An identifier of at most 1,024 characters. |
| Opaque reference | `opaque:` followed by exactly 64 lowercase hexadecimal digits. It stands for a value the host keeps private, such as a credential or a database name. |
| Timestamp | UTC, in the form `2026-11-11T09:00:00Z`, with up to six fractional digits. |
| Count | A whole number from 0 to 9,007,199,254,740,991. |

Generate opaque references on the host, for example with a keyed hash of the real value,
and keep the mapping private. Never put a token, key, password or credential-bearing URL
in either format.

## Host manifest

**Purpose.** The manifest is the host's statement of which agents exist, who owns them,
where they run and what their tools reach. An agent appears on the map only if a manifest
lists it. One manifest covers one tenant of one executor.

**Schemas.** [version 1](../schemas/agent-guard-inventory-manifest-v1.schema.json),
[version 2](../schemas/agent-guard-inventory-manifest-v2.schema.json),
[version 3](../schemas/agent-guard-inventory-manifest-v3.schema.json).

**Validator.** `validateInventoryManifest(value)` returns a frozen copy or throws.
`loadInventoryManifestFile(path)` reads a private file and then runs the same checks.

### Top-level fields

| Field | Versions | Type | Meaning |
| --- | --- | --- | --- |
| `schemaVersion` | all | `1`, `2` or `3` | The manifest version. |
| `evidenceKind` | all | `"host_asserted"` | Always this value. |
| `source` | all | object | Which executor and tenant the manifest belongs to. See below. |
| `manifestId` | all | identifier | A stable name for this manifest. Keep it the same across revisions. |
| `revision` | all | count | Raise it every time the content changes. |
| `observedAt` | all | timestamp | When the host gathered this information. |
| `agents` | all | list | The declared agents. |
| `deployments` | all | list | Where each agent runs. |
| `taskBindings` | all | list | Which deployment each task belongs to. |
| `resourceBindings` | all | list | What a granted resource really is. |
| `executionBindings` | all | list | Which identity or MCP connection a tool uses in a deployment. |
| `authorityId` | 2, 3 | identifier | The system or team that vouches for these statements. |
| `owners` | 2, 3 | list | The people, teams and services that can own agents and resources. |
| `credentialReferences` | 2, 3 | list | Credentials that deployments use, described without their values. |
| `directAccess` | 3 | list | Paths that act without the guard. `[]` means the host declared none. It does not mean anyone checked. |

`source` has five identifiers: `companyId`, `sourceId`, `enrollmentGeneration`,
`inventoryInstanceId` and `tenantId`. Copy them from the executor's own snapshot
(`executor.inventorySnapshot({ tenantId }).source`). Composition fails with
`INVENTORY_MANIFEST_SOURCE_MISMATCH` if any of the five differs.

### Records

**`agents`**

| Field | Versions | Type |
| --- | --- | --- |
| `id` | all | identifier, unique |
| `name` | all | identifier; display name from version 2 |
| `ownerId` | all | identifier or `null` |
| `teamId` | all | identifier or `null`. Agent Map uses it to decide which readers see the agent. |
| `purpose` | 2, 3 | description or `null` |
| `lifecycleState` | 2, 3 | `active`, `inactive`, `retired` or `unknown` |
| `ownershipStatus` | 2, 3 | `assigned`, `unassigned` or `unknown` |
| `ownershipSource` | 2, 3 | identifier or `null`: where the ownership fact came from |

From version 2, `assigned` requires an `ownerId` that names an entry in `owners`.
`unassigned` and `unknown` require `ownerId: null`. Use `unassigned` only when your
records say the agent has no owner, and `unknown` when they cannot tell.

**`deployments`**

| Field | Versions | Type |
| --- | --- | --- |
| `id` | all | identifier, unique |
| `agentId` | all | the `id` of a declared agent |
| `environment` | all | identifier or `null` |
| `runtimeRef` | 2, 3 | opaque reference or `null` |
| `workloadGeneration` | 2, 3 | identifier or `null` |
| `buildRef` | 2, 3 | opaque reference or `null` |
| `bindingAuthority` | 2, 3 | identifier or `null`: who bound this runtime to the agent |
| `credentialReferenceIds` | 2, 3 | list of `credentialReferences` ids, no duplicates |

**`taskBindings`**

| Field | Type |
| --- | --- |
| `taskId` | identifier, unique. Must be a task in the snapshot. |
| `deploymentId` | the `id` of a declared deployment |

**`resourceBindings`**

| Field | Versions | Type |
| --- | --- | --- |
| `id` | all | identifier, unique |
| `tool` | all | a tool name that appears in the snapshot |
| `resourceRef` | all | a resource selector exactly as the snapshot exports it for that tool. Not `*`. Each (`tool`, `resourceRef`) pair appears once. |
| `target` | all | an AWS resource; from version 2, an AWS or a host resource |
| `actions` | all | 1 or more identifiers, no duplicates. For an AWS target each is `service:Action` with the service of the ARN. |
| `scope` | all | `exact` or `prefix`. For an AWS target it is `prefix` only when the target `kind` is `prefix`. |
| `displayName` | 2, 3 | display name |
| `ownerId`, `ownershipStatus`, `ownershipSource` | 2, 3 | as for agents |
| `sensitivity` | 2, 3 | `public`, `internal`, `confidential`, `restricted` or `unknown` |
| `approvedDestinations` | 2, 3 | list of opaque references, no duplicates |
| `dependsOn` | 2, 3 | list of other resource binding ids, no duplicates, not its own |

An AWS resource target is
`{ provider: "aws", partition, accountId, region, arn, kind }`. `partition` is `aws`,
`aws-cn` or `aws-us-gov`; `accountId` is 12 digits; `region` must match the ARN and is `""`
when the ARN has none; the ARN has no spaces and no `*` or `?`. `kind` is `bucket`,
`object` or `prefix` for S3 and `resource` for every other service.

A host resource target (version 2 and later) is
`{ provider: "host", id, name, kind }`. `id` is an opaque reference, `name` a display
name, and `kind` one of `service`, `repository`, `database`, `queue`, `storage` or `other`.
The same `id` must carry the same `name` and `kind` everywhere in the manifest.

**`executionBindings`**

| Field | Type |
| --- | --- |
| `id` | identifier, unique |
| `tool` | a tool name that appears in the snapshot |
| `deploymentId` | the `id` of a declared deployment. Each (`deploymentId`, `tool`) pair appears once. |
| `connectionId` | identifier or `null`: the name of the MCP connection the tool uses |
| `identitySelection` | `static`, `dynamic` or `unknown` |
| `identity` | for `static`, `{ provider: "aws", partition, accountId, region: "", arn }` where the ARN is an IAM role, IAM user or STS assumed role. Otherwise `null`. |

**`owners`** (version 2 and later)

| Field | Type |
| --- | --- |
| `id` | identifier, unique |
| `name` | display name |
| `kind` | `person`, `team` or `service` |

**`credentialReferences`** (version 2 and later)

| Field | Type |
| --- | --- |
| `id` | opaque reference, unique |
| `name` | display name |
| `issuerRef` | opaque reference or `null` |
| `audienceRefs`, `recipientRefs` | lists of opaque references, no duplicates |
| `lifecycleState` | `active`, `rotating`, `revoked`, `expired` or `unknown` |
| `expiresAt` | timestamp or `null` |
| `rotationStatus` | `current`, `due`, `overdue` or `unknown` |

**`directAccess`** (version 3)

Each entry is a path the host says can act without going through the guard, such as an
operations shell or a direct database connection.

| Field | Type |
| --- | --- |
| `id` | opaque reference, unique |
| `deploymentId` | the `id` of a declared deployment |
| `kind` | `shell`, `database`, `network`, `sdk`, `mcp` or `other` |
| `targetRef` | `null`, or the `id` of a host resource target that a resource binding in this manifest uses |
| `description` | description |

### Limits

| What | Limit |
| --- | --- |
| Whole manifest | 2 MiB of JSON, 200,000 values, 32 levels of nesting |
| `agents`, `deployments`, `owners`, `credentialReferences` | 1,000 entries each |
| `taskBindings`, `resourceBindings`, `executionBindings` | 10,000 entries each |
| `directAccess` | 1,000 entries in total, 32 per deployment |
| `credentialReferenceIds` on a deployment | 32 |
| `actions`, `approvedDestinations`, `dependsOn` on a resource binding | 128 each |
| `audienceRefs`, `recipientRefs` on a credential reference | 128 each |

### Example

A valid version 3 manifest with one agent, one deployment and one declared direct path:

```json
{
  "schemaVersion": 3,
  "evidenceKind": "host_asserted",
  "source": {
    "companyId": "example-company", "sourceId": "support-host", "enrollmentGeneration": "enrollment-1",
    "inventoryInstanceId": "00000000-0000-4000-8000-000000000001", "tenantId": "example-tenant"
  },
  "authorityId": "platform-team",
  "manifestId": "company-catalog",
  "revision": 1,
  "observedAt": "2026-11-11T09:00:00.000Z",
  "owners": [{ "id": "support-team", "name": "Support team", "kind": "team" }],
  "credentialReferences": [],
  "agents": [{
    "id": "support-agent", "name": "Support assistant", "ownerId": "support-team", "teamId": "support",
    "purpose": "Answers customer tickets", "lifecycleState": "active",
    "ownershipStatus": "assigned", "ownershipSource": "platform-team"
  }],
  "deployments": [{
    "id": "support-prod", "agentId": "support-agent", "environment": "production",
    "runtimeRef": null, "workloadGeneration": null, "buildRef": null, "bindingAuthority": null,
    "credentialReferenceIds": []
  }],
  "taskBindings": [],
  "resourceBindings": [],
  "executionBindings": [],
  "directAccess": [{
    "id": "opaque:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "deploymentId": "support-prod", "kind": "shell", "targetRef": null,
    "description": "On-call engineers can open a shell in the support container"
  }]
}
```

### What changed between versions

| Version | Change |
| --- | --- |
| 1 | Agents, deployments, task bindings, resource bindings to AWS resources, execution bindings. |
| 2 | Adds `authorityId`, `owners` and `credentialReferences`. Agents gain purpose, lifecycle and ownership. Deployments gain runtime, build and credential references. Resource bindings gain a display name, ownership, sensitivity, approved destinations and dependencies, and can target a host resource as well as an AWS one. |
| 3 | Version 2 plus the required `directAccess` list. |

Version 1 and version 2 manifests are still accepted. A reader that does not know a
version rejects the manifest; it never drops the fields it does not understand.

### Publishing a new revision

The collector compares each manifest with the one it last published for the same source.
It refuses a lower `revision` (`MANIFEST_REVISION_ROLLBACK`), changed content under the
same `revision` (`MANIFEST_CONTENT_CONFLICT`), a lower `schemaVersion`
(`MANIFEST_SCHEMA_ROLLBACK`) and a different `manifestId` (`MANIFEST_ID_CONFLICT`).
Reordering a list or changing `observedAt` does not count as a content change.

## Inventory snapshot

**Purpose.** A snapshot is the executor's complete list, for one tenant, of tasks, their
grants and budgets, and the tools those grants name. It is a point-in-time record, not a
decision about what a task may do next.

**Schemas.** [version 1](../schemas/agent-guard-inventory-v1.schema.json),
[version 2](../schemas/agent-guard-inventory-v2.schema.json).

**Producers.** `executor.inventorySnapshot({ tenantId })` returns a core snapshot. The
executor must be created with the `inventory` option. `composeInventorySnapshot` and
`composeMcpInventorySnapshot` validate their input and return the larger profiles.

### Top-level fields

| Field | Versions | Type | Meaning |
| --- | --- | --- | --- |
| `schemaVersion` | all | `1` or `2` | The snapshot version. |
| `profile` | all | `core`, `host` or `host-mcp` | `core` holds tasks and tools. `host` adds the manifest. `host-mcp` also adds MCP connection records. |
| `source` | all | object | The same five identifiers as in the manifest. |
| `snapshotId` | all | identifier | A new random id for each snapshot. |
| `generatedAt` | all | timestamp | When the snapshot was produced. |
| `ledgerRevision` | all | count | The revision of the executor's ledger that was read. |
| `policyEpoch` | all | count | The executor's policy epoch at that revision. |
| `coverage` | all | object | What was collected. See below. |
| `tasks` | all | list | Every task of the tenant. |
| `tools` | all | list | The stored tools that those tasks' grants name. |
| `untrustedContextDefault` | 2 | `allow`, `require_approval`, `deny` or `null` | What the executor does with a tool that sets no `untrustedContext` of its own. `null` when unknown. |
| `manifest` | all | manifest | Present for `host` and `host-mcp` only. A version 1 snapshot carries a version 1 or 2 manifest; a version 2 snapshot carries any version. |
| `mcp` | all | object | Present for `host-mcp` only: `{ observedAt, connections }`. |

**`coverage`** has one entry per kind of data:

| Entry | Value |
| --- | --- |
| `tasks`, `tools` | `{ status: "complete", observedAt }` |
| `manifest` | `{ status: "not_collected" }` in a core snapshot; `{ status: "complete", observedAt }` otherwise |
| `mcp` | `{ status: "not_collected" }`, or in a `host-mcp` snapshot `{ status, observedAt }` with `complete`, `partial` or `unavailable` |
| `cloud` | `{ status: "not_collected" }` |

`not_collected` means the snapshot says nothing about that subject. It never means "none".

### Tasks

| Field | Versions | Type |
| --- | --- | --- |
| `id` | all | identifier, unique |
| `tenantId` | all | the snapshot's tenant |
| `principalId` | all | identifier: the caller the task runs for |
| `parentTaskId` | all | a task `id` in the same task family with the same principal, or `null` |
| `sourceTaskId` | all | a task `id` in the same task family, or `null` |
| `familyId` | all | identifier: the task family |
| `grants` | all | list of `{ tool, resources }`, one entry per tool |
| `budget` | all | `{ maxCalls, maxConcurrent, maxCost, deadline }`. `deadline` is Unix time in milliseconds. |
| `allowedRecipients` | all | list of identifiers, no duplicates |
| `allowControlPlane` | all | boolean |
| `revoked` | all | boolean |
| `sensitive` | all | boolean, the same for every task in a family |
| `usage` | all | `{ calls, concurrent, spent, reserved }` |
| `untrusted` | 2 | boolean, the same for every task in a family |

`untrusted` is `true` when the task family has read outside content: text that people
outside your organization can write, such as email, web pages or customer tickets. Once
set it stays set.

By default the executor exports resource selectors and recipients as opaque references,
so a snapshot does not reveal the real names. The selector `*` is exported as `*`. Set
`inventory.referenceMode` to `'raw'` on the executor to export the real values.

### Tools

| Field | Versions | Type |
| --- | --- | --- |
| `name` | all | identifier, unique |
| `fingerprint` | all | 64 lowercase hexadecimal digits (SHA-256 of the tool definition) |
| `revision` | all | count |
| `registered` | all | boolean: the running host has this exact tool version registered |
| `approved` | all | boolean |
| `requiresApproval` | all | boolean; `null` when `registered` is `false` |
| `controlPlane` | all | boolean; `null` when `registered` is `false` |
| `maxCost` | all | count; `null` when `registered` is `false` |
| `readsUntrusted` | 2 | boolean or `null`: the tool returns outside content |
| `untrustedContext` | 2 | `allow`, `require_approval`, `deny` or `null`: what happens to this tool once the task family is `untrusted` |
| `sendsExternal` | 2 | boolean or `null`: the tool can send data outside |

The three version 2 labels are `null` when the tool is not registered or the host did not
declare that label. `null` means unknown, not `false`.

A grant can name a tool the executor has no record of. That tool is simply absent from
`tools`.

### Limits

| What | Limit |
| --- | --- |
| Whole snapshot | 8 MiB of JSON less 16 bytes per task, 500,000 values, 32 levels of nesting |
| `tasks` | 10,000 |
| `tools` | 10,000 |
| `grants` on a task | 2,048 |
| `resources` in a grant | 1,024 |
| Resource selectors across all tasks | 100,000 |
| `allowedRecipients` on a task | 1,024 |
| MCP connections named by a manifest | 128 |
| MCP operations across all connections | 10,000 |

A snapshot over a limit fails with `INVENTORY_LIMIT_EXCEEDED`. The executor never returns
part of a tenant.

### Example

A valid version 2 core snapshot with one task and one tool:

```json
{
  "schemaVersion": 2,
  "profile": "core",
  "source": {
    "companyId": "example-company", "sourceId": "support-host", "enrollmentGeneration": "enrollment-1",
    "inventoryInstanceId": "00000000-0000-4000-8000-000000000001", "tenantId": "example-tenant"
  },
  "snapshotId": "26f9bd0d-decd-46ce-a7ad-6eceba81cbe5",
  "generatedAt": "2026-11-11T09:05:00.000Z",
  "ledgerRevision": 4,
  "policyEpoch": 1,
  "untrustedContextDefault": "allow",
  "coverage": {
    "tasks": { "status": "complete", "observedAt": "2026-11-11T09:05:00.000Z" },
    "tools": { "status": "complete", "observedAt": "2026-11-11T09:05:00.000Z" },
    "manifest": { "status": "not_collected" },
    "mcp": { "status": "not_collected" },
    "cloud": { "status": "not_collected" }
  },
  "tasks": [{
    "id": "ticket-task", "tenantId": "example-tenant", "principalId": "support-app",
    "parentTaskId": null, "sourceTaskId": null, "familyId": "ticket-task",
    "grants": [{
      "tool": "tickets.read",
      "resources": ["opaque:f9784797efdc52dafcade9cceca274263a48273d8343f43db5f4df31f9c099dd"]
    }],
    "budget": { "maxCalls": 5, "maxConcurrent": 1, "maxCost": 0, "deadline": 1794408609923 },
    "allowedRecipients": [], "allowControlPlane": false, "revoked": false,
    "sensitive": false, "untrusted": false,
    "usage": { "calls": 0, "concurrent": 0, "spent": 0, "reserved": 0 }
  }],
  "tools": [{
    "name": "tickets.read",
    "fingerprint": "c1bd36ec245034298d86a12f97696d9c01f96713d390ffc9c9090a99f2b3a091",
    "revision": 1, "registered": true, "approved": true,
    "requiresApproval": false, "controlPlane": false, "maxCost": 0,
    "readsUntrusted": true, "untrustedContext": null, "sendsExternal": null
  }]
}
```

Composing this snapshot with the manifest example above returns a `host` snapshot: the
same fields, `profile: "host"`, a new `snapshotId` and `generatedAt`, the manifest under
`manifest`, and `coverage.manifest` set to `complete`.

### What changed between versions

| Version | Change |
| --- | --- |
| 1 | Tasks, tools, coverage and the optional `manifest` and `mcp` sections. |
| 2 | Adds `untrustedContextDefault`, `untrusted` on every task, and `readsUntrusted`, `untrustedContext` and `sendsExternal` on every tool. Accepts a version 3 manifest. |

The executor emits version 1 unless it has something to say in the new fields: a tool
declares one of the three labels, or a task family is `untrusted`. Composing a version 1
core snapshot with a version 3 manifest returns a version 2 snapshot in which
`untrustedContextDefault` and the tool labels are `null` and every task has
`untrusted: false`.

## MCP connection record

**Purpose.** A connection record is the state of one managed MCP connection at one moment:
who it connects as, whether it is ready, and which operations it offers. A `host-mcp`
snapshot holds one record for each `connectionId` that the manifest's execution bindings
name.

**Schema.** [version 1](../schemas/agent-guard-mcp-inventory-v1.schema.json).

**Validator.** `validateMcpConnectionInventory(value)`. A managed connection from
`@shieldaai/agent-guard-mcp` produces this record with its `inventory()` method.

| Field | Type |
| --- | --- |
| `schemaVersion` | `1` |
| `identity` | `{ serverId, transportRef, principalId, tenantId }`. `transportRef` is an opaque reference; the others are identifiers. |
| `sessionId` | identifier, generated locally |
| `revision`, `authorizationEpoch`, `metadataRevision` | counts |
| `state` | `connecting`, `refreshing`, `ready`, `quarantined` or `closed` |
| `metadataState` | `unobserved`, `current` or `stale` |
| `observedAt` | timestamp |
| `operations` | list of `{ name, kind, fingerprint }`. `name` is unique, `kind` is `tool`, `resource` or `prompt`, `fingerprint` is 64 lowercase hexadecimal digits. |

Only a `ready` connection lists operations, and it must have `metadataState: "current"`
and a `metadataRevision` of at least 1. In any other state `operations` is empty, and
`metadataState` is `unobserved` when `metadataRevision` is 0 and `stale` otherwise.

| What | Limit |
| --- | --- |
| Whole record | 2 MiB of JSON |
| `operations` | 256 |

Example:

```json
{
  "schemaVersion": 1,
  "identity": {
    "serverId": "reports", "principalId": "report-reader", "tenantId": "example-tenant",
    "transportRef": "opaque:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "sessionId": "5b1f6f0e-6a53-4c57-9d0f-2f5f1f1c9a10",
  "revision": 3, "authorizationEpoch": 1, "metadataRevision": 1,
  "state": "ready", "metadataState": "current",
  "observedAt": "2026-11-11T09:00:00.000Z",
  "operations": [{
    "name": "read_report", "kind": "tool",
    "fingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  }]
}
```

Inside a snapshot, each entry of `mcp.connections` is one of:

- `{ connectionId, status: "observed", inventory }`, where `inventory` is the record above
  with `operations` reduced to the tools bound to that connection.
- `{ connectionId, status: "unavailable", reason }`, where `reason` is `missing` (no source
  was supplied for the connection), `capture_failed`, `changed` (the connection changed
  while the snapshot was taken), `scope_mismatch` (it belongs to another tenant) or
  `registration_mismatch` (an operation does not match the tool the executor has
  registered).

## Validation errors

Each validator throws an `ExecutorError` whose `code` is one of these. No error contains
the rejected content.

| Code | Meaning |
| --- | --- |
| `INVENTORY_MANIFEST_INVALID` | The manifest has a missing, unknown or malformed field, a duplicate id, or an unsupported version. |
| `INVENTORY_MANIFEST_LIMIT_EXCEEDED` | The manifest is over a limit. |
| `INVENTORY_MANIFEST_REFERENCE_INVALID` | An id points at something that is not declared: an owner, agent, deployment, credential reference, resource binding or host resource, or, during composition, a task, tool or resource selector that is not in the snapshot. |
| `INVENTORY_MANIFEST_SOURCE_MISMATCH` | The manifest's `source` differs from the snapshot's. |
| `INVENTORY_MANIFEST_FILE_INVALID` | `loadInventoryManifestFile` could not accept the file: wrong owner or permissions, a symbolic link, too large, or not valid JSON. |
| `INVENTORY_MANIFEST_FILE_UNSUPPORTED` | `loadInventoryManifestFile` was called on Windows. |
| `INVENTORY_SNAPSHOT_INVALID` | The snapshot passed to a compose function is malformed. |
| `INVENTORY_LIMIT_EXCEEDED` | The snapshot is over a limit. |
| `INVENTORY_MCP_INVALID` | The MCP connection record is malformed. |
| `INVENTORY_MCP_LIMIT_EXCEEDED` | The MCP connection record, or the set of connections, is over a limit. |
