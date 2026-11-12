# Agent Guard Cartography integration

`agent-guard-cartography` is a Python collector that reads complete inventory
snapshots from Agent Guard executors, validates them, keeps a private copy on
disk and publishes each one into Neo4j as an immutable snapshot, using
[Cartography](https://github.com/cartography-cncf/cartography)'s data model. The
[Agent Map service](../../packages/agent-map/README.md) reads that graph to show
which agents exist, what they were granted and what changed.

The collector only reads. It never changes what the guard allows or what the
executor runs, and nothing in the graph is an authorization decision: every
grant, binding and cloud match is recorded with `assessment: unknown`.

The package is experimental (version `0.1.0a1`).

## What you need

- **Python 3.13** on Linux or macOS (Linux inside WSL2 also works). Native Windows
  is not supported: the archive and lock rely on POSIX ownership and file locks.
- **[uv](https://docs.astral.sh/uv/)**, to install the locked dependencies.
- **Neo4j 5.23 or later.** That is what the Agent Map service, which reads this
  graph, requires; the collector's own queries are tested only against Neo4j
  Community 5.26.32. A remote database
  must be reached with verified TLS (`bolt+s://` or `neo4j+s://`); plaintext
  `bolt://` is accepted only for a literal loopback address.
- **An Agent Guard executor that runs the inventory observer.** The host (your
  trusted application code) starts it with `startInventoryServer()` and issues an
  `agi_v1.…` observer token; see the
  [executor guide](../../packages/executor/README.md#inventory-experimental).
  The [agent cartography guide](../../docs/guides/agent-cartography.md) walks
  through the whole setup, executor included.

Optional: AWS IAM and S3 metadata for one account ([AWS.md](../../deployment/cartography/AWS.md)).

## Install

From a checkout of this repository:

```sh
cd integrations/cartography
uv sync --locked
```

This installs four commands into the project environment; run them with
`uv run <command>`:

| Command | Purpose |
| --- | --- |
| `agent-guard-cartography` | Collect enrolled executors, or import one snapshot file. |
| `agent-guard-recovery` | List and discard pending receipts; back up, restore and replay the archive. |
| `agent-guard-source-lifecycle` | Replace one enrolled source generation with its successor. |
| `agent-guard-map-report` | Store counts of what changed between two snapshots. |

To install on another host, build a wheel with `uv build` and install
`dist/agent_guard_cartography-0.1.0a1-py3-none-any.whl` there. Each command is
also available as a module, for example
`python -m agent_guard_cartography.pilot_recovery` for `agent-guard-recovery`.

## Collect your first executor

1. Choose where the collector keeps its files. Every example in this
   documentation uses the same two private directories:

   ```sh
   CONFIG="$HOME/.config/agent-guard-cartography"       # enrollment files
   STATE="$HOME/.local/share/agent-guard-cartography"   # archive, lock, backups
   install -d -m 700 "$CONFIG" "$STATE"
   ```

2. Write the enrollment. Copy the example and replace its placeholders with the
   executor's real identity, profile and observer address:

   ```sh
   install -m 600 examples/observer-enrollment.json "$CONFIG/observer.json"
   ```

   An enrollment fixes the five-field source identity (`companyId`, `sourceId`,
   `enrollmentGeneration`, `inventoryInstanceId`, `tenantId`), the profile, the
   exact observer endpoint and the *name* of the environment variable that
   holds the observer token. The token itself never goes in a file or on the
   command line.

3. Provide the two secrets through the environment and run one collection:

   ```sh
   export NEO4J_PASSWORD=...                 # from your secret store
   export AGENT_GUARD_OBSERVER_TOKEN=...     # the agi_v1 token for this executor

   uv run agent-guard-cartography \
     --enrollment "$CONFIG/observer.json" \
     --archive-dir "$STATE/archive" \
     --neo4j-uri bolt://127.0.0.1:7687
   ```

   On success it prints one JSON line with `"status": "complete"`, the
   `receipt_id` of the stored snapshot and an `import_result` whose `source_id`
   identifies this source in the graph. The archive directory is created on the
   first run.

4. Keep it running. Add `--watch` to collect every five minutes
   (`--interval-seconds`, 1–3,600). Repeat `--enrollment` to collect several
   executors in one serial queue. Stop with Ctrl-C or SIGTERM.

Then start the [Agent Map service](../../packages/agent-map/README.md) against
the same database to query the result.

## How collection works

### Profiles

| Profile | Contents |
| --- | --- |
| `core` | Source identity, tasks, principals, tools, resource selectors and grants. |
| `host` | `core` plus a manifest written by the host: agents, owners, deployments, resource bindings and execution identities. |
| `host-mcp` | `host` plus observed Model Context Protocol (MCP) connections and the operations they expose. |

The first import fixes a source's profile. Changing it requires a new
`enrollmentGeneration`.

### One collection, step by step

1. **Fetch.** One authenticated `POST` to the enrolled
   `/v1/inventory/snapshot` endpoint. HTTP is allowed only to a literal loopback
   address; anything else needs verified HTTPS. Redirects, proxies from the
   environment, compressed or chunked replies and duplicate headers are refused.
   The response must be complete JSON within 8 MiB and ten seconds (an
   enrollment can lower both; the deadline can be raised to 60 seconds).
2. **Validate.** The snapshot is checked against the bundled JSON schemas and
   cross-record rules (see [Inventory contract](#inventory-contract)), and its
   source and profile must equal the enrollment's.
3. **Archive.** The snapshot and a *receipt* are written to the archive before
   anything touches the graph.
4. **Publish.** The snapshot is loaded as a new projection and published in one
   transaction that moves the source's `current_snapshot_id`. A failed import
   leaves the previous view in place.
5. **Maintain.** Old projections and archive files are retired (see
   [Retention](#retention-and-archive-sizing)).

Observer collection calls no AWS API. AWS is contacted only when you pass
`--aws-enrollment`.

### The archive and the lock

The archive directory must be owned by the collector's user with mode 0700; its
files have mode 0600. Symlinks, hard-linked files and files owned by someone else
are refused. It holds, per snapshot, `<receipt id>.snapshot.json` and
`<receipt id>.receipt.json`, plus one `health-<source id>.json` per source and
any `lifecycle-*.json` journals. It contains no credentials or endpoints.

Every command that reads or writes an archive holds that archive's lock for its
whole run, so only one runs at a time; `--watch` holds it until it stops. The
lock is the file `<archive directory>.lock` beside the archive directory:
`$STATE/archive.lock` for `$STATE/archive`. It is derived from the archive's
location alone, so no option is needed and the working directory does not
matter. `agent-guard-recovery restore` locks the file beside its
`--destination`, the archive it creates; `inspect` takes no lock. The command's
user must be able to create that file in the archive's parent directory. It is a
POSIX file lock on one host and volume, not a distributed lease. The file is
never removed; do not delete it while a command runs.

`--lock-file FILE` names a second lock to hold as well; it never replaces the
archive's. Use it when two commands write the same Neo4j database without
sharing an archive: two collectors with separate archives, or a file import
(`--snapshot`), which has no archive. A file import without `--lock-file` locks
`.agent-guard-cartography.lock` in its working directory. If you upgrade a
deployment that relied on `--lock-file` or on that working-directory file, see
[upgrading the lock](../../deployment/cartography/RUNBOOK.md#upgrading-the-lock).

A file the archive did not write, such as macOS `.DS_Store`, is never read or
counted; the collector names it once in an `ARCHIVE_FILE_IGNORED` warning. An
unreadable receipt fails only the source it belongs to, is reported every cycle
as `ARCHIVE_FILE_DAMAGED` and is kept until you repair or discard it. A receipt
is unreadable when its content is invalid, or when the file is not a private
file of the collector's user (wrong mode or owner, a second hard link): repair
that one with `chmod 600`, and the next cycle accepts it again.

While it runs, the collector keeps an index of the archive in memory instead of
re-reading the directory, and checks once per cycle for files that something
else added, removed, rewrote or changed the mode, owner or links of. The files
it acts on — the receipt and snapshot being published, replayed or discarded —
are always read and verified from disk, and pruning deletes a file only if it
is still the one that was indexed.

### Pending receipts and replay

A receipt is *pending* until the graph publishes its snapshot. The failure line
of a snapshot that was stored but not published carries its `receipt_id`.

One kind of rejected snapshot is not kept. When the graph refuses a newly
collected snapshot because it already holds a newer view of the source
(`REVISION_ROLLBACK`, or `GENERATED_AT_ROLLBACK` at the same revision), no retry
could ever publish it: the failure is reported without a `receipt_id` and
recorded in the source's health file, and nothing is stored. An executor whose
clock was set back therefore fails each poll with `GENERATED_AT_ROLLBACK` until
its clock passes the published capture, then publishes again by itself.

- **Replay** a pending receipt with the same enrollment and archive. No observer
  token is needed:

  ```sh
  uv run agent-guard-cartography \
    --enrollment "$CONFIG/observer.json" \
    --archive-dir "$STATE/archive" \
    --neo4j-uri bolt://127.0.0.1:7687 \
    --replay-receipt RECEIPT_ID
  ```

  The archive verifies the snapshot's hash, source and profile again, and the
  importer applies its normal rules. A snapshot the graph already published
  returns its existing result and moves nothing. A pending snapshot is published,
  and becomes the current one, only if it is not older than the current view: a
  lower ledger revision is refused with `REVISION_ROLLBACK`, and at the same
  revision a capture generated before the published one is refused with
  `GENERATED_AT_ROLLBACK`.

- **List and discard** with the collector stopped:

  ```sh
  uv run agent-guard-recovery pending --archive-dir "$STATE/archive"
  uv run agent-guard-recovery discard --archive-dir "$STATE/archive" \
    --receipt-id RECEIPT_ID --reviewed
  ```

  `pending` changes nothing; add `--enrollment` to list one source. `discard`
  requires `--reviewed` and removes one pending, uncertain, invalid or orphaned
  record. An *uncertain* receipt is one the graph already knew when it was
  replayed, so nothing confirmed what it published; retention never removes it.
  `discard` refuses a published receipt (`ARCHIVE_DISCARD_REFUSED`; retention
  removes those) and a receipt whose file has unsafe permissions or cannot be
  read (`ARCHIVE_FILE_UNSAFE`, `ARCHIVE_READ_FAILED`): repair the file instead.

A source may hold 16 pending receipts (`--archive-max-pending`, 1–1,024). After
that its new snapshots are refused with `ARCHIVE_PENDING_LIMIT_EXCEEDED` until
you replay or discard some; other sources continue.

### Retention and archive sizing

Every poll stores a new snapshot, even when nothing changed:

```text
snapshots needed = sources × (retention seconds ÷ interval seconds + 1)
bytes needed     = snapshots needed × average snapshot size
```

| Limit | Default | Maximum | Option |
| --- | --- | --- | --- |
| Snapshots | 4,096 | 100,000 | `--archive-max-snapshots` |
| Bytes | 256 MiB | 8 GiB | `--archive-max-bytes` |
| Archive retention | 7 days | 90 days (minimum 1 hour) | `--archive-retention-seconds` |
| Pending receipts per source | 16 | 1,024 | `--archive-max-pending` |
| Graph retention | 1 hour | 30 days (minimum 60 seconds) | `--retention-seconds` |
| Enrollments | — | 128 | `--enrollment` |

One source at the default 300-second interval and seven-day retention needs
2,017 snapshots, so **the defaults hold two sources**. The maximum holds 49
sources at those settings; 128 sources fit with about 2.7 days of retention, or
a longer interval. Pass the same `--archive-*` values to every command that
opens the archive.

The archive always keeps the newest two publications of each source, every
snapshot a graph pointer refers to, and every pending or uncertain receipt.
Older published snapshots are removed once they pass the retention age. If the
archive fills first, the collector removes the oldest of them early and warns
with `ARCHIVE_RETENTION_SHORTENED`; a source fails with `ARCHIVE_LIMIT_EXCEEDED`
only when nothing more can be removed. Every collection run, one-shot or
`--watch`, refuses to start (`ARCHIVE_SIZING_INVALID`) when
`--archive-max-snapshots` is below three per enrolled source; a receipt replay
does not check. `--watch` also warns once at startup
(`ARCHIVE_SIZING_INSUFFICIENT`) when the limit cannot hold the retention window.

In the graph, a source's current and previous projections are never retired.
Other projections are retired after `--retention-seconds`, at most 32 per source
per cycle.

### Output and exit status

All four commands report the same way. Each success is one JSON line on stdout.
Each failure is one JSON line on stderr: `{"status": "failed", "code": "…"}`,
with `source_id`, `receipt_id`, `file` or `operation` when they apply. Codes are
stable and never contain paths, messages or credentials. `"status": "warning"`
lines do not change the exit status.

A command line that cannot be parsed is the one exception: for an unknown or
missing option, or a value outside its range, the command prints a usage line
and `<command>: error: <message>` as plain text on stderr and exits 2 before it
does anything.

| Exit status | Meaning |
| --- | --- |
| 0 | Everything completed. A `--watch` run stopped by Ctrl-C or SIGTERM also exits 0. |
| 1 | An unexpected failure (`COLLECTION_FAILED`, `IMPORT_FAILED`, `RECOVERY_FAILED`, `SOURCE_TRANSITION_FAILED`, `REFERENCE_REPORT_FAILED`). |
| 2 | A failure with a specific code, such as `NEO4J_UNAVAILABLE`, `NEO4J_AUTH_FAILED`, `PROCESS_LOCK_PATH_INVALID`, `INGESTION_ALREADY_RUNNING`, `COLLECTOR_ENROLLMENT_NOT_FOUND` or `REFERENCE_QUERY_FAILED`; or a command line that could not be parsed. |
| 130, 143 | A one-shot run interrupted by Ctrl-C or SIGTERM. |

One failing source does not stop the others; a one-shot run exits nonzero if any
source failed. If maintenance fails after a publication, the success line
reports `"maintenance": "unavailable"` with a `maintenance_code` and the run
exits 2. Every command accepts `--verbose`, which also logs the exception type
and message as a `"status": "debug"` line, with credential values redacted.

## Reference

### Inventory contract

The schemas are JSON Schema Draft 2020-12 files in [`schemas/`](../../schemas),
bundled into the wheel: inventory
[v1](../../schemas/agent-guard-inventory-v1.schema.json) and
[v2](../../schemas/agent-guard-inventory-v2.schema.json), manifest
[v1](../../schemas/agent-guard-inventory-manifest-v1.schema.json),
[v2](../../schemas/agent-guard-inventory-manifest-v2.schema.json) and
[v3](../../schemas/agent-guard-inventory-manifest-v3.schema.json), and the
[MCP connection schema](../../schemas/agent-guard-mcp-inventory-v1.schema.json).
The [contract document](../../docs/agent-cartography-contract.md) lists the fields.

| Field | Contract |
| --- | --- |
| `schemaVersion`, `profile` | `1` or `2`; `core`, `host` or `host-mcp`. |
| `source` | Exact company, source, enrollment generation, ledger instance and tenant. |
| `snapshotId`, `generatedAt` | Immutable snapshot identifier and UTC timestamp. |
| `ledgerRevision`, `policyEpoch` | Nonnegative JavaScript-safe integers. |
| `coverage` | Which components were collected, and when. |
| `tasks` | Identity, parent and provenance references, grants, budgets, usage, recipients and state. |
| `tools` | Registration and approval evidence; flags the executor could not observe are `null`. |
| `manifest` | Required for `host` and `host-mcp`, forbidden for `core`. |
| `mcp` | Required for `host-mcp` only: one observed or unavailable record per manifest connection. |

The validator rejects unknown properties at every level, duplicate IDs and JSON
keys, non-finite numbers, invalid timestamps, tasks of another tenant, missing
task references and reference cycles. Limits: 8 MiB, 32 nesting levels, 10,000
tasks, 10,000 tools, 100,000 resource selectors, and 2 MiB for a manifest. Errors
are stable codes that never quote imported values.

Rules worth knowing when you read the graph:

- A grant can name a tool that is not registered; the tool node then has
  `known_metadata = false`. Tool names are not interpreted as read or write
  actions, and `*` is a local wildcard selector, not an edge to every resource.
- Delegation (`parentTaskId`, `G_DELEGATED_FROM`) and provenance
  (`sourceTaskId`, `G_DERIVED_FROM`) are separate relationships.
- A revoked, expired or blocked task is still inventory; the validator does not
  evaluate authorization.

### Host manifest

The host writes the manifest; it is an assertion, not a verified claim, and it
never changes grants. See the
[executor guide](../../packages/executor/README.md#inventory-experimental)
for its shape and [how agents get onto the map](../../docs/guides/agent-cartography.md#how-agents-get-onto-the-map).

- **Nodes:** `GuardAgent`, `GuardOwner`, `GuardCredentialReference`,
  `GuardDeployment`, `GuardDirectAccess` (manifest v3: paths a deployment has that
  bypass the guard), `GuardResourceBinding`, `GuardExecutionBinding`,
  `GuardExternalResource` and `GuardExternalIdentity`. Each carries
  `evidence_kind = 'host_asserted'` and the manifest's ID, revision and
  observation time.
- **Agents** exist only if the manifest declares them. A task not assigned to a
  deployment stays in the graph but is listed under no agent.
- **Resource bindings** map one local tool and selector to one exact target
  (account, partition, ARN, kind and scope). A wildcard grant never fans out to
  mapped resources. Targets with `provider: host` are opaque IDs that never join
  AWS nodes.
- **Execution bindings** belong to a deployment and a tool. Only a declared
  static identity gets an identity edge; a dynamic or unknown identity stays
  unresolved.
- **Credential references**, issuers, audiences and build references are opaque
  host identifiers. There are no secret, token or URL fields; the host must keep
  names and purpose text free of secrets.
- **Revisions:** `manifest.revision` advances independently of `ledgerRevision`.
  A lower revision, different content at the same revision, a different
  `manifestId` and a lower manifest schema version are all refused. Moving from
  manifest v1 to v2 requires a higher revision.

Limits: 1,000 owners and 1,000 credential references per manifest, 32 credential
references and 32 direct-access entries per deployment, 128 entries in each
dependency, destination, audience and recipient list.

### MCP observations

`GuardMcpConnection` nodes are scoped to the source and the host's connection
ID. An observed record carries its lifecycle state, session and revisions; an
unavailable record carries only the reason, so a new projection never shows a
stale `ready` state. `GuardMcpOperation` nodes carry operation names, kinds and
fingerprints. Edges: `G_VIA_CONNECTION` (execution binding to connection),
`G_EXPOSES_OPERATION` and `G_OPERATION_TOOL` (operation to the executor tool).

The importer refuses a session whose revisions go backwards, different content
at the same revision, and a retired session that reappears. It remembers at
most 128 connection IDs per enrollment and 64 retired sessions per connection;
past that, publication fails with `MCP_ENROLLMENT_ROTATION_REQUIRED` and you
enroll a new `enrollmentGeneration`. No descriptor, endpoint, resource URI or
credential is stored. Connections are observed by the host, not by this
collector.

### Reading the graph

`GuardSource` is keyed by the full source identity. Every import creates a
`GuardSnapshot` projection; each node has a per-projection `id` and a stable
`entity_id`. Always select through the source's current pointer — a plain label
scan also returns staged, failed and historical projections:

```cypher
MATCH (s:GuardSource {id: $sourceId})
MATCH (p:GuardSnapshot {id: s.current_snapshot_id, status: 'published'})
MATCH (t:GuardTask)-[:G_IN_SNAPSHOT]->(p)
OPTIONAL MATCH (t)-[:G_HAS_GRANT]->(g:GuardGrant)
RETURN t.task_id, t.revoked, g.tool, g.resources, g.assessment,
       p.generated_at, p.coverage_json
```

Publication checks node counts and every expected relationship before it moves
the pointer. Importing an identical snapshot again returns its existing result;
reusing a snapshot ID for different content is refused. Retirement removes only
this integration's nodes in one old projection; provider nodes such as
`AWSRole` are never deleted.

<a id="file-import-into-a-dedicated-sandbox"></a>

### Import a snapshot file

For a sandbox database, import one prepared file instead of collecting. The
expected source comes from a separate trusted file, never from the snapshot:

```sh
uv run agent-guard-cartography \
  --snapshot tests/fixtures/alpha-v1.json \
  --expected-source examples/alpha-source.json \
  --lock-file "$STATE/archive.lock" \
  --neo4j-uri bolt://127.0.0.1:7687
```

A file import has no archive, so it has no lock of its own. `--lock-file` above
names the collector's archive lock, which keeps the import from running beside a
collector that writes the same database; see
[the archive and the lock](#the-archive-and-the-lock).

It prints the source ID and projection ID. Input files must be regular files
(symlinks to regular files are followed); pipes, devices and directories are
refused.

### AWS metadata and cloud joins

Both are optional and off by default; [AWS.md](../../deployment/cartography/AWS.md)
is the operator guide.

- `--cloud-scope FILE` allows the importer to link host-declared AWS references
  to provider nodes already in the graph, for the listed company, tenant and
  accounts only. `G_CLOUD_MATCH` is an exact role, user or bucket match;
  `G_CLOUD_CONTAINER` links an object or prefix reference to its bucket. A match
  needs one provider node whose account, node and ownership timestamps are all
  within `maxAgeSeconds` (default two hours). Missing, ambiguous, out-of-scope
  or stale matches create no link, and the reason is recorded. At most 1,024
  references are looked up per import.
- `--aws-enrollment FILE` makes the collector capture IAM role and user
  identifiers and S3 bucket names and regions for one account, using five fixed
  read-only API operations, and publish them as the provider nodes those joins
  need. With `includeIamPolicyEvidence: true` it also reads the account's IAM
  identity policies and writes `G_AWS_POLICY_CANDIDATE` edges for three S3
  actions. The three rules are fixed in the collector;
  [aws-permission-relationships.yaml](../../deployment/cartography/aws-permission-relationships.yaml)
  states the same rules for upstream Cartography and is not read by this package.

A candidate edge or a cloud match is evidence, never proof of access, and a
missing edge is never proof of denial.

### Operator guides

- [RUNBOOK.md](../../deployment/cartography/RUNBOOK.md): the synthetic end-to-end
  check, backups and reconstruction, difference reports, monitoring, rollback.
- [SOURCE-LIFECYCLE.md](../../deployment/cartography/SOURCE-LIFECYCLE.md):
  replacing an executor that was restored or cloned.
- [AWS.md](../../deployment/cartography/AWS.md): AWS metadata and policy evidence.
- [IDENTITY.md](../../deployment/cartography/IDENTITY.md): company sign-in for
  the Agent Map viewer.

## Develop and test

Besides Python 3.13 and uv you need Node 22.13 or newer and a running Docker
engine. Build the JavaScript packages from the repository root first (the unit
tests run the built executor against the Python contract):

```sh
npm ci --ignore-scripts
npm run build
```

Then, from this directory:

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest tests/unit
uv run python scripts/test-disposable-neo4j.py -- -q
```

The last command starts its own Neo4j container from the image pinned in
[neo4j-image.txt](neo4j-image.txt), with a generated password and a random
loopback port, runs `tests/integration` against it and removes it. It accepts no
existing database address. Missing Node, missing build output or an unavailable
Docker engine fail the run; nothing is skipped silently. Tests use synthetic data
and call no cloud API.

To check the built package in isolation:

```sh
uv build
uv run --isolated --no-project \
  --with dist/agent_guard_cartography-0.1.0a1-py3-none-any.whl \
  python scripts/check-installed.py
```

## Versions and limits

- Cartography `0.144.0`, pinned with its hash in `uv.lock`; Python 3.13; Neo4j
  Community 5.26.32 for tests.
- Apache-2.0. Neo4j Community is a separate GPLv3 service.
- One collector process per database, on one host. There is no distributed
  ingestion.
- Neo4j Community has no per-user read permissions: anyone with database
  credentials can read every tenant's inventory. Keep the credentials on trusted
  hosts and give readers access through the Agent Map service instead.
- A revision comparison detects a rollback, not an unreported restore. An
  executor that was restored or cloned must be enrolled with a new
  `enrollmentGeneration`; see
  [SOURCE-LIFECYCLE.md](../../deployment/cartography/SOURCE-LIFECYCLE.md).
