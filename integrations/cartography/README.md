# Agent Guard Cartography integration

Experimental implementation of the inventory contract and graph milestones in
[the integration plan](../../docs/cartography-integration-plan.md). It validates
single-tenant inventory files and enrolled observer responses, imports declared grants through Cartography's data
model, and publishes immutable graph snapshots. Agent Guard's execution path is
unchanged.

This implementation supports the **core** inventory profile (source identity,
tasks, principals, tools, resource selectors and grants), the **host** profile,
which adds a validated host-owned manifest, and the **host-mcp** profile for managed
connection and operation observations. Host assertions describe agents,
deployments, resource mappings and execution identities without changing grants.
Optional cloud joins record separate evidence from existing AWS inventory;
they do not change the executor's cloud coverage field or its authority.
The executor provides a trusted-host
`inventorySnapshot({ tenantId })` API; see its [README](../../packages/executor/README.md).
A separate loopback `startInventoryServer()` now adds tenant-scoped observer
authentication and bounded complete responses. The collector supports serial
multi-source polling, protected replay and retention. The scoped reference service,
viewer and isolated pilot tooling are implemented; see the [runbook](../../deployment/cartography/RUNBOOK.md)
for measured performance, backup/reconstruction and deployment-specific rollout gates.

## Run the checks

Requirements: Python 3.13, `uv`, Node >=22.13, and a running local Docker engine. The integration
uses Cartography **0.144.0** and the dependencies in `uv.lock`; it does not add
Python or Neo4j dependencies to the npm packages.

Build the executor from the repository root first:

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

The unit suite executes the built TypeScript exporter against a temporary encrypted
ledger and validates its output with the independent Python contract. It covers
tenant isolation, normalized grants, delegation and provenance, repeated read-only
snapshots, revocation, persistent identity, and unavailable tool flags after restart.
Missing Node or missing build output fails this check instead of silently skipping it.
Only this repository test bridge needs Node; installed Python consumers do not.
An additional actual HTTP bridge validates authenticated observer responses and
checks denied scopes, wrong credentials, filter rejection and response caps. The
Python consumer receives the same snapshot contract over either path. A third
bridge exercises manifest composition and host-profile observer delivery, including
invalid source/ARN mappings and preservation of all core authority fields. The MCP
bridge connects a real SDK server and managed client to the durable executor and
checks lifecycle transitions, descriptor drift, removal and observer delivery.

The last command creates a uniquely named **Neo4j Community 5.26.32** container
using the version and multi-platform digest in [neo4j-image.txt](neo4j-image.txt).
Authentication is enabled with a generated password. It publishes only a random
loopback Bolt port, uses temporary data and capped resources, and removes its own
container and volumes on completion or failure. It accepts no existing database
URL. Integration fixtures check container ownership before opening a session;
Docker being unavailable is a failure, not a skipped validation.

For Colima installations that do not forward VM loopback ports, the runner can
create a temporary SSH tunnel using the active Colima connection. The database
remains bound to loopback. The tunnel and temporary connection file are removed
with the container; no persistent Colima settings are changed.

The integration cases cover authenticated connectivity, two successive snapshots,
idempotency, revision and content conflicts, partial-load failures, required
relationship validation, two-tenant cleanup isolation, an existing cloud-node
sentinel, and protection of current/previous projections. Host-profile cases also
check binding edges, manifest revision/content conflicts, profile pinning and
cleanup of failed or retired metadata projections. Tests use synthetic
data and do not call cloud APIs or read provider credentials.

## Inventory contract

The canonical schema is
[agent-guard-inventory-v1.schema.json](../../schemas/agent-guard-inventory-v1.schema.json),
using JSON Schema Draft 2020-12. It is bundled into both the wheel and source
archive, alongside the standalone
[manifest schema](../../schemas/agent-guard-inventory-manifest-v1.schema.json) and
[MCP connection schema](../../schemas/agent-guard-mcp-inventory-v1.schema.json);
installed consumers do not need this repository. Python additionally
checks graph references and cross-record invariants that JSON Schema cannot express.

| Field | Contract |
| --- | --- |
| `schemaVersion`, `profile` | Exactly `1`; profile `core`, `host` or `host-mcp`. |
| `source` | Exact company, source, enrollment generation, ledger instance and tenant identity. |
| `snapshotId`, `generatedAt` | Immutable snapshot identifier and valid UTC timestamp. |
| `ledgerRevision`, `policyEpoch` | Nonnegative JavaScript-safe integers. |
| `coverage` | Tasks/tools complete; host manifest complete with its own capture time; host-mcp coverage computed from observations; cloud uncollected or unavailable. |
| `tasks` | Identity, parent and provenance references, grants, budgets, usage, recipients and state. |
| `tools` | Registration/approval evidence and safe flags; unavailable live flags are `null`. |
| `manifest` | Required for `host` and `host-mcp`, forbidden for `core`; exact source, independent revision and closed host assertions. |
| `mcp` | Required only for `host-mcp`; capture time and one observed/unavailable record per manifest connection ID. |

The validator rejects unknown properties at every object level, duplicate IDs or
JSON keys, non-finite numbers, invalid timestamps, cross-tenant task records,
missing task references and cycles. It limits input to 8 MiB, 32 JSON nesting
levels, 10,000 tasks, 10,000 tools and 100,000 resource selectors, with an additional
aggregate value/work bound. Errors use stable codes and omit imported values.

Task grants are normalized to one entry per tool with unique resource selectors.
The executor exporter merges duplicate tool grants from raw task options
before producing this profile. A grant can reference a tool absent from the
registration inventory; the graph preserves its unknown metadata. Tool names are
not interpreted as read/write/delete actions. `*` is a local wildcard selector,
not an edge to every discovered cloud resource.

Delegation (`parentTaskId`) and provenance (`sourceTaskId`) remain separate. The
validator checks relationship consistency without evaluating authorization or
rejecting an inventory merely because a task is revoked, expired or blocked.
Only the actual executor and resource backend may authorize execution.

## Host assertions and bindings

`validate_manifest()` enforces the standalone 2 MiB/200,000-value contract and its
cross-record/ARN rules. `validate_snapshot()` also checks exact manifest source,
coverage timestamp, and task/tool/resource references against the core inventory.
Manifest validation does not contact AWS or accept a manifest as authorization.
See the [executor guide](../../packages/executor/README.md#host-owned-manifest-and-bindings)
for the input shape and the runnable `examples/inventory-manifest.mjs`.

The graph adds `GuardAgent`, `GuardDeployment`, `GuardResourceBinding`,
`GuardExecutionBinding`, `GuardExternalResource` and `GuardExternalIdentity` inside
the same immutable projection. Every new node carries `evidence_kind='host_asserted'`,
`assessment='unknown'` and manifest provenance. Task-to-deployment associations are
optional; unassigned tasks remain visible. Resource mappings include the local
tool and exported selector plus the exact target account/partition/ARN, kind,
scope and explicit actions. Wildcard grants never fan out to mapped cloud resources.

Execution bindings belong to a deployment and tool. Only a declared static identity
has an identity edge; dynamic/unknown selection remains unresolved. A connection
ID does not establish a live MCP connection. Follow the explicit
task→deployment→execution-binding association when interpreting metadata; sharing
a tool name or caller principal does not share execution identities. External
reference nodes are scoped host assertions, not provider inventory or IAM permission
edges. In particular, S3 account ownership is asserted by the host because its ARN
omits the account. Bucket, object and prefix scopes are retained separately.

The first import pins the source profile. Changing core↔host or `manifestId`
requires a new enrolled generation; mixing profiles cannot silently erase host
metadata. `manifest.revision` advances independently of `ledgerRevision`.
Decreasing revisions and different associations at the same manifest revision are
rejected at staging and publication. Capture-time-only refreshes and reordered
equivalent records are allowed. A manifest update at an unchanged ledger revision
still must preserve identical core authority content. Failed composition or
publication leaves the previous current snapshot in place.

## MCP observations

`GuardMcpConnection` nodes are scoped to the inventory source and host connection
ID. Observed records carry lifecycle, manager session and independent inventory,
authorization and metadata revisions. Unavailable records carry only the capture
status/reason and provenance, so a new projection cannot retain an old `ready`
state. `GuardMcpOperation` nodes carry only explicitly bound operation names, kinds
and fingerprints. Host execution bindings use `G_VIA_CONNECTION`; connections
use `G_EXPOSES_OPERATION`, and operations use `G_OPERATION_TOOL` to reference the
matching executor tool. These relationships are evidence with unknown assessment,
not permission decisions or joins to a task principal's cloud permissions.

The independent validator checks tenant scope, exact manifest connection coverage,
operation allowlists, executor registration/fingerprints and computed coverage.
The importer enforces per-session revision monotonicity and same-revision content
consistency. A changed manifest may change the exposed operation subset. New
sessions may reset counters; retired sessions cannot reappear. Failed or missing
captures preserve internal revision watermarks while publishing unavailable
current nodes. These checks run again at publication to protect against races.

Watermarks are bounded to 128 connection IDs over an enrollment and 64 retired
sessions per connection. Rotate `enrollmentGeneration` for an intentional reset
or when those limits are reached. Changing inventory profile also requires a new
enrollment. No descriptor, endpoint, resource URI, credential or native transport
session is stored by this projection. The CLI imports files or enrolled observer responses;
connection capture happens in the host, not in Cartography.

## Observer collection and restart recovery

Create trusted enrollment files from host-reviewed deployment information. Each
fixes the entire five-field source identity, profile, exact observer endpoint and
the name of a credential environment variable. Start with
[observer-enrollment.json](examples/observer-enrollment.json), replacing its
placeholder enrollment/ledger IDs and port. The credential is a separate
`agi_v1.…` observer token; do not put it in the enrollment file or command line.
Neither an incoming snapshot nor discovery can enroll a new ledger or tenant.

With `NEO4J_URI`, `NEO4J_PASSWORD` and `AGENT_GUARD_OBSERVER_TOKEN` supplied by the
host's secret configuration, run from this directory:

```sh
uv run agent-guard-cartography \
  --enrollment examples/observer-enrollment.json \
  --archive-dir "$PWD/.collector-archive" \
  --neo4j-uri "$NEO4J_URI" \
  --lock-file "$PWD/.collector.lock"
```

This performs one collection. Add `--watch` for a five-minute polling cycle;
`--interval-seconds` accepts 1–3,600 seconds. Repeat `--enrollment` for up to 128
sources in one serial queue. A source failure does not prevent the others from
being collected; a one-shot run exits nonzero if any source fails. The worker
holds the shared database lock between polls, so another manual or scheduled
worker cannot overlap. Credential environment variables are read for each attempt.
Use Ctrl-C to stop cleanly. Every worker must share the same lock path and volume.

HTTP is permitted only for literal loopback addresses. Remote endpoints require
verified HTTPS, the exact `/v1/inventory/snapshot` path, and a host-deployed TLS
bridge. Redirects, ambient proxies, compressed/chunked replies, duplicate length
headers and duplicate JSON keys are rejected. Capture requires a complete
length-delimited JSON response within 8 MiB and ten seconds by default; enrollment
can tighten those bounds (maximum deadline 60 seconds). The total deadline also
covers DNS and validation through four bounded worker slots. Late DNS completion
cannot send credentials after cancellation. No AWS API is called by this collector.

`SnapshotArchive` writes validated snapshots before graph import, with atomic
replacement, directory synchronization and private owned files. The directory
must have mode 0700; files must have mode 0600. Symlinks, hard-linked files and
unsafe ownership are rejected. Use a real directory path, including on systems
where `/tmp` is a symlink. Snapshots retain only the inventory allowlist; observer
credentials, endpoint configuration and response error bodies are excluded.

Each successful CLI line includes a `receipt_id`. After a crash, use the same
enrollment/archive with `--replay-receipt RECEIPT_ID`; no observer token is needed
for replay. The archive checks content hashes, source, profile and snapshot ID
again, and the importer applies the normal revision and idempotency rules.
Replay never restores executor authority. A successful replay of an old receipt
does not move the current graph pointer backwards.

Private health files retain the latest attempt/error, last successful receipt,
failure count and source snapshot generation time. A successful import attempt
is distinct from fresh source evidence or the current graph projection; inspect
`GuardSource.current_snapshot_id` for the latter. Errors contain stable codes.
Automatic graph maintenance retains current/previous projections and waits at
least one hour by default (`--retention-seconds`, minimum 60). Archive cleanup
keeps seven days of published snapshots, current/previous graph pointers and
pending or uncertain receipts. It runs before storing a new snapshot and after
publication. Each graph maintenance pass handles at most 32 obsolete projections.

The archive defaults to 4,096 snapshots and 256 MiB; configure
`--archive-max-snapshots` and `--archive-max-bytes` for actual inventory size.
Committed archive files are also capped at four times the snapshot limit.
New snapshots reserve space for both snapshot and receipt before either write;
updates reuse their file slot but still require temporary byte headroom.
Quota exhaustion fails closed. Pending/uncertain receipts require explicit replay
or operator reconciliation and are not silently evicted. Protected directories
and POSIX locks support one host/volume; this is not a distributed lease.

## Single-account AWS metadata collection

The optional `--aws-enrollment` mode now populates the provider metadata needed
by cloud joins. Follow [AWS.md](../../deployment/cartography/AWS.md) and copy
[aws-enrollment.json](examples/aws-enrollment.json) to a protected file. Configure
one exact commercial account, caller ARN, region and three temporary credential
environment names. AWS collection is disabled by default and requires matching
observer enrollment and an explicit cloud scope.

The five fixed SDK operations are STS GetCallerIdentity, IAM ListRoles/ListUsers,
and S3 ListBuckets/GetBucketLocation. Policy documents and other extra returned
fields are discarded. The collector neither assumes roles nor discovers accounts
or credential profiles. It does not run upstream reporting jobs or collect
objects or ACL data. Temporary credentials are frozen
for one owned worker; verified HTTPS, response/page/item/call bounds and an
overall process deadline prevent an unbounded capture.

The observer worker holds one shared ingestion lock. AWS capture runs before
Guard collection when due, defaulting to an hour after the last attempt finishes.
`--watch --interval-seconds 300 --aws-interval-seconds 3600` coordinates both
cadences; no separate scheduler is installed. AWS failures produce safe bounded
receipts, retain the last complete evidence with its original time, and allow
ordinary observer collection to continue. One-shot failures exit nonzero.

Publication uses the pinned Cartography schemas/query builder in one transaction.
`GuardAwsCollection` and `G_AWS_OBSERVED` record complete scoped membership.
An empty capture retires membership while preserving shared provider nodes,
ownership edges and Guard snapshots. Managed cloud joins require current
membership and matching capture/provider evidence; another writer cannot make
an omitted or stale managed observation fresh. Real AWS account validation and
company rollout remain separate work.

Set `includeIamPolicyEvidence: true` in the private enrollment to add the bounded
IAM `GetAccountAuthorizationDetails` read. The complete principal/group/policy
census must resolve; otherwise the full AWS capture fails. The pinned mapper
produces only GetObject/PutObject/ListBucket candidates for observed buckets.
Boundaries and unsupported expressions suppress the affected principal's
candidates. Every result remains `assessment: unknown`, with bucket-summary scope.
Policy byte/statement/work/edge limits apply before publication; documents and
condition values never leave the worker. The graph retains minimized
`G_AWS_POLICY_CANDIDATE` relationships, per-principal coverage and a census digest,
atomically with metadata. Successful opt-out removes only this collection's
candidates. Existing `CAN_*` and other collectors' edges are preserved. See
[the policy guide](../../deployment/cartography/AWS.md#opt-in-to-iam-policy-evidence)
for limits, unsupported semantics and rollout. The reference API/viewer now
exposes candidates only through visible task/deployment execution and resource
bindings, with provenance/freshness checks and explicit unknown assessments.
It preserves object/prefix scope and omits live policy observations from history.

## AWS inventory joins

Use `--cloud-scope examples/cloud-scope.json` only after reviewing its explicit
company, tenant, partition and AWS account allowlist. Repeat this option for
different company/tenant scopes in a multi-source run. Unlisted scopes receive
no cloud enrichment. Cloud configuration is also available as `cloud_scope=` on
`import_snapshot()` and `build_sync()`.

The supported provider model is pinned to Cartography 0.144.0: exact `AWSRole`
and `AWSUser` ARN/ID plus `AWSPrincipal`, or exact `AWSS3Bucket` ARN/name, owned
through the configured `AWSAccount`'s `RESOURCE` relationship. Account, node and
ownership timestamps must all be present, non-future and within `maxAgeSeconds`
(default two hours). Explicit bucket regions must match. Missing, ambiguous,
unsupported, out-of-scope or stale matches create no positive provider link.
Lookups are limited to 1,024 external references and a five-second transaction.

`G_CLOUD_MATCH` means an exact role/user/bucket association. Object and prefix
references retain their original ARN/kind/scope and use `G_CLOUD_CONTAINER` to
their exact bucket. Dynamic/unknown execution identity creates no principal join.
The collector never joins a task's calling principal by name or borrows another
execution binding's identity. All cloud assessments remain `unknown`.

Cloud evidence is rechecked in the bounded publication transaction. Changes or
optional lookup failures publish explicit unavailable evidence with fresh
mandatory inventory; no old successful joins are reused. A narrowly scoped
retry drops failed cloud capture while preserving the same publication CAS.
The graph stores independent `cloud_coverage_json`, reference status/reason,
capture time and the three provider timestamps (Unix seconds). Complete coverage
means the configured references matched, not complete AWS discovery or effective
permission. Shared provider nodes/edges may change independently after capture.
Cleanup removes only Guard nodes and their outgoing links.

The opt-in policy reducer uses the reviewed
[S3 permission mapping](../../deployment/cartography/aws-permission-relationships.yaml)
for the enrolled account. The YAML is also packaged at
`agent_guard_cartography/data/aws-permission-relationships.yaml`. It selects
GetObject, PutObject and ListBucket evidence only. Only condition keys/flags are
retained; conditional denies and object/prefix-to-bucket projection limit what
those edges prove. Missing edges never prove denial, and bucket edges never
establish permission over an exact object or every object. No provider policy
blobs or condition values are copied into Guard observations.

## File import into a dedicated sandbox

The CLI is a host-side collector; keep it outside agent tool access.
Supply an independent, trusted source enrollment file and a database password
through an environment variable. Do not derive a trusted enrollment from an
untrusted incoming inventory.

Snapshot, observer enrollment, expected-source/cloud-scope and lifecycle
transition inputs must resolve to regular files. Named pipes, devices and
directories are rejected before reading; symlinks to regular files remain
supported. Existing byte limits and JSON/schema validation still apply. Private
AWS enrollment and archive files retain their stricter path/permission checks.

For a dedicated local sandbox whose Bolt endpoint and password are already set:

```sh
uv run agent-guard-cartography \
  --snapshot tests/fixtures/alpha-v1.json \
  --expected-source examples/alpha-source.json \
  --neo4j-uri "$NEO4J_URI" \
  --neo4j-password-env-var NEO4J_PASSWORD \
  --lock-file .agent-guard-cartography.lock
```

Import `alpha-v2.json` with the same enrollment to publish the next view. The
disposable test runner exercises this CLI automatically, so a manual database is
not required to verify the milestone. The CLI emits a JSON receipt containing
the scoped source key and projection ID. Exit status is nonzero on invalid
inventory, source mismatch or incomplete import.

The CLI constructs one explicit Cartography `Sync` stage. It does not invoke
default provider discovery. It uses a POSIX file lock; every worker targeting the
same database must use the same protected lock path on the same host/volume.
Distributed collection and Windows locking are outside this milestone. Verified
TLS is required for remote database endpoints; cleartext is limited to loopback.

## Publication and cleanup

`GuardSource` is keyed by the full enrolled source tuple. Every import attempt
creates a distinct `GuardSnapshot` projection; task/tool/grant/resource/principal
nodes carry both a versioned storage ID and a stable logical `entity_id`.

Cartography loads endpoints first, then their relationships. Publication validates
node counts and required relationship endpoints and atomically updates
`current_snapshot_id` and `previous_snapshot_id`. A failed or losing import stays
unpublished. Replaying an identical completed snapshot returns its receipt without
moving the current pointer; reusing its ID for different content is rejected.

Always select a published projection through `GuardSource.current_snapshot_id`.
An unrestricted label scan includes staged, failed and historical evidence.
For example, with the source key returned by the CLI as `$sourceId`:

```cypher
MATCH (s:GuardSource {id: $sourceId})
MATCH (p:GuardSnapshot {id: s.current_snapshot_id, status: 'published'})
MATCH (t:GuardTask)-[:G_IN_SNAPSHOT]->(p)
OPTIONAL MATCH (t)-[:G_HAS_GRANT]->(g:GuardGrant)
RETURN t.task_id, t.revoked, g.tool, g.resources, g.assessment,
       p.generated_at, p.coverage_json
```

All grants remain `evidence_kind='declared'`, `assessment='unknown'`. The graph
does not make effective-permission claims. `G_DELEGATED_FROM` and `G_DERIVED_FROM`
preserve distinct task relationships. Raw arguments, results, credentials, token
hashes, memory bodies and arbitrary tool metadata are not contract fields.

Cleanup runs the real Cartography `GraphJob` with `GuardSnapshotId` restricted to
one unpublished projection. Retirement targets only allowlisted Guard labels in
an old projection, preserves its receipt, and refuses current/previous views.
Provider nodes are never cleanup targets. Retirement has a configurable grace
period. The optional [Agent Map service](../../packages/agent-map/README.md)
reads current/previous published projections through fixed scoped queries;
it does not hold unbounded historical cursors.

The file lock and pointer compare-and-set protect this single-worker experiment.
They are not a distributed ingestion service. Revision comparison can detect
rollback but cannot prove an unreported restore did not occur. Restores/clones
must use explicit new enrollment generations. The host can now run an explicit
source transition after the successor is fully published and archived. It fences
old-generation imports, removes the predecessor from normal reads, and preserves
the decision through backup/replay. Completed transition journals drive bounded
post-grace graph retirement; the latest two archived snapshots per source remain
recovery anchors. Missing enrollments and outages never trigger supersession.
See [source lifecycle operations](../../deployment/cartography/SOURCE-LIFECYCLE.md).

## Build and check the packaged contract

```sh
uv build
uv run --isolated --no-project \
  --with dist/agent_guard_cartography-0.1.0a1-py3-none-any.whl \
  python scripts/check-installed.py
```

The installed consumer checks the bundled schema against the canonical contract,
validates the synthetic fixtures, and imports the custom stage with Cartography
0.144.0. `hatch_build.py` also includes the schema when building a wheel from the
source archive, without relying on an external repository path.

## Pilot operations

The [pilot runbook](../../deployment/cartography/RUNBOOK.md) covers the new
Compose-backed live synthetic deployment, private archive backup and fresh-graph
reconstruction, bounded 30-day minimized differences, rollback and benchmark gates.
The collector accepts plaintext database connections only through direct
`bolt://` literal-loopback addresses; routing `neo4j://` is rejected because its
advertised peers may be remote. Remote connections require verified TLS.

```sh
uv run python scripts/run-pilot.py --output /absolute/new-verification.json
uv run python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /absolute/new-benchmark.json
```

Both runners create and verify ownership of their own disposable databases. The
live runner compares graph snapshot/logical-content identity after restore and
executor authority before/after collection and reconstruction. Packaged
`pilot_recovery` and `reference_report` modules are included in wheel/source-archive
consumer checks. Company SSO/TLS and live AWS deployment need separate approved
configuration and review; the supplied pilot uses synthetic data and local
credentials only.

The [company identity endpoint](../../deployment/cartography/IDENTITY.md) adds
provider-neutral OIDC/HTTPS browser access to the same scoped Neo4j reader.
Its disposable integration test signs in through a local verified HTTPS issuer,
checks hidden/nonexistent equivalence and host scope despite broader signed
claims, revokes the reader and verifies no graph mutation. This exercises the
implementation without enrolling a real company identity provider.

## Compatibility baseline

- Cartography release `0.144.0`, source commit
  `66ead780c590c2db63947286fa8d5131f44697f8`.
- Cartography wheel SHA256
  `89ee88f4fca44a1a74e10de253475f14ba84154b5e88c908ad2a34412b26872a`,
  also recorded in `uv.lock`.
- Python 3.13; Neo4j Community 5.26.32 at the pinned image digest.
- Apache-2.0 integration and Cartography code; Neo4j remains a separate GPLv3
  Community service. Community credentials do not establish database-level
  read-only or per-team permissions.

The contract/collector checks do not establish live cloud coverage or production
throughput. The reference milestone additionally tests company/tenant/team
visibility in the real Neo4j query adapter; it does not establish company SSO,
remote deployment or database-level isolation on Community edition.

Validation recorded on 29 October 2026: **84 unit cases and 15 Neo4j integration
cases passed with no skips**, using Python 3.13.10 on macOS arm64 with Colima,
Cartography 0.144.0, Neo4j driver 6.4.1 and the pinned Community 5.26.32 server.
Ruff lint/format checks, lockfile verification, wheel/source-archive builds and an
isolated installed-wheel consumer check passed. The disposable container and
tunnel were removed. The separate Ubuntu CI workflow is included; these results
are from the local run, not a completed hosted CI run.
