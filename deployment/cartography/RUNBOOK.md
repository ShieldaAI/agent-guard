# Cartography pilot operations

This is an isolated single-company pilot. The supplied verification uses synthetic
agents and new Docker resources only. It does not read an existing executor ledger,
use AWS credentials, install a timer, or expose a public listener.

## Prerequisites and layout

Use Linux, macOS with Docker Desktop/Colima, or Linux inside WSL2. Native Windows
is unsupported because this workflow relies on POSIX file ownership, locks and
atomic directory publication. Install Node 22.13+, Python 3.13, uv 0.13.6, Docker Engine 28+
and Docker Compose. The full benchmark reserves 4 CPUs/4 GiB for its disposable
database; provide at least 8 GiB to the Docker VM. Run the benchmark without a
competing test workload.

The pilot and benchmark reject older or unrecognized Docker daemon versions
before starting containers: Docker documents [localhost-port exposure before
28.0.0](https://docs.docker.com/engine/network/port-publishing/#publishing-ports).

From the repository root:

```sh
npm ci --ignore-scripts
npm run build
cd integrations/cartography
uv sync --locked
uv run python scripts/run-pilot.py --output /absolute/new-pilot-report.json
```

The runner creates two successive authenticated Neo4j containers using
[compose.yaml](compose.yaml), a real synthetic durable executor, a loopback
observer, the collector/archive, and the reference HTTP service. It checks all
three reader scopes, collects changes, writes a minimized report, backs up the
archive, stops the inventory stack, checks executor admission, and reconstructs
the graph in a fresh database. It then queries that restored graph through HTTP.
Only a successful complete run returns `status: passed`; interrupted verification
returns a failing exit status. Resources are checked against unique ownership
labels before teardown. No existing database address or Docker project is accepted.

Neo4j has a named data volume during each exercise, authentication enabled, a
digest-pinned image and only a dynamic loopback Bolt port. Database HTTP/HTTPS
interfaces are disabled. Collector and reference processes run on the host to
preserve their existing loopback rules. The launcher creates a private temporary
directory under the user's home because Colima normally shares that location.
It removes that directory on completion. Custom `--directory` paths must be new,
private and available to the Docker daemon; existing directories are refused.
The Docker daemon and the host account remain trusted administrators.

To inspect the live viewer instead of completing the restore exercise:

```sh
uv run python scripts/run-pilot.py --serve --directory /absolute/new-private-pilot
```

Open the printed loopback URL. Read the desired `blue`, `red` or `beta` reference
credential from the printed private `reader-credentials.json` path using your
editor; enter it in the viewer. The launcher never prints credential values.
This viewer reads the two startup observations from the actual synthetic graph;
`--serve` does not start a background polling schedule. For an enrolled pilot,
use the collector CLI's `--watch` mode with its configured five-minute interval.
Its separate
browser-only demo remains labeled as such. Ctrl-C closes the host processes,
container, network and graph volume. A user-selected directory remains available
with private archive/backup/evidence files; it must not be reused as an authority
ledger or silently re-enrolled. No public preview or deployment is created.

## Performance gate

```sh
uv run python scripts/benchmark-pilot.py --profile smoke --samples 100 --output /absolute/new-smoke.json
uv run python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /absolute/new-acceptance.json
```

The acceptance profile publishes exactly 10,000 tasks and 100,000 grants across
100 bounded sources, then times real HTTP `get_agent_access` and `explain_access`
queries. It includes the first cold query, failures and response sizes. It checks
actual graph counts, every query result, publication within 120 seconds per
successful source collection, p95 below two seconds for each operation, and owned
container/tunnel cleanup. Whole-cycle duration is reported separately. A failed
gate produces a nonzero exit code and an explicit failed report. This measures
synthetic bounded reads, not company-wide exhaustive graph queries or AWS API
latency. Hardware and configured limits accompany the measurements.

The separate admission benchmark measures the observer's effect on the executor.
Run these commands from the repository root:

```sh
node scripts/benchmark-admission.mjs --profile smoke --output /absolute/new-admission-smoke.json
node scripts/benchmark-admission.mjs --profile acceptance --output /absolute/new-admission-acceptance.json
```

It creates a fresh file-backed executor for each fixed baseline/polling/polling/
baseline phase. Each starts with 100 tasks and 1,000 grants and runs the same
serial governed no-op workload. Baseline has inventory disabled; polling enables
the actual HTTP observer at a fixed 250 ms cadence, using a separate worker for
response parsing. An independent workload worker sends the serial prepare and
execute HTTP requests in both modes, so synchronous executor work cannot defer
the client's request-start timestamp. This is a deliberate stress cadence; the deployed collector's
default remains five minutes. No existing ledger, credential or cloud account is
used.

Admission latency is the shared `process.hrtime.bigint()` interval from HTTP
execute request initiation in the workload worker to entry into the governed tool
in the executor thread, including queueing, transport and final durable
admission, and excluding tool work and settlement. Prepare, complete execute and
combined request durations and nanosecond timestamp strings are retained too.
Worker startup is outside request timing. Acceptance retains 250 measured
samples and all 50 excluded warmup samples per phase, identifying the cold first
call separately. It pools the two baseline and two polling measured sets and
requires polling p95 / baseline p95 **≤ 1.10**, with no retries or discarded
outliers. Effect/call counts must match, all observer polls must succeed without
busy skips, at least three polls must complete during each measured polling
phase, and every owned resource must close. Poll completion membership is computed
from common-clock completion timestamps within the workload worker's exact measured
interval; message delivery to the executor does not define that boundary.
All poll timings, counts, workload,
hardware and cleanup outcomes are recorded in the private JSON artifact.

The smoke profile retains 100 measured samples per phase and checks correctness;
it reports but does not enforce or certify the 10% regression target. A failed
acceptance run exits nonzero and retains its evidence. Do not rerun until a pass
and discard earlier results; investigate hardware contention or change the
documented workload/implementation before collecting new evidence.

The initial 30 October 2026 admission artifact is retained as explicitly
superseded preliminary evidence. Its workload client shared the executor event
loop, allowing synchronous inventory work to defer request timing and undercount
queueing. Its reported 3.508% regression does not certify the acceptance gate.
The corrected independent-client runs are recorded separately; the earlier raw
measurement is preserved rather than overwritten.

Before optimization, the corrected local acceptance run on 30 October 2026
**failed the 10% performance gate**: admission p95 was 23.545 ms without inventory
and 27.225 ms while polling, a **15.630%** regression. Correctness passed: all 1,000 measured
admissions and 200 retained warmup calls completed with exact effect/budget
counts, the polling phases completed 40 and 39 polls within their measurement
intervals with no failed or busy-skipped polls, and all six owned resources
closed in every phase. That failed raw report remains part of the validation
evidence. Profiling then identified 1,000 repeated HMAC calculations for one
resource reference in each fixture snapshot. A bounded cache scoped to one
snapshot removes that repeated work while preserving reference identity,
validation, wildcard behavior and tenant separation.

After that implementation change and its regression tests, one further
acceptance run on the same day **passed the unchanged 10% gate**. The workload,
independent-client method, fixed phase order, sample counts and threshold were
unchanged. All 1,000 measured admissions and 200 retained warmup calls completed
with exact effect/budget counts; the polling phases completed 41 and 40 polls
during measurement, with no failed or busy-skipped polls. All six owned resources
closed in every phase. The post-change p95 results were:

| Interval | Without inventory | While polling | Regression |
| --- | ---: | ---: | ---: |
| Admission to tool entry | 25.103 ms | 25.961 ms | 3.420% |
| Preparation | 17.506 ms | 22.031 ms | 25.849% |
| Complete execute request | 32.950 ms | 33.151 ms | 0.610% |
| Combined prepare and execute | 50.430 ms | 52.440 ms | 3.986% |

The 10% gate applies to admission, not every individual stage. These are local
macOS arm64/Node measurements with 100 tasks/1,000 grants per fresh executor and
a 250 ms observer cadence; they do not establish production latency or a
completed hosted CI run. The earlier failed report and the new passing report
are both retained in the [validation evidence](validation/README.md), alongside
the graph/recovery reports and the superseded measurement.

The [pilot CI workflow](../../.github/workflows/cartography-pilot.yml) runs the
live restore/rollback exercise and graph/admission smoke profiles on relevant
pull requests. Its manual full-benchmark option runs both acceptance profiles.
It uploads only safe
verification reports for 30 days, never config, credentials, archives or database
volumes. Local measurements do not establish a completed hosted CI run.

## Private backups and reconstruction

Back up collector evidence, never the executor's authority ledger. Stop the
collector before taking the same ingestion lock. The bundle contains validated
snapshots, receipts, health and source/profile metadata, with a versioned manifest
and SHA256 hashes. It excludes endpoint URLs, credential environment names,
credential values and Neo4j configuration. Hashes detect corruption, not malicious
replacement by someone able to rewrite the entire bundle; restrict backup access
and use your approved encrypted backup storage. Retention follows your host policy.

```sh
uv run python -m agent_guard_cartography.pilot_recovery backup \
  --archive-dir /private/collector/archive \
  --lock-file /private/collector/ingestion.lock \
  --enrollment /private/collector/alpha.json \
  --enrollment /private/collector/beta.json \
  --destination /private/backups/new-backup
uv run python -m agent_guard_cartography.pilot_recovery inspect \
  --backup-dir /private/backups/new-backup
uv run python -m agent_guard_cartography.pilot_recovery restore \
  --backup-dir /private/backups/new-backup \
  --lock-file /private/recovery/ingestion.lock \
  --destination /private/recovery/restored-evidence
```

All parent directories must already be private and owned by the operator.
Destinations must not exist or be inside the source archive. Files, links, schema,
hashes and bounds are checked before atomic publication. Restoration does not
activate a collector or change a graph.

For reconstruction, open the approved fresh Neo4j database and call the packaged
`replay_published(session, restored_evidence, inspected['manifest']['sources'],
replay_archive_directory=new_working_archive, lock_file=shared_lock)` API. It
refuses any existing Guard source, snapshot or projection node. It preserves
provider nodes and replays only confirmed published receipts in per-source order;
pending and uncertain/idempotent outcomes are counted and excluded for review.
Do not mix this replay with a running collector. Keep the original restored
evidence unchanged and point resumed collection at the new working archive.

Graph replay currently enforces the default 256 MiB archive and 4,096-snapshot
limits. Increasing limits through the backup/inspect/restore Python APIs does
not raise the replay limits; larger bundles are not supported for graph recovery.

Projection IDs are regenerated. Compare original snapshot IDs, source IDs,
logical entities and content, not physical projection IDs. The replay result
records old/new projection mappings. Cloud joins are not reconstructed from a
backup: recollect approved provider inventory and fresh source observations before
treating cloud coverage as current. A missing retained predecessor is a real gap.
If replay is interrupted, preserve its evidence and repeat against another fresh
Guard graph and new working archive; it never deletes an occupied graph to retry.

A restored/cloned executor is a different operation: obtain a new explicit
enrollment generation and follow the executor recovery policy. Never copy graph
state, collector receipts or graph watermarks into its authority ledger.
After the successor is fully collected, use the explicit
[source lifecycle procedure](SOURCE-LIFECYCLE.md) to supersede its predecessor.
The command journals and fences the old generation; removing an enrollment alone
does not retire it. Backup/replay preserves completed lifecycle decisions and
refuses pending transitions or an incomplete reconstruction archive.

## Operational difference reports and monitoring

```sh
uv run python -m agent_guard_cartography.reference_report \
  --endpoint http://127.0.0.1:8789/v1/query \
  --token-env AGENT_MAP_REPORT_TOKEN \
  --source-id GRAPH_SOURCE_SHA256 \
  --directory /private/collector/differences
```

Provision a separate least-scope reference token through the host's secret
environment. Reports contain counts by entity type, opaque source/projection
IDs, recording time and coverage-gap status. They omit entity names, entity IDs,
arguments, tools, principals and credentials. A private store marker binds files
to this report directory. Each report write prunes valid owned reports older than
30 days, with hard count/byte limits. If reporting stops, operators must apply
their retention cleanup; no background deletion task is installed.
Unexpected/corrupted files fail closed or remain for
operator review; they are never assumed disposable from their names alone.
Reports describe net snapshot differences, not every invocation or intermediate
permission change. Do not poll after every execution.

Monitor source age, independent component freshness, collector failure codes,
publication duration, query failures/latency, disk quota and pending receipts.
Default collection is every five minutes, staleness after fifteen minutes, graph
retirement after one hour, archive retention seven days, and provider freshness
two hours. Alert on repeated errors, a stale mandatory component, quota pressure,
rejected publication or restore mismatch. Logs/reports must not contain tokens,
raw arguments/results or remote MCP descriptors.

## Company rollout and identity gateway contract

The [company identity endpoint](IDENTITY.md) now supplies provider-neutral OIDC
sign-in, direct HTTPS and server-side browser sessions. It calls the same scoped
query service directly. Register one exact issuer/client/callback and bind each
verified subject to an explicit host-owned company/tenant/team scope. Provider
groups, email addresses and company/team claims grant no access; `allTeams` is
always an explicit host setting. The cookie endpoint has no MCP transport.
The existing loopback bearer/MCP service remains available for local clients.

The viewer discovers the endpoint's authentication mode, uses same-origin cookies
and CSRF for company sessions, and clears inventory on logout, expiry and rejected
authorization. Login, CSRF, session rotation, in-flight revocation and bounded
provider exchanges have disposable HTTPS tests. No organization identity provider,
trusted public certificate/domain or AWS account is configured by these tests.
Follow [IDENTITY.md](IDENTITY.md) for private configuration, TLS, revocation and
the remaining company-browser acceptance checks. Do not rewrite Host/Origin or
forward identity headers to bypass either endpoint's authority checks.
Database READ mode is not an authorization boundary;
use separate enforceable reader/collector roles where your Neo4j edition supports
them. Community credentials remain privileged and stay on trusted hosts.

Begin with one non-production executor. Pin source identity/profile/generation,
manifest and account allowlists before enrolling it. The opt-in
[AWS metadata collector](AWS.md) supplies verified single-account IAM role/user
and S3 bucket observations. Its hourly cadence runs inside the observer worker
under the same ingestion lock; AWS failure leaves the previous complete evidence
and does not suppress Guard polling. It requires a reviewed read-only identity,
explicit enrollment and scope, private configuration, and temporary credentials.
An additional `includeIamPolicyEvidence` flag enables bounded IAM policy reads
and owned S3 candidate edges with unknown assessments. Review the additional
account-wide read and policy limits in the [AWS guide](AWS.md#opt-in-to-iam-policy-evidence).
Raw policy data stays inside the worker. The reference viewer presents only
binding-specific candidates with unknown assessments and independent freshness.
After an AWS refresh, wait for a successful Guard poll to renew provider joins;
changed or stale evidence is explicitly unavailable. No AWS collection or timer is enabled
by the synthetic pilot or by installing the package.

Before expanding beyond that pilot, record live AWS join checks, the organization's
SSO/TLS and credential-rotation tests, representative load results, backup storage
and restore evidence, and independent security review. These deployment-specific
gates cannot be satisfied with synthetic credentials.

## Rollback

1. Stop polling and the reference/gateway processes; disable observer endpoints
   through trusted host configuration. Do not revoke task authority as a side
   effect of an inventory rollback.
2. Keep the executor running. Verify a permitted request succeeds and a denied
   resource/tenant request still fails; the automated pilot performs these checks
   with synthetic tools while the graph is absent.
3. Preserve private receipts, failure summaries and backup metadata. Remove only
   uniquely owned disposable resources, or retain production graph volumes under
   the operator's retention policy. Never run broad database deletion as rollback.
4. Diagnose and restore into a fresh reference graph, then verify scope and
   freshness before resuming polling. Execution must remain independent throughout.

References: [Neo4j Docker secrets](https://neo4j.com/docs/operations-manual/current/docker/docker-compose-standalone/)
and [Docker configuration](https://neo4j.com/docs/operations-manual/current/docker/configuration/).
The checked-in image remains pinned to Community 5.26.32 rather than following a
moving image tag.
