# Cartography collector operations

This runbook is for the operator of an
[Agent Guard Cartography collector](../../integrations/cartography/README.md).
It covers a synthetic end-to-end check, load measurement, backups and
reconstruction, difference reports, monitoring, rollout and rollback. Install
the collector and run a first collection with the README before using it.

Words used here: **the guard** is the core Agent Guard package, **the executor**
is the executor package that runs governed tools, and **the host** is your
trusted application code that embeds them.

<a id="prerequisites-and-layout"></a>

## Layout used in every example

All collector commands for one database must share one archive; its lock file
lies beside it and every command takes it by itself. The examples use two
private directories:

```sh
CONFIG="$HOME/.config/agent-guard-cartography"       # enrollment files
STATE="$HOME/.local/share/agent-guard-cartography"   # archive, lock, backups
install -d -m 700 "$CONFIG" "$STATE"
```

| Path | Contents |
| --- | --- |
| `$CONFIG/*.json` | Observer, cloud-scope, AWS and source-transition files (mode 0600). |
| `$STATE/archive` | The collector's archive. |
| `$STATE/archive.lock` | The archive's lock. Every command that names the archive takes it; no option is needed. |
| `$STATE/backups/…` | Backups. |
| `$STATE/differences` | Difference reports. |

Run the commands from `integrations/cartography` with `uv run`, or install the
wheel and drop the `uv run` prefix. Parent directories must already exist and
be private; only the collector creates its archive directory.

### Upgrading the lock

Earlier releases locked the file named by `--lock-file`, or
`.agent-guard-cartography.lock` in the working directory when it was omitted.
Each command now locks `<archive directory>.lock` beside its archive
(`$STATE/archive.lock` here) and holds a `--lock-file` only in addition. For an
existing deployment:

1. Stop every collector, lifecycle and recovery command before you install the
   new version. An old command and a new one do not share a lock.
2. Make sure the collector's user can create `$STATE/archive.lock`, that is, can
   write the archive's parent directory. If it cannot, have an administrator
   create the file once, owned by that user
   (`install -o USER -m 600 /dev/null "$STATE/archive.lock"`); otherwise every
   command fails with `PROCESS_LOCK_PATH_INVALID`.
3. A `--lock-file` you already pass keeps working. You may drop it unless it is
   what excludes a second collector with another archive, or a file import,
   from the same database.
4. Delete the old lock files when nothing is running; they are no longer read.

## Run the synthetic end-to-end check

This check uses invented agents and its own Docker resources. It reads no
existing executor ledger, uses no AWS credentials and opens no public listener.

Requirements: Linux, macOS with Docker Desktop or Colima, or Linux inside WSL2;
Node 22.13+, Python 3.13, uv, Docker Engine 28+ with Docker Compose. Older Docker
daemons are refused because they can
[expose published localhost ports](https://docs.docker.com/engine/network/port-publishing/#publishing-ports).

From the repository root:

```sh
npm ci --ignore-scripts
npm run build
cd integrations/cartography
uv sync --locked
uv run python scripts/run-pilot.py --output /absolute/new-report.json
```

The script starts Neo4j from [compose.yaml](compose.yaml) (authentication on,
image pinned by digest, a random loopback Bolt port, HTTP interfaces off), a
synthetic executor with its observer, the collector and the Agent Map service.
It collects twice, queries the map with three reader scopes, writes a
difference report, backs up the archive, stops the inventory stack, checks that
the executor still admits and denies requests, and rebuilds the graph in a
second fresh database. It reports `status: passed` only if every step completed,
and removes the containers, network, volume and its temporary directory.

To look at the result in the viewer instead:

```sh
uv run python scripts/run-pilot.py --serve --directory /absolute/new-private-directory
```

Open the printed loopback URL and sign in with a reader credential from the
printed `reader-credentials.json` path. The script never prints credential
values. `--serve` shows the two startup collections and does not keep polling.
Ctrl-C removes the processes, container, network and volume; the directory you
named stays, with its archive and backup files. Do not reuse it for a real
executor.

<a id="performance-gate"></a>

## Measure load

```sh
uv run python scripts/benchmark-pilot.py --profile acceptance --samples 100 --output /absolute/new-benchmark.json
```

The `acceptance` profile publishes 10,000 tasks and 100,000 grants across 100
synthetic sources into a disposable database (4 CPUs and 4 GiB; give the Docker
VM at least 8 GiB), then times `get_agent_access` and `explain_access` over
HTTP. It fails unless every source publishes within 120 seconds and each
operation's 95th-percentile latency is under two seconds. `--profile smoke` is a
two-source version. The numbers describe that synthetic workload on your
hardware, not a production deployment.

To measure what observer polling costs the executor, from the repository root:

```sh
node scripts/benchmark-admission.mjs --profile acceptance --output /absolute/new-admission.json
```

It runs the same governed workload with the observer off and with it polled
every 250 ms, and fails if the 95th-percentile time from request to tool entry
grows by more than 10%. That cadence is a deliberate stress; the collector's
default is 300 seconds.

Running the observer-owning service confined to a single CPU while polling it
every 250 ms is not a supported configuration.

## Back up and reconstruct

A backup holds collector evidence only: validated snapshots, receipts, health
files, lifecycle journals and a manifest with a SHA-256 hash per file. It never
includes the executor's ledger, endpoints, credential names or values, or Neo4j
configuration. The hashes detect corruption, not replacement by someone who can
rewrite the whole backup: store backups where only the operator can write.

Stop the collector first; `backup` takes the archive's lock, which a running
collector holds. `restore` locks the file beside its destination, and `replay`
the one beside the restored evidence.

```sh
install -d -m 700 "$STATE/backups"

uv run agent-guard-recovery backup \
  --archive-dir "$STATE/archive" \
  --enrollment "$CONFIG/observer.json" \
  --destination "$STATE/backups/2026-11-12"

uv run agent-guard-recovery inspect \
  --backup-dir "$STATE/backups/2026-11-12"

uv run agent-guard-recovery restore \
  --backup-dir "$STATE/backups/2026-11-12" \
  --destination "$STATE/restored-evidence"
```

Repeat `--enrollment` for every enrolled source. A destination must not exist
and must not be inside the source directory. `restore` only copies verified
files into a new directory; it starts nothing and changes no graph. A backup is
a closed set: a file the archive did not write (for example `.DS_Store`) is
refused with `RECOVERY_FILE_UNEXPECTED` and named in `file`. Remove it and retry.

To rebuild the graph, point `replay` at an **empty** Neo4j database, the
restored evidence and a working archive directory that does not exist yet:

```sh
export NEO4J_PASSWORD=...
uv run agent-guard-recovery replay \
  --archive-dir "$STATE/restored-evidence" \
  --replay-archive-dir "$STATE/working-archive" \
  --backup-dir "$STATE/backups/2026-11-12" \
  --neo4j-uri bolt://127.0.0.1:7687
```

`--backup-dir` takes the sources from the backup; use repeated `--enrollment`
instead to name them from enrollment files. What replay does:

- It refuses a database that already holds any Guard source, snapshot or
  projection node. Provider nodes such as `AWSRole` may be present and are left
  alone.
- It imports each source's published snapshots in their original order, then
  reapplies completed source transitions. Pending receipts and receipts whose
  outcome was never confirmed are counted (`pendingExcluded`,
  `uncertainExcluded`) and left in the restored evidence for review.
- A capture older than one already replayed at the same ledger revision is left
  out of the working archive and counted as `supersededExcluded`. It stays in the
  restored evidence.
- Projection IDs are new. Source IDs, snapshot IDs and entity IDs are unchanged,
  and the result lists each old and new projection ID.
- Cloud joins are not rebuilt. Collect AWS metadata and the sources again before
  treating cloud coverage as current.

Afterwards, resume collection with `--archive-dir "$STATE/working-archive"` and
keep the restored evidence unchanged. If replay is interrupted, the working
archive is marked incomplete and every command refuses it: start again with
another empty database and a new working directory.

Pass the collector's `--archive-max-snapshots`, `--archive-max-bytes` and
`--archive-max-pending` to these commands when it runs with non-default values;
otherwise a larger archive is refused with `ARCHIVE_LIMIT_EXCEEDED` or
`RECOVERY_LIMIT_EXCEEDED`. Archive sizing, pending receipts and `discard` are
described in the
[README](../../integrations/cartography/README.md#pending-receipts-and-replay).

An executor that was itself restored or cloned is a different case: enroll it
with a new generation and follow [SOURCE-LIFECYCLE.md](SOURCE-LIFECYCLE.md).
Never copy graph state or collector receipts into an executor's ledger.

## Record what changed

```sh
uv run agent-guard-map-report \
  --endpoint http://127.0.0.1:8789/v1/query \
  --token-env AGENT_MAP_REPORT_TOKEN \
  --source-id SOURCE_ID \
  --directory "$STATE/differences"
```

`SOURCE_ID` is the `source_id` the collector prints. The token is a separate
`agm_v1.…` reader token for the Agent Map service, with the narrowest scope that
can see the source. Each report records how many entities of each type were
added, removed or changed between the previous and current snapshot, the two
projection IDs, the time and whether coverage had a gap. It contains no names,
entity IDs, tools, principals or credentials.

Each run also deletes this directory's reports older than 30 days. The
directory must be used for nothing else; a file the command did not write stops
it rather than being deleted. A report is the net difference between two
snapshots, not a log of every call: run it after a collection, not after every
execution.

## Monitor

| Watch | Default | Act when |
| --- | --- | --- |
| Collection interval | 300 seconds | A source has no success for 15 minutes. |
| Failure lines on stderr | — | The same `code` repeats, or exit status is nonzero. |
| Pending receipts | 16 per source | `agent-guard-recovery pending` lists any. |
| Archive use | 4,096 snapshots, 256 MiB | `ARCHIVE_RETENTION_SHORTENED` or `ARCHIVE_LIMIT_EXCEEDED` appears. |
| Graph retention | 1 hour | — |
| Archive retention | 7 days | — |
| AWS metadata age | 2 hours (`maxAgeSeconds`) | Cloud joins report `stale`. |

The archive's `health-<source id>.json` files record each source's last
attempt, last success, last error code and consecutive failures. Failure and
warning lines and exit statuses are described in the
[README](../../integrations/cartography/README.md#output-and-exit-status). Logs
and reports never contain tokens, tool arguments or results.

## Roll out

1. **Start with one non-production executor.** Fix its source identity, profile
   and manifest before enrolling it.
2. **Database access.** Give the collector and the Agent Map service separate
   Neo4j accounts where your edition supports roles. On Neo4j Community every
   credential can read and write everything, so keep credentials on trusted
   hosts; opening a session in read mode is not an access control.
3. **Readers.** The Agent Map service answers loopback clients with bearer
   tokens. For browser access with company sign-in, set up the
   [identity endpoint](IDENTITY.md).
4. **AWS (optional).** [AWS.md](AWS.md) adds IAM and S3 metadata for one
   account, collected by the same process under the same lock.
5. **Before widening use,** check with your own systems what synthetic data
   cannot show: AWS joins against the real account, sign-in and credential
   rotation, load at your size, and a backup restored from your backup storage.
   The [signed review guide](../../docs/guides/pilot-review.md) describes how to
   record such a check for one deployment.

## Roll back

Removing the collector never affects what the executor allows.

1. Stop the collector and the Agent Map processes, and turn the observer
   endpoint off in the host's configuration. Do not revoke task authority.
2. Leave the executor running. Confirm that a permitted request still succeeds
   and a denied one still fails.
3. Keep the archive, failure output and backups. Remove only resources you
   created for this collector; never run a broad delete against the database.
4. To return, restore into an empty database as described above, check scope
   and freshness, then resume collection.
