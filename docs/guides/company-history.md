# Move finished Agent Ops requests into company history

[Agent Ops](../../apps/agent-ops/README.md) keeps every request and its receipt in live
stores with a fixed capacity. This guide shows how to move finished requests into
encrypted history files, so the live stores have room again and no record is lost.

## What you will achieve

- Up to 100 finished requests per run moved into one encrypted, read-only history file.
- Room in the live request store and in the executor's archive.
- The ability to look up any archived receipt later, and to recover if a run is
  interrupted.

## Prerequisites

- Agent Ops installed on Linux as described in the
  [Linux deployment runbook](../../deployment/production/README.md). The command-line tool
  refuses to run on any other system.
- The service stopped. Every command here needs exclusive access to both stores.
- The path to your private configuration file. The examples use `/private/config.json`.
- `historyDirectory` and `historyMirrorDirectory` set in that configuration. Bundles made
  by `onboard` set both. For an older installation, do step 1 first.

This procedure covers the ticket workflow, where each request has one task. It refuses a
request whose task family has delegated tasks, source-task links or stored memory. Those
stay in the executor's archive under its normal limits.

Every command that changes something works in two passes. Run it once to get a preview
and a `digest`. Read the preview. Run it again with `--apply --digest` and that exact
digest. If anything was written in between, the digest no longer matches and you preview
again.

## Steps

### 1. Older installations only: enroll the history directories

Skip this step if your configuration came from `onboard`.

Create an owner-only history directory and add its absolute path to the configuration as
`historyDirectory`. Then:

```sh
node apps/agent-ops/cli.mjs enroll-history --config /private/config.json
node apps/agent-ops/cli.mjs enroll-history --config /private/config.json \
  --apply --digest REVIEW_DIGEST
```

Create a second owner-only directory under the witness directory, add it as
`historyMirrorDirectory`, then:

```sh
node apps/agent-ops/cli.mjs enroll-history-mirror --config /private/config.json
node apps/agent-ops/cli.mjs enroll-history-mirror --config /private/config.json \
  --apply --digest REVIEW_DIGEST
```

The mirror holds a second copy of every history file, kept apart from the data, the
primary history and the keys. Enrollment copies and checks the whole existing history
before it turns mirroring on. If it is interrupted, the service will not start: preview
and apply again to finish.

### 2. Preview one company

```sh
node apps/agent-ops/cli.mjs compact-history --config /private/config.json \
  --tenant COMPANY --limit 100
```

`COMPANY` is the tenant id from your configuration. `--limit` is 1 to 100 and defaults to
100. Read the result before you continue: how many requests will move (`count`), how many
are finished (`eligible`), how many are left out because their outcome is not confirmed
(`excludedUnresolved`), and whether anything blocks the run (`blockers`).

### 3. Apply

```sh
node apps/agent-ops/cli.mjs compact-history --config /private/config.json \
  --tenant COMPANY --limit 100 --apply --digest REVIEW_DIGEST
```

### 4. Verify

```sh
node apps/agent-ops/cli.mjs verify-history --config /private/config.json
node apps/agent-ops/cli.mjs check --config /private/config.json
```

Then start the service again. Repeat steps 2 to 4 for the next batch or the next company.

### 5. Look up an archived receipt

```sh
node apps/agent-ops/cli.mjs lookup-history --config /private/config.json \
  --tenant COMPANY --request ORIGINAL_REQUEST_ID
```

This reads the history files. It does not submit anything.

## What you should see

Each command prints one line of JSON with an `event` field.

| Command | `event` | Key fields |
| --- | --- | --- |
| `compact-history` (preview) | `COMPANY_HISTORY` | `status: "preview"`, `count`, `eligible`, `excludedUnresolved`, `digest`, `blockers` |
| `compact-history --apply` | `COMPANY_HISTORY` | `status: "compacted"`, `requests`, `archives`, `segment`, `commitment`, `archivedRequests` |
| `verify-history` | `HISTORY_VERIFIED` | `status: "verified"`, `companies`, `segments`, `bytes` |
| `lookup-history` | `HISTORY_LOOKUP` | `found: true`, `requestId`, `state`, `receipt`, `segment`; or `found: false` |
| `enroll-history`, `enroll-history-mirror` | `HISTORY_ENROLLMENT`, `HISTORY_MIRROR_ENROLLMENT` | `status: "preview"` with `digest`, then `status: "enrolled"` |

A failure prints `{"event":"START_FAILED","code":"..."}` on standard error and exits
with status 1.

After a run, the service's request lists show only the requests that are still live.

## What is kept and what is not

Each history file holds the selected requests, their exact backend receipts, the audit
entries that still existed for them, and the executor's complete record of each task
family: budgets, counters, approvals and revoked identities.

- Tickets stay live. Only requests and their receipts move.
- A request whose outcome is pending, running or unconfirmed is never moved. It stays
  live with its reservation.
- Request ids are never reused, even after their records move to history.
- Audit entries that the live audit buffer had already dropped cannot be recreated.
- History files are never rewritten or deleted. The history directory grows; the live
  database files do not shrink on disk.
- Keys and decrypted history never appear in browser responses, metrics or exports.

Keep every history file, in both directories, with your data backups. Keep the keys and
the witness directory under separate custody, as the
[custody guide](../../deployment/production/custody.md) describes.

## Limits

| What | Limit |
| --- | --- |
| Requests moved per run | 100 |
| Decoded content of one history file | 16 MiB |
| One encrypted history file | 24 MiB |
| History files across the whole deployment, all companies together | 10,000 |
| Companies with history | 10,000 |

The service's capacity status warns when history files reach 80% of the limit and raises
a critical alert at 95%. Plan a migration with the deployment owner before the limit is
reached. Do not delete files or reset counters to make room.

Startup and `verify-history` read the whole history chain, so both take longer as history
grows. Measure them on your own storage before you set a maintenance window or a health
check grace period.

## Recover from an interrupted run

An unfinished run blocks startup and every other maintenance command.

1. Run the same `compact-history` preview again. It reports `status: "recovery-required"`
   and a new `digest`.
2. Run it with `--apply --digest` and that digest. This resumes the same batch. It cannot
   pick different requests.
3. Run `verify-history`.

If the response to a finished run was lost, nothing is pending and nothing is repeated.

## Move or restore the history directory

A copied or restored directory is not accepted until you enroll it.

1. Copy every history file to the new private directory.
2. Stop the service and point `historyDirectory` at the new path.
3. Run `enroll-history` (preview, then apply). It checks every file first.
4. If a run was interrupted before the move, finish it as described above.

## Recover lost primary data

Use this when the primary database or history directory is lost but the witness directory,
the mirror and the keys are intact.

1. Stop the service. Keep the damaged files for investigation.
2. If the history volume was lost, recreate the directory at the configured path.
3. Run:

   ```sh
   node apps/agent-ops/cli.mjs recovery --config /private/config.json --operation repair
   node apps/agent-ops/cli.mjs recovery --config /private/config.json --operation repair \
     --apply --digest REVIEW_DIGEST
   node apps/agent-ops/cli.mjs enroll-history --config /private/config.json
   node apps/agent-ops/cli.mjs enroll-history --config /private/config.json \
     --apply --digest REVIEW_DIGEST
   ```

4. If a run was interrupted, finish it. Then run `verify-history` and `check`.

Repair rebuilds the primary copy from the mirror and the current witness state. It saves
any existing primary files under recovery names before it replaces them. It does not
resend any action and does not settle unconfirmed work.

This cannot recover from losing the witness directory, the mirror and the keys at the same
time. Keep separate off-host backups for that case.

## What can go wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `LINUX_DEPLOYMENT_REQUIRED` | The command ran on macOS or Windows. | Run it on the Linux host. |
| `USAGE_INVALID` | A flag is missing or unknown, `--limit` is not 1 to 100, or `--apply` was given without `--digest`. | Compare the command with the steps above. |
| `HISTORY_SCOPE_INVALID` | `--tenant` is not a company in the configuration. | Use the tenant id from the configuration. |
| `HISTORY_PREVIEW_STALE` | Something was written between preview and apply, or the digest was copied wrongly. | Preview again and apply the new digest. |
| `HISTORY_EMPTY` | No finished request is ready to move. | Nothing to do. |
| The preview lists `blockers` | A selected request's task cannot be archived yet. Each blocker is a code. | Resolve the named condition, then preview again. |
| `HISTORY_RECOVERY_REQUIRED` | An earlier run did not finish, possibly for another company. | Follow [Recover from an interrupted run](#recover-from-an-interrupted-run) for that company. |
| `HISTORY_DIRECTORY_NOT_ENROLLED`, `HISTORY_MIRROR_NOT_ENROLLED`, `HISTORY_MIRROR_REQUIRED` | The history or mirror directory is not configured or not enrolled. | Do step 1. |
| `HISTORY_SEGMENT_CAPACITY` | The next file would pass the 10,000-file limit. Nothing was changed. | Stop archiving and plan a migration with the deployment owner. |
| `HISTORY_MIGRATION_REQUIRED` | The existing history is already over the limit. | Do not start the service. Keep all stores, history, witnesses and keys, and plan a migration. |
| `HISTORY_EVIDENCE_INVALID`, `HISTORY_COMMITMENT_MISMATCH`, `HISTORY_MIRROR_MISMATCH` | A history file is missing, was replaced, or does not match the stores. | Stop. Keep everything as it is and restore the exact missing files from backup. |

When a check fails, do not clear the pending run by hand, delete request ids, replace the
witness directory with an older backup, or assume that an unconfirmed action failed.

Do not restore an older Agent Ops version onto stores that hold history. Older versions
cannot read them. See the [upgrade guide](../../deployment/production/upgrades.md).
