# Operational monitoring and response

This guide applies to the single-owner Linux Agent Ops service. It defines the
signals, the log events, initial targets and alert rules. Meeting the targets is
the installation's job. Assign a responsible owner, an alert recipient and an
external collector before running unattended workloads.

## Signals and access

| Signal | Scope and access | Meaning |
| --- | --- | --- |
| `GET /health/live` | Minimal public response | The process can respond. It does not read or prove storage health. |
| `GET /health/ready` | Minimal public response, bounded request budget | Both stores are readable, the persisted policy matches, the certificate is unexpired and the process is not draining. A failure exposes a fixed code only. |
| `GET /api/status` | OIDC session with `operator` role | Current tenant workflow counts and unresolved age; explicitly deployment-wide capacity and HTTP aggregates. No task arguments, ticket titles or credentials. |
| `GET /api/metrics` | Same authenticated operator scope | Prometheus text with fixed metric names/labels. It never uses tenant, actor, ticket, path or request IDs as metric labels. |
| Log events on stdout and stderr | The deployment's log collector; restrict access | One JSON object per line. See [Log events](#log-events). |

The HTTP diagnostic endpoints are for authenticated operators. This profile does
not add an unattended bearer credential or an unauthenticated metrics listener.
Automated monitoring should ingest the deployment's stdout and the minimal health
probe. Do not put browser cookies or proposal-agent credentials in monitoring jobs.

The Compose healthcheck pins the configured certificate, validates its identity
and validity, and sends the configured Host. Keep an independent external HTTPS
probe to detect routing/DNS failures that an in-container healthcheck cannot see.
Low host disk space, filesystem errors, host load, process restarts, collector
delivery and identity-provider availability require host/infrastructure signals.

## Log events

Every stdout line is a JSON object with `at` (ISO 8601 time), `event` and the
fields listed below. A field is present only when it has a value. Codes are fixed
uppercase identifiers.

### Security events

The server emits these while it serves requests. `operatorId` and `tenantId` are
the enrolled IDs of the signed-in person and appear only when the request carried
a valid signed-in session. A refused agent request carries neither. Security
events contain no raw subject, token, cookie, client address, URL, query text,
error message or file path.

| Event | Fields | Emitted when |
| --- | --- | --- |
| `SIGN_IN_SUCCEEDED` | `operatorId`, `tenantId` | The OIDC callback verified the identity and mapped it to an enrolled subject. |
| `SIGN_IN_FAILED` | `operatorId`, `tenantId`, `code`, `cause` | `POST /auth/login` or the OIDC callback was refused. The IDs appear only when a signed-in session made the attempt. `code` is `AUTH_FAILED`, `FORBIDDEN` (for example a verified subject that is not enrolled), `CSRF_INVALID`, `UNAUTHENTICATED`, `RATE_LIMITED` or `SIGN_IN_UNAVAILABLE`. `cause` appears only with `SIGN_IN_UNAVAILABLE`: the service's own refusal code (for example `LOGIN_CAPACITY_REACHED`), or for an unexpected error that error's uppercase code or `UNCODED`. |
| `SIGNED_OUT` | `operatorId`, `tenantId` | `POST /auth/logout` was accepted. |
| `ACCESS_DENIED` | `operatorId`, `tenantId`, `code` | Any other request was refused with `FORBIDDEN`, `UNAUTHENTICATED` or `CSRF_INVALID`. |
| `REQUEST_FAILED` | `operatorId`, `tenantId`, `code`, `cause` | Any other request was answered with a 5xx status, except load shedding (`BUSY`) and shutdown (`NOT_READY`). `code` is the response code. `cause` appears for an unexpected error: that error's uppercase code, or `UNCODED`. |
| `TLS_RELOADED` | none | `SIGHUP` reloaded the TLS key and certificate. |
| `IDENTITY_BINDINGS_RELOADED` | none | `SIGHUP` reloaded identity bindings and agent credentials. All sessions and pending sign-ins were invalidated. |

Refusals without a signed-in person (`SIGN_IN_FAILED` and `ACCESS_DENIED` lines
without `operatorId`) are aggregated per event and `code`. The first one in a
60-second window is logged immediately. Later ones in that window are counted
and reported in one line when the window closes; that line carries `count`, the
number of suppressed occurrences. A refusal by a signed-in person is always
logged individually.

A security event that cannot be written is dropped and counted; the access
decision does not change. The CLI refuses to enqueue an event when stdout is
destroyed or already has more than 1 MiB buffered. The count is reported as
`securityLog.failures` in `OPERATIONS_STATUS` and as
`agent_ops_security_log_failures_total` in the metrics.

### Service lifecycle events

| Event | Fields | Emitted when |
| --- | --- | --- |
| `READY` | `publicOrigin` | The stores are open and the listener accepts connections. |
| `OPERATIONS_STATUS` | `schemaVersion`, `capturedAt`, `scope` (`deployment`), `uptimeSeconds`, `requests`, `unconfirmed`, `oldestUnconfirmedMs`, `securityLog` (`configured`, `failures`), `http` (`windowSeconds`, `requests`, `serverErrors`, `rateLimited`, `p95UpperBoundMs`, `p95AboveMaxBucket`), `capacity`, `capacityWarning`, `tlsExpiresAt` | Every 60 seconds. Each `capacity` entry has `id`, `used`, `limit`, `ratio` and `state` (`ok`, `warning`, `critical` or `unknown`); `history_segments` adds `committed` and `reserved`. Deployment aggregates only: no tenant or actor IDs. |
| `AUTO_ARCHIVE` | `archived`, `skipped`, `causes` | An online-retention run archived or skipped at least one request. `causes` lists the sorted blocker or error codes of the skipped requests, without naming a request. |
| `AUTO_ARCHIVE_FAILED` | `code`, `file` | An online-retention run failed as a whole. The service keeps running. |
| `CONFIG_RELOAD_FAILED` | `code`, `file` | `SIGHUP` could not reload: for example `RESTART_REQUIRED` when a key other than `bindings`, `agents` or `tls` changed. The service then shuts down with exit code 1. |
| `STORE_HEALTH_FAILED` | `code`, `file` | The periodic status check could not read the stores. The service then shuts down with exit code 1. |
| `SHUTTING_DOWN` | none | `SIGTERM` or `SIGINT` started an orderly shutdown. |

`START_FAILED` is written to stderr as one JSON line without `at`. It is the
only event on stderr and is emitted when the service cannot start or an offline
command fails. Its fields are `code` (the error's uppercase code, or
`CONFIG_OR_STORE_UNAVAILABLE`), `step` (what was being read or done: `arguments`,
`--config`, `--manifest`, `--tickets`, `storage-paths`, `tls`, `stores`, `listen`
or the command name), `file` (the configuration key of the private file that
failed, for example `tls.keyFile`, never its path) and a fixed `help` text. The
usage text follows when `code` is `USAGE_INVALID`.

In `CONFIG_RELOAD_FAILED`, `STORE_HEALTH_FAILED` and `AUTO_ARCHIVE_FAILED`,
`code` is the error's uppercase code and `file` is the same configuration key as
in `START_FAILED`.

### Offline command results

Each offline command writes one result event to stdout and exits. The fields are
the command's own result, such as counts, limits, IDs, digests and outcomes. No
result contains a key or a secret value.

| Event | Command |
| --- | --- |
| `ONBOARDING_PREPARED` | `onboard`. Includes the generated config path, the history directories and the callback URL. |
| `PREFLIGHT` | `preflight`. Contains `status`, `callbackUrl` and `checks`. The exit code is 1 when `status` is `failed`. |
| `INITIALIZED` | `init` |
| `STORES_VERIFIED` | `check` |
| `LIMIT_CONFIGURATION` | `configure-limits` |
| `TICKET_IMPORT` | `import-tickets` |
| `OFFLINE_CUSTODY` | `custody` |
| `CURRENT_STATE_RECOVERY` | `recovery` |
| `HISTORY_MIRROR_ENROLLMENT` | `enroll-history-mirror` |
| `HISTORY_ENROLLMENT` | `enroll-history` |
| `COMPANY_HISTORY` | `compact-history` |
| `HISTORY_VERIFIED` | `verify-history` |
| `HISTORY_LOOKUP` | `lookup-history`. Contains `found` and, for a match, `requestId`, `state`, `receipt`, `segment` and `commitment`. |

## Operating targets and alerts

Use these as initial targets, then record an explicit reviewed installation policy.
Measure before claiming an SLO is met. Exclude planned offline maintenance from
the availability denominator only when its approved interval is recorded.

| Target or condition | Initial alert | Required response |
| --- | --- | --- |
| Ready for at least 99.9% of eligible 30-day observations | Critical after two consecutive failed 30-second probes | Stop new work, inspect fixed error codes and preserve both stores/witnesses. Never initialize as a repair. |
| The service starts and stays up | Critical on any `START_FAILED`, `STORE_HEALTH_FAILED` or `CONFIG_RELOAD_FAILED` | Read `code`, `step` and `file`. Preserve existing state; correct the named configuration or storage problem and start again. |
| At least one status event every 60 seconds | Critical after 180 seconds without a valid event | Inspect process and collector separately. Missing telemetry is unknown health. |
| 5xx response fraction below 0.1% over the reporting period | Critical when at least five 5xx responses and at least 5% of recent requests fail | Check readiness, storage and host load, and the `REQUEST_FAILED` codes. Preserve unresolved outcomes. A malformed request target is answered with 400 and does not count. |
| At least 95% of requests complete within two seconds | Warning when the recent window has at least 20 requests and the 95th-percentile bucket exceeds two seconds | Inspect host saturation and data size. No timeout-driven resubmission. |
| No unresolved effect left unattended | Warning for any unconfirmed submission; critical when the oldest request is at least five minutes old | Open its original request and check the backend receipt. Reconciliation never submits the change again. If no receipt exists, an operator can review the close-out evidence, which shows the ticket as reviewed beside the ticket as it is now, and close the request as not applied. |
| Capacity has enough reviewed headroom | Warning at 80%, critical at 95% of any configured capacity | Review retention, backup custody and offline maintenance. Do not auto-raise limits or delete unresolved records. |
| History stays within the recovery-supported closure | Warning at 8,000, critical at 9,500 committed plus reserved segments, across all tenants | Plan before the fixed 10,000-segment ceiling. Pause new compaction at critical capacity; preserve records, history, witnesses and keys for a separately reviewed compatible recovery adapter or migration. |
| Served TLS remains valid | Warning below 14 days; critical below seven days; expired certificate fails readiness | Publish the renewed key and certificate atomically, run preflight, then send `SIGHUP` to reload them in place and verify HTTPS. No restart is needed; existing sessions are invalidated. A failed reload stops the service. |
| Security events reach the configured logger | Critical for any logger callback failure; warning if no logger is configured | Investigate collector health. Authorization outcomes must remain unchanged by logging errors. |
| Bounded client request rate | Warning at ten rate-limited requests within the recent window | Inspect workload volume and retry behavior; do not bypass the limit. |

For authentication investigation, alert on repeated `SIGN_IN_FAILED` or
`ACCESS_DENIED` in the external collector, with a rate threshold chosen for the
installation. Add `count` to the rate for aggregated lines. A denial alone is
not proof of an attack. Never add raw credentials or request URLs to improve
troubleshooting.

HTTP counters are process-local and reset on restart. Histograms use fixed upper
bounds of 50, 100, 250, 500, 1,000, 2,000, 5,000 and 10,000 ms. The UI's recent
window aggregates five one-minute buckets; it is not an exact sliding window.
Health, metrics and status calls contribute to HTTP totals. A disconnected client
is recorded as status class 4xx using internal code 499. The display's percentile
is a bucket upper bound, not an exact duration. Export lifetime counter samples
before restart and use collector-side rates for the reporting-period SLO.
Delivery and retention of collected logs are the collector owner's responsibility.

Capacity distinguishes retained request counts, receipt counts, decoded backend
bytes, decoded executor ledger bytes and retained keys. These limits do not
describe physical disk usage or archive/backup storage. Maintenance labels global
usage separately from tenant-specific request lists. Raising a limit changes no
agent grant, action budget, deadline or consumed approval.

Business history has a separate fixed recovery limit. `historyCapacity` in the
operator-only Setup/Maintenance response reports deployment-wide `committed`,
`reserved`, `total` and `limit`; `total` includes a pending compaction's reserved
slot. Status/stdout expose the same breakdown under `history_segments`. Prometheus
exports `agent_ops_capacity_used{resource="history_segments"}` and the matching
limit, plus `agent_ops_history_segments_committed` and
`agent_ops_history_segments_reserved`. Alert on the total so a reservation cannot
hide an exhausted slot. The limit is not configurable by `configure-limits`.

At `HISTORY_SEGMENT_CAPACITY`, stop new compaction and retain the current state.
`HISTORY_MIGRATION_REQUIRED` means existing history exceeds this supported
recovery profile and normal startup refuses it. The response is a separately
reviewed compatible streaming/partitioned recovery adapter or migration protocol;
deleting segments, resetting identifiers or removing witnesses cannot create safe
capacity. Plan this work before exhaustion. The count limit does not replace disk
space monitoring for either the primary history or its independent recovery copy.

## Activity snapshots and authoritative history

An operator can choose **Maintenance → Prepare activity snapshot**, inspect the
event count, coverage and SHA-256 fingerprint, then download JSON. The CSRF-bound
`POST /api/audit/export` produces the same minimized snapshot. Only the current
tenant's last 1,000 retained activity events can be included; the live activity
ring itself retains at most 4,000 events across the deployment. The artifact says
how many retained events were omitted and explicitly marks historical drop count
as unknown. An empty snapshot does not prove that no activity happened.

Each activity event names its actor: the enrolled ID of the person or agent, or
`system:retention` for an `AUTO_ARCHIVED` event recorded by online retention.
Identity enrollment refuses any operator or agent ID that starts with `system:`,
so an enrolled identity cannot be recorded as a service actor.

The digest detects changed bytes when compared with a trusted recorded digest;
it is not an independent signature, an immutable external audit log or proof of a
complete decision history. The snapshot excludes raw model/tool arguments, ticket
titles, secret keys, credentials and archived payloads. Protect downloaded files
because enrolled operator IDs and request references remain operational data.

Use the reviewed business-retention workflow and its authenticated encrypted
history artifacts for authoritative retained receipts and their execution evidence.
Activity snapshots never authorize retention, release an unresolved reservation,
restore a task or reconstruct spent authority.

## Installation verification

Cold backups and current recovery mirrors have different purposes. A cold backup
preserves an archival checkpoint; later startup or workflow writes can make it
stale against the surviving witness. Repair after primary-volume loss relies on
the exact encrypted payload, archive/catalog rows and history under independent
witness custody. Neither a recent backup timestamp nor a successful old-backup
verification proves that this repair works.

Keep the current witnesses, their recovery mirrors and the necessary keys outside
the primary data's loss domain. Monitor capacity and storage failures in both
domains. Repair must use the newest authenticated surviving state, preserve
unfinished work and never rewind a witness to match an older backup. It does not
provide automatic failover or recovery from losing every independent copy.
Before unattended use, exercise actual primary data/history-volume loss in a
disposable test environment after new work has made an older cold backup stale.
Verify the latest receipt, unresolved reservation, spent budget, history and
retired identities survive repair. Record the exact build/configuration and
results. The service cannot verify this exercise, alert delivery or off-host
custody; Setup shows them as **Not verified here**.

1. Record who receives critical alerts, the monitored image/configuration identity,
   and where the external collector preserves security and lifecycle records.
2. Confirm the normal health probe, an authenticated status response and a status
   stdout event. Check that an unauthenticated status/metrics request is refused.
3. In the disposable test environment, stop the service and verify the
   missing-readiness/status alert reaches its recipient and is acknowledged.
   Restart and confirm recovery without reinitialization. Do not induce storage
   faults in company data.
4. Exercise one denied review and one confirmed update. Match request references
   to the minimized activity snapshot and authoritative receipt; verify no raw
   ticket content or credentials reached the collector.
5. Exercise the documented post-commit failure fixture and receipt-only recovery.
   Confirm an unresolved alert and that reconciliation adds no second backend write.
6. Record results, alert delivery/acknowledgement times and remaining limits.

`node --test apps/agent-ops/test/observability.test.mjs` exercises metric bounds,
tenant scoping, thresholds, export minimization, authentication, readiness rate
limits and logger-failure isolation. Browser checks cover the visible status and
explicit download flow. Repeat the installation checks when custody, routing,
identity, collectors or the supported deployment profile changes.
