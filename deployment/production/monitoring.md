# Operational monitoring and response

This specification applies to the single-owner Linux Agent Ops service. It defines
installation targets and alert rules; it is not evidence that a company has met
those targets. Enroll a responsible owner, an alert recipient and an external
collector before enabling unattended workloads. Record a delivered test alert
and its acknowledgement in the installation's acceptance record.

## Signals and access

| Signal | Scope and access | Meaning |
| --- | --- | --- |
| `GET /health/live` | Minimal public response | The process can respond. It does not read or prove storage health. |
| `GET /health/ready` | Minimal public response, bounded request budget | Both stores are readable, the persisted policy matches, the certificate is unexpired and the process is not draining. A failure exposes a fixed code only. |
| `GET /api/status` | OIDC session with `operator` role | Current tenant workflow counts and unresolved age; explicitly deployment-wide capacity and HTTP aggregates. No task arguments, ticket titles or credentials. |
| `GET /api/metrics` | Same authenticated operator scope | Prometheus text with fixed metric names/labels. It never uses tenant, actor, ticket, path or request IDs as metric labels. |
| `OPERATIONS_STATUS` stdout event | Host-owned collector | A bounded deployment aggregate every 60 seconds: usage, limits, unresolved age, HTTP window, certificate expiry and security-logger health. No tenant or actor IDs. |
| Security stdout events | Host-owned collector; restrict access | `SIGN_IN_SUCCEEDED`, `SIGN_IN_FAILED`, `SIGNED_OUT`, `IDENTITY_BINDINGS_RELOADED` and `ACCESS_DENIED`. Only fixed reason codes and, for a known valid session, enrolled operator/tenant IDs. No raw subject, token, cookie, IP, URL or query text. |

The HTTP diagnostic endpoints are for authenticated operators. This profile does
not add an unattended bearer credential or an unauthenticated metrics listener.
Automated monitoring should ingest the deployment's stdout and the minimal health
probe. Do not put browser cookies or proposal-agent credentials in monitoring jobs.

The Compose healthcheck pins the configured certificate, validates its identity
and validity, and sends the configured Host. Keep an independent external HTTPS
probe to detect routing/DNS failures that an in-container healthcheck cannot see.
Low host disk space, filesystem errors, host load, process restarts, collector
delivery and identity-provider availability require host/infrastructure signals.

## Operating targets and alerts

Use these as initial targets, then record an explicit reviewed installation policy.
Measure before claiming an SLO is met. Exclude planned offline maintenance from
the availability denominator only when its approved interval is recorded.

| Target or condition | Initial alert | Required response |
| --- | --- | --- |
| Ready for at least 99.9% of eligible 30-day observations | Critical after two consecutive failed 30-second probes | Stop new work, inspect fixed error codes and preserve both stores/witnesses. Never initialize as a repair. |
| At least one status event every 60 seconds | Critical after 180 seconds without a valid event | Inspect process and collector separately. Missing telemetry is unknown health. |
| 5xx response fraction below 0.1% over the reporting period | Critical when at least five 5xx responses and at least 5% of recent requests fail | Check readiness, storage and host load. Preserve unresolved outcomes. |
| At least 95% of requests complete within two seconds | Warning when the recent window has at least 20 requests and the 95th-percentile bucket exceeds two seconds | Inspect host saturation and data size. No timeout-driven resubmission. |
| No unresolved effect left unattended | Warning for any unconfirmed submission; critical when the oldest request is at least five minutes old | Open its original request and check the backend receipt. Reconciliation never submits the change again. |
| Capacity has enough reviewed headroom | Warning at 80%, critical at 95% of any configured capacity | Review retention, backup custody and offline maintenance. Do not auto-raise limits or delete unresolved records. |
| History stays within the recovery-supported closure | Warning at 8,000, critical at 9,500 committed plus reserved segments, across all tenants | Plan before the fixed 10,000-segment ceiling. Pause new compaction at critical capacity; preserve records, history, witnesses and keys for a separately reviewed compatible recovery adapter or migration. |
| Served TLS remains valid | Warning below 14 days; critical below seven days; expired certificate fails readiness | Renew trusted material, preflight, then restart and verify HTTPS. |
| Security events reach the configured logger | Critical for any logger callback failure; warning if no logger is configured | Investigate collector health. Authorization outcomes must remain unchanged by logging errors. |
| Bounded client request rate | Warning at ten rate-limited requests within the recent window | Inspect workload volume and retry behavior; do not bypass the limit. |

For authentication investigation, alert on repeated `SIGN_IN_FAILED` or
`ACCESS_DENIED` in the external collector, with an installation-reviewed rate
threshold. A denial alone is not proof of an attack. Never add raw credentials or
request URLs to improve troubleshooting.

HTTP counters are process-local and reset on restart. Histograms use fixed upper
bounds of 50, 100, 250, 500, 1,000, 2,000, 5,000 and 10,000 ms. The UI's recent
window aggregates five one-minute buckets; it is not an exact sliding window.
Health, metrics and status calls contribute to HTTP totals. A disconnected client
is recorded as status class 4xx using internal code 499. The display's percentile
is a bucket upper bound, not an exact duration. Export lifetime counter samples
before restart and use collector-side rates for the reporting-period SLO.
The CLI refuses to enqueue a security event when stdout is destroyed or already
has more than 1 MiB buffered; the failure counter/alert records that loss. A slow
collector must not create an unbounded security-event queue or change an access
decision. The collector must preserve its own delivery/retention evidence.

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

The digest detects changed bytes when compared with a trusted recorded digest;
it is not an independent signature, an immutable external audit log or proof of a
complete decision history. The snapshot excludes raw model/tool arguments, ticket
titles, secret keys, credentials and archived payloads. Protect downloaded files
because enrolled operator IDs and request references remain operational data.

Use the reviewed business-retention workflow and its authenticated encrypted
history artifacts for authoritative retained receipts and their execution evidence.
Activity snapshots never authorize retention, release an unresolved reservation,
restore a task or reconstruct spent authority. External security/activity log
retention remains the collector owner's responsibility.

## Installation verification

Cold backups and current recovery mirrors have different purposes. A cold backup
preserves an archival checkpoint; later startup or workflow writes can make it
stale against the surviving witness. Current primary-volume-loss repair relies on
the exact encrypted payload, archive/catalog rows and history under independent
witness custody. Neither a recent backup timestamp nor a successful old-backup
verification proves this current recovery path works.

Keep the current witnesses, their recovery mirrors and the necessary keys outside
the primary data's loss domain. Monitor capacity and storage failures in both
domains. Repair must use the newest authenticated surviving state, preserve
unfinished work and never rewind a witness to match an older backup. It does not
provide automatic failover or recovery from losing every independent copy.
Before unattended use, exercise actual primary data/history-volume loss in the
disposable acceptance environment after new work has made an older cold backup
stale. Verify the latest receipt, unresolved reservation, spent budget, history
and retired identities survive repair. Record the exact build/configuration and
results. The UI's **Not verified here** checklist cannot attest to that exercise.

1. Record who receives critical alerts, the monitored image/configuration identity,
   and where the external collector preserves security and lifecycle records.
2. Confirm the normal health probe, an authenticated status response and a status
   stdout event. Check that an unauthenticated status/metrics request is refused.
3. In the disposable acceptance environment, stop the service and verify the
   missing-readiness/status alert reaches its recipient. Restart and confirm
   recovery without reinitialization. Do not induce storage faults in company data.
4. Exercise one denied review and one confirmed update. Match request references
   to the minimized activity snapshot and authoritative receipt; verify no raw
   ticket content or credentials reached the collector.
5. Exercise the documented post-commit failure fixture and receipt-only recovery.
   Confirm an unresolved alert and that reconciliation adds no second backend write.
6. Capture results, alert delivery/acknowledgement times and remaining limits.
   Browser automation and local collector-hook tests do not prove external alert
   delivery or representative human usability.

`node --test apps/agent-ops/test/observability.test.mjs` exercises metric bounds,
tenant scoping, thresholds, export minimization, authentication, readiness rate
limits and logger-failure isolation. Browser checks cover the visible status and
explicit download flow. Repeat the installation checks when custody, routing,
identity, collectors or the supported deployment profile changes.
