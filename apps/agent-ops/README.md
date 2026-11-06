# Agent Ops: protected ticket workflow

Agent Ops is a repository-hosted reference service for one Linux owner. It combines
the durable executor, a persistent ticket backend, standard OIDC sign-in and a
browser review/recovery interface. The backend owns real persisted ticket records;
initial ticket data is explicitly enrolled by the deployment owner. It does not
connect to Jira, Linear or another company ticket system.

Start with the [Linux deployment runbook](../../deployment/production/README.md).
This application is part of the source deployment, not a sixth npm package.
Build the workspace before running its entry point. Only Linux is supported by
the production CLI. POSIX library tests also run on macOS.

## Enroll your company workspace

Use **Setup** after signing in with the operator role. It shows the enrolled
tenant, OIDC issuer/callback, read-only configuration checks, deployment-wide
capacity and generic host commands. Configuration files, private paths and secret
values are not displayed. Setup does not run commands or change configuration.
Runtime configuration checks establish local readability and the current sign-in.
The separate company acceptance checklist marks backup/restore, off-host custody,
alert delivery and company-environment validation **Not verified here**. Preserve
their actual acceptance records before unattended use; local green checks do not
substitute for those records.

The host onboarding workflow is:

1. Prepare the company manifest with the intended public HTTPS origin, IdP client
   and enrolled subjects/roles, TLS and secret-file references, storage ownership,
   and desired capacity. Follow the manifest example in the Linux runbook.
2. Run `onboard --manifest PATH --output-dir PATH` on the host to generate private
   configuration and seed files. Start with company ticket records or an empty
   seed; onboarding does not create model-generated demo authority.
3. Run `preflight --config PATH` and address the reported TLS, OIDC, permissions
   and storage findings. Preflight is read-only and does not grant approval or
   dispatch a ticket change. Stop an existing service first: the durable-state
   check needs exclusive store access. Follow the runbook's initialization/start steps.
4. To add company records later, stop the service and preview
   `import-tickets --config PATH --tickets PATH`. Review the exact batch and
   digest, then explicitly apply the reviewed import with the CLI's apply flags.
   Imports add new records; they do not overwrite existing ticket versions or
   approve pending requests. Restart the service and refresh the browser.

These subcommands are provided by `node apps/agent-ops/cli.mjs`; use the complete
commands and file schema in the [Linux runbook](../../deployment/production/README.md).
Import is for records owned by this local ticket backend. Connecting an existing
company ticket system requires a separately implemented adapter with its own
authorization, conditional writes and authoritative receipt handling.

An empty Tickets view points operators to Setup and tells other roles to contact
the deployment owner. Once records are enrolled, a requester can prepare a change
and a reviewer can inspect its exact effect before submitting it.

## Identity and permissions

The owner enrolls OIDC subjects in a private configuration file. The confidential
client verifies signed ID tokens, issuer, audience, state, nonce and PKCE before
mapping the subject to one operator ID, tenant and explicit roles. IdP group names,
browser fields, proxy headers and model output do not create permissions.

| Role | Operations |
| --- | --- |
| `requester` | Propose a status change to a ticket in the enrolled tenant. |
| `reviewer` | Approve or deny an exact pending request in that tenant. |
| `operator` | Look up an authoritative receipt, reconcile an uncertain outcome, preview/apply task archival, and inspect setup and deployment capacity. |

All signed-in operators can read tickets and requests in their own tenant. One
owner can hold all three roles. This is not a mandatory two-person approval
policy. Each decision still records the actual enrolled reviewer's identity.
Session lifetime is at most 15 minutes and cannot exceed the ID token expiry.
Expiry, logout, process restart or identity reload invalidates the session.
`SIGHUP` reloads identities and proposal credentials, invalidates all sessions and
rechecks authorization for in-flight requests before effects. A failed reload
stops the service. Other configuration changes require restart. IdP-side revocation
alone is bounded by session lifetime; use reload for immediate local revocation.

The optional agent credential is a host-enrolled random bearer token with an agent
ID, tenant and exact ticket allowlist. It can propose through `POST /agent/requests`
with `{"ticketId":"T-1","status":"resolved"}` (or `open`), and read its own
request/receipt through `GET /agent/requests/:id`. It cannot approve,
execute directly, reconcile, archive or read arbitrary tickets. Keep this token in
the trusted adapter, outside prompts and tool arguments. The adapter returns the
request ID and review state to the agent. Humans use the OIDC browser interface.
The runtime holds the only ticket write path; do not expose its backend files,
keyring, OIDC secret or executor administration object to an agent workload.

## Review and recovery

The review shows ticket ID/title, tenant, original and requested status, exact
resource version, digest and expiry. Preparation has no ticket effect. Approve
submits that reviewed action once. Denial revokes its task. Changed, expired or
restart-invalidated preparations require a new request and review.

Before dispatch, the service persists the request, task/action binding, operation
ID and authenticated decision. The ticket backend compares the expected version
and commits the change with its unique receipt in one encrypted transaction.
An interrupted response is **unconfirmed**, even if the write succeeded.
The recovery button looks up the original receipt, checks its tenant, ticket,
operation, digest and resulting version, then settles the executor reservation.
It never resubmits a ticket change. A missing or mismatched receipt leaves the
request unconfirmed and blocks archival. It does not establish that nothing
happened. Follow the runbook and preserve both stores for investigation.

The guard and ticket databases each have a separate rollback witness. Their
authority-instance binding prevents mixing stores from different deployments.
Normal startup opens existing authority only. It cannot initialize a missing
database or witness. An older backup cannot be accepted by rolling back a witness
alongside it. Preserve witness custody independently from database restoration.

A cold backup is an archival checkpoint. Any later authoritative write, including
startup changes, can make that checkpoint too old for the current witness.
Primary-volume-loss recovery therefore requires the exact-current encrypted
mirrors under surviving independent witness custody, together with the required
keys and mirrored history. It is an explicit offline repair, not rollback to a
chosen checkpoint or automatic failover. Preserve unresolved outcomes, current
receipts, spent budgets and identity fences. Follow the deployment runbook, and
retain the installation's actual volume-loss repair evidence; Setup does not
verify that the storage domains or their recovery copies will survive a failure.
Setup separately reports current-state recovery enrollment from authenticated
store flags and verified history binding at service startup. Legacy installations
show **Current-state recovery not enrolled**; a service without a verified host
observation shows **Recovery enrollment not verified here**. Neither state claims
that a usable cold checkpoint exists. Enrollment is not a restore-drill result.

Task archival first previews the whole family and binds a short-lived digest to
the operator and tenant. It refuses active, uncertain or externally referenced
state. Applying retires the family and atomically preserves encrypted evidence
before removing live task records. Exact tombstones prevent old IDs regaining
authority. The business receipt remains visible. A persisted archival intent and
verified executor receipt recover a crash between the two stores' commits.

Key rotation is offline and operates on the complete enrolled store group.
Review the custody operation and digest, apply it with the service stopped,
verify both stores, then restart. The independent custody catalog escrows the new
key before publication; interrupted rotation has an explicit recovery operation.
Active-key retirement removes a reviewed unused key from the runtime ring only
after verifying registered backups and their dependencies. Historical secrets
remain in independent encrypted escrow. Keys never enter the browser or CLI
output. Inventory/trace consumers using key-derived references must explicitly
reenroll their observation generation. Follow the exact custody commands in the
[Linux runbook](../../deployment/production/README.md).

Business-history retention is also reviewed offline. It preserves exact requests,
receipts and execution evidence in authenticated encrypted history before
compacting eligible live records; unresolved outcomes remain protected. Permanent
identity fences prevent compacted IDs from regaining authority. Maintenance shows
the tenant's committed local history count, last commit and head fingerprint.
These observations do not prove off-host custody, restore testing or complete
external activity-log retention.
This compactor supports the reference ticket workflow's single-root families.
General SDK families with delegation, source-task relationships or governed memory
keep their finite archive limits and are refused by this compactor. See the
[company-history guide](../../docs/guides/company-history.md) for its exact scope.

## Operational limits

The reference backend defaults to 500 enrolled tickets, 4,000 retained
requests/receipts, and 16 MiB each for backend and executor ledger data. Host
configuration can change these limits within the supported ceilings; the service
fails closed at its configured capacity. Operator-only Setup and Maintenance
show the active configured limits and deployment-wide counts. Backend byte usage
measures decoded ledger data, not database disk size. Counts in ticket/request
lists remain scoped to the signed-in tenant.

| Setting | Default | Supported range |
| --- | --- | --- |
| `maxTickets` | 500 | 1–10,000 |
| `maxRequests` | 4,000 | 1–20,000; also bounds receipts |
| `maxBackendBytes` | 16 MiB | 1–64 MiB |
| `maxLedgerBytes` | 16 MiB | 1–64 MiB |
| `maxRetainedKeys` | 4 | 1–64 |

The recovery profile also has a **fixed deployment-wide limit of 10,000 business
history segments** across all tenants. A pending compaction reserves one slot;
committed plus reserved segments consume the limit. Setup, Maintenance, status,
stdout monitoring and metrics report this breakdown, with warnings at 80% and
critical alerts at 95%. This is not a `configure-limits` setting. At exhaustion,
stop new compaction and preserve all records, history, witnesses and keys. The
deployment owner needs a separately reviewed compatible recovery adapter or
migration plan before the profile can retain more history. Existing over-limit
history requires migration review and cannot start as a repairable installation.

Limit changes must retain all existing rows and keys. A smaller setting that
cannot hold current usage fails. Increasing a setting does not allocate storage
or validate host sizing; preflight and monitoring remain deployment duties.

Lists use pages of at most 500 records with Previous/Next controls and explicit
current-range totals. Current/unresolved requests sort first. The request filter
applies to the current page. Pages reflect live state, so new activity can move
rows; Refresh resets to the first page. Archival frees executor task capacity;
it preserves business receipts and the backend's retained request count. Size
and count limits are independent. Review host resources and retention before
raising a limit through the offline configuration/CLI workflow and restarting.
Set the desired values in the private configuration, stop the service, and run
`configure-limits --config PATH` to preview the change. Review its retained counts
and digest before rerunning with `--apply --digest DIGEST`. Run the documented
verification before restarting. The reviewed change retains existing evidence.

The executor's archive limits and live ledger limit remain documented in its
[README](../../packages/executor/README.md). The keyring defaults to four retained
keys; its configured key count/limit is visible to operators. Raising that limit
uses the offline limit-change workflow, which also updates the keyring policy.
Use the enrolled offline custody workflow for active-key retirement; manually
editing the keyring cannot establish that retained history remains recoverable.
The service logs bounded, nonsecret request/unconfirmed counts and a capacity
warning at 80%. `/health/live` and `/health/ready` return only minimal status.
Connect these logs and health results to the deployment owner's monitoring.
Activity logs are bounded; persistent receipts/reviewer records and encrypted
archives carry the retained business evidence. This is not an external immutable
audit archive or a distributed/HA service.

## Verification and next work

Operator-only **Maintenance** includes current operational status, scoped
unresolved outcomes, configured capacity alerts and a reviewed activity-snapshot
download. The snapshot explicitly reports bounded coverage and omissions; it is
not a complete audit history or a replacement for authoritative receipts.
Authenticated `/api/status` and `/api/metrics` provide the same diagnostic scope.
The CLI emits bounded deployment metrics and minimized security events to the
host collector. See the [monitoring and response specification](../../deployment/production/monitoring.md)
for signal definitions, operating targets, alert thresholds and installation
verification. External alert delivery must be checked in the real installation.

`npm test` includes workflow and real signed-OIDC HTTPS tests. The Linux runbook
includes container verification. [check-browser.mjs](check-browser.mjs) exercises
the UI contract; [check-browser-service.mjs](check-browser-service.mjs) drives the
real local HTTPS/OIDC/SQLite service. Both use browser automation and accessibility
checks. Their fixture results do
not replace actual IdP/host onboarding. Customer TLS, IdP enrollment, secret
custody, off-host witness retention and monitoring must be configured for the real
installation.

To repeat the browser checks with the versions used for this review, install the
test tools outside the workspace and use their directory as the first argument:

```sh
ops_browser_tools="$(mktemp -d)"
npm install --prefix "$ops_browser_tools" --ignore-scripts playwright@1.63.0 axe-core@4.14.0
"$ops_browser_tools/node_modules/.bin/playwright" install chromium
node apps/agent-ops/check-browser.mjs "$ops_browser_tools" artifacts/agent-ops-ui
node apps/agent-ops/check-browser-service.mjs "$ops_browser_tools" artifacts/agent-ops-ui
```

Both scripts accept a fourth argument, `chromium`, `firefox` or `webkit`. Install
the selected engines with Playwright and use separate artifact directories per
engine. The checked-in private `tools/browser` package pins the same browser-test
dependencies for CI without adding them to the production workspaces. Browser
reports name the measured engine/version; they do not establish human usability.

The real-service harness uses OpenSSL to create disposable TLS and a local signed
OIDC provider. Its browser accepts that fixture's self-signed certificate only;
the service verifies the explicitly configured fixture CA. Runtime TLS validation
is not disabled. The [verification review](../../docs/production-p0-review.md)
records measured results and their scope.

The [production plan](../../docs/production-plan.md) also adds an agent inventory
to Agent Map/Cartography: owners, identities, tools, permission evidence, resources,
credential references, drift and freshness. Those graph extensions are planned;
inventory observations never grant execution authority.
