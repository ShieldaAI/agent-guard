# Agent Ops: protected ticket workflow

Agent Ops is a **reference app**: a reference service in this repository for one
Linux owner. It combines the executor (`@shieldaai/agent-guard-executor`), a
persistent ticket backend, standard OIDC sign-in and a browser review/recovery
interface. Agent Ops is the host: the trusted application code that embeds the
executor. The Linux machine it runs on is called the deployment machine below.
The backend owns real persisted ticket records; initial ticket data is explicitly
enrolled by the deployment owner. It does not connect to Jira, Linear or another
company ticket system.

Start with the [Linux deployment runbook](../../deployment/production/README.md).
This application is part of the source deployment, not a sixth npm package.
Build the workspace before running its entry point. Only Linux is supported by
the production CLI. POSIX library tests also run on macOS.

## Enroll your company workspace

Use **Setup** after signing in with the operator role. It shows the enrolled
tenant, OIDC issuer/callback, service checks, deployment-wide capacity and
generic commands for the deployment machine. Configuration files, private paths
and secret values are not displayed. Setup does not run commands or change
configuration. The service checks are measured when the page loads: both
encrypted stores were read and verified, the security-event logger is configured
and has not failed, the served TLS certificate has at least 14 days left,
current-state recovery was enrolled at startup, and no capacity limit is above
80%. Each reads **Ready** or **Needs attention**. Setup does not verify backup and restore, custody
off the deployment machine, history and key retention, alert delivery or the
company environment. It lists them as **Not verified here**; check each one on
the real installation before unattended use.

The onboarding workflow on the deployment machine is:

1. Prepare the company manifest with the intended public HTTPS origin, IdP client
   and enrolled subjects/roles, TLS and secret-file references, storage ownership,
   and desired capacity. Follow the manifest example in the Linux runbook.
2. Run `onboard --manifest PATH --output-dir PATH` on the deployment machine to
   generate private configuration and seed files. Start with company ticket
   records or an empty seed; onboarding does not create model-generated demo
   authority.
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
owner can hold all three roles. By default this is not a mandatory two-person
approval policy. Set `"requests": { "forbidSelfApproval": true }` once a second
reviewer is enrolled, so no one approves their own request. Each decision still
records the actual enrolled reviewer's identity.
Session lifetime is at most 15 minutes and cannot exceed the ID token expiry.
Before sign-in, the browser holds only a signed five-minute cookie with a derived
CSRF token; anonymous visitors create no server-side state. Server state starts
at `POST /auth/login`, which also renews that cookie so it outlives the
three-minute sign-in. A client that drives the sign-in itself must send the
cookie set by that response, not the earlier one, with the callback.
`POST /auth/login` from a session that is already signed in is refused with
`ALREADY_SIGNED_IN` (409) and leaves that session as it is. Each client address
holds at most four pending sign-ins (128 in total). At either cap a new sign-in
replaces the oldest pending one, that address's own at the per-address cap and
the oldest of all at the total, so a full table never refuses a new sign-in and
people who share a proxy or NAT address are not locked out by abandoned
attempts. A sign-in page left open past five minutes renews its cookie and
retries once by itself.
Expiry, logout, process restart or identity reload invalidates the session.
`SIGHUP` reloads identities, proposal credentials and the TLS key and certificate,
invalidates all sessions and rechecks authorization for in-flight requests before
effects. New connections use the reloaded certificate. A failed reload stops the
service. Other configuration changes require restart. IdP-side revocation
alone is bounded by session lifetime; use reload for immediate local revocation.

Each client address (IPv4, or IPv6 /64) gets 180 requests per minute. The page
and its stylesheet and script files are answered from memory and do not count,
so loading the page never uses up the limit. When the address table is full, the
oldest window is dropped instead of refusing new clients.

The service accepts at most 128 connections, 64 of them from one client address.
A connection is closed when it does not finish its TLS handshake within 5
seconds, sends no complete request within 10 seconds or stays idle for 30
seconds. At most 32 requests run at once. Requests without a signed-in session
or an enrolled agent token share 16 of those slots, and one client address holds
at most 4 of the 16, so anonymous traffic cannot shut out signed-in people and
one address cannot keep others from signing in. `/health/live` and
`/health/ready` take no slot; readiness reuses one verified read of the stores
for two seconds and counts toward the rate limit.

**A per-client limit in front of the service is required** in two cases. These
limits are counted per client address, so they cannot tell clients apart when
they share one, and they are small enough for many addresses to fill:

- Clients share an address: a NAT, a forward proxy, or an L4 passthrough load
  balancer, behind which every client has the balancer's address. One of them
  can then use up the shared request limit, the address's 4 anonymous slots and
  its 64 connections, and can replace the pending sign-ins of the others.
- Someone controls many addresses (for example a routed IPv6 prefix, where each
  /64 counts as one address): two addresses can hold all 128 connections, four
  can hold the 16 anonymous slots, and a few dozen can keep replacing every
  pending sign-in.

Limit connections, concurrent requests and new sign-ins per real client at the
load balancer or firewall, and do not expose the service to networks that do not
need it.

Three optional top-level configuration keys tune these limits. They are bounded
and need a restart:

| Key | Default | Range | Meaning |
| --- | --- | --- | --- |
| `sessionTtlMs` | 900000 | 1000 to 900000 | Longest signed-in session, in milliseconds. Never above 15 minutes or the ID token expiry. |
| `rateLimitPerMinute` | 180 | 60 to 100000 | Requests per minute for one client address. Raise it when many people share one proxy address. |
| `signInFlowsPerClient` | 4 | 1 to 128 | Pending sign-ins kept for one client address before the oldest is replaced. |

The optional `requests` configuration sets review and admission policy:
`reviewExpiryMs` (default 5 minutes, 1 minute to 24 hours), `forbidSelfApproval`
(default `false`), `maxPendingPerRequester` (default 50) and `maxPendingPerTenant`
(default 1,000). A requester or agent at its cap gets `PENDING_LIMIT_REACHED` (429)
without affecting anyone else. `shareDenialReason` (default `false`) controls who
sees a reviewer's optional denial reason. By default it stays with signed-in
people in the tenant. When `true`, an agent that reads its own request through
`GET /agent/requests/:id` receives it too.

Set `requests.autoArchiveAfterDays` (1 to 3,650) to turn on online retention. Once a
minute, the service archives the executor task families of finished requests older
than that, at most 10 per run and oldest first. It uses the same retire-then-archive
path as the Archive view and records `AUTO_ARCHIVED` by `system:retention`.
Enrollment refuses an operator or agent ID that starts with `system:`. A request
with any blocker, such as an unconfirmed effect, is skipped and left for an
operator. Moving request records into company history files is still an offline
`compact-history` job.

The optional agent credential is a random bearer token that the deployment owner
enrolls with an agent ID, tenant and exact ticket allowlist. It can propose through `POST /agent/requests`
with `{"ticketId":"T-1","status":"resolved"}` (or `open`), and read its own
request/receipt through `GET /agent/requests/:id`. A proposal for a ticket outside
the allowlist gets the same `403 FORBIDDEN` whether or not that ticket exists.
It cannot approve,
execute directly, reconcile, archive or read arbitrary tickets. Keep this token in
the trusted adapter, outside prompts and tool arguments. The adapter returns the
request ID and review state to the agent. Humans use the OIDC browser interface.
The runtime holds the only ticket write path; do not expose its backend files,
keyring, OIDC secret or executor administration object to an agent workload.

## Review and recovery

The review opens with one sentence that states the effect, for example
"Ticket T-1 “Customer delivery” will change from open to resolved." It is built
only from fields the service validated. Below it are who asked (a person or an
agent) and when, a live countdown to the review deadline, the ticket, the
expected version and the tenant, each explained in place. The action fingerprint
and operation reference are under **Technical details**.

- Nothing is selected for the reviewer. After a refresh the selection is kept
  only for the same request; if it is gone the page says so and selects nothing.
- **Deny** comes first and **Approve** has the same weight. Approval takes two
  steps: the second repeats the effect sentence after the service has read the
  stored action back from the executor (`GET /api/requests/:id`) and confirmed it
  is the change shown. The service repeats that check before it approves.
  `POST /api/requests/:id/approve` and `.../deny` answer `REVIEW_STALE` (409) and
  do nothing when the request is no longer pending, is being decided by someone
  else, carries a different fingerprint from the one sent, no longer matches the
  fingerprint that was reviewed, or (approve only) has a stored action that is
  gone or is not the change shown. Refresh and review the current request.
- Denial can carry a reason of up to 280 characters on one line. It is stored
  with the request and shown to signed-in people in the tenant. An agent reading
  its own request receives it only when `requests.shareDenialReason` is `true`.
  It never enters the activity log.
- The requester can **withdraw** their own pending request
  (`POST /api/requests/:id/withdraw`). The request becomes `withdrawn`, its task
  is revoked and nothing is applied.
- With `forbidSelfApproval` on, the requester is not offered Approve on their own
  request. `GET /api/session` reports the policy as `policy.forbidSelfApproval`.
  The service answers such an approval with `SELF_APPROVAL_FORBIDDEN` (409, not
  403: the reviewer keeps the role and can still deny or withdraw the request).
- New requests appear without Refresh. The page asks for the list every 15
  seconds while its tab is visible, with `If-None-Match`; an unchanged list is
  answered `304` without a body. A failed or rate-limited poll doubles the
  interval up to two minutes, and a hidden tab does not poll. Requests on screen
  are updated where they are; new ones are announced as "1 new request" and
  shown when asked for, so rows never move under the pointer.
- Leaving and returning to the tab keeps the workspace. The session is checked
  quietly on return; only a session that really ended shows sign-in, and signing
  in again returns to the same request (`#requests/<id>` in the address).

Preparation has no ticket effect. Approve submits that reviewed action once.
Denial and withdrawal revoke its task. Changed, expired or restart-invalidated
preparations require a new request and review.

Before dispatch, the service persists the request, task/action binding, operation
ID and authenticated decision. The ticket backend compares the expected version
and commits the change with its unique receipt in one encrypted transaction.
An interrupted response is **unconfirmed**, even if the write succeeded.
The recovery button looks up the original receipt, checks its tenant, ticket,
operation, digest and resulting version, then settles the executor reservation.
It never resubmits a ticket change. A missing or mismatched receipt leaves the
request unconfirmed and blocks archival. It does not establish that nothing
happened. Follow the runbook and preserve both stores for investigation.

An approval whose dispatch does not complete ends in one of four states. The
fixed cause code is recorded on the request and in the activity log:

| What happened | State | Activity event |
| --- | --- | --- |
| The backend refused inside this process before its transaction committed (the reviewer's authorization was revoked, the ticket changed, a storage limit or the clock refused the write) and the store holds no receipt. The reservation is settled at zero cost. | **failed**, or **changed** when the ticket had changed | `DISPATCH_REFUSED` |
| The executor refused before it admitted the call, so the stored action was never run (for example its approval or task was no longer valid). | **review_required**: prepare a new request | `DISPATCH_FAILED` |
| The executor admitted the call and settled it as failed without running the backend (the task or approval deadline passed first), and the store holds no receipt. | **failed** | `DISPATCH_FAILED` |
| Anything else: a lost response, a storage error, an outcome the executor has not recorded or no longer holds, or any case in which a receipt exists. | **unconfirmed** | `OUTCOME_UNCONFIRMED` |

The first row is definitive because the ticket change and its receipt commit in
one local transaction. A request is never marked failed while a receipt for it
exists.

An unconfirmed request that will never get a receipt, for example after a crash
between the approval and the commit, can be closed by an operator with
`POST /api/requests/:id/close-out`. Sent with an empty body (`{}`) it changes
nothing and returns the evidence ("Review close-out"):

- no receipt exists for the operation. Because the ticket change and its receipt
  commit together, this alone shows the change was never applied;
- the ticket as this request was reviewed (`reviewedVersion`, `reviewedStatus`)
  beside the ticket as it is now (`ticketVersion`, `ticketStatus`), and
  `ticketChanged` when they differ. Another request may have changed the ticket
  since; the operator checks that its current state is the expected one;
- the executor's record of the call (`execution`): still unsettled (`UNKNOWN`,
  `RUNNING`, `ADMITTED`), never run (`PREPARED`, `NEVER_ADMITTED`), or settled at
  zero cost (`FAILED`, `SETTLED_NO_CHARGE`).

Sent again with `{"digest": "..."}`, the digest of exactly that evidence, it
closes the request ("Close as not applied"): the reservation is settled at zero
cost, the request becomes failed with cause `CLOSED_WITHOUT_RECEIPT` and
`CLOSED_OUT` is recorded with the operator. It never submits the change. If the
ticket or anything else in the evidence changed after it was shown the digest no
longer matches (`CLOSE_OUT_STALE`): review it again. If a receipt exists
(`RECEIPT_FOUND`) reconcile instead. If the executor's records show a call that
may have run and cannot be accounted for (`CLOSE_OUT_UNPROVEN`) the request stays
unconfirmed for investigation.

The executor's ledger database and the ticket database each have a separate
rollback witness. Their authority-instance binding prevents mixing stores from
different deployments.
Both stores refuse to work when the system clock is behind the last time they
recorded (`CLOCK_INVALID`), so a clock that stepped backward stops the service
from starting. After the clock is confirmed correct, start once with
`--accept-clock-skew MS` (1 to 86400000): a backward step of at most that many
milliseconds is accepted at that start only, and the executor records
`CLOCK_SKEW_ACCEPTED`. Leave the option out otherwise.

Normal startup opens existing authority only. It cannot initialize a missing
database or witness. An older backup cannot be accepted by rolling back a witness
alongside it. Preserve witness custody independently from database restoration.

A cold backup is an archival checkpoint. Any later authoritative write, including
startup changes, can make that checkpoint too old for the current witness.
Primary-volume-loss recovery therefore requires the exact-current encrypted
mirrors under surviving independent witness custody, together with the required
keys and mirrored history. It is an explicit offline repair, not rollback to a
chosen checkpoint or automatic failover. Preserve unresolved outcomes, current
receipts, spent budgets and identity fences. Follow the deployment runbook.
Setup reports current-state recovery enrollment from authenticated store flags
and the history binding verified at service startup. Legacy installations show
**Current-state recovery not enrolled**; a service that has no verified startup
observation shows **Recovery enrollment not verified here**. Neither state
claims that a usable cold checkpoint exists.

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
This compactor supports the reference ticket workflow's single-root families.
General SDK families with delegation, source-task relationships or governed memory
keep their finite archive limits and are refused by this compactor. See the
[company-history guide](../../docs/guides/company-history.md) for its exact scope.

## Operational limits

The reference backend defaults to 500 enrolled tickets, 4,000 retained
requests/receipts, and 16 MiB each for backend and executor ledger data. The
private configuration can change these limits within the supported ceilings; the service
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
or validate the deployment machine's sizing; preflight and monitoring remain deployment duties.

Lists use pages of at most 500 records with Previous/Next controls and explicit
current-range totals. Current/unresolved requests sort first. The request filter
applies to the current page. Pages reflect live state, so new activity can move
rows between pages; Refresh resets to the first page. Archival frees executor task capacity;
it preserves business receipts and the backend's retained request count. Size
and count limits are independent. Review the deployment machine's resources and retention before
raising a limit through the offline configuration/CLI workflow and restarting.
Set the desired values in the private configuration, stop the service, and run
`configure-limits --config PATH` to preview the change. Review its retained counts
and digest before rerunning with `--apply --digest DIGEST`. Run the documented
verification before restarting.

The executor's archive limits and live ledger limit remain documented in its
[README](../../packages/executor/README.md). The keyring defaults to four retained
keys; its configured key count/limit is visible to operators. Raising that limit
uses the offline limit-change workflow, which also updates the keyring policy.
Use the enrolled offline custody workflow for active-key retirement; manually
editing the keyring cannot establish that retained history remains recoverable.
The service logs bounded, nonsecret request/unconfirmed counts and a capacity
warning at 80%. A request answered with 5xx (other than load shedding or
shutdown) also logs one `REQUEST_FAILED` event with the response code and, for an
unexpected error, a `cause`: the error's own code when it is a plain uppercase
identifier, otherwise `UNCODED`. Messages, paths and request data are never
logged. `START_FAILED` names the `step` that failed and, when a configured
private file was the problem, its configuration key in `file` (for example
`tls.keyFile`), never the path. `/health/live` and `/health/ready` return only minimal status.
Connect these logs and health results to the deployment owner's monitoring.
Activity logs are bounded; persistent receipts/reviewer records and encrypted
archives carry the retained business evidence. This is not an external immutable
audit archive or a distributed/HA service.

## Monitoring and verification

Maintenance also shows a **Tool definition** panel: whether the definition of the
service's own tool (`ticket.update`) differs from the one last approved, and if so
each changed field with the approved and the current value. The service approves
its own tool at startup, so this is a record to read after an upgrade, not an
approval step. The changed fields are shown until the service restarts again;
after that the panel reports no change. It covers the definition, not the tool's code.

Operator-only **Maintenance** includes current operational status, scoped
unresolved outcomes, configured capacity alerts and a reviewed activity-snapshot
download. The snapshot reports its bounded coverage and omissions.
Authenticated `/api/status` and `/api/metrics` provide the same diagnostic scope.
The CLI writes bounded deployment metrics and minimized security events to
stdout for the deployment's log collector. See the
[monitoring guide](../../deployment/production/monitoring.md) for every log
event, operating targets, alert thresholds and installation verification.

`npm test` includes workflow and real signed-OIDC HTTPS tests. The Linux runbook
includes container verification. [check-browser.mjs](check-browser.mjs) exercises
the UI contract; [check-browser-service.mjs](check-browser-service.mjs) drives the
real local HTTPS/OIDC/SQLite service. Both use browser automation and accessibility
checks. Their fixture results do not replace onboarding with the real IdP on the
real deployment machine: TLS, IdP enrollment, secret custody, witness custody off
that machine and monitoring must be configured for the real installation.

To run the browser checks, install the test tools outside the workspace and use
their directory as the first argument:

```sh
ops_browser_tools="$(mktemp -d)"
npm install --prefix "$ops_browser_tools" --ignore-scripts playwright@1.63.0 axe-core@4.14.0
"$ops_browser_tools/node_modules/.bin/playwright" install chromium
node apps/agent-ops/check-browser.mjs "$ops_browser_tools" artifacts/agent-ops-ui
node apps/agent-ops/check-browser-service.mjs "$ops_browser_tools" artifacts/agent-ops-ui
```

Both scripts accept a third argument, `chromium`, `firefox` or `webkit`. Install
the selected engines with Playwright and use separate artifact directories per
engine. The checked-in private `tools/browser` package pins the same browser-test
dependencies for CI without adding them to the production workspaces. Browser
reports name the measured engine/version; they do not establish human usability.

The real-service harness uses OpenSSL to create disposable TLS and a local signed
OIDC provider. Its browser accepts that fixture's self-signed certificate only;
the service verifies the explicitly configured fixture CA. Runtime TLS validation
is not disabled.

Agent Map and Cartography provide the agent inventory: owners, identities, tools,
permission evidence, resources, credential references, drift and freshness. See the
[agent cartography guide](../../docs/guides/agent-cartography.md). Inventory
observations never grant execution authority.
