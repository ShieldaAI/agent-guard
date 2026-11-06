# Single-owner Linux operations service

This profile runs the repository's `apps/agent-ops` HTTPS service for a durable
reference ticket backend. A requester or enrolled agent proposes an exact ticket
status change; an OIDC-authenticated reviewer approves or denies it; an operator
reconciles an uncertain receipt and archives eligible task families. This is a
reference business integration, not an installation in a customer environment.

For a new installation, build the image and create the private storage directories,
then follow [Company onboarding](#company-onboarding). It generates the company
configuration and keyring from your inputs. The manual enrollment procedure below
is for an existing private configuration.

The supported deployment is one Linux host, one service owner, and local durable
POSIX filesystems with reliable SQLite locking and synchronization. The process
owns an encrypted authority database and a separately encrypted ticket database.
Each has its own rollback witness. There is no distributed writer or automatic
failover. A second owner fails to acquire the store. Size and availability needs
may justify another deployment architecture; this profile does not claim HA.

## Build and local verification

Use an independently reviewed Linux Node image from a supported release line,
pinned by repository digest. The build refuses versions below the current
security floor: 22.23.4, 24.22.1 or 26.12.1. These floors cover published fixes
through October 21, 2026; review newer advisories before each deployment. The
runtime removes unused npm, Corepack and Yarn tooling. Build from the repository
root after `npm run check` passes. No mutable image default or automatic Compose
pull is configured.
The [dated advisory review](advisories-2026-11-06.md) records the base-image
findings, removed runtime tooling and the unresolved November Node security
pre-alert. A pinned digest does not eliminate the need for security updates.

```sh
export NODE_IMAGE='YOUR_REVIEWED_NODE_IMAGE@sha256:YOUR_REVIEWED_DIGEST'
docker build --pull=false --build-arg NODE_IMAGE="$NODE_IMAGE" \
  -f deployment/production/Dockerfile -t agent-ops:reviewed .
export AGENT_OPS_IMAGE="$(docker image inspect agent-ops:reviewed --format '{{.Id}}')"
docker run --rm --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001 \
  --entrypoint node "$AGENT_OPS_IMAGE" deployment/production/verify-maintenance.mjs
```

The smoke script accepts no deployment paths. It creates disposable fixtures,
performs a reviewed update with an interrupted receipt, rotates both stores,
reconciles without repeating the effect, archives the completed task and rejects
a stale authority copy against the current witness. It removes its fixtures.
A process/container restart test is not physical host power-loss validation.
Revalidate the chosen Linux filesystem, storage synchronization, backup controls
and recovery procedure before using the host for real work.

## Provision private storage and identity

Allocate dedicated UID/GID 10001. The service runs nonroot with all capabilities
dropped, a read-only image filesystem, bounded memory/process/CPU/log resources,
no Docker socket, and no agent workspace mounts. Only its two state directories
and private temporary filesystem are writable during ordinary service operation.
OIDC discovery/token/JWKS traffic needs outbound HTTPS to the configured issuer
and any explicitly enrolled endpoint origins. Apply host-level egress policy if
required; Compose alone does not restrict destination addresses.

Prepare four canonical directories. Keep the witness directory outside the data
backup/restore domain. Mounting sibling paths from one rollbackable volume does
not provide that operational separation. The key/config directory is separate
from both data volumes and is writable only in offline maintenance. Encrypted
history has its own directory, mounted read-only by the running service and
writable by the stopped-owner maintenance profile. Retain it with data backups.

```sh
sudo install -d -o 10001 -g 10001 -m 0700 /srv/agent-ops/data
sudo install -d -o 10001 -g 10001 -m 0700 /var/lib/agent-ops-witness
sudo install -d -o 10001 -g 10001 -m 0700 /var/lib/agent-ops-witness/history-mirror
sudo install -d -o 10001 -g 10001 -m 0700 /etc/agent-ops
sudo install -d -o 10001 -g 10001 -m 0700 /srv/agent-ops/history
export AGENT_OPS_DATA=/srv/agent-ops/data
export AGENT_OPS_WITNESS=/var/lib/agent-ops-witness
export AGENT_OPS_CONFIG=/etc/agent-ops
export AGENT_OPS_HISTORY=/srv/agent-ops/history
```

Provision reviewed `config.json` from [config.example.json](config.example.json),
the HTTPS certificate/key, the confidential OIDC client secret, and a private
`tickets.json` seed under `/etc/agent-ops`. Every file must be a regular single-link
file, owned by UID 10001, mode 0600 or 0400; directories must be owner-only. Use
canonical paths and trusted ancestor directories. Do not put secret values in
Compose environment variables, image layers, command arguments or source control.
Configured database, witness, keyring, history, mirror and secret-file paths must
fit **512 UTF-8 bytes including the final filename**. Onboarding checks the
generated paths before publishing a bundle; startup and preflight enforce the
same bound so an accepted installation remains compatible with offline recovery.
`CONFIG_PATH_TOO_LONG` requires a shorter private mount or directory path, not a
larger storage quota.
Bind the entire config directory so atomic keyring replacement works; runtime
mounts that directory read-only. Protect its host copy and backups separately.

Set `publicOrigin` to the exact external HTTPS origin, including the port when
nondefault; enroll `${publicOrigin}/auth/callback` at the OIDC provider. Use exact
issuer subjects and explicit per-tenant roles. The sample subjects/domains/client
ID are placeholders, not usable identities. For a private issuer CA, add `caFile`
under `oidc`. `endpointOrigins` explicitly enrolls different origins used by
provider endpoints. `clientAuthMethod` may select a supported confidential-client
method; the secret is still loaded from its private file.

Seed format is `{ "tickets": [{ "id": "T-1", "tenantId": "your-tenant", "title":
"Your enrolled ticket", "status": "open" }] }`. The default cap is 500 tickets; an empty initial seed is supported. The configured
cap may be raised up to 10,000 before importing additional company tickets.
The reference backend retains ticket state and operation receipts itself; adapting
a real ticket service requires that service's idempotent operation ID and durable
receipt semantics, plus integration verification.

## Company onboarding

Prepare the data, witness and config directories above, plus a separate private
input directory owned by UID/GID 10001, mode 0700. Place your company TLS key and
certificate, confidential OIDC client secret, optional issuer CA, and reviewed
company ticket file there as private regular files. Copy
[onboarding.example.json](onboarding.example.json) to `onboarding.json` and replace
its company, origin, owner subject and provider values. Input paths inside the
manifest use `/run/company/...`; storage paths use the container mount paths in
the sample. Omitting `ticketsFile` generates an empty seed; no demo tickets are
created for a company.

```sh
export AGENT_OPS_ONBOARDING=/etc/agent-ops-onboarding
export AGENT_OPS_CONFIG_FILE=/run/agent-ops/company/config.json
docker compose -f deployment/production/compose.yaml run --rm onboarding
docker compose -f deployment/production/compose.yaml run --rm onboarding \
  preflight --config "$AGENT_OPS_CONFIG_FILE"
docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance \
  apps/agent-ops/cli.mjs init --config "$AGENT_OPS_CONFIG_FILE" \
  --tickets /run/agent-ops/company/tickets.json
docker compose -f deployment/production/compose.yaml up -d agent-ops
```

`onboard` atomically creates a new private `company` bundle with config, copied
TLS/OIDC files, a fresh keyring and the reviewed ticket seed. It refuses an existing
output bundle and does not initialize authority. Review its generated callback
URL and enroll that exact URL and owner subject with the company IdP. `preflight`
checks certificate/key/hostname validity, private paths, identity enrollment,
keyring policy, OIDC HTTPS discovery and existing store status. New stores are
reported as pending initialization. Discovery does not prove the client secret
or account binding; sign in through the browser after startup to verify both.

The `onboarding` Compose profile has no published ports, reads `/run/company`
read-only, and may use outbound HTTPS for IdP discovery. The profile is inactive
during ordinary startup. It does not automatically download images or enroll a
hosted account. The `maintenance` profile retains `network_mode: none`.
`AGENT_OPS_CONFIG_FILE` controls both the runtime command and healthcheck; its
default remains `/run/agent-ops/config.json` for existing deployments. Keep the
original input secrets and generated bundle under your key-custody policy.

## Reviewed capacity changes and ticket imports

Defaults remain 500 tickets, 4000 requests/receipts, 16 MiB per live store and four
retained keys. `limits` in the private config accepts these bounded integer values:

| Field | Default | Allowed range |
| --- | ---: | ---: |
| `maxTickets` | 500 | 1–10,000 |
| `maxRequests` | 4000 | 1–20,000 |
| `maxBackendBytes` | 16,777,216 | 1,048,576–67,108,864 |
| `maxLedgerBytes` | 16,777,216 | 1,048,576–67,108,864 |
| `maxRetainedKeys` | 4 | 1–64 |

The backend policy and keyring limit are persisted. Editing config alone does not
apply a policy change: startup refuses a mismatch. Stop the service, atomically
publish the reviewed config, preview the proposed change, then apply that exact
digest. Replace the digest placeholder with the value from your own preview.

```sh
docker compose -f deployment/production/compose.yaml stop agent-ops
docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance \
  apps/agent-ops/cli.mjs configure-limits --config "$AGENT_OPS_CONFIG_FILE"
docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance \
  apps/agent-ops/cli.mjs configure-limits --config "$AGENT_OPS_CONFIG_FILE" \
  --apply --digest REVIEWED_PREVIEW_DIGEST
docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance \
  apps/agent-ops/cli.mjs check --config "$AGENT_OPS_CONFIG_FILE"
docker compose -f deployment/production/compose.yaml up -d agent-ops
```

A lower limit must accommodate every retained ticket, request, receipt, key and
encoded store. Invalid, fractional or oversized values are rejected. No rows,
keys, budgets, reservations or approvals are deleted to make a limit fit. A
process interruption between policy commits leaves startup closed; obtain a new
preview and apply the same intended configuration to finish. Increasing storage
limits does not grant a task more calls, resources, cost or time. Review actual
memory, disk, backup and latency needs before raising them: the example container
has a 512 MiB memory limit, and the numeric ceilings are not a guarantee that
maximum-sized simultaneous stores fit that resource allocation.

For new company tickets, place a private `{ "tickets": [...] }` file in the
onboarding input directory. Each ticket needs a new ID and an explicitly enrolled
tenant. Existing IDs and versions cannot be overwritten by this import.

```sh
docker compose -f deployment/production/compose.yaml stop agent-ops
docker compose -f deployment/production/compose.yaml run --rm onboarding \
  import-tickets --config "$AGENT_OPS_CONFIG_FILE" --tickets /run/company/additional-tickets.json
docker compose -f deployment/production/compose.yaml run --rm onboarding \
  import-tickets --config "$AGENT_OPS_CONFIG_FILE" --tickets /run/company/additional-tickets.json \
  --apply --digest REVIEWED_IMPORT_DIGEST
docker compose -f deployment/production/compose.yaml up -d agent-ops
```

Keep the owner stopped through preview and apply. The digest binds the exact batch
and current authority; intervening changes require a new preview. Imports add new
records without changing existing ticket versions, requests or receipts. Review
company labels, ticket titles and record counts after restart. An uncertain
previous action still requires receipt reconciliation and cannot be cleared by
importing tickets or increasing a limit.

## First enrollment from an existing private configuration

Run these from the repository root with the five `AGENT_OPS_*` environment
variables above. `keygen` refuses an existing keyring. `init` requires all four
store/witness files to be absent; normal startup never enrolls missing authority.

```sh
docker compose -f deployment/production/compose.yaml run --rm maintenance \
  keygen --keyring /run/agent-ops/keyring.json --key-id initial
docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance \
  apps/agent-ops/cli.mjs init --config /run/agent-ops/config.json --tickets /run/agent-ops/tickets.json
docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance \
  apps/agent-ops/cli.mjs check --config /run/agent-ops/config.json
docker compose -f deployment/production/compose.yaml up -d agent-ops
```

Compose publishes only `127.0.0.1:8443` by default. Provide a reviewed TCP/TLS
passthrough or secure local access path to that listener; do not expose it by
changing the bind address without your deployment's access controls. The service
terminates TLS and requires the configured Host header. It rejects `Forwarded`,
`X-Forwarded-*` and `X-Auth-*` headers; proxy identity headers cannot grant roles.
The healthcheck connects inside the container, pins the peer certificate to the
configured certificate bytes, sends the correct Host, and asks `/health/ready`.
It sends no user credentials. Readiness checks both stores; liveness only reports
that the process can respond. Unhealthy status does not itself cause Compose to
restart a running container.

The process handles SIGTERM with draining and a 25-second shutdown deadline;
Compose allows 30 seconds. Pending reviews are invalidated on restart. An effect
with an uncertain outcome stays unresolved until its durable receipt is checked.
Use SIGHUP only after atomically publishing changed identity bindings or agent
credentials: it reloads them and invalidates existing sessions. Other config
changes require restart; a failed reload stops the service.

```sh
docker compose -f deployment/production/compose.yaml kill -s SIGHUP agent-ops
docker compose -f deployment/production/compose.yaml ps
docker compose -f deployment/production/compose.yaml logs --tail 100 agent-ops
```

The process emits redacted lifecycle/error codes and periodic request counts,
unresolved counts and capacity warnings. Alert on an absent/unhealthy service,
`START_FAILED`, `STORE_HEALTH_FAILED`, repeated uncertain receipts, capacity
warnings and low disk space. Export logs to your organization's collector if
retention beyond the bounded local log is needed. The bounded activity/audit lists
are operational records, not a complete external audit archive.

## Offline key custody and rotation

Follow the [offline custody runbook](custody.md) to enroll both stores, create
verified cold backups, rotate their keys as one managed group, and retire inactive
keys from the runtime ring into independent encrypted escrow. The dedicated
`custody` Compose profile has no network and mounts its secrets only while the
owner is stopped. The normal service never mounts the offline custody keyring.

Every custody mutation requires an exact preview digest. Rotation preserves
revocations, budgets, receipts and per-archive keys. Retirement first authenticates
all enrolled stores and registered backups; it never destroys historical keys or
claims to enumerate unregistered off-host backups. Once enrolled, generic
single-store rotation and raw-ring export refuse the managed ring. Use the
application custody command so external history cannot be omitted.

The runtime ring defaults to four retained keys, configurable from 1 through 64.
Its policy must match `limits.maxRetainedKeys`; use `configure-limits` for reviewed
installation-wide changes. Retire a verified inactive key before adding another
when full. Do not edit away keys or reuse retired identifiers. Independent custody
keys have their own retained-key policy and rotation procedure. Changing a secret
cannot restore confidentiality of already exposed older state.

For integrations using inventory or decision traces, outer-key rotation changes
pseudonymous references. Enroll a new inventory generation and trace collection
epoch before resuming exports, preserving the historical boundary. Agent Ops does
not enable those exporters itself.

## Backup, recovery and capacity

The [custody procedure](custody.md) creates consistent encrypted snapshots with
complete archive/history closure and authenticated manifests. It excludes witness
files. Keep current witnesses and keys under independent custody and preserve
SQLite journals after abnormal shutdown. Do not delete a journal, replace a
witness, change a schema number or initialize new authority as a repair.

Cold-checkpoint repair is deliberately strict: every snapshot must match its
**current** witness. A startup, later transaction or key rotation makes an older
checkpoint stale. A cold backup alone is therefore not a general disaster-recovery
solution for a live installation.

New installations also keep an encrypted **current-state mirror** in independent
witness custody. Each ledger change, archive and custody catalog change is
mirrored in the same SQLite transaction. Immutable history ciphertext is mirrored
before either authority head advances. If primary databases or history are lost,
the offline `recovery --operation repair` workflow reconstructs their exact
current state from surviving witnesses, mirrors and runtime keys. It previews
both stores and the complete history closure, preserves existing damaged files,
and never rewinds a witness or authorizes replay. Follow the exact commands and
directory re-enrollment steps in the [recovery runbook](custody.md).

Existing installations explicitly enroll the complete history mirror before
claiming this protection. Recovery does not cover simultaneous loss of witness
custody, its mirror or required keys. Keep these in an independent failure domain
and test the actual storage's durability. The [production acceptance review](../../docs/production-readiness.md)
separates repository fault-test evidence from company installation acceptance.

The two application stores are linked by their stable authority identity. Missing
or mismatched receipts leave outcomes unconfirmed. Reconciliation may settle the
original action from its exact backend receipt; absence of evidence never permits
a speculative retry or a reset of spent authority.

The operator page previews task-family retirement and archival with exact counts
and blockers. Active or uncertain work and external references block it. SDK
archives retain encrypted evidence and permanent reuse prevention. Their bounded
general-purpose pool is 4,096 archives, 256 MiB total ciphertext, 32 MiB per
ciphertext, and 65,536 residual task/memory identifiers. Ordinary archival alone
does not remove the separately retained business requests and receipts.

The selected ticket profile adds the reviewed business-history process below to
reuse live request capacity and SDK archive slots. Delegated or memory-bearing
SDK archives retain their original finite limits. Capacity warnings at 80% and
critical warnings at 95% call for reviewed maintenance before admission stops;
none of these bounds authorize eviction of receipts or unresolved reservations.

Use the [monitoring guide](monitoring.md) for bounded status/security events,
latency/capacity alerts and collector verification. Use the [upgrade guide](upgrades.md)
before changing an image; older readers must not interpret newer authority
semantics. Installation acceptance remains pending until its real custody,
recovery, alerts and identity environment have been exercised.

## Reviewed company history

The [company-history runbook](../../docs/guides/company-history.md) provides
reviewed offline compaction for Agent Ops single-root ticket workflows. It keeps
exact receipts and authenticated SDK archive evidence in encrypted, immutable
segments, then reclaims selected business records and local SDK archive rows.
Permanent identity fences preserve non-reuse. Unconfirmed work, delegated
families and memory-bearing histories are not eligible; their capacity limits
still apply.

Onboarding provisions `historyDirectory` and an independent `historyMirrorDirectory`
under witness custody; the container profile mounts
`AGENT_OPS_HISTORY` read-only for the runtime and writable for maintenance.
Legacy installations must explicitly enroll a private history directory.
Stop the service, review `compact-history` without `--apply`, apply its exact
digest, and run `verify-history` before restarting. A persisted partial operation
blocks ordinary service startup until reviewed recovery completes. A relocated
history volume requires complete verification and explicit re-enrollment.

Retain every committed segment with the two stores and independently protected
keys/witnesses. The custody adapter derives and verifies the complete history
closure; never select only recent files. Startup and maintenance verify the whole
chain, so their cost grows with retained bytes. The current backup adapter safely
refuses histories above 10,000 segments; plan a reviewed streaming adapter before
that threshold. External history consumes durable storage indefinitely and is
not automatically pruned. The runbook details recovery checkpoints, residual
metadata bounds and the limits of the retained audit evidence.

## Repeatable deployment gate

The verification stage adds a disposable HTTPS identity-provider fixture. The
default production stage excludes it and the app's tests. Build both from the
same reviewed checkout and base digest; do not deploy the verification image.
The host verifier requires Node, Docker Compose and OpenSSL, generates temporary
TLS material, and sends it only over stdin to its isolated test container.

```sh
docker build --pull=false --build-arg NODE_IMAGE="$NODE_IMAGE" --target verification \
  -f deployment/production/Dockerfile -t agent-ops:verification .
VERIFY_IMAGE=$(docker image inspect agent-ops:verification --format '{{.Id}}')
node deployment/production/check-images.mjs --production "$AGENT_OPS_IMAGE" \
  --verification "$VERIFY_IMAGE" --output artifacts/production-profile/runtime-comparison.json
node deployment/production/check-linux.mjs --image "$VERIFY_IMAGE" \
  --output artifacts/production-profile/evidence.json
```

The verifier checks the resolved Compose controls and the corresponding actual
container controls, company manifest onboarding, preflight, signed OIDC login,
CLI initialization and health, reviewed capacity changes, bulk imports and pagination,
rotation beyond the legacy four-key default, setup counts/limits, exact review and
update, SIGKILL/restart, session and review invalidation, second-owner refusal,
cold restore without witness rollback, two-store rotation, a subsequent update,
HTTPS archival and stale-restore refusal. It also verifies history compaction,
managed backup/key retirement, latest-state repair after primary directory loss,
preserved unresolved reservations, bounded concurrent reads and overload admission.
Independent Docker named volumes survive the verifier process and reopen in a
fresh container. The image comparison proves that production application bytes
match those tested. Evidence files cannot be overwritten. These disposable
fixtures do not certify a production
bind volume, restore automation, a cloud identity tenant or a deployed customer
service. The [self-hosted onboarding record](../../docs/validation/self-hosted-onboarding-2026-11-05.json)
records the exact image and those limits. The earlier
[P0 record](../../docs/validation/production-linux-2026-11-05.json) is retained separately.
CI repeats the gate on Linux amd64.
