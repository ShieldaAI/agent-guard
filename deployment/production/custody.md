# Offline key custody, cold backup and current-witness recovery

This procedure supports one stopped Linux owner with the existing two witnessed stores and enrolled encrypted history directory. A separate offline keyring encrypts the custody ledger, migration escrow, append-only catalog and backup manifests. Active-key retirement removes an inactive key from the runtime keyring **only after** all enrolled stores and every registered backup authenticate. Historical keys remain in independent encrypted escrow. This is not key destruction or proof that no unmanaged backup exists elsewhere.

The custody command locks both live stores, the runtime keyring and the independent witnessed custody ledger. Each mutation requires its own exact preview digest. A live service, changed preview, missing history segment, changed catalog, missing key, unsafe directory or stale witness stops the operation. The application adapter derives the entire external-history closure from the authenticated backend and SDK heads; operators cannot select a partial list of files.

## Separate storage and secrets

Stop the service before using this profile. Provision four additional canonical host directories, each owned by UID/GID `10001:10001`, mode `0700`:

```sh
export AGENT_OPS_CUSTODY_DATA=/srv/agent-ops-custody
export AGENT_OPS_CUSTODY_WITNESS=/srv/agent-ops-custody-witness
export AGENT_OPS_CUSTODY_KEYS=/media/offline-agent-ops-keys
export AGENT_OPS_BACKUPS=/srv/agent-ops-backups
```

These paths must be separate from one another, the live data, witnesses, history and runtime keyring directory. No path may be an ancestor, descendant, symlink or case alias of another custody domain. Merely choosing different folder names is not physical failure-domain redundancy: deploy witnesses and offline key custody according to the actual storage/host failure model. Keep the custody-key medium unmounted except during these operations. The normal runtime service has no mount for any custody secret or catalog. The `custody` profile has no network and inherits the non-root, read-only-rootfs, dropped-capability, resource and logging limits. Its explicit writable mounts permit the reviewed offline changes.

Create the directories with administrator tooling appropriate to the host; Compose refuses to create missing bind paths. Create `/media/offline-agent-ops-keys/custody.json` as UID 10001, mode `0600`:

```json
{
  "version": 1,
  "custodyDatabase": "/var/lib/agent-ops-custody/catalog.sqlite",
  "custodyWitness": "/var/lib/agent-ops-custody-witness/catalog.sqlite",
  "custodyKeyringFile": "/run/agent-ops-custody-keys/keyring.json",
  "backupDirectory": "/var/lib/agent-ops-backups"
}
```

The file contains paths, not secret key values. Existing `AGENT_OPS_CONFIG`, data/history/witness variables and the reviewed `AGENT_OPS_IMAGE` remain required. Preserve the company-bundle override when used:

```sh
export AGENT_OPS_CONFIG_FILE=/run/agent-ops/company/config.json
docker compose -f deployment/production/compose.yaml stop agent-ops
docker compose -f deployment/production/compose.yaml --profile custody run --rm --entrypoint node custody \
  packages/executor/dist/ledger-maintenance-cli.js keygen \
  --keyring /run/agent-ops-custody-keys/keyring.json --key-id custody-2026-01 --max-keys 64
```

`keygen` refuses to replace an existing keyring. Back up this independently held offline keyring using your secret-custody process; losing all copies makes escrow and backup manifests unreadable. Never put that keyring in the ordinary runtime configuration tree or next to its encrypted backups.

For the examples below, define an offline command helper in the host shell:

```sh
custody() {
  docker compose -f deployment/production/compose.yaml --profile custody run --rm custody \
    custody --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}" \
    --custody-config /run/agent-ops-custody-keys/custody.json "$@"
}
```

## Enroll the complete managed store set

```sh
custody --operation enroll
custody --operation enroll --apply --digest REVIEWED_ENROLLMENT_DIGEST
```

Review the returned counts and digest, then use that exact digest. The application command always enrolls its authority and ticket stores with their existing stable identities. The full original runtime key set is encrypted into migration escrow before any key can leave the active ring. It preserves keys for unknown older backups. Enrolled ledgers require at least schema 2 so older published readers fail closed; current-state mirrored ledgers preserve schema 3. A managed marker binds the runtime ring to the witnessed source stores; restoring an older unmarked ring cannot bypass that binding.

After enrollment, use `custody --operation rotate` instead of the generic runtime `rotate` command. Generic raw-ring export and runtime rotation reject managed rings. Runtime startup still needs only its active keyring and the existing stores; offline custody secrets are never required to serve requests.

## Create and verify a cold backup

```sh
custody --operation backup
custody --operation backup --apply --digest REVIEWED_BACKUP_DIGEST
custody --operation verify --backup-id RETURNED_BACKUP_UUID
```

The backup directory contains consistent encrypted SQLite snapshots, complete encrypted external-history segments, and an authenticated encrypted manifest with independent key escrow. It contains no witness file. Files and directory entries are flushed before the backup is registered in the witnessed catalog. A crash before registration may leave an encrypted orphan directory; it is not reported as a valid registered backup and must not be substituted for one.

Source authority, receipts, budgets and witnesses do not advance while taking a snapshot. Validation decrypts every retained SDK archive and verifies every referenced history segment. Generic SDK manifests are limited to 20,000 files and 16 MiB of decoded metadata; the Agent Ops history adapter has the stricter 10,000-segment closure limit. Above a limit, backup and key retirement stop with a capacity error; no partial backup is accepted. Live history verification itself uses bounded segment memory. Plan retention/export capacity before reaching these limits; a tiered backup protocol is not implemented.

The append-only catalog grows on disk and verification scans the registered backup history. Its explicit 100,000-record ceiling bounds verification bookkeeping; the preview exposes this limit, and mutations stop before exceeding it. Monitor custody disk space and maintenance duration. There is no automatic backup/catalog deletion or secret destruction. Preserve the custody database independently of its witness; copying both backward defeats the threat boundary and is prohibited.

## Rotate runtime keys and retire inactive keys

```sh
custody --operation rotate --key-id runtime-2026-02
custody --operation rotate --key-id runtime-2026-02 --apply --digest REVIEWED_ROTATION_DIGEST
custody --operation status
custody --operation retire --key-id initial
custody --operation retire --key-id initial --apply --digest REVIEWED_RETIREMENT_DIGEST
```

Choose a fresh key ID that has never been issued in this custody catalog. Rotation first commits independent escrow, then atomically publishes the new active key, then rekeys both stores while preserving their plaintext authority and archived data. The pending journal permits either store to be on the old or new key after interruption. Retirement refuses a key still used by any enrolled store, the final active key, changed backups, missing history, or unregistered ring changes. The old key remains encrypted in escrow for old snapshots and unmanaged historical backups.

Runtime keyring capacity remains its explicit policy (default 4, configurable 1..64). Retire a verified inactive key before adding another when full. Do not edit JSON to drop keys or reuse a retired ID. Key rotation changes outer-key-derived inventory/trace references; reenroll collectors with a new enrollment generation before resuming exports.

## Recover interrupted operations

```sh
custody --operation status
custody --operation recover
custody --operation recover --apply --digest REVIEWED_RECOVERY_DIGEST
```

A pending mutation blocks ordinary custody changes until recovered. Reuse the existing catalog, witness, keyrings and backup directories; do not delete lock files, recreate witnesses or enroll a fresh authority to bypass an error. OS locks release on process exit. The journal records intent before active-key removal or source-file replacement. Recovery validates current keys, source identities, backup ciphertext and witness commitments again. If a valid owner has already resumed and advanced authority after an interrupted restore, `recover` can report `restoreSuperseded: true`. Exact reviewed apply then cancels only the obsolete intent after every current store and history chain verifies; it does not restore old bytes or rewind any witness.

For an interrupted restore, incomplete staging files are preserved under private `.partial-*` names and rebuilt from verified backup bytes. Original damaged sources and journals are retained under `.recovery-UUID`; interrupted history copies are atomically replaced only from the verified closure. Review those encrypted recovery artifacts after success under your retention policy. They are not normal backup entries.

## Restore data against current witnesses

```sh
custody --operation restore --backup-id RETURNED_BACKUP_UUID
custody --operation restore --backup-id RETURNED_BACKUP_UUID --apply --digest REVIEWED_RESTORE_DIGEST
```

Restore supports missing or corrupted data files **only when every saved snapshot commitment exactly matches its current independently retained witness**. Witness files are locked, never copied or rewritten. A service transaction or key rotation after the backup advances the witness; that older backup is then rejected as `CUSTODY_RESTORE_STALE`. This deliberately prevents replaying old approvals, budgets or external effects. A cold snapshot is not a promise of recovery to an earlier point after new external work.

The supported restore is in place in the enrolled directories with their current identities. It does not re-enroll relocated history directories, restore lost witnesses, reconcile unconfirmed external effects or authorize data-loss rollback. If current witnesses have advanced beyond all available snapshots, the cold `custody restore` command cannot safely reconstruct missing transactions. For the enrolled current-state mirror profile, use the exact-current repair procedure below. Without that mirror, preserve the surviving files and resolve recovery with the authoritative backend.

After successful recovery, run the existing offline `check` and inspect unconfirmed work before starting the service. The independent custody journal and all keys must remain intact until recovery is complete.

## Rotate independent custody secrets

The custody keyring has explicit retained key IDs; older envelope keys remain available. With every owner stopped, rotate the custody database itself using the existing staged helper:

```sh
docker compose -f deployment/production/compose.yaml --profile custody run --rm --entrypoint node custody \
  packages/executor/dist/ledger-maintenance-cli.js rotate \
  --keyring /run/agent-ops-custody-keys/keyring.json \
  --database /var/lib/agent-ops-custody/catalog.sqlite \
  --witness /var/lib/agent-ops-custody-witness/catalog.sqlite \
  --next-key-id custody-2027-01
custody --operation status
custody --operation verify --backup-id A_REGISTERED_BACKUP_UUID
```

The new custody key encrypts the current catalog state and future escrow records/manifests. Old catalog records and backup envelopes remain readable using retained offline keys. Reuse the same next key ID if interrupted. Preserve every custody key; the current helper has a 64-key ceiling and refuses overflow. There is no automatic historical-envelope re-encryption or old custody-key destruction.

If an old custody secret may have leaked, rotate custody first, then rotate runtime keys through managed custody so newly issued runtime keys and future archive keys are protected by the fresh custody secret. This cannot make already exposed backups or historical keys secret again. Recovering from a compromised host requires a trustworthy host and independently verified custody, not merely changing a file on that host. Record the incident scope and preserve required historical keys separately.

## Repair the latest committed state after primary storage loss

New Agent Ops installations enable a current-state recovery mirror. This is a separate guarantee from cold checkpoints: encrypted current payloads, archive rows and custody catalog rows are written into the independent witness database in the **same SQLite transaction** as authority and its commitment, including key rotation. Immutable encrypted history segments are durably copied to `historyMirrorDirectory` before their heads can be published. No periodic backup interval or earlier checkpoint selects authority.

Mirrored stores use schema **3**. Older schema-1/2 writers refuse them; current writers reject removing mirror mode. SQLite opens the witness as its physical main database and attaches the primary database, so its super-journal remains in the witness domain when primary storage disappears. Startup authenticates the latest payload and verifies mirror-table consistency. The supported guarantee is recovery of acknowledged committed state when primary data/history are lost **and the current witness databases, their journals, complete history mirrors and current runtime keys survive intact**. A transaction whose caller did not receive confirmation may be present or absent according to SQLite recovery; existing unknown-outcome reconciliation still applies. This is neither multi-owner replication nor recovery from simultaneous witness/key loss.

The regular runtime mounts no offline custody secrets. Native current repair uses the existing private runtime keyring, independent witnesses and history mirror; it does **not** mount the offline escrow keyring. The `maintenance` profile already mounts those live data/config/witness/history domains and has no network.

1. Stop every service/maintenance owner. Preserve surviving witness files **and all their journals/super-journals**. Do not remove journals manually or replace witnesses with backup copies.
2. If entire primary directories were lost, recreate the configured primary data and history directories at the same canonical paths with UID/GID 10001 and mode 0700. Do not recreate missing witness or mirror directories as empty replacements. Repair requires their authentic surviving contents.
3. Run the exact-current preview and reviewed apply:

```sh
docker compose -f deployment/production/compose.yaml --profile maintenance run --rm --entrypoint node maintenance   apps/agent-ops/cli.mjs recovery --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}" --operation repair
docker compose -f deployment/production/compose.yaml --profile maintenance run --rm --entrypoint node maintenance   apps/agent-ops/cli.mjs recovery --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}" --operation repair   --apply --digest REVIEWED_CURRENT_REPAIR_DIGEST
```

Every registered store is exclusively locked through its surviving witness. SQLite resolves hot journals before any mirror is read. The command authenticates current payloads, archives and complete committed/pending history closure, stages and verifies all replacements before promoting a primary, and never changes a witness commitment. Originals and journals are captured atomically into private `.guard-original-*/original` directories; history originals use `.guard-history-original-*/original`. Damaged entries remain opaque, including symlinks. Publication refuses an unexpected newly appeared primary instead of overwriting it. Staged files remain private if interrupted, including the recoverable extra link left by interruption during publication. Repair can be retried with a **new preview** after interruption, including partial multi-store promotion. It always selects the then-current surviving witnesses, so a resumed owner's newer state supersedes an earlier preview rather than being overwritten.

4. The result reports `historyReenrollmentRequired: true`. Explicitly verify and re-enroll the restored history directory before normal startup, even if its path stayed the same:

```sh
docker compose -f deployment/production/compose.yaml --profile maintenance run --rm --entrypoint node maintenance   apps/agent-ops/cli.mjs enroll-history --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}"
docker compose -f deployment/production/compose.yaml --profile maintenance run --rm --entrypoint node maintenance   apps/agent-ops/cli.mjs enroll-history --config "${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}"   --apply --digest REVIEWED_HISTORY_ENROLLMENT_DIGEST
```

If a history-compaction transition was pending, its required target segment is restored too. Resume that exact reviewed `compact-history` transition; do not discard it or reconstruct another receipt. Run offline `check`, review unresolved work, then start the service. Keep preserved encrypted originals until recovery is verified. Native repair output contains only counts and digests, not business records or keys.

For a legacy installation, provision the configured private `historyMirrorDirectory` under independent witness custody, then use `enroll-history-mirror --config PATH` and its exact `--apply --digest HASH`. That operation verifies and backfills the entire history closure, enables both native store mirrors, and publishes the directory enrollment. A crash between enrollment phases is fail-closed and retryable using a fresh preview; do not start an older binary. The generic SDK offers `manageLedgerRecovery(options, {operation:'enroll'})` and `agent-guard-ledger recovery enroll --config PATH`; application history must use the authoritative host adapter, never a user-selected partial file list.

### Recover the independent custody catalog

New custody catalogs also enable schema-3 current-state mirroring. If the catalog's primary database is lost after runtime-key retirement, its current escrow/index can be repaired from the surviving independent custody witness and retained offline custody keyring. This operation uses the `custody` profile because it explicitly needs those offline secrets; the ordinary application repair does not.

Create a private `0600` `/run/agent-ops-custody-keys/catalog-recovery.json` through the corresponding host mount:

```json
{
  "version": 1,
  "keyringFile": "/run/agent-ops-custody-keys/keyring.json",
  "stores": [{
    "id": "custody",
    "database": "/var/lib/agent-ops-custody/catalog.sqlite",
    "witnessPath": "/var/lib/agent-ops-custody-witness/catalog.sqlite"
  }]
}
```

Run the generic CLI through the offline profile, first previewing and then applying its exact digest:

```sh
docker compose -f deployment/production/compose.yaml --profile custody run --rm --entrypoint node custody packages/executor/dist/ledger-maintenance-cli.js recovery repair --config /run/agent-ops-custody-keys/catalog-recovery.json
docker compose -f deployment/production/compose.yaml --profile custody run --rm --entrypoint node custody packages/executor/dist/ledger-maintenance-cli.js recovery repair --config /run/agent-ops-custody-keys/catalog-recovery.json --apply --digest REVIEWED_CATALOG_REPAIR_DIGEST
```

Existing pre-mirror custody catalogs must be migrated while their current primary database still authenticates: use the same two commands with `recovery enroll` in place of `recovery repair`. Enrollment atomically binds the current ciphertext and complete catalog rows under schema 3; it does not reset prior key issuance, retirements or backup inventory. After repair, run custody `status` and verify the registered backups before any new retirement. Lost current custody witnesses or all retained offline keys remain outside this recoverable-primary-loss guarantee.

## SDK use and test coverage

`manageLedgerCustody(options, request)` previews; pass `{expectedDigest: preview.digest}` as its third argument to apply. The options enroll an exact bounded store set and a host-only authoritative history adapter. The generic SDK CLI intentionally refuses ledgers with exported history unless such a host integration supplies the complete closure. All JSON outputs contain counts, limits, IDs, digests and outcomes, never raw keys or decrypted business records.

The custody tests cover both-store rotation, active retirement with old-backup readability, independent custody-key rotation, rollback/tamper refusal, complete business-history backup/restore, process termination after retirement intent, and partial restore-stage recovery. The current-state tests cover newer writes after a cold checkpoint, complete primary data/history loss, exact receipt preservation, rotation, archive/catalog replication, mode removal refusal, actual old-reader fencing, mirror-write rollback, process loss before/after commit, interrupted primary promotion, and a process killed after native super-journal publication with the entire primary directory removed.

These tests run locally and simulate process and storage loss. Physical power loss, controller flush behavior, independent-volume durability and simultaneous loss of independent domains must be validated on the deployment's actual storage.
