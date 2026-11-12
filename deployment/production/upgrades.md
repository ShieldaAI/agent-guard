# Upgrade and failed-upgrade recovery

Schedule an offline window with the single deployment owner. Record the running
image digest, source revision, configuration and a verified cold backup before
changing the service. Keep the current witnesses under their independent custody;
they are never restored from the data backup. Verify the new image against
disposable data first, including the actual company's storage and TLS/OIDC setup.

1. Stop `agent-ops` and wait for the process to release both stores. Preserve all
   original database and SQLite recovery files. Complete any pending maintenance
   recovery before changing versions.
2. Make and verify a cold backup using the custody runbook. Preserve the complete
   active and offline key material and every referenced encrypted history file.
   Store the backup with access controls independent of the live service.
3. Build or obtain the reviewed immutable image of the new version. It must meet
   the Node version floor in the [runbook](README.md#build-and-local-verification).
   Read its migration and compatibility notes, inspect the dependency inventory,
   and verify its exact checks. A mutable tag is not a release identity.
4. Run the new image's offline `check` and `preflight` with the production
   configuration, then start exactly one owner. Complete company sign-in, scoped
   read-only inspection and a dedicated test-ticket review. Confirm the receipt
   at the backend, monitoring delivery and readiness before reopening agent work.

## Ledger compatibility and binary rollback

The current reader accepts schema 1, 2 and 3 ledgers. New
retirement/history/custody semantics persist at least schema 2 atomically with the
authority transition. Native current-state recovery requires schema 3, which
enforces atomic mirroring under independent witness custody. New Ops deployments
enable this by default; existing deployments use the reviewed history-mirror
enrollment procedure. Published alpha.3 readers accept only schema 1 and reject
later schemas. Pre-mirror schema 2 readers reject schema 3. These fences matter
because older code does not understand archived-ID
tombstones or namespace retirement fences: allowing it to interpret current
state could recreate authority that had already been spent and retired, or stop
updating the recovery mirror without reporting the lost protection.

Regression tests cover both fences. One creates and spends a task with the
published alpha.3 package, opens it with the current code, retires and archives
it, and verifies that alpha.3 then refuses the database without changing its
bytes, while the current reader still rejects reuse of the retired task ID. The
other verifies that a frozen pre-mirror reader refuses schema 3 without changing
either current database or witness bytes.

An image rollback is allowed only when that reader understands the **current**
ledger semantics and configuration. Do not edit `schema`, remove history fields,
delete a catalog, replace a witness, or initialize new authority to make an older
image start. A pre-upgrade data backup will normally be stale once the current
owner has advanced witnessed state; a failed restore is a deliberate safety
boundary, not an instruction to restore the witness too.

If the new image fails after changing state, keep admission stopped, preserve the
current data/witness/history/key set and diagnostics, and use a compatible fixed
image or the documented current-witness recovery procedure. When independent
custody or required evidence is lost, do not infer that previous actions failed.
Preserve unresolved reservations and investigate the backend receipts. The
runbook does not promise automatic rollback across an authority migration.

A renewed TLS key and certificate do not need a restart. Publish the
company-controlled private files atomically, run preflight, then send `SIGHUP`:
the service reloads them in place for new connections and invalidates existing
sessions. A mismatched, not-yet-valid or expired served leaf certificate is
refused, and a failed reload stops the service. A changed OIDC secret, like any
other configuration change, needs an orderly restart (run preflight first; the
restart also invalidates sessions). Keep maintenance available to repair
configuration even when a served certificate has expired.
