# Reviewed company history

Agent Ops can repeatedly free its live request/receipt capacity and its SDK archive
pool while preserving exact business evidence. This is an offline operation for the
single-owner ticket profile. The service never deletes history automatically.
General SDK archives containing delegation, source-task links or governed memory
keep their existing bounded retention profile; this compactor refuses them.

## What is retained

Each immutable encrypted segment contains the selected requests, exact backend
receipts, relevant business audit entries still retained when reviewed, and the
complete SDK family archives with original budgets, counters, revoked identities,
approvals and retained provenance. Earlier audit entries already pruned by the
bounded audit buffers cannot be recreated. Ticket records and their CAS versions
remain live and are never reset by compaction.

New request IDs combine an installation/company-specific random namespace with a
persisted increasing sequence. The backend reserves each sequence atomically with
its request. It never resets the sequence when records are exported. The SDK derives
a permanent deny-through fence from authenticated exported identities. A fence
stops before any live task, including uncertain work. Exported identities above such
a gap keep individual tombstones until a later reviewed operation can advance the
fence. Legacy UUID identities retain their individual tombstones permanently.
Changing a tenant cannot reuse a retired ID.

The backend keeps one authenticated history head/key and counter set per company.
Every new segment receives a fresh AES-256-GCM key. Its encrypted payload includes
the previous head and key, permitting complete backward verification without an
ever-growing live key catalog. A previously leaked ledger/head key cannot decrypt
a later segment. The exact canonical plaintext digest is committed before a pending
key/nonce is first used; a changed recovery payload is refused before encryption.
Keys and decrypted SDK evidence never enter browser responses, metrics or activity
exports. The latest head is protected by the encrypted, witnessed backend ledger;
the SDK independently commits the matching external-history hash.

Schema 2 fences older binaries from ledgers containing these authority semantics.
The default exact-current recovery profile uses schema 3, which also fences
readers that do not maintain the independent recovery mirror.
Keep the new reader for inspection and recovery. Restoring an older binary or
manually changing the schema number is not an upgrade rollback procedure.

## Enrollment and ordinary operation

New onboarding bundles include `historyDirectory`, defaulting to the data directory
name followed by `-history`. Standard container paths use
`/var/lib/agent-ops-history`. It is a separate private directory from live data,
witnesses and key/config custody. The runtime mount is read-only; offline
maintenance has write access. `historyMirrorDirectory` defaults to the private
`history-mirror` child of the backend witness directory. It must remain under that
independent custody, separate from primary data, history and keys. New stores
enable native exact-current encrypted mirroring before accepting work. Keep all
committed segments and verified off-host
copies. The external storage grows with history; compaction does not erase it or
shrink SQLite files securely.

For an existing installation, stop the owner, provision an owner-only history
directory, add its canonical absolute path to private configuration, and review
its enrollment:

```sh
node apps/agent-ops/cli.mjs enroll-history --config /private/config.json
node apps/agent-ops/cli.mjs enroll-history --config /private/config.json \
  --apply --digest REVIEW_DIGEST
```

For legacy exact-current recovery enrollment, provision the private mirror child,
add `historyMirrorDirectory` to configuration, then run:

```sh
node apps/agent-ops/cli.mjs enroll-history-mirror --config /private/config.json
node apps/agent-ops/cli.mjs enroll-history-mirror --config /private/config.json \
  --apply --digest REVIEW_DIGEST
```

This verifies and copies the complete authoritative history before enabling
native schema-3 mirroring for each store and publishing the history enrollment
marker. It never upgrades an incomplete copy to authority. A crash between store
enrollments leaves startup blocked; obtain a new preview and finish the same
enrollment while the owner remains stopped. The service refuses a missing mirror
configuration, unenrolled directory, incomplete native enrollment or missing
committed mirrored segment. This reviewed command also repairs a lost mirror
copy from a fully verified, intact primary chain; it never infers heads from file
names or promotes an old segment.

Run bounded maintenance before the live ledger is full. Both store owners must be
stopped; maintenance acquires both exclusive store locks. Preview one company and
review the eligible count, excluded unresolved count and blockers:

```sh
node apps/agent-ops/cli.mjs compact-history --config /private/config.json \
  --tenant COMPANY --limit 100
node apps/agent-ops/cli.mjs compact-history --config /private/config.json \
  --tenant COMPANY --limit 100 --apply --digest REVIEW_DIGEST
node apps/agent-ops/cli.mjs verify-history --config /private/config.json
```

The digest binds the exact company, selection, both ledger revisions and directory
identity. An intervening write requires another preview. Existing SDK archives are
exported first, which also permits reclaiming a full archive pool. Pending, running,
unconfirmed or referenced work is never exported as completed work. Excluded
unresolved requests remain live with their original reservations. Missing receipts
never justify failure settlement or redispatch.

Look up a compacted receipt without submitting another action:

```sh
node apps/agent-ops/cli.mjs lookup-history --config /private/config.json \
  --tenant COMPANY --request ORIGINAL_REQUEST_ID
```

`lookup-history` prints minimized request state and the exact receipt; the host-only
module also supports complete evidence inspection. Normal request lists contain the
remaining live records. The operator status reports local segment/count/head
metadata, not proof of off-host custody, restoration or alert delivery.

## Crash recovery and relocation

The commit order is: persist the exact reviewed intent; retire/archive eligible SDK
families; bind plaintext; fsync the exact immutable encrypted segment and directory
under independent mirror custody, then do the same for the primary history copy;
atomically compact SDK rows and identity fences; then atomically remove the exact
exported business rows and commit the new backend head. Partial temporary ciphertext
is safely restaged, never installed over another final segment.

The same ciphertext bytes are retained in both places. The mirror contains no
plaintext key. Its head keys come from the authenticated exact-current backend
state mirrored atomically with its witness commitment. A segment is recoverable
before either SDK or business head can refer to it, including the SDK-committed,
business-pending crash state. A conflicting existing mirror file stops compaction
before SDK archive deletion and is never silently overwritten.

An unfinished intent blocks ordinary startup and other maintenance mutations. Run
the same `compact-history` preview again. A `recovery-required` result identifies
the existing operation; explicitly applying its new digest resumes that operation.
It cannot select a replacement batch or change the encryption plaintext. A response
lost after the final commit leaves no pending intent and no duplicate effect.

Missing, substituted or unauthentic segments, inconsistent SDK/backend commitments,
or changed reviewed sources stop recovery. Preserve both stores, witnesses and
history. Restore the exact evidence through the reviewed custody procedure; do not
clear the intent, recreate authority, delete tombstones or infer that an uncertain
effect failed.

A restored/moved directory has a different identity. Copy the complete immutable
chain, stop the service, point configuration to the private replacement directory,
and run `enroll-history` preview/apply. This verifies every committed segment before
rebinding custody. For an interrupted SDK compaction it also verifies the pending
export needed for recovery. Enrollment does not clear that intent: complete its
reviewed `compact-history` recovery afterward. Never replace the current witnesses
with an older data backup merely to make a restored ledger open.

For primary database/history loss with current independent witnesses, mirrors and
keys intact, stop the owner and preserve the damaged files for investigation.
Recreate the private primary history directory if its volume was lost, retaining
the configured canonical path. Then review current recovery:

```sh
node apps/agent-ops/cli.mjs recovery --config /private/config.json --operation repair
node apps/agent-ops/cli.mjs recovery --config /private/config.json --operation repair \
  --apply --digest REVIEW_DIGEST
node apps/agent-ops/cli.mjs enroll-history --config /private/config.json
node apps/agent-ops/cli.mjs enroll-history --config /private/config.json \
  --apply --digest REVIEW_DIGEST
```

Repair reads the current witness-bound state rather than a possibly stale cold
backup. It verifies the complete mirrored history closure, including any pending
segment required by an advanced SDK head, before restoring exact primary evidence.
It does not roll witnesses back, clear unresolved work, or redispatch actions.
Reviewed repair preserves existing primary database/history files under private
recovery names before installing the exact current copies; inspect and retain
those originals according to the incident procedure. Immutable compaction and
mirror backfill themselves never overwrite conflicting segments. Directory
re-enrollment binds restored custody after complete verification. If an intent
remains pending, finish its reviewed `compact-history` recovery before restart.
Run `verify-history` and `check` after recovery. This procedure cannot recover
simultaneous loss of current independent witnesses/mirrors and keys, and does not
replace separately verified off-host backups or storage durability acceptance.

## Resource and verification boundaries

An operation exports at most 100 requests and 16 MiB of decoded segment content;
the encrypted file bound is 24 MiB. It uses at most 10,000 company namespaces and
safe-integer sequences/segment numbers, stopping before overflow. New numbered
identities ordinarily reduce to a constant fence. Persistent unresolved gaps and
legacy UUIDs can still reach the SDK's 65,536 residual-identifier bound; this is a
safe stop requiring resolution or a separately reviewed migration, not eviction.

Startup and offline verification check the full backward chain and, when enabled,
its exact mirrored ciphertext copy. They use one
segment at a time plus bounded live ledger snapshots, with I/O/CPU proportional to
retained history. They are not constant-time startup. Ordinary tool calls do not
rescan old media. Protect the read-only runtime history mount, monitor storage and
schedule verification/custody checks. Budget maintenance windows and startup health
grace periods using measurements on the deployment's retained history and storage.

The supported backup and exact-current repair manifest holds at most **10,000
segments across the whole deployment**, not per company. Usage is the sum of
authenticated company head indexes plus one reserved slot for a durable pending
compaction intent. New compaction refuses with `HISTORY_SEGMENT_CAPACITY` before
committing intent, archiving tasks, publishing files or advancing either head when
that additional segment would exceed the ceiling. The transaction rechecks the
reservation. The ceiling protects recovery and is not a configurable business limit.

A pending operation that reserved the final slot can still resume. Even after the
SDK head advances, the business head remains at the previous segment until its
head update and pending-intent removal commit together; the slot is counted once.
Operator capacity status includes committed and reserved deployment-wide usage,
with warnings at 80% and critical alerts at 95%.

An existing history or pending intent from an older writer above this ceiling
requires a separately reviewed migration. Normal startup and compaction refuse
with `HISTORY_MIGRATION_REQUIRED` before executor recovery or authority changes;
the stores, witnesses and retained evidence are preserved. Before reaching the
ceiling, plan a reviewed compatible streaming/partitioned custody and repair
implementation or migration. Do not delete segments, reset counters or alter
witnesses to fit the bound. The custody adapter also retains its defensive
`HISTORY_BACKUP_FILE_LIMIT` check and never returns a truncated closure. Independent
custody verification is still required for actual off-host backup and restore
acceptance.

`apps/agent-ops/test/retention.test.mjs` checks recurring capacity reuse, legacy
budget/tombstone preservation, unresolved gaps, all commit-phase recovery points,
nonce/plaintext binding, immutable staging, missing/tampered segments, witnessed
rollback rejection, future-key separation and verified fresh-directory recovery.
`apps/agent-ops/test/history-recovery.test.mjs` checks mirrored publication order,
complete backfill and partial enrollment recovery, pending closure completeness,
immutable conflict refusal and explicit restored-directory enrollment.
Its local multi-segment timing is a fixture measurement, not a deployment throughput
or storage SLA. Linux container/installed-entry-point results are recorded separately.
