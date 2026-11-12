# Replace an enrolled source generation

When an executor is restored from a backup or cloned, its inventory can no
longer be trusted to continue the old one. The host (your trusted application
code) enrolls it with a new `enrollmentGeneration`, and the
[collector](../../integrations/cartography/README.md) treats it as a separate
source. This guide retires the old generation once the new one is published.

A source is identified by five fields: company, source, tenant, enrollment
generation and inventory instance. The old generation stays active until you
run the command below. Removing an enrollment file, or failing to collect a
source, never retires it.

## Perform an explicit replacement

1. Enroll and collect the successor with the collector, using the same archive
   as before, until it publishes successfully. A failed successor
   collection leaves the predecessor active.
2. Copy [source-transition.json](../../integrations/cartography/examples/source-transition.json)
   to `$CONFIG/source-transition.json` (mode 0600). Replace both source objects
   with the exact approved identities and set the pinned profile. Company,
   native `sourceId` and tenant must match; enrollment generations must differ.
   A restored ledger may retain its instance ID; a newly initialized clone has
   its own instance ID. Profile migration is not part of this operation.
3. Stop any polling collector using this database before running the lifecycle
   command. A `--watch` collector holds the archive's lock for its entire run;
   the lifecycle command otherwise fails with `INGESTION_ALREADY_RUNNING`.
   The independent executor can continue running. Run the lifecycle command
   with the same database and archive; it takes the archive's lock itself:

   ```sh
   CONFIG="$HOME/.config/agent-guard-cartography"       # enrollment files
   STATE="$HOME/.local/share/agent-guard-cartography"   # archive, lock, backups
   cd integrations/cartography
   uv run agent-guard-source-lifecycle \
     --transition "$CONFIG/source-transition.json" \
     --archive-dir "$STATE/archive" \
     --neo4j-uri bolt://127.0.0.1:7687
   ```

   The password is read from `NEO4J_PASSWORD`. `--archive-dir` must be the
   collector's existing archive: a path that does not exist fails with
   `ARCHIVE_DIRECTORY_NOT_FOUND` instead of creating an empty archive (pass
   `--create` only if you really mean a new one). The command accepts the same
   archive, lock and Neo4j options as the collector.
4. Restart polling with only the successor in the active collection queue.
   Normal polling also
   performs bounded retirement maintenance for completed predecessor journals,
   even though those predecessors are no longer enrolled.

Preflight requires matching published graph endpoints and confirmed archived
evidence. An ordinary invalid request creates no pending transition. Both graph
sources are checked again under ordered source locks before the transaction
commits. That transaction marks the predecessor superseded, saves its old
projection pointers in audit fields, and clears its normal current/previous
pointers. New reads exclude it; a read whose captured source set changes before
final validation fails as a whole. No executor authority, provider inventory or
other tenant changes.

The safe receipt contains transition/source hashes, profile and supersession
time. Repeating the exact command returns the original receipt. A conflicting
successor or an attempt to reactivate an old generation is rejected. Direct
snapshot import and an already-staged publication also reject a superseded
source, including replay of an otherwise idempotent old snapshot.

## Handle an interrupted transition

The private archive writes a pending intent before graph mutation and completes
it after the graph receipt is durable. If the process or connection fails at
that boundary, **rerun the exact transition command with the same archive**.
Graph idempotency reconciles an already-committed operation without
reactivating the old source. The journal intentionally remains pending if the
commit outcome cannot be established.

Pending intents reject predecessor collection and receipt replay before observer
requests, graph writes or receipt updates. They also block backup/reconstruction
and different lifecycle operations. Do not delete or rename a journal to bypass
these checks. An active successor may still collect or replay its receipts. Once
the original intent is reconciled, later replacements can proceed. Completed chains and explicit
multiple-predecessor replacements are supported; cycles, conflicting successors
and incompatible profiles are rejected.

## Retention and reconstruction

Normal collector maintenance retires at most 32 superseded projections per
cycle. It verifies each completed journal against the graph tombstone and waits
for the configured grace period, measured from the later of snapshot publication
and supersession. It removes only allowlisted entities belonging to that exact
projection. Snapshot receipts, source tombstones, shared provider nodes and
other scopes remain intact.

The archive retains its latest two confirmed snapshots per source as recovery
anchors, including superseded generations. Journals are retained as well. This
is bounded recovery evidence, not a promise to delete every old archive file
after seven days. Existing archive byte/snapshot limits still apply, and lifecycle
metadata supports at most 128 distinct source identities across all journals in
the archive. Capacity exhaustion
fails closed; it never silently discards a tombstone.

`agent-guard-recovery backup` follows completed transitions from the
enrollments you name, so predecessor evidence is included; unrelated sources
are not. The backup's hashes cover the journals. `restore` preserves them, and
`replay` rebuilds the snapshots before applying the transitions in order, so
the new working archive holds the same completed decisions.

An interrupted reconstruction leaves a marker in its working archive, and
collection, receipt replay, pruning and backup all refuse that archive. Retry
with another empty database and a new working archive, as the
[runbook](RUNBOOK.md#back-up-and-reconstruct) describes, and start the Agent Map
service only after replay reports `complete`. Never reconstruct into a graph
that already holds Guard data, overwrite an executor's ledger, or remove a
journal to reuse an old generation.

The command does only this replacement. It does not discover executors, infer
revocation from outages, rotate credentials or coordinate collectors on
different hosts.
