# Replace an enrolled source generation

An executor restore or clone must use a newly approved `enrollmentGeneration`.
The five-field source identity remains exact: company, native source, tenant,
enrollment generation and persistent inventory instance. A new generation is a
separate source until the trusted host explicitly supersedes its predecessor.
Removing an enrollment file or failing to collect a source never retires it.

## Perform an explicit replacement

1. Configure and collect the approved successor with the normal collector, using
   the existing private archive and the same ingestion lock as every writer to
   this database. Require a successful complete publication. Failed successor
   collection leaves the predecessor active.
2. Copy [source-transition.json](../../integrations/cartography/examples/source-transition.json)
   into the host's private configuration directory. Replace both source objects
   with the exact approved identities and set the pinned profile. Company,
   native `sourceId` and tenant must match; enrollment generations must differ.
   A restored ledger may retain its instance ID; a newly initialized clone has
   its own instance ID. Profile migration is not part of this operation.
3. Stop any polling collector using this database before running the lifecycle
   command. A `--watch` collector holds the ingestion lock for its entire run;
   the lifecycle command otherwise fails with `INGESTION_ALREADY_RUNNING`.
   The independent executor can continue running. Run the lifecycle command
   with the same database, archive and lock:

   ```sh
   cd integrations/cartography
   uv run agent-guard-source-lifecycle \
     --transition "$HOME/.config/agent-guard-cartography/source-transition.json" \
     --archive-dir "$HOME/.local/share/agent-guard-cartography/archive" \
     --neo4j-uri bolt://127.0.0.1:7687 \
     --neo4j-password-env-var NEO4J_PASSWORD \
     --lock-file "$HOME/.local/share/agent-guard-cartography/ingestion.lock"
   ```

   Set `NEO4J_PASSWORD` through the existing trusted secret mechanism. The command
   also supports verified `bolt+s`/`neo4j+s` and an explicit database/user. The
   equivalent module entry point is `python -m agent_guard_cartography.lifecycle`.
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
that boundary, **rerun the exact transition command with the same archive and
lock**. Graph idempotency reconciles an already-committed operation without
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

Backup expands the supplied active enrollment metadata through connected,
completed transitions so predecessor evidence is included. Unrelated sources
remain out of scope. File hashes cover the journals. Restore preserves them, and
fresh-graph replay reconstructs snapshots before applying transitions in order.
The new working archive receives the same completed lifecycle decisions.

Interrupted reconstruction retains a private recovery marker; normal collection,
receipt replay, pruning and backup refuse that incomplete archive. The collector
checks this before AWS/observer collection and maintenance; database connectivity
may still be verified first. Rejected replay preserves confirmed receipt bytes.
Use another fresh Guard graph and
new working archive for a retry. Start the reference service only after replay
returns complete. Never reconstruct into an existing Guard graph, overwrite an
authority ledger, or remove tombstones to reuse an old generation.

This command is an explicit enrollment lifecycle operation. It does not discover
executors, infer revocation from outages, rotate credentials, or provide
distributed-worker fencing.
