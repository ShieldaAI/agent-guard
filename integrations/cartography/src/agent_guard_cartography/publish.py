"""Collector orchestration; persist complete observations before graph publication."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.cloud import CloudJoinError, CloudScope
from agent_guard_cartography.collector import CollectionError, CollectorEnrollment, collect_snapshot
from agent_guard_cartography.graph import (
    GraphImportError,
    ImportResult,
    cleanup_staging,
    import_snapshot,
    retire_projection,
)
from agent_guard_cartography.inventory import InventoryValidationError


@dataclass(frozen=True)
class CollectionResult:
    receipt_id: str
    import_result: ImportResult
    generated_at: str
    duration_ms: int

    def summary(self) -> dict:
        return {**asdict(self), "status": "complete"}


def _code(error: Exception) -> str:
    if isinstance(
        error,
        (ArchiveError, CloudJoinError, CollectionError, GraphImportError, InventoryValidationError),
    ):
        return error.code
    return "COLLECTION_FAILED"


def _failed_health(
    archive: SnapshotArchive, enrollment: CollectorEnrollment, error: Exception
) -> None:
    try:
        archive.record_health(enrollment.source, enrollment.profile, error_code=_code(error))
    except Exception:
        # Disk failures cannot replace the original transport/publication diagnostic.
        pass


def collect_and_publish(
    session,
    enrollment: CollectorEnrollment,
    token: str,
    archive: SnapshotArchive,
    *,
    cloud_scope: CloudScope | None = None,
) -> CollectionResult:
    """Caller holds the database's ingestion lock for the entire collection."""
    archive.require_publishable_source(enrollment.source)
    started = time.monotonic()
    try:
        snapshot = collect_snapshot(enrollment, token)
        receipt = archive.store(snapshot)
    except Exception as error:
        _failed_health(archive, enrollment, error)
        raise
    return publish_receipt(
        session,
        enrollment,
        archive,
        receipt.receipt_id,
        cloud_scope=cloud_scope,
        started=started,
    )


def publish_receipt(
    session,
    enrollment: CollectorEnrollment,
    archive: SnapshotArchive,
    receipt_id: str,
    *,
    cloud_scope: CloudScope | None = None,
    started: float | None = None,
) -> CollectionResult:
    """Retry a protected receipt after restart; the graph enforces idempotency/revisions."""
    # Expected lifecycle/recovery fences must precede graph writes and receipt
    # failure bookkeeping, preserving the confirmed recovery evidence unchanged.
    archive.require_publishable_source(enrollment.source)
    started = time.monotonic() if started is None else started
    loaded = False
    try:
        snapshot = archive.load(receipt_id, enrollment.source, enrollment.profile)
        loaded = True
        result = import_snapshot(
            session,
            snapshot,
            enrollment.source,
            cloud_scope=cloud_scope,
        )
        archive.record_result(receipt_id, result)
        archive.record_health(
            enrollment.source, enrollment.profile, result=result, snapshot=snapshot
        )
    except Exception as error:
        if loaded:
            try:
                archive.record_failure(receipt_id, _code(error))
            except Exception:
                pass
        _failed_health(archive, enrollment, error)
        raise
    return CollectionResult(
        receipt_id,
        result,
        snapshot["generatedAt"],
        int((time.monotonic() - started) * 1000),
    )


def retire_obsolete(
    session,
    source_id: str,
    *,
    minimum_retention_seconds: int = 3600,
    limit: int = 32,
) -> int:
    """Bounded maintenance under the same lock, scoped to this enrolled source only."""
    if (
        type(minimum_retention_seconds) is not int
        or minimum_retention_seconds < 60
        or type(limit) is not int
        or not 1 <= limit <= 128
    ):
        raise GraphImportError("RETENTION_INVALID")
    cutoff = int(time.time() * 1000) - minimum_retention_seconds * 1000
    candidates = list(
        session.run(
            "MATCH (s:GuardSource {id:$source}),(p:GuardSnapshot {source_id:$source}) "
            "WHERE (s.lifecycle_status='superseded' OR "
            "NOT p.id IN [coalesce(s.current_snapshot_id,''),coalesce(s.previous_snapshot_id,'')]) "
            "AND (coalesce(s.lifecycle_status,'active')='active' OR "
            "(s.lifecycle_status='superseded' AND s.superseded_at_ms < $cutoff)) "
            "AND ((p.status='published' AND p.published_at_ms < $cutoff) OR "
            "(p.status IN ['staging','failed','cleaning'] AND p.created_at_ms < $cutoff)) "
            "RETURN p.id AS id,p.status AS status ORDER BY p.created_at_ms LIMIT $limit",
            source=source_id,
            cutoff=cutoff,
            limit=limit,
        )
    )
    retired = 0
    for candidate in candidates:
        try:
            if candidate["status"] == "published":
                retire_projection(
                    session, candidate["id"], minimum_retention_seconds=minimum_retention_seconds
                )
            else:
                cleanup_staging(session, candidate["id"])
            retired += 1
        except GraphImportError as error:
            if error.code not in (
                "PROJECTION_PROTECTED",
                "PROJECTION_RETENTION",
                "PROJECTION_NOT_STAGING",
                "PROJECTION_NOT_PUBLISHED",
            ):
                raise
    return retired


def prune_archive(session, archive: SnapshotArchive) -> int:
    """Protect actual database pointers as well as the archive's local publication receipts."""
    pointers = list(
        session.run(
            "MATCH (s:GuardSource) RETURN s.current_snapshot_id AS current, "
            "s.previous_snapshot_id AS previous LIMIT 10001"
        )
    )
    if len(pointers) > 10000:
        raise GraphImportError("MAINTENANCE_LIMIT_EXCEEDED")
    protected = tuple(
        {row[key] for row in pointers for key in ("current", "previous") if row[key] is not None}
    )
    return archive.prune(protected_projection_ids=protected)


def retire_superseded(
    session,
    archive: SnapshotArchive,
    *,
    minimum_retention_seconds: int = 3600,
    limit: int = 32,
) -> int:
    """Maintain completed supersessions even when old sources are no longer enrolled."""
    if (
        type(minimum_retention_seconds) is not int
        or minimum_retention_seconds < 60
        or type(limit) is not int
        or not 1 <= limit <= 128
    ):
        raise GraphImportError("RETENTION_INVALID")
    records = archive.list_transitions()
    if len(records) > 128:
        raise GraphImportError("MAINTENANCE_LIMIT_EXCEEDED")
    retired = 0
    for record in records:
        if record["status"] != "complete":
            continue
        receipt = record["receipt"]
        # A completed local journal must agree with this graph's tombstone;
        # mismatched/restoring graphs never turn an active source into cleanup work.
        current = session.run(
            "MATCH (s:GuardSource {id:$id,lifecycle_status:'superseded',"
            "lifecycle_operation_id:$operation,superseded_by:$successor,"
            "superseded_at_ms:$timestamp}) RETURN s.id AS id",
            id=receipt["predecessorSourceId"],
            operation=receipt["transitionId"],
            successor=receipt["successorSourceId"],
            timestamp=receipt["supersededAtMs"],
        ).single()
        if current is None:
            continue
        retired += retire_obsolete(
            session,
            receipt["predecessorSourceId"],
            minimum_retention_seconds=minimum_retention_seconds,
            limit=limit - retired,
        )
        if retired >= limit:
            break
    return retired
