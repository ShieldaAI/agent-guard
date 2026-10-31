"""Exercise the actual Cartography loader and cleanup against disposable Neo4j."""

from copy import deepcopy

import pytest
from cartography.config import Config

from agent_guard_cartography.graph import (
    GraphImportError,
    cleanup_projection_rows,
    cleanup_staging,
    import_snapshot,
    retire_projection,
    source_key,
)
from agent_guard_cartography.inventory import InventoryValidationError

pytestmark = pytest.mark.integration


def node_count(session, label, projection_id):
    assert label in {"GuardTask", "GuardTool", "GuardResource", "GuardGrant", "GuardPrincipal"}
    return session.run(
        f"MATCH (n:{label} {{projection_id:$projection}}) RETURN count(n) AS count",
        projection=projection_id,
    ).single(strict=True)["count"]


def source_state(session, source_id):
    return dict(
        session.run(
            "MATCH (s:GuardSource {id:$id}) RETURN s",
            id=source_id,
        ).single(strict=True)["s"]
    )


def current_task_ids(session, source_id):
    return {
        row["id"]
        for row in session.run(
            "MATCH (s:GuardSource {id:$source}), "
            "(t:GuardTask)-[:G_IN_SNAPSHOT]->(p:GuardSnapshot) "
            "WHERE p.id=s.current_snapshot_id RETURN t.task_id AS id",
            source=source_id,
        )
    }


def test_custom_stage_and_two_snapshot_publication(neo4j_driver, neo4j_session, snapshot_factory):
    from agent_guard_cartography.cli import build_sync

    first = snapshot_factory()
    results = []
    sync = build_sync(first, first["source"], on_result=results.append)
    assert (
        sync.run(
            neo4j_driver,
            Config(
                neo4j_uri="bolt://unused-by-custom-stage",
                neo4j_database="neo4j",
                update_tag=100,
            ),
        )
        == 0
    )
    assert len(results) == 1
    original = results[0]
    assert original.published
    assert current_task_ids(neo4j_session, original.source_id) == {
        "research-root",
        "review-child",
        "handoff-task",
    }
    second = snapshot_factory("alpha-v2")
    updated = import_snapshot(neo4j_session, second, second["source"], update_tag=101)
    source = source_state(neo4j_session, original.source_id)
    assert source["current_snapshot_id"] == updated.projection_id
    assert source["previous_snapshot_id"] == original.projection_id
    assert source["ledger_revision"] == 2
    assert current_task_ids(neo4j_session, original.source_id) == {"research-root", "handoff-task"}
    # Publication keeps the previous generation intact for evidence/history.
    assert node_count(neo4j_session, "GuardTask", original.projection_id) == 3
    assert node_count(neo4j_session, "GuardTask", updated.projection_id) == 2
    removed_tool = neo4j_session.run(
        "MATCH (t:GuardTool {projection_id:$projection,name:'records.delete'}) RETURN count(t) AS count",
        projection=updated.projection_id,
    ).single(strict=True)["count"]
    assert removed_tool == 0
    grant_ids = [
        row["entity"]
        for row in neo4j_session.run(
            "MATCH (g:GuardGrant {task_id:'research-root',tool:'records.read'}) "
            "WHERE g.projection_id IN $projections RETURN g.entity_id AS entity",
            projections=[original.projection_id, updated.projection_id],
        )
    ]
    assert len(grant_ids) == 2 and len(set(grant_ids)) == 1


def test_grants_remain_declared_and_provenance_is_not_delegation(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory()
    # Child first proves relationship loading does not depend on input order.
    snapshot["tasks"] = list(reversed(snapshot["tasks"]))
    root = next(task for task in snapshot["tasks"] if task["id"] == "research-root")
    root["grants"][0]["resources"] = ["*"]
    result = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=200)
    relations = {
        (row["child"], row["kind"], row["parent"])
        for row in neo4j_session.run(
            "MATCH (a:GuardTask {projection_id:$projection})-[r:G_DELEGATED_FROM|G_DERIVED_FROM]->"
            "(b:GuardTask) RETURN a.task_id AS child,type(r) AS kind,b.task_id AS parent",
            projection=result.projection_id,
        )
    }
    assert relations == {
        ("review-child", "G_DELEGATED_FROM", "research-root"),
        ("handoff-task", "G_DERIVED_FROM", "research-root"),
    }
    principals = {
        row["task"]: row["principal"]
        for row in neo4j_session.run(
            "MATCH (t:GuardTask {projection_id:$projection})-[:G_ACTS_AS]->(p:GuardPrincipal) "
            "RETURN t.task_id AS task,p.principal_id AS principal",
            projection=result.projection_id,
        )
    }
    assert principals == {
        "research-root": "operator-1",
        "review-child": "operator-1",
        "handoff-task": "operator-2",
    }
    grants = list(
        neo4j_session.run(
            "MATCH (g:GuardGrant {projection_id:$projection}) RETURN g.evidence_kind AS evidence,g.assessment AS assessment",
            projection=result.projection_id,
        )
    )
    assert grants and all(
        row["evidence"] == "declared" and row["assessment"] == "unknown" for row in grants
    )
    wildcard = neo4j_session.run(
        "MATCH (r:GuardResource {projection_id:$projection,resource_id:'*'}) "
        "RETURN r.selector_kind AS kind,count(r) AS count",
        projection=result.projection_id,
    ).single(strict=True)
    assert wildcard["kind"] == "wildcard" and wildcard["count"] == 1
    assert (
        neo4j_session.run(
            "MATCH (r:GuardResource {projection_id:$projection})-[:CAN_READ|CAN_WRITE]->() RETURN count(r) AS count",
            projection=result.projection_id,
        ).single(strict=True)["count"]
        == 0
    )


def test_idempotency_and_conflicting_snapshot_id(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory()
    first = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=300)
    duplicate = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=301)
    assert duplicate.idempotent and not duplicate.published
    assert duplicate.projection_id == first.projection_id
    assert (
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source}) RETURN count(p) AS count",
            source=first.source_id,
        ).single(strict=True)["count"]
        == 1
    )
    changed = deepcopy(snapshot)
    changed["tasks"][0]["usage"]["calls"] = 1
    with pytest.raises(GraphImportError, match="SNAPSHOT_ID_CONFLICT"):
        import_snapshot(neo4j_session, changed, changed["source"], update_tag=302)
    assert (
        source_state(neo4j_session, first.source_id)["current_snapshot_id"] == first.projection_id
    )


def test_old_revision_and_wrong_source_cannot_publish(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory("alpha-v2")
    current = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=400)
    stale = snapshot_factory()
    stale["snapshotId"] = "new-id-for-old-revision"
    with pytest.raises(GraphImportError, match="REVISION_ROLLBACK"):
        import_snapshot(neo4j_session, stale, stale["source"], update_tag=401)
    expected = dict(snapshot["source"], tenantId="not-authorized")
    with pytest.raises(GraphImportError, match="SOURCE_SCOPE_MISMATCH"):
        import_snapshot(neo4j_session, snapshot, expected, update_tag=402)
    assert (
        source_state(neo4j_session, current.source_id)["current_snapshot_id"]
        == current.projection_id
    )


def test_same_revision_cannot_change_core_authority(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory()
    current = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=450)
    changed = deepcopy(snapshot)
    changed["snapshotId"] = "changed-authority-at-same-revision"
    changed["tasks"][0]["grants"][0]["resources"] = ["*"]
    with pytest.raises(GraphImportError, match="REVISION_CONTENT_CONFLICT"):
        import_snapshot(neo4j_session, changed, changed["source"], update_tag=451)
    assert (
        source_state(neo4j_session, current.source_id)["current_snapshot_id"]
        == current.projection_id
    )


def test_same_revision_can_refresh_capture_times(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory()
    original = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=460)
    refreshed = deepcopy(snapshot)
    refreshed["snapshotId"] = "same-authority-fresh-capture"
    refreshed["generatedAt"] = "2026-10-29T12:05:00Z"
    for component in ("tasks", "tools"):
        refreshed["coverage"][component]["observedAt"] = refreshed["generatedAt"]
    updated = import_snapshot(neo4j_session, refreshed, refreshed["source"], update_tag=461)
    assert updated.published
    source = source_state(neo4j_session, original.source_id)
    assert source["current_snapshot_id"] == updated.projection_id
    assert source["previous_snapshot_id"] == original.projection_id
    assert source["ledger_revision"] == 1


def test_unknown_tool_is_visible_without_invented_availability(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory()
    snapshot["tasks"][0]["grants"].append({"tool": "future-tool", "resources": ["report-A"]})
    result = import_snapshot(neo4j_session, snapshot, snapshot["source"], update_tag=470)
    tool = neo4j_session.run(
        "MATCH (t:GuardTool {projection_id:$projection,name:'future-tool'}) "
        "RETURN t.known_metadata AS known,t.registered AS registered,t.approved AS approved",
        projection=result.projection_id,
    ).single(strict=True)
    assert tool["known"] is False
    assert tool["registered"] is None and tool["approved"] is None


def test_invalid_snapshot_cannot_change_published_graph(neo4j_session, snapshot_factory):
    first = snapshot_factory()
    result = import_snapshot(neo4j_session, first, first["source"], update_tag=500)
    invalid = snapshot_factory("alpha-v2")
    invalid["tasks"][0]["tokenHash"] = "must-never-enter-the-graph"
    with pytest.raises(InventoryValidationError):
        import_snapshot(neo4j_session, invalid, invalid["source"], update_tag=501)
    assert (
        source_state(neo4j_session, result.source_id)["current_snapshot_id"] == result.projection_id
    )
    assert (
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source}) RETURN count(p) AS count",
            source=result.source_id,
        ).single(strict=True)["count"]
        == 1
    )


def test_interrupted_staging_keeps_previous_view_and_can_be_discarded(
    neo4j_session, snapshot_factory
):
    first = snapshot_factory()
    original = import_snapshot(neo4j_session, first, first["source"], update_tag=600)
    second = snapshot_factory("alpha-v2")

    def fail():
        raise RuntimeError("synthetic interruption before publication")

    with pytest.raises(RuntimeError, match="synthetic interruption"):
        import_snapshot(neo4j_session, second, second["source"], update_tag=601, after_load=fail)
    assert (
        source_state(neo4j_session, original.source_id)["current_snapshot_id"]
        == original.projection_id
    )
    assert "review-child" in current_task_ids(neo4j_session, original.source_id)
    failed = neo4j_session.run(
        "MATCH (p:GuardSnapshot {source_id:$source,status:'failed'}) RETURN p.id AS id",
        source=original.source_id,
    ).single(strict=True)["id"]
    assert node_count(neo4j_session, "GuardTask", failed) == 2
    cleanup_staging(neo4j_session, failed)
    assert node_count(neo4j_session, "GuardTask", failed) == 0
    assert node_count(neo4j_session, "GuardTask", original.projection_id) == 3
    retried = import_snapshot(neo4j_session, second, second["source"], update_tag=602)
    assert retried.published and retried.projection_id != failed


def test_late_import_cannot_overwrite_newer_publication(neo4j_session, snapshot_factory):
    first = snapshot_factory()
    original = import_snapshot(neo4j_session, first, first["source"], update_tag=700)
    second = snapshot_factory("alpha-v2")
    third = deepcopy(second)
    third["snapshotId"] = "third-snapshot"
    third["ledgerRevision"] = 3
    winner = []

    def publish_newer():
        winner.append(import_snapshot(neo4j_session, third, third["source"], update_tag=702))

    with pytest.raises(GraphImportError, match="PUBLICATION_CONFLICT"):
        import_snapshot(
            neo4j_session, second, second["source"], update_tag=701, after_load=publish_newer
        )
    source = source_state(neo4j_session, original.source_id)
    assert source["current_snapshot_id"] == winner[0].projection_id
    assert source["previous_snapshot_id"] == original.projection_id


def test_missing_required_relationship_prevents_publication(neo4j_session, snapshot_factory):
    first = snapshot_factory()
    original = import_snapshot(neo4j_session, first, first["source"], update_tag=750)
    incomplete = deepcopy(first)
    incomplete.update(snapshotId="missing-delegation-edge", ledgerRevision=2)

    def remove_delegation():
        neo4j_session.run(
            "MATCH (a:GuardTask)-[r:G_DELEGATED_FROM]->(:GuardTask), "
            "(a)-[:G_IN_SNAPSHOT]->(p:GuardSnapshot {source_id:$source,status:'staging'}) "
            "DELETE r",
            source=original.source_id,
        ).consume()

    with pytest.raises(GraphImportError, match="PROJECTION_RELATIONSHIP_MISMATCH"):
        import_snapshot(
            neo4j_session,
            incomplete,
            incomplete["source"],
            update_tag=751,
            after_load=remove_delegation,
        )
    assert (
        source_state(neo4j_session, original.source_id)["current_snapshot_id"]
        == original.projection_id
    )


@pytest.mark.parametrize(
    "relationship,target_label,error",
    [
        ("G_ACTS_AS", "GuardPrincipal", "PROJECTION_RELATIONSHIP_MISMATCH"),
        ("G_IN_SNAPSHOT", "GuardSnapshot", "PROJECTION_COUNT_MISMATCH"),
    ],
)
def test_balanced_missing_and_duplicate_edges_prevent_publication(
    neo4j_session, snapshot_factory, relationship, target_label, error
):
    beta = snapshot_factory("beta-v1")
    other = import_snapshot(neo4j_session, beta, beta["source"])
    other_state = source_state(neo4j_session, other.source_id)
    other_tasks = current_task_ids(neo4j_session, other.source_id)
    first = snapshot_factory()
    original = import_snapshot(neo4j_session, first, first["source"])
    original_state = source_state(neo4j_session, original.source_id)
    original_state.pop("lock_revision")
    original_tasks = current_task_ids(neo4j_session, original.source_id)
    incomplete = deepcopy(first)
    incomplete.update(snapshotId="balanced-edge-corruption", ledgerRevision=2)

    def corrupt_relationships():
        # The total edge count stays unchanged: one expected endpoint pair is
        # missing and another occurs twice. Aggregate counts cannot prove this.
        deleted = neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source,status:'staging'}), "
            f"(a:GuardTask {{task_id:'research-root'}})-[r:{relationship}]->(:{target_label}) "
            "WHERE a.projection_id=p.id DELETE r RETURN count(r) AS count",
            source=original.source_id,
        ).single(strict=True)["count"]
        duplicated = neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source,status:'staging'}), "
            f"(a:GuardTask {{task_id:'review-child'}})-[:{relationship}]->(b:{target_label}) "
            "WHERE a.projection_id=p.id "
            f"CREATE (a)-[duplicate:{relationship}]->(b) RETURN count(duplicate) AS count",
            source=original.source_id,
        ).single(strict=True)["count"]
        assert deleted == duplicated == 1

    with pytest.raises(GraphImportError, match=f"^{error}$"):
        import_snapshot(
            neo4j_session,
            incomplete,
            incomplete["source"],
            after_load=corrupt_relationships,
        )
    preserved_state = source_state(neo4j_session, original.source_id)
    # Staging acquires a source lock; no publication state may advance.
    preserved_state.pop("lock_revision")
    assert preserved_state == original_state
    assert current_task_ids(neo4j_session, original.source_id) == original_tasks
    assert source_state(neo4j_session, other.source_id) == other_state
    assert current_task_ids(neo4j_session, other.source_id) == other_tasks
    failed = neo4j_session.run(
        "MATCH (p:GuardSnapshot {source_id:$source,snapshot_id:$snapshot}) "
        "RETURN p.status AS status",
        source=original.source_id,
        snapshot=incomplete["snapshotId"],
    ).single(strict=True)
    assert failed["status"] == "failed"


def test_cartography_cleanup_is_scoped_and_preserves_cloud_node(neo4j_session, snapshot_factory):
    beta = snapshot_factory("beta-v1")
    other = import_snapshot(neo4j_session, beta, beta["source"], update_tag=800)
    alpha = snapshot_factory()
    source_id = source_key(alpha["source"])
    sentinel = f"arn:aws:s3:::synthetic-{source_id}"
    neo4j_session.run("CREATE (:AWSS3Bucket {id:$id})", id=sentinel).consume()
    cleaned = []

    def exercise_cleanup():
        projection = neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source,status:'staging'}) RETURN p.id AS id",
            source=source_id,
        ).single(strict=True)["id"]
        stale_id = f"{projection}-stale-resource"
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {id:$projection}),(cloud:AWSS3Bucket {id:$cloud}) "
            "CREATE (r:GuardResource {id:$id,projection_id:$projection,source_id:$source,"
            "lastupdated:1,entity_id:'synthetic-stale',tenant_id:'alpha',resource_id:'old',tool:'records.read'}) "
            "CREATE (r)-[:G_IN_SNAPSHOT {lastupdated:1}]->(p) CREATE (r)-[:G_MAPS_TO]->(cloud)",
            projection=projection,
            cloud=sentinel,
            id=stale_id,
            source=source_id,
        ).consume()
        cleanup_projection_rows(neo4j_session, projection, update_tag=801)
        assert (
            neo4j_session.run(
                "MATCH (r:GuardResource {id:$id}) RETURN count(r) AS count",
                id=stale_id,
            ).single(strict=True)["count"]
            == 0
        )
        cleaned.append(projection)

    current = import_snapshot(
        neo4j_session,
        alpha,
        alpha["source"],
        update_tag=801,
        after_load=exercise_cleanup,
    )
    assert cleaned == [current.projection_id]
    assert node_count(neo4j_session, "GuardTask", other.projection_id) == 3
    assert (
        source_state(neo4j_session, other.source_id)["current_snapshot_id"] == other.projection_id
    )
    assert (
        neo4j_session.run(
            "MATCH (b:AWSS3Bucket {id:$id}) RETURN count(b) AS count",
            id=sentinel,
        ).single(strict=True)["count"]
        == 1
    )
    with pytest.raises(GraphImportError, match="PROJECTION_PROTECTED"):
        cleanup_projection_rows(neo4j_session, current.projection_id, update_tag=802)


def test_retirement_keeps_current_previous_other_tenant_and_cloud(neo4j_session, snapshot_factory):
    first = snapshot_factory()
    old = import_snapshot(neo4j_session, first, first["source"], update_tag=900)
    second = snapshot_factory("alpha-v2")
    previous = import_snapshot(neo4j_session, second, second["source"], update_tag=901)
    third = deepcopy(second)
    third.update(snapshotId="empty-third", ledgerRevision=3, tasks=[], tools=[])
    current = import_snapshot(neo4j_session, third, third["source"], update_tag=902)
    beta = snapshot_factory("beta-v1")
    other = import_snapshot(neo4j_session, beta, beta["source"], update_tag=903)
    cloud_id = f"shared-cloud-{old.source_id}"
    neo4j_session.run(
        "MATCH (r:GuardResource {projection_id:$projection}) "
        "WITH r LIMIT 1 CREATE (b:AWSS3Bucket {id:$id}) CREATE (r)-[:G_MAPS_TO]->(b)",
        projection=old.projection_id,
        id=cloud_id,
    ).consume()
    for protected in (current, previous, other):
        with pytest.raises(GraphImportError, match="PROJECTION_PROTECTED"):
            retire_projection(neo4j_session, protected.projection_id, minimum_retention_seconds=0)
    with pytest.raises(GraphImportError, match="PROJECTION_RETENTION"):
        retire_projection(neo4j_session, old.projection_id, minimum_retention_seconds=3600)
    retire_projection(neo4j_session, old.projection_id, minimum_retention_seconds=0)
    assert node_count(neo4j_session, "GuardTask", old.projection_id) == 0
    assert node_count(neo4j_session, "GuardTask", previous.projection_id) == 2
    assert node_count(neo4j_session, "GuardTask", other.projection_id) == 3
    assert current_task_ids(neo4j_session, old.source_id) == set()
    assert (
        neo4j_session.run(
            "MATCH (b:AWSS3Bucket {id:$id}) RETURN count(b) AS count",
            id=cloud_id,
        ).single(strict=True)["count"]
        == 1
    )
