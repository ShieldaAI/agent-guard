"""Publish real managed MCP observations into the disposable Cartography graph."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from agent_guard_cartography.graph import (
    GraphImportError,
    cleanup_staging,
    import_snapshot,
    retire_projection,
)

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mcp-executor.mjs"
MCP_LABELS = ("GuardMcpConnection", "GuardMcpOperation")


@pytest.fixture(scope="module")
def exported_mcp():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/index.js").is_file():
        pytest.fail("MCP integration tests require Node >=22.13 and npm run build at repo root")
    result = subprocess.run(
        [node, str(FIXTURE)], cwd=ROOT, capture_output=True, text=True, check=False, timeout=30
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.fixture
def mcp_snapshots(exported_mcp):
    suffix = uuid4().hex

    def snapshot(name="ready"):
        value = deepcopy(exported_mcp[name])
        value["source"]["sourceId"] += f"-{suffix}"
        value["manifest"]["source"] = dict(value["source"])
        value["snapshotId"] = uuid4().hex
        return value

    return snapshot


def next_capture(snapshot, **updates):
    value = deepcopy(snapshot)
    value["snapshotId"] = uuid4().hex
    value["mcp"]["connections"][0]["inventory"].update(updates)
    return value


def source_state(session, source_id):
    return dict(
        session.run("MATCH (s:GuardSource {id:$id}) RETURN s", id=source_id).single(strict=True)[
            "s"
        ]
    )


def connection_state(session, projection):
    return dict(
        session.run(
            "MATCH (c:GuardMcpConnection {projection_id:$projection}) RETURN c",
            projection=projection,
        ).single(strict=True)["c"]
    )


def count_operations(session, projection):
    return session.run(
        "MATCH (o:GuardMcpOperation {projection_id:$projection}) RETURN count(o) AS count",
        projection=projection,
    ).single(strict=True)["count"]


def test_actual_mcp_lifecycle_and_metadata_drift_project_only_current_operations(
    neo4j_session, mcp_snapshots
):
    original_fingerprint = None
    for name in ("ready", "quarantined", "refreshed", "removed", "closed"):
        snapshot = mcp_snapshots(name)
        inventory = snapshot["mcp"]["connections"][0]["inventory"]
        result = import_snapshot(neo4j_session, snapshot, snapshot["source"])
        connection = connection_state(neo4j_session, result.projection_id)
        assert connection["state"] == inventory["state"]
        assert connection["metadata_state"] == inventory["metadataState"]
        assert connection["metadata_revision"] == inventory["metadataRevision"]
        assert connection["capture_status"] == "observed"
        assert count_operations(neo4j_session, result.projection_id) == len(inventory["operations"])
        if name in ("ready", "refreshed"):
            path = neo4j_session.run(
                "MATCH (b:GuardExecutionBinding {projection_id:$projection})-[:G_VIA_CONNECTION]->"
                "(c:GuardMcpConnection)-[:G_EXPOSES_OPERATION]->"
                "(o:GuardMcpOperation)-[:G_OPERATION_TOOL]->(t:GuardTool) "
                "RETURN b.evidence_kind AS binding,c.evidence_kind AS connection,"
                "o.evidence_kind AS operation,o.assessment AS assessment,"
                "o.fingerprint AS fingerprint,t.fingerprint AS registeredFingerprint",
                projection=result.projection_id,
            ).single(strict=True)
            assert path["binding"] == "host_asserted"
            assert path["connection"] == path["operation"] == "observed"
            assert path["assessment"] == "unknown"
            assert path["fingerprint"] == path["registeredFingerprint"]
            if name == "ready":
                original_fingerprint = path["fingerprint"]
            else:
                assert path["fingerprint"] != original_fingerprint
        assert (
            neo4j_session.run(
                "MATCH (n {projection_id:$projection})-[r:CAN_EXECUTE|CAN_READ|CAN_WRITE]->() "
                "RETURN count(r) AS count",
                projection=result.projection_id,
            ).single(strict=True)["count"]
            == 0
        )
        assert (
            neo4j_session.run(
                "MATCH (c:GuardMcpConnection {projection_id:$projection})--(p:GuardPrincipal) "
                "RETURN count(p) AS count",
                projection=result.projection_id,
            ).single(strict=True)["count"]
            == 0
        )


def test_mcp_lifecycle_revision_publishes_with_unchanged_ledger_and_manifest(
    neo4j_session, mcp_snapshots
):
    snapshot = mcp_snapshots()
    first = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    inventory = snapshot["mcp"]["connections"][0]["inventory"]
    changed = next_capture(
        snapshot,
        revision=inventory["revision"] + 1,
        authorizationEpoch=inventory["authorizationEpoch"] + 1,
        state="quarantined",
        metadataState="stale",
        operations=[],
    )
    second = import_snapshot(neo4j_session, changed, changed["source"])
    current = source_state(neo4j_session, first.source_id)
    assert current["current_snapshot_id"] == second.projection_id
    assert current["ledger_revision"] == snapshot["ledgerRevision"]
    assert current["manifest_revision"] == snapshot["manifest"]["revision"]
    assert connection_state(neo4j_session, second.projection_id)["state"] == "quarantined"
    assert count_operations(neo4j_session, second.projection_id) == 0
    duplicate = import_snapshot(neo4j_session, changed, changed["source"])
    assert duplicate.idempotent and duplicate.projection_id == second.projection_id


def test_unavailable_mcp_capture_allows_fresh_core_without_reusing_ready_data(
    neo4j_session, mcp_snapshots
):
    snapshot = mcp_snapshots()
    first = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    watermarks = source_state(neo4j_session, first.source_id)["mcp_watermarks_json"]
    unavailable = next_capture(snapshot)
    unavailable["ledgerRevision"] += 1
    unavailable["tasks"][0]["revoked"] = True
    unavailable["mcp"]["connections"] = [
        {"connectionId": "documents-mcp", "status": "unavailable", "reason": "missing"}
    ]
    unavailable["coverage"]["mcp"]["status"] = "unavailable"
    second = import_snapshot(neo4j_session, unavailable, unavailable["source"])
    current = source_state(neo4j_session, first.source_id)
    assert current["ledger_revision"] == unavailable["ledgerRevision"]
    assert current["mcp_watermarks_json"] == watermarks
    connection = connection_state(neo4j_session, second.projection_id)
    assert connection["capture_status"] == "unavailable"
    assert connection["unavailable_reason"] == "missing"
    for field in (
        "state",
        "server_id",
        "principal_id",
        "session_id",
        "metadata_revision",
        "revision",
    ):
        assert field not in connection
    assert count_operations(neo4j_session, second.projection_id) == 0
    assert neo4j_session.run(
        "MATCH (t:GuardTask {projection_id:$projection,task_id:$task}) RETURN t.revoked AS revoked",
        projection=second.projection_id,
        task=unavailable["tasks"][0]["id"],
    ).single(strict=True)["revoked"]


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("revision", "MCP_REVISION_ROLLBACK"),
        ("authorizationEpoch", "MCP_REVISION_ROLLBACK"),
        ("metadataRevision", "MCP_REVISION_ROLLBACK"),
        ("lifecycle", "MCP_REVISION_CONTENT_CONFLICT"),
        ("operations", "MCP_REVISION_CONTENT_CONFLICT"),
        ("manifest", "MANIFEST_REVISION_ROLLBACK"),
        ("profile", "PROFILE_CONFLICT"),
    ],
)
def test_invalid_component_progression_never_replaces_current_graph(
    neo4j_session, mcp_snapshots, change, code
):
    snapshot = mcp_snapshots()
    snapshot["manifest"]["revision"] = 2
    snapshot["mcp"]["connections"][0]["inventory"].update(
        revision=10, authorizationEpoch=5, metadataRevision=2
    )
    original = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    candidate = next_capture(snapshot)
    inventory = candidate["mcp"]["connections"][0]["inventory"]
    if change in ("revision", "authorizationEpoch", "metadataRevision"):
        inventory[change] -= 1
    elif change == "lifecycle":
        inventory.update(state="closed", metadataState="stale", operations=[])
    elif change == "operations":
        inventory["operations"] = []
    elif change == "manifest":
        candidate["manifest"]["revision"] -= 1
    else:
        candidate["profile"] = "host"
        candidate.pop("mcp")
        candidate["coverage"]["mcp"] = {"status": "not_collected"}
    with pytest.raises(GraphImportError, match=f"^{code}$"):
        import_snapshot(neo4j_session, candidate, candidate["source"])
    assert (
        source_state(neo4j_session, original.source_id)["current_snapshot_id"]
        == original.projection_id
    )


def test_reconnect_resets_counters_but_retired_sessions_cannot_reappear(
    neo4j_session, mcp_snapshots
):
    snapshot = mcp_snapshots()
    first = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    reconnect = next_capture(
        snapshot,
        sessionId="replacement-local-session",
        revision=0,
        authorizationEpoch=0,
        metadataRevision=0,
        state="connecting",
        metadataState="unobserved",
        operations=[],
    )
    second = import_snapshot(neo4j_session, reconnect, reconnect["source"])
    assert connection_state(neo4j_session, second.projection_id)["state"] == "connecting"
    with pytest.raises(GraphImportError, match="^MCP_SESSION_REPLAY$"):
        import_snapshot(neo4j_session, next_capture(snapshot), snapshot["source"])
    assert (
        source_state(neo4j_session, first.source_id)["current_snapshot_id"] == second.projection_id
    )


def test_mcp_edge_validation_and_scoped_cleanup_include_both_new_labels(
    neo4j_session, mcp_snapshots
):
    snapshot = mcp_snapshots()
    first = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    failed = next_capture(snapshot)

    def remove_operation_link():
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {snapshot_id:$snapshot,status:'staging'})"
            "<-[:G_IN_SNAPSHOT]-(o:GuardMcpOperation)-[r:G_OPERATION_TOOL]->() DELETE r",
            snapshot=failed["snapshotId"],
        ).consume()

    with pytest.raises(GraphImportError, match="^PROJECTION_RELATIONSHIP_MISMATCH$"):
        import_snapshot(neo4j_session, failed, failed["source"], after_load=remove_operation_link)
    failed_projection = neo4j_session.run(
        "MATCH (p:GuardSnapshot {snapshot_id:$id}) RETURN p.id AS id",
        id=failed["snapshotId"],
    ).single(strict=True)["id"]
    cleanup_staging(neo4j_session, failed_projection)
    assert count_operations(neo4j_session, failed_projection) == 0
    assert count_operations(neo4j_session, first.projection_id) == 1
    import_snapshot(neo4j_session, next_capture(snapshot), snapshot["source"])
    latest = import_snapshot(neo4j_session, next_capture(snapshot), snapshot["source"])
    retire_projection(neo4j_session, first.projection_id, minimum_retention_seconds=0)
    for label in MCP_LABELS:
        assert (
            neo4j_session.run(
                f"MATCH (n:{label} {{projection_id:$projection}}) RETURN count(n) AS count",
                projection=first.projection_id,
            ).single(strict=True)["count"]
            == 0
        )
    assert count_operations(neo4j_session, latest.projection_id) == 1


def test_late_mcp_publication_cannot_replace_newer_connection_observations(
    neo4j_session, mcp_snapshots
):
    snapshot = mcp_snapshots()
    original = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    revision = snapshot["mcp"]["connections"][0]["inventory"]["revision"]
    late = next_capture(snapshot, revision=revision + 1)
    newer = next_capture(snapshot, revision=revision + 2)
    published = []

    def publish_newer():
        published.append(import_snapshot(neo4j_session, newer, newer["source"]))

    with pytest.raises(GraphImportError, match="^PUBLICATION_CONFLICT$"):
        import_snapshot(neo4j_session, late, late["source"], after_load=publish_newer)
    current = source_state(neo4j_session, original.source_id)
    assert current["current_snapshot_id"] == published[0].projection_id
    assert connection_state(neo4j_session, published[0].projection_id)["revision"] == revision + 2
