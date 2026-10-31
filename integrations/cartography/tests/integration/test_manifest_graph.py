"""Publish actual executor host compositions through Cartography into disposable Neo4j."""

from __future__ import annotations

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
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "manifest-executor.mjs"
HOST_LABELS = (
    "GuardAgent",
    "GuardDeployment",
    "GuardResourceBinding",
    "GuardExecutionBinding",
    "GuardExternalResource",
    "GuardExternalIdentity",
)


@pytest.fixture(scope="module")
def exported_host_snapshot():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/index.js").is_file():
        pytest.fail("Host integration tests require Node >=22.13 and npm run build at repo root")
    result = subprocess.run(
        [node, str(FIXTURE)], cwd=ROOT, capture_output=True, text=True, check=False, timeout=30
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["observedHost"]["body"]


@pytest.fixture
def host_snapshot(exported_host_snapshot):
    snapshot = deepcopy(exported_host_snapshot)
    snapshot["source"]["sourceId"] += f"-{uuid4().hex}"
    snapshot["manifest"]["source"] = dict(snapshot["source"])
    snapshot["snapshotId"] = uuid4().hex
    return snapshot


def source_state(session, source_id):
    return dict(
        session.run("MATCH (s:GuardSource {id:$id}) RETURN s", id=source_id).single(strict=True)[
            "s"
        ]
    )


def count(session, label, projection):
    assert label in (*HOST_LABELS, "GuardTask")
    return session.run(
        f"MATCH (n:{label} {{projection_id:$projection}}) RETURN count(n) AS count",
        projection=projection,
    ).single(strict=True)["count"]


def next_manifest(snapshot, revision):
    value = deepcopy(snapshot)
    value["snapshotId"] = uuid4().hex
    value["manifest"]["revision"] = revision
    value["manifest"]["observedAt"] = f"2026-10-30T00:00:{revision:02d}Z"
    value["coverage"]["manifest"]["observedAt"] = value["manifest"]["observedAt"]
    return value


def test_host_graph_records_assertions_without_borrowing_runtime_identity(
    neo4j_session, host_snapshot
):
    result = import_snapshot(neo4j_session, host_snapshot, host_snapshot["source"], update_tag=1000)
    projection = result.projection_id
    assert count(neo4j_session, "GuardTask", projection) == 3
    for label in HOST_LABELS:
        expected = 1 if label == "GuardExternalIdentity" else 2
        assert count(neo4j_session, label, projection) == expected
        evidence = list(
            neo4j_session.run(
                f"MATCH (n:{label} {{projection_id:$projection}}) RETURN n.evidence_kind AS kind,"
                "n.manifest_id AS manifest,n.manifest_revision AS revision,"
                "n.manifest_observed_at AS observed",
                projection=projection,
            )
        )
        assert all(
            row["kind"] == "host_asserted"
            and row["manifest"] == "manifest-one"
            and row["revision"] == 1
            and row["observed"] == "2026-10-30T00:00:00Z"
            for row in evidence
        )
    assignments = {
        (row["task"], row["deployment"], row["agent"])
        for row in neo4j_session.run(
            "MATCH (t:GuardTask {projection_id:$projection})-[:G_ASSIGNED_TO]->"
            "(d:GuardDeployment)-[:G_INSTANCE_OF]->(a:GuardAgent) "
            "RETURN t.task_id AS task,d.deployment_id AS deployment,a.agent_id AS agent",
            projection=projection,
        )
    }
    assert assignments == {
        ("root", "deployment-static", "agent-research"),
        ("child", "deployment-dynamic", "agent-review"),
    }
    bindings = list(
        neo4j_session.run(
            "MATCH (b:GuardExecutionBinding {projection_id:$projection})-[:G_EXECUTES_FOR]->"
            "(d:GuardDeployment), (b)-[:G_EXECUTES_TOOL]->(t:GuardTool) "
            "OPTIONAL MATCH (b)-[:G_USES_IDENTITY]->(i:GuardExternalIdentity) "
            "RETURN b.identity_selection AS selection,d.deployment_id AS deployment,"
            "t.name AS tool,i.arn AS arn",
            projection=projection,
        )
    )
    assert len(bindings) == 2
    for binding in bindings:
        assert binding["tool"] == "records.read"
        if binding["selection"] == "dynamic":
            assert binding["deployment"] == "deployment-dynamic"
            assert binding["arn"] is None
        else:
            assert binding["selection"] == "static"
            assert binding["arn"] == "arn:aws:iam::111122223333:role/ManifestReader"
    resources = list(
        neo4j_session.run(
            "MATCH (b:GuardResourceBinding {projection_id:$projection})-[:G_BINDS_SELECTOR]->"
            "(r:GuardResource), (b)-[:G_MAPS_TO]->(e:GuardExternalResource) "
            "RETURN r.tool AS tool,r.resource_id AS reference,b.scope AS scope,"
            "b.actions AS actions,e.kind AS kind,e.arn AS arn,e.account_id AS account",
            projection=projection,
        )
    )
    assert {row["kind"] for row in resources} == {"object", "prefix"}
    for resource in resources:
        assert resource["tool"] == "records.read"
        assert resource["reference"].startswith("opaque:")
        assert resource["actions"] == ["s3:GetObject"]
        assert resource["scope"] == ("prefix" if resource["kind"] == "prefix" else "exact")
        assert resource["account"] == "111122223333"
    assert (
        neo4j_session.run(
            "MATCH (g:GuardGrant {projection_id:$projection}) "
            "WHERE g.assessment<>'unknown' OR g.evidence_kind<>'declared' RETURN count(g) AS count",
            projection=projection,
        ).single(strict=True)["count"]
        == 0
    )
    assert (
        neo4j_session.run(
            "MATCH (n {projection_id:$projection})-[r:CAN_READ|CAN_WRITE|CAN_EXECUTE]->() "
            "RETURN count(r) AS count",
            projection=projection,
        ).single(strict=True)["count"]
        == 0
    )


def test_manifest_revision_advances_independently_of_core_authority(neo4j_session, host_snapshot):
    first = import_snapshot(neo4j_session, host_snapshot, host_snapshot["source"], update_tag=1100)
    second = next_manifest(host_snapshot, 2)
    second["manifest"]["agents"][0]["teamId"] = "changed-team"
    updated = import_snapshot(neo4j_session, second, second["source"], update_tag=1101)
    current = source_state(neo4j_session, first.source_id)
    assert current["current_snapshot_id"] == updated.projection_id
    assert current["previous_snapshot_id"] == first.projection_id
    assert current["ledger_revision"] == host_snapshot["ledgerRevision"]
    assert current["policy_epoch"] == host_snapshot["policyEpoch"]
    assert current["manifest_revision"] == 2
    duplicate = import_snapshot(neo4j_session, second, second["source"], update_tag=1102)
    assert duplicate.idempotent and duplicate.projection_id == updated.projection_id


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("rollback", "MANIFEST_REVISION_ROLLBACK"),
        ("same-revision-content", "MANIFEST_CONTENT_CONFLICT"),
        ("manifest-identity", "MANIFEST_ID_CONFLICT"),
        ("core-downgrade", "PROFILE_CONFLICT"),
    ],
)
def test_invalid_manifest_progression_cannot_replace_current_projection(
    neo4j_session, host_snapshot, change, code
):
    current = next_manifest(host_snapshot, 2)
    original = import_snapshot(neo4j_session, current, current["source"], update_tag=1200)
    candidate = deepcopy(current)
    candidate["snapshotId"] = uuid4().hex
    if change == "rollback":
        candidate["manifest"]["revision"] = 1
    elif change == "same-revision-content":
        candidate["manifest"]["agents"][0]["name"] = "Different assertion"
    elif change == "manifest-identity":
        candidate["manifest"]["manifestId"] = "different-manifest"
    else:
        candidate["profile"] = "core"
        candidate.pop("manifest")
        candidate["coverage"]["manifest"] = {"status": "not_collected"}
    with pytest.raises(GraphImportError, match=f"^{code}$"):
        import_snapshot(neo4j_session, candidate, candidate["source"], update_tag=1201)
    assert (
        source_state(neo4j_session, original.source_id)["current_snapshot_id"]
        == original.projection_id
    )


def test_late_manifest_import_cannot_replace_a_newer_assertion(neo4j_session, host_snapshot):
    original = import_snapshot(
        neo4j_session, host_snapshot, host_snapshot["source"], update_tag=1300
    )
    candidate = next_manifest(host_snapshot, 2)
    newer = next_manifest(host_snapshot, 3)
    winners = []

    def publish_newer():
        winners.append(import_snapshot(neo4j_session, newer, newer["source"], update_tag=1302))

    with pytest.raises(
        GraphImportError, match="^(PUBLICATION_CONFLICT|MANIFEST_REVISION_ROLLBACK)$"
    ):
        import_snapshot(
            neo4j_session, candidate, candidate["source"], update_tag=1301, after_load=publish_newer
        )
    current = source_state(neo4j_session, original.source_id)
    assert current["current_snapshot_id"] == winners[0].projection_id
    assert current["manifest_revision"] == 3


def test_missing_manifest_relationship_prevents_publication(neo4j_session, host_snapshot):
    original = import_snapshot(
        neo4j_session, host_snapshot, host_snapshot["source"], update_tag=1400
    )
    candidate = next_manifest(host_snapshot, 2)

    def remove_identity():
        neo4j_session.run(
            "MATCH (b:GuardExecutionBinding)-[r:G_USES_IDENTITY]->(:GuardExternalIdentity), "
            "(b)-[:G_IN_SNAPSHOT]->(p:GuardSnapshot {source_id:$source,status:'staging'}) "
            "DELETE r",
            source=original.source_id,
        ).consume()

    with pytest.raises(GraphImportError, match="^PROJECTION_RELATIONSHIP_MISMATCH$"):
        import_snapshot(
            neo4j_session,
            candidate,
            candidate["source"],
            update_tag=1401,
            after_load=remove_identity,
        )
    assert (
        source_state(neo4j_session, original.source_id)["current_snapshot_id"]
        == original.projection_id
    )


def test_manifest_retirement_is_scoped_and_preserves_other_sources_and_native_cloud_nodes(
    neo4j_session, host_snapshot
):
    old = import_snapshot(neo4j_session, host_snapshot, host_snapshot["source"], update_tag=1500)
    previous_snapshot = next_manifest(host_snapshot, 2)
    previous = import_snapshot(
        neo4j_session, previous_snapshot, previous_snapshot["source"], update_tag=1501
    )
    cleared = next_manifest(host_snapshot, 3)
    for field in ("agents", "deployments", "taskBindings", "resourceBindings", "executionBindings"):
        cleared["manifest"][field] = []
    current = import_snapshot(neo4j_session, cleared, cleared["source"], update_tag=1502)
    other = deepcopy(host_snapshot)
    other["source"]["sourceId"] += "-other"
    other["manifest"]["source"] = dict(other["source"])
    foreign = import_snapshot(neo4j_session, other, other["source"], update_tag=1503)
    cloud_id = f"native-cloud-{old.source_id}"
    neo4j_session.run(
        "MATCH (r:GuardExternalResource {projection_id:$projection}) WITH r LIMIT 1 "
        "CREATE (cloud:AWSS3Bucket {id:$id}) CREATE (r)-[:G_MAPS_TO]->(cloud)",
        projection=old.projection_id,
        id=cloud_id,
    ).consume()
    for protected in (current, previous, foreign):
        with pytest.raises(GraphImportError, match="^PROJECTION_PROTECTED$"):
            retire_projection(neo4j_session, protected.projection_id, minimum_retention_seconds=0)
    retire_projection(neo4j_session, old.projection_id, minimum_retention_seconds=0)
    for label in HOST_LABELS:
        assert count(neo4j_session, label, old.projection_id) == 0
        assert count(neo4j_session, label, current.projection_id) == 0
        assert count(neo4j_session, label, previous.projection_id) > 0
        assert count(neo4j_session, label, foreign.projection_id) > 0
    assert count(neo4j_session, "GuardTask", current.projection_id) == 3
    assert (
        neo4j_session.run(
            "MATCH (cloud:AWSS3Bucket {id:$id}) RETURN count(cloud) AS count", id=cloud_id
        ).single(strict=True)["count"]
        == 1
    )


def test_failed_host_staging_can_be_cleaned_without_current_manifest_loss(
    neo4j_session, host_snapshot
):
    current = import_snapshot(
        neo4j_session, host_snapshot, host_snapshot["source"], update_tag=1600
    )
    candidate = next_manifest(host_snapshot, 2)

    def fail():
        raise RuntimeError("synthetic host staging interruption")

    with pytest.raises(RuntimeError, match="synthetic host staging interruption"):
        import_snapshot(
            neo4j_session, candidate, candidate["source"], update_tag=1601, after_load=fail
        )
    failed = neo4j_session.run(
        "MATCH (p:GuardSnapshot {source_id:$source,status:'failed'}) RETURN p.id AS id",
        source=current.source_id,
    ).single(strict=True)["id"]
    cleanup_staging(neo4j_session, failed)
    for label in HOST_LABELS:
        assert count(neo4j_session, label, failed) == 0
        assert count(neo4j_session, label, current.projection_id) > 0
    assert (
        source_state(neo4j_session, current.source_id)["current_snapshot_id"]
        == current.projection_id
    )
