"""Exact cloud joins against only the owned disposable provider fixture graph."""

import json
import time
from copy import deepcopy
from uuid import uuid4

import pytest

import agent_guard_cartography.cloud as cloud
from agent_guard_cartography.cloud import CloudJoinError, validate_cloud_scope
from agent_guard_cartography.graph import (
    GraphImportError,
    cleanup_staging,
    import_snapshot,
    retire_projection,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def cloud_snapshot(snapshot_factory):
    snapshot = snapshot_factory()
    account = str(uuid4().int % 10**12).zfill(12)
    suffix = uuid4().hex
    bucket = f"guard-cloud-{suffix}"
    role = f"arn:aws:iam::{account}:role/worker-{suffix}"
    target = {"provider": "aws", "partition": "aws", "accountId": account, "region": ""}
    snapshot["profile"] = "host"
    snapshot["snapshotId"] = uuid4().hex
    snapshot["tasks"][0]["grants"][0]["resources"].extend(["bucket", "object", "prefix"])
    snapshot["manifest"] = {
        "schemaVersion": 1,
        "evidenceKind": "host_asserted",
        "source": dict(snapshot["source"]),
        "manifestId": "cloud-manifest",
        "revision": 1,
        "observedAt": snapshot["generatedAt"],
        "agents": [{"id": "agent", "name": "Worker", "ownerId": None, "teamId": None}],
        "deployments": [
            {"id": "deployment", "agentId": "agent", "environment": "test"},
            {"id": "dynamic-deployment", "agentId": "agent", "environment": "test"},
        ],
        "taskBindings": [{"taskId": "research-root", "deploymentId": "deployment"}],
        "resourceBindings": [
            {
                "id": kind,
                "tool": "records.read",
                "resourceRef": kind,
                "target": {**target, "arn": f"arn:aws:s3:::{bucket}{suffix}", "kind": kind},
                "actions": ["s3:GetObject"],
                "scope": "prefix" if kind == "prefix" else "exact",
            }
            for kind, suffix in [
                ("bucket", ""),
                ("object", "/private/report.txt"),
                ("prefix", "/private/"),
            ]
        ],
        "executionBindings": [
            {
                "id": "static",
                "tool": "records.read",
                "deploymentId": "deployment",
                "connectionId": None,
                "identitySelection": "static",
                "identity": {**target, "arn": role},
            },
            {
                "id": "dynamic",
                "tool": "records.read",
                "deploymentId": "dynamic-deployment",
                "connectionId": None,
                "identitySelection": "dynamic",
                "identity": None,
            },
        ],
    }
    snapshot["coverage"]["manifest"] = {
        "status": "complete",
        "observedAt": snapshot["manifest"]["observedAt"],
    }
    scope = validate_cloud_scope(
        {
            "companyId": snapshot["source"]["companyId"],
            "tenantId": "alpha",
            "accounts": [{"partition": "aws", "accountId": account}],
        }
    )
    return snapshot, scope, account, bucket, role


def seed(session, case, *, timestamp=None):
    _, _, account, bucket, role = case
    stamp = int(time.time()) if timestamp is None else timestamp
    session.run(
        "CREATE (a:AWSAccount {id:$account,lastupdated:$stamp,sentinel:'provider-account'}) "
        "CREATE (r:AWSRole:AWSPrincipal {id:$role,arn:$role,lastupdated:$stamp,sentinel:'provider-role'}) "
        "CREATE (b:AWSS3Bucket {id:$bucket,arn:$arn,region:'eu-west-1',lastupdated:$stamp,sentinel:'provider-bucket'}) "
        "CREATE (a)-[:RESOURCE {lastupdated:$stamp}]->(r) CREATE (a)-[:RESOURCE {lastupdated:$stamp}]->(b) "
        "CREATE (r)-[:CAN_READ {lastupdated:$stamp,has_condition:true,conditions:'private-condition-canary'}]->(b)",
        account=account,
        role=role,
        bucket=bucket,
        arn=f"arn:aws:s3:::{bucket}",
        stamp=stamp,
    ).consume()


def import_case(session, case, **options):
    snapshot, scope, *_ = case
    return import_snapshot(session, snapshot, snapshot["source"], cloud_scope=scope, **options)


def next_snapshot(snapshot):
    value = deepcopy(snapshot)
    value["snapshotId"] = uuid4().hex
    return value


def current(session, result):
    return session.run(
        "MATCH (s:GuardSource {id:$id}) RETURN s.current_snapshot_id AS current",
        id=result.source_id,
    ).single()["current"]


def cloud_nodes(session, projection):
    return [
        dict(row["n"])
        for row in session.run(
            "MATCH (n {projection_id:$projection}) WHERE n:GuardExternalIdentity OR n:GuardExternalResource RETURN n",
            projection=projection,
        )
    ]


def cloud_edges(session, projection):
    return list(
        session.run(
            "MATCH (n {projection_id:$projection})-[r:G_CLOUD_MATCH|G_CLOUD_CONTAINER]->(p) "
            "RETURN n.arn AS arn,type(r) AS relation,r.assessment AS assessment,p.arn AS target",
            projection=projection,
        )
    )


def test_exact_identity_and_bucket_joins_preserve_object_prefix_and_execution_scope(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)
    result = import_case(neo4j_session, cloud_snapshot)
    nodes = cloud_nodes(neo4j_session, result.projection_id)
    assert len(nodes) == 4
    assert {node["cloud_status"] for node in nodes} == {"resolved"}
    assert {node["cloud_assessment"] for node in nodes} == {"unknown"}
    edges = cloud_edges(neo4j_session, result.projection_id)
    assert len(edges) == 4
    assert sum(edge["relation"] == "G_CLOUD_CONTAINER" for edge in edges) == 2
    for edge in edges:
        assert edge["assessment"] == "unknown"
        if edge["relation"] == "G_CLOUD_MATCH":
            assert edge["arn"] == edge["target"]
        else:
            assert edge["arn"].startswith(edge["target"] + "/")
    identities = list(
        neo4j_session.run(
            "MATCH (e:GuardExecutionBinding {projection_id:$projection}) OPTIONAL MATCH (e)-[:G_USES_IDENTITY]->(i) "
            "RETURN e.binding_id AS binding,count(i) AS identities",
            projection=result.projection_id,
        )
    )
    assert {row["binding"]: row["identities"] for row in identities} == {"static": 1, "dynamic": 0}
    receipt = neo4j_session.run(
        "MATCH (p:GuardSnapshot {id:$id}) RETURN p.cloud_coverage_json AS cloud,p.coverage_json AS core",
        id=result.projection_id,
    ).single()
    assert json.loads(receipt["cloud"])["status"] == "complete"
    assert json.loads(receipt["core"])["cloud"] == {"status": "not_collected"}
    assert "private-condition-canary" not in json.dumps(nodes)
    assert import_case(neo4j_session, cloud_snapshot).idempotent


@pytest.mark.parametrize("problem", ["missing_ownership", "ambiguous", "stale", "future"])
def test_incomplete_provider_evidence_never_creates_a_positive_join(
    neo4j_session, cloud_snapshot, problem
):
    seed(neo4j_session, cloud_snapshot)
    _, _, account, bucket, _ = cloud_snapshot
    if problem == "missing_ownership":
        neo4j_session.run(
            "MATCH (:AWSAccount {id:$account})-[r:RESOURCE]->(:AWSS3Bucket {id:$bucket}) DELETE r",
            account=account,
            bucket=bucket,
        ).consume()
    elif problem == "ambiguous":
        neo4j_session.run(
            "MATCH (a:AWSAccount {id:$account})-[:RESOURCE]->(b:AWSS3Bucket {id:$bucket}) CREATE (a)-[:RESOURCE {lastupdated:b.lastupdated}]->(b)",
            account=account,
            bucket=bucket,
        ).consume()
    else:
        neo4j_session.run(
            "MATCH (b:AWSS3Bucket {id:$bucket}) SET b.lastupdated=$stamp",
            bucket=bucket,
            stamp=int(time.time()) + (99999 if problem == "future" else -99999),
        ).consume()
    result = import_case(neo4j_session, cloud_snapshot)
    resources = [
        node for node in cloud_nodes(neo4j_session, result.projection_id) if "kind" in node
    ]
    expected = {
        "missing_ownership": "missing",
        "ambiguous": "ambiguous",
        "stale": "stale",
        "future": "freshness_unknown",
    }[problem]
    assert {node["cloud_reason"] for node in resources} == {expected}
    assert len(cloud_edges(neo4j_session, result.projection_id)) == 1


def test_changed_provider_between_capture_and_publication_drops_links_but_publishes_core(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)

    def change():
        neo4j_session.run(
            "MATCH (b:AWSS3Bucket {id:$bucket}) SET b.lastupdated=0", bucket=cloud_snapshot[3]
        ).consume()

    result = import_case(neo4j_session, cloud_snapshot, after_load=change)
    assert result.published
    resources = [
        node for node in cloud_nodes(neo4j_session, result.projection_id) if "kind" in node
    ]
    assert {node["cloud_reason"] for node in resources} == {"changed"}
    assert len(cloud_edges(neo4j_session, result.projection_id)) == 1


@pytest.mark.parametrize("failure_phase", ["capture", "publication"])
def test_optional_lookup_failure_publishes_fresh_core_without_stale_cloud_links(
    neo4j_session, cloud_snapshot, monkeypatch, failure_phase
):
    seed(neo4j_session, cloud_snapshot)
    first = import_case(neo4j_session, cloud_snapshot)
    value = next_snapshot(cloud_snapshot[0])
    value["ledgerRevision"] += 1
    value["tasks"][0]["revoked"] = True
    original = cloud._lookup
    calls = 0

    def fail(tx, reference, target, scope):
        nonlocal calls
        calls += 1
        if failure_phase == "capture" or calls > 4:
            raise RuntimeError("private-provider-error-canary")
        return original(tx, reference, target, scope)

    monkeypatch.setattr(cloud, "_lookup", fail)
    second = import_snapshot(neo4j_session, value, value["source"], cloud_scope=cloud_snapshot[1])
    assert current(neo4j_session, first) == second.projection_id
    assert cloud_edges(neo4j_session, second.projection_id) == []
    nodes = cloud_nodes(neo4j_session, second.projection_id)
    assert {node["cloud_reason"] for node in nodes} == {"capture_failed"}
    assert all("cloud_provider_id" not in node for node in nodes)
    assert "private-provider-error-canary" not in json.dumps(nodes)
    assert len(cloud_edges(neo4j_session, first.projection_id)) == 4


def test_unexpected_cloud_edge_rejects_publication_and_cleanup_preserves_provider(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)
    first = import_case(neo4j_session, cloud_snapshot)
    value = next_snapshot(cloud_snapshot[0])

    def corrupt():
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {snapshot_id:$snapshot,status:'staging'})<-[:G_IN_SNAPSHOT]-(n:GuardExternalIdentity), "
            "(b:AWSS3Bucket {id:$bucket}) CREATE (n)-[:G_CLOUD_MATCH]->(b)",
            snapshot=value["snapshotId"],
            bucket=cloud_snapshot[3],
        ).consume()

    with pytest.raises(CloudJoinError, match="^CLOUD_RELATIONSHIP_CONFLICT$"):
        import_snapshot(
            neo4j_session, value, value["source"], cloud_scope=cloud_snapshot[1], after_load=corrupt
        )
    assert current(neo4j_session, first) == first.projection_id
    failed = neo4j_session.run(
        "MATCH (p:GuardSnapshot {snapshot_id:$id,status:'failed'}) RETURN p.id AS id",
        id=value["snapshotId"],
    ).single()["id"]
    cleanup_staging(neo4j_session, failed)
    assert cloud_nodes(neo4j_session, failed) == []
    assert (
        neo4j_session.run(
            "MATCH (b:AWSS3Bucket {id:$id}) RETURN b.sentinel AS sentinel", id=cloud_snapshot[3]
        ).single()["sentinel"]
        == "provider-bucket"
    )


def test_retirement_removes_only_scoped_links_and_never_provider_nodes(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)
    first = import_case(neo4j_session, cloud_snapshot)
    second_value = next_snapshot(cloud_snapshot[0])
    second = import_snapshot(
        neo4j_session, second_value, second_value["source"], cloud_scope=cloud_snapshot[1]
    )
    third_value = next_snapshot(cloud_snapshot[0])
    third = import_snapshot(
        neo4j_session, third_value, third_value["source"], cloud_scope=cloud_snapshot[1]
    )
    retire_projection(neo4j_session, first.projection_id, minimum_retention_seconds=0)
    assert cloud_nodes(neo4j_session, first.projection_id) == []
    assert len(cloud_edges(neo4j_session, second.projection_id)) == 4
    assert len(cloud_edges(neo4j_session, third.projection_id)) == 4
    assert (
        neo4j_session.run(
            "MATCH (:AWSAccount {id:$id})-[:RESOURCE]->(p) RETURN count(p) AS count",
            id=cloud_snapshot[2],
        ).single()["count"]
        == 2
    )
    assert (
        neo4j_session.run(
            "MATCH (:AWSRole {id:$id})-[r:CAN_READ]->() RETURN r.conditions AS conditions",
            id=cloud_snapshot[4],
        ).single()["conditions"]
        == "private-condition-canary"
    )


def test_cloud_enrollment_mismatch_is_rejected_before_graph_writes(neo4j_session, cloud_snapshot):
    value = cloud_snapshot[0]
    scope = validate_cloud_scope(
        {
            "companyId": "foreign",
            "tenantId": "alpha",
            "accounts": [{"partition": "aws", "accountId": cloud_snapshot[2]}],
        }
    )
    with pytest.raises(CloudJoinError, match="^CLOUD_SCOPE_MISMATCH$"):
        import_snapshot(neo4j_session, value, value["source"], cloud_scope=scope)
    assert (
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {snapshot_id:$id}) RETURN count(p) AS count",
            id=value["snapshotId"],
        ).single()["count"]
        == 0
    )


def test_cloud_capture_cannot_publish_over_a_newer_source_pointer(neo4j_session, cloud_snapshot):
    seed(neo4j_session, cloud_snapshot)
    first = import_case(neo4j_session, cloud_snapshot)
    stale = next_snapshot(cloud_snapshot[0])
    fresh = next_snapshot(cloud_snapshot[0])
    published = []

    def newer():
        published.append(
            import_snapshot(neo4j_session, fresh, fresh["source"], cloud_scope=cloud_snapshot[1])
        )

    with pytest.raises(GraphImportError, match="^PUBLICATION_CONFLICT$"):
        import_snapshot(
            neo4j_session, stale, stale["source"], cloud_scope=cloud_snapshot[1], after_load=newer
        )
    assert current(neo4j_session, first) == published[0].projection_id
    assert len(cloud_edges(neo4j_session, published[0].projection_id)) == 4
