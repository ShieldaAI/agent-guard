"""Actual v2 observer exports, atomic Neo4j projection and scoped Map queries."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from test_reference_queries import query

from agent_guard_cartography.archive import SnapshotArchive
from agent_guard_cartography.graph import GraphImportError, import_snapshot, retire_projection
from agent_guard_cartography.inventory import validate_snapshot

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).parents[1] / "fixtures" / "manifest-executor.mjs"


@pytest.fixture(scope="module")
def exported_v2():
    result = subprocess.run(
        [shutil.which("node"), str(FIXTURE), "--v2"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["observedHost"]["body"]


@pytest.fixture
def v2_snapshot(exported_v2):
    value = deepcopy(exported_v2)
    value["source"]["companyId"] += "-" + uuid4().hex
    value["source"]["sourceId"] += "-" + uuid4().hex
    value["manifest"]["source"] = dict(value["source"])
    value["snapshotId"] = uuid4().hex
    return validate_snapshot(value)


def publish(session, value, **options):
    return import_snapshot(session, value, value["source"], **options)


def advanced(value):
    result = deepcopy(value)
    result["snapshotId"] = uuid4().hex
    result["manifest"]["revision"] += 1
    return result


def scope(value, all_teams=False):
    return {
        "subject": "reviewer",
        "companyId": value["source"]["companyId"],
        "tenantIds": [value["source"]["tenantId"]],
        "teamIds": ["team-research"],
        "allTeams": all_teams,
    }


def source_record(session, source_id):
    return dict(
        session.run("MATCH (s:GuardSource {id:$id}) RETURN s", id=source_id).single(strict=True)[
            "s"
        ]
    )


def test_actual_v2_edges_provenance_and_generic_cloud_separation(neo4j_session, v2_snapshot):
    result = publish(
        neo4j_session,
        v2_snapshot,
        cloud_scope={
            "companyId": v2_snapshot["source"]["companyId"],
            "tenantId": "alpha",
            "accounts": [{"partition": "aws", "accountId": "111122223333"}],
        },
    )
    edges = {
        row["kind"]: row["count"]
        for row in neo4j_session.run(
            "MATCH (n {projection_id:$projection})-[r]->() WHERE type(r) IN ['G_OWNED_BY','G_RESOURCE_OWNED_BY','G_USES_CREDENTIAL','G_DEPENDS_ON'] RETURN type(r) AS kind,count(r) AS count",
            projection=result.projection_id,
        )
    }
    assert edges == {
        "G_OWNED_BY": 1,
        "G_RESOURCE_OWNED_BY": 2,
        "G_USES_CREDENTIAL": 2,
        "G_DEPENDS_ON": 1,
    }
    for row in neo4j_session.run(
        "MATCH (n {projection_id:$projection}) WHERE n:GuardOwner OR n:GuardCredentialReference RETURN n",
        projection=result.projection_id,
    ):
        node = row["n"]
        assert node["manifest_schema_version"] == 2 and node["authority_id"] == "company-directory"
        assert node["assessment"] == "unknown" and node["evidence_kind"] == "host_asserted"
    host = neo4j_session.run(
        "MATCH (n:GuardExternalResource {projection_id:$projection,provider:'host'}) OPTIONAL MATCH (n)-[r:G_CLOUD_MATCH|G_CLOUD_CONTAINER]->() RETURN n,count(r) AS edges",
        projection=result.projection_id,
    ).single(strict=True)
    assert host["edges"] == 0 and host["n"]["cloud_status"] == "not_collected"
    assert host["n"]["cloud_reason"] == "unsupported_provider" and "arn" not in host["n"]
    aws = list(
        neo4j_session.run(
            "MATCH (n {projection_id:$projection,provider:'aws'}) RETURN n.cloud_reason AS reason",
            projection=result.projection_id,
        )
    )
    assert aws and all(row["reason"] == "missing" for row in aws)
    assert source_record(neo4j_session, result.source_id)["manifest_schema_version"] == 2


def test_v2_reordering_restart_hash_and_schema_downgrade_fences(
    neo4j_driver, neo4j_session, v2_snapshot, tmp_path
):
    first = publish(neo4j_session, v2_snapshot)
    with SnapshotArchive(tmp_path / "archive") as archive:
        receipt = archive.store(v2_snapshot)
        archive.record_result(receipt.receipt_id, first)
    reordered = deepcopy(v2_snapshot)
    reordered["snapshotId"] = uuid4().hex
    for field in (
        "owners",
        "credentialReferences",
        "agents",
        "deployments",
        "resourceBindings",
        "executionBindings",
        "taskBindings",
    ):
        reordered["manifest"][field].reverse()
    with neo4j_driver.session(database="neo4j") as reopened:
        with SnapshotArchive(tmp_path / "archive") as archive:
            restored = archive.load(receipt.receipt_id, v2_snapshot["source"], "host")
            assert restored == v2_snapshot
            assert publish(reopened, restored).idempotent
        second = publish(reopened, reordered)
        assert second.published
        assert publish(reopened, reordered).idempotent
        original_replay = publish(reopened, v2_snapshot)
        assert original_replay.idempotent and original_replay.projection_id == first.projection_id
        changed = deepcopy(reordered)
        changed["snapshotId"] = uuid4().hex
        changed["manifest"]["owners"][0]["name"] = "Changed owner"
        with pytest.raises(GraphImportError, match="^MANIFEST_CONTENT_CONFLICT$"):
            publish(reopened, changed)
        downgrade = advanced(reordered)
        manifest = downgrade["manifest"]
        manifest["schemaVersion"] = 1
        for key in ("owners", "credentialReferences", "authorityId"):
            manifest.pop(key)
        fields = {
            "agents": {"id", "name", "ownerId", "teamId"},
            "deployments": {"id", "agentId", "environment"},
            "resourceBindings": {"id", "tool", "resourceRef", "target", "actions", "scope"},
        }
        for collection, allowed in fields.items():
            manifest[collection] = [
                {key: item for key, item in record.items() if key in allowed}
                for record in manifest[collection]
            ]
        # The old schema has no host targets. Its valid AWS-only subset still
        # cannot erase already published v2 semantics in the same generation.
        manifest["resourceBindings"] = [
            binding
            for binding in manifest["resourceBindings"]
            if binding["target"]["provider"] == "aws"
        ]
        validate_snapshot(downgrade)
        with pytest.raises(GraphImportError, match="^MANIFEST_SCHEMA_ROLLBACK$"):
            publish(reopened, downgrade)
        assert (
            source_record(reopened, first.source_id)["current_snapshot_id"] == second.projection_id
        )


def test_new_relationship_validation_and_interruption_keep_previous_projection(
    neo4j_session, v2_snapshot
):
    first = publish(neo4j_session, v2_snapshot)
    candidate = advanced(v2_snapshot)
    candidate["manifest"]["agents"][0]["ownerId"] = "owner-review"

    def corrupt_relation():
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source,status:'staging'})<-[:G_IN_SNAPSHOT]-(d:GuardDeployment)-[r:G_USES_CREDENTIAL]->() DELETE r",
            source=first.source_id,
        ).consume()

    with pytest.raises(GraphImportError, match="^PROJECTION_RELATIONSHIP_MISMATCH$"):
        publish(neo4j_session, candidate, after_load=corrupt_relation)
    assert (
        source_record(neo4j_session, first.source_id)["current_snapshot_id"] == first.projection_id
    )
    candidate["snapshotId"] = uuid4().hex
    second = publish(neo4j_session, candidate)
    assert second.published
    third = publish(neo4j_session, advanced(candidate))
    retire_projection(neo4j_session, first.projection_id, minimum_retention_seconds=0)
    assert (
        source_record(neo4j_session, first.source_id)["current_snapshot_id"] == third.projection_id
    )
    assert (
        neo4j_session.run(
            "MATCH (n {projection_id:$id}) WHERE n:GuardOwner OR n:GuardCredentialReference RETURN count(n) AS count",
            id=first.projection_id,
        ).single()["count"]
        == 0
    )


def test_scoped_map_indexes_credentials_dependencies_and_permission_differences(
    neo4j_session, v2_snapshot
):
    # Keep the second resource in valid core inventory, but only in an unassigned
    # task. A visible dependency must not pull that resource into the team view.
    value = deepcopy(v2_snapshot)
    visible_ref, hidden_ref = (
        binding["resourceRef"] for binding in value["manifest"]["resourceBindings"]
    )
    for task in value["tasks"]:
        for grant in task["grants"]:
            if grant["tool"] == "records.read":
                grant["resources"] = [visible_ref]
    unassigned = next(task for task in value["tasks"] if task["id"] == "unassigned")
    unassigned["grants"].append({"tool": "records.read", "resources": [hidden_ref]})
    value["manifest"]["resourceBindings"][0]["dependsOn"] = ["prefix-binding"]
    value["manifest"]["resourceBindings"][1]["dependsOn"] = []
    first = publish(neo4j_session, validate_snapshot(value))
    operations = [
        {"operation": "list_agents", "args": {"sourceId": first.source_id}},
        {"operation": "list_owners", "args": {"sourceId": first.source_id, "limit": 1}},
        {"operation": "list_resources", "args": {"sourceId": first.source_id, "limit": 1}},
        {
            "operation": "get_agent_access",
            "args": {"sourceId": first.source_id, "agentId": "agent-research"},
        },
        {
            "operation": "get_resource_access",
            "args": {"sourceId": first.source_id, "resourceId": "object-binding"},
        },
        {"operation": "get_changes", "args": {"sourceId": first.source_id}},
    ]
    response = query(scope(value), {"sourceId": first.source_id}, operations)
    assert response["ok"] and all(item["ok"] for item in response["outputs"]), response
    text = json.dumps(response)
    for private in (
        "agent-review",
        "deployment-dynamic",
        "Review credential",
        "owner-review",
        "prefix-binding",
        "Company records",
    ):
        assert private not in text
    data = [item["response"]["data"] for item in response["outputs"]]
    assert data[1]["total"] == data[2]["total"] == data[4]["total"] == 1
    assert data[2]["resources"][0]["dependencies"] == []
    assert data[5]["coverageGap"] is True and data[5]["policyHistory"] == "not_collected"
    for status in data[4]["collection"].values():
        assert status == "not_collected"
    updated = advanced(value)
    updated["ledgerRevision"] += 1
    next(
        grant
        for task in updated["tasks"]
        if task["id"] == "root"
        for grant in task["grants"]
        if grant["tool"] == "records.read"
    )["resources"].append("new-visible-selector")
    updated["manifest"]["owners"].append(
        {"id": "successor", "name": "Successor team", "kind": "team"}
    )
    updated["manifest"]["agents"][0]["ownerId"] = "successor"
    updated["manifest"]["resourceBindings"][0]["actions"] = ["s3:GetObject", "s3:GetObjectVersion"]
    second = publish(neo4j_session, updated)
    changes = query(
        scope(updated),
        {"sourceId": second.source_id, "history": True},
        [
            {
                "operation": "get_changes",
                "args": {"sourceId": second.source_id, "changeKind": "permissions"},
            },
            {
                "operation": "get_changes",
                "args": {"sourceId": second.source_id, "changeKind": "ownership"},
            },
        ],
    )
    assert changes["ok"] and all(item["ok"] for item in changes["outputs"]), changes
    assert changes["outputs"][0]["response"]["data"]["changes"]["changed"]
    assert changes["outputs"][1]["response"]["data"]["changes"]["changed"]
    assert "Review credential" not in json.dumps(changes)


def test_same_opaque_owner_credential_and_resource_ids_never_merge_tenants(
    neo4j_session, v2_snapshot
):
    first = publish(neo4j_session, v2_snapshot)
    other = deepcopy(v2_snapshot)
    other["source"]["tenantId"] = "beta"
    other["manifest"]["source"] = dict(other["source"])
    for task in other["tasks"]:
        task["tenantId"] = "beta"
    second = publish(neo4j_session, other)
    rows = list(
        neo4j_session.run(
            "MATCH (n) WHERE n.projection_id IN $projections AND (n:GuardOwner OR n:GuardCredentialReference OR n:GuardExternalResource) RETURN n.projection_id AS projection,n.entity_id AS entity",
            projections=[first.projection_id, second.projection_id],
        )
    )
    assert {row["entity"] for row in rows if row["projection"] == first.projection_id}.isdisjoint(
        row["entity"] for row in rows if row["projection"] == second.projection_id
    )


def test_visible_generic_actions_remain_uncollected_without_breaking_aws_evidence(
    neo4j_session, v2_snapshot
):
    value = deepcopy(v2_snapshot)
    value["manifest"]["resourceBindings"][1]["actions"] = ["read", "record.read"]
    receipt = publish(neo4j_session, value)
    response = query(
        scope(value),
        {"sourceId": receipt.source_id},
        [
            {
                "operation": "get_agent_access",
                "args": {"sourceId": receipt.source_id, "agentId": "agent-research"},
            },
            {
                "operation": "get_agent_inventory",
                "args": {
                    "sourceId": receipt.source_id,
                    "agentId": "agent-research",
                    "section": "policies",
                    "limit": 10,
                },
            },
            {"operation": "list_resources", "args": {"sourceId": receipt.source_id}},
            {
                "operation": "get_resource_access",
                "args": {"sourceId": receipt.source_id, "resourceId": "prefix-binding"},
            },
        ],
    )
    assert response["ok"] and all(item["ok"] for item in response["outputs"]), response
    access, inventory, resources, resource = [
        item["response"]["data"] for item in response["outputs"]
    ]
    for evidence in (access["policyEvidence"], inventory["items"]):
        generic = [item for item in evidence if item["action"] in ("read", "record.read")]
        aws = [item for item in evidence if item["action"] == "s3:GetObject"]
        assert {item["action"] for item in generic} == {"read", "record.read"}
        assert all(
            item["status"] == "not_collected"
            and item["reason"] == "unsupported_action"
            and item["assessment"] == "unknown"
            and item["candidates"] == []
            for item in generic
        )
        assert len(aws) == 1 and aws[0]["reason"] == "cloud_not_collected"
    assert resources["total"] == 2 and resource["total"] == 1
    target = resource["resource"]["targets"][0]
    assert target["provider"] == "host" and target.get("arn") is None
    assert resource["resource"]["actions"] == ["read", "record.read"]
    assert resource["assessment"] == "unknown"
    assert set(resource["collection"].values()) == {"not_collected"}
