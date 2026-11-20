"""Manifest v4 networkIsolation: real executor export -> Neo4j projection -> scoped Map reads."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from test_reference_queries import query

from agent_guard_cartography.graph import GraphImportError, import_snapshot
from agent_guard_cartography.inventory import validate_snapshot

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).parents[1] / "fixtures" / "manifest-executor.mjs"
NETWORK_FIELDS = (
    "network_status",
    "network_segment",
    "network_egress",
    "network_egress_targets",
    "sandbox_kind",
)


def exported(flag):
    result = subprocess.run(
        [shutil.which("node"), str(FIXTURE), flag],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["observedHost"]["body"]


@pytest.fixture(scope="module")
def exported_v4():
    return exported("--v4")


def fresh(value):
    value = deepcopy(value)
    value["source"]["companyId"] += "-" + uuid4().hex
    value["source"]["sourceId"] += "-" + uuid4().hex
    value["manifest"]["source"] = dict(value["source"])
    value["snapshotId"] = uuid4().hex
    return validate_snapshot(value)


def scope(value, teams=("team-research", "team-review")):
    return {
        "subject": "reviewer",
        "companyId": value["source"]["companyId"],
        "tenantIds": [value["source"]["tenantId"]],
        "teamIds": list(teams),
        "allTeams": False,
    }


def map_deployments(value, source_id, operations=None):
    response = query(scope(value), {"sourceId": source_id}, operations)
    assert response["ok"], response
    [source] = response["view"]["sources"]
    nodes = {
        node["properties"]["deployment_id"]: node["properties"]
        for node in source["current"]["nodes"]
        if node["label"] == "GuardDeployment"
    }
    return nodes, response["outputs"]


def network(properties):
    return {field: properties.get(field) for field in NETWORK_FIELDS}


def test_declared_isolation_is_projected_and_read_by_the_map(neo4j_session, exported_v4):
    value = fresh(exported_v4)
    result = import_snapshot(neo4j_session, value, value["source"])
    stored = {
        row["id"]: dict(row["d"].items())
        for row in neo4j_session.run(
            "MATCH (d:GuardDeployment {projection_id:$id}) RETURN d.deployment_id AS id, d",
            id=result.projection_id,
        )
    }
    assert stored["deployment-static"]["network_status"] == "declared"
    assert stored["deployment-static"]["network_egress_targets"] == [
        "opaque:" + "6" * 64,
        "opaque:" + "7" * 64,
    ]
    assert stored["deployment-dynamic"]["network_status"] == "not_declared"
    assert all(field not in stored["deployment-dynamic"] for field in NETWORK_FIELDS[1:])

    deployments, _ = map_deployments(value, result.source_id)
    assert network(deployments["deployment-static"]) == {
        "network_status": "declared",
        "network_segment": "opaque:" + "5" * 64,
        "network_egress": "allowlist",
        "network_egress_targets": ["opaque:" + "6" * 64, "opaque:" + "7" * 64],
        "sandbox_kind": "container",
    }
    assert network(deployments["deployment-dynamic"])["network_status"] == "not_declared"


def test_an_empty_allowlist_and_no_segment_survive_the_round_trip(neo4j_session, exported_v4):
    value = deepcopy(exported_v4)
    value["manifest"]["networkIsolation"] = [
        {
            "deploymentId": "deployment-dynamic",
            "segmentId": None,
            "egress": "none",
            "egressTargets": [],
            "sandbox": "vm",
        }
    ]
    value = fresh(value)
    result = import_snapshot(neo4j_session, value, value["source"])
    deployments, _ = map_deployments(value, result.source_id)
    dynamic = network(deployments["deployment-dynamic"])
    # Neo4j stores no nulls: the segment reads back absent, which means none when declared.
    assert dynamic == {
        "network_status": "declared",
        "network_segment": None,
        "network_egress": "none",
        "network_egress_targets": [],
        "sandbox_kind": "vm",
    }


def test_v3_to_v4_at_the_same_revision_publishes_and_shows_as_a_change(neo4j_session, exported_v4):
    old = fresh(exported("--v3"))
    first = import_snapshot(neo4j_session, old, old["source"])
    deployments, _ = map_deployments(old, first.source_id)
    assert all(network(item)["network_status"] is None for item in deployments.values())

    upgraded = deepcopy(exported_v4)
    upgraded["source"] = dict(old["source"])
    upgraded["manifest"]["source"] = dict(old["source"])
    upgraded["snapshotId"] = uuid4().hex
    upgraded["manifest"]["revision"] = old["manifest"]["revision"] + 1
    # Same ledger revision: the lifted core must not read as REVISION_CONTENT_CONFLICT.
    assert upgraded["ledgerRevision"] == old["ledgerRevision"]
    upgraded["generatedAt"] = old["generatedAt"]
    second = import_snapshot(neo4j_session, validate_snapshot(upgraded), old["source"])
    assert second.published

    operations = [
        {
            "operation": "get_changes",
            "args": {"sourceId": first.source_id, "changeKind": "bindings"},
        }
    ]
    _, [changes] = map_deployments(old, first.source_id, operations)
    assert changes["ok"], changes
    details = {
        item["after"]["properties"]["deployment_id"]: item
        for item in changes["response"]["data"]["details"]
        if item["label"] == "GuardDeployment" and item["after"]
    }
    assert set(NETWORK_FIELDS) <= set(details["deployment-static"]["changedFields"])
    assert "network_status" in details["deployment-dynamic"]["changedFields"]

    downgrade = deepcopy(old)
    downgrade["snapshotId"] = uuid4().hex
    downgrade["manifest"]["revision"] = upgraded["manifest"]["revision"] + 1
    with pytest.raises(GraphImportError, match="^MANIFEST_SCHEMA_ROLLBACK$"):
        import_snapshot(neo4j_session, validate_snapshot(downgrade), old["source"])
