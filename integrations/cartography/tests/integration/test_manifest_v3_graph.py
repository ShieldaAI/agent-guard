"""Manifest v3 directAccess: real executor export -> Neo4j projection -> scoped Map queries."""

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
def exported_v3():
    return exported("--v3")


def fresh(value):
    value = deepcopy(value)
    value["source"]["companyId"] += "-" + uuid4().hex
    value["source"]["sourceId"] += "-" + uuid4().hex
    value["manifest"]["source"] = dict(value["source"])
    value["snapshotId"] = uuid4().hex
    return validate_snapshot(value)


def scope(value, teams=("team-research",), all_teams=False):
    return {
        "subject": "reviewer",
        "companyId": value["source"]["companyId"],
        "tenantIds": [value["source"]["tenantId"]],
        "teamIds": list(teams),
        "allTeams": all_teams,
    }


def agent_access(value, source_id, agent_id, **options):
    operations = [
        {"operation": "get_agent_access", "args": {"sourceId": source_id, "agentId": agent_id}}
    ]
    response = query(scope(value, **options), {"sourceId": source_id}, operations)
    assert response["ok"], response
    return response["outputs"][0]


def test_declared_paths_are_projected_and_reported_per_deployment(neo4j_session, exported_v3):
    value = fresh(exported_v3)
    result = import_snapshot(neo4j_session, value, value["source"])
    row = neo4j_session.run(
        "MATCH (a:GuardDirectAccess {projection_id:$id})-[:G_DIRECT_ACCESS_FOR]->(d:GuardDeployment) "
        "RETURN a, d.deployment_id AS deployment",
        id=result.projection_id,
    ).single(strict=True)
    assert row["deployment"] == "deployment-static"
    assert row["a"]["kind"] == "database" and row["a"]["evidence_kind"] == "host_asserted"
    statuses = dict(
        neo4j_session.run(
            "MATCH (d:GuardDeployment {projection_id:$id}) "
            "RETURN d.deployment_id AS id, d.direct_access_status AS status",
            id=result.projection_id,
        ).values()
    )
    assert statuses == {"deployment-static": "found", "deployment-dynamic": "none_declared"}

    research = agent_access(value, result.source_id, "agent-research")
    assert research["ok"], research
    [deployment] = research["response"]["data"]["outsideGuard"]["directAccess"]
    assert (deployment["deploymentId"], deployment["status"]) == ("deployment-static", "found")
    assert [entry["kind"] for entry in deployment["entries"]] == ["database"]

    review = agent_access(value, result.source_id, "agent-review", teams=("team-review",))
    [deployment] = review["response"]["data"]["outsideGuard"]["directAccess"]
    assert (deployment["status"], deployment["entries"]) == ("none_declared", [])


def test_a_team_reader_never_sees_another_teams_declared_path(neo4j_session, exported_v3):
    value = fresh(exported_v3)
    result = import_snapshot(neo4j_session, value, value["source"])
    response = query(scope(value, teams=("team-review",)), {"sourceId": result.source_id})
    assert response["ok"], response
    text = json.dumps(response)
    assert "records database directly" not in text and "deployment-static" not in text
    hidden = agent_access(value, result.source_id, "agent-research", teams=("team-review",))
    assert hidden == {"ok": False, "code": "MAP_NOT_FOUND"}


def test_a_v2_manifest_reads_unknown_and_v3_cannot_roll_back_to_v2(neo4j_session, exported_v3):
    old = fresh(exported("--v2"))
    first = import_snapshot(neo4j_session, old, old["source"])
    [deployment] = agent_access(old, first.source_id, "agent-research")["response"]["data"][
        "outsideGuard"
    ]["directAccess"]
    assert deployment["status"] == "unknown"

    upgraded = deepcopy(exported_v3)
    upgraded["source"] = dict(old["source"])
    upgraded["manifest"]["source"] = dict(old["source"])
    upgraded["snapshotId"] = uuid4().hex
    upgraded["manifest"]["revision"] = old["manifest"]["revision"] + 1
    # The two fixtures were exported at different times. At the same ledger revision a
    # capture older than the published one is refused (GENERATED_AT_ROLLBACK), so the
    # upgrade carries the published capture time; the manifest change is what is tested.
    upgraded["generatedAt"] = old["generatedAt"]
    second = import_snapshot(neo4j_session, validate_snapshot(upgraded), old["source"])
    assert second.published

    downgrade = deepcopy(old)
    downgrade["snapshotId"] = uuid4().hex
    downgrade["manifest"]["revision"] = upgraded["manifest"]["revision"] + 1
    with pytest.raises(GraphImportError, match="^MANIFEST_SCHEMA_ROLLBACK$"):
        import_snapshot(neo4j_session, validate_snapshot(downgrade), old["source"])
