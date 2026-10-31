"""Run the real TypeScript read service against scoped disposable Cartography projections."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

from agent_guard_cartography.graph import import_snapshot
from agent_guard_cartography.inventory import validate_snapshot

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
BRIDGE = Path(__file__).parents[1] / "fixtures" / "query-agent-map.mjs"


@pytest.fixture
def reference_snapshot(snapshot_factory):
    value = snapshot_factory()
    value["source"]["companyId"] += "-" + uuid4().hex
    root, child, handoff = value["tasks"]
    root["id"] = "hidden-root-canary"
    root["familyId"] = root["id"]
    child["id"] = "visible-task"
    child["parentTaskId"] = root["id"]
    child["familyId"] = root["id"]
    handoff["id"] = "unassigned-task-canary"
    handoff["sourceTaskId"] = root["id"]
    handoff["familyId"] = root["id"]
    handoff["principalId"] = "unassigned-principal-canary"
    value["profile"] = "host-mcp"
    manifest = {
        "schemaVersion": 1,
        "evidenceKind": "host_asserted",
        "source": dict(value["source"]),
        "manifestId": "configuration",
        "revision": 1,
        "observedAt": value["generatedAt"],
        "agents": [
            {
                "id": "visible-agent",
                "name": "Research reader",
                "ownerId": "visible-owner",
                "teamId": "visible-team",
            },
            {
                "id": "hidden-agent-canary",
                "name": "hidden-name-canary",
                "ownerId": "hidden-owner-canary",
                "teamId": "hidden-team",
            },
        ],
        "deployments": [
            {"id": "visible-deployment", "agentId": "visible-agent", "environment": "test"},
            {
                "id": "hidden-deployment-canary",
                "agentId": "hidden-agent-canary",
                "environment": "hidden-environment-canary",
            },
        ],
        "taskBindings": [
            {"taskId": child["id"], "deploymentId": "visible-deployment"},
            {"taskId": root["id"], "deploymentId": "hidden-deployment-canary"},
        ],
        "resourceBindings": [],
        "executionBindings": [],
    }
    for visible, tool, resource in [
        (True, "records.read", "report-A"),
        (False, "records.delete", "report-B"),
    ]:
        name = "visible" if visible else "hidden-canary"
        manifest["resourceBindings"].append(
            {
                "id": name + "-resource",
                "tool": tool,
                "resourceRef": resource,
                "target": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "111122223333",
                    "region": "",
                    "arn": f"arn:aws:s3:::reports/{name}.txt",
                    "kind": "object",
                },
                "actions": ["s3:GetObject" if visible else "s3:DeleteObject"],
                "scope": "exact",
            }
        )
        manifest["executionBindings"].append(
            {
                "id": name + "-execution",
                "tool": tool,
                "deploymentId": "visible-deployment" if visible else "hidden-deployment-canary",
                "connectionId": "shared-mcp",
                "identitySelection": "static",
                "identity": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "111122223333",
                    "region": "",
                    "arn": f"arn:aws:iam::111122223333:role/{name}",
                },
            }
        )
    value["manifest"] = manifest
    value["coverage"]["manifest"] = {"status": "complete", "observedAt": manifest["observedAt"]}
    value["mcp"] = {
        "observedAt": value["generatedAt"],
        "connections": [
            {
                "connectionId": "shared-mcp",
                "status": "observed",
                "inventory": {
                    "schemaVersion": 1,
                    "identity": {
                        "serverId": "reports",
                        "transportRef": "opaque:" + "a" * 64,
                        "principalId": "mcp-reader",
                        "tenantId": "alpha",
                    },
                    "sessionId": "mcp-session",
                    "revision": 1,
                    "authorizationEpoch": 1,
                    "metadataRevision": 1,
                    "state": "ready",
                    "metadataState": "current",
                    "observedAt": value["generatedAt"],
                    "operations": [
                        {"name": tool["name"], "kind": "tool", "fingerprint": tool["fingerprint"]}
                        for tool in value["tools"][:2]
                    ],
                },
            }
        ],
    }
    value["coverage"]["mcp"] = {"status": "complete", "observedAt": value["generatedAt"]}
    return validate_snapshot(value)


def scope(snapshot, *, all_teams=False):
    return {
        "subject": "reader",
        "companyId": snapshot["source"]["companyId"],
        "tenantIds": [snapshot["source"]["tenantId"]],
        "teamIds": ["visible-team"],
        "allTeams": all_teams,
    }


def query(scope_value, request=None, operations=None, limits=None, now=None):
    node = shutil.which("node")
    assert node is not None and (ROOT / "packages/agent-map/dist/index.js").is_file(), (
        "Run npm run build before reference query tests"
    )
    result = subprocess.run(
        [node, str(BRIDGE)],
        input=json.dumps(
            {
                "scope": scope_value,
                "request": request or {},
                "operations": operations or [],
                "limits": limits or {},
                **({"now": now} if now is not None else {}),
            }
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    password = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())["password"]
    assert password not in result.stdout + result.stderr
    return json.loads(result.stdout)


def publish(session, snapshot):
    return import_snapshot(session, snapshot, snapshot["source"])


def test_recomposed_health_preserves_original_capture_times_without_hidden_connections(
    neo4j_session, reference_snapshot
):
    snapshot = deepcopy(reference_snapshot)
    old = "2026-10-01T00:00:00.000Z"
    tool_time = "2026-10-02T00:00:00.000Z"
    snapshot["generatedAt"] = "2026-10-30T09:00:00.000Z"
    snapshot["coverage"]["tasks"]["observedAt"] = old
    snapshot["coverage"]["tools"]["observedAt"] = tool_time
    snapshot["coverage"]["mcp"]["observedAt"] = snapshot["generatedAt"]
    snapshot["mcp"]["observedAt"] = snapshot["generatedAt"]
    visible = snapshot["mcp"]["connections"][0]
    hidden = deepcopy(visible)
    hidden["connectionId"] = "hidden-mcp-canary"
    hidden["inventory"]["observedAt"] = "2000-01-01T00:00:00.000Z"
    hidden["inventory"]["operations"] = [
        item for item in hidden["inventory"]["operations"] if item["name"] == "records.delete"
    ]
    visible["inventory"]["observedAt"] = old
    visible["inventory"]["operations"] = [
        item for item in visible["inventory"]["operations"] if item["name"] == "records.read"
    ]
    snapshot["mcp"]["connections"].append(hidden)
    snapshot["manifest"]["executionBindings"][1]["connectionId"] = hidden["connectionId"]
    receipt = publish(neo4j_session, snapshot)
    now = int(datetime.fromisoformat(snapshot["generatedAt"]).timestamp() * 1000)
    response = query(
        scope(snapshot),
        {"sourceId": receipt.source_id},
        [{"operation": "get_inventory_health", "args": {"sourceId": receipt.source_id}}],
        now=now,
    )
    assert response["ok"], response
    assert response["outputs"][0]["ok"], response
    health = response["outputs"][0]["response"]["data"]["sources"][0]
    assert health["stale"] is False
    for component, expected in (("tasks", old), ("tools", tool_time), ("mcp", old)):
        assert health["coverage"][component]["observedAt"] == expected
        assert health["coverage"][component]["stale"] is True
        assert health["coverage"][component]["ageSeconds"] > 86_400
    assert "hidden-mcp-canary" not in json.dumps(response)
    assert "2000-01-01" not in json.dumps(response)


def test_retained_projections_keep_their_own_original_core_capture_times(
    neo4j_session, reference_snapshot
):
    old = deepcopy(reference_snapshot)
    old["coverage"]["tasks"]["observedAt"] = "2026-10-01T00:00:00.000Z"
    old["coverage"]["tools"]["observedAt"] = "2026-10-02T00:00:00.000Z"
    publish(neo4j_session, old)
    current = deepcopy(old)
    current["snapshotId"] = uuid4().hex
    current["ledgerRevision"] += 1
    current["generatedAt"] = "2026-10-30T09:00:00.000Z"
    current["coverage"]["tasks"]["observedAt"] = "2026-10-03T00:00:00.000Z"
    current["coverage"]["tools"]["observedAt"] = "2026-10-04T00:00:00.000Z"
    receipt = publish(neo4j_session, current)
    response = query(scope(current), {"sourceId": receipt.source_id, "history": True})
    assert response["ok"], response
    source = response["view"]["sources"][0]
    for name, snapshot in (("previous", old), ("current", current)):
        for component in ("tasks", "tools"):
            assert source[name]["coverage"][component] == snapshot["coverage"][component]


@pytest.mark.parametrize("coverage", [None, "{invalid", "x" * 5000])
def test_missing_or_malformed_stored_capture_metadata_never_becomes_fresh(
    neo4j_session, reference_snapshot, coverage
):
    receipt = publish(neo4j_session, reference_snapshot)
    neo4j_session.run(
        "MATCH (p:GuardSnapshot {id:$id}) SET p.coverage_json=$coverage",
        id=receipt.projection_id,
        coverage=coverage,
    ).consume()
    response = query(scope(reference_snapshot), {"sourceId": receipt.source_id})
    if coverage is None:
        assert response["ok"], response
        for component in ("tasks", "tools"):
            assert response["view"]["sources"][0]["current"]["coverage"][component] == {
                "status": "complete"
            }
    else:
        assert response == {"ok": False, "code": "MAP_UNAVAILABLE"}


def test_real_queries_filter_hidden_teams_ancestors_shared_operations_and_provider_data(
    neo4j_session, reference_snapshot
):
    receipt = publish(neo4j_session, reference_snapshot)
    neo4j_session.run(
        "MATCH (a:GuardAgent {projection_id:$id,agent_id:'visible-agent'}) SET a.arbitrary_metadata='private-metadata-canary'",
        id=receipt.projection_id,
    ).consume()
    neo4j_session.run(
        "MATCH (c:GuardMcpConnection {projection_id:$id}) "
        "SET c.principal_id='hidden-principal-canary',c.session_id='hidden-session-canary',"
        "c.revision=999,c.metadata_revision=999",
        id=receipt.projection_id,
    ).consume()
    neo4j_session.run(
        "CREATE (p:AWSRole {id:$id,policy:'provider-policy-canary'})", id=uuid4().hex
    ).consume()
    before = neo4j_session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
    response = query(
        scope(reference_snapshot),
        {"sourceId": receipt.source_id},
        [
            {
                "operation": "get_agent_access",
                "args": {"sourceId": receipt.source_id, "agentId": "visible-agent"},
            },
            {
                "operation": "explain_access",
                "args": {
                    "sourceId": receipt.source_id,
                    "taskId": "visible-task",
                    "tool": "records.read",
                    "resourceId": "report-A",
                },
            },
            {
                "operation": "find_agents_with_access",
                "args": {"resourceRef": "report-A", "action": "s3:GetObject"},
            },
        ],
    )
    assert response["ok"], response
    serialized = json.dumps(response)
    for forbidden in [
        "hidden-",
        "unassigned-",
        "private-metadata-canary",
        "provider-policy-canary",
        "records.delete",
        "family_id",
        "manifest_revision",
    ]:
        assert forbidden not in serialized
    (source,) = response["view"]["sources"]
    nodes = source["current"]["nodes"]
    assert {node["properties"]["task_id"] for node in nodes if node["label"] == "GuardTask"} == {
        "visible-task"
    }
    assert {
        node["properties"]["name"] for node in nodes if node["label"] == "GuardMcpOperation"
    } == {"records.read"}
    assert all(item["ok"] for item in response["outputs"])
    explanation = response["outputs"][1]["response"]["data"]
    assert "ancestor_evidence_outside_visible_scope" in json.dumps(explanation)
    assert neo4j_session.run("MATCH (n) RETURN count(n) AS count").single()["count"] == before
    admin = query(scope(reference_snapshot, all_teams=True), {"sourceId": receipt.source_id})
    assert "hidden-root-canary" in json.dumps(admin)
    assert "unassigned-task-canary" in json.dumps(admin)


def test_unknown_and_unauthorized_lookups_share_empty_or_not_found_results(
    neo4j_session, reference_snapshot
):
    receipt = publish(neo4j_session, reference_snapshot)
    for changed in [
        {**scope(reference_snapshot), "companyId": "another-company"},
        {**scope(reference_snapshot), "tenantIds": ["another-tenant"]},
        {**scope(reference_snapshot), "teamIds": ["another-team"]},
    ]:
        assert query(changed, {"sourceId": receipt.source_id}) == {
            "ok": True,
            "view": {"sources": []},
            "outputs": [],
        }
    results = query(
        scope(reference_snapshot),
        {"sourceId": receipt.source_id},
        [
            {
                "operation": "get_agent_access",
                "args": {"sourceId": receipt.source_id, "agentId": agent_id},
            }
            for agent_id in [
                "hidden-agent-canary",
                "never-existed",
                "id' MATCH (n) DETACH DELETE n //",
            ]
        ],
    )
    assert [item for item in results["outputs"]] == [{"ok": False, "code": "MAP_NOT_FOUND"}] * 3


def test_hidden_only_changes_do_not_affect_visible_differences_or_counts(
    neo4j_session, reference_snapshot
):
    publish(neo4j_session, reference_snapshot)
    updated = deepcopy(reference_snapshot)
    updated["snapshotId"] = uuid4().hex
    updated["ledgerRevision"] += 1
    updated["tasks"][0]["revoked"] = True
    updated["manifest"]["revision"] += 1
    updated["manifest"]["agents"][1]["name"] = "hidden-changed-canary"
    receipt = publish(neo4j_session, updated)
    response = query(
        scope(updated),
        {"sourceId": receipt.source_id, "history": True},
        [
            {
                "operation": "get_changes",
                "args": {"sourceId": receipt.source_id, "since": "previous"},
            },
            {"operation": "get_inventory_health", "args": {}},
        ],
    )
    assert response["ok"]
    changes = response["outputs"][0]["response"]["data"]["changes"]
    assert changes == {"added": [], "removed": [], "changed": []}
    assert "hidden-" not in json.dumps(response)
    assert len(response["outputs"][1]["response"]["data"]["sources"]) == 1


def test_historical_team_moves_do_not_reveal_old_hidden_ownership(
    neo4j_session, reference_snapshot
):
    snapshot = deepcopy(reference_snapshot)
    snapshot["manifest"]["agents"].append(
        {"id": "staying-visible", "name": "Staying", "ownerId": None, "teamId": "visible-team"}
    )
    publish(neo4j_session, snapshot)
    snapshot["snapshotId"] = uuid4().hex
    snapshot["manifest"]["revision"] += 1
    snapshot["manifest"]["agents"][0]["teamId"] = "hidden-team"
    receipt = publish(neo4j_session, snapshot)
    response = query(scope(snapshot), {"sourceId": receipt.source_id, "history": True})
    assert response["ok"]
    for projection in [
        response["view"]["sources"][0]["current"],
        response["view"]["sources"][0]["previous"],
    ]:
        assert {
            node["properties"].get("agent_id")
            for node in projection["nodes"]
            if node["label"] == "GuardAgent"
        } == {"staying-visible"}
        assert all(node["label"] != "GuardTask" for node in projection["nodes"])


def test_real_query_limits_fail_before_returning_partial_graphs(neo4j_session, reference_snapshot):
    receipt = publish(neo4j_session, reference_snapshot)
    result = query(
        scope(reference_snapshot), {"sourceId": receipt.source_id}, limits={"maxNodes": 1}
    )
    assert result == {"ok": False, "code": "MAP_LIMIT_EXCEEDED"}
    result = query(
        scope(reference_snapshot), {"sourceId": receipt.source_id}, limits={"maxEdges": 1}
    )
    assert result == {"ok": False, "code": "MAP_LIMIT_EXCEEDED"}


def test_agent_index_does_not_load_task_neighborhoods(neo4j_session, reference_snapshot):
    receipt = publish(neo4j_session, reference_snapshot)
    response = query(
        scope(reference_snapshot),
        {"sourceId": receipt.source_id, "summary": True},
        [{"operation": "list_agents", "args": {}}],
        {"maxNodes": 2},
    )
    assert response["ok"], response
    nodes = response["view"]["sources"][0]["current"]["nodes"]
    assert {node["label"] for node in nodes} == {"GuardAgent", "GuardDeployment"}
    assert response["outputs"][0]["ok"], response
    assert len(response["outputs"][0]["response"]["data"]["agents"]) == 1


@pytest.mark.parametrize("ownership", ["hidden", "unassigned"])
def test_historical_task_move_hides_task_derived_evidence(
    neo4j_session, reference_snapshot, ownership
):
    snapshot = deepcopy(reference_snapshot)
    publish(neo4j_session, snapshot)
    snapshot["snapshotId"] = uuid4().hex
    snapshot["manifest"]["revision"] += 1
    if ownership == "hidden":
        snapshot["manifest"]["taskBindings"][0]["deploymentId"] = "hidden-deployment-canary"
    else:
        snapshot["manifest"]["taskBindings"].pop(0)
    receipt = publish(neo4j_session, snapshot)
    response = query(scope(snapshot), {"sourceId": receipt.source_id, "history": True})
    assert response["ok"], response
    for projection in [
        response["view"]["sources"][0]["current"],
        response["view"]["sources"][0]["previous"],
    ]:
        assert any(node["label"] == "GuardAgent" for node in projection["nodes"])
        assert all(
            node["label"]
            not in {
                "GuardTask",
                "GuardGrant",
                "GuardPrincipal",
                "GuardResource",
                "GuardResourceBinding",
                "GuardExternalResource",
            }
            for node in projection["nodes"]
        )
        assert "visible-task" not in json.dumps(projection)


def test_core_and_unassigned_inventory_require_explicit_source_wide_scope(
    neo4j_session, snapshot_factory
):
    snapshot = snapshot_factory()
    snapshot["source"]["companyId"] += uuid4().hex
    receipt = publish(neo4j_session, snapshot)
    assert query(scope(snapshot), {"sourceId": receipt.source_id})["view"]["sources"] == []
    result = query(scope(snapshot, all_teams=True), {"sourceId": receipt.source_id})
    assert result["ok"]
    assert (
        len(
            [
                node
                for node in result["view"]["sources"][0]["current"]["nodes"]
                if node["label"] == "GuardTask"
            ]
        )
        == 3
    )
