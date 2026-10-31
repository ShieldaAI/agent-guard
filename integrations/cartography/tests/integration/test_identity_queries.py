"""Real OIDC/TLS login binds a browser to scoped reads in the owned Neo4j graph."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_reference_queries import reference_snapshot as reference_snapshot
from test_reference_queries import scope

from agent_guard_cartography.graph import import_snapshot

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
BRIDGE = Path(__file__).parents[1] / "fixtures" / "query-identity-map.mjs"


def test_oidc_identity_binding_drives_real_neo4j_visibility_and_revocation(
    neo4j_session, reference_snapshot
):
    receipt = import_snapshot(neo4j_session, reference_snapshot, reference_snapshot["source"])
    before = neo4j_session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
    node = shutil.which("node")
    assert node is not None and (ROOT / "packages/agent-map/dist/identity-http.js").is_file(), (
        "Run npm run build before identity graph tests"
    )
    operations = [
        {"operation": "list_agents", "args": {"sourceId": receipt.source_id}},
        {
            "operation": "get_agent_access",
            "args": {"sourceId": receipt.source_id, "agentId": "visible-agent"},
        },
        {
            "operation": "get_agent_access",
            "args": {"sourceId": receipt.source_id, "agentId": "hidden-agent-canary"},
        },
        {
            "operation": "get_agent_access",
            "args": {"sourceId": receipt.source_id, "agentId": "nonexistent-agent"},
        },
    ]
    result = subprocess.run(
        [node, str(BRIDGE)],
        input=json.dumps({"scope": scope(reference_snapshot), "operations": operations}),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    password = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())["password"]
    assert password not in result.stdout + result.stderr
    for forbidden in [
        "agm_sess_v1.",
        "agm_login_v1.",
        "agm_csrf_v1.",
        "test-access-token-not-for-browser",
        "hidden-",
        "unassigned-",
        "records.delete",
    ]:
        assert forbidden not in result.stdout
    response = json.loads(result.stdout)
    assert response["ok"] is True
    listing, visible, hidden, absent = response["outputs"]
    assert [item["status"] for item in response["outputs"]] == [200, 200, 404, 404]
    assert [item["agentId"] for item in listing["response"]["data"]["agents"]] == ["visible-agent"]
    assert {item["taskId"] for item in visible["response"]["data"]["tasks"]} == {"visible-task"}
    assert hidden == absent == {"status": 404, "response": {"error": "MAP_NOT_FOUND"}}
    assert response["revokedStatus"] == 401
    assert response["revokedResponse"] == {"error": "MAP_SESSION_REQUIRED"}
    assert neo4j_session.run("MATCH (n) RETURN count(n) AS count").single()["count"] == before
