"""Dangerous three: real executor export -> Neo4j -> scoped Map flags, list and detail alike.

The export is the v3 host fixture (agent-research runs `root`; agent-review runs `child`,
delegated from `root`). The test sets the outside-content labels the way a labelled
executor would report them, then imports the snapshot.
"""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from test_reference_queries import query

from agent_guard_cartography.graph import import_snapshot
from agent_guard_cartography.inventory import validate_snapshot

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).parents[1] / "fixtures" / "manifest-executor.mjs"
FUTURE = 4_102_444_800_000
PARTNER = "opaque:" + "5" * 64


@pytest.fixture(scope="module")
def exported():
    result = subprocess.run(
        [shutil.which("node"), str(FIXTURE), "--v3"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["observedHost"]["body"]


def labelled(exported, mode=None, child_wildcard=False):
    value = deepcopy(exported)
    value["source"]["companyId"] += "-" + uuid4().hex
    value["source"]["sourceId"] += "-" + uuid4().hex
    value["manifest"]["source"] = dict(value["source"])
    value["snapshotId"] = uuid4().hex
    value["untrustedContextDefault"] = "allow"
    for task in value["tasks"]:
        task["budget"]["deadline"] = FUTURE
        task["allowedRecipients"] = [PARTNER]
        if child_wildcard and task["id"] == "child":
            task["grants"] = [{"tool": "records.read", "resources": ["*"]}]
    (tool,) = value["tools"]
    tool.update(readsUntrusted=True, sendsExternal=True, untrustedContext=mode)
    for binding in value["manifest"]["resourceBindings"]:
        if binding["id"] == "prefix-binding":
            binding["sensitivity"] = "restricted"
    return validate_snapshot(value)


def scope(value, teams=("team-research", "team-review"), all_teams=False):
    return {
        "subject": "reviewer",
        "companyId": value["source"]["companyId"],
        "tenantIds": [value["source"]["tenantId"]],
        "teamIds": list(teams),
        "allTeams": all_teams,
    }


def read(value, source_id, operations, **options):
    result = query(scope(value, **options), {"sourceId": source_id}, operations)
    assert result["ok"], result
    outputs = result["outputs"]
    assert all(item["ok"] for item in outputs), outputs
    return [item["response"]["data"] for item in outputs], json.dumps(result)


def flags(value, source_id, agent, **options):
    (data,), wire = read(
        value,
        source_id,
        [{"operation": "get_agent_access", "args": {"sourceId": source_id, "agentId": agent}}],
        **options,
    )
    return data["boundaryFlags"][0], wire


def listed(value, source_id, **options):
    (data,), _ = read(
        value,
        source_id,
        [{"operation": "list_agents", "args": {"sourceId": source_id, "includeFlags": True}}],
        **options,
    )
    return {agent["agentId"]: agent["boundaryFlags"]["dangerousThree"] for agent in data["agents"]}


def filtered(value, source_id, status, **options):
    """The flag filter reads the full scoped graph, a different read from the page path."""
    (data,), _ = read(
        value,
        source_id,
        [{"operation": "list_agents", "args": {"sourceId": source_id, "flagStatus": status}}],
        **options,
    )
    return {agent["agentId"] for agent in data["agents"]}


def test_list_and_detail_agree_and_an_allow_sender_is_exposed(neo4j_session, exported):
    value = labelled(exported)
    receipt = import_snapshot(neo4j_session, value, value["source"])
    detail, _ = flags(value, receipt.source_id, "agent-review", all_teams=True)
    assert detail["status"] == "exposed", detail
    assert detail["legs"] == {
        "privateData": "present",
        "outsideContent": "present",
        "externalSend": "present",
    }
    assert listed(value, receipt.source_id, all_teams=True) == {
        "agent-research": "exposed",
        "agent-review": "exposed",
    }


def test_an_ancestor_outside_the_viewer_scope_makes_the_send_leg_unknown(neo4j_session, exported):
    value = labelled(exported)
    receipt = import_snapshot(neo4j_session, value, value["source"])
    detail, wire = flags(value, receipt.source_id, "agent-review", teams=("team-review",))
    assert detail["legs"]["externalSend"] == "unknown"
    assert detail["status"] == "unknown"
    assert "ancestor_evidence_outside_visible_scope" in detail["notes"]
    assert listed(value, receipt.source_id, teams=("team-review",)) == {"agent-review": "unknown"}
    assert filtered(value, receipt.source_id, "unknown", teams=("team-review",)) == {"agent-review"}
    assert filtered(value, receipt.source_id, "exposed", teams=("team-review",)) == set()
    # In scope through the other team, the same ancestor is read even in a one-agent read.
    both, _ = flags(value, receipt.source_id, "agent-review")
    assert both["status"] == "exposed"


def test_mitigation_follows_the_sender_mode(neo4j_session, exported):
    value = labelled(exported, mode="require_approval")
    receipt = import_snapshot(neo4j_session, value, value["source"])
    detail, _ = flags(value, receipt.source_id, "agent-review", all_teams=True)
    assert detail["status"] == "mitigated", detail
    assert any(item["leg"] == "mitigation" for item in detail["evidence"])


def test_a_wildcard_grant_only_counts_bindings_in_the_viewer_scope(neo4j_session, exported):
    value = labelled(exported, child_wildcard=True)
    receipt = import_snapshot(neo4j_session, value, value["source"])
    visible, _ = flags(value, receipt.source_id, "agent-review", all_teams=True)
    assert visible["legs"]["privateData"] == "present"
    assert any(
        item["reason"] == "binding_restricted" and item["leg"] == "privateData"
        for item in visible["evidence"]
    )
    hidden, wire = flags(value, receipt.source_id, "agent-review", teams=("team-review",))
    assert hidden["legs"]["privateData"] == "unknown"
    for status in ("exposed", "mitigated", "unknown", "absent"):
        expected = {"agent-review"} if status == hidden["status"] else set()
        assert filtered(value, receipt.source_id, status, teams=("team-review",)) == expected
    assert filtered(value, receipt.source_id, visible["status"], all_teams=True) >= {"agent-review"}
    assert "binding_restricted" not in wire
    assert "prefix-binding" not in wire and "object-binding" not in wire


def test_an_ancestor_chain_through_another_team_stops_at_the_hidden_ancestor(
    neo4j_session, exported
):
    """research `grandchild` <- review `child` <- research `root`, and `root` allows no
    recipients. A research reader cannot see past `child`, so `grandchild`'s send leg is
    unknown in every read, with the scope note."""
    value = deepcopy(labelled(exported))
    root = next(task for task in value["tasks"] if task["id"] == "root")
    root["allowedRecipients"] = []
    child = next(task for task in value["tasks"] if task["id"] == "child")
    grandchild = deepcopy(child)
    grandchild.update(id="grandchild", parentTaskId="child")
    value["tasks"].append(grandchild)
    value["manifest"]["taskBindings"].append(
        {"taskId": "grandchild", "deploymentId": "deployment-static"}
    )
    value = validate_snapshot(value)
    receipt = import_snapshot(neo4j_session, value, value["source"])
    research = ("team-research",)
    detail, wire = flags(value, receipt.source_id, "agent-research", teams=research)
    assert detail["status"] == "unknown", detail
    assert detail["legs"]["externalSend"] == "unknown"
    assert "ancestor_evidence_outside_visible_scope" in detail["notes"]
    assert "agent-review" not in wire
    assert listed(value, receipt.source_id, teams=research) == {"agent-research": "unknown"}
    assert filtered(value, receipt.source_id, "unknown", teams=research) == {"agent-research"}
    # With both teams the chain is read in full: no scope note, and `root` (which also
    # grants an unregistered tool) keeps the agent unknown in every read alike.
    both, _ = flags(value, receipt.source_id, "agent-research")
    assert "ancestor_evidence_outside_visible_scope" not in both["notes"]
    assert both["status"] == listed(value, receipt.source_id)["agent-research"]
    assert "agent-research" in filtered(value, receipt.source_id, both["status"])
