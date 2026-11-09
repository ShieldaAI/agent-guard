import json
from pathlib import Path

from agent_guard_cartography.graph import import_snapshot

FIXTURES = Path(__file__).parents[1] / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_v2_outside_content_fields_are_projected(neo4j_session):
    snapshot = load("core-v2-boundaries.json")
    result = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    tools = {
        row["name"]: row
        for row in neo4j_session.run(
            "MATCH (t:GuardTool {projection_id:$id}) "
            "RETURN t.name AS name, t.reads_untrusted AS reads, t.sends_external AS sends, "
            "t.untrusted_context AS mode",
            id=result.projection_id,
        )
    }
    assert (tools["email.read"]["reads"], tools["email.read"]["sends"]) == (True, False)
    assert tools["email.send"]["mode"] == "require_approval"
    tasks = {
        row["id"]: row["untrusted"]
        for row in neo4j_session.run(
            "MATCH (t:GuardTask {projection_id:$id}) RETURN t.task_id AS id, t.untrusted AS untrusted",
            id=result.projection_id,
        )
    }
    assert tasks == {"reader": True, "clean": False}


def test_v1_imports_gain_no_outside_content_properties(neo4j_session):
    snapshot = load("alpha-v1.json")
    result = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    keys = neo4j_session.run(
        "MATCH (n {projection_id:$id}) WHERE n:GuardTool OR n:GuardTask "
        "UNWIND keys(n) AS key RETURN collect(DISTINCT key) AS keys",
        id=result.projection_id,
    ).single(strict=True)["keys"]
    assert not {"reads_untrusted", "sends_external", "untrusted_context", "untrusted"} & set(keys)
