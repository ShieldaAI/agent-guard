import pytest

from agent_guard_cartography.graph import import_snapshot

pytestmark = pytest.mark.integration


def test_v2_outside_content_fields_are_projected(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory("core-v2-boundaries")
    result = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    tools = {
        row["name"]: row
        for row in neo4j_session.run(
            "MATCH (t:GuardTool {projection_id:$id}) "
            "RETURN t.name AS name, t.reads_untrusted AS reads, t.sends_external AS sends, "
            "t.untrusted_context AS mode, t.untrusted_context_default AS default",
            id=result.projection_id,
        )
    }
    assert (tools["email.read"]["reads"], tools["email.read"]["sends"]) == (True, False)
    assert tools["email.send"]["mode"] == "require_approval"
    assert {row["default"] for row in tools.values()} == {"allow"}
    tasks = {
        row["id"]: row["untrusted"]
        for row in neo4j_session.run(
            "MATCH (t:GuardTask {projection_id:$id}) RETURN t.task_id AS id, t.untrusted AS untrusted",
            id=result.projection_id,
        )
    }
    assert tasks == {"reader": True, "clean": False}


def test_v1_imports_gain_no_outside_content_properties(neo4j_session, snapshot_factory):
    snapshot = snapshot_factory()
    result = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    keys = neo4j_session.run(
        "MATCH (n {projection_id:$id}) WHERE n:GuardTool OR n:GuardTask "
        "UNWIND keys(n) AS key RETURN collect(DISTINCT key) AS keys",
        id=result.projection_id,
    ).single(strict=True)["keys"]
    assert not {
        "reads_untrusted",
        "sends_external",
        "untrusted_context",
        "untrusted_context_default",
        "untrusted",
    } & set(keys)
