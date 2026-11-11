"""Neo4j query plans for the Map store's boundary reads: bounded, indexed, no cartesian joins.

The bridge records the exact Cypher and parameters the store runs for a read and asks
Neo4j to EXPLAIN each one, so these checks follow the templates as they change.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from test_discovery_queries import publish as publish_discovery
from test_identity_scope_queries import broad, publish
from test_reference_queries import reference_snapshot as reference_snapshot  # noqa: F401
from test_reference_queries import scope

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]
BRIDGE = Path(__file__).parents[1] / "fixtures" / "explain-agent-map.mjs"
FORBIDDEN = {"CartesianProduct", "AllNodesScan"}


def explain(case, request, *, all_teams=False, one_source=True):
    result = subprocess.run(
        [shutil.which("node"), str(BRIDGE)],
        input=json.dumps(
            {
                "scope": scope(case["snapshot"], all_teams=all_teams),
                "request": {
                    **({"sourceId": case["receipt"].source_id} if one_source else {}),
                    **request,
                },
                "now": int(time.time()) * 1000,
            }
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    password = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())["password"]
    assert password not in result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert output["ok"] is True, output
    return output["plans"]


@pytest.fixture
def case(neo4j_session, reference_snapshot):
    return publish(
        neo4j_session,
        reference_snapshot,
        broad,
        hidden_statements=broad,
        wildcard_tool="records.list",
        # Keep the hidden root so the ancestor queries have work to plan.
        own_root=False,
    )


@pytest.mark.parametrize(
    ("request_", "all_teams"),
    [
        ({"agentId": "visible-agent", "boundary": True}, False),
        ({"agentId": "visible-agent", "boundary": True}, True),
        ({"agentId": "visible-agent"}, False),
        ({"agentId": "visible-agent"}, True),
        ({"outsideGuard": True}, False),
        ({"outsideGuard": True}, True),
        ({"flags": True}, False),
        ({"flags": True}, True),
        ({"flags": True, "agentIds": ["visible-agent"]}, False),
        ({"flags": True, "agentIds": ["visible-agent"]}, True),
        ({"summary": True}, False),
        ({"summary": True}, True),
        ({"history": True}, False),
        ({"history": True}, True),
    ],
)
def test_boundary_reads_have_no_cartesian_product_or_all_nodes_scan(case, request_, all_teams):
    plans = explain(case, request_, all_teams=all_teams)
    assert plans
    for plan in plans:
        assert not FORBIDDEN & set(plan["operators"]), plan


def test_the_reverse_identity_query_runs_and_seeks_the_identity_by_its_unique_id(case):
    for request_ in ({"agentId": "visible-agent", "boundary": True}, {"outsideGuard": True}):
        plans = [
            plan
            for plan in explain(case, request_, all_teams=True)
            if plan["kind"] == "identity_scope"
        ]
        # The read runs it twice: once for the answer, once after the publication recheck.
        assert len(plans) == 2, request_
        for plan in plans:
            assert "NodeUniqueIndexSeek" in plan["operators"], plan


def test_a_flags_read_skips_policy_and_identity_queries(case):
    kinds = {plan["kind"] for plan in explain(case, {"flags": True})}
    assert not {"policy", "identity_scope"} & kinds
    assert {"GuardTask", "GuardResourceBinding"} <= kinds


def test_an_inventory_read_skips_boundary_queries(case):
    """get_agent_inventory reads one agent without ancestors or identity scope."""
    kinds = {plan["kind"] for plan in explain(case, {"agentId": "visible-agent"})}
    assert "identity_scope" not in kinds
    heads = [plan["head"] for plan in explain(case, {"agentId": "visible-agent"})]
    assert not any("G_DELEGATED_FROM|G_DERIVED_FROM*1..16" in head for head in heads)


def test_boundary_reads_plan_the_wildcard_and_ancestor_queries(case):
    for all_teams in (False, True):
        for request_ in (
            {"agentId": "visible-agent", "boundary": True},
            {"flags": True, "agentIds": ["visible-agent"]},
        ):
            kinds = {plan["kind"] for plan in explain(case, request_, all_teams=all_teams)}
            assert {"wildcard", "ancestors"} <= kinds, (request_, all_teams, kinds)
            if all_teams:
                # The hidden root is in scope here, so its record and edges are read too.
                assert "ancestor_tasks" in kinds


@pytest.mark.parametrize(
    ("request_", "page"),
    [
        ({"undeclared": True}, None),
        ({"undeclared": True, "page": {"kind": "tasks", "offset": 0, "limit": 50}}, "tasks"),
        (
            {"undeclared": True, "page": {"kind": "principals", "offset": 20, "limit": 100}},
            "principals",
        ),
    ],
)
def test_undeclared_activity_reads_start_at_the_snapshot_and_load_no_nodes(case, request_, page):
    plans = explain(case, request_, all_teams=True)
    kinds = [plan["kind"] for plan in plans]
    # Counts and at most one page; none of the per-label node queries of the other reads.
    assert sorted(set(kinds) - {"other"}) == sorted(
        ["undeclared_counts", *([f"undeclared_{page}"] if page else [])]
    )
    for plan in plans:
        assert not FORBIDDEN & set(plan["operators"]), plan
        if plan["kind"].startswith("undeclared"):
            # Bounded by one projection: the snapshot is found by its unique id.
            assert "NodeUniqueIndexSeek" in plan["operators"], plan


def test_unclaimed_identity_reads_have_no_cartesian_product_or_all_nodes_scan(
    neo4j_session, reference_snapshot
):
    # An account with identities nobody declared, so the page query runs too.
    plans = explain(
        publish_discovery(neo4j_session, reference_snapshot),
        {"unclaimedIdentities": True, "page": {"offset": 0, "limit": 100}},
        all_teams=True,
        one_source=False,
    )
    kinds = [plan["kind"] for plan in plans]
    assert {"claimed_identities", "unclaimed_counts", "unclaimed_page"} <= set(kinds)
    # The collections are read twice: for the answer, and for the recheck after it.
    assert kinds.count("aws_collections") == 2
    for plan in plans:
        assert not FORBIDDEN & set(plan["operators"]), plan
