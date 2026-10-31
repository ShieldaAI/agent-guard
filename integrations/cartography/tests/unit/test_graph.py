from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.cli import _validate_uri, build_sync, ingestion_lock
from agent_guard_cartography.graph import GraphImportError, build_rows, source_key
from agent_guard_cartography.inventory import load_snapshot

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_local_selectors_do_not_expand_to_cloud_permissions():
    snapshot = load_snapshot(FIXTURES / "alpha-v1.json")
    snapshot["tasks"][0]["grants"][0]["resources"] = ["*"]
    rows = build_rows(snapshot, "projection", source_key(snapshot["source"]))
    wildcard = [row for row in rows["GuardResource"] if row["resource_id"] == "*"]
    assert len(wildcard) == 1
    assert wildcard[0]["selector_kind"] == "wildcard"
    assert all(row["assessment"] == "unknown" for row in rows["GuardGrant"])
    assert all(label.startswith("Guard") for label in rows)


def test_shared_native_ids_do_not_merge_tenant_or_projection_identity():
    first = load_snapshot(FIXTURES / "alpha-v1.json")
    other = deepcopy(first)
    other["source"]["tenantId"] = "another-tenant"
    source1, source2 = source_key(first["source"]), source_key(other["source"])
    a = build_rows(first, "projection1", source1)
    b = build_rows(other, "projection1", source2)
    c = build_rows(first, "projection2", source1)
    assert source1 != source2
    for label in a:
        assert {x["id"] for x in a[label]}.isdisjoint(x["id"] for x in b[label])
        assert {x["id"] for x in a[label]}.isdisjoint(x["id"] for x in c[label])
        assert {x["entity_id"] for x in a[label]} == {x["entity_id"] for x in c[label]}


def test_configured_scope_mismatch_rejected_before_stage_construction():
    snapshot = load_snapshot(FIXTURES / "alpha-v1.json")
    source = {**snapshot["source"], "tenantId": "different"}
    with pytest.raises(GraphImportError, match="^SOURCE_SCOPE_MISMATCH$"):
        build_sync(snapshot, source)


def test_custom_sync_contains_only_agent_guard_stage():
    snapshot = load_snapshot(FIXTURES / "alpha-v1.json")
    sync = build_sync(snapshot, snapshot["source"])
    assert list(sync._stages) == ["agent_guard"]


def test_one_host_worker_lock_rejects_overlap_and_allows_reopen(tmp_path):
    lock = tmp_path / "ingest.lock"
    with ingestion_lock(lock):
        with pytest.raises(GraphImportError, match="^INGESTION_ALREADY_RUNNING$"):
            with ingestion_lock(lock):
                pytest.fail("The second worker acquired the lock")
    with ingestion_lock(lock):
        assert lock.exists()


@pytest.mark.parametrize(
    "uri",
    [
        "bolt://127.0.0.1:7687",
        "bolt://[::1]:7687",
        "neo4j+s://graph.example.com:7687",
        "bolt+s://graph.example.com",
    ],
)
def test_database_uri_accepts_loopback_or_verified_tls(uri):
    _validate_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "bolt://graph.example.com:7687",
        "neo4j://192.0.2.1:7687",
        "neo4j://127.0.0.1:7687",
        "neo4j://localhost:7687",
        "bolt://localhost:7687",
        "bolt+ssc://graph.example.com",
        "neo4j+ssc://graph.example.com",
        "bolt://user:password@localhost:7687",
        "bolt://localhost:7687?x=1",
        "bolt://localhost:7687#fragment",
        "bolt://localhost:7687/database",
        "bolt://localhost:0",
        "bolt://localhost:65536",
        "http://localhost:7687",
        "bolt://localhost:invalid",
        "bolt://",
        "bolt://[broken",
    ],
)
def test_database_uri_rejects_unsafe_or_malformed_configuration(uri):
    with pytest.raises(GraphImportError, match="^NEO4J_URI_INVALID$"):
        _validate_uri(uri)
