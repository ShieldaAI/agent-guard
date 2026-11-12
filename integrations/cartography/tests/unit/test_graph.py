from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography import graph
from agent_guard_cartography._command import ingestion_lock
from agent_guard_cartography._command import validate_neo4j_uri as _validate_uri
from agent_guard_cartography.cli import build_sync
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


class Rows(list):
    def single(self):
        return self[0] if self else None

    def consume(self):
        return None


class PublishedSource:
    """The source row and current projection a publication transaction would see."""

    def __init__(self, snapshot, generated_at):
        self.created = []
        self.generated_at = generated_at
        self.source = {
            "id": source_key(snapshot["source"]),
            "profile": snapshot["profile"],
            "ledger_revision": snapshot["ledgerRevision"],
            "policy_epoch": snapshot["policyEpoch"],
            "authority_hash": graph._authority_hash(snapshot),
            "current_snapshot_id": "c" * 64,
        }

    def run(self, query, **parameters):
        if query.startswith("MERGE (s:GuardSource"):
            return Rows()
        if "lock_revision" in query:
            return Rows([{"s": self.source}])
        if "snapshot_id:$snapshot_id" in query:
            return Rows()
        if "RETURN p.generated_at" in query:
            assert parameters == {"id": "c" * 64, "source_id": self.source["id"]}
            assert not any(word in query for word in ("SET", "CREATE", "MERGE", "DELETE"))
            return Rows([{"generated_at": self.generated_at}] if self.generated_at else [])
        assert "CREATE (p:GuardSnapshot" in query
        self.created.append(parameters["properties"])
        return Rows()


def begin(tx, snapshot):
    return graph._begin(
        tx,
        snapshot,
        source_key(snapshot["source"]),
        "d" * 64,
        "e" * 64,
        graph._authority_hash(snapshot),
        1,
    )


@pytest.mark.parametrize(
    "published,candidate,accepted",
    [
        ("2026-10-29T12:05:00Z", "2026-10-29T12:00:00Z", False),
        # Variable fractional digits must compare as instants, not as text.
        ("2026-10-29T12:00:00.5Z", "2026-10-29T12:00:00Z", False),
        ("2026-10-29T12:00:00Z", "2026-10-29T12:00:00.5Z", True),
        ("2026-10-29T12:00:00Z", "2026-10-29T12:00:00Z", True),
        ("2026-10-29T12:00:00Z", "2026-10-29T12:05:00Z", True),
        # A projection written before this field was recorded cannot be compared.
        (None, "2026-10-29T12:00:00Z", True),
    ],
)
def test_older_capture_cannot_replace_a_newer_one_at_the_same_revision(
    published, candidate, accepted
):
    snapshot = load_snapshot(FIXTURES / "alpha-v1.json")
    snapshot["snapshotId"] = "replayed-capture"
    snapshot["generatedAt"] = candidate
    tx = PublishedSource(snapshot, published)
    if accepted:
        assert begin(tx, snapshot) == ("c" * 64, None)
        assert [row["generated_at"] for row in tx.created] == [candidate]
    else:
        with pytest.raises(GraphImportError, match="^GENERATED_AT_ROLLBACK$"):
            begin(tx, snapshot)
        assert tx.created == []


def test_newer_revision_is_not_held_back_by_capture_time():
    snapshot = load_snapshot(FIXTURES / "alpha-v1.json")
    tx = PublishedSource(snapshot, "2030-01-01T00:00:00Z")
    snapshot["ledgerRevision"] += 1
    snapshot["snapshotId"] = "next-revision"
    assert begin(tx, snapshot) == ("c" * 64, None)
    assert len(tx.created) == 1


def test_missing_lock_directory_has_its_own_code(tmp_path):
    with pytest.raises(GraphImportError, match="^PROCESS_LOCK_PATH_INVALID$"):
        with ingestion_lock(tmp_path / "missing" / "ingest.lock"):
            pytest.fail("A lock was taken on a path that does not exist")
