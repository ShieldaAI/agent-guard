"""Closed source-transition input, safe CLI ordering and bounded retirement."""

import json
from copy import deepcopy
from hashlib import sha256

import pytest

from agent_guard_cartography import archive as archive_module
from agent_guard_cartography import lifecycle, publish
from agent_guard_cartography.graph import GraphImportError, source_key
from agent_guard_cartography.lifecycle import LifecycleError, transition_id, validate_transition


@pytest.fixture
def transition():
    source = {
        "companyId": "company",
        "sourceId": "executor",
        "tenantId": "tenant",
        "enrollmentGeneration": "before",
        "inventoryInstanceId": "ledger-before",
    }
    return {
        "schemaVersion": 1,
        "predecessor": source,
        "successor": {
            **source,
            "enrollmentGeneration": "after",
            "inventoryInstanceId": "ledger-after",
        },
        "profile": "core",
    }


def receipt(transition, timestamp=123):
    return {
        "schemaVersion": 1,
        "transitionId": transition_id(transition),
        "predecessorSourceId": source_key(transition["predecessor"]),
        "successorSourceId": source_key(transition["successor"]),
        "profile": transition["profile"],
        "supersededAtMs": timestamp,
    }


def test_transition_is_detached_canonical_and_preserves_explicit_generation(transition):
    checked = validate_transition(transition)
    assert checked == transition and checked is not transition
    assert checked["predecessor"] is not transition["predecessor"]
    expected = sha256(
        json.dumps(transition, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert transition_id(transition) == expected
    reordered = dict(reversed(list(transition.items())))
    reordered["predecessor"] = dict(reversed(list(transition["predecessor"].items())))
    assert transition_id(reordered) == expected
    transition["successor"]["inventoryInstanceId"] = "another-ledger"
    assert checked["successor"]["inventoryInstanceId"] == "ledger-after"
    assert transition_id(transition) != expected


@pytest.mark.parametrize("profile", ["core", "host", "host-mcp"])
def test_each_profile_and_retained_ledger_identity_is_supported(transition, profile):
    transition["profile"] = profile
    transition["successor"]["inventoryInstanceId"] = transition["predecessor"][
        "inventoryInstanceId"
    ]
    assert validate_transition(transition) == transition


@pytest.mark.parametrize("field", ["companyId", "sourceId", "tenantId"])
def test_transition_cannot_cross_installation_scope(transition, field):
    transition["successor"][field] = "foreign-canary"
    with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_SCOPE_MISMATCH$"):
        validate_transition(transition)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(schemaVersion=True),
        lambda value: value.update(schemaVersion=2),
        lambda value: value.update(profile="unknown"),
        lambda value: value.update(secret="private-canary"),
        lambda value: value.pop("profile"),
        lambda value: value.update(predecessor=[]),
        lambda value: value["successor"].update(secret="private-canary"),
        lambda value: value["successor"].pop("tenantId"),
        lambda value: value["successor"].update(enrollmentGeneration="before"),
        lambda value: value["successor"].update(inventoryInstanceId=""),
        lambda value: value["successor"].update(inventoryInstanceId="  "),
        lambda value: value["successor"].update(inventoryInstanceId="bad\x00value"),
        lambda value: value["successor"].update(inventoryInstanceId="\ud800"),
        lambda value: value["successor"].update(inventoryInstanceId="x" * 4097),
        lambda value: value["successor"].update(inventoryInstanceId=7),
    ],
)
def test_invalid_transitions_fail_with_safe_diagnostics(transition, mutate):
    mutate(transition)
    with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_INVALID$"):
        validate_transition(transition)


@pytest.mark.parametrize("blank", ["\ufeff", " \ufeff\t", "\ufeff\x1c\ufeff\x85\ufeff\n"])
@pytest.mark.parametrize("endpoint", ["predecessor", "successor"])
def test_transition_rejects_bom_only_source_identifiers(transition, blank, endpoint):
    for field in transition[endpoint]:
        value = deepcopy(transition)
        value[endpoint][field] = blank
        if field in ("companyId", "sourceId", "tenantId"):
            value["predecessor"][field] = value["successor"][field] = blank
        with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_INVALID$"):
            validate_transition(value)


def test_transition_preserves_nonblank_bom_source_identifiers(transition):
    for endpoint in ("predecessor", "successor"):
        transition[endpoint] = {
            key: f"\ufeff \n{value}\ufeff\x85" for key, value in transition[endpoint].items()
        }
    assert validate_transition(transition) == transition


@pytest.mark.parametrize("stamp", [True, -1, 1.5, "123", 253_402_300_800_000])
def test_timestamp_validation_precedes_any_graph_call(transition, stamp):
    with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_INVALID$"):
        lifecycle.supersede_source(None, transition, timestamp_ms=stamp)


@pytest.mark.parametrize(
    "contents",
    [b"\xff", b"[]", b'{"profile":"core","profile":"host"}', b"x" * (256 * 1024 + 1)],
)
def test_transition_file_is_bounded_strict_json(tmp_path, contents):
    path = tmp_path / "private-path-canary.json"
    path.write_bytes(contents)
    with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_INVALID$"):
        lifecycle.load_transition(path)


def test_transition_file_accepts_valid_utf8_without_widening_scope(tmp_path, transition):
    transition["successor"]["inventoryInstanceId"] = "ledger-😀"
    path = tmp_path / "transition.json"
    path.write_text(json.dumps(transition, ensure_ascii=False))
    assert lifecycle.load_transition(path) == transition


@pytest.mark.parametrize("failure", [None, "preflight", "evidence", "graph", "finish"])
def test_cli_preflights_then_journals_before_graph_and_finishes_after_commit(
    tmp_path, transition, monkeypatch, capsys, failure
):
    events = []
    result = receipt(transition)

    class Context:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def session(self, **_kwargs):
            return self

    class Archive(Context):
        def __init__(self, _path, **options):
            assert options == {"max_snapshots": 4096, "max_bytes": 256 * 1024 * 1024}

        def require_transition_evidence(self, value, *, projection_ids):
            assert value == transition and set(projection_ids) == {
                result["predecessorSourceId"],
                result["successorSourceId"],
            }
            events.append("evidence")
            if failure == "evidence":
                raise archive_module.ArchiveError("ARCHIVE_TRANSITION_EVIDENCE_MISSING")

        def stage_transition(self, value):
            assert value == transition
            events.append("stage")

        def finish_transition(self, value, graph_receipt):
            assert value == transition and graph_receipt == result
            events.append("finish")
            if failure == "finish":
                raise RuntimeError("private-diagnostic-canary")

    def preflight(_session, value):
        assert value == transition
        events.append("preflight")
        if failure == "preflight":
            raise LifecycleError("SOURCE_TRANSITION_SOURCE_MISSING")

    def supersede(_session, value):
        assert value == transition
        events.append("graph")
        if failure == "graph":
            raise RuntimeError("private-diagnostic-canary")
        return result

    monkeypatch.setattr(archive_module, "SnapshotArchive", Archive)
    monkeypatch.setattr(lifecycle.GraphDatabase, "driver", lambda *_a, **_k: Context())
    monkeypatch.setattr(lifecycle, "preflight_transition", preflight)
    monkeypatch.setattr(
        lifecycle,
        "_transition_projection_ids",
        lambda *_: {
            result["predecessorSourceId"]: "a" * 64,
            result["successorSourceId"]: "b" * 64,
        },
    )
    monkeypatch.setattr(lifecycle, "supersede_source", supersede)
    monkeypatch.setenv("TEST_LIFECYCLE_PASSWORD", "private-password-canary")
    path = tmp_path / "transition.json"
    path.write_text(json.dumps(transition))
    status = lifecycle.main(
        [
            "--transition",
            str(path),
            "--archive-dir",
            str(tmp_path / "archive"),
            "--neo4j-uri",
            "bolt://127.0.0.1:7687",
            "--neo4j-password-env-var",
            "TEST_LIFECYCLE_PASSWORD",
            "--lock-file",
            str(tmp_path / "lock"),
        ]
    )
    captured = capsys.readouterr()
    assert "private-" not in captured.out + captured.err
    if failure == "preflight":
        assert events == ["preflight"] and status == 2
    elif failure == "evidence":
        assert events == ["preflight", "evidence"] and status == 2
    elif failure == "graph":
        assert events == ["preflight", "evidence", "stage", "graph"] and status == 1
    else:
        assert events == ["preflight", "evidence", "stage", "graph", "finish"]
        assert status == (1 if failure else 0)
    if failure is None:
        assert json.loads(captured.out) == result


def test_superseded_maintenance_skips_pending_and_mismatched_graphs_and_caps_total(
    transition, monkeypatch
):
    records = []
    for index, status in enumerate(("pending", "complete", "complete", "complete", "complete")):
        value = deepcopy(transition)
        value["predecessor"]["enrollmentGeneration"] = f"generation-{index}"
        records.append({"status": status, "receipt": receipt(value)})
    queried, retired = [], []

    class Archive:
        def list_transitions(self):
            return records

    class Session:
        def run(self, _query, **parameters):
            queried.append(parameters["id"])
            self.parameters = parameters
            return self

        def single(self):
            return (
                None
                if self.parameters["id"] == records[1]["receipt"]["predecessorSourceId"]
                else {"id": self.parameters["id"]}
            )

    def retire(_session, source_id, **kwargs):
        retired.append((source_id, kwargs["limit"]))
        return min(2, kwargs["limit"])

    monkeypatch.setattr(publish, "retire_obsolete", retire)
    assert publish.retire_superseded(Session(), Archive(), limit=3) == 3
    assert len(queried) == 3
    assert [limit for _, limit in retired] == [3, 1]
    assert records[0]["receipt"]["predecessorSourceId"] not in queried


@pytest.mark.parametrize(
    "options", [{"limit": 0}, {"limit": 129}, {"minimum_retention_seconds": 59}]
)
def test_retirement_options_are_validated_before_archive_or_graph_access(options):
    with pytest.raises(GraphImportError, match="^RETENTION_INVALID$"):
        publish.retire_superseded(None, None, **options)
