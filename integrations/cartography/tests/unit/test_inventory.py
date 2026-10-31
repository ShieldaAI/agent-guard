from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.inventory import (
    MAX_JSON_DEPTH,
    MAX_SNAPSHOT_BYTES,
    InventoryValidationError,
    load_snapshot,
    validate_snapshot,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def snapshot():
    return json.loads((FIXTURES / "alpha-v1.json").read_text())


@pytest.mark.parametrize("name", ["alpha-v1.json", "alpha-v2.json", "beta-v1.json"])
def test_fixtures_validate(name):
    assert load_snapshot(FIXTURES / name)["profile"] == "core"


def test_result_is_detached(snapshot):
    validated = validate_snapshot(snapshot)
    snapshot["tasks"][0]["grants"][0]["resources"].append("changed")
    assert "changed" not in validated["tasks"][0]["grants"][0]["resources"]
    validated["tools"][0]["name"] = "another-change"
    assert snapshot["tools"][0]["name"] == "records.read"


@pytest.mark.parametrize("location", ["envelope", "task", "tool", "source", "grant"])
def test_unlisted_secret_fields_are_rejected_without_echo(snapshot, location):
    containers = {
        "envelope": snapshot,
        "task": snapshot["tasks"][0],
        "tool": snapshot["tools"][0],
        "source": snapshot["source"],
        "grant": snapshot["tasks"][0]["grants"][0],
    }
    containers[location]["canary-secret-key"] = "canary-secret-value"
    with pytest.raises(InventoryValidationError) as caught:
        validate_snapshot(snapshot)
    assert str(caught.value) == "INVENTORY_SCHEMA_INVALID"
    assert "canary" not in repr(caught.value)


@pytest.mark.parametrize(
    "field,value", [("schemaVersion", 2), ("schemaVersion", True), ("profile", "full")]
)
def test_unsupported_version_or_profile(snapshot, field, value):
    snapshot[field] = value
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


@pytest.mark.parametrize("value", [9007199254740992, -1, 1.5, True])
def test_revisions_are_nonnegative_js_safe_integers(snapshot, value):
    snapshot["ledgerRevision"] = value
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


def test_fractional_deadline_preserved(snapshot):
    snapshot["tasks"][0]["budget"]["deadline"] += 0.5
    assert validate_snapshot(snapshot)["tasks"][0]["budget"]["deadline"] % 1 == 0.5


@pytest.mark.parametrize(
    "value", ["not-a-time", "2026-99-99T00:00:00Z", "2026-10-29T00:00:00+01:00"]
)
def test_timestamps_are_valid_utc(snapshot, value):
    snapshot["generatedAt"] = value
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


@pytest.mark.parametrize("value", ["", "  ", "bad\x00id"])
def test_identifiers_are_bounded_nonempty_and_no_nul(snapshot, value):
    snapshot["source"]["sourceId"] = value
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


def test_cross_tenant_task_rejected(snapshot):
    snapshot["tasks"][0]["tenantId"] = "beta"
    with pytest.raises(InventoryValidationError, match="INVENTORY_TENANT_MISMATCH"):
        validate_snapshot(snapshot)


@pytest.mark.parametrize("collection", ["tasks", "tools"])
def test_duplicate_entity_ids_rejected(snapshot, collection):
    snapshot[collection].append(deepcopy(snapshot[collection][0]))
    with pytest.raises(InventoryValidationError, match="INVENTORY_DUPLICATE_ID"):
        validate_snapshot(snapshot)


def test_grants_are_normalized_by_tool(snapshot):
    snapshot["tasks"][0]["grants"].append({"tool": "records.read", "resources": ["report-C"]})
    with pytest.raises(InventoryValidationError, match="INVENTORY_DUPLICATE_GRANT"):
        validate_snapshot(snapshot)


def test_grant_to_unregistered_tool_stays_valid(snapshot):
    snapshot["tasks"][0]["grants"].append({"tool": "future-tool", "resources": ["*"]})
    validated = validate_snapshot(snapshot)
    assert validated["tasks"][0]["grants"][-1] == {"tool": "future-tool", "resources": ["*"]}


@pytest.mark.parametrize("field", ["parentTaskId", "sourceTaskId"])
def test_missing_task_reference_rejected(snapshot, field):
    snapshot["tasks"][1][field] = "absent"
    with pytest.raises(InventoryValidationError, match="INVENTORY_REFERENCE_INVALID"):
        validate_snapshot(snapshot)


@pytest.mark.parametrize("field", ["parentTaskId", "sourceTaskId"])
def test_self_reference_rejected(snapshot, field):
    snapshot["tasks"][0][field] = "research-root"
    with pytest.raises(InventoryValidationError, match="INVENTORY_REFERENCE_CYCLE"):
        validate_snapshot(snapshot)


def test_mixed_provenance_delegation_cycle_rejected(snapshot):
    snapshot["tasks"][0]["sourceTaskId"] = "review-child"
    with pytest.raises(InventoryValidationError, match="INVENTORY_REFERENCE_CYCLE"):
        validate_snapshot(snapshot)


def test_diamond_graph_is_not_a_cycle(snapshot):
    snapshot["tasks"][2]["sourceTaskId"] = "review-child"
    fourth = deepcopy(snapshot["tasks"][2])
    fourth.update(id="fourth", parentTaskId="handoff-task", sourceTaskId="research-root")
    snapshot["tasks"].append(fourth)
    assert len(validate_snapshot(snapshot)["tasks"]) == 4


def test_delegation_cannot_change_principal(snapshot):
    snapshot["tasks"][1]["principalId"] = "different"
    with pytest.raises(InventoryValidationError, match="INVENTORY_PRINCIPAL_INVALID"):
        validate_snapshot(snapshot)


def test_provenance_does_not_require_same_principal_or_grants(snapshot):
    validated = validate_snapshot(snapshot)
    assert validated["tasks"][2]["principalId"] != validated["tasks"][0]["principalId"]
    assert validated["tasks"][2]["grants"][0]["tool"] == "outbound.send"


@pytest.mark.parametrize("field,value", [("familyId", "other-family"), ("sensitive", True)])
def test_shared_family_consistency(snapshot, field, value):
    snapshot["tasks"][1][field] = value
    with pytest.raises(InventoryValidationError, match="INVENTORY_FAMILY_INVALID"):
        validate_snapshot(snapshot)


def test_unregistered_tool_flags_are_unknown(snapshot):
    tool = snapshot["tools"][0]
    tool.update(
        registered=False, approved=False, requiresApproval=None, controlPlane=None, maxCost=None
    )
    assert validate_snapshot(snapshot)["tools"][0]["requiresApproval"] is None
    tool["requiresApproval"] = False
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


def test_registered_tool_flags_must_be_known(snapshot):
    snapshot["tools"][0]["requiresApproval"] = None
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


def test_mandatory_component_must_be_complete(snapshot):
    snapshot["coverage"]["tasks"]["status"] = "unavailable"
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


def test_optional_component_can_be_unavailable_without_blocking_tasks(snapshot):
    snapshot["coverage"]["mcp"]["status"] = "unavailable"
    assert validate_snapshot(snapshot)["coverage"]["tasks"]["status"] == "complete"
    snapshot["mcpConnections"] = [{"status": "ready"}]
    with pytest.raises(InventoryValidationError, match="INVENTORY_SCHEMA_INVALID"):
        validate_snapshot(snapshot)


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}'])
def test_duplicate_json_keys_rejected_before_validation(tmp_path, text):
    path = tmp_path / "snapshot.json"
    path.write_text(text)
    with pytest.raises(InventoryValidationError, match="INVENTORY_DUPLICATE_KEY"):
        load_snapshot(path)


@pytest.mark.parametrize(
    "text", ['{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e999}', '{"x":', '"\ud800"']
)
def test_malformed_nonfinite_or_invalid_unicode_json(tmp_path, text):
    path = tmp_path / "snapshot.json"
    path.write_bytes(text.encode("utf-8", errors="surrogatepass"))
    with pytest.raises(InventoryValidationError, match="INVENTORY_JSON_INVALID"):
        load_snapshot(path)


def test_oversized_file_is_bounded(tmp_path):
    path = tmp_path / "snapshot.json"
    with path.open("wb") as stream:
        stream.truncate(MAX_SNAPSHOT_BYTES + 1)
    with pytest.raises(InventoryValidationError, match="INVENTORY_LIMIT_EXCEEDED"):
        load_snapshot(path)


def test_nested_input_is_bounded():
    value = []
    for _ in range(MAX_JSON_DEPTH + 1):
        value = [value]
    with pytest.raises(InventoryValidationError, match="INVENTORY_LIMIT_EXCEEDED"):
        validate_snapshot(value)


def test_cyclic_python_input_is_rejected():
    value = []
    value.append(value)
    with pytest.raises(InventoryValidationError, match="INVENTORY_JSON_INVALID"):
        validate_snapshot(value)


def test_large_python_strings_are_bounded_before_serialization():
    with pytest.raises(InventoryValidationError, match="INVENTORY_LIMIT_EXCEEDED"):
        validate_snapshot({"value": "x" * (MAX_SNAPSHOT_BYTES + 1)})


def test_aggregate_utf8_bytes_are_bounded_before_serialization():
    value = {
        "first": "\u00e9" * (MAX_SNAPSHOT_BYTES // 4),
        "second": "\u00e9" * (MAX_SNAPSHOT_BYTES // 4),
    }
    with pytest.raises(InventoryValidationError, match="INVENTORY_LIMIT_EXCEEDED"):
        validate_snapshot(value)


def test_large_keys_are_bounded_before_serialization():
    with pytest.raises(InventoryValidationError, match="INVENTORY_LIMIT_EXCEEDED"):
        validate_snapshot({"x" * (MAX_SNAPSHOT_BYTES + 1): None})


@pytest.mark.parametrize("value", [({"x": 1},), {1: "a"}, {"value": float("nan")}])
def test_non_json_python_input_is_rejected(value):
    with pytest.raises(InventoryValidationError, match="INVENTORY_JSON_INVALID"):
        validate_snapshot(value)


def test_file_error_does_not_echo_path(tmp_path):
    with pytest.raises(InventoryValidationError) as caught:
        load_snapshot(tmp_path / "secret-file-name.json")
    assert str(caught.value) == "INVENTORY_READ_FAILED"
