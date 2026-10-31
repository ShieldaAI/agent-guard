"""Validate MCP evidence and bounded publication receipts independently of grants."""

import json
from copy import deepcopy

import pytest
from test_manifest import host_snapshot

from agent_guard_cartography.graph import (
    MAX_MCP_WATERMARK_BYTES,
    GraphImportError,
    _authority_hash,
    _check_component_versions,
    _manifest_properties,
    _mcp_properties,
    _next_mcp_watermarks,
    build_rows,
    source_key,
)
from agent_guard_cartography.inventory import (
    InventoryValidationError,
    validate_mcp_inventory,
    validate_snapshot,
)


def mcp_snapshot():
    snapshot = host_snapshot()
    snapshot["profile"] = "host-mcp"
    observed_at = "2026-10-30T00:00:00Z"
    snapshot["mcp"] = {
        "observedAt": observed_at,
        "connections": [
            {
                "connectionId": "mcp-ref",
                "status": "observed",
                "inventory": {
                    "schemaVersion": 1,
                    "identity": {
                        "serverId": "local-server",
                        "transportRef": "opaque:" + "a" * 64,
                        "principalId": "mcp-service-identity",
                        "tenantId": snapshot["source"]["tenantId"],
                    },
                    "sessionId": "local-session",
                    "revision": 5,
                    "authorizationEpoch": 2,
                    "metadataRevision": 1,
                    "state": "ready",
                    "metadataState": "current",
                    "observedAt": observed_at,
                    "operations": [
                        {"name": "records.read", "kind": "tool", "fingerprint": "1" * 64}
                    ],
                },
            }
        ],
    }
    snapshot["coverage"]["mcp"] = {"status": "complete", "observedAt": observed_at}
    return snapshot


def inventory(snapshot):
    return snapshot["mcp"]["connections"][0]["inventory"]


def component(snapshot):
    return {
        "profile": snapshot["profile"],
        **_manifest_properties(snapshot),
        **_mcp_properties(snapshot),
    }


def watermarks(snapshot):
    return {"mcp_watermarks_json": _next_mcp_watermarks({}, component(snapshot))}


def test_mcp_observations_are_detached_and_do_not_change_authority():
    incoming = mcp_snapshot()
    snapshot = validate_snapshot(incoming)
    assert snapshot == incoming
    inventory(incoming)["operations"].clear()
    assert inventory(snapshot)["operations"]
    assert _authority_hash(incoming) == _authority_hash(snapshot)
    assert inventory(snapshot)["identity"]["principalId"] != snapshot["tasks"][0]["principalId"]


@pytest.mark.parametrize("state", ["connecting", "refreshing", "quarantined", "closed"])
@pytest.mark.parametrize("metadata_revision", [0, 1, 20])
def test_nonready_lifecycle_is_observed_without_exposing_operations(state, metadata_revision):
    snapshot = mcp_snapshot()
    inventory(snapshot).update(
        state=state,
        metadataRevision=metadata_revision,
        metadataState="stale" if metadata_revision else "unobserved",
        operations=[],
    )
    assert validate_snapshot(snapshot)["coverage"]["mcp"]["status"] == "complete"


@pytest.mark.parametrize("kind", ["tool", "resource", "prompt"])
def test_all_local_mcp_operation_kinds_can_bind_to_registered_tools(kind):
    snapshot = mcp_snapshot()
    inventory(snapshot)["operations"][0]["kind"] = kind
    validate_snapshot(snapshot)


@pytest.mark.parametrize(
    "change",
    [
        lambda i: i.update(rawMetadata="private-canary"),
        lambda i: i["identity"].update(transportIdentity="private-canary"),
        lambda i: i["identity"].update(transportRef="https://private-canary"),
        lambda i: i["operations"][0].update(uri="private-canary"),
        lambda i: i["operations"][0].update(description="private-canary"),
        lambda i: i["operations"][0].update(remoteName="private-canary"),
        lambda i: i["operations"].append(deepcopy(i["operations"][0])),
        lambda i: i["operations"][0].update(kind="completion"),
        lambda i: i.update(state="closed"),
        lambda i: i.update(metadataRevision=0),
        lambda i: i.update(metadataState="stale"),
        lambda i: i.update(revision=-1),
        lambda i: i.update(authorizationEpoch=2**53),
        lambda i: i.update(sessionId="\x85\x1c"),
        lambda i: i.update(sessionId="\ud800"),
        lambda i: i.update(sessionId="x\x00y"),
        lambda i: i.update(observedAt="2026-02-30T00:00:00Z"),
        lambda i: i.update(
            operations=[
                {"name": f"op-{n}", "kind": "tool", "fingerprint": "a" * 64} for n in range(257)
            ]
        ),
    ],
)
def test_safe_connection_refuses_raw_metadata_inconsistent_lifecycle_and_unbounded_values(change):
    value = inventory(mcp_snapshot())
    change(value)
    with pytest.raises(InventoryValidationError) as error:
        validate_mcp_inventory(value)
    assert "private-canary" not in str(error.value)


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.update(profile="host"),
        lambda s: s.pop("manifest"),
        lambda s: s["manifest"]["source"].update(tenantId="foreign"),
        lambda s: s["manifest"]["executionBindings"][1].update(connectionId="different"),
        lambda s: s["mcp"]["connections"].clear(),
        lambda s: s["mcp"]["connections"].append(deepcopy(s["mcp"]["connections"][0])),
        lambda s: inventory(s)["identity"].update(tenantId="foreign"),
        lambda s: inventory(s)["operations"][0].update(name="records.delete", fingerprint="2" * 64),
        lambda s: inventory(s)["operations"][0].update(fingerprint="a" * 64),
        lambda s: s["tools"][0].update(registered=False),
        lambda s: s["coverage"]["mcp"].update(status="partial"),
        lambda s: s["coverage"]["mcp"].update(observedAt="2026-10-30T00:00:01Z"),
    ],
)
def test_composition_requires_manifest_scope_exact_connections_registered_fingerprints_and_coverage(
    change,
):
    snapshot = mcp_snapshot()
    change(snapshot)
    with pytest.raises(InventoryValidationError):
        validate_snapshot(snapshot)


def test_empty_partial_unavailable_and_removed_operations_are_explicit_valid_states():
    snapshot = mcp_snapshot()
    inventory(snapshot)["operations"] = []
    validate_snapshot(snapshot)
    snapshot["mcp"]["connections"] = [
        {"connectionId": "mcp-ref", "status": "unavailable", "reason": "changed"}
    ]
    snapshot["coverage"]["mcp"]["status"] = "unavailable"
    validate_snapshot(snapshot)
    snapshot["manifest"]["executionBindings"][0]["connectionId"] = "second"
    record = mcp_snapshot()["mcp"]["connections"][0]
    snapshot["mcp"]["connections"].append({**record, "connectionId": "second"})
    snapshot["coverage"]["mcp"]["status"] = "partial"
    validate_snapshot(snapshot)
    snapshot["manifest"]["executionBindings"] = []
    snapshot["mcp"]["connections"] = []
    snapshot["coverage"]["mcp"]["status"] = "complete"
    validate_snapshot(snapshot)


def test_graph_projects_explicit_paths_without_identity_or_authority_borrowing():
    snapshot = validate_snapshot(mcp_snapshot())
    rows = build_rows(snapshot, "projection", source_key(snapshot["source"]))
    (connection,) = rows["GuardMcpConnection"]
    (operation,) = rows["GuardMcpOperation"]
    binding = next(row for row in rows["GuardExecutionBinding"] if row["connection_id"])
    assert binding["connection_node_id"] == connection["id"]
    assert connection["operation_node_ids"] == [operation["id"]]
    assert operation["tool_node_id"] in {row["id"] for row in rows["GuardTool"]}
    assert connection["principal_id"] == "mcp-service-identity"
    assert "mcp-service-identity" not in {row["principal_id"] for row in rows["GuardPrincipal"]}
    assert connection["evidence_kind"] == operation["evidence_kind"] == "observed"
    assert connection["assessment"] == operation["assessment"] == "unknown"
    assert "approved" not in operation and "registered" not in operation
    host = host_snapshot()
    host_rows = build_rows(host, "host", source_key(host["source"]))
    assert not host_rows["GuardMcpConnection"] and not host_rows["GuardMcpOperation"]
    assert all(row["connection_node_id"] is None for row in host_rows["GuardExecutionBinding"])


def test_unavailable_projection_never_reuses_ready_identity_metadata_or_operations():
    snapshot = mcp_snapshot()
    snapshot["mcp"]["connections"] = [
        {"connectionId": "mcp-ref", "status": "unavailable", "reason": "capture_failed"}
    ]
    snapshot["coverage"]["mcp"]["status"] = "unavailable"
    rows = build_rows(validate_snapshot(snapshot), "next", source_key(snapshot["source"]))
    (connection,) = rows["GuardMcpConnection"]
    assert connection["capture_status"] == "unavailable"
    assert connection["unavailable_reason"] == "capture_failed"
    for field in (
        "state",
        "metadata_state",
        "metadata_revision",
        "session_id",
        "server_id",
        "principal_id",
        "revision",
    ):
        assert connection[field] is None
    assert not rows["GuardMcpOperation"]


def test_mcp_nodes_keep_source_identity_but_are_isolated_by_tenant_and_projection():
    snapshot = mcp_snapshot()
    first = build_rows(snapshot, "one", source_key(snapshot["source"]))
    second = build_rows(snapshot, "two", source_key(snapshot["source"]))
    other = deepcopy(snapshot)
    other["source"]["tenantId"] = "other-tenant"
    third = build_rows(other, "one", source_key(other["source"]))
    for label in ("GuardMcpConnection", "GuardMcpOperation"):
        assert first[label][0]["entity_id"] == second[label][0]["entity_id"]
        assert first[label][0]["id"] != second[label][0]["id"]
        assert first[label][0]["entity_id"] != third[label][0]["entity_id"]
        assert first[label][0]["id"] != third[label][0]["id"]


def test_connection_byte_limit_counts_unicode_encoding_before_graph_import():
    value = inventory(mcp_snapshot())
    value["operations"] = [
        {"name": f"{number}-" + "💾" * 4090, "kind": "tool", "fingerprint": "a" * 64}
        for number in range(256)
    ]
    with pytest.raises(InventoryValidationError, match="^INVENTORY_LIMIT_EXCEEDED$"):
        validate_mcp_inventory(value)


@pytest.mark.parametrize("field", ["revision", "authorizationEpoch", "metadataRevision"])
def test_mcp_counters_cannot_roll_back_within_a_session(field):
    snapshot = mcp_snapshot()
    current = watermarks(snapshot)
    inventory(snapshot)[field] -= 1
    with pytest.raises(GraphImportError, match="^MCP_REVISION_ROLLBACK$"):
        _next_mcp_watermarks(current, component(snapshot))


@pytest.mark.parametrize(
    "change",
    [
        lambda i: i.update(state="closed", metadataState="stale", operations=[]),
        lambda i: i["identity"].update(principalId="different-identity"),
        lambda i: i.update(authorizationEpoch=3),
        lambda i: i.update(metadataRevision=2),
        lambda i: i["operations"].clear(),
    ],
)
def test_equal_inventory_revision_rejects_changed_content(change):
    snapshot = mcp_snapshot()
    current = watermarks(snapshot)
    change(inventory(snapshot))
    with pytest.raises(GraphImportError, match="^MCP_REVISION_CONTENT_CONFLICT$"):
        _next_mcp_watermarks(current, component(snapshot))


def test_mcp_watermarks_ignore_capture_time_and_allow_manifest_exposure_changes():
    snapshot = mcp_snapshot()
    current = watermarks(snapshot)
    inventory(snapshot)["observedAt"] = "2026-10-30T00:00:01Z"
    assert _next_mcp_watermarks(current, component(snapshot)) == current["mcp_watermarks_json"]
    snapshot["manifest"]["revision"] += 1
    inventory(snapshot)["operations"].clear()
    _next_mcp_watermarks(current, component(snapshot))


def test_missing_capture_preserves_replay_receipts_and_new_session_resets_counters():
    snapshot = mcp_snapshot()
    current = watermarks(snapshot)
    missing = deepcopy(snapshot)
    missing["mcp"]["connections"] = [
        {"connectionId": "mcp-ref", "status": "unavailable", "reason": "missing"}
    ]
    missing["coverage"]["mcp"]["status"] = "unavailable"
    unavailable_receipts = _next_mcp_watermarks(current, component(validate_snapshot(missing)))
    assert unavailable_receipts == current["mcp_watermarks_json"]
    current = {"mcp_watermarks_json": unavailable_receipts}
    inventory(snapshot).update(
        sessionId="new-local-session",
        revision=0,
        authorizationEpoch=0,
        metadataRevision=0,
        state="connecting",
        metadataState="unobserved",
        operations=[],
    )
    next_watermarks = _next_mcp_watermarks(current, component(validate_snapshot(snapshot)))
    with pytest.raises(GraphImportError, match="^MCP_SESSION_REPLAY$"):
        _next_mcp_watermarks({"mcp_watermarks_json": next_watermarks}, component(mcp_snapshot()))


def test_retired_sessions_and_removed_connection_ids_have_bounded_receipts():
    snapshot = mcp_snapshot()
    current = watermarks(snapshot)
    for number in range(64):
        inventory(snapshot)["sessionId"] = f"new-session-{number}"
        current = {"mcp_watermarks_json": _next_mcp_watermarks(current, component(snapshot))}
    inventory(snapshot)["sessionId"] = "one-too-many"
    with pytest.raises(GraphImportError, match="^MCP_ENROLLMENT_ROTATION_REQUIRED$"):
        _next_mcp_watermarks(current, component(snapshot))
    missing = mcp_snapshot()
    missing["mcp"]["connections"] = []
    current = {}
    for number in range(128):
        missing["mcp"]["connections"] = [
            {"connectionId": f"connection-{number}", "status": "unavailable", "reason": "missing"}
        ]
        current = {"mcp_watermarks_json": _next_mcp_watermarks(current, component(missing))}
    missing["mcp"]["connections"][0]["connectionId"] = "one-too-many"
    with pytest.raises(GraphImportError, match="^MCP_ENROLLMENT_ROTATION_REQUIRED$"):
        _next_mcp_watermarks(current, component(missing))
    assert len(json.loads(current["mcp_watermarks_json"])) == 128
    assert len(current["mcp_watermarks_json"].encode()) < MAX_MCP_WATERMARK_BYTES


def test_host_mcp_profile_keeps_manifest_revision_checks_and_profile_pin():
    current = component(mcp_snapshot())
    candidate = dict(current)
    candidate["manifest_revision"] = 0
    with pytest.raises(GraphImportError, match="^MANIFEST_REVISION_ROLLBACK$"):
        _check_component_versions(current, candidate)
    candidate = {**current, "profile": "host"}
    with pytest.raises(GraphImportError, match="^PROFILE_CONFLICT$"):
        _check_component_versions(current, candidate)
