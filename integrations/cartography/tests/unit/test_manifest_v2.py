"""Versioned host assertions remain bounded observations, never authority."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.cloud import (
    collect_cloud,
    provider_target,
    unavailable_cloud,
    validate_cloud_scope,
)
from agent_guard_cartography.graph import (
    GraphImportError,
    _authority_hash,
    _check_component_versions,
    _manifest_hash,
    _manifest_properties,
    build_rows,
    source_key,
)
from agent_guard_cartography.inventory import (
    InventoryValidationError,
    validate_manifest,
    validate_snapshot,
)
from agent_guard_cartography.models import SCHEMAS
from agent_guard_cartography.reference_report import minimize_changes


def host_v2():
    return json.loads((Path(__file__).parents[1] / "fixtures" / "host-v2.json").read_text())


def test_v2_snapshot_detaches_all_metadata_and_preserves_core_authority():
    incoming = host_v2()
    original = deepcopy(incoming)
    validated = validate_snapshot(incoming)
    incoming["manifest"]["owners"][0]["name"] = "mutated"
    incoming["manifest"]["credentialReferences"][0]["audienceRefs"].clear()
    assert validated == original
    assert _authority_hash(validated) == _authority_hash({**validated, "manifest": {}})
    assert (
        validated["coverage"]["tasks"]["observedAt"]
        != validated["coverage"]["manifest"]["observedAt"]
    )


def test_schema_version_uses_json_integer_semantics_without_accepting_booleans():
    value = host_v2()["manifest"]
    value["schemaVersion"] = 2.0
    assert validate_manifest(value)["schemaVersion"] == 2
    value["schemaVersion"] = True
    with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
        validate_manifest(value)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m.update(schemaVersion=True),
        lambda m: m.update(schemaVersion=3),
        lambda m: m.update(token="secret-canary"),
        lambda m: m.pop("authorityId"),
        lambda m: m["owners"].append(deepcopy(m["owners"][0])),
        lambda m: m["credentialReferences"].append(deepcopy(m["credentialReferences"][0])),
        lambda m: m["credentialReferences"][0].update(secret="secret-canary"),
        lambda m: m["credentialReferences"][0].update(
            id="https://user:secret-canary@example.invalid"
        ),
        lambda m: m["credentialReferences"][0].update(issuerRef="opaque:" + "A" * 64),
        lambda m: m["credentialReferences"][0].update(expiresAt="2026-02-30T00:00:00Z"),
        lambda m: m["credentialReferences"][0]["recipientRefs"].append(
            m["credentialReferences"][0]["recipientRefs"][0]
        ),
        lambda m: m["deployments"][0].update(credentialReferenceIds=["opaque:" + "0" * 64]),
        lambda m: m["deployments"][0]["credentialReferenceIds"].append(
            m["deployments"][0]["credentialReferenceIds"][0]
        ),
        lambda m: m["agents"][0].update(ownerId="missing"),
        lambda m: m["agents"][0].update(ownerId=None),
        lambda m: m["agents"][0].update(ownershipStatus="unknown"),
        lambda m: m["agents"][0].update(ownershipStatus="unassigned"),
        lambda m: m["resourceBindings"][0].update(ownerId="missing"),
        lambda m: m["resourceBindings"][0].update(dependsOn=["missing"]),
        lambda m: m["resourceBindings"][0].update(dependsOn=["report"]),
        lambda m: m["resourceBindings"][0].update(dependsOn=["company-database"] * 2),
        lambda m: m["resourceBindings"][0].update(approvedDestinations=["https://example.invalid"]),
        lambda m: m["resourceBindings"][1]["target"].update(id="opaque:" + "a" * 63),
        lambda m: m["resourceBindings"][1]["target"].update(id="opaque:" + "a" * 64 + "\n"),
        lambda m: m["resourceBindings"][1]["target"].update(
            url="https://user:secret-canary@example.invalid"
        ),
        lambda m: m["resourceBindings"][1].update(actions=[]),
    ],
)
def test_v2_rejects_unknown_fields_invalid_ownership_references_and_credentials(mutation):
    candidate = host_v2()["manifest"]
    mutation(candidate)
    with pytest.raises(InventoryValidationError) as error:
        validate_manifest(candidate)
    assert str(error.value) == error.value.code
    assert "secret-canary" not in str(error.value)


@pytest.mark.parametrize("field,maximum", [("name", 256), ("purpose", 1024)])
def test_v2_display_bounds_count_unicode_scalars(field, maximum):
    candidate = host_v2()["manifest"]
    candidate["agents"][0][field] = "😀" * maximum
    assert validate_manifest(candidate) == candidate
    candidate["agents"][0][field] += "😀"
    with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
        validate_manifest(candidate)


def test_v2_catalog_and_reference_limits_fail_entire_manifest():
    original = host_v2()["manifest"]
    for candidate in [
        {
            **original,
            "owners": [{"id": f"owner-{i}", "name": "Owner", "kind": "team"} for i in range(1001)],
        },
        {
            **original,
            "credentialReferences": [
                dict(original["credentialReferences"][0], id="opaque:" + f"{i:064x}")
                for i in range(1001)
            ],
        },
    ]:
        with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
            validate_manifest(candidate)
    candidate = deepcopy(original)
    candidate["credentialReferences"][0]["audienceRefs"] = [
        "opaque:" + f"{i:064x}" for i in range(129)
    ]
    with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
        validate_manifest(candidate)


def test_host_identity_is_stable_across_names_but_conflicting_definitions_fail():
    snapshot = host_v2()
    source = source_key(snapshot["source"])
    first = build_rows(validate_snapshot(snapshot), "one", source)
    snapshot["manifest"]["resourceBindings"][1]["target"]["name"] = "Renamed database"
    second = build_rows(validate_snapshot(snapshot), "two", source)

    def host(rows):
        return next(row for row in rows["GuardExternalResource"] if row["provider"] == "host")

    assert host(first)["entity_id"] == host(second)["entity_id"]
    assert host(first)["name"] != host(second)["name"]
    duplicate = deepcopy(snapshot["manifest"]["resourceBindings"][1])
    duplicate.update(id="other-binding", resourceRef="report-A")
    snapshot["manifest"]["resourceBindings"][0] = duplicate
    for binding in snapshot["manifest"]["resourceBindings"]:
        binding["dependsOn"] = []
    validate_manifest(snapshot["manifest"])
    duplicate["target"]["kind"] = "queue"
    with pytest.raises(InventoryValidationError, match="^INVENTORY_MANIFEST_BINDING_INVALID$"):
        validate_manifest(snapshot["manifest"])


def test_v2_projection_properties_and_relationships_are_source_scoped():
    snapshot = validate_snapshot(host_v2())
    first = build_rows(snapshot, "one", source_key(snapshot["source"]))
    other = deepcopy(snapshot)
    other["source"]["tenantId"] = "other"
    other["manifest"]["source"] = dict(other["source"])
    for task in other["tasks"]:
        task["tenantId"] = "other"
    second = build_rows(validate_snapshot(other), "one", source_key(other["source"]))
    for label in first:
        assert {row["id"] for row in first[label]}.isdisjoint(row["id"] for row in second[label])
    owner = first["GuardOwner"][0]
    assert first["GuardAgent"][0]["owner_node_id"] == owner["id"]
    assert set(first["GuardDeployment"][0]["credential_node_ids"]) == {
        row["id"] for row in first["GuardCredentialReference"]
    }
    assert first["GuardResourceBinding"][1]["dependency_node_ids"] == [
        first["GuardResourceBinding"][0]["id"]
    ]
    for label in (
        "GuardOwner",
        "GuardCredentialReference",
        "GuardAgent",
        "GuardDeployment",
        "GuardResourceBinding",
    ):
        assert all(
            row["authority_id"] == "company-directory"
            and row["manifest_schema_version"] == 2
            and row["assessment"] == "unknown"
            for row in first[label]
        )
    assert not hasattr(SCHEMAS["GuardDeployment"].properties, "credential_node_ids")
    assert not hasattr(SCHEMAS["GuardResourceBinding"].properties, "dependency_node_ids")


def test_v2_semantic_hash_ignores_only_order_and_capture_time():
    manifest = host_v2()["manifest"]
    reordered = deepcopy(manifest)
    for field in (
        "agents",
        "deployments",
        "owners",
        "credentialReferences",
        "taskBindings",
        "resourceBindings",
        "executionBindings",
    ):
        reordered[field].reverse()
    for deployment in reordered["deployments"]:
        deployment["credentialReferenceIds"].reverse()
    for binding in reordered["resourceBindings"]:
        for field in ("actions", "approvedDestinations", "dependsOn"):
            binding[field].reverse()
    for credential in reordered["credentialReferences"]:
        for field in ("audienceRefs", "recipientRefs"):
            credential[field].reverse()
    reordered["observedAt"] = "2026-11-01T00:00:00Z"
    assert _manifest_hash(manifest) == _manifest_hash(reordered)
    reordered["authorityId"] = "different-directory"
    assert _manifest_hash(manifest) != _manifest_hash(reordered)


def test_manifest_schema_downgrade_is_rejected_even_with_newer_revision():
    current = {"profile": "host", **_manifest_properties(host_v2())}
    downgrade = {**current, "manifest_schema_version": 1, "manifest_revision": 100}
    with pytest.raises(GraphImportError, match="^MANIFEST_SCHEMA_ROLLBACK$"):
        _check_component_versions(current, downgrade)
    legacy = {key: value for key, value in current.items() if key != "manifest_schema_version"}
    legacy["manifest_hash"] = "old-v1"
    with pytest.raises(GraphImportError, match="^MANIFEST_CONTENT_CONFLICT$"):
        _check_component_versions(legacy, current)
    _check_component_versions(legacy, {**current, "manifest_revision": 6})


def test_host_only_cloud_capture_never_opens_provider_transaction():
    snapshot = host_v2()
    rows = build_rows(snapshot, "one", source_key(snapshot["source"]))
    rows["GuardExternalResource"] = [
        row for row in rows["GuardExternalResource"] if row["provider"] == "host"
    ]
    rows["GuardExternalIdentity"] = []
    scope = validate_cloud_scope(
        {
            "companyId": "example-company",
            "tenantId": "alpha",
            "accounts": [{"partition": "aws", "accountId": "123456789012"}],
        }
    )
    capture = collect_cloud(object(), rows, scope)
    assert len(capture["observations"]) == 1
    observation = capture["observations"][0]
    assert (
        observation["status"] == "not_collected" and observation["reason"] == "unsupported_provider"
    )
    assert provider_target(observation["reference"], scope) is None
    assert unavailable_cloud(capture)["observations"] == capture["observations"]


def test_new_report_labels_retain_counts_only():
    result = minimize_changes(
        {
            "operation": "get_changes",
            "data": {
                "sourceId": "a" * 64,
                "coverageGap": False,
                "from": {"projectionId": "b" * 64},
                "to": {"projectionId": "c" * 64},
                "changes": {
                    "added": [{"label": "GuardOwner", "name": "private-canary"}],
                    "removed": [],
                    "changed": [
                        {"label": "GuardCredentialReference", "before": {"id": "private-canary"}}
                    ],
                },
            },
        },
        "a" * 64,
    )
    assert result["counts"] == {
        "added": {"GuardOwner": 1},
        "removed": {},
        "changed": {"GuardCredentialReference": 1},
    }
    assert "private-canary" not in json.dumps(result)
