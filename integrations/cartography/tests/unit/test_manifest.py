import json
from copy import deepcopy
from pathlib import Path

import pytest

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


def host_snapshot():
    snapshot = json.loads((Path(__file__).parents[1] / "fixtures" / "alpha-v1.json").read_text())
    snapshot["profile"] = "host"
    snapshot["manifest"] = {
        "schemaVersion": 1,
        "evidenceKind": "host_asserted",
        "source": deepcopy(snapshot["source"]),
        "manifestId": "host-config",
        "revision": 1,
        "observedAt": "2026-10-29T10:00:00Z",
        "agents": [
            {"id": "research-agent", "name": "Research", "ownerId": "owner", "teamId": "team"}
        ],
        "deployments": [
            {"id": "deployment", "agentId": "research-agent", "environment": "production"},
            {"id": "dynamic-deployment", "agentId": "research-agent", "environment": None},
        ],
        "taskBindings": [{"taskId": "research-root", "deploymentId": "deployment"}],
        "resourceBindings": [
            {
                "id": "object-binding",
                "tool": "records.read",
                "resourceRef": "report-A",
                "target": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "123456789012",
                    "region": "",
                    "arn": "arn:aws:s3:::reports/report-A",
                    "kind": "object",
                },
                "actions": ["s3:GetObject"],
                "scope": "exact",
            },
            {
                "id": "prefix-binding",
                "tool": "records.read",
                "resourceRef": "report-B",
                "target": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "123456789012",
                    "region": "",
                    "arn": "arn:aws:s3:::reports/prefix/",
                    "kind": "prefix",
                },
                "actions": ["s3:GetObject"],
                "scope": "prefix",
            },
        ],
        "executionBindings": [
            {
                "id": "static-execution",
                "tool": "records.read",
                "deploymentId": "deployment",
                "connectionId": None,
                "identitySelection": "static",
                "identity": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "123456789012",
                    "region": "",
                    "arn": "arn:aws:iam::123456789012:role/research",
                },
            },
            {
                "id": "dynamic-execution",
                "tool": "records.read",
                "deploymentId": "dynamic-deployment",
                "connectionId": "mcp-ref",
                "identitySelection": "dynamic",
                "identity": None,
            },
        ],
    }
    snapshot["coverage"]["manifest"] = {
        "status": "complete",
        "observedAt": snapshot["manifest"]["observedAt"],
    }
    return snapshot


def test_host_snapshot_preserves_core_authority_and_detaches_manifest():
    incoming = host_snapshot()
    snapshot = validate_snapshot(incoming)
    assert snapshot == incoming
    incoming["manifest"]["agents"][0]["name"] = "changed"
    assert snapshot["manifest"]["agents"][0]["name"] == "Research"
    assert (
        snapshot["coverage"]["tasks"]["observedAt"]
        != snapshot["coverage"]["manifest"]["observedAt"]
    )
    assert _authority_hash(snapshot) == _authority_hash({**snapshot, "manifest": {}})


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.update(tokens=["private-canary"]),
        lambda m: m["agents"][0].update(metadata={"secret": "private-canary"}),
        lambda m: m["agents"].append(deepcopy(m["agents"][0])),
        lambda m: m["deployments"][0].update(agentId="missing"),
        lambda m: m["taskBindings"][0].update(deploymentId="missing"),
        lambda m: m["taskBindings"].append(deepcopy(m["taskBindings"][0])),
        lambda m: m["resourceBindings"][0].update(resourceRef="*"),
        lambda m: m["resourceBindings"].append(
            {**m["resourceBindings"][0], "id": "duplicate-reference"}
        ),
        lambda m: m["resourceBindings"][0]["target"].update(partition="aws-cn"),
        lambda m: m["resourceBindings"][0]["target"].update(region="us-east-1"),
        lambda m: m["resourceBindings"][0]["target"].update(
            arn="arn:aws:s3:us-east-1::reports/object"
        ),
        lambda m: m["resourceBindings"][0]["target"].update(
            arn="arn:aws:s3::123456789012:reports/object"
        ),
        lambda m: m["resourceBindings"][0]["target"].update(arn="arn:aws:s3:::reports/*"),
        lambda m: m["resourceBindings"][0]["target"].update(kind="bucket"),
        lambda m: m["resourceBindings"][0].update(scope="prefix"),
        lambda m: m["resourceBindings"][1]["target"].update(
            arn="arn:aws:s3:::reports/no-trailing-slash"
        ),
        lambda m: m["resourceBindings"][0].update(actions=["s3:*"]),
        lambda m: m["resourceBindings"][0].update(actions=["s3:GetObject", "s3:GetObject"]),
        lambda m: m["resourceBindings"][0].update(actions=["iam:GetRole"]),
        lambda m: m["executionBindings"][0].update(identity=None),
        lambda m: m["executionBindings"][1].update(identity=m["executionBindings"][0]["identity"]),
        lambda m: m["executionBindings"][0]["identity"].update(accountId="210987654321"),
        lambda m: m["executionBindings"][0]["identity"].update(arn="arn:aws:s3:::bucket"),
        lambda m: m["executionBindings"][0]["identity"].update(
            arn="arn:aws:iam::123456789012:policy/policy"
        ),
        lambda m: m["executionBindings"][0]["identity"].update(
            arn="arn:aws:iam::123456789012:role//name"
        ),
        lambda m: m["executionBindings"][0]["identity"].update(
            arn="arn:aws:sts:us-east-1:123456789012:assumed-role/role/session", region="us-east-1"
        ),
        lambda m: m["executionBindings"].append(
            {**m["executionBindings"][0], "id": "ambiguous-identity"}
        ),
        lambda m: m.update(revision=-1),
        lambda m: m.update(observedAt="2026-02-30T12:00:00Z"),
    ],
)
def test_manifest_refuses_secret_fields_ambiguous_bindings_and_inconsistent_arns(change):
    manifest = host_snapshot()["manifest"]
    change(manifest)
    with pytest.raises(InventoryValidationError) as error:
        validate_manifest(manifest)
    assert "private-canary" not in str(error.value)


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s["manifest"]["source"].update(tenantId="foreign"),
        lambda s: s["manifest"]["source"].update(enrollmentGeneration="different"),
        lambda s: s["manifest"]["source"].update(inventoryInstanceId="different"),
        lambda s: s["manifest"]["taskBindings"][0].update(taskId="foreign-task"),
        lambda s: s["manifest"]["resourceBindings"][0].update(tool="records.delete"),
        lambda s: s["manifest"]["resourceBindings"][0].update(resourceRef="ungranted"),
        lambda s: s["manifest"]["executionBindings"][0].update(tool="unobserved"),
        lambda s: s["coverage"]["manifest"].update(observedAt="2026-10-29T12:00:00Z"),
        lambda s: s.update(profile="core"),
    ],
)
def test_composed_snapshot_requires_exact_source_and_observed_references(change):
    snapshot = host_snapshot()
    change(snapshot)
    with pytest.raises(InventoryValidationError):
        validate_snapshot(snapshot)


def test_host_graph_has_only_asserted_binding_paths_and_keeps_unassigned_tasks():
    snapshot = validate_snapshot(host_snapshot())
    rows = build_rows(snapshot, "projection", source_key(snapshot["source"]))
    assert len(rows["GuardTask"]) == 3
    assert sum(row["deployment_node_id"] is not None for row in rows["GuardTask"]) == 1
    assert len(rows["GuardExternalIdentity"]) == 1
    dynamic = next(
        row for row in rows["GuardExecutionBinding"] if row["identity_selection"] == "dynamic"
    )
    assert dynamic["identity_node_id"] is None
    assert {row["kind"] for row in rows["GuardExternalResource"]} == {"object", "prefix"}
    assert {row["scope"] for row in rows["GuardResourceBinding"]} == {"exact", "prefix"}
    for label in (
        "GuardAgent",
        "GuardDeployment",
        "GuardExternalIdentity",
        "GuardExternalResource",
        "GuardResourceBinding",
        "GuardExecutionBinding",
    ):
        assert all(
            row["evidence_kind"] == "host_asserted"
            and row["assessment"] == "unknown"
            and row["manifest_revision"] == 1
            for row in rows[label]
        )
    assert all(row["assessment"] == "unknown" for row in rows["GuardGrant"])
    assert all(label.startswith("Guard") for label in rows)


def test_host_binding_identity_is_scoped_to_tenant_and_projection():
    snapshot = host_snapshot()
    first = build_rows(snapshot, "one", source_key(snapshot["source"]))
    other = deepcopy(snapshot)
    other["source"]["tenantId"] = "foreign"
    second = build_rows(other, "one", source_key(other["source"]))
    third = build_rows(snapshot, "two", source_key(snapshot["source"]))
    for label in first:
        assert {row["id"] for row in first[label]}.isdisjoint(row["id"] for row in second[label])
        assert {row["id"] for row in first[label]}.isdisjoint(row["id"] for row in third[label])


def test_manifest_hash_is_order_independent_and_capture_time_is_not_content():
    manifest = host_snapshot()["manifest"]
    reordered = deepcopy(manifest)
    for field in ("agents", "deployments", "taskBindings", "resourceBindings", "executionBindings"):
        reordered[field].reverse()
    reordered["observedAt"] = "2026-10-29T12:30:00Z"
    assert _manifest_hash(manifest) == _manifest_hash(reordered)
    reordered["agents"][0]["ownerId"] = "different-owner"
    assert _manifest_hash(manifest) != _manifest_hash(reordered)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda c: c.update(profile="core"), "PROFILE_CONFLICT"),
        (lambda c: c.update(manifest_id="different"), "MANIFEST_ID_CONFLICT"),
        (lambda c: c.update(manifest_revision=0), "MANIFEST_REVISION_ROLLBACK"),
        (lambda c: c.update(manifest_hash="changed"), "MANIFEST_CONTENT_CONFLICT"),
    ],
)
def test_manifest_publication_versions_are_independent_of_authority(change, code):
    candidate = {"profile": "host", **_manifest_properties(host_snapshot())}
    current = dict(candidate)
    change(candidate)
    with pytest.raises(GraphImportError, match=f"^{code}$"):
        _check_component_versions(current, candidate)


def test_manifest_revision_advance_is_permitted_without_core_authority_changes():
    candidate = {"profile": "host", **_manifest_properties(host_snapshot())}
    current = dict(candidate)
    candidate.update(manifest_revision=2, manifest_hash="new-declared-metadata")
    _check_component_versions(current, candidate)
    with pytest.raises(GraphImportError, match="^PROFILE_CONFLICT$"):
        _check_component_versions({"current_snapshot_id": "legacy-core"}, candidate)


def test_manifest_limits_reject_entire_optional_component():
    manifest = host_snapshot()["manifest"]
    manifest["agents"] = [
        {"id": f"agent-{i}", "name": "x" * 4096, "ownerId": None, "teamId": None}
        for i in range(600)
    ]
    with pytest.raises(InventoryValidationError, match="^INVENTORY_LIMIT_EXCEEDED$"):
        validate_manifest(manifest)
