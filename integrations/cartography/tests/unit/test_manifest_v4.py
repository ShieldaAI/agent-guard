"""Manifest v4 (host-declared networkIsolation) from the real executor, checked by Python."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.graph import _authority_hash, _manifest_hash, build_rows, source_key
from agent_guard_cartography.inventory import (
    MANIFEST_V3_SCHEMA_FILENAME,
    InventoryValidationError,
    _validator,
    validate_manifest,
    validate_snapshot,
)
from agent_guard_cartography.models import SCHEMAS

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).parents[1] / "fixtures" / "manifest-executor.mjs"
NETWORK_FIELDS = (
    "network_status",
    "network_segment",
    "network_egress",
    "network_egress_targets",
    "sandbox_kind",
)


def run(flag):
    node = shutil.which("node")
    assert node is not None and (ROOT / "packages/executor/dist/index.js").is_file()
    result = subprocess.run(
        [node, str(FIXTURE), flag],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def v4():
    return run("--v4")


def rows(snapshot):
    return build_rows(snapshot, "projection", source_key(snapshot["source"]))


def deployments(snapshot):
    return {row["deployment_id"]: row for row in rows(snapshot)["GuardDeployment"]}


def opaque(index):
    return f"opaque:{index:064x}"


def test_actual_v4_composition_and_observer_output_validate(v4):
    for value in [v4["composed"], v4["observedHost"]["body"]]:
        snapshot = validate_snapshot(value)
        assert snapshot["schemaVersion"] == 2
        assert snapshot["manifest"]["schemaVersion"] == 4
        [entry] = snapshot["manifest"]["networkIsolation"]
        assert (entry["deploymentId"], entry["egress"], entry["sandbox"]) == (
            "deployment-static",
            "allowlist",
            "container",
        )
        # v4 keeps v3's declaration of paths outside the guard.
        assert [item["kind"] for item in snapshot["manifest"]["directAccess"]] == ["database"]
    assert "private-" not in json.dumps(v4)


def test_projection_marks_declared_and_not_declared_per_deployment(v4):
    projected = deployments(validate_snapshot(v4["composed"]))
    static, dynamic = projected["deployment-static"], projected["deployment-dynamic"]
    assert {field: static[field] for field in NETWORK_FIELDS} == {
        "network_status": "declared",
        "network_segment": "opaque:" + "5" * 64,
        "network_egress": "allowlist",
        # Stored sorted: the host's order carries no meaning.
        "network_egress_targets": ["opaque:" + "6" * 64, "opaque:" + "7" * 64],
        "sandbox_kind": "container",
    }
    assert {field: dynamic.get(field) for field in NETWORK_FIELDS} == {
        "network_status": "not_declared",
        "network_segment": None,
        "network_egress": None,
        "network_egress_targets": None,
        "sandbox_kind": None,
    }
    assert set(NETWORK_FIELDS) & set(dynamic) == {"network_status"}
    # v3's direct-access status is unchanged by v4.
    assert static["direct_access_status"] == "found"
    assert dynamic["direct_access_status"] == "none_declared"


def test_a_null_segment_and_no_egress_are_projected_as_declared(v4):
    snapshot = deepcopy(v4["composed"])
    snapshot["manifest"]["networkIsolation"] = [
        {
            "deploymentId": "deployment-dynamic",
            "segmentId": None,
            "egress": "none",
            "egressTargets": [],
            "sandbox": "vm",
        }
    ]
    projected = deployments(validate_snapshot(snapshot))
    dynamic = projected["deployment-dynamic"]
    assert dynamic["network_status"] == "declared"
    assert dynamic["network_segment"] is None
    assert (dynamic["network_egress"], dynamic["network_egress_targets"]) == ("none", [])
    assert dynamic["sandbox_kind"] == "vm"
    assert projected["deployment-static"]["network_status"] == "not_declared"


def test_an_empty_declaration_marks_every_deployment_not_declared(v4):
    snapshot = deepcopy(v4["composed"])
    snapshot["manifest"]["networkIsolation"] = []
    projected = deployments(validate_snapshot(snapshot))
    assert {row["network_status"] for row in projected.values()} == {"not_declared"}


@pytest.mark.parametrize("flag", ["--v2", "--v3"])
def test_an_older_manifest_never_reads_as_declared_or_not_declared(flag):
    projected = deployments(validate_snapshot(run(flag)["composed"]))
    assert all(not set(NETWORK_FIELDS) & set(row) for row in projected.values())


def test_a_v3_only_validator_refuses_v4(v4):
    manifest = v4["composed"]["manifest"]
    assert next(_validator(MANIFEST_V3_SCHEMA_FILENAME).iter_errors(manifest), None) is not None


def test_the_deployment_model_declares_the_network_properties():
    properties = SCHEMAS["GuardDeployment"].properties
    for field in NETWORK_FIELDS:
        assert getattr(properties, field).name == field


def entry(deployment="deployment-static", **overrides):
    return {
        "deploymentId": deployment,
        "segmentId": None,
        "egress": "allowlist",
        "egressTargets": [opaque(1)],
        "sandbox": "process",
        **overrides,
    }


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda m: m.pop("networkIsolation"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m.pop("directAccess"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m.update(schemaVersion=5), "INVENTORY_SCHEMA_INVALID"),
        (
            lambda m: m["networkIsolation"][0].update(egress="restricted"),
            "INVENTORY_SCHEMA_INVALID",
        ),
        (lambda m: m["networkIsolation"][0].update(sandbox="jail"), "INVENTORY_SCHEMA_INVALID"),
        (
            lambda m: m["networkIsolation"][0].update(segmentId="segment"),
            "INVENTORY_SCHEMA_INVALID",
        ),
        (
            lambda m: m["networkIsolation"][0].update(egressTargets=["api.example.com"]),
            "INVENTORY_SCHEMA_INVALID",
        ),
        (
            lambda m: m["networkIsolation"][0].update(egressTargets=[opaque(1), opaque(1)]),
            "INVENTORY_SCHEMA_INVALID",
        ),
        (
            lambda m: m["networkIsolation"][0].update(
                egressTargets=[opaque(index) for index in range(33)]
            ),
            "INVENTORY_SCHEMA_INVALID",
        ),
        (lambda m: m["networkIsolation"][0].update(egress="open"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m["networkIsolation"][0].update(egress="none"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m["networkIsolation"][0].pop("egressTargets"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m["networkIsolation"][0].update(secret="x"), "INVENTORY_SCHEMA_INVALID"),
        (
            lambda m: m["networkIsolation"][0].update(deploymentId="missing"),
            "INVENTORY_MANIFEST_REFERENCE_INVALID",
        ),
        (lambda m: m["networkIsolation"].append(entry()), "INVENTORY_DUPLICATE_ID"),
        (
            lambda m: m.update(networkIsolation=[entry(f"d-{index}") for index in range(1001)]),
            "INVENTORY_SCHEMA_INVALID",
        ),
    ],
)
def test_malformed_declarations_are_refused(v4, mutate, code):
    manifest = deepcopy(v4["validated"])
    mutate(manifest)
    with pytest.raises(InventoryValidationError, match=f"^{code}$"):
        validate_manifest(manifest)


def test_limits_and_empty_declarations_are_accepted(v4):
    manifest = deepcopy(v4["validated"])
    manifest["networkIsolation"] = [
        entry(egressTargets=[opaque(index) for index in range(32)]),
        entry("deployment-dynamic", egress="open", egressTargets=[], sandbox="none"),
    ]
    assert len(validate_manifest(manifest)["networkIsolation"][0]["egressTargets"]) == 32
    manifest["networkIsolation"] = [entry(egressTargets=[])]
    assert validate_manifest(manifest)["networkIsolation"][0]["egressTargets"] == []
    manifest["networkIsolation"] = []
    assert validate_manifest(manifest)["networkIsolation"] == []


def test_manifest_hash_ignores_declaration_order_but_not_content(v4):
    manifest = deepcopy(v4["validated"])
    manifest["networkIsolation"] = [
        entry(egressTargets=[opaque(1), opaque(2)]),
        entry("deployment-dynamic", egress="none", egressTargets=[]),
    ]
    reordered = deepcopy(manifest)
    reordered["networkIsolation"].reverse()
    reordered["networkIsolation"][1]["egressTargets"].reverse()
    assert _manifest_hash(manifest) == _manifest_hash(reordered)
    for field, value in [("sandbox", "vm"), ("segmentId", opaque(9)), ("egress", "open")]:
        changed = deepcopy(manifest)
        changed["networkIsolation"][1][field] = value
        assert _manifest_hash(manifest) != _manifest_hash(changed), field


def test_moving_to_v4_does_not_change_authority_at_the_same_revision():
    v2, v3, v4 = (run(flag)["composed"] for flag in ("--v2", "--v3", "--v4"))
    assert (v2["schemaVersion"], v3["schemaVersion"], v4["schemaVersion"]) == (1, 2, 2)
    assert v2["ledgerRevision"] == v3["ledgerRevision"] == v4["ledgerRevision"]
    assert _authority_hash(v2) == _authority_hash(v3) == _authority_hash(v4)
    flagged = deepcopy(v4)
    flagged["tasks"][0]["untrusted"] = True
    assert _authority_hash(flagged) != _authority_hash(v4)
