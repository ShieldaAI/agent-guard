"""Manifest v3 (host-declared directAccess) from the real executor, checked by Python."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.graph import _authority_hash, _manifest_hash, build_rows, source_key
from agent_guard_cartography.inventory import (
    MANIFEST_V2_SCHEMA_FILENAME,
    InventoryValidationError,
    _validator,
    validate_manifest,
    validate_snapshot,
)

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).parents[1] / "fixtures" / "manifest-executor.mjs"


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
def v3():
    return run("--v3")


def rows(snapshot):
    return build_rows(snapshot, "projection", source_key(snapshot["source"]))


def test_actual_v3_composition_and_observer_output_validate(v3):
    for value in [v3["composed"], v3["observedHost"]["body"]]:
        snapshot = validate_snapshot(value)
        assert snapshot["schemaVersion"] == 2
        assert snapshot["manifest"]["schemaVersion"] == 3
        assert [entry["kind"] for entry in snapshot["manifest"]["directAccess"]] == ["database"]
    assert "private-" not in json.dumps(v3)


def test_projection_marks_found_and_none_declared_per_deployment(v3):
    projected = rows(validate_snapshot(v3["composed"]))
    [entry] = projected["GuardDirectAccess"]
    assert (entry["kind"], entry["evidence_kind"], entry["assessment"]) == (
        "database",
        "host_asserted",
        "unknown",
    )
    deployments = {row["deployment_id"]: row for row in projected["GuardDeployment"]}
    assert entry["deployment_node_id"] == deployments["deployment-static"]["id"]
    assert deployments["deployment-static"]["direct_access_status"] == "found"
    assert deployments["deployment-dynamic"]["direct_access_status"] == "none_declared"


def test_a_v2_manifest_never_reads_as_none_declared():
    projected = rows(validate_snapshot(run("--v2")["composed"]))
    assert projected["GuardDirectAccess"] == []
    assert all("direct_access_status" not in row for row in projected["GuardDeployment"])


def test_a_v2_only_validator_refuses_v3(v3):
    manifest = v3["composed"]["manifest"]
    assert next(_validator(MANIFEST_V2_SCHEMA_FILENAME).iter_errors(manifest), None) is not None


def entry(manifest, index, deployment="deployment-static"):
    return {
        "id": f"opaque:{index:064x}",
        "deploymentId": deployment,
        "kind": "shell",
        "targetRef": None,
        "description": "Ops shell",
    }


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda m: m.pop("directAccess"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m["directAccess"][0].update(kind="ssh"), "INVENTORY_SCHEMA_INVALID"),
        (lambda m: m["directAccess"][0].update(id="raw"), "INVENTORY_SCHEMA_INVALID"),
        (
            lambda m: m["directAccess"][0].update(targetRef="db.internal"),
            "INVENTORY_SCHEMA_INVALID",
        ),
        (lambda m: m["directAccess"][0].update(secret="x"), "INVENTORY_SCHEMA_INVALID"),
        (
            lambda m: m["directAccess"][0].update(deploymentId="missing"),
            "INVENTORY_MANIFEST_REFERENCE_INVALID",
        ),
        (
            lambda m: m["directAccess"][0].update(targetRef="opaque:" + "e" * 64),
            "INVENTORY_MANIFEST_REFERENCE_INVALID",
        ),
        (
            lambda m: m["directAccess"].append(deepcopy(m["directAccess"][0])),
            "INVENTORY_DUPLICATE_ID",
        ),
        (
            lambda m: m.update(directAccess=[entry(m, index) for index in range(33)]),
            "INVENTORY_MANIFEST_LIMIT_EXCEEDED",
        ),
    ],
)
def test_malformed_declarations_are_refused(v3, mutate, code):
    manifest = deepcopy(v3["validated"])
    mutate(manifest)
    with pytest.raises(InventoryValidationError, match=f"^{code}$"):
        validate_manifest(manifest)


def test_limits_and_empty_declarations_are_accepted(v3):
    manifest = deepcopy(v3["validated"])
    manifest["directAccess"] = [entry(manifest, index) for index in range(32)]
    assert len(validate_manifest(manifest)["directAccess"]) == 32
    manifest["directAccess"] = []
    assert validate_manifest(manifest)["directAccess"] == []


def test_manifest_hash_ignores_declaration_order_but_not_content(v3):
    manifest = deepcopy(v3["validated"])
    manifest["directAccess"] = [entry(manifest, 1), entry(manifest, 2)]
    reordered = deepcopy(manifest)
    reordered["directAccess"].reverse()
    assert _manifest_hash(manifest) == _manifest_hash(reordered)
    changed = deepcopy(manifest)
    changed["directAccess"][0]["kind"] = "network"
    assert _manifest_hash(manifest) != _manifest_hash(changed)


def test_neutral_v2_fields_do_not_change_authority_at_the_same_revision():
    v2, v3 = run("--v2")["composed"], run("--v3")["composed"]
    assert (v2["schemaVersion"], v3["schemaVersion"]) == (1, 2)
    assert v2["ledgerRevision"] == v3["ledgerRevision"]
    assert _authority_hash(v2) == _authority_hash(v3)
    flagged = deepcopy(v3)
    flagged["tasks"][0]["untrusted"] = True
    assert _authority_hash(flagged) != _authority_hash(v3)
    labelled = deepcopy(v3)
    labelled["tools"][0]["sendsExternal"] = False
    assert _authority_hash(labelled) != _authority_hash(v3)
