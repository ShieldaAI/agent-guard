import copy
import json
from pathlib import Path

import pytest

from agent_guard_cartography.inventory import (
    SCHEMA_FILENAME,
    InventoryValidationError,
    _validator,
    validate_snapshot,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "core-v2-boundaries.json"


def snapshot():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_executor_v2_snapshot_validates_and_keeps_outside_content_fields():
    value = validate_snapshot(snapshot())
    assert value["schemaVersion"] == 2
    assert {task["id"]: task["untrusted"] for task in value["tasks"]} == {
        "clean": False,
        "reader": True,
    }
    tools = {tool["name"]: tool for tool in value["tools"]}
    assert tools["email.read"]["readsUntrusted"] is True
    assert tools["email.send"]["untrustedContext"] == "require_approval"
    assert value["untrustedContextDefault"] == "allow"


def test_a_v1_only_collector_fails_closed_on_v2():
    assert next(_validator(SCHEMA_FILENAME).iter_errors(snapshot()), None) is not None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("untrustedContextDefault"),
        lambda value: value.update(untrustedContextDefault="sometimes"),
        lambda value: value["tasks"][0].pop("untrusted"),
        lambda value: value["tools"][0].pop("sendsExternal"),
        lambda value: value["tools"][0].update(untrustedContext="sometimes"),
        lambda value: value["tools"][0].update(
            registered=False, requiresApproval=None, controlPlane=None, maxCost=None
        ),
    ],
)
def test_malformed_v2_records_are_refused(mutate):
    value = copy.deepcopy(snapshot())
    mutate(value)
    with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
        validate_snapshot(value)


def test_family_members_must_agree_on_untrusted():
    value = copy.deepcopy(snapshot())
    reader = next(task for task in value["tasks"] if task["id"] == "reader")
    clean = next(task for task in value["tasks"] if task["id"] == "clean")
    clean["familyId"] = reader["familyId"]
    with pytest.raises(InventoryValidationError, match="^INVENTORY_FAMILY_INVALID$"):
        validate_snapshot(value)
