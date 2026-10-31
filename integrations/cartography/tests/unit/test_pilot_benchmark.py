from datetime import UTC, datetime

import pytest

from agent_guard_cartography.graph import build_rows
from agent_guard_cartography.pilot_benchmark import (
    PROFILES,
    gates,
    nearest_rank,
    synthetic_snapshot,
)


@pytest.mark.parametrize("profile", PROFILES)
def test_pilot_fixture_is_bounded_valid_and_has_expected_tasks_and_grants(profile):
    snapshot = synthetic_snapshot(profile, "unit-run", 0, datetime(2026, 10, 30, tzinfo=UTC))
    shape = PROFILES[profile]
    assert len(snapshot["tasks"]) == shape["agents_per_source"] * shape["tasks_per_agent"]
    assert sum(len(task["grants"]) for task in snapshot["tasks"]) == len(snapshot["tasks"]) * 10
    assert len(snapshot["tools"]) == 10
    assert len(snapshot["manifest"]["agents"]) == shape["agents_per_source"]
    rows = build_rows(snapshot, "projection", "source")
    assert sum(map(len, rows.values())) < 2000
    assert len(rows["GuardResource"]) == 10


def test_acceptance_profile_cannot_be_confused_with_smoke_scale():
    shape = PROFILES["acceptance"]
    tasks = shape["sources"] * shape["agents_per_source"] * shape["tasks_per_agent"]
    assert tasks == 10_000
    assert tasks * shape["grants_per_task"] == 100_000


def test_nearest_rank_includes_cold_and_failed_samples_in_gate():
    values = list(range(1, 21))
    assert nearest_rank(values) == 19
    for invalid in ([], [float("nan")], [-1], [float("inf")]):
        with pytest.raises(ValueError, match="PILOT_MEASUREMENT_INVALID"):
            nearest_rank(invalid)


def test_pilot_gates_fail_on_wrong_scale_failure_missing_samples_or_slow_tail():
    publications = [0.3, 0.4]
    queries = [
        {
            "operation": "get_agent_access" if index % 2 else "explain_access",
            "ok": True,
            "seconds": 0.2,
        }
        for index in range(40)
    ]
    counts = {"sources": 2, "tasks": 40, "grants": 400}
    assert gates("smoke", publications, queries, counts)["passed"]
    assert not gates("acceptance", publications, queries, counts)["passed"]
    assert not gates("smoke", [0.3, 120.1], queries, counts)["passed"]
    assert not gates("smoke", publications, queries[:-1], counts)["passed"]
    assert not gates("smoke", publications, [queries[0]] * 39 + [queries[1]], counts)["passed"]
    assert not gates("smoke", publications, [{**queries[0], "ok": False}, *queries[1:]], counts)[
        "passed"
    ]
    assert not gates(
        "smoke", publications, [{**sample, "seconds": 2.0} for sample in queries], counts
    )["passed"]
    assert not gates("smoke", publications, queries, {**counts, "grants": 399})["passed"]
