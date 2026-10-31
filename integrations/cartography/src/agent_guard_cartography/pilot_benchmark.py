"""Synthetic pilot fixtures and deterministic performance gates; never authority data."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from agent_guard_cartography.inventory import validate_snapshot

PROFILES = {
    "smoke": {"sources": 2, "agents_per_source": 2, "tasks_per_agent": 10, "grants_per_task": 10},
    "acceptance": {
        "sources": 100,
        "agents_per_source": 10,
        "tasks_per_agent": 10,
        "grants_per_task": 10,
    },
}
PUBLICATION_LIMIT_SECONDS = 120.0
QUERY_P95_LIMIT_SECONDS = 2.0


def synthetic_snapshot(profile: str, run_id: str, index: int, now: datetime) -> dict[str, Any]:
    """A bounded host-profile source with shared tools/selectors and separate agents."""
    shape = PROFILES[profile]
    if not 0 <= index < shape["sources"] or now.tzinfo is None:
        raise ValueError("PILOT_FIXTURE_INVALID")
    observed = now.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    source = {
        "companyId": f"synthetic-pilot-{run_id}",
        "sourceId": f"executor-{index:03d}",
        "enrollmentGeneration": "synthetic-1",
        "inventoryInstanceId": f"ledger-{index:03d}",
        "tenantId": f"tenant-{index % 10}",
    }
    tools = [
        {
            "name": f"records.read-{number}",
            "fingerprint": sha256(f"synthetic-tool-{number}".encode()).hexdigest(),
            "revision": 1,
            "registered": True,
            "approved": True,
            "requiresApproval": False,
            "controlPlane": False,
            "maxCost": 0,
        }
        for number in range(shape["grants_per_task"])
    ]
    agents = [
        {
            "id": f"agent-{number}",
            "name": f"Synthetic agent {number}",
            "ownerId": f"owner-{number}",
            "teamId": f"team-{number % 2}",
        }
        for number in range(shape["agents_per_source"])
    ]
    deployments = [
        {"id": f"deployment-{number}", "agentId": agent["id"], "environment": "synthetic-pilot"}
        for number, agent in enumerate(agents)
    ]
    tasks = []
    task_bindings = []
    for agent_number in range(shape["agents_per_source"]):
        for task_number in range(shape["tasks_per_agent"]):
            task_id = f"task-{agent_number}-{task_number}"
            tasks.append(
                {
                    "id": task_id,
                    "tenantId": source["tenantId"],
                    "principalId": f"principal-{agent_number}",
                    "parentTaskId": None,
                    "sourceTaskId": None,
                    "familyId": task_id,
                    "grants": [
                        {"tool": tool["name"], "resources": [f"record-{number}"]}
                        for number, tool in enumerate(tools)
                    ],
                    "budget": {
                        "maxCalls": 1000,
                        "maxConcurrent": 4,
                        "maxCost": 1000,
                        "deadline": int((now + timedelta(days=7)).timestamp() * 1000),
                    },
                    "allowedRecipients": [],
                    "allowControlPlane": False,
                    "revoked": False,
                    "sensitive": False,
                    "usage": {"calls": 0, "concurrent": 0, "spent": 0, "reserved": 0},
                }
            )
            task_bindings.append({"taskId": task_id, "deploymentId": f"deployment-{agent_number}"})
    manifest = {
        "schemaVersion": 1,
        "evidenceKind": "host_asserted",
        "source": source,
        "manifestId": "synthetic-host",
        "revision": 1,
        "observedAt": observed,
        "agents": agents,
        "deployments": deployments,
        "taskBindings": task_bindings,
        "resourceBindings": [
            {
                "id": f"resource-{number}",
                "tool": tool["name"],
                "resourceRef": f"record-{number}",
                "target": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "111122223333",
                    "region": "",
                    "arn": f"arn:aws:s3:::synthetic-pilot/record-{number}",
                    "kind": "object",
                },
                "actions": ["s3:GetObject"],
                "scope": "exact",
            }
            for number, tool in enumerate(tools)
        ],
        "executionBindings": [
            {
                "id": f"execution-{agent_number}-{number}",
                "tool": tool["name"],
                "deploymentId": f"deployment-{agent_number}",
                "connectionId": None,
                "identitySelection": "static",
                "identity": {
                    "provider": "aws",
                    "partition": "aws",
                    "accountId": "111122223333",
                    "region": "",
                    "arn": f"arn:aws:iam::111122223333:role/SyntheticReader{agent_number}",
                },
            }
            for agent_number in range(shape["agents_per_source"])
            for number, tool in enumerate(tools)
        ],
    }
    return validate_snapshot(
        {
            "schemaVersion": 1,
            "profile": "host",
            "source": source,
            "snapshotId": f"synthetic-{index}-1",
            "generatedAt": observed,
            "ledgerRevision": 1,
            "policyEpoch": 1,
            "coverage": {
                "tasks": {"status": "complete", "observedAt": observed},
                "tools": {"status": "complete", "observedAt": observed},
                "manifest": {"status": "complete", "observedAt": observed},
                "mcp": {"status": "not_collected"},
                "cloud": {"status": "not_collected"},
            },
            "tasks": tasks,
            "tools": tools,
            "manifest": manifest,
        }
    )


def nearest_rank(values: list[float], percentile: float = 0.95) -> float:
    """Nearest-rank p95, without averaging away failures or the cold first sample."""
    if (
        not values
        or not 0 < percentile <= 1
        or any(not math.isfinite(value) or value < 0 for value in values)
    ):
        raise ValueError("PILOT_MEASUREMENT_INVALID")
    return sorted(values)[math.ceil(len(values) * percentile) - 1]


def gates(profile: str, publications: list[float], queries: list[dict], counts: dict) -> dict:
    shape = PROFILES[profile]
    expected_tasks = shape["sources"] * shape["agents_per_source"] * shape["tasks_per_agent"]
    expected_grants = expected_tasks * shape["grants_per_task"]
    expected_sources = shape["sources"]
    operations = ("get_agent_access", "explain_access")
    valid_queries = all(
        type(sample.get("seconds")) in (float, int)
        and math.isfinite(sample["seconds"])
        and sample["seconds"] >= 0
        and sample.get("ok") is True
        and sample.get("operation") in operations
        for sample in queries
    )
    p95 = {
        operation: nearest_rank(
            [sample["seconds"] for sample in queries if sample.get("operation") == operation]
        )
        if valid_queries and any(sample.get("operation") == operation for sample in queries)
        else None
        for operation in operations
    }
    passed = {
        "published_source_count": counts.get("sources") == expected_sources,
        "task_count": counts.get("tasks") == expected_tasks,
        "grant_count": counts.get("grants") == expected_grants,
        "publication_deadline": len(publications) == expected_sources
        and all(
            math.isfinite(value) and 0 <= value <= PUBLICATION_LIMIT_SECONDS
            for value in publications
        ),
        "query_success": valid_queries
        and all(
            sum(sample.get("operation") == operation for sample in queries) >= 20
            for operation in operations
        ),
        "query_p95": all(
            value is not None and value < QUERY_P95_LIMIT_SECONDS for value in p95.values()
        ),
    }
    return {
        "passed": all(passed.values()),
        "checks": passed,
        "query_p95_seconds": p95,
        "publication_max_seconds": max(publications) if publications else None,
        "targets": {
            "publication_per_source_seconds": PUBLICATION_LIMIT_SECONDS,
            "query_p95_seconds": QUERY_P95_LIMIT_SECONDS,
        },
        "expected": {
            "sources": expected_sources,
            "tasks": expected_tasks,
            "grants": expected_grants,
        },
    }
