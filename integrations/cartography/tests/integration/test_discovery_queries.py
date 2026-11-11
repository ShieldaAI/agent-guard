"""Agent discovery reads on a real graph: undeclared activity and unclaimed IAM identities."""

from __future__ import annotations

import json
import time
from copy import deepcopy
from uuid import uuid4

import pytest
from test_reference_queries import query, scope
from test_reference_queries import reference_snapshot as reference_snapshot

from agent_guard_cartography.aws_config import validate_aws_enrollment
from agent_guard_cartography.aws_graph import publish_aws_capture
from agent_guard_cartography.cloud import validate_cloud_scope
from agent_guard_cartography.graph import import_snapshot
from agent_guard_cartography.inventory import validate_snapshot

pytestmark = pytest.mark.integration
DATE = "2020-01-01T00:00:00Z"
# Names that only an all-teams reader may ever see.
CANARIES = ("stray", "unassigned", "batch-runner", "ci-deployer")


def publish(neo4j_session, reference_snapshot, *, aws=True):
    """Two declared agents; one sub-task and one unrelated task with no binding.

    The account holds the two declared roles plus a role and a user nobody declared.
    """
    snapshot = deepcopy(reference_snapshot)
    snapshot["source"]["companyId"] += "-" + uuid4().hex[:8]
    snapshot["manifest"]["source"] = dict(snapshot["source"])
    stray = deepcopy(
        next(task for task in snapshot["tasks"] if task["id"] == "unassigned-task-canary")
    )
    stray.update(
        id="stray-task",
        familyId="stray-task",
        parentTaskId=None,
        sourceTaskId=None,
        principalId="stray-principal",
    )
    snapshot["tasks"].append(stray)
    account = str(uuid4().int % 10**12).zfill(12)
    declared = []
    for index, binding in enumerate(snapshot["manifest"]["executionBindings"]):
        arn = f"arn:aws:iam::{account}:role/declared-{index}"
        binding["identity"].update(accountId=account, arn=arn)
        declared.append(arn)
    snapshot = validate_snapshot(snapshot)
    if not aws:
        receipt = import_snapshot(neo4j_session, snapshot, snapshot["source"])
        return {"snapshot": snapshot, "receipt": receipt, "account": account}

    def role(arn, path="/"):
        return {
            "arn": arn,
            "roleid": "AROA" + uuid4().hex[:12].upper(),
            "name": arn.rsplit("/", 1)[1],
            "path": path,
            "createdate": DATE,
            "createdate_dt": DATE,
        }

    config = validate_aws_enrollment(
        {
            "schemaVersion": 1,
            "companyId": snapshot["source"]["companyId"],
            "tenantId": snapshot["source"]["tenantId"],
            "partition": "aws",
            "accountId": account,
            "region": "us-east-1",
            "expectedCallerArn": f"arn:aws:sts::{account}:assumed-role/Collector/test",
            "accessKeyIdEnv": "TEST_KEY",
            "secretAccessKeyEnv": "TEST_SECRET",
            "sessionTokenEnv": "TEST_SESSION",
        }
    )
    publish_aws_capture(
        neo4j_session,
        config,
        {
            "capturedAt": int(time.time()) - 10,
            "roles": [
                *(role(arn) for arn in declared),
                role(f"arn:aws:iam::{account}:role/service/batch-runner", "/service/"),
            ],
            "users": [
                {
                    "arn": f"arn:aws:iam::{account}:user/ci-deployer",
                    "userid": "AIDAEXAMPLE",
                    "name": "ci-deployer",
                    "path": "/",
                    "createdate": DATE,
                    "createdate_dt": DATE,
                    "passwordlastused": "",
                    "passwordlastused_dt": None,
                }
            ],
            "buckets": [],
        },
    )
    cloud = validate_cloud_scope(
        {
            "companyId": snapshot["source"]["companyId"],
            "tenantId": snapshot["source"]["tenantId"],
            "accounts": [{"partition": "aws", "accountId": account}],
            "maxAgeSeconds": 120,
        }
    )
    receipt = import_snapshot(neo4j_session, snapshot, snapshot["source"], cloud_scope=cloud)
    return {"snapshot": snapshot, "receipt": receipt, "account": account}


def run(case, operations, *, all_teams=True, now=None):
    result = query(
        scope(case["snapshot"], all_teams=all_teams),
        request={"summary": True},
        operations=operations,
        now=(int(time.time()) if now is None else now) * 1000,
    )
    assert result["ok"] is True, result
    for output in result["outputs"]:
        assert output["ok"] is True, output
    return [output["response"]["data"] for output in result["outputs"]]


def test_undeclared_tasks_and_callers_are_counted_and_listed_for_an_all_teams_reader(
    neo4j_session, reference_snapshot
):
    case = publish(neo4j_session, reference_snapshot)
    source_id = case["receipt"].source_id
    health, tasks, principals, second = run(
        case,
        [
            {"operation": "get_inventory_health", "args": {}},
            {"operation": "list_undeclared_activity", "args": {"sourceId": source_id}},
            {
                "operation": "list_undeclared_activity",
                "args": {"sourceId": source_id, "kind": "principals"},
            },
            {
                "operation": "list_undeclared_activity",
                "args": {"sourceId": source_id, "offset": 1, "limit": 1},
            },
        ],
    )
    assert health["sources"][0]["undeclaredActivity"] == {
        "status": "complete",
        "tasks": 2,
        "tasksIsMinimum": False,
        "principals": 2,
        "principalsIsMinimum": False,
        "manifest": "collected",
    }
    assert [
        (item["taskId"], item["principalId"], item["parentDeclared"]) for item in tasks["items"]
    ] == [
        ("stray-task", "stray-principal", False),
        # Handed off from a task of a declared agent: a missing binding, not an unknown caller.
        ("unassigned-task-canary", "unassigned-principal-canary", True),
    ]
    assert (tasks["total"], tasks["truncated"], tasks["totalIsMinimum"]) == (2, False, False)
    assert all(item["tools"] and not item["toolsTruncated"] for item in tasks["items"])
    assert all(
        (item["evidenceKind"], item["assessment"]) == ("observed", "unknown")
        for item in tasks["items"]
    )
    assert [(item["principalId"], item["tasks"]) for item in principals["items"]] == [
        ("stray-principal", 1),
        ("unassigned-principal-canary", 1),
    ]
    assert tasks["receipt"]["projectionId"] == health["sources"][0]["projectionId"]
    # Declared tasks and their callers never appear.
    listed = json.dumps([tasks["items"], principals["items"]])
    assert "visible-task" not in listed and "hidden-root-canary" not in listed
    assert [item["taskId"] for item in second["items"]] == ["unassigned-task-canary"]
    assert (second["offset"], second["limit"], second["total"]) == (1, 1, 2)


def test_a_source_without_a_manifest_counts_every_task_and_says_no_manifest(
    neo4j_session, snapshot_factory
):
    snapshot = snapshot_factory()
    snapshot["source"]["companyId"] += uuid4().hex
    receipt = import_snapshot(neo4j_session, snapshot, snapshot["source"])
    (health,) = run(
        {"snapshot": snapshot, "receipt": receipt},
        [{"operation": "get_inventory_health", "args": {}}],
    )
    activity = health["sources"][0]["undeclaredActivity"]
    assert (activity["status"], activity["tasks"], activity["manifest"]) == (
        "complete",
        len(snapshot["tasks"]),
        "not_collected",
    )


def test_a_team_scoped_reader_sees_no_name_and_no_count(neo4j_session, reference_snapshot):
    case = publish(neo4j_session, reference_snapshot)
    source_id = case["receipt"].source_id
    outputs = run(
        case,
        [
            {"operation": "get_inventory_health", "args": {}},
            {"operation": "list_undeclared_activity", "args": {"sourceId": source_id}},
            {
                "operation": "list_undeclared_activity",
                "args": {"sourceId": source_id, "kind": "principals"},
            },
            {"operation": "list_unclaimed_identities", "args": {}},
        ],
        all_teams=False,
    )
    health, *notes = outputs
    assert health["sources"][0]["undeclaredActivity"] == {
        "status": "not_visible",
        "reason": "all_teams_required",
    }
    assert all(note == notes[0] for note in notes)
    assert set(notes[0]) == {"visibility", "status", "note"}
    text = json.dumps(outputs)
    assert not any(canary in text for canary in CANARIES)
    # The store itself refuses the read for this scope: no query runs.
    for request in ({"undeclared": True}, {"unclaimedIdentities": True}):
        refused = query(scope(case["snapshot"]), request=request)
        assert refused == {"ok": False, "code": "MAP_REQUEST_INVALID"}


def test_iam_identities_no_declared_binding_names_are_listed_as_candidates(
    neo4j_session, reference_snapshot
):
    case = publish(neo4j_session, reference_snapshot)
    account = case["account"]
    data, page = run(
        case,
        [
            {"operation": "list_unclaimed_identities", "args": {}},
            {"operation": "list_unclaimed_identities", "args": {"offset": 1, "limit": 1}},
        ],
    )
    assert (data["status"], data["reason"], data["total"], data["truncated"]) == (
        "complete",
        None,
        2,
        False,
    )
    assert [(item["arn"], item["kind"], item["path"]) for item in data["identities"]] == [
        (f"arn:aws:iam::{account}:role/service/batch-runner", "role", "/service/"),
        (f"arn:aws:iam::{account}:user/ci-deployer", "user", "/"),
    ]
    assert all(
        (item["candidate"], item["evidenceKind"], item["assessment"])
        == (True, "provider_inventory", "unknown")
        for item in data["identities"]
    )
    (collected,) = data["accounts"]
    assert (collected["accountId"], collected["status"], collected["observed"]) == (
        account,
        "complete",
        4,
    )
    assert (collected["unclaimed"], collected["stale"]) == (2, False)
    # Every execution binding in the manifest names an identity.
    assert data["bindingsWithoutIdentity"] is False
    assert [item["sourceId"] for item in data["declaredFrom"]] == [case["receipt"].source_id]
    assert "declared-" not in json.dumps(data["identities"])
    assert [item["name"] for item in page["identities"]] == ["ci-deployer"]


def test_stale_or_missing_aws_data_reads_unknown_and_lists_nothing(
    neo4j_session, reference_snapshot
):
    case = publish(neo4j_session, reference_snapshot)
    # The enrolled limit is 120 seconds; the capture is ten seconds old.
    (stale,) = run(
        case,
        [{"operation": "list_unclaimed_identities", "args": {}}],
        now=int(time.time()) + 200,
    )
    assert (stale["status"], stale["total"], stale["identities"]) == ("unknown", None, [])
    assert [(item["status"], item["reason"]) for item in stale["accounts"]] == [
        ("unknown", "stale")
    ]
    assert stale["accounts"][0]["observed"] is None
    assert not any(canary in json.dumps(stale) for canary in ("batch-runner", "ci-deployer"))

    uncollected = publish(neo4j_session, reference_snapshot, aws=False)
    (missing,) = run(uncollected, [{"operation": "list_unclaimed_identities", "args": {}}])
    assert (missing["status"], missing["reason"], missing["total"]) == (
        "unknown",
        "cloud_not_collected",
        None,
    )
    assert (missing["accounts"], missing["identities"]) == ([], [])
