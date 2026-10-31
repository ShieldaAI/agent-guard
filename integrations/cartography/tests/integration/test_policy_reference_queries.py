"""Real policy reducer, atomic publication and scoped TypeScript reference reads."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_reference_queries import query, scope
from test_reference_queries import reference_snapshot as reference_snapshot

from agent_guard_cartography import cloud as cloud_module
from agent_guard_cartography.aws_config import collection_id, validate_aws_enrollment
from agent_guard_cartography.aws_graph import publish_aws_capture
from agent_guard_cartography.aws_policy import capture_policy_evidence
from agent_guard_cartography.cloud import validate_cloud_scope
from agent_guard_cartography.graph import import_snapshot

pytestmark = pytest.mark.integration


@pytest.fixture
def policy_reference(neo4j_session, reference_snapshot):
    snapshot = deepcopy(reference_snapshot)
    account = str(uuid4().int % 10**12).zfill(12)
    bucket = f"reference-{uuid4().hex}"
    stamp = int(time.time()) - 10
    date = "2020-01-01T00:00:00Z"
    roles = []
    details = []
    for index, binding in enumerate(snapshot["manifest"]["executionBindings"]):
        name = "Reader" if index == 0 else "HiddenRoleCanary"
        arn = f"arn:aws:iam::{account}:role/{name}"
        binding["identity"].update(accountId=account, arn=arn)
        roles.append(
            {
                "arn": arn,
                "roleid": f"AROAEXAMPLE{index}",
                "name": name,
                "path": "/",
                "createdate": date,
                "createdate_dt": date,
            }
        )
        details.append(
            {
                "Arn": arn,
                "RoleId": f"AROAEXAMPLE{index}",
                "RoleName": name,
                "Path": "/",
                "CreateDate": datetime(2020, 1, 1, tzinfo=UTC),
                "AttachedManagedPolicies": [],
                "RolePolicyList": [
                    {
                        "PolicyName": "private-policy-name-canary",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": f"arn:aws:s3:::{bucket}/private-prefix-canary/*",
                                    "Condition": {
                                        "StringEquals": {
                                            "aws:PrincipalTag/team"
                                            if index == 0
                                            else "hidden-condition-canary": "private-condition-value-canary"
                                        }
                                    },
                                }
                            ],
                        },
                    }
                ],
            }
        )
    for binding in snapshot["manifest"]["resourceBindings"]:
        target = binding["target"]
        suffix = target["arn"].split("/", 1)[1]
        target.update(accountId=account, arn=f"arn:aws:s3:::{bucket}/{suffix}")
    config = validate_aws_enrollment(
        {
            "schemaVersion": 1,
            "companyId": snapshot["source"]["companyId"],
            "tenantId": snapshot["source"]["tenantId"],
            "partition": "aws",
            "accountId": account,
            "region": "us-east-1",
            "expectedCallerArn": f"arn:aws:sts::{account}:assumed-role/Reader/test",
            "accessKeyIdEnv": "TEST_KEY",
            "secretAccessKeyEnv": "TEST_SECRET",
            "sessionTokenEnv": "TEST_SESSION",
            "includeIamPolicyEvidence": True,
        }
    )
    capture = {
        "capturedAt": stamp,
        "roles": roles,
        "users": [],
        "buckets": [
            {
                "Name": bucket,
                "Arn": f"arn:aws:s3:::{bucket}",
                "Region": "us-east-1",
                "CreationDate": date,
            }
        ],
    }
    capture["policyEvidence"] = capture_policy_evidence(
        config,
        capture,
        lambda *_args, **_kwargs: {
            "RoleDetailList": details,
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": [],
            "IsTruncated": False,
        },
        lambda: None,
    )
    publish_aws_capture(neo4j_session, config, capture)
    cloud = validate_cloud_scope(
        {
            "companyId": snapshot["source"]["companyId"],
            "tenantId": snapshot["source"]["tenantId"],
            "accounts": [{"partition": "aws", "accountId": account}],
            "maxAgeSeconds": 120,
        }
    )
    receipt = import_snapshot(neo4j_session, snapshot, snapshot["source"], cloud_scope=cloud)
    return {
        "snapshot": snapshot,
        "config": config,
        "capture": capture,
        "details": details,
        "cloud": cloud,
        "receipt": receipt,
        "now": int(time.time()) * 1000,
        "bucket": bucket,
        "role": roles[0]["arn"],
        "collection": collection_id(config),
    }


def read_case(case, *, operations=None, request=None, now=None):
    source_id = case["receipt"].source_id
    return query(
        scope(case["snapshot"]),
        request=request or {"sourceId": source_id},
        operations=operations
        or [
            {
                "operation": "get_agent_access",
                "args": {"sourceId": source_id, "agentId": "visible-agent"},
            }
        ],
        now=case["now"] if now is None else now,
    )


def evidence(result):
    assert result["ok"] is True, result
    output = result["outputs"][0]
    assert output["ok"] is True, output
    return output["response"]["data"]["policyEvidence"]


def test_reducer_to_scoped_reference_exposes_only_bound_unknown_candidates(
    neo4j_session, policy_reference
):
    case = policy_reference
    neo4j_session.run(
        "MATCH (p:AWSRole {id:$role}),(b:AWSS3Bucket {id:$bucket}) "
        "CREATE (p)-[:CAN_READ {conditions:'raw-shared-policy-canary'}]->(b)",
        role=case["role"],
        bucket=case["bucket"],
    ).consume()
    result = read_case(case)
    (item,) = evidence(result)
    assert item["status"] == "complete" and item["assessment"] == "unknown", item
    assert item["action"] == "s3:GetObject"
    assert item["candidates"] == [
        {
            "relationship": "CAN_READ",
            "hasCondition": True,
            "conditionKeys": ["aws:PrincipalTag/team"],
            "resourceScope": "bucket_summary",
        }
    ]
    assert item["observedAt"] == datetime.fromtimestamp(
        case["capture"]["capturedAt"], UTC
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    wire = json.dumps(result)
    for forbidden in (
        "hidden-",
        "HiddenRoleCanary",
        "private-",
        "raw-shared-policy-canary",
        case["capture"]["policyEvidence"]["policyHash"],
        case["collection"],
    ):
        assert forbidden not in wire
    targets = [
        node
        for node in result["view"]["sources"][0]["current"]["nodes"]
        if node["label"] == "GuardExternalResource"
    ]
    assert targets[0]["properties"]["arn"].endswith("/visible.txt")
    assert targets[0]["properties"]["cloud_match_kind"] == "containment"


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_resource_case_correction_reaches_scoped_reference_after_refresh(
    neo4j_session, policy_reference, effect, monkeypatch
):
    case = policy_reference
    # Force the refreshed observations across a second boundary; the query
    # clock captured by the original fixture predates these observations.
    refreshed_at = case["now"] // 1000 + 1
    monkeypatch.setattr(cloud_module, "time", SimpleNamespace(time=lambda: refreshed_at))
    details = deepcopy(case["details"])
    statements = details[0]["RolePolicyList"][0]["PolicyDocument"]["Statement"]
    changed = {
        **statements[0],
        "Effect": effect,
        "Resource": f"arn:aws:s3:::{case['bucket'].upper()}/private-prefix-canary/*",
    }
    if effect == "Allow":
        statements[:] = [changed]
    else:
        statements.append(changed)
    capture = deepcopy(case["capture"])
    capture["capturedAt"] += 1
    capture["policyEvidence"] = capture_policy_evidence(
        case["config"],
        capture,
        lambda *_args, **_kwargs: {
            "RoleDetailList": details,
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": [],
            "IsTruncated": False,
        },
        lambda: None,
    )
    publish_aws_capture(neo4j_session, case["config"], capture)
    snapshot = deepcopy(case["snapshot"])
    snapshot["snapshotId"] = uuid4().hex
    snapshot["ledgerRevision"] += 1
    receipt = import_snapshot(
        neo4j_session, snapshot, snapshot["source"], cloud_scope=case["cloud"]
    )
    refreshed = {**case, "snapshot": snapshot, "receipt": receipt}
    # Preserve the fail-closed future-timestamp check, then read at the refresh
    # time. Reusing the fixture's old clock made this test depend on wall time.
    (future,) = evidence(read_case(refreshed))
    assert future["status"] == "unavailable" and future["reason"] == "changed", json.dumps(future)
    result = read_case(refreshed, now=refreshed_at * 1000)
    (item,) = evidence(result)
    assert item["status"] == "complete" and item["assessment"] == "unknown", json.dumps(item)
    if effect == "Allow":
        assert item["reason"] == "no_candidate" and item["candidates"] == []
    else:
        assert item["candidates"] == [
            {
                "relationship": "CAN_READ",
                "hasCondition": True,
                "conditionKeys": ["aws:PrincipalTag/team"],
                "resourceScope": "bucket_summary",
            }
        ]
    assert "private-" not in json.dumps(result) and "hidden-" not in json.dumps(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "provider_time",
        "provider_region",
        "membership_hash",
        "candidate_hash",
        "candidate_condition",
        "duplicate_candidate",
        "duplicate_membership",
        "marker_scope",
        "link_removed",
    ],
)
def test_changed_or_malformed_provider_evidence_never_returns_candidates(
    neo4j_session, policy_reference, mutation
):
    case = policy_reference
    queries = {
        "provider_time": "MATCH (p:AWSRole {id:$role}) SET p.lastupdated=p.lastupdated+1",
        "provider_region": "MATCH (b:AWSS3Bucket {id:$bucket}) SET b.region='eu-west-1'",
        "membership_hash": "MATCH (:GuardAwsCollection {id:$collection})-[r:G_AWS_OBSERVED]->(:AWSRole {id:$role}) SET r.capture_hash=$bad",
        "candidate_hash": "MATCH (:AWSRole {id:$role})-[r:G_AWS_POLICY_CANDIDATE {collection_id:$collection}]->() SET r.policy_hash=$bad",
        "candidate_condition": "MATCH (:AWSRole {id:$role})-[r:G_AWS_POLICY_CANDIDATE {collection_id:$collection}]->() SET r.has_condition=false",
        "duplicate_candidate": "MATCH (p:AWSRole {id:$role})-[r:G_AWS_POLICY_CANDIDATE {collection_id:$collection}]->(b) CREATE (p)-[copy:G_AWS_POLICY_CANDIDATE]->(b) SET copy=properties(r)",
        "duplicate_membership": "MATCH (c:GuardAwsCollection {id:$collection})-[r:G_AWS_OBSERVED]->(p:AWSRole {id:$role}) CREATE (c)-[copy:G_AWS_OBSERVED]->(p) SET copy=properties(r)",
        "marker_scope": "MATCH (c:GuardAwsCollection {id:$collection}) SET c.tenant_id='unrelated-tenant'",
        "link_removed": "MATCH (n:GuardExternalIdentity {projection_id:$projection})-[r:G_CLOUD_MATCH]->() DELETE r",
    }
    neo4j_session.run(
        queries[mutation],
        role=case["role"],
        bucket=case["bucket"],
        collection=case["collection"],
        projection=case["receipt"].projection_id,
        bad="f" * 64,
    ).consume()
    result = read_case(case)
    if not result["ok"]:
        assert result["code"] == "MAP_UNAVAILABLE"
    else:
        rows = evidence(result)
        assert rows and all(row["status"] != "complete" and row["candidates"] == [] for row in rows)


def test_policy_freshness_uses_enrolled_scope_even_before_default_reader_limit(policy_reference):
    result = read_case(
        policy_reference, now=(policy_reference["capture"]["capturedAt"] + 121) * 1000
    )
    (item,) = evidence(result)
    assert item["status"] == "unavailable" and item["reason"] == "stale"
    assert item["candidates"] == []


def test_policy_refresh_waits_for_guard_joins_and_opt_out_is_visible(
    neo4j_session, policy_reference
):
    case = policy_reference
    updated = deepcopy(case["capture"])
    updated["capturedAt"] += 1
    updated["policyEvidence"]["edges"] = []
    updated["policyEvidence"]["policyHash"] = "e" * 64
    publish_aws_capture(neo4j_session, case["config"], updated)
    (changed,) = evidence(read_case(case))
    assert changed["status"] == "unavailable" and changed["candidates"] == []
    updated.pop("policyEvidence")
    updated["capturedAt"] += 1
    publish_aws_capture(
        neo4j_session, replace(case["config"], include_iam_policy_evidence=False), updated
    )
    (disabled,) = evidence(read_case(case))
    assert disabled["status"] in ("not_collected", "unavailable")
    assert disabled["candidates"] == []


def test_other_collection_candidate_and_shared_cartography_edge_cannot_fill_missing_candidate(
    neo4j_session, policy_reference
):
    case = policy_reference
    neo4j_session.run(
        "MATCH (p:AWSRole {id:$role})-[r:G_AWS_POLICY_CANDIDATE {collection_id:$collection}]->(b) "
        "SET r.collection_id='other-collection-canary' "
        "CREATE (p)-[:CAN_READ {has_condition:false,conditions:'private-canary'}]->(b)",
        role=case["role"],
        collection=case["collection"],
    ).consume()
    (item,) = evidence(read_case(case))
    assert item["status"] == "complete" and item["reason"] == "no_candidate"
    assert item["candidates"] == [] and item["assessment"] == "unknown"


def test_live_policy_observations_are_omitted_from_snapshot_history(policy_reference):
    case = policy_reference
    result = read_case(
        case,
        request={"sourceId": case["receipt"].source_id, "history": True},
        operations=[{"operation": "get_changes", "args": {"sourceId": case["receipt"].source_id}}],
    )
    assert result["ok"] is True
    assert not result["view"]["sources"][0]["current"].get("policyEvidence")
    assert result["outputs"][0]["response"]["data"]["policyHistory"] == "not_collected"


def test_explanation_lookup_and_hidden_agent_share_the_same_scoped_candidates(policy_reference):
    case = policy_reference
    source = case["receipt"].source_id
    operations = [
        {
            "operation": "explain_access",
            "args": {
                "sourceId": source,
                "taskId": "visible-task",
                "tool": "records.read",
                "resourceId": "report-A",
            },
        },
        {
            "operation": "find_agents_with_access",
            "args": {"sourceId": source, "resourceRef": "report-A", "action": "s3:GetObject"},
        },
        {
            "operation": "get_agent_access",
            "args": {"sourceId": source, "agentId": "hidden-agent-canary"},
        },
        {"operation": "get_agent_access", "args": {"sourceId": source, "agentId": "absent-agent"}},
    ]
    result = read_case(case, operations=operations)
    explanation, lookup, hidden, absent = result["outputs"]
    assert explanation["ok"] is True and lookup["ok"] is True
    rows = explanation["response"]["data"]["externalEvidence"]["policyEvidence"]
    assert len(rows) == 1 and rows[0]["candidates"][0]["relationship"] == "CAN_READ"
    candidates = lookup["response"]["data"]["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["evidence"][0]["policyEvidence"] == rows
    assert hidden == absent == {"ok": False, "code": "MAP_NOT_FOUND"}
    assert "hidden-" not in json.dumps(result)


def test_valid_long_host_action_is_explicitly_unsupported_not_an_api_failure(
    neo4j_session, policy_reference
):
    case = policy_reference
    action = "s3:" + "A" * 300
    neo4j_session.run(
        "MATCH (n:GuardResourceBinding {projection_id:$projection,binding_id:'visible-resource'}) SET n.actions=[$action]",
        projection=case["receipt"].projection_id,
        action=action,
    ).consume()
    (item,) = evidence(read_case(case))
    assert item["action"] == action and item["status"] == "not_collected"
    assert item["reason"] == "unsupported_action" and item["candidates"] == []


def test_shared_tool_and_selector_do_not_borrow_another_visible_deployment_identity(
    neo4j_session, policy_reference
):
    case = policy_reference
    updated = deepcopy(case["snapshot"])
    updated["snapshotId"] = uuid4().hex
    updated["ledgerRevision"] += 1
    updated["manifest"]["revision"] += 1
    updated["manifest"]["agents"][1]["teamId"] = "visible-team"
    updated["manifest"]["executionBindings"][1]["tool"] = "records.read"
    inventory = updated["mcp"]["connections"][0]["inventory"]
    inventory["revision"] += 1
    inventory["operations"] = [
        operation for operation in inventory["operations"] if operation["name"] == "records.read"
    ]
    # Both visible tasks now have the same tool and the same declared selector,
    # but each deployment retains its own independently captured execution role.
    receipt = import_snapshot(neo4j_session, updated, updated["source"], cloud_scope=case["cloud"])
    case = {**case, "snapshot": updated, "receipt": receipt, "now": int(time.time()) * 1000}
    source = receipt.source_id
    result = read_case(
        case,
        operations=[
            {
                "operation": "explain_access",
                "args": {
                    "sourceId": source,
                    "taskId": "visible-task",
                    "tool": "records.read",
                    "resourceId": "report-A",
                },
            },
            {
                "operation": "explain_access",
                "args": {
                    "sourceId": source,
                    "taskId": "hidden-root-canary",
                    "tool": "records.read",
                    "resourceId": "report-A",
                },
            },
        ],
    )
    assert result["ok"] is True, result
    output = result["outputs"][0]
    assert output["ok"] is True, output
    (item,) = output["response"]["data"]["externalEvidence"]["policyEvidence"]
    assert item["candidates"][0]["conditionKeys"] == ["aws:PrincipalTag/team"]
    assert "hidden-condition-canary" not in json.dumps(output)
    other = result["outputs"][1]
    assert other["ok"] is True, other
    (other_item,) = other["response"]["data"]["externalEvidence"]["policyEvidence"]
    assert other_item["candidates"][0]["conditionKeys"] == ["hidden-condition-canary"]


@pytest.mark.parametrize(
    "mutation",
    [
        "agent_team",
        "deployment_agent",
        "execution_identity",
        "duplicate_assignment",
        "duplicate_agent",
        "duplicate_executor_deployment",
        "duplicate_executor_tool",
        "duplicate_identity",
        "duplicate_grant_tool",
        "duplicate_binding_selector",
        "duplicate_binding_resource",
        "duplicate_task_grant",
        "duplicate_grant_selector",
    ],
)
def test_committed_binding_changes_between_policy_reads_reject_the_whole_response(
    neo4j_session, policy_reference, mutation
):
    case = policy_reference
    updated = deepcopy(case["snapshot"])
    updated["snapshotId"] = uuid4().hex
    updated["ledgerRevision"] += 1
    updated["manifest"]["revision"] += 1
    updated["manifest"]["agents"][1]["teamId"] = "visible-team"
    receipt = import_snapshot(neo4j_session, updated, updated["source"], cloud_scope=case["cloud"])
    case = {**case, "snapshot": updated, "receipt": receipt, "now": int(time.time()) * 1000}

    # A second authorized agent keeps this source selected even after the first
    # agent leaves the team. Unchanged source pointers must not mask path drift.
    baseline = read_case(case)
    (candidate,) = evidence(baseline)
    assert candidate["status"] == "complete" and candidate["candidates"]
    agents = {
        node["properties"]["agent_id"]
        for node in baseline["view"]["sources"][0]["current"]["nodes"]
        if node["label"] == "GuardAgent"
    }
    assert agents == {"visible-agent", "hidden-agent-canary"}

    root = Path(__file__).resolve().parents[4]
    node = shutil.which("node")
    assert node is not None
    process = subprocess.run(
        [node, str(Path(__file__).parents[1] / "fixtures" / "query-policy-race.mjs")],
        input=json.dumps(
            {
                "scope": scope(updated),
                "request": {"sourceId": receipt.source_id},
                "now": case["now"],
                "mutation": mutation,
            }
        ),
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr
    password = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())["password"]
    assert password not in process.stdout + process.stderr
    assert json.loads(process.stdout) == {
        "result": {"ok": False, "code": "MAP_UNAVAILABLE"},
        "mutationCount": 1,
        "proofs": [[True], [False]],
        "sourceReads": 2,
        "sourcePointersUnchanged": True,
    }
