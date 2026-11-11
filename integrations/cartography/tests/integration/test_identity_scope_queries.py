"""C2 identity scope: real policy reducer -> Neo4j -> scoped reverse identity reads."""

from __future__ import annotations

import time
from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from test_reference_queries import query, scope
from test_reference_queries import reference_snapshot as reference_snapshot

from agent_guard_cartography.aws_config import validate_aws_enrollment
from agent_guard_cartography.aws_graph import publish_aws_capture
from agent_guard_cartography.aws_policy import capture_policy_evidence
from agent_guard_cartography.cloud import validate_cloud_scope
from agent_guard_cartography.graph import import_snapshot

pytestmark = pytest.mark.integration
DATE = "2020-01-01T00:00:00Z"


def publish(
    neo4j_session,
    reference_snapshot,
    statements,
    extra_buckets=2,
    policy=True,
    hidden_statements=None,
    whole_bucket=False,
    wildcard_tool=None,
    own_root=True,
):
    """The visible role gets `statements`; the account holds the bound bucket plus extras."""
    snapshot = deepcopy(reference_snapshot)
    # A separate company scope per publish, so one test can publish twice.
    snapshot["source"]["companyId"] += "-" + uuid4().hex[:8]
    snapshot["manifest"]["source"] = dict(snapshot["source"])
    account = str(uuid4().int % 10**12).zfill(12)
    bound = f"bound-{uuid4().hex[:20]}"
    extras = sorted(f"extra-{index}-{uuid4().hex[:16]}" for index in range(extra_buckets))
    roles, details = [], []
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
                "createdate": DATE,
                "createdate_dt": DATE,
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
                            "Statement": statements(bound)
                            if index == 0
                            else (hidden_statements(bound) if hidden_statements else []),
                        },
                    }
                ],
            }
        )
    if own_root:
        # The visible task starts its own family, so a team reader can follow its whole
        # chain; otherwise its hidden root leaves the grant's liveness unknown.
        task = next(task for task in snapshot["tasks"] if task["id"] == "visible-task")
        task.update(parentTaskId=None, familyId="visible-task")
    if wildcard_tool:
        # A `*` grant on the visible task, so boundary reads ask which bindings are sensitive.
        task = next(task for task in snapshot["tasks"] if task["id"] == "visible-task")
        task["grants"].append({"tool": wildcard_tool, "resources": ["*"]})
    for binding in snapshot["manifest"]["resourceBindings"]:
        suffix = binding["target"]["arn"].split("/", 1)[1]
        # The hidden agent's tool is bound to the first extra bucket, so its identity
        # reaching the visible bucket is reach outside the guard.
        bucket = extras[0] if "hidden" in binding["id"] and extras else bound
        if whole_bucket and "hidden" not in binding["id"]:
            binding["target"].update(accountId=account, arn=f"arn:aws:s3:::{bucket}", kind="bucket")
        else:
            binding["target"].update(accountId=account, arn=f"arn:aws:s3:::{bucket}/{suffix}")
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
            "includeIamPolicyEvidence": policy,
        }
    )
    capture = {
        "capturedAt": int(time.time()) - 10,
        "roles": roles,
        "users": [],
        "buckets": [
            {
                "Name": name,
                "Arn": f"arn:aws:s3:::{name}",
                "Region": "us-east-1",
                "CreationDate": DATE,
            }
            for name in [bound, *extras]
        ],
    }
    if policy:
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
    return {"snapshot": snapshot, "receipt": receipt, "bound": bound, "extras": extras}


def identity_scope(case, *, agent="visible-agent", all_teams=False):
    source_id = case["receipt"].source_id
    result = query(
        scope(case["snapshot"], all_teams=all_teams),
        request={"sourceId": source_id, "agentId": agent},
        operations=[
            {"operation": "get_agent_access", "args": {"sourceId": source_id, "agentId": agent}}
        ],
        now=int(time.time()) * 1000,
    )
    assert result["ok"] is True, result
    output = result["outputs"][0]
    return result, output


def broad(bound):
    return [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]


def test_an_identity_reaching_every_bucket_lists_each_unbound_bucket(
    neo4j_session, reference_snapshot
):
    case = publish(neo4j_session, reference_snapshot, broad)
    result, output = identity_scope(case)
    assert output["ok"] is True, output
    (item,) = output["response"]["data"]["outsideGuard"]["identityScope"]
    assert item["status"] == "broader_than_grants", item
    assert item["boundBuckets"] == [case["bound"]]
    # Neither extra is mapped by a binding in this team's scope (the first belongs to the
    # hidden team, the second to nobody): a team reader gets a note, no names, no count.
    assert item["extraResources"] == []
    assert item["notes"] == ["evidence_outside_visible_scope"]
    assert not any(name in str(result) for name in case["extras"])
    _, everyone = identity_scope(case, all_teams=True)
    (full,) = everyone["response"]["data"]["outsideGuard"]["identityScope"]
    assert [extra["bucketName"] for extra in full["extraResources"]] == case["extras"]
    assert "notes" not in full
    assert all(
        extra["relationship"] == "CAN_READ" and extra["hasCondition"] is False
        for extra in full["extraResources"]
    )
    wire = str(result)
    for forbidden in ("HiddenRoleCanary", "private-policy-name-canary", "hidden-canary-execution"):
        assert forbidden not in wire


def test_a_policy_limited_to_the_bound_bucket_matches_and_conditions_are_kept(
    neo4j_session, reference_snapshot
):
    def scoped(bound):
        return [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bound}/*"},
        ]

    # The tool binds one object; a bucket-level candidate may reach past it.
    case = publish(neo4j_session, reference_snapshot, scoped)
    (item,) = identity_scope(case)[1]["response"]["data"]["outsideGuard"]["identityScope"]
    assert (item["status"], item["reason"], item["extraResources"]) == (
        "unknown",
        "binding_narrower_than_candidate",
        [],
    )
    # Bound as the whole bucket, the same policy matches the grants.
    case = publish(neo4j_session, reference_snapshot, scoped, whole_bucket=True)
    (item,) = identity_scope(case)[1]["response"]["data"]["outsideGuard"]["identityScope"]
    assert (item["status"], item["extraResources"]) == ("matches_grants", [])

    def conditional(bound):
        return [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": "research"}},
            }
        ]

    case = publish(neo4j_session, reference_snapshot, conditional, extra_buckets=1)
    (item,) = identity_scope(case, all_teams=True)[1]["response"]["data"]["outsideGuard"][
        "identityScope"
    ]
    assert item["status"] == "broader_than_grants"
    (extra,) = item["extraResources"]
    assert extra["bucketName"] == case["extras"][0]
    assert (extra["hasCondition"], extra["conditionKeys"]) == (True, ["aws:PrincipalTag/team"])


def test_disabled_policy_evidence_is_unknown(neo4j_session, reference_snapshot):
    case = publish(neo4j_session, reference_snapshot, broad, policy=False)
    (item,) = identity_scope(case)[1]["response"]["data"]["outsideGuard"]["identityScope"]
    assert (item["status"], item["reason"], item["extraResources"]) == (
        "unknown",
        "disabled",
        [],
    )


def test_a_team_reader_never_sees_another_teams_identity_scope(neo4j_session, reference_snapshot):
    case = publish(neo4j_session, reference_snapshot, broad)
    _, hidden = identity_scope(case, agent="hidden-agent-canary")
    assert hidden == {"ok": False, "code": "MAP_NOT_FOUND"}
    _, visible = identity_scope(case, all_teams=True)
    (item,) = visible["response"]["data"]["outsideGuard"]["identityScope"]
    assert item["executionBindingId"] != "hidden-canary-execution"


def resources(case, *, all_teams=False):
    source_id = case["receipt"].source_id
    result = query(
        scope(case["snapshot"], all_teams=all_teams),
        request={"sourceId": source_id},
        operations=[
            {"operation": "list_resources", "args": {"sourceId": source_id}},
            {
                "operation": "get_resource_access",
                "args": {"sourceId": source_id, "resourceId": "visible-resource"},
            },
        ],
        now=int(time.time()) * 1000,
    )
    assert result["ok"] is True, result
    listing, detail = (item["response"]["data"] for item in result["outputs"])
    return {row["bindingId"]: row["outsideGuard"] for row in listing["resources"]}, detail, result


def test_another_tool_identity_reaching_a_bound_bucket_is_reach_outside_the_guard(
    neo4j_session, reference_snapshot
):
    case = publish(neo4j_session, reference_snapshot, broad, hidden_statements=broad)
    column, detail, _ = resources(case, all_teams=True)
    assert column["visible-resource"] == "yes"
    (identity,) = detail["outsideGuard"]["identities"]
    assert (identity["tool"], identity["relationship"]) == ("records.delete", "CAN_READ")
    assert detail["outsideGuard"]["status"] == "yes"

    # A team reader sees neither the other team's identity nor any count of it. A v1
    # manifest declares no direct paths, so the column is unknown, never none_found.
    column, detail, wire = resources(case)
    assert column == {"visible-resource": "unknown"}
    assert detail["outsideGuard"]["identities"] == []
    assert "direct_access_undeclared" in detail["outsideGuard"]["unknownReasons"]
    assert "outside_visible_scope" in detail["outsideGuard"]["unknownReasons"]
    assert "records.delete" not in str(wire) and "HiddenRoleCanary" not in str(wire)


def test_a_bucket_bound_by_another_agent_of_the_same_scope_is_listed(
    neo4j_session, reference_snapshot
):
    """Withholding follows the reader's teams, not the agents in this one-agent read."""
    case = publish(neo4j_session, reference_snapshot, broad)
    source_id = case["receipt"].source_id
    reader = {
        **scope(case["snapshot"]),
        "teamIds": ["visible-team", "hidden-team"],
    }
    result = query(
        reader,
        request={"sourceId": source_id, "agentId": "visible-agent"},
        operations=[
            {
                "operation": "get_agent_access",
                "args": {"sourceId": source_id, "agentId": "visible-agent"},
            }
        ],
        now=int(time.time()) * 1000,
    )
    assert result["ok"] is True, result
    (item,) = result["outputs"][0]["response"]["data"]["outsideGuard"]["identityScope"]
    names = [extra["bucketName"] for extra in item["extraResources"]]
    assert case["extras"][0] in names, "the other agent's bucket is in this reader's scope"


def test_a_grant_on_a_task_whose_root_is_hidden_is_unknown_to_a_team_reader(
    neo4j_session, reference_snapshot
):
    """The executor refuses a task whose ancestor is revoked; a team reader cannot see the
    hidden root, so the grant's liveness, and the identity comparison, are unknown."""
    case = publish(neo4j_session, reference_snapshot, broad, own_root=False)
    (item,) = identity_scope(case)[1]["response"]["data"]["outsideGuard"]["identityScope"]
    assert (item["status"], item["reason"], item["extraResources"]) == (
        "unknown",
        "grant_lineage_unknown",
        [],
    )
