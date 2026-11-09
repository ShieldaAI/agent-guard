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


def publish(neo4j_session, reference_snapshot, statements, extra_buckets=2, policy=True):
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
                            "Statement": statements(bound) if index == 0 else [],
                        },
                    }
                ],
            }
        )
    for binding in snapshot["manifest"]["resourceBindings"]:
        suffix = binding["target"]["arn"].split("/", 1)[1]
        binding["target"].update(accountId=account, arn=f"arn:aws:s3:::{bound}/{suffix}")
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
    assert [extra["bucketName"] for extra in item["extraResources"]] == case["extras"]
    assert all(
        extra["relationship"] == "CAN_READ" and extra["hasCondition"] is False
        for extra in item["extraResources"]
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

    case = publish(neo4j_session, reference_snapshot, scoped)
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
    (item,) = identity_scope(case)[1]["response"]["data"]["outsideGuard"]["identityScope"]
    assert item["status"] == "broader_than_grants"
    (extra,) = item["extraResources"]
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
