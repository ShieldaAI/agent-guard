"""Atomic canonical AWS metadata and managed cloud joins in an owned Neo4j graph."""

import json
import time
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime

import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from test_cloud_graph import cloud_edges, cloud_nodes, import_case, next_snapshot, seed
from test_cloud_graph import cloud_snapshot as cloud_snapshot

import agent_guard_cartography.aws_graph as aws_graph
from agent_guard_cartography.aws_capture import capture_from_clients
from agent_guard_cartography.aws_config import (
    AwsCollectionError,
    collection_id,
    validate_aws_enrollment,
)
from agent_guard_cartography.aws_graph import publish_aws_capture
from agent_guard_cartography.graph import import_snapshot

pytestmark = pytest.mark.integration


def enrollment(case):
    _, scope, account, *_ = case
    return validate_aws_enrollment(
        {
            "schemaVersion": 1,
            "companyId": scope.company_id,
            "tenantId": scope.tenant_id,
            "partition": "aws",
            "accountId": account,
            "region": "us-east-1",
            "expectedCallerArn": f"arn:aws:sts::{account}:assumed-role/Reader/collector",
            "accessKeyIdEnv": "TEST_KEY",
            "secretAccessKeyEnv": "TEST_SECRET",
            "sessionTokenEnv": "TEST_SESSION",
        }
    )


def capture(case, stamp=None):
    _, _, account, bucket, role = case
    stamp = int(time.time()) - 10 if stamp is None else stamp
    date = "2020-01-01T00:00:00Z"
    return {
        "capturedAt": stamp,
        "roles": [
            {
                "arn": role,
                "roleid": "AROATEST",
                "name": role.rsplit("/", 1)[1],
                "path": "/",
                "createdate": date,
                "createdate_dt": date,
            }
        ],
        "users": [
            {
                "arn": f"arn:aws:iam::{account}:user/reader",
                "userid": "AIDATEST",
                "name": "reader",
                "path": "/",
                "createdate": date,
                "createdate_dt": date,
                "passwordlastused": "",
                "passwordlastused_dt": None,
            }
        ],
        "buckets": [
            {
                "Name": bucket,
                "Arn": f"arn:aws:s3:::{bucket}",
                "Region": "eu-west-1",
                "CreationDate": date,
            }
        ],
    }


def state(session, config):
    row = session.run(
        "MATCH (c:GuardAwsCollection {id:$id}) OPTIONAL MATCH (c)-[m:G_AWS_OBSERVED]->(p) RETURN properties(c) AS collection,collect({id:p.id,properties:properties(p),membership:properties(m)}) AS nodes",
        id=collection_id(config),
    ).single()
    return dict(row) if row else None


@pytest.mark.parametrize("policy_enabled", [False, True])
def test_stubbed_sdk_to_cartography_to_scoped_guard_join_excludes_private_provider_data(
    neo4j_session, cloud_snapshot, policy_enabled
):
    config = replace(enrollment(cloud_snapshot), include_iam_policy_evidence=policy_enabled)
    date = datetime(2020, 1, 1, tzinfo=UTC)
    account, bucket, role = cloud_snapshot[2:]
    sdk = botocore.session.get_session()
    with ExitStack() as stack:
        clients = {}
        stubs = {}
        for name in ("sts", "iam", "s3"):
            endpoint = (
                "https://iam.amazonaws.com"
                if name == "iam"
                else f"https://{name}.us-east-1.amazonaws.com"
            )
            client = sdk.create_client(
                name,
                region_name="us-east-1",
                endpoint_url=endpoint,
                aws_access_key_id="fixture-key-canary",
                aws_secret_access_key="fixture-secret-canary",
                aws_session_token="fixture-session-canary",
                config=Config(proxies={}),
            )
            clients[name] = client
            stack.callback(client.close)
            stubs[name] = stack.enter_context(Stubber(client))
        stubs["sts"].add_response(
            "get_caller_identity",
            {"Account": account, "Arn": config.expected_caller_arn, "UserId": "fixture-user"},
            {},
        )
        stubs["iam"].add_response(
            "list_roles",
            {
                "IsTruncated": False,
                "Roles": [
                    {
                        "Arn": role,
                        "RoleName": role.rsplit("/", 1)[1],
                        "RoleId": "AROABCDEFGHIJKLMNOPQ",
                        "Path": "/",
                        "CreateDate": date,
                        "Description": "private-description-canary",
                        "AssumeRolePolicyDocument": '{"private":"trust-policy-canary"}',
                    }
                ],
            },
            {"MaxItems": 1000},
        )
        stubs["iam"].add_response(
            "list_users", {"IsTruncated": False, "Users": []}, {"MaxItems": 1000}
        )
        if policy_enabled:
            stubs["iam"].add_response(
                "get_account_authorization_details",
                {
                    "IsTruncated": False,
                    "RoleDetailList": [
                        {
                            "Arn": role,
                            "RoleName": role.rsplit("/", 1)[1],
                            "RoleId": "AROABCDEFGHIJKLMNOPQ",
                            "Path": "/",
                            "CreateDate": date,
                            "AssumeRolePolicyDocument": '{"private":"trust-policy-canary"}',
                            "RolePolicyList": [
                                {
                                    "PolicyName": "PrivateRead",
                                    "PolicyDocument": json.dumps(
                                        {
                                            "Version": "2012-10-17",
                                            "Statement": {
                                                "Effect": "Allow",
                                                "Action": "s3:GetObject",
                                                "Resource": f"arn:aws:s3:::{bucket}/private/*",
                                                "Condition": {
                                                    "StringEquals": {
                                                        "aws:PrincipalTag/team": "private-condition-canary"
                                                    }
                                                },
                                            },
                                        }
                                    ),
                                }
                            ],
                        }
                    ],
                    "UserDetailList": [],
                    "GroupDetailList": [],
                    "Policies": [],
                },
                {
                    "Filter": ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"],
                    "MaxItems": 100,
                },
            )
        stubs["s3"].add_response(
            "list_buckets",
            {"Buckets": [{"Name": bucket, "CreationDate": date, "BucketRegion": "eu-west-1"}]},
            {"MaxBuckets": 1000},
        )
        stubs["s3"].add_response(
            "get_bucket_location",
            {"LocationConstraint": "eu-west-1"},
            {"Bucket": bucket, "ExpectedBucketOwner": account},
        )
        captured = capture_from_clients(config, clients)
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    assert "canary" not in json.dumps(captured)
    receipt = publish_aws_capture(neo4j_session, config, captured)
    assert receipt["status"] == "complete"
    assert "canary" not in json.dumps(state(neo4j_session, config), default=str)
    result = import_case(neo4j_session, cloud_snapshot)
    assert len(cloud_edges(neo4j_session, result.projection_id)) == 4
    assert {item["cloud_status"] for item in cloud_nodes(neo4j_session, result.projection_id)} == {
        "resolved"
    }
    assert (
        neo4j_session.run(
            "MATCH (:AWSRole {id:$role})-[r:CAN_READ|CAN_WRITE|CAN_LIST]->() RETURN count(r) AS count",
            role=role,
        ).single()["count"]
        == 0
    )
    assert neo4j_session.run(
        "MATCH (:AWSRole {id:$role})-[r:G_AWS_POLICY_CANDIDATE {collection_id:$id}]->() "
        "RETURN count(r) AS count",
        role=role,
        id=collection_id(config),
    ).single()["count"] == int(policy_enabled)


def test_complete_capture_uses_canonical_provider_nodes_and_existing_scoped_joins(
    neo4j_session, cloud_snapshot
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    receipt = publish_aws_capture(neo4j_session, config, data)
    assert receipt == {
        "status": "complete",
        "collectionId": collection_id(config),
        "capturedAt": data["capturedAt"],
        "roles": 1,
        "users": 1,
        "buckets": 1,
        "assessment": "unknown",
        "idempotent": False,
    }
    labels = neo4j_session.run(
        "MATCH (r:AWSRole {id:$id}) RETURN labels(r) AS labels", id=cloud_snapshot[4]
    ).single()["labels"]
    assert {"AWSPrincipal", "PermissionRole", "AWSRole"} <= set(labels)
    assert len(state(neo4j_session, config)["nodes"]) == 3
    result = import_case(neo4j_session, cloud_snapshot)
    assert len(cloud_edges(neo4j_session, result.projection_id)) == 4
    assert {n["cloud_status"] for n in cloud_nodes(neo4j_session, result.projection_id)} == {
        "resolved"
    }
    assert {n["cloud_assessment"] for n in cloud_nodes(neo4j_session, result.projection_id)} == {
        "unknown"
    }


def test_idempotency_rollback_conflict_and_enrollment_drift_do_not_mutate(
    neo4j_session, cloud_snapshot
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    previous = state(neo4j_session, config)
    assert publish_aws_capture(neo4j_session, config, data)["idempotent"] is True
    for changed, code in [
        ({**data, "capturedAt": data["capturedAt"] - 1}, "AWS_CAPTURE_ROLLBACK"),
        ({**data, "roles": []}, "AWS_CAPTURE_CONFLICT"),
    ]:
        with pytest.raises(AwsCollectionError, match=f"^{code}$"):
            publish_aws_capture(neo4j_session, config, changed)
    with pytest.raises(AwsCollectionError, match="^AWS_ENROLLMENT_CONFLICT$"):
        publish_aws_capture(neo4j_session, replace(config, region="eu-west-1"), data)
    assert state(neo4j_session, config) == previous


def test_publication_failure_rolls_back_partial_canonical_writes_and_membership(
    neo4j_session, cloud_snapshot, monkeypatch
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    previous = state(neo4j_session, config)
    original = aws_graph.build_ingestion_query

    def fail(schema):
        if schema.label == "AWSUser":
            raise RuntimeError("private-canary")
        return original(schema)

    monkeypatch.setattr(aws_graph, "build_ingestion_query", fail)
    with pytest.raises(AwsCollectionError, match="^AWS_PUBLICATION_FAILED$"):
        publish_aws_capture(neo4j_session, config, {**data, "capturedAt": data["capturedAt"] + 1})
    assert state(neo4j_session, config) == previous
    assert (
        neo4j_session.run(
            "MATCH (a:AWSAccount {id:$id}) RETURN a.lastupdated AS stamp", id=config.account_id
        ).single()["stamp"]
        == data["capturedAt"]
    )


def test_empty_capture_retires_only_owned_membership_preserving_shared_providers_and_guard(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    first = import_case(neo4j_session, cloud_snapshot)
    before = neo4j_session.run(
        "MATCH (n {projection_id:$id}) RETURN count(n) AS count", id=first.projection_id
    ).single()["count"]
    empty = {"capturedAt": data["capturedAt"] + 1, "roles": [], "users": [], "buckets": []}
    publish_aws_capture(neo4j_session, config, empty)
    assert (
        neo4j_session.run(
            "MATCH (n {projection_id:$id}) RETURN count(n) AS count", id=first.projection_id
        ).single()["count"]
        == before
    )
    assert len(cloud_edges(neo4j_session, first.projection_id)) == 4
    sentinel = neo4j_session.run(
        "MATCH (r:AWSRole {id:$role})-[p:CAN_READ]->(b:AWSS3Bucket {id:$bucket}) RETURN r.sentinel AS role,b.sentinel AS bucket,p.conditions AS conditions",
        role=cloud_snapshot[4],
        bucket=cloud_snapshot[3],
    ).single()
    assert dict(sentinel) == {
        "role": "provider-role",
        "bucket": "provider-bucket",
        "conditions": "private-condition-canary",
    }
    second = next_snapshot(cloud_snapshot[0])
    result = import_snapshot(neo4j_session, second, second["source"], cloud_scope=cloud_snapshot[1])
    assert cloud_edges(neo4j_session, result.projection_id) == []
    assert {n["cloud_reason"] for n in cloud_nodes(neo4j_session, result.projection_id)} == {
        "missing"
    }


def test_bucket_ownership_conflict_preserves_unrelated_account_and_never_enrolls(
    neo4j_session, cloud_snapshot
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    neo4j_session.run(
        "CREATE (a:AWSAccount {id:$account,sentinel:'other'}) CREATE (b:AWSS3Bucket {id:$bucket,arn:$arn}) CREATE (a)-[:RESOURCE]->(b)",
        account="other-" + config.account_id,
        bucket=cloud_snapshot[3],
        arn=data["buckets"][0]["Arn"],
    ).consume()
    with pytest.raises(AwsCollectionError, match="^AWS_PROVIDER_CONFLICT$"):
        publish_aws_capture(neo4j_session, config, data)
    assert state(neo4j_session, config) is None
    assert (
        neo4j_session.run(
            "MATCH (:AWSAccount {id:$id}) RETURN count(*) AS count", id=config.account_id
        ).single()["count"]
        == 0
    )
    assert (
        neo4j_session.run(
            "MATCH (:AWSAccount {id:$id,sentinel:'other'})-[:RESOURCE]->(:AWSS3Bucket {id:$bucket}) RETURN count(*) AS count",
            id="other-" + config.account_id,
            bucket=cloud_snapshot[3],
        ).single()["count"]
        == 1
    )


def test_independent_provider_refresh_does_not_renew_managed_collection_freshness(
    neo4j_session, cloud_snapshot
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    data["capturedAt"] = int(time.time()) - 10_000
    publish_aws_capture(neo4j_session, config, data)
    neo4j_session.run(
        "MATCH (a:AWSAccount {id:$id})-[r:RESOURCE]->(p) SET a.lastupdated=$stamp,r.lastupdated=$stamp,p.lastupdated=$stamp",
        id=config.account_id,
        stamp=int(time.time()),
    ).consume()
    result = import_case(neo4j_session, cloud_snapshot)
    assert cloud_edges(neo4j_session, result.projection_id) == []
    assert {n["cloud_reason"] for n in cloud_nodes(neo4j_session, result.projection_id)} == {
        "stale"
    }


def test_membership_change_between_cloud_capture_and_publication_drops_new_links(
    neo4j_session, cloud_snapshot
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)

    def remove_membership():
        publish_aws_capture(
            neo4j_session,
            config,
            {"capturedAt": data["capturedAt"] + 1, "roles": [], "users": [], "buckets": []},
        )

    result = import_case(neo4j_session, cloud_snapshot, after_load=remove_membership)
    assert result.published and cloud_edges(neo4j_session, result.projection_id) == []
    assert {n["cloud_reason"] for n in cloud_nodes(neo4j_session, result.projection_id)} == {
        "changed"
    }


@pytest.mark.parametrize("change", ["newer_provider", "missing_marker_id", "same_time_region"])
def test_managed_capture_cannot_borrow_changed_provider_evidence(
    neo4j_session, cloud_snapshot, change
):
    config, data = enrollment(cloud_snapshot), capture(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    if change == "newer_provider":
        neo4j_session.run(
            "MATCH (a:AWSAccount {id:$id})-[r:RESOURCE]->(p) SET r.lastupdated=$stamp,p.lastupdated=$stamp",
            id=config.account_id,
            stamp=data["capturedAt"] + 1,
        ).consume()
    elif change == "missing_marker_id":
        neo4j_session.run(
            "MATCH (c:GuardAwsCollection {id:$id}) REMOVE c.id", id=collection_id(config)
        ).consume()
    else:
        neo4j_session.run(
            "MATCH (p:AWSS3Bucket {id:$id}) SET p.region='eu-west-2'", id=cloud_snapshot[3]
        ).consume()
    result = import_case(neo4j_session, cloud_snapshot)
    nodes = cloud_nodes(neo4j_session, result.projection_id)
    if change == "same_time_region":
        nodes = [n for n in nodes if "kind" in n]
        assert len(cloud_edges(neo4j_session, result.projection_id)) == 1
    else:
        assert cloud_edges(neo4j_session, result.projection_id) == []
    assert {n["cloud_reason"] for n in nodes} == {
        "freshness_unknown" if change == "missing_marker_id" else "changed"
    }
