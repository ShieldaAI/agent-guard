"""Atomic ownership, retirement and isolation for minimized IAM candidate evidence."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest
from test_aws_collection import capture, enrollment, state
from test_cloud_graph import cloud_edges, cloud_nodes, import_case, seed
from test_cloud_graph import cloud_snapshot as cloud_snapshot

import agent_guard_cartography.aws_graph as aws_graph
from agent_guard_cartography.aws_config import AwsCollectionError, collection_id
from agent_guard_cartography.aws_graph import publish_aws_capture

pytestmark = pytest.mark.integration


def policy_case(case):
    config = replace(enrollment(case), include_iam_policy_evidence=True)
    data = capture(case)
    role, user = data["roles"][0]["arn"], data["users"][0]["arn"]
    data["policyEvidence"] = {
        "schemaVersion": 1,
        "assessment": "unknown",
        "mappingVersion": "s3-identity-policy-v1",
        "policyHash": "a" * 64,
        "principals": [
            {"arn": role, "boundaryPresent": False, "status": "mapped"},
            {"arn": user, "boundaryPresent": True, "status": "boundary_unresolved"},
        ],
        "edges": [
            {
                "principalArn": role,
                "bucketArn": data["buckets"][0]["Arn"],
                "relationship": "CAN_READ",
                "hasCondition": True,
                "conditionKeys": ["aws:PrincipalTag/team"],
                "resourceScope": "bucket_summary",
                "assessment": "unknown",
            }
        ],
        "counts": {"groups": 0, "managedPolicies": 1, "inlinePolicies": 1, "statements": 2},
    }
    return config, data


def candidates(session, config):
    return [
        dict(row)
        for row in session.run(
            "MATCH (p)-[r:G_AWS_POLICY_CANDIDATE {collection_id:$id}]->(b) "
            "RETURN p.id AS principal,b.id AS bucket,properties(r) AS edge "
            "ORDER BY principal,bucket,r.relationship",
            id=collection_id(config),
        )
    ]


def complete_state(session, config):
    metadata = state(session, config)
    metadata["nodes"].sort(key=lambda row: row["id"] or "")
    return {"metadata": metadata, "candidates": candidates(session, config)}


def test_policy_publication_minimizes_evidence_and_preserves_shared_provider_edges(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)
    config, data = policy_case(cloud_snapshot)
    receipt = publish_aws_capture(neo4j_session, config, data)
    assert receipt["assessment"] == "unknown"
    assert receipt["policyEvidence"] == {
        "status": "complete",
        "principals": 2,
        "edges": 1,
        "boundaryPrincipals": 1,
        "unsupportedPrincipals": 0,
    }
    (candidate,) = candidates(neo4j_session, config)
    marker = state(neo4j_session, config)["collection"]
    assert marker["policy_status"] == "complete"
    assert marker["policy_edges"] == 1
    assert marker["policy_hash"] == data["policyEvidence"]["policyHash"]
    assert candidate["edge"] == {
        "collection_id": collection_id(config),
        "capture_hash": marker["content_hash"],
        "captured_at": data["capturedAt"],
        "policy_hash": "a" * 64,
        "mapping_version": "s3-identity-policy-v1",
        "relationship": "CAN_READ",
        "has_condition": True,
        "condition_keys": ["aws:PrincipalTag/team"],
        "resource_scope": "bucket_summary",
        "assessment": "unknown",
        "evidence_kind": "iam_identity_policy_candidate",
    }
    observed = {row["id"]: row["membership"] for row in state(neo4j_session, config)["nodes"]}
    assert observed[data["roles"][0]["arn"]]["policy_status"] == "mapped"
    assert observed[data["users"][0]["arn"]]["policy_status"] == "boundary_unresolved"
    assert observed[data["users"][0]["arn"]]["policy_boundary_present"] is True
    assert "policy_status" not in observed[data["buckets"][0]["Name"]]
    sentinel = neo4j_session.run(
        "MATCH (:AWSRole {id:$role})-[r:CAN_READ]->(:AWSS3Bucket {id:$bucket}) "
        "RETURN properties(r) AS value",
        role=cloud_snapshot[4],
        bucket=cloud_snapshot[3],
    ).single()["value"]
    assert sentinel["conditions"] == "private-condition-canary"
    assert "canary" not in json.dumps(candidate)
    assert "conditions" not in candidate["edge"]
    assert "PolicyDocument" not in json.dumps(marker)
    # Provider inventory still composes independently; it cannot promote the
    # candidate into an Agent Guard effective-authorization decision.
    result = import_case(neo4j_session, cloud_snapshot)
    assert len(cloud_edges(neo4j_session, result.projection_id)) == 4
    assert {
        row["cloud_assessment"] for row in cloud_nodes(neo4j_session, result.projection_id)
    } == {"unknown"}


def test_policy_hash_change_replaces_owned_candidates_and_same_time_conflicts(
    neo4j_session, cloud_snapshot
):
    config, data = policy_case(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    previous = complete_state(neo4j_session, config)
    assert publish_aws_capture(neo4j_session, config, data)["idempotent"] is True
    assert complete_state(neo4j_session, config) == previous
    changed = deepcopy(data)
    changed["policyEvidence"]["policyHash"] = "b" * 64
    changed["policyEvidence"]["edges"][0]["relationship"] = "CAN_WRITE"
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_CONFLICT$"):
        publish_aws_capture(neo4j_session, config, changed)
    assert complete_state(neo4j_session, config) == previous
    changed["capturedAt"] += 1
    publish_aws_capture(neo4j_session, config, changed)
    (edge,) = candidates(neo4j_session, config)
    assert edge["edge"]["relationship"] == "CAN_WRITE"
    assert edge["edge"]["policy_hash"] == "b" * 64
    assert edge["edge"]["capture_hash"] != previous["candidates"][0]["edge"]["capture_hash"]
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_ROLLBACK$"):
        publish_aws_capture(neo4j_session, config, data)
    assert candidates(neo4j_session, config) == [edge]


def test_policy_publication_failure_after_candidate_replacement_rolls_everything_back(
    neo4j_session, cloud_snapshot, monkeypatch
):
    config, data = policy_case(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    previous = complete_state(neo4j_session, config)
    original = aws_graph._publish_policy_evidence

    def fail_after_replacement(*args):
        original(*args)
        raise RuntimeError("private-provider-policy-canary")

    monkeypatch.setattr(aws_graph, "_publish_policy_evidence", fail_after_replacement)
    changed = deepcopy(data)
    changed["capturedAt"] += 1
    changed["policyEvidence"]["edges"] = []
    with pytest.raises(AwsCollectionError, match="^AWS_PUBLICATION_FAILED$"):
        publish_aws_capture(neo4j_session, config, changed)
    assert complete_state(neo4j_session, config) == previous


def test_policy_opt_out_retires_only_its_owned_layer_and_clears_policy_membership(
    neo4j_session, cloud_snapshot
):
    seed(neo4j_session, cloud_snapshot)
    config, data = policy_case(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    # Two enrolled tenants may observe the same shared provider nodes. Their
    # candidate edges must remain independent, including an identical action.
    other = replace(config, tenant_id="other-tenant")
    publish_aws_capture(neo4j_session, other, data)
    foreign = candidates(neo4j_session, other)
    disabled = replace(config, include_iam_policy_evidence=False)
    metadata = {key: value for key, value in data.items() if key != "policyEvidence"}
    metadata["capturedAt"] += 1
    receipt = publish_aws_capture(neo4j_session, disabled, metadata)
    assert "policyEvidence" not in receipt
    assert candidates(neo4j_session, config) == []
    assert candidates(neo4j_session, other) == foreign
    current = state(neo4j_session, config)
    assert current["collection"]["policy_status"] == "disabled"
    assert "policy_hash" not in current["collection"]
    assert "policy_edges" not in current["collection"]
    assert all(
        not any(key.startswith("policy_") for key in row["membership"]) for row in current["nodes"]
    )
    assert (
        neo4j_session.run(
            "MATCH (:AWSRole {id:$role})-[r:CAN_READ]->(:AWSS3Bucket {id:$bucket}) "
            "RETURN r.conditions AS value",
            role=cloud_snapshot[4],
            bucket=cloud_snapshot[3],
        ).single()["value"]
        == "private-condition-canary"
    )


def test_empty_complete_policy_capture_retires_candidates_but_retains_shared_provider_nodes(
    neo4j_session, cloud_snapshot
):
    config, data = policy_case(cloud_snapshot)
    publish_aws_capture(neo4j_session, config, data)
    empty = {
        "capturedAt": data["capturedAt"] + 1,
        "roles": [],
        "users": [],
        "buckets": [],
        "policyEvidence": {
            **data["policyEvidence"],
            "policyHash": "b" * 64,
            "principals": [],
            "edges": [],
            "counts": {"groups": 0, "managedPolicies": 0, "inlinePolicies": 0, "statements": 0},
        },
    }
    publish_aws_capture(neo4j_session, config, empty)
    assert candidates(neo4j_session, config) == []
    marker = state(neo4j_session, config)["collection"]
    assert marker["policy_status"] == "complete" and marker["policy_edges"] == 0
    assert (
        neo4j_session.run(
            "MATCH (:AWSAccount {id:$id})-[:RESOURCE]->(n) RETURN count(n) AS count",
            id=config.account_id,
        ).single()["count"]
        == 3
    )


def test_unsupported_principal_status_is_kept_without_an_allow_or_deny_edge(
    neo4j_session, cloud_snapshot
):
    config, data = policy_case(cloud_snapshot)
    data["policyEvidence"]["principals"][0]["status"] = "unsupported"
    data["policyEvidence"]["edges"] = []
    receipt = publish_aws_capture(neo4j_session, config, data)
    assert receipt["policyEvidence"]["unsupportedPrincipals"] == 1
    assert candidates(neo4j_session, config) == []
    memberships = state(neo4j_session, config)["nodes"]
    role = next(row for row in memberships if row["id"] == data["roles"][0]["arn"])
    assert role["membership"]["policy_status"] == "unsupported"
    assert role["membership"]["policy_assessment"] == "unknown"
