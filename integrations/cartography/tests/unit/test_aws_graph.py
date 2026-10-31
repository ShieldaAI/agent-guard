"""The host publication boundary accepts only bounded metadata snapshots."""

from copy import deepcopy
from dataclasses import replace

import pytest
from cartography.graph.querybuilder import build_ingestion_query

from agent_guard_cartography.aws_config import AwsCollectionError, validate_aws_enrollment
from agent_guard_cartography.aws_graph import _schemas, publish_aws_capture, validate_aws_capture


def enrollment():
    return validate_aws_enrollment(
        {
            "schemaVersion": 1,
            "companyId": "company",
            "tenantId": "tenant",
            "partition": "aws",
            "accountId": "111122223333",
            "region": "us-east-1",
            "expectedCallerArn": "arn:aws:sts::111122223333:assumed-role/Reader/collector",
            "accessKeyIdEnv": "TEST_KEY",
            "secretAccessKeyEnv": "TEST_SECRET",
            "sessionTokenEnv": "TEST_SESSION",
        }
    )


def capture():
    return {
        "capturedAt": 1_700_000_000,
        "roles": [
            {
                "arn": "arn:aws:iam::111122223333:role/Reader",
                "roleid": "AROAEXAMPLE",
                "name": "Reader",
                "path": "/",
                "createdate": "2020-01-01T00:00:00Z",
                "createdate_dt": "2020-01-01T00:00:00Z",
            }
        ],
        "users": [],
        "buckets": [
            {
                "Name": "reports",
                "Arn": "arn:aws:s3:::reports",
                "Region": "us-east-1",
                "CreationDate": "2020-01-01T00:00:00Z",
            }
        ],
    }


def test_capture_is_detached_and_schema_reuses_canonical_metadata_without_private_fields():
    data = capture()
    validated = validate_aws_capture(enrollment(), data)
    data["roles"][0]["name"] = "changed"
    assert validated["roles"][0]["name"] == "Reader"
    for category, schema in _schemas().items():
        query = build_ingestion_query(schema)
        assert "$AWS_ID" in query and ":RESOURCE" in query
        assert schema.label in {"AWSRole", "AWSUser", "AWSS3Bucket"}
        assert "policy" not in query.lower() and "passwordlastused" not in query
        assert "delete" not in query.lower()
        if category != "buckets":
            assert "AWSPrincipal" in query


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c.update(secret="private-canary"),
        lambda c: c.update(capturedAt=True),
        lambda c: c.update(capturedAt=253402300799),
        lambda c: c.update(roles=tuple(c["roles"])),
        lambda c: c["roles"][0].update(policy="private-canary"),
        lambda c: c["roles"][0].update(arn="arn:aws:iam::999999999999:role/Reader"),
        lambda c: c["roles"][0].update(createdate_dt="2020-01-01T00:00:00"),
        lambda c: c["roles"][0].update(createdate_dt="2020-01-01T00:00:00+01:00"),
        lambda c: c["roles"].append(deepcopy(c["roles"][0])),
        lambda c: c["buckets"][0].update(Arn="arn:aws:s3:::wrong"),
        lambda c: c["buckets"][0].update(Region="cn-north-1"),
        lambda c: c["buckets"][0].update(Region="us-gov-west-1"),
        lambda c: c["buckets"][0].update(Name="bad..name"),
    ],
)
def test_invalid_capture_fails_before_a_graph_transaction_and_returns_safe_code(change):
    class NeverConnect:
        def begin_transaction(self, **_kwargs):
            pytest.fail("invalid capture reached the graph")

    data = capture()
    change(data)
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_INVALID$"):
        publish_aws_capture(NeverConnect(), enrollment(), data)


def test_item_and_byte_limits_are_applied_before_publication():
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_LIMIT_EXCEEDED$"):
        validate_aws_capture(replace(enrollment(), max_items=1), capture())
    data = capture()
    data["roles"] *= 20
    # Distinct allowed IDs, keeping the byte check independent of duplicate detection.
    data["roles"] = [
        {**row, "name": f"Reader{index}", "arn": f"arn:aws:iam::111122223333:role/Reader{index}"}
        for index, row in enumerate(data["roles"])
    ]
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_LIMIT_EXCEEDED$"):
        validate_aws_capture(replace(enrollment(), max_capture_bytes=1024), data)


def policy_capture():
    data = capture()
    principal = data["roles"][0]["arn"]
    data["policyEvidence"] = {
        "schemaVersion": 1,
        "assessment": "unknown",
        "mappingVersion": "s3-identity-policy-v1",
        "policyHash": "a" * 64,
        "principals": [{"arn": principal, "boundaryPresent": False, "status": "mapped"}],
        "edges": [
            {
                "principalArn": principal,
                "bucketArn": data["buckets"][0]["Arn"],
                "relationship": "CAN_READ",
                "hasCondition": True,
                "conditionKeys": ["aws:PrincipalTag/team"],
                "resourceScope": "bucket_summary",
                "assessment": "unknown",
            }
        ],
        "counts": {"groups": 0, "managedPolicies": 0, "inlinePolicies": 1, "statements": 1},
    }
    return data


def test_policy_capture_is_opt_in_and_detaches_nested_safe_evidence():
    data = policy_capture()
    config = replace(enrollment(), include_iam_policy_evidence=True)
    validated = validate_aws_capture(config, data)
    data["policyEvidence"]["edges"][0]["conditionKeys"].append("changed")
    data["policyEvidence"]["principals"][0]["status"] = "unsupported"
    assert validated["policyEvidence"]["edges"][0]["conditionKeys"] == ["aws:PrincipalTag/team"]
    assert validated["policyEvidence"]["principals"][0]["status"] == "mapped"
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_INVALID$"):
        validate_aws_capture(enrollment(), policy_capture())
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_INVALID$"):
        validate_aws_capture(config, capture())


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(policyDocument="private-policy-canary"),
        lambda e: e["edges"][0].update(conditions="private-condition-canary"),
        lambda e: e["edges"][0].update(assessment="allowed"),
        lambda e: e["edges"][0].update(bucketArn="arn:aws:s3:::unenrolled"),
        lambda e: e["edges"][0].update(principalArn="arn:aws:iam::999999999999:role/Reader"),
        lambda e: e["principals"][0].update(boundaryPresent=True),
        lambda e: e["principals"][0].update(status="unsupported"),
        lambda e: e["edges"].append(deepcopy(e["edges"][0])),
    ],
)
def test_policy_boundary_rejects_tampering_before_graph_access(change):
    class NeverConnect:
        def begin_transaction(self, **_kwargs):
            pytest.fail("invalid policy evidence reached the graph")

    data = policy_capture()
    change(data["policyEvidence"])
    with pytest.raises(AwsCollectionError, match="^AWS_POLICY_INVALID$"):
        publish_aws_capture(
            NeverConnect(), replace(enrollment(), include_iam_policy_evidence=True), data
        )


def test_capture_byte_budget_includes_sanitized_policy_evidence():
    data = policy_capture()
    data["policyEvidence"]["edges"][0]["conditionKeys"] = [f"key-{i:03}" for i in range(20)]
    config = replace(enrollment(), include_iam_policy_evidence=True, max_capture_bytes=1024)
    assert len(str(capture())) < config.max_capture_bytes
    with pytest.raises(AwsCollectionError, match="^AWS_CAPTURE_LIMIT_EXCEEDED$"):
        validate_aws_capture(config, data)
