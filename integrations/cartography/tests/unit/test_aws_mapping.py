"""Pin the pilot mapping to the real Cartography parser and evidence semantics."""

from importlib.resources import as_file, files
from pathlib import Path

import pytest
from cartography.intel.aws.permission_relationships import (
    calculate_permission_relationships,
    compile_statement,
    is_valid_rpr,
    parse_permission_relationships_file,
)
from cartography.models.aws.iam.role import AWSRoleSchema
from cartography.models.aws.iam.user import AWSUserSchema
from cartography.models.aws.s3.bucket import S3BucketSchema
from cartography.models.core.relationships import LinkDirection

ROOT = Path(__file__).resolve().parents[4]
MAPPING = ROOT / "deployment" / "cartography" / "aws-permission-relationships.yaml"
ROLE = "arn:aws:iam::111122223333:role/Reader"
BUCKET = "arn:aws:s3:::reports"


@pytest.fixture(scope="module")
def mapping():
    if MAPPING.is_file():
        return parse_permission_relationships_file(str(MAPPING))
    resource = files("agent_guard_cartography").joinpath(
        "data", "aws-permission-relationships.yaml"
    )
    with as_file(resource) as path:
        return parse_permission_relationships_file(str(path))


def calculate(mapping, statement, *more):
    principals = {ROLE: {"policy": compile_statement([statement, *more])}}
    return calculate_permission_relationships(principals, [BUCKET], mapping["permissions"])


def test_pilot_yaml_is_accepted_by_pinned_upstream_and_contains_only_reviewed_edges(mapping):
    assert mapping == [
        {
            "target_label": "AWSS3Bucket",
            "permissions": ["s3:GetObject"],
            "relationship_name": "CAN_READ",
        },
        {
            "target_label": "AWSS3Bucket",
            "permissions": ["s3:PutObject"],
            "relationship_name": "CAN_WRITE",
        },
        {
            "target_label": "AWSS3Bucket",
            "permissions": ["s3:ListBucket"],
            "relationship_name": "CAN_LIST",
        },
    ]
    assert all(is_valid_rpr(item) for item in mapping)


@pytest.mark.parametrize("index", range(3))
def test_mapping_retains_conditional_allow_evidence(mapping, index):
    item = mapping[index]
    condition = [{"StringEquals": {"aws:PrincipalTag/team": "reports"}}]
    (edge,) = calculate(
        item,
        {
            "effect": "Allow",
            "action": item["permissions"],
            "resource": [BUCKET if index == 2 else f"{BUCKET}/scoped/*"],
            "condition": condition,
        },
    )
    assert edge["principal_arn"] == ROLE
    assert edge["resource_arn"] == BUCKET
    assert edge["has_condition"] is True
    assert edge["condition_keys"] == ["aws:PrincipalTag/team"]
    # The source mapper retains the blob. The Agent Guard projection does not
    # need to copy condition values to explain that unresolved conditions exist.
    import json

    assert json.loads(edge["conditions"]) == condition


@pytest.mark.parametrize("resource", [f"{BUCKET}/one.txt", f"{BUCKET}/reports/*"])
def test_upstream_s3_bucket_edges_cannot_prove_object_or_prefix_permission(mapping, resource):
    (edge,) = calculate(
        mapping[0], {"effect": "Allow", "action": ["s3:GetObject"], "resource": [resource]}
    )
    # No resource-pattern information is attached to the resulting bucket edge.
    # The consumer must keep its original object/prefix binding scope separately.
    assert edge["resource_arn"] == BUCKET
    assert "resource" not in edge
    assert "scope" not in edge


def test_unconditional_path_is_retained_but_is_still_only_policy_evidence(mapping):
    (edge,) = calculate(
        mapping[2], {"effect": "Allow", "action": ["s3:ListBucket"], "resource": [BUCKET]}
    )
    assert edge["has_condition"] is False
    assert edge["condition_keys"] == []
    assert edge["conditions"] is None
    assert "allowed" not in edge and "assessment" not in edge


def test_missing_edge_does_not_distinguish_no_policy_from_conditional_deny(mapping):
    assert calculate_permission_relationships({}, [BUCKET], mapping[0]["permissions"]) == []
    assert (
        calculate(
            mapping[0],
            {"effect": "Allow", "action": ["s3:GetObject"], "resource": [f"{BUCKET}/*"]},
            {
                "effect": "Deny",
                "action": ["s3:GetObject"],
                "resource": [f"{BUCKET}/*"],
                "condition": [{"Bool": {"aws:SecureTransport": "false"}}],
            },
        )
        == []
    )


@pytest.mark.parametrize("schema_type", [AWSRoleSchema, AWSUserSchema, S3BucketSchema])
def test_provider_join_contract_has_explicit_account_ownership_and_independent_time(schema_type):
    schema = schema_type()
    assert schema.label in {"AWSRole", "AWSUser", "AWSS3Bucket"}
    assert schema.properties.arn.name in {"arn", "Arn"}
    assert schema.properties.lastupdated.name == "lastupdated"
    assert schema.properties.lastupdated.set_in_kwargs is True
    relation = schema.sub_resource_relationship
    assert relation.target_node_label == "AWSAccount"
    assert relation.direction is LinkDirection.INWARD
    assert relation.rel_label == "RESOURCE"
    assert relation.properties.lastupdated.set_in_kwargs is True
