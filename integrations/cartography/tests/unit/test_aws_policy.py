from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from urllib.parse import quote

import pytest
import yaml

from agent_guard_cartography import aws_policy
from agent_guard_cartography.aws_config import AwsCollectionError, AwsEnrollment
from agent_guard_cartography.aws_policy import (
    FILTER,
    MAPPINGS,
    capture_policy_evidence,
    validate_policy_evidence,
)

ACCOUNT = "123456789012"
DATE = datetime(2024, 1, 2, tzinfo=UTC)
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Reader"
USER = f"arn:aws:iam::{ACCOUNT}:user/Reader"
GROUP = f"arn:aws:iam::{ACCOUNT}:group/Readers"
POLICY = f"arn:aws:iam::{ACCOUNT}:policy/Read"
BUCKET = "arn:aws:s3:::reports"


@pytest.fixture
def enrollment():
    return AwsEnrollment(
        "company",
        "tenant",
        "aws",
        ACCOUNT,
        "us-east-1",
        f"arn:aws:sts::{ACCOUNT}:assumed-role/Inventory/session",
        "KEY",
        "SECRET",
        "TOKEN",
        include_iam_policy_evidence=True,
    )


def entity(kind="Role", name="Reader"):
    return {
        f"{kind}Name": name,
        f"{kind}Id": f"{kind}IDENTIFIER",
        "Path": "/",
        "Arn": f"arn:aws:iam::{ACCOUNT}:{kind.lower()}/{name}",
        "CreateDate": DATE,
    }


def statement(**changes):
    return {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": f"{BUCKET}/private/*",
        **changes,
    }


def document(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements) or [statement()]}


def managed(doc=None):
    return {
        "Arn": POLICY,
        "PolicyName": "Read",
        "PolicyId": "ANPAIDENTIFIER",
        "DefaultVersionId": "v1",
        "PolicyVersionList": [
            {"VersionId": "v1", "IsDefaultVersion": True, "Document": doc or document()}
        ],
    }


def attachment():
    return {"PolicyName": "Read", "PolicyArn": POLICY}


def response(*, role_doc=None, users=None, groups=None, policies=None):
    role = entity()
    role["RolePolicyList"] = [{"PolicyName": "inline", "PolicyDocument": role_doc or document()}]
    return {
        "IsTruncated": False,
        "RoleDetailList": [role],
        "UserDetailList": users or [],
        "GroupDetailList": groups or [],
        "Policies": policies or [],
    }


def metadata(pages):
    capture = {"capturedAt": 0, "roles": [], "users": [], "buckets": [{"Arn": BUCKET}]}
    for page in pages:
        for kind in ("Role", "User"):
            for item in page.get(f"{kind}DetailList", []):
                capture[f"{kind.lower()}s"].append(
                    {
                        "arn": item["Arn"],
                        "name": item[f"{kind}Name"],
                        "path": item["Path"],
                        f"{kind.lower()}id": item[f"{kind}Id"],
                        "createdate": "2024-01-02T00:00:00Z",
                    }
                )
    return capture


def run(enrollment, pages=None, capture=None):
    pages = deepcopy(pages or [response()])
    capture = capture or metadata(pages)
    original = deepcopy(pages)
    calls, page_calls = [], []

    def call(service, operation, **kwargs):
        calls.append((service, operation, kwargs))
        return pages.pop(0)

    result = capture_policy_evidence(enrollment, capture, call, lambda: page_calls.append(1))
    assert len(page_calls) == len(original) == len(calls)
    for index, (service, operation, kwargs) in enumerate(calls):
        assert (service, operation) == ("iam", "get_account_authorization_details")
        assert kwargs == {
            "Filter": FILTER,
            "MaxItems": 100,
            **({"Marker": original[index - 1]["Marker"]} if index else {}),
        }
    return result


def error(code, callback):
    with pytest.raises(AwsCollectionError) as raised:
        callback()
    assert raised.value.code == str(raised.value) == code


def test_literal_mapping_matches_packaged_reviewed_rules():
    source = (
        Path(__file__).resolve().parents[4]
        / "deployment/cartography/aws-permission-relationships.yaml"
    )
    resource = files("agent_guard_cartography").joinpath(
        "data", "aws-permission-relationships.yaml"
    )
    mapping = yaml.safe_load(source.read_text() if source.is_file() else resource.read_text())
    assert MAPPINGS == tuple(
        (item["relationship_name"], item["permissions"][0]) for item in mapping
    )
    assert all(
        item["target_label"] == "AWSS3Bucket" and len(item["permissions"]) == 1 for item in mapping
    )


def test_inline_capture_is_sanitized_and_deep_copied(enrollment):
    value = run(enrollment)
    assert value["principals"] == [{"arn": ROLE, "boundaryPresent": False, "status": "mapped"}]
    assert value["edges"] == [
        {
            "principalArn": ROLE,
            "bucketArn": BUCKET,
            "relationship": "CAN_READ",
            "hasCondition": False,
            "conditionKeys": [],
            "resourceScope": "bucket_summary",
            "assessment": "unknown",
        }
    ]
    assert value["counts"] == {
        "groups": 0,
        "managedPolicies": 0,
        "inlinePolicies": 1,
        "statements": 1,
    }
    assert "private" not in json.dumps(value)
    copied = validate_policy_evidence(enrollment, metadata([response()]), value)
    copied["principals"][0]["status"] = "unsupported"
    copied["edges"][0]["conditionKeys"].append("changed")
    copied["counts"]["groups"] = 100
    assert value["principals"][0]["status"] == "mapped"
    assert value["edges"][0]["conditionKeys"] == []
    assert value["counts"]["groups"] == 0


def test_managed_default_versions_and_cross_page_group_inheritance(enrollment):
    user, group = entity("User"), entity("Group", "Readers")
    user["GroupList"] = ["Readers"]
    group["AttachedManagedPolicies"] = [attachment()]
    first = response(users=[user])
    first.update(IsTruncated=True, Marker="next")
    policy = managed(document(statement(Action="s3:ListBucket", Resource=BUCKET)))
    policy["PolicyVersionList"].append(
        {
            "VersionId": "v2",
            "IsDefaultVersion": False,
            "Document": document(statement(Effect="Deny")),
        }
    )
    second = {"IsTruncated": False, "GroupDetailList": [group], "Policies": [policy]}
    value = run(enrollment, [first, second])
    assert [(edge["principalArn"], edge["relationship"]) for edge in value["edges"]] == [
        (ROLE, "CAN_READ"),
        (USER, "CAN_LIST"),
    ]
    assert value["counts"] == {
        "groups": 1,
        "managedPolicies": 1,
        "inlinePolicies": 1,
        "statements": 2,
    }


def test_aws_managed_policy_is_supported(enrollment):
    value = response(policies=[managed()])
    value["Policies"][0]["Arn"] = "arn:aws:iam::aws:policy/Read"
    value["RoleDetailList"][0]["AttachedManagedPolicies"] = [
        {"PolicyName": "Read", "PolicyArn": "arn:aws:iam::aws:policy/Read"}
    ]
    assert len(run(enrollment, [value])["edges"]) == 1


@pytest.mark.parametrize("conditional", [False, True])
def test_deny_from_group_suppresses_user_candidates(enrollment, conditional):
    user, group = entity("User"), entity("Group", "Readers")
    user.update(
        GroupList=["Readers"], UserPolicyList=[{"PolicyName": "read", "PolicyDocument": document()}]
    )
    deny = statement(
        Effect="Deny",
        **({"Condition": {"Bool": {"aws:SecureTransport": "false"}}} if conditional else {}),
    )
    group["GroupPolicyList"] = [{"PolicyName": "deny", "PolicyDocument": document(deny)}]
    value = run(enrollment, [response(users=[user], groups=[group])])
    assert [edge["principalArn"] for edge in value["edges"]] == [ROLE]


def test_conditional_allow_exposes_only_context_keys(enrollment):
    doc = document(statement(Condition={"StringEquals": {"aws:PrincipalTag/team": "SECRET_TEAM"}}))
    value = run(enrollment, [response(role_doc=doc)])
    assert value["edges"][0]["hasCondition"] is True
    assert value["edges"][0]["conditionKeys"] == ["aws:PrincipalTag/team"]
    assert "SECRET_TEAM" not in json.dumps(value)
    doc["Statement"].append(statement())
    edge = run(enrollment, [response(role_doc=doc)])["edges"][0]
    assert edge["hasCondition"] is False and edge["conditionKeys"] == []


def test_boundary_blocks_principal_and_is_not_additive(enrollment):
    page = response(policies=[managed()])
    page["RoleDetailList"][0]["PermissionsBoundary"] = {
        "PermissionsBoundaryArn": POLICY,
        "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
    }
    result = run(enrollment, [page])
    assert result["principals"] == [
        {"arn": ROLE, "boundaryPresent": True, "status": "boundary_unresolved"}
    ]
    assert result["edges"] == []


@pytest.mark.parametrize(
    "change",
    [
        {"NotAction": "s3:DeleteObject"},
        {"NotResource": "arn:aws:s3:::other/*"},
        {"Resource": f"{BUCKET}/${{aws:username}}/*"},
        {"Resource": "arn:aws:s3:::rep*/*"},
        {"Principal": "*"},
        {"Action": "s3:Get(Object)"},
        {"Unknown": "value"},
    ],
)
def test_unsupported_statement_suppresses_whole_principal(enrollment, change):
    result = run(
        enrollment, [response(role_doc=document(statement(), statement(Effect="Deny", **change)))]
    )
    assert result["principals"][0]["status"] == "unsupported"
    assert result["edges"] == []


@pytest.mark.parametrize(
    ("resource", "matches"),
    [
        ("arn:aws:s3:::report?/*", True),
        ("arn:aws:s3:::reports?/*", False),
        ("arn:aws:s3:::rep(orts)/*", False),
        ("arn:aws:s3:::reports[ab]/*", False),
        ("arn:aws:s3:::reports.+/*", False),
        ("*", True),
    ],
)
def test_wildcards_are_escaped_and_question_mark_matches_exactly_one(enrollment, resource, matches):
    assert (
        bool(run(enrollment, [response(role_doc=document(statement(Resource=resource)))])["edges"])
        is matches
    )


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
@pytest.mark.parametrize(
    ("resource", "matches"),
    [
        ("arn:aws:s3:::reports", True),
        ("arn:aws:s3:::reports/Private/Report.JSON", True),
        ("arn:aws:s3:::REPORTS", False),
        ("arn:aws:s3:::REPORTS/private/*", False),
        ("ARN:aws:s3:::reports/private/*", False),
        ("arn:AWS:s3:::reports/private/*", False),
        ("arn:aws:S3:::reports/private/*", False),
        ("arn:aws:s3:::REPORT?/*", False),
    ],
)
def test_resource_case_is_preserved_in_bucket_projection(enrollment, effect, resource, matches):
    selected = statement(Effect=effect, Resource=resource)
    statements = [selected] if effect == "Allow" else [statement(), selected]
    result = run(enrollment, [response(role_doc=document(*statements))])
    assert result["principals"][0]["status"] == "mapped"
    assert bool(result["edges"]) is (matches if effect == "Allow" else not matches)
    assert all(edge["assessment"] == "unknown" for edge in result["edges"])


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_action_case_remains_insensitive_with_case_sensitive_resources(enrollment, effect):
    selected = statement(
        Effect=effect, Action="S3:gEtObJeCt", Resource=f"{BUCKET}/Private/Report.JSON"
    )
    statements = [selected] if effect == "Allow" else [statement(), selected]
    result = run(enrollment, [response(role_doc=document(*statements))])
    assert bool(result["edges"]) is (effect == "Allow")


def test_policy_document_wire_encoding_and_single_statement(enrollment):
    doc = {
        "Version": "2012-10-17",
        "Statement": statement(Condition={"StringEquals": {"aws:key%74": "value%2F"}}),
    }
    plain = run(enrollment, [response(role_doc=doc)])
    decoded = run(enrollment, [response(role_doc=json.dumps(doc))])
    encoded = run(enrollment, [response(role_doc=quote(json.dumps(doc)))])
    assert plain == encoded == decoded
    assert plain["edges"][0]["conditionKeys"] == ["aws:key%74"]


@pytest.mark.parametrize("empty_document", [False, True])
def test_evaluation_budget_includes_principals_without_statements(enrollment, empty_document):
    page = response()
    page["RoleDetailList"][0]["RolePolicyList"] = (
        [{"PolicyName": "empty", "PolicyDocument": {"Statement": []}}] if empty_document else []
    )
    error(
        "AWS_POLICY_LIMIT_EXCEEDED",
        lambda: run(replace(enrollment, max_policy_evaluations=2), [page]),
    )


def test_policy_hash_excludes_tags_trust_and_unused_versions_but_tracks_conditions(enrollment):
    page = response(policies=[managed()])
    before = run(enrollment, [page])
    page["RoleDetailList"][0].update(
        Tags=[{"Key": "team", "Value": "secret"}], AssumeRolePolicyDocument=document()
    )
    page["Policies"][0]["PolicyVersionList"].append(
        {
            "VersionId": "v2",
            "IsDefaultVersion": False,
            "Document": document(statement(Effect="Deny")),
        }
    )
    assert run(enrollment, [page])["policyHash"] == before["policyHash"]
    page["RoleDetailList"][0]["RolePolicyList"][0]["PolicyDocument"]["Statement"][0][
        "Condition"
    ] = {"StringEquals": {"aws:PrincipalTag/team": "secret"}}
    assert run(enrollment, [page])["policyHash"] != before["policyHash"]


@pytest.mark.parametrize(
    "problem", ["group", "attachment", "boundary", "census", "default", "duplicate", "account"]
)
def test_incomplete_census_fails_without_partial_evidence(enrollment, problem):
    page = response(policies=[managed()])
    capture = metadata([page])
    role = page["RoleDetailList"][0]
    if problem == "group":
        user = entity("User")
        user["GroupList"] = ["missing"]
        page["UserDetailList"] = [user]
        capture = metadata([page])
    elif problem == "attachment":
        role["AttachedManagedPolicies"] = [
            {"PolicyName": "Missing", "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/Missing"}
        ]
    elif problem == "boundary":
        role["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/Missing",
            "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
        }
    elif problem == "census":
        capture["roles"][0]["roleid"] = "CHANGED"
    elif problem == "default":
        page["Policies"][0]["DefaultVersionId"] = "v2"
    elif problem == "duplicate":
        page["Policies"].append(deepcopy(page["Policies"][0]))
    elif problem == "account":
        page["Policies"][0]["Arn"] = "arn:aws:iam::000000000000:policy/Read"
    error("AWS_POLICY_INCOMPLETE", lambda: run(enrollment, [page], capture))


@pytest.mark.parametrize("marker", ["missing", "repeated", "terminal"])
def test_pagination_rejects_incomplete_markers(enrollment, marker):
    first = response()
    if marker == "missing":
        first["IsTruncated"] = True
        code = "AWS_POLICY_INVALID"
        pages = [first]
    elif marker == "terminal":
        first["Marker"] = "unexpected"
        code = "AWS_POLICY_INCOMPLETE"
        pages = [first]
    else:
        first.update(IsTruncated=True, Marker="same")
        pages = [first, {"IsTruncated": True, "Marker": "same"}]
        code = "AWS_POLICY_INCOMPLETE"
    error(code, lambda: run(enrollment, pages))


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("max_policy_bytes", 100),
        ("max_policy_statements", 0),
        ("max_policy_evaluations", 5),
        ("max_policy_edges", 0),
        ("max_items", 0),
        ("max_capture_bytes", 100),
    ],
)
def test_capture_limit_exhaustion_is_atomic(enrollment, field, limit):
    error("AWS_POLICY_LIMIT_EXCEEDED", lambda: run(replace(enrollment, **{field: limit})))


def test_output_expansion_is_bounded_before_all_edges_are_allocated(enrollment, monkeypatch):
    page = response(role_doc=document(statement(Resource="*")))
    capture = metadata([page])
    capture["buckets"] = [{"Arn": f"arn:aws:s3:::reports-{index}"} for index in range(100)]
    upstream = aws_policy.calculate_permission_relationships
    probes = []

    def measured(principals, resources, permissions):
        assert len(resources) == 1
        probes.append(1)
        return upstream(principals, resources, permissions)

    monkeypatch.setattr(aws_policy, "calculate_permission_relationships", measured)
    error(
        "AWS_POLICY_LIMIT_EXCEEDED",
        lambda: run(replace(enrollment, max_capture_bytes=1500), [page], capture),
    )
    assert 1 <= len(probes) < 10


@pytest.mark.parametrize(
    "condition",
    [
        {f"Operator{index}": {"aws:key": "value"} for index in range(33)},
        {"StringEquals": {f"aws:key{index}": "value" for index in range(129)}},
        {"StringEquals": {"aws:key": ["value"] * 129}},
        {"StringEquals": {"aws:key": "x" * 8193}},
    ],
)
def test_absolute_condition_limits(enrollment, condition):
    error(
        "AWS_POLICY_LIMIT_EXCEEDED",
        lambda: run(enrollment, [response(role_doc=document(statement(Condition=condition)))]),
    )


@pytest.mark.parametrize(
    "doc",
    [
        "{bad-json",
        '{"Statement":[],"Statement":[]}',
        {"Statement": "bad"},
        document(statement(Effect="Unexpected")),
        document(statement(Action=[])),
        document(statement(Condition={})),
        document(statement(Condition={"StringEquals": {"aws:key": {"bad": "value"}}})),
    ],
)
def test_malformed_documents_fail_with_stable_error(enrollment, doc):
    error("AWS_POLICY_INVALID", lambda: run(enrollment, [response(role_doc=doc)]))


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(rawPolicies=[]),
        lambda value: value.update(schemaVersion=True),
        lambda value: value.update(policyHash="not-a-hash"),
        lambda value: value["edges"][0].update(conditions="secret"),
        lambda value: value["edges"][0].update(relationship=[]),
        lambda value: value["edges"][0].update(relationship="CAN_ADMIN"),
        lambda value: value["edges"][0].update(bucketArn="arn:aws:s3:::missing"),
        lambda value: value["edges"][0].update(hasCondition=True),
        lambda value: value["edges"].append(deepcopy(value["edges"][0])),
        lambda value: value["principals"][0].update(status="unsupported"),
        lambda value: value["principals"][0].update(boundaryPresent=True),
        lambda value: value["counts"].update(statements=0),
    ],
)
def test_publication_validator_rejects_forged_or_inconsistent_evidence(enrollment, change):
    value = run(enrollment)
    change(value)
    error(
        "AWS_POLICY_INVALID",
        lambda: validate_policy_evidence(enrollment, metadata([response()]), value),
    )


def test_empty_complete_capture_and_disabled_reducer(enrollment):
    page = {"IsTruncated": False}
    capture = {"roles": [], "users": [], "buckets": []}
    result = run(enrollment, [page], capture)
    assert result["edges"] == result["principals"] == []
    assert set(result["counts"].values()) == {0}
    error("AWS_POLICY_INVALID", lambda: run(replace(enrollment, include_iam_policy_evidence=False)))
