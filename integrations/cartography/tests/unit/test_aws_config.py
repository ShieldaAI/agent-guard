"""Explicit AWS enrollment is bounded and never discovers credentials."""

import json
import os
from dataclasses import FrozenInstanceError, replace

import pytest

from agent_guard_cartography.aws_config import (
    AwsCollectionError,
    collection_id,
    enrollment_dict,
    load_aws_enrollment,
    validate_aws_enrollment,
)


@pytest.fixture
def configuration():
    return {
        "schemaVersion": 1,
        "companyId": "company",
        "tenantId": "tenant",
        "partition": "aws",
        "accountId": "111122223333",
        "region": "us-east-1",
        "expectedCallerArn": "arn:aws:sts::111122223333:assumed-role/Reader/collector",
        "accessKeyIdEnv": "AGM_AWS_ACCESS",
        "secretAccessKeyEnv": "AGM_AWS_SECRET",
        "sessionTokenEnv": "AGM_AWS_SESSION",
    }


def test_config_is_immutable_and_has_scope_stable_identity(configuration, monkeypatch):
    monkeypatch.delenv("AGM_AWS_ACCESS", raising=False)
    enrollment = validate_aws_enrollment(configuration)
    assert enrollment.timeout_seconds == 120 and enrollment.max_items == 10_000
    assert enrollment.include_iam_policy_evidence is False
    assert validate_aws_enrollment(enrollment_dict(enrollment)) == enrollment
    with pytest.raises(FrozenInstanceError):
        enrollment.region = "us-west-2"
    configuration["tenantId"] = "other"
    assert enrollment.tenant_id == "tenant"
    assert collection_id(enrollment) != collection_id(validate_aws_enrollment(configuration))
    assert collection_id(enrollment) == collection_id(
        replace(enrollment, access_key_id_env="ROTATED_ACCESS")
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schemaVersion", True),
        ("schemaVersion", 2),
        ("companyId", ""),
        ("tenantId", "\ud800"),
        ("accountId", "123"),
        ("accountId", "١١١١٢٢٢٢٣٣٣٣"),
        ("partition", "aws-cn"),
        ("region", "us-gov-west-1"),
        ("region", "us-east-1.attacker.invalid"),
        ("expectedCallerArn", "arn:aws:iam::111122223333:root"),
        ("expectedCallerArn", "arn:aws:sts::999988887777:assumed-role/Reader/collector"),
        ("expectedCallerArn", "arn:aws:sts::111122223333:assumed-role/Reader/*"),
        ("accessKeyIdEnv", "bad-name"),
        ("sessionTokenEnv", "AGM_AWS_ACCESS"),
        ("timeoutSeconds", 0),
        ("timeoutSeconds", 601),
        ("requestTimeoutSeconds", 31),
        ("maxApiCalls", True),
        ("maxPages", 0),
        ("maxItems", 50_001),
        ("maxResponseBytes", 8 * 1024 * 1024 + 1),
        ("maxCaptureBytes", 64 * 1024 * 1024 + 1),
        ("includeIamPolicyEvidence", 1),
        ("includeIamPolicyEvidence", "true"),
        ("includeIamPolicyEvidence", None),
        ("maxPolicyBytes", 1023),
        ("maxPolicyBytes", 32 * 1024 * 1024 + 1),
        ("maxPolicyStatements", 0),
        ("maxPolicyStatements", 50_001),
        ("maxPolicyEvaluations", True),
        ("maxPolicyEvaluations", 1_000_001),
        ("maxPolicyEdges", 0),
        ("maxPolicyEdges", 50_001),
        ("endpointUrl", "https://attacker.invalid"),
        ("profile", "ambient"),
        ("accessKeyId", "credential-canary"),
    ],
)
def test_invalid_enrollments_fail_without_echoing_values(configuration, field, value):
    configuration[field] = value
    with pytest.raises(AwsCollectionError) as error:
        validate_aws_enrollment(configuration)
    assert str(error.value) == "AWS_CONFIG_INVALID"


@pytest.mark.parametrize("field", ["companyId", "tenantId"])
@pytest.mark.parametrize("blank", ["\ufeff", " \ufeff\t", "\ufeff\x1c\ufeff\x85\ufeff\n"])
def test_aws_enrollment_rejects_bom_only_identifiers(configuration, field, blank):
    base = validate_aws_enrollment(configuration)
    config = {**configuration, field: blank}
    attribute = "company_id" if field == "companyId" else "tenant_id"
    typed = replace(base, **{attribute: blank})
    for value in (config, typed):
        with pytest.raises(AwsCollectionError, match="^AWS_CONFIG_INVALID$"):
            validate_aws_enrollment(value)


def test_aws_enrollment_preserves_nonblank_bom_identifiers(configuration):
    configuration.update(companyId="\ufeff \ncompany\ufeff\x85", tenantId="\ufefftenant\ufeff")
    value = validate_aws_enrollment(configuration)
    assert value.company_id == configuration["companyId"]
    assert value.tenant_id == configuration["tenantId"]
    assert validate_aws_enrollment(value) == value


def test_private_config_loader_rejects_unsafe_inputs(configuration, tmp_path):
    path = tmp_path / "aws.json"
    path.write_text(json.dumps(configuration))
    path.chmod(0o600)
    assert load_aws_enrollment(path) == validate_aws_enrollment(configuration)
    path.chmod(0o644)
    with pytest.raises(AwsCollectionError):
        load_aws_enrollment(path)
    path.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(AwsCollectionError):
        load_aws_enrollment(alias)
    alias.unlink()
    os.link(path, alias)
    with pytest.raises(AwsCollectionError):
        load_aws_enrollment(path)
    alias.unlink()
    path.write_text('{"schemaVersion":1,"schemaVersion":1}')
    with pytest.raises(AwsCollectionError):
        load_aws_enrollment(path)
    path.write_bytes(b" " * 32_769)
    with pytest.raises(AwsCollectionError):
        load_aws_enrollment(path)
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(AwsCollectionError):
        load_aws_enrollment(path)


def test_policy_limits_do_not_enable_collection_and_opt_in_keeps_scope_identity(configuration):
    base = validate_aws_enrollment(configuration)
    configuration.update(
        maxPolicyBytes=2048, maxPolicyStatements=12, maxPolicyEvaluations=100, maxPolicyEdges=20
    )
    bounded = validate_aws_enrollment(configuration)
    assert bounded.include_iam_policy_evidence is False
    assert (
        bounded.max_policy_bytes,
        bounded.max_policy_statements,
        bounded.max_policy_evaluations,
        bounded.max_policy_edges,
    ) == (2048, 12, 100, 20)
    configuration["includeIamPolicyEvidence"] = True
    enabled = validate_aws_enrollment(configuration)
    assert enabled.include_iam_policy_evidence is True
    assert collection_id(enabled) == collection_id(bounded) == collection_id(base)
    assert validate_aws_enrollment(enrollment_dict(enabled)) == enabled
