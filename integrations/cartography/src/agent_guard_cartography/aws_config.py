"""Explicit single-account AWS enrollment; validation never loads credentials."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, fields
from hashlib import sha256
from pathlib import Path
from typing import Any


class AwsCollectionError(RuntimeError):
    """Stable diagnostics only; never retain provider responses or credential values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AwsEnrollment:
    company_id: str
    tenant_id: str
    partition: str
    account_id: str
    region: str
    expected_caller_arn: str
    access_key_id_env: str
    secret_access_key_env: str
    session_token_env: str
    timeout_seconds: int = 120
    request_timeout_seconds: int = 5
    max_api_calls: int = 1000
    max_pages: int = 100
    max_items: int = 10_000
    max_response_bytes: int = 4 * 1024 * 1024
    max_capture_bytes: int = 16 * 1024 * 1024
    include_iam_policy_evidence: bool = False
    max_policy_bytes: int = 8 * 1024 * 1024
    max_policy_statements: int = 10_000
    max_policy_evaluations: int = 100_000
    max_policy_edges: int = 10_000


_NAMES = {
    "company_id": "companyId",
    "tenant_id": "tenantId",
    "partition": "partition",
    "account_id": "accountId",
    "region": "region",
    "expected_caller_arn": "expectedCallerArn",
    "access_key_id_env": "accessKeyIdEnv",
    "secret_access_key_env": "secretAccessKeyEnv",
    "session_token_env": "sessionTokenEnv",
    "timeout_seconds": "timeoutSeconds",
    "request_timeout_seconds": "requestTimeoutSeconds",
    "max_api_calls": "maxApiCalls",
    "max_pages": "maxPages",
    "max_items": "maxItems",
    "max_response_bytes": "maxResponseBytes",
    "max_capture_bytes": "maxCaptureBytes",
    "include_iam_policy_evidence": "includeIamPolicyEvidence",
    "max_policy_bytes": "maxPolicyBytes",
    "max_policy_statements": "maxPolicyStatements",
    "max_policy_evaluations": "maxPolicyEvaluations",
    "max_policy_edges": "maxPolicyEdges",
}
_LIMITS = {
    "timeoutSeconds": (120, 1, 600),
    "requestTimeoutSeconds": (5, 1, 30),
    "maxApiCalls": (1000, 1, 10_000),
    "maxPages": (100, 1, 1000),
    "maxItems": (10_000, 1, 50_000),
    "maxResponseBytes": (4 * 1024 * 1024, 1024, 8 * 1024 * 1024),
    "maxCaptureBytes": (16 * 1024 * 1024, 1024, 64 * 1024 * 1024),
    "maxPolicyBytes": (8 * 1024 * 1024, 1024, 32 * 1024 * 1024),
    "maxPolicyStatements": (10_000, 1, 50_000),
    "maxPolicyEvaluations": (100_000, 1, 1_000_000),
    "maxPolicyEdges": (10_000, 1, 50_000),
}


def enrollment_dict(value: AwsEnrollment) -> dict:
    """Non-secret wire representation for a private worker pipe and configuration tests."""
    return {
        "schemaVersion": 1,
        **{_NAMES[field.name]: getattr(value, field.name) for field in fields(value)},
    }


def _invalid() -> None:
    raise AwsCollectionError("AWS_CONFIG_INVALID")


def validate_aws_enrollment(value: Any) -> AwsEnrollment:
    if isinstance(value, AwsEnrollment):
        value = enrollment_dict(value)
    required = {"schemaVersion", *(_NAMES[name] for name in list(_NAMES)[:9])}
    if (
        type(value) is not dict
        or not required <= value.keys()
        or value.keys() - {"schemaVersion", *_NAMES.values()}
    ):
        _invalid()
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        _invalid()
    for name in ("companyId", "tenantId"):
        item = value[name]
        if (
            type(item) is not str
            or len(item) > 4096
            or not any(character != "\ufeff" and not character.isspace() for character in item)
            or "\0" in item
            or any(0xD800 <= ord(char) <= 0xDFFF for char in item)
        ):
            _invalid()
    if (
        value["partition"] != "aws"
        or type(value["accountId"]) is not str
        or not re.fullmatch(r"[0-9]{12}", value["accountId"])
    ):
        _invalid()
    if type(value["region"]) is not str or not re.fullmatch(
        r"(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|west|north|south|northeast|northwest|southeast|southwest)-[1-9][0-9]?",
        value["region"],
    ):
        _invalid()
    arn = value["expectedCallerArn"]
    if (
        type(arn) is not str
        or len(arn) > 2048
        or not re.fullmatch(
            rf"arn:aws:(?:iam::{value['accountId']}:user/[A-Za-z0-9+=,.@_/-]+|sts::{value['accountId']}:assumed-role/[A-Za-z0-9+=,.@_-]+/[A-Za-z0-9+=,.@_-]+)",
            arn,
        )
    ):
        _invalid()
    credentials = [
        value[name] for name in ("accessKeyIdEnv", "secretAccessKeyEnv", "sessionTokenEnv")
    ]
    if (
        any(
            type(name) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name)
            for name in credentials
        )
        or len(set(credentials)) != 3
    ):
        _invalid()
    normalized = dict(value)
    include_policies = value.get("includeIamPolicyEvidence", False)
    if type(include_policies) is not bool:
        _invalid()
    normalized["includeIamPolicyEvidence"] = include_policies
    for name, (default, minimum, maximum) in _LIMITS.items():
        item = value.get(name, default)
        if type(item) is not int or not minimum <= item <= maximum:
            _invalid()
        normalized[name] = item
    if normalized["requestTimeoutSeconds"] > normalized["timeoutSeconds"]:
        _invalid()
    return AwsEnrollment(**{name: normalized[external] for name, external in _NAMES.items()})


def collection_id(value: AwsEnrollment) -> str:
    """Stable scope identity; credentials, caller-session identity and limits are excluded."""
    value = validate_aws_enrollment(value)
    return sha256(
        json.dumps(
            [value.company_id, value.tenant_id, value.partition, value.account_id],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def load_aws_enrollment(path: Path | str) -> AwsEnrollment:
    """Read a bounded private regular file, refusing links, devices and blocking FIFOs."""
    if not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise AwsCollectionError("AWS_PLATFORM_UNSUPPORTED")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > 32_768
        ):
            _invalid()
        raw = bytearray()
        while len(raw) <= 32_768:
            chunk = os.read(descriptor, 32_769 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > 32_768:
            _invalid()

        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    _invalid()
                result[key] = item
            return result

        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        return validate_aws_enrollment(value)
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise AwsCollectionError("AWS_CONFIG_INVALID") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
