"""Provider matches are scoped evidence, never permission decisions."""

from copy import deepcopy

import pytest

from agent_guard_cartography.cloud import (
    MAX_CLOUD_REFERENCES,
    CloudJoinError,
    CloudScope,
    check_cloud_scope,
    classify_provider,
    collect_cloud,
    provider_target,
    unavailable_cloud,
    validate_cloud_scope,
)

CONFIG = {
    "companyId": "company",
    "tenantId": "alpha",
    "accounts": [{"partition": "aws", "accountId": "111122223333"}],
}
NOW = 1_800_000_000


def reference(**changes):
    return {
        "id": "reference",
        "label": "GuardExternalIdentity",
        "partition": "aws",
        "account_id": "111122223333",
        "region": "",
        "arn": "arn:aws:iam::111122223333:role/worker",
        **changes,
    }


def match(**changes):
    return {
        "element_id": "element",
        "provider_id": reference()["arn"],
        "arn": reference()["arn"],
        "region": "",
        "node_updated": NOW,
        "ownership_updated": NOW,
        "account_updated": NOW,
        **changes,
    }


def test_scope_is_detached_and_enrolled_to_exact_company_tenant():
    config = deepcopy(CONFIG)
    scope = validate_cloud_scope(config)
    config["accounts"][0]["accountId"] = "999999999999"
    assert scope.accounts == (("aws", "111122223333"),)
    assert validate_cloud_scope(scope) == scope
    check_cloud_scope(scope, {"companyId": "company", "tenantId": "alpha"})
    for source in [
        {"companyId": "other", "tenantId": "alpha"},
        {"companyId": "company", "tenantId": "beta"},
    ]:
        with pytest.raises(CloudJoinError, match="^CLOUD_SCOPE_MISMATCH$"):
            check_cloud_scope(scope, source)


@pytest.mark.parametrize(
    "change",
    [
        {"token": "private-canary"},
        {"companyId": ""},
        {"tenantId": "\0"},
        {"maxAgeSeconds": True},
        {"maxAgeSeconds": 0},
        {"maxAgeSeconds": 604801},
        {"accounts": []},
        {"accounts": [{"partition": "invalid", "accountId": "111122223333"}]},
        {"accounts": [{"partition": "aws", "accountId": 111122223333}]},
        {"accounts": CONFIG["accounts"] * 2},
        {"accounts": CONFIG["accounts"] * 65},
    ],
)
def test_invalid_configuration_is_bounded_and_redacted(change):
    with pytest.raises(CloudJoinError, match="^CLOUD_CONFIG_INVALID$"):
        validate_cloud_scope({**deepcopy(CONFIG), **change})


@pytest.mark.parametrize("account", ["١" * 12, "１" * 12, "1" * 11 + "١"])
@pytest.mark.parametrize("as_scope", [False, True])
def test_account_enrollment_requires_ascii_digits(account, as_scope):
    value = (
        CloudScope("company", "alpha", (("aws", account),))
        if as_scope
        else {**deepcopy(CONFIG), "accounts": [{"partition": "aws", "accountId": account}]}
    )
    with pytest.raises(CloudJoinError, match="^CLOUD_CONFIG_INVALID$"):
        validate_cloud_scope(value)


@pytest.mark.parametrize("field", ["companyId", "tenantId"])
@pytest.mark.parametrize("blank", ["\ufeff", " \ufeff\t", "\ufeff\x1c\ufeff\x85\ufeff\n"])
def test_cloud_enrollment_rejects_bom_only_identifiers(field, blank):
    config = {**CONFIG, field: blank}
    scope = CloudScope(config["companyId"], config["tenantId"], (("aws", "111122223333"),))
    for value in (config, scope):
        with pytest.raises(CloudJoinError, match="^CLOUD_CONFIG_INVALID$"):
            validate_cloud_scope(value)


def test_cloud_enrollment_preserves_nonblank_bom_identifiers():
    config = {**CONFIG, "companyId": "\ufeff \ncompany\ufeff\x85", "tenantId": "\ufefftenant\ufeff"}
    scope = validate_cloud_scope(config)
    assert scope.company_id == config["companyId"] and scope.tenant_id == config["tenantId"]
    assert validate_cloud_scope(scope) == scope


@pytest.mark.parametrize(
    ("kind", "suffix", "relationship"),
    [
        ("bucket", "reports", "G_CLOUD_MATCH"),
        ("object", "reports/private/report.txt", "G_CLOUD_CONTAINER"),
        ("prefix", "reports/private/", "G_CLOUD_CONTAINER"),
    ],
)
def test_s3_objects_and_prefixes_remain_container_associations(kind, suffix, relationship):
    value = reference(label="GuardExternalResource", arn=f"arn:aws:s3:::{suffix}", kind=kind)
    assert provider_target(value, validate_cloud_scope(CONFIG)) == {
        "label": "AWSS3Bucket",
        "id": "reports",
        "arn": "arn:aws:s3:::reports",
        "relationship": relationship,
    }
    assert value["arn"] == f"arn:aws:s3:::{suffix}"


@pytest.mark.parametrize(
    "changes",
    [
        {"account_id": "999988887777"},
        {"partition": "aws-cn"},
        {"arn": "arn:aws:sts::111122223333:assumed-role/worker/session"},
        {"arn": "arn:aws:iam::999988887777:role/worker"},
        {
            "label": "GuardExternalResource",
            "kind": "resource",
            "arn": "arn:aws:ec2:eu-west-1:111122223333:instance/i-1",
        },
    ],
)
def test_unknown_or_unenrolled_provider_identity_is_never_guessed(changes):
    assert provider_target(reference(**changes), validate_cloud_scope(CONFIG)) is None


@pytest.mark.parametrize(
    ("matches", "status", "reason"),
    [
        ([], "unresolved", "missing"),
        ([match(), match(element_id="other")], "unresolved", "ambiguous"),
        ([match(node_updated=NOW - 7201)], "stale", "stale"),
        ([match(ownership_updated=NOW - 7201)], "stale", "stale"),
        ([match(account_updated=NOW - 7201)], "stale", "stale"),
        ([match(node_updated=NOW + 1)], "unavailable", "freshness_unknown"),
        ([match(ownership_updated=True)], "unavailable", "freshness_unknown"),
        ([match(account_updated=None)], "unavailable", "freshness_unknown"),
        ([match()], "resolved", None),
    ],
)
def test_provider_receipts_require_unique_and_fresh_node_account_and_ownership(
    matches, status, reason
):
    scope = validate_cloud_scope(CONFIG)
    observed = classify_provider(
        reference(), provider_target(reference(), scope), matches, scope, NOW
    )
    assert (observed["status"], observed["reason"]) == (status, reason)
    assert (observed["match"] is not None) == (status == "resolved")


def test_region_mismatch_cannot_resolve():
    scope = validate_cloud_scope(CONFIG)
    value = reference(
        label="GuardExternalResource", arn="arn:aws:s3:::reports", kind="bucket", region="eu-west-1"
    )
    observed = classify_provider(
        value, provider_target(value, scope), [match(region="eu-west-2")], scope, NOW
    )
    assert observed["reason"] == "region_mismatch"
    assert observed["match"] is None


class Transaction:
    def __init__(self, failure=False):
        self.failure, self.queries, self.committed = failure, [], False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def run(self, query, **params):
        self.queries.append((query, params))
        if self.failure:
            raise RuntimeError("private-provider-canary")
        return [match()]

    def commit(self):
        self.committed = True


class Session:
    def __init__(self, tx):
        self.tx, self.started = tx, 0

    def begin_transaction(self, *, timeout):
        assert timeout == 5
        self.started += 1
        return self.tx


def rows(*refs):
    return {
        label: [ref for ref in refs if ref["label"] == label]
        for label in ("GuardExternalIdentity", "GuardExternalResource")
    }


def test_one_timed_transaction_and_parameterized_exact_match(monkeypatch):
    monkeypatch.setattr("agent_guard_cartography.cloud.time.time", lambda: NOW)
    session = Session(Transaction())
    result = collect_cloud(session, rows(reference()), validate_cloud_scope(CONFIG))
    assert session.started == 1 and session.tx.committed
    query, params = session.tx.queries[0]
    assert "LIMIT 2" in query and "p:AWSPrincipal" in query and "r:RESOURCE" in query
    assert "111122223333" not in query
    assert params == {
        "account": "111122223333",
        "arn": reference()["arn"],
        "provider_id": reference()["arn"],
        "company": "company",
        "tenant": "alpha",
        "partition": "aws",
    }
    assert result["observations"][0]["status"] == "resolved"
    retry = unavailable_cloud(result)
    assert retry["observations"][0]["reason"] == "capture_failed"
    assert retry["observations"][0]["match"] is None
    assert result["observations"][0]["status"] == "resolved"


def test_capture_failure_is_optional_and_redacted():
    result = collect_cloud(
        Session(Transaction(True)), rows(reference()), validate_cloud_scope(CONFIG)
    )
    assert result["observations"][0]["reason"] == "capture_failed"
    assert result["observations"][0]["match"] is None
    assert "private-provider-canary" not in str(result)


def test_overflow_drops_all_optional_evidence_without_queries():
    session = Session(Transaction())
    result = collect_cloud(
        session,
        rows(*[reference(id=str(i)) for i in range(MAX_CLOUD_REFERENCES + 1)]),
        validate_cloud_scope(CONFIG),
    )
    assert session.started == 0
    assert len(result["observations"]) == MAX_CLOUD_REFERENCES + 1
    assert {entry["reason"] for entry in result["observations"]} == {"limit_exceeded"}


def test_unenrolled_account_is_never_read():
    session = Session(Transaction())
    result = collect_cloud(
        session, rows(reference(account_id="999999999999")), validate_cloud_scope(CONFIG)
    )
    assert session.tx.queries == []
    assert result["observations"][0]["reason"] == "scope_not_enrolled"


@pytest.mark.parametrize(
    ("change", "status", "reason"),
    [
        ({}, "resolved", None),
        ({"member_hash": None}, "unresolved", "missing"),
        ({"collection_status": "running"}, "unavailable", "freshness_unknown"),
        ({"collection_version": 2}, "unavailable", "freshness_unknown"),
        ({"member_hash": "b" * 64}, "unavailable", "freshness_unknown"),
        ({"collection_updated": NOW - 7201, "member_updated": NOW - 7201}, "stale", "stale"),
        (
            {"collection_updated": NOW + 1, "member_updated": NOW + 1},
            "unavailable",
            "freshness_unknown",
        ),
    ],
)
def test_managed_collection_requires_current_membership_and_its_own_freshness(
    change, status, reason
):
    scope = validate_cloud_scope(CONFIG)
    provider = match(
        collection_id="c" * 64,
        collection_hash="a" * 64,
        member_hash="a" * 64,
        collection_version=1,
        collection_status="complete",
        collection_updated=NOW,
        member_updated=NOW,
    )
    provider.update(change)
    result = classify_provider(
        reference(), provider_target(reference(), scope), [provider], scope, NOW
    )
    assert (result["status"], result["reason"]) == (status, reason)
