from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import botocore.session
import pytest
from botocore.stub import Stubber

from agent_guard_cartography import aws_capture as capture
from agent_guard_cartography.aws_config import AwsCollectionError, AwsEnrollment

ACCOUNT = "123456789012"
CALLER = f"arn:aws:sts::{ACCOUNT}:assumed-role/Inventory/session"
DATE = datetime(2024, 1, 2, tzinfo=UTC)


@pytest.fixture
def enrollment():
    return AwsEnrollment(
        "company",
        "tenant",
        "aws",
        ACCOUNT,
        "us-east-1",
        CALLER,
        "CAPTURE_KEY",
        "CAPTURE_SECRET",
        "CAPTURE_TOKEN",
    )


def role(name="Reader", identifier="AROABCDEFGHIJKLMNOPQ"):
    return {
        "Path": "/service/",
        "RoleName": name,
        "RoleId": identifier,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/service/{name}",
        "CreateDate": DATE,
    }


def user():
    return {
        "Path": "/",
        "UserName": "Reader",
        "UserId": "AIDABCDEFGHIJKLMNOPQ",
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/Reader",
        "CreateDate": DATE,
        "PasswordLastUsed": datetime(2026, 1, 1, tzinfo=UTC),
    }


class Client:
    def __init__(self, **operations):
        self.operations = operations
        self.calls = []

    def __getattr__(self, name):
        def invoke(**kwargs):
            self.calls.append((name, kwargs))
            values = self.operations.get(name)
            assert values, f"Unexpected operation: {name}"
            value = values.pop(0)
            if isinstance(value, Exception):
                raise value
            return value

        return invoke


def clients(*, identity=None, roles=None, users=None, buckets=None, locations=None, policies=None):
    return {
        "sts": Client(
            get_caller_identity=[
                identity if identity is not None else {"Account": ACCOUNT, "Arn": CALLER}
            ]
        ),
        "iam": Client(
            list_roles=roles if roles is not None else [{"Roles": [], "IsTruncated": False}],
            list_users=users if users is not None else [{"Users": [], "IsTruncated": False}],
            get_account_authorization_details=policies if policies is not None else [],
        ),
        "s3": Client(
            list_buckets=buckets if buckets is not None else [{"Buckets": []}],
            get_bucket_location=locations if locations is not None else [],
        ),
    }


def error(code, fn):
    with pytest.raises(AwsCollectionError) as raised:
        fn()
    assert raised.value.code == code
    assert str(raised.value) == code


def test_official_stubber_full_capture_uses_only_explicit_metadata_operations(enrollment):
    session = botocore.session.get_session()
    sdk = {
        name: session.create_client(
            name,
            region_name="us-east-1",
            aws_access_key_id="fixture-key",
            aws_secret_access_key="fixture-secret",
            aws_session_token="fixture-token",
        )
        for name in ("sts", "iam", "s3")
    }
    with ExitStack() as stack:
        stubs = {name: stack.enter_context(Stubber(client)) for name, client in sdk.items()}
        stubs["sts"].add_response(
            "get_caller_identity", {"Account": ACCOUNT, "Arn": CALLER, "UserId": "fixture-user"}, {}
        )
        stubs["iam"].add_response(
            "list_roles",
            {"Roles": [role("Zed")], "IsTruncated": True, "Marker": "next"},
            {"MaxItems": 1000},
        )
        stubs["iam"].add_response(
            "list_roles",
            {"Roles": [role("Able", "AROABCDEFGHIJKLMNOPR")], "IsTruncated": False},
            {"MaxItems": 1000, "Marker": "next"},
        )
        stubs["iam"].add_response(
            "list_users", {"Users": [user()], "IsTruncated": False}, {"MaxItems": 1000}
        )
        stubs["s3"].add_response(
            "list_buckets",
            {
                "Buckets": [
                    {"Name": "fixture-bucket", "CreationDate": DATE, "BucketRegion": "eu-west-1"}
                ],
                "ContinuationToken": "next",
            },
            {"MaxBuckets": 1000},
        )
        stubs["s3"].add_response(
            "get_bucket_location",
            {"LocationConstraint": "EU"},
            {"Bucket": "fixture-bucket", "ExpectedBucketOwner": ACCOUNT},
        )
        stubs["s3"].add_response(
            "list_buckets", {"Buckets": []}, {"MaxBuckets": 1000, "ContinuationToken": "next"}
        )
        captured_at = int(time.time())
        result = capture.capture_from_clients(enrollment, sdk, clock=lambda: captured_at)
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    for client in sdk.values():
        client.close()
    assert set(result) == {"capturedAt", "roles", "users", "buckets"}
    assert result["capturedAt"] == captured_at
    assert [item["name"] for item in result["roles"]] == ["Able", "Zed"]
    assert result["roles"][0]["createdate_dt"] == "2024-01-02T00:00:00Z"
    assert result["users"][0]["passwordlastused"] == ""
    assert result["users"][0]["passwordlastused_dt"] is None
    assert result["buckets"] == [
        {
            "Name": "fixture-bucket",
            "Arn": "arn:aws:s3:::fixture-bucket",
            "Region": "eu-west-1",
            "CreationDate": "2024-01-02T00:00:00Z",
        }
    ]
    assert "2026-01-01" not in json.dumps(result)
    from agent_guard_cartography.aws_graph import validate_aws_capture

    assert validate_aws_capture(enrollment, result) == result


@pytest.mark.parametrize(
    "identity",
    [
        {"Account": "999999999999", "Arn": CALLER},
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:root"},
        {"Account": ACCOUNT, "Arn": CALLER + "other"},
        {},
    ],
)
def test_wrong_identity_fails_before_any_inventory_request(enrollment, identity):
    selected = clients(identity=identity)
    error("AWS_IDENTITY_MISMATCH", lambda: capture.capture_from_clients(enrollment, selected))
    assert selected["iam"].calls == selected["s3"].calls == []


@pytest.mark.parametrize(
    "pages",
    [
        [{"Roles": [], "IsTruncated": True}],
        [
            {"Roles": [], "IsTruncated": True, "Marker": "again"},
            {"Roles": [], "IsTruncated": True, "Marker": "again"},
        ],
        [{"Roles": [], "IsTruncated": False, "Marker": "unexpected"}],
        [{"Roles": [], "IsTruncated": "false"}],
        [{"Roles": []}],
    ],
)
def test_iam_completeness_and_marker_validation(enrollment, pages):
    error(
        "AWS_CAPTURE_INVALID",
        lambda: capture.capture_from_clients(enrollment, clients(roles=pages)),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"Arn": "arn:aws:iam::999999999999:role/service/Reader"},
        {"RoleName": "Wrong"},
        {"Path": "../"},
        {"RoleId": ""},
        {"CreateDate": datetime(2024, 1, 1)},
    ],
)
def test_role_identity_and_dates_are_strict(enrollment, mutation):
    error(
        "AWS_CAPTURE_INVALID",
        lambda: capture.capture_from_clients(
            enrollment, clients(roles=[{"Roles": [{**role(), **mutation}], "IsTruncated": False}])
        ),
    )


def test_duplicate_identity_is_not_silently_deduplicated(enrollment):
    pages = [
        {"Roles": [role()], "IsTruncated": True, "Marker": "next"},
        {"Roles": [role()], "IsTruncated": False},
    ]
    error(
        "AWS_CAPTURE_INVALID",
        lambda: capture.capture_from_clients(enrollment, clients(roles=pages)),
    )


@pytest.mark.parametrize(
    "bucket,location",
    [
        ({"Name": "../invalid", "CreationDate": DATE}, {}),
        ({"Name": "fixture-bucket", "CreationDate": DATE}, {"LocationConstraint": "us-gov-west-1"}),
        ({"Name": "fixture-bucket", "CreationDate": DATE, "BucketRegion": "eu-west-1"}, {}),
        ({"Name": "fixture-bucket", "CreationDate": DATE, "BucketArn": "arn:aws:s3:::wrong"}, {}),
    ],
)
def test_bucket_metadata_must_be_canonical(enrollment, bucket, location):
    selected = clients(buckets=[{"Buckets": [bucket]}], locations=[location])
    error("AWS_CAPTURE_INVALID", lambda: capture.capture_from_clients(enrollment, selected))


def test_s3_pagination_cycles_and_duplicate_buckets_fail(enrollment):
    error(
        "AWS_CAPTURE_INVALID",
        lambda: capture.capture_from_clients(
            enrollment,
            clients(
                buckets=[
                    {"Buckets": [], "ContinuationToken": "again"},
                    {"Buckets": [], "ContinuationToken": "again"},
                ]
            ),
        ),
    )
    bucket = {"Name": "fixture-bucket", "CreationDate": DATE, "BucketRegion": "us-east-1"}
    error(
        "AWS_CAPTURE_INVALID",
        lambda: capture.capture_from_clients(
            enrollment, clients(buckets=[{"Buckets": [bucket, bucket]}], locations=[{}])
        ),
    )


def test_optional_provider_failure_is_not_reported_as_complete(enrollment):
    selected = clients(
        buckets=[
            {
                "Buckets": [
                    {"Name": "fixture-bucket", "CreationDate": DATE, "BucketRegion": "us-east-1"}
                ]
            }
        ],
        locations=[RuntimeError("provider-response-secret-canary")],
    )
    error("AWS_COLLECTION_FAILED", lambda: capture.capture_from_clients(enrollment, selected))


@pytest.mark.parametrize(
    "limit,code", [("max_api_calls", "AWS_LIMIT_EXCEEDED"), ("max_pages", "AWS_LIMIT_EXCEEDED")]
)
def test_aggregate_call_and_page_bounds(enrollment, limit, code):
    error(code, lambda: capture.capture_from_clients(replace(enrollment, **{limit: 1}), clients()))


def test_item_and_serialized_capture_bounds(enrollment):
    selected = clients(
        roles=[{"Roles": [role(), role("Second", "AROABCDEFGHIJKLMNOPR")], "IsTruncated": False}]
    )
    error(
        "AWS_LIMIT_EXCEEDED",
        lambda: capture.capture_from_clients(replace(enrollment, max_items=1), selected),
    )
    selected = clients(
        roles=[
            {
                "Roles": [role(str(index), f"AROABCDEFGHIJKLMN{index}") for index in range(10)],
                "IsTruncated": False,
            }
        ]
    )
    error(
        "AWS_CAPTURE_TOO_LARGE",
        lambda: capture.capture_from_clients(replace(enrollment, max_capture_bytes=1024), selected),
    )


def test_entire_response_is_bounded_including_unexported_fields(enrollment):
    selected = clients(identity={"Account": ACCOUNT, "Arn": CALLER, "Unused": "x" * 2000})
    error(
        "AWS_RESPONSE_TOO_LARGE",
        lambda: capture.capture_from_clients(
            replace(enrollment, max_response_bytes=1024), selected
        ),
    )


def test_logical_deadline_checked_after_each_api_call(enrollment):
    now = [0]

    def identity():
        now[0] = 2
        return {"Account": ACCOUNT, "Arn": CALLER}

    selected = clients()
    selected["sts"] = SimpleNamespace(get_caller_identity=identity)
    error(
        "AWS_TIMEOUT",
        lambda: capture.capture_from_clients(
            replace(enrollment, timeout_seconds=1, request_timeout_seconds=1),
            selected,
            monotonic=lambda: now[0],
        ),
    )


def test_explicit_credentials_only_and_no_ambient_fallback(enrollment, monkeypatch):
    for name in ("CAPTURE_KEY", "CAPTURE_SECRET", "CAPTURE_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ambient-key-canary")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret-canary")
    error("AWS_CREDENTIAL_REQUIRED", lambda: capture.capture_aws(enrollment))
    expected = ["frozen-key", "frozen-secret", "frozen-token"]
    for name, value in zip(
        ("CAPTURE_KEY", "CAPTURE_SECRET", "CAPTURE_TOKEN"), expected, strict=True
    ):
        monkeypatch.setenv(name, value)

    def run(_enrollment, values):
        monkeypatch.setenv("CAPTURE_SECRET", "changed")
        assert values == expected
        return {"capturedAt": 1, "roles": [], "users": [], "buckets": []}

    monkeypatch.setattr(capture, "_run_worker", run)
    assert capture.capture_aws(enrollment)["roles"] == []


class Response:
    def __init__(self, body=b"<response/>", status=200, headers=None):
        self.status = status
        self.body = io.BytesIO(body)
        self.headers = headers or {"Content-Type": "text/xml"}
        self.reads = []

    def getheaders(self):
        return list(self.headers.items())

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, size):
        self.reads.append(size)
        return self.body.read(size)


def transport(enrollment, monkeypatch, response):
    seen = []

    class Connection:
        def __init__(self, host, port, **kwargs):
            assert kwargs["context"].check_hostname is True
            assert kwargs["context"].verify_mode == capture.ssl.CERT_REQUIRED
            seen.append((host, port, kwargs))

        def request(self, *args):
            seen.append(args)

        def getresponse(self):
            return response

        def close(self):
            seen.append("closed")

    monkeypatch.setattr(capture.http.client, "HTTPSConnection", Connection)
    return capture._BoundedHTTPS(
        enrollment, ["iam.amazonaws.com"], capture._Budget(enrollment)
    ), seen


@pytest.mark.parametrize(
    "url",
    [
        "http://iam.amazonaws.com/",
        "https://iam.amazonaws.com.evil/",
        "https://user@iam.amazonaws.com/",
        "https://iam.amazonaws.com:444/",
        "https://iam.amazonaws.com/#fragment",
    ],
)
def test_transport_rejects_noncanonical_destinations_before_network(enrollment, monkeypatch, url):
    selected, seen = transport(enrollment, monkeypatch, Response())
    request = SimpleNamespace(url=url, body=None, method="POST", headers={})
    error("AWS_ENDPOINT_DENIED", lambda: selected.send(request))
    assert not seen


@pytest.mark.parametrize(
    "response,code",
    [
        (Response(status=302), "AWS_ENDPOINT_DENIED"),
        (Response(headers={"Content-Encoding": "gzip"}), "AWS_CAPTURE_INVALID"),
        (Response(headers={"Content-Length": "100000"}), "AWS_RESPONSE_TOO_LARGE"),
        (Response(headers={"Content-Length": "100"}), "AWS_CAPTURE_INVALID"),
        (
            Response(headers={"Content-Length": "11", "Transfer-Encoding": "chunked"}),
            "AWS_CAPTURE_INVALID",
        ),
        (Response(headers={"Transfer-Encoding": "compress"}), "AWS_CAPTURE_INVALID"),
        (Response(body=b"x" * 3000), "AWS_RESPONSE_TOO_LARGE"),
    ],
)
def test_transport_caps_before_botocore_parsing(enrollment, monkeypatch, response, code):
    selected, seen = transport(replace(enrollment, max_response_bytes=1024), monkeypatch, response)
    request = SimpleNamespace(
        url="https://iam.amazonaws.com/", body=b"Action=ListRoles", method="POST", headers={}
    )
    error(code, lambda: selected.send(request))
    assert seen[-1] == "closed"
    assert not response.reads or response.reads[0] <= 1025


def test_transport_returns_official_aws_response_and_always_closes(enrollment, monkeypatch):
    selected, seen = transport(enrollment, monkeypatch, Response(b"<ok/>"))
    request = SimpleNamespace(
        url="https://iam.amazonaws.com/",
        body=b"Action=ListRoles",
        method="POST",
        headers={"Authorization": b"fixture-signature"},
    )
    response = selected.send(request)
    assert response.content == b"<ok/>"
    assert seen[1][3]["Accept-Encoding"] == "identity"
    assert seen[-1] == "closed"


def test_duplicate_framing_headers_are_rejected_before_body(enrollment, monkeypatch):
    response = Response()
    response.getheaders = lambda: [("Content-Length", "11"), ("Content-Length", "11")]
    selected, _seen = transport(enrollment, monkeypatch, response)
    request = SimpleNamespace(
        url="https://iam.amazonaws.com/", body=b"Action=ListRoles", method="POST", headers={}
    )
    error("AWS_CAPTURE_INVALID", lambda: selected.send(request))
    assert response.reads == []


def test_worker_sanitizes_environment_and_never_places_credentials_in_argv(enrollment, monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://untrusted.example")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy-secret-canary.example")
    script = "import json,sys,os; v=json.load(sys.stdin); assert v['credentials']==['key','secret','token']; assert not any(k in ('AWS_ENDPOINT_URL','AWS_PROFILE','HTTPS_PROXY','HTTP_PROXY','PYTHONPATH') for k in os.environ); assert os.environ['AWS_CONFIG_FILE']==os.devnull; assert os.environ['AWS_SHARED_CREDENTIALS_FILE']==os.devnull; assert os.environ['BOTO_CONFIG']==os.devnull; assert os.environ['AWS_EC2_METADATA_DISABLED']=='true'; print(json.dumps({'ok':True,'capture':{'capturedAt':1,'roles':[],'users':[],'buckets':[]}}))"
    result = capture._run_worker(
        enrollment, ["key", "secret", "token"], command=[sys.executable, "-c", script]
    )
    assert result["buckets"] == []


def test_real_sdk_signing_and_regional_selection_use_only_fixed_endpoints(enrollment, monkeypatch):
    from botocore.awsrequest import AWSResponse

    seen = []
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://untrusted.example")
    monkeypatch.setenv("AWS_PROFILE", "untrusted-profile")

    # No HTTP connection occurs: this replaces the entire already-verified transport.
    class SignedTransport:
        def __init__(self, _enrollment, hosts, _budget):
            self.hosts = hosts

        def close(self):
            pass

        def send(self, request):
            url = urlsplit(request.url)
            assert url.hostname in self.hosts
            capture._wire_request(enrollment, request, url)
            authorization = request.headers["Authorization"].decode()
            seen.append((url.hostname, url.path, authorization))
            if url.hostname.startswith("sts."):
                body = f"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>{CALLER}</Arn><Account>{ACCOUNT}</Account><UserId>fixture</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"
            elif url.hostname == "iam.amazonaws.com":
                body_text = (
                    request.body.decode() if isinstance(request.body, bytes) else request.body
                )
                operation = parse_qs(body_text)["Action"][0]
                assert operation in ("ListRoles", "ListUsers")
                key = "Roles" if operation == "ListRoles" else "Users"
                assert "/us-east-1/iam/aws4_request" in authorization
                body = f"<{operation}Response><{operation}Result><{key}/><IsTruncated>false</IsTruncated></{operation}Result></{operation}Response>"
            elif url.hostname == "s3.ap-south-1.amazonaws.com":
                assert url.path == "/" and "max-buckets=1000" in url.query
                body = "<ListAllMyBucketsResult><Buckets><Bucket><Name>fixture-bucket</Name><CreationDate>2024-01-02T00:00:00Z</CreationDate><BucketRegion>eu-west-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>"
            else:
                assert url.hostname == "s3.eu-west-1.amazonaws.com"
                assert url.path == "/fixture-bucket" and url.query == "location"
                assert request.headers["x-amz-expected-bucket-owner"] == ACCOUNT.encode()
                assert "/eu-west-1/s3/aws4_request" in authorization
                body = "<LocationConstraint>eu-west-1</LocationConstraint>"
            return AWSResponse(
                request.url, 200, {"content-type": "text/xml"}, capture._BufferedRaw(body.encode())
            )

    monkeypatch.setattr(capture, "_BoundedHTTPS", SignedTransport)
    result = capture._capture_worker(
        replace(enrollment, region="ap-south-1"), ["fixture-key", "fixture-secret", "fixture-token"]
    )
    assert len(seen) == 5
    assert result["buckets"][0]["Region"] == "eu-west-1"


def test_policy_opt_in_uses_official_sdk_and_discards_private_policy_values(enrollment):
    enrollment = replace(enrollment, include_iam_policy_evidence=True)
    session = botocore.session.get_session()
    sdk = {
        name: session.create_client(
            name,
            region_name="us-east-1",
            aws_access_key_id="fixture-key",
            aws_secret_access_key="fixture-secret",
            aws_session_token="fixture-token",
        )
        for name in ("sts", "iam", "s3")
    }
    document = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::fixture-bucket/private-prefix-canary/*",
            "Condition": {"StringEquals": {"aws:PrincipalTag/team": "condition-value-canary"}},
        },
    }
    with ExitStack() as stack:
        stubs = {name: stack.enter_context(Stubber(client)) for name, client in sdk.items()}
        stubs["sts"].add_response(
            "get_caller_identity", {"Account": ACCOUNT, "Arn": CALLER, "UserId": "fixture-user"}, {}
        )
        stubs["iam"].add_response(
            "list_roles", {"Roles": [role()], "IsTruncated": False}, {"MaxItems": 1000}
        )
        stubs["iam"].add_response(
            "list_users", {"Users": [], "IsTruncated": False}, {"MaxItems": 1000}
        )
        stubs["s3"].add_response(
            "list_buckets",
            {
                "Buckets": [
                    {"Name": "fixture-bucket", "CreationDate": DATE, "BucketRegion": "us-east-1"}
                ]
            },
            {"MaxBuckets": 1000},
        )
        stubs["s3"].add_response(
            "get_bucket_location", {}, {"Bucket": "fixture-bucket", "ExpectedBucketOwner": ACCOUNT}
        )
        stubs["iam"].add_response(
            "get_account_authorization_details",
            {
                "RoleDetailList": [
                    {
                        **role(),
                        "RolePolicyList": [
                            {
                                "PolicyName": "policy-name-canary",
                                "PolicyDocument": json.dumps(document),
                            }
                        ],
                    }
                ],
                "IsTruncated": True,
                "Marker": "policies-next",
            },
            policy_parameters(),
        )
        stubs["iam"].add_response(
            "get_account_authorization_details",
            {"IsTruncated": False},
            {**policy_parameters(), "Marker": "policies-next"},
        )
        result = capture.capture_from_clients(enrollment, sdk)
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    for client in sdk.values():
        client.close()
    evidence = result["policyEvidence"]
    assert evidence["assessment"] == "unknown"
    assert evidence["principals"] == [
        {"arn": role()["Arn"], "boundaryPresent": False, "status": "mapped"}
    ]
    assert evidence["edges"] == [
        {
            "principalArn": role()["Arn"],
            "bucketArn": "arn:aws:s3:::fixture-bucket",
            "relationship": "CAN_READ",
            "hasCondition": True,
            "conditionKeys": ["aws:PrincipalTag/team"],
            "resourceScope": "bucket_summary",
            "assessment": "unknown",
        }
    ]
    serialized = json.dumps(result)
    assert "canary" not in serialized
    assert "PolicyDocument" not in serialized


def policy_parameters():
    return {
        "Filter": ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"],
        "MaxItems": 100,
    }


def policy_wire_parameters():
    return {
        "Action": "GetAccountAuthorizationDetails",
        "Version": "2010-05-08",
        "MaxItems": "100",
        **{
            f"Filter.member.{index}": name
            for index, name in enumerate(policy_parameters()["Filter"], start=1)
        },
    }


def test_policy_read_is_absent_without_explicit_opt_in(enrollment):
    selected = clients(policies=[RuntimeError("must-not-run")])
    result = capture.capture_from_clients(enrollment, selected)
    assert "policyEvidence" not in result
    assert [name for name, _params in selected["iam"].calls] == ["list_roles", "list_users"]


@pytest.mark.parametrize("limit", ["max_api_calls", "max_pages"])
def test_policy_calls_consume_existing_aggregate_budget(enrollment, limit):
    selected = clients(policies=[{"IsTruncated": False}])
    maximum = 4 if limit == "max_api_calls" else 3
    error(
        "AWS_LIMIT_EXCEEDED",
        lambda: capture.capture_from_clients(
            replace(enrollment, include_iam_policy_evidence=True, **{limit: maximum}), selected
        ),
    )
    assert [name for name, _params in selected["iam"].calls] == ["list_roles", "list_users"]


def test_policy_provider_failure_aborts_entire_capture_without_response_details(enrollment):
    error(
        "AWS_COLLECTION_FAILED",
        lambda: capture.capture_from_clients(
            replace(enrollment, include_iam_policy_evidence=True),
            clients(policies=[RuntimeError("private-policy-provider-error-canary")]),
        ),
    )


def test_policy_mapping_cannot_extend_total_deadline(enrollment, monkeypatch):
    from agent_guard_cartography import aws_policy

    now = [0]

    def mapper(*_args):
        now[0] = 2
        return {}

    monkeypatch.setattr(aws_policy, "capture_policy_evidence", mapper)
    error(
        "AWS_TIMEOUT",
        lambda: capture.capture_from_clients(
            replace(
                enrollment,
                include_iam_policy_evidence=True,
                timeout_seconds=1,
                request_timeout_seconds=1,
            ),
            clients(),
            monotonic=lambda: now[0],
        ),
    )


@pytest.mark.parametrize(
    "change,code",
    [
        (lambda item: item.update(PolicyDocument="private-worker-canary"), "AWS_POLICY_INVALID"),
        (lambda item: item.update(assessment="allowed"), "AWS_POLICY_INVALID"),
        (lambda item: item.update(edges=[{}, {}]), "AWS_POLICY_LIMIT_EXCEEDED"),
    ],
)
def test_public_capture_revalidates_private_worker_policy_output(
    enrollment, monkeypatch, change, code
):
    enrolled = replace(enrollment, include_iam_policy_evidence=True, max_policy_edges=1)
    result = capture.capture_from_clients(enrolled, clients(policies=[{"IsTruncated": False}]))
    change(result["policyEvidence"])
    monkeypatch.setattr(capture, "_credentials", lambda _enrollment: ["key", "secret", "token"])
    monkeypatch.setattr(capture, "_run_worker", lambda *_args: result)
    error(code, lambda: capture.capture_aws(enrolled))


def test_public_capture_rejects_missing_policy_result_from_opted_in_worker(enrollment, monkeypatch):
    monkeypatch.setattr(capture, "_credentials", lambda _enrollment: ["key", "secret", "token"])
    monkeypatch.setattr(
        capture,
        "_run_worker",
        lambda *_args: {"capturedAt": 1, "roles": [], "users": [], "buckets": []},
    )
    error(
        "AWS_CAPTURE_INVALID",
        lambda: capture.capture_aws(replace(enrollment, include_iam_policy_evidence=True)),
    )


def test_policy_response_uses_existing_pre_projection_size_limit(enrollment):
    error(
        "AWS_RESPONSE_TOO_LARGE",
        lambda: capture.capture_from_clients(
            replace(enrollment, include_iam_policy_evidence=True, max_response_bytes=1024),
            clients(policies=[{"IsTruncated": False, "Unused": "policy-canary" * 1000}]),
        ),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"Version": "other"},
        {"MaxItems": "1000"},
        {"Filter.member.1": "Role"},
        {"Filter.member.5": "User"},
        {"Filter.member.6": "User"},
        {"Marker": ""},
        {"Extra": "private-canary"},
    ],
)
def test_policy_wire_requires_exact_bounded_complete_operation(enrollment, mutation):
    body = urlencode({**policy_wire_parameters(), **mutation}).encode()
    request = SimpleNamespace(method="POST", body=body, headers={})
    error(
        "AWS_ENDPOINT_DENIED",
        lambda: capture._wire_request(
            replace(enrollment, include_iam_policy_evidence=True),
            request,
            urlsplit("https://iam.amazonaws.com/"),
        ),
    )


def test_policy_wire_requires_opt_in_and_accepts_bounded_pagination(enrollment):
    request = SimpleNamespace(
        method="POST", body=urlencode(policy_wire_parameters()).encode(), headers={}
    )
    url = urlsplit("https://iam.amazonaws.com/")
    error("AWS_ENDPOINT_DENIED", lambda: capture._wire_request(enrollment, request, url))
    opted_in = replace(enrollment, include_iam_policy_evidence=True)
    capture._wire_request(opted_in, request, url)
    request.body = urlencode({**policy_wire_parameters(), "Marker": "next-marker"}).encode()
    capture._wire_request(opted_in, request, url)


def test_real_signed_policy_request_and_xml_are_accepted_only_when_enrolled(
    enrollment, monkeypatch
):
    from botocore.awsrequest import AWSResponse

    enrollment = replace(enrollment, include_iam_policy_evidence=True)
    seen = []
    role_xml = (
        "<Path>/service/</Path><RoleName>Reader</RoleName>"
        "<RoleId>AROABCDEFGHIJKLMNOPQ</RoleId>"
        f"<Arn>{role()['Arn']}</Arn><CreateDate>2024-01-02T00:00:00Z</CreateDate>"
    )
    encoded_policy = quote(
        json.dumps(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::fixture-bucket/*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "private-xml-canary"}},
                }
            }
        ),
        safe="",
    )

    class SignedTransport:
        def __init__(self, selected, hosts, _budget):
            assert selected.include_iam_policy_evidence
            self.hosts = hosts

        def close(self):
            pass

        def send(self, request):
            url = urlsplit(request.url)
            assert url.hostname in self.hosts
            capture._wire_request(enrollment, request, url)
            if url.hostname.startswith("sts."):
                body = f"<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>{CALLER}</Arn><Account>{ACCOUNT}</Account><UserId>fixture</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"
            elif url.hostname == "iam.amazonaws.com":
                text = request.body.decode() if isinstance(request.body, bytes) else request.body
                values = parse_qs(text)
                operation = values["Action"][0]
                assert "/us-east-1/iam/aws4_request" in request.headers["Authorization"].decode()
                seen.append(operation)
                if operation == "GetAccountAuthorizationDetails":
                    assert {
                        key: items[0] for key, items in values.items()
                    } == policy_wire_parameters()
                    content = (
                        f"<RoleDetailList><member>{role_xml}"
                        "<RolePolicyList><member><PolicyName>fixture</PolicyName>"
                        f"<PolicyDocument>{encoded_policy}</PolicyDocument>"
                        "</member></RolePolicyList></member></RoleDetailList>"
                        "<UserDetailList/><GroupDetailList/><Policies/>"
                    )
                else:
                    content = (
                        f"<Roles><member>{role_xml}</member></Roles>"
                        if operation == "ListRoles"
                        else "<Users/>"
                    )
                body = f"<{operation}Response><{operation}Result>{content}<IsTruncated>false</IsTruncated></{operation}Result></{operation}Response>"
            elif url.path == "/fixture-bucket":
                body = "<LocationConstraint/>"
            else:
                body = "<ListAllMyBucketsResult><Buckets><Bucket><Name>fixture-bucket</Name><CreationDate>2024-01-02T00:00:00Z</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>"
            return AWSResponse(
                request.url, 200, {"content-type": "text/xml"}, capture._BufferedRaw(body.encode())
            )

    monkeypatch.setattr(capture, "_BoundedHTTPS", SignedTransport)
    result = capture._capture_worker(enrollment, ["fixture-key", "fixture-secret", "fixture-token"])
    assert seen == ["ListRoles", "ListUsers", "GetAccountAuthorizationDetails"]
    (edge,) = result["policyEvidence"]["edges"]
    assert edge["relationship"] == "CAN_READ"
    assert edge["conditionKeys"] == ["aws:PrincipalTag/team"]
    assert edge["hasCondition"] is True
    assert "private-xml-canary" not in json.dumps(result)


def test_missing_bucket_region_fails_before_location_lookup(enrollment):
    selected = clients(buckets=[{"Buckets": [{"Name": "fixture-bucket", "CreationDate": DATE}]}])
    error("AWS_CAPTURE_INVALID", lambda: capture.capture_from_clients(enrollment, selected))
    assert [name for name, _ in selected["s3"].calls] == ["list_buckets"]


@pytest.mark.parametrize(
    "host,method,path,body",
    [
        ("s3.us-east-1.amazonaws.com", "HEAD", "/fixture-bucket", None),
        ("s3.us-east-1.amazonaws.com", "GET", "/fixture-bucket/object", None),
        ("s3.us-east-1.amazonaws.com", "GET", "/fixture-bucket?policy", None),
        ("iam.amazonaws.com", "POST", "/", b"Action=GenerateServiceLastAccessedDetails"),
        ("iam.amazonaws.com", "POST", "/", b"Action=ListRoles&Action=DeleteRole"),
        ("sts.us-east-1.amazonaws.com", "POST", "/", b"Action=AssumeRole"),
    ],
)
def test_transport_rejects_unlisted_sdk_retry_or_mutation_operations(
    enrollment, monkeypatch, host, method, path, body
):
    selected, seen = transport(enrollment, monkeypatch, Response())
    selected.allowed_hosts = frozenset([host])
    request = SimpleNamespace(url=f"https://{host}{path}", body=body, method=method, headers={})
    error("AWS_ENDPOINT_DENIED", lambda: selected.send(request))
    assert seen == []


def test_worker_hard_deadline_kills_owned_process(enrollment, monkeypatch):
    launched = []
    original = subprocess.Popen

    def start(*args, **kwargs):
        process = original(*args, **kwargs)
        launched.append(process)
        return process

    monkeypatch.setattr(capture.subprocess, "Popen", start)
    started = time.monotonic()
    error(
        "AWS_TIMEOUT",
        lambda: capture._run_worker(
            replace(enrollment, timeout_seconds=1, request_timeout_seconds=1),
            ["key", "secret", "token"],
            command=[sys.executable, "-c", "import time; time.sleep(60)"],
        ),
    )
    assert time.monotonic() - started < 3
    assert launched[0].poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(launched[0].pid, 0)


@pytest.mark.parametrize(
    "script,code",
    [
        ("import sys; sys.stdout.write('x'*5000)", "AWS_CAPTURE_TOO_LARGE"),
        ("print('not-json')", "AWS_COLLECTION_FAILED"),
        ('print(\'{"ok":false,"error":[]}\')', "AWS_COLLECTION_FAILED"),
        ('print(\'{"ok":false,"error":"secret-provider-error"}\')', "AWS_COLLECTION_FAILED"),
        ('import sys; print(\'{"ok":false,"error":"AWS_TIMEOUT"}\'); sys.exit(2)', "AWS_TIMEOUT"),
    ],
)
def test_worker_output_and_diagnostics_are_bounded(enrollment, script, code):
    error(
        code,
        lambda: capture._run_worker(
            replace(enrollment, max_capture_bytes=1024),
            ["key", "secret", "token"],
            command=[sys.executable, "-c", script],
        ),
    )


@pytest.mark.parametrize(
    "code", ["AWS_POLICY_INVALID", "AWS_POLICY_INCOMPLETE", "AWS_POLICY_LIMIT_EXCEEDED"]
)
def test_worker_preserves_only_stable_policy_diagnostics(enrollment, code):
    payload = json.dumps({"ok": False, "error": code})
    error(
        code,
        lambda: capture._run_worker(
            replace(enrollment, include_iam_policy_evidence=True),
            ["key", "secret", "token"],
            command=[sys.executable, "-c", f"import sys; print({payload!r}); sys.exit(2)"],
        ),
    )
