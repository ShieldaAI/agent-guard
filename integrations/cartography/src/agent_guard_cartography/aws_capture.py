"""Bounded single-account AWS capture, with optional minimized IAM policy evidence.

Production exchanges run in an owned disposable process. Botocore signs and
parses five metadata APIs and one explicitly enabled policy API; its transport is verified,
nonredirecting HTTPS transport that caps bodies before botocore parses them.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import re
import selectors
import signal
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agent_guard_cartography.aws_config import (
    AwsCollectionError,
    AwsEnrollment,
    enrollment_dict,
    validate_aws_enrollment,
)

_REGION = re.compile(
    r"(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|west|north|south|northeast|northwest|southeast|southwest)-[1-9][0-9]?"
)
_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}")
_CODES = {
    "AWS_CONFIG_INVALID",
    "AWS_CREDENTIAL_REQUIRED",
    "AWS_IDENTITY_MISMATCH",
    "AWS_CAPTURE_INVALID",
    "AWS_CAPTURE_TOO_LARGE",
    "AWS_RESPONSE_TOO_LARGE",
    "AWS_LIMIT_EXCEEDED",
    "AWS_TIMEOUT",
    "AWS_ENDPOINT_DENIED",
    "AWS_COLLECTION_FAILED",
    "AWS_PLATFORM_UNSUPPORTED",
    "AWS_POLICY_INVALID",
    "AWS_POLICY_INCOMPLETE",
    "AWS_POLICY_LIMIT_EXCEEDED",
}


def _fail(code: str = "AWS_CAPTURE_INVALID") -> None:
    raise AwsCollectionError(code)


def _json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
            default=lambda item: _date(item),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail()


def _text(value: Any, maximum: int = 2048) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8", "surrogatepass")) > maximum
        or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        _fail()
    return value


def _date(value: Any) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        _fail()


class _Budget:
    def __init__(self, enrollment: AwsEnrollment, monotonic=time.monotonic):
        self.enrollment = enrollment
        self.monotonic = monotonic
        self.deadline = monotonic() + enrollment.timeout_seconds
        self.calls = 0
        self.pages = 0

    def check(self) -> None:
        if self.monotonic() >= self.deadline:
            _fail("AWS_TIMEOUT")

    def call(self) -> None:
        self.check()
        self.calls += 1
        if self.calls > self.enrollment.max_api_calls:
            _fail("AWS_LIMIT_EXCEEDED")

    def page(self) -> None:
        self.check()
        self.pages += 1
        if self.pages > self.enrollment.max_pages:
            _fail("AWS_LIMIT_EXCEEDED")


def capture_from_clients(
    enrollment: AwsEnrollment, clients: dict, *, clock=time.time, monotonic=time.monotonic
) -> dict:
    """Capture from already selected trusted clients; useful for offline SDK stubs.

    This function enforces logical/response limits. Production additionally uses
    the bounded transport and owned worker below for DNS/socket/process deadlines.
    No failure returns a partial capture.
    """
    enrollment = validate_aws_enrollment(enrollment)
    budget = _Budget(enrollment, monotonic)
    item_count = 0
    capture_size = 128
    output: dict[str, Any] = {"capturedAt": 0, "roles": [], "users": [], "buckets": []}

    def call(service, operation, *, selected_client=None, **kwargs):
        budget.call()
        try:
            result = getattr(
                selected_client if selected_client is not None else clients[service], operation
            )(**kwargs)
        except AwsCollectionError:
            raise
        except Exception:
            _fail("AWS_COLLECTION_FAILED")
        budget.check()
        if type(result) is not dict:
            _fail()
        if len(_json(result)) > enrollment.max_response_bytes:
            _fail("AWS_RESPONSE_TOO_LARGE")
        return result

    def append(kind, value):
        nonlocal item_count, capture_size
        item_count += 1
        if item_count > enrollment.max_items:
            _fail("AWS_LIMIT_EXCEEDED")
        capture_size += len(_json(value)) + 1
        if capture_size > enrollment.max_capture_bytes:
            _fail("AWS_CAPTURE_TOO_LARGE")
        output[kind].append(value)

    identity = call("sts", "get_caller_identity")
    if (
        identity.get("Account") != enrollment.account_id
        or identity.get("Arn") != enrollment.expected_caller_arn
    ):
        _fail("AWS_IDENTITY_MISMATCH")

    for kind, operation, list_key, id_key, name_key, arn_kind in (
        ("roles", "list_roles", "Roles", "RoleId", "RoleName", "role"),
        ("users", "list_users", "Users", "UserId", "UserName", "user"),
    ):
        marker = None
        seen_markers: set[str] = set()
        seen_arns: set[str] = set()
        seen_ids: set[str] = set()
        while True:
            budget.page()
            page = call("iam", operation, MaxItems=1000, **({"Marker": marker} if marker else {}))
            entries = page.get(list_key)
            if type(entries) is not list or type(page.get("IsTruncated")) is not bool:
                _fail()
            for entry in entries:
                if type(entry) is not dict:
                    _fail()
                name = _text(entry.get(name_key), 64)
                path = _text(entry.get("Path"), 512)
                arn = _text(entry.get("Arn"))
                identifier = _text(entry.get(id_key), 128)
                if (
                    not _NAME.fullmatch(name)
                    or not re.fullmatch(r"/[\x21-\x7e]*/|/", path)
                    or not re.fullmatch(r"[A-Za-z0-9]+", identifier)
                ):
                    _fail()
                if (
                    arn != f"arn:aws:iam::{enrollment.account_id}:{arn_kind}{path}{name}"
                    or arn in seen_arns
                    or identifier in seen_ids
                ):
                    _fail()
                seen_arns.add(arn)
                seen_ids.add(identifier)
                created = _date(entry.get("CreateDate"))
                value = {
                    "arn": arn,
                    id_key.lower(): identifier,
                    "name": name,
                    "path": path,
                    "createdate": created,
                    "createdate_dt": created,
                }
                if kind == "users":
                    value.update(passwordlastused="", passwordlastused_dt=None)
                append(kind, value)
            if not page["IsTruncated"]:
                if page.get("Marker") not in (None, ""):
                    _fail()
                break
            marker = _text(page.get("Marker"), 2048)
            if marker in seen_markers:
                _fail()
            seen_markers.add(marker)

    continuation = None
    seen_tokens: set[str] = set()
    seen_buckets: set[str] = set()
    while True:
        budget.page()
        page = call(
            "s3",
            "list_buckets",
            MaxBuckets=1000,
            **({"ContinuationToken": continuation} if continuation else {}),
        )
        buckets = page.get("Buckets")
        if type(buckets) is not list:
            _fail()
        for bucket in buckets:
            if type(bucket) is not dict:
                _fail()
            name = _text(bucket.get("Name"), 63)
            if (
                not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", name)
                or ".." in name
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", name)
                or name in seen_buckets
            ):
                _fail()
            seen_buckets.add(name)
            if item_count >= enrollment.max_items:
                _fail("AWS_LIMIT_EXCEEDED")
            listed_region = bucket.get("BucketRegion")
            if type(listed_region) is not str or not _REGION.fullmatch(listed_region):
                _fail()
            # MaxBuckets requests include BucketRegion. Select the exact canonical
            # regional endpoint, without following any server-directed redirect.
            regional = (
                clients["s3_region"](listed_region) if "s3_region" in clients else clients["s3"]
            )
            location = call(
                "s3",
                "get_bucket_location",
                selected_client=regional,
                Bucket=name,
                ExpectedBucketOwner=enrollment.account_id,
            )
            region = location.get("LocationConstraint")
            if region is None:
                region = "us-east-1"
            elif region == "EU":
                region = "eu-west-1"
            if type(region) is not str or not _REGION.fullmatch(region) or listed_region != region:
                _fail()
            arn = f"arn:aws:s3:::{name}"
            if bucket.get("BucketArn", arn) != arn:
                _fail()
            append(
                "buckets",
                {
                    "Name": name,
                    "Arn": arn,
                    "Region": region,
                    "CreationDate": _date(bucket.get("CreationDate")),
                },
            )
        continuation = page.get("ContinuationToken")
        if continuation in (None, ""):
            break
        continuation = _text(continuation, 2048)
        if continuation in seen_tokens:
            _fail()
        seen_tokens.add(continuation)

    if enrollment.include_iam_policy_evidence:
        from agent_guard_cartography.aws_policy import capture_policy_evidence

        output["policyEvidence"] = capture_policy_evidence(enrollment, output, call, budget.page)

    budget.check()
    captured_at = clock()
    if type(captured_at) not in (int, float) or not 0 < captured_at < 253402300799:
        _fail()
    output["capturedAt"] = int(captured_at)
    for key in ("roles", "users"):
        output[key].sort(key=lambda value: value["arn"])
    output["buckets"].sort(key=lambda value: value["Name"])
    if len(_json(output)) > enrollment.max_capture_bytes:
        _fail("AWS_CAPTURE_TOO_LARGE")
    return output


class _BufferedRaw(io.BytesIO):
    def stream(self, amt=1024, decode_content=False):
        while data := self.read(amt):
            yield data


def _wire_request(enrollment, request, url):
    """Restrict SDK retries/hooks as well as the caller to enrolled read APIs."""

    def parameters(value):
        try:
            parsed = parse_qs(value, keep_blank_values=True, max_num_fields=9)
        except (ValueError, UnicodeError):
            _fail("AWS_ENDPOINT_DENIED")
        if any(len(items) != 1 for items in parsed.values()):
            _fail("AWS_ENDPOINT_DENIED")
        return {key: items[0] for key, items in parsed.items()}

    if url.hostname == "iam.amazonaws.com" or url.hostname.startswith("sts."):
        if request.method != "POST" or url.path != "/" or url.query:
            _fail("AWS_ENDPOINT_DENIED")
        try:
            body = request.body.decode("ascii") if isinstance(request.body, bytes) else request.body
            values = parameters(body)
        except (TypeError, UnicodeError, AttributeError):
            _fail("AWS_ENDPOINT_DENIED")
        if url.hostname == "iam.amazonaws.com":
            if values.get("Action") == "GetAccountAuthorizationDetails":
                expected = {
                    "Action": "GetAccountAuthorizationDetails",
                    "Version": "2010-05-08",
                    "MaxItems": "100",
                    **{
                        f"Filter.member.{index}": name
                        for index, name in enumerate(
                            ("User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"),
                            start=1,
                        )
                    },
                }
                if (
                    not enrollment.include_iam_policy_evidence
                    or any(values.get(key) != value for key, value in expected.items())
                    or values.keys() - {*expected, "Marker"}
                    or ("Marker" in values and not values["Marker"])
                ):
                    _fail("AWS_ENDPOINT_DENIED")
            elif values.get("Action") not in ("ListRoles", "ListUsers") or values.keys() - {
                "Action",
                "Version",
                "Marker",
                "MaxItems",
            }:
                _fail("AWS_ENDPOINT_DENIED")
        elif values.get("Action") != "GetCallerIdentity" or values.keys() - {"Action", "Version"}:
            _fail("AWS_ENDPOINT_DENIED")
    else:
        if request.method != "GET" or request.body not in (None, b"", ""):
            _fail("AWS_ENDPOINT_DENIED")
        values = parameters(url.query)
        if url.path == "/":
            if values.get("max-buckets") != "1000" or values.keys() - {
                "max-buckets",
                "continuation-token",
            }:
                _fail("AWS_ENDPOINT_DENIED")
        else:
            headers = {
                name.lower(): value.decode("ascii") if isinstance(value, bytes) else value
                for name, value in request.headers.items()
            }
            if (
                not re.fullmatch(r"/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", url.path)
                or values != {"location": ""}
                or headers.get("x-amz-expected-bucket-owner") != enrollment.account_id
            ):
                _fail("AWS_ENDPOINT_DENIED")


class _BoundedHTTPS:
    """No ambient proxies, endpoint overrides, redirects, insecure TLS or streaming parses."""

    def __init__(self, enrollment, allowed_hosts, budget):
        self.enrollment = enrollment
        self.allowed_hosts = frozenset(allowed_hosts)
        self.budget = budget
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def close(self):
        pass

    def send(self, request):
        from botocore.awsrequest import AWSResponse

        self.budget.call()
        url = urlsplit(request.url)
        if (
            url.scheme != "https"
            or url.hostname not in self.allowed_hosts
            or url.port not in (None, 443)
            or url.username
            or url.password
            or url.fragment
        ):
            _fail("AWS_ENDPOINT_DENIED")
        body = request.body
        if body is not None and not isinstance(body, (str, bytes, bytearray)):
            _fail("AWS_ENDPOINT_DENIED")
        if body is not None and len(body) > 65536:
            _fail("AWS_LIMIT_EXCEEDED")
        _wire_request(self.enrollment, request, url)
        timeout = min(
            self.enrollment.request_timeout_seconds, self.budget.deadline - self.budget.monotonic()
        )
        connection = http.client.HTTPSConnection(
            url.hostname, 443, timeout=timeout, context=self.context
        )
        try:
            headers = {
                name: value.decode("ascii") if isinstance(value, bytes) else value
                for name, value in request.headers.items()
            }
            headers["Accept-Encoding"] = "identity"
            headers["Connection"] = "close"
            connection.request(
                request.method, url.path + ("?" + url.query if url.query else ""), body, headers
            )
            response = connection.getresponse()
            header_pairs = response.getheaders()
            counts = {}
            for name, _value in header_pairs:
                lower = name.lower()
                counts[lower] = counts.get(lower, 0) + 1
            if any(
                counts.get(name, 0) > 1
                for name in ("content-length", "transfer-encoding", "content-encoding")
            ) or ("content-length" in counts and "transfer-encoding" in counts):
                _fail()
            transfer = response.getheader("Transfer-Encoding")
            if transfer is not None and transfer.lower() != "chunked":
                _fail()
            header_bytes = sum(len(name) + len(value) + 4 for name, value in header_pairs)
            maximum = self.enrollment.max_response_bytes
            if header_bytes > min(maximum, 65536):
                _fail("AWS_RESPONSE_TOO_LARGE")
            if response.status in (301, 302, 303, 307, 308):
                _fail("AWS_ENDPOINT_DENIED")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                _fail("AWS_CAPTURE_INVALID")
            length = response.getheader("Content-Length")
            if length is not None and (
                not re.fullmatch(r"[0-9]+", length) or int(length) > maximum - header_bytes
            ):
                _fail("AWS_RESPONSE_TOO_LARGE")
            data = response.read(maximum - header_bytes + 1)
            self.budget.check()
            if len(data) + header_bytes > maximum:
                _fail("AWS_RESPONSE_TOO_LARGE")
            if length is not None and len(data) != int(length):
                _fail()
            return AWSResponse(request.url, response.status, dict(header_pairs), _BufferedRaw(data))
        except AwsCollectionError:
            raise
        except Exception:
            _fail("AWS_COLLECTION_FAILED")
        finally:
            connection.close()


def _credentials(enrollment):
    values = [
        os.environ.get(name)
        for name in (
            enrollment.access_key_id_env,
            enrollment.secret_access_key_env,
            enrollment.session_token_env,
        )
    ]
    if any(
        type(value) is not str
        or not value
        or len(value) > 65536
        or not value.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
        for value in values
    ):
        _fail("AWS_CREDENTIAL_REQUIRED")
    return values


def _capture_worker(enrollment, credentials):
    import botocore.session
    from botocore.config import Config

    # Supplying all frozen values bypasses profile, IMDS, web identity and refresh providers.
    session = botocore.session.Session(session_vars={"profile": (None, None, None, None)})
    session.set_config_variable("config_file", os.devnull)
    session.set_config_variable("credentials_file", os.devnull)
    session.set_credentials(*credentials)
    budget = _Budget(enrollment)
    clients = {}

    def client_for(service, region):
        if not _REGION.fullmatch(region):
            _fail("AWS_ENDPOINT_DENIED")
        identity = (service, region)
        if identity not in clients:
            if len(clients) >= 66:
                _fail("AWS_LIMIT_EXCEEDED")
            host = "iam.amazonaws.com" if service == "iam" else f"{service}.{region}.amazonaws.com"
            config = Config(
                region_name=region,
                connect_timeout=enrollment.request_timeout_seconds,
                read_timeout=enrollment.request_timeout_seconds,
                retries={"max_attempts": 0},
                proxies={},
                ignore_configured_endpoint_urls=True,
                use_dualstack_endpoint=False,
                use_fips_endpoint=False,
                s3={"addressing_style": "path", "use_accelerate_endpoint": False},
            )
            client = session.create_client(
                service,
                endpoint_url=f"https://{host}",
                config=config,
                aws_access_key_id=credentials[0],
                aws_secret_access_key=credentials[1],
                aws_session_token=credentials[2],
                verify=True,
            )
            client._endpoint.http_session.close()
            client._endpoint.http_session = _BoundedHTTPS(enrollment, [host], budget)
            clients[identity] = client
        return clients[identity]

    try:
        return capture_from_clients(
            enrollment,
            {
                "sts": client_for("sts", enrollment.region),
                "iam": client_for("iam", "us-east-1"),
                "s3": client_for("s3", enrollment.region),
                "s3_region": lambda region: client_for("s3", region),
            },
        )
    finally:
        for client in clients.values():
            client.close()


def _run_worker(enrollment, credentials, *, command=None):
    if os.name != "posix":
        _fail("AWS_PLATFORM_UNSUPPORTED")
    deadline = time.monotonic() + enrollment.timeout_seconds
    payload = _json({"enrollment": enrollment_dict(enrollment), "credentials": credentials})
    if len(payload) > 256 * 1024:
        _fail("AWS_CONFIG_INVALID")
    process = subprocess.Popen(
        command or [sys.executable, "-I", "-m", __name__, "--worker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": os.defpath,
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "BOTO_CONFIG": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
        },
        start_new_session=True,
        close_fds=True,
    )
    output = bytearray()
    sent = 0
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _fail("AWS_TIMEOUT")
                for key, _events in selector.select(min(remaining, 0.1)):
                    if key.fileobj is process.stdin:
                        try:
                            sent += os.write(process.stdin.fileno(), payload[sent : sent + 65536])
                        except BrokenPipeError:
                            sent = len(payload)
                        if sent == len(payload):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                        else:
                            output.extend(chunk)
                            if len(output) > enrollment.max_capture_bytes + 1024:
                                _fail("AWS_CAPTURE_TOO_LARGE")
        try:
            result = json.loads(output)
        except (ValueError, UnicodeError, RecursionError):
            _fail("AWS_COLLECTION_FAILED")
        if process.returncode != 0 or type(result) is not dict or result.get("ok") is not True:
            code = result.get("error") if type(result) is dict else None
            _fail(code if type(code) is str and code in _CODES else "AWS_COLLECTION_FAILED")
        if (
            set(result) != {"ok", "capture"}
            or type(result["capture"]) is not dict
            or len(_json(result["capture"])) > enrollment.max_capture_bytes
        ):
            _fail("AWS_CAPTURE_INVALID")
        return result["capture"]
    finally:
        # Kill the owned group even after normal completion, so descendants cannot outlive a run.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()


def capture_aws(enrollment: AwsEnrollment) -> dict:
    """Explicit opt-in live capture. Only named frozen environment credentials are read."""
    enrollment = validate_aws_enrollment(enrollment)
    if os.name != "posix":
        _fail("AWS_PLATFORM_UNSUPPORTED")
    try:
        from agent_guard_cartography.aws_graph import validate_aws_capture

        # Treat even the private worker pipe as an untrusted snapshot boundary:
        # callers only receive the complete allowlisted metadata/evidence shape.
        return validate_aws_capture(enrollment, _run_worker(enrollment, _credentials(enrollment)))
    except AwsCollectionError:
        raise
    except Exception:
        _fail("AWS_COLLECTION_FAILED")


def _main():
    # Worker is internal and receives values over a private pipe, never argv or logs.
    try:
        if sys.argv[1:] != ["--worker"]:
            _fail("AWS_CONFIG_INVALID")
        value = json.loads(sys.stdin.buffer.read(256 * 1024 + 1))
        if type(value) is not dict or set(value) != {"enrollment", "credentials"}:
            _fail("AWS_CONFIG_INVALID")
        enrollment = validate_aws_enrollment(value["enrollment"])
        credentials = value["credentials"]
        if (
            type(credentials) is not list
            or len(credentials) != 3
            or any(type(item) is not str or not item or len(item) > 65536 for item in credentials)
        ):
            _fail("AWS_CREDENTIAL_REQUIRED")
        result = _json({"ok": True, "capture": _capture_worker(enrollment, credentials)})
        if len(result) > enrollment.max_capture_bytes + 1024:
            _fail("AWS_CAPTURE_TOO_LARGE")
        sys.stdout.buffer.write(result)
        return 0
    except Exception as error:
        code = (
            error.code
            if isinstance(error, AwsCollectionError)
            and type(error.code) is str
            and error.code in _CODES
            else "AWS_COLLECTION_FAILED"
        )
        sys.stdout.buffer.write(_json({"ok": False, "error": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
