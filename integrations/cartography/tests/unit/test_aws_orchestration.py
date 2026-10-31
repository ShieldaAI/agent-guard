"""One lock owner coordinates AWS metadata refresh and ordinary Guard polling."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_guard_cartography import cli
from agent_guard_cartography.aws_config import AwsCollectionError
from agent_guard_cartography.graph import GraphImportError

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "alpha-v1.json"
ACCOUNT = "111122223333"


@pytest.fixture
def configured(tmp_path, monkeypatch):
    source = json.loads(FIXTURE.read_text())["source"]
    observer = {
        "source": source,
        "profile": "core",
        "endpoint": "http://127.0.0.1:8181/v1/inventory/snapshot",
        "tokenEnv": "TEST_OBSERVER_TOKEN",
    }
    cloud = {
        "companyId": source["companyId"],
        "tenantId": source["tenantId"],
        "accounts": [{"partition": "aws", "accountId": ACCOUNT}],
    }
    aws = {
        "schemaVersion": 1,
        "companyId": source["companyId"],
        "tenantId": source["tenantId"],
        "partition": "aws",
        "accountId": ACCOUNT,
        "region": "us-east-1",
        "expectedCallerArn": f"arn:aws:sts::{ACCOUNT}:assumed-role/MapReader/pilot",
        "accessKeyIdEnv": "TEST_AWS_ACCESS_KEY",
        "secretAccessKeyEnv": "TEST_AWS_SECRET_KEY",
        "sessionTokenEnv": "TEST_AWS_SESSION_TOKEN",
    }
    files = {name: tmp_path / f"{name}.json" for name in ("observer", "cloud", "aws")}

    def save(name, value):
        files[name].write_text(json.dumps(value))
        files[name].chmod(0o600)

    for name, value in (("observer", observer), ("cloud", cloud), ("aws", aws)):
        save(name, value)
    lock = tmp_path / "database.lock"
    events = []
    clock = SimpleNamespace(now=0.0)

    def assert_locked():
        with pytest.raises(GraphImportError, match="INGESTION_ALREADY_RUNNING"):
            with cli.ingestion_lock(lock):
                pytest.fail("The AWS/Guard operation escaped the shared ingestion lock")

    class Driver:
        def __enter__(self):
            assert_locked()
            return self

        def __exit__(self, *_args):
            pass

        def verify_connectivity(self):
            assert_locked()
            events.append(("verify", clock.now))

        @contextmanager
        def session(self, **_kwargs):
            assert_locked()
            yield object()

    def create_driver(*_args, **_kwargs):
        assert_locked()
        return Driver()

    @contextmanager
    def archive(*_args, **_kwargs):
        assert_locked()
        yield SimpleNamespace(require_recovery_complete=lambda: None)

    def capture(enrollment):
        assert_locked()
        assert enrollment.account_id == ACCOUNT
        events.append(("aws_capture", clock.now))
        return {"capturedAt": 1, "roles": [], "users": [], "buckets": []}

    def publish(_session, enrollment, capture):
        assert_locked()
        assert enrollment.account_id == ACCOUNT
        assert capture["roles"] == []
        events.append(("aws_publish", clock.now))
        return {
            "status": "complete",
            "collection_id": "b" * 64,
            "captured_at": 1,
            "counts": {"roles": 0, "users": 0, "buckets": 0},
        }

    def collect(_session, enrollment, _token, _archive, *, cloud_scope=None):
        assert_locked()
        assert enrollment.source == source
        if cloud_scope is not None:
            assert cloud_scope.accounts == (("aws", ACCOUNT),)
        events.append(("guard", clock.now))
        return SimpleNamespace(
            import_result=SimpleNamespace(source_id="a" * 64),
            summary=lambda: {"status": "complete", "source_id": "a" * 64},
        )

    monkeypatch.setenv("NEO4J_PASSWORD", "database-secret-canary")
    monkeypatch.setenv("TEST_OBSERVER_TOKEN", "agi_v1." + "a" * 43)
    monkeypatch.setattr(cli.GraphDatabase, "driver", create_driver)
    monkeypatch.setattr(cli, "SnapshotArchive", archive)
    monkeypatch.setattr(cli, "capture_aws", capture)
    monkeypatch.setattr(cli, "publish_aws_capture", publish)
    monkeypatch.setattr(cli, "collect_and_publish", collect)
    monkeypatch.setattr(cli, "prune_archive", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "retire_obsolete", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "retire_superseded", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock.now)
    arguments = [
        "--enrollment",
        str(files["observer"]),
        "--archive-dir",
        str(tmp_path / "archive"),
        "--cloud-scope",
        str(files["cloud"]),
        "--aws-enrollment",
        str(files["aws"]),
        "--neo4j-uri",
        "bolt://127.0.0.1:7687",
        "--lock-file",
        str(lock),
    ]
    return SimpleNamespace(
        arguments=arguments,
        events=events,
        source=source,
        aws=aws,
        cloud=cloud,
        save=save,
        files=files,
        clock=clock,
        lock=lock,
        assert_locked=assert_locked,
    )


def test_one_shot_aws_capture_and_publication_precede_guard_under_same_lock(configured, capsys):
    assert cli.main(configured.arguments) == 0
    assert [event for event, _ in configured.events] == [
        "verify",
        "aws_capture",
        "aws_publish",
        "guard",
    ]
    output = capsys.readouterr()
    rows = [json.loads(line) for line in output.out.splitlines()]
    assert len(rows) == 2
    assert rows[0]["kind"] == "aws_collection"
    assert rows[0]["status"] == "complete"
    assert rows[1]["status"] == "complete"
    assert output.err == ""
    assert "database-secret-canary" not in output.out


def test_aws_capture_failure_does_not_publish_or_suppress_guard(configured, monkeypatch, capsys):
    def fail(_enrollment):
        configured.assert_locked()
        configured.events.append(("aws_capture", configured.clock.now))
        raise RuntimeError("aws-secret-and-response-canary")

    monkeypatch.setattr(cli, "capture_aws", fail)
    assert cli.main(configured.arguments) != 0
    assert [event for event, _ in configured.events] == ["verify", "aws_capture", "guard"]
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "complete"
    error = json.loads(output.err)
    assert error["kind"] == "aws_collection" and error["status"] == "failed"
    assert "canary" not in output.out + output.err


def test_policy_opt_in_reaches_capture_and_receipt_has_only_safe_counts(
    configured, monkeypatch, capsys
):
    configured.aws["includeIamPolicyEvidence"] = True
    configured.save("aws", configured.aws)

    def capture(enrollment):
        configured.assert_locked()
        assert enrollment.include_iam_policy_evidence is True
        return {
            "capturedAt": 1,
            "roles": [],
            "users": [],
            "buckets": [],
            "policyEvidence": {
                "principals": [{"arn": "private-principal-canary", "status": "unsupported"}],
                "edges": [],
                "policyHash": "private-policy-canary",
            },
        }

    monkeypatch.setattr(cli, "capture_aws", capture)
    assert cli.main(configured.arguments) == 0
    output = capsys.readouterr()
    receipt = json.loads(output.out.splitlines()[0])
    assert receipt["policy_evidence"] == {
        "status": "complete",
        "assessment": "unknown",
        "candidate_edges": 0,
        "unresolved_principals": 1,
    }
    assert "canary" not in output.out + output.err


def test_incomplete_policy_capture_preserves_publication_and_guard_polling(
    configured, monkeypatch, capsys
):
    configured.aws["includeIamPolicyEvidence"] = True
    configured.save("aws", configured.aws)

    def fail(enrollment):
        configured.assert_locked()
        assert enrollment.include_iam_policy_evidence is True
        raise AwsCollectionError("AWS_POLICY_INCOMPLETE")

    monkeypatch.setattr(cli, "capture_aws", fail)
    assert cli.main(configured.arguments) == 2
    assert [event for event, _ in configured.events] == ["verify", "guard"]
    output = capsys.readouterr()
    assert json.loads(output.err)["code"] == "AWS_POLICY_INCOMPLETE"
    assert json.loads(output.out)["status"] == "complete"


def test_aws_publication_failure_does_not_suppress_guard(configured, monkeypatch, capsys):
    def fail(_session, _enrollment, _capture):
        configured.assert_locked()
        raise RuntimeError("private-neo4j-response-canary")

    monkeypatch.setattr(cli, "publish_aws_capture", fail)
    assert cli.main(configured.arguments) != 0
    assert [event for event, _ in configured.events] == ["verify", "aws_capture", "guard"]
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "complete"
    assert json.loads(output.err)["status"] == "failed"
    assert "canary" not in output.out + output.err


@pytest.mark.parametrize("code", ["AWS_PRIVATE_canary", {"private": "canary"}, "AWS_TIMEOUT"])
def test_aws_errors_keep_safe_codes_only_and_do_not_break_collection(
    configured, monkeypatch, capsys, code
):
    def fail(_enrollment):
        raise AwsCollectionError(code)

    monkeypatch.setattr(cli, "capture_aws", fail)
    assert cli.main(configured.arguments) != 0
    assert [event for event, _ in configured.events] == ["verify", "guard"]
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "complete"
    failure = json.loads(output.err)
    assert failure["code"] == ("AWS_TIMEOUT" if code == "AWS_TIMEOUT" else "AWS_COLLECTION_FAILED")
    assert "canary" not in output.out + output.err


@pytest.mark.parametrize("failure", [False, True])
def test_watch_aws_cadence_starts_after_attempt_completion(configured, monkeypatch, failure):
    def capture(_enrollment):
        configured.assert_locked()
        configured.events.append(("aws_capture", configured.clock.now))
        configured.clock.now += 20
        if failure:
            raise RuntimeError("provider-unavailable-canary")
        return {"capturedAt": 1, "roles": [], "users": [], "buckets": []}

    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 4:
            raise KeyboardInterrupt()
        configured.clock.now += seconds

    monkeypatch.setattr(cli, "capture_aws", capture)
    monkeypatch.setattr(cli.time, "sleep", sleep)
    # A wildly unrelated wall clock must not control the periodic due calculation.
    monkeypatch.setattr(cli.time, "time", lambda: 1_000_000 + configured.clock.now * 1000)
    assert (
        cli.main(
            [
                *configured.arguments,
                "--watch",
                "--interval-seconds",
                "30",
                "--aws-interval-seconds",
                "60",
            ]
        )
        == 0
    )
    assert [when for event, when in configured.events if event == "aws_capture"] == [0, 90]
    assert [when for event, when in configured.events if event == "guard"] == [20, 30, 60, 110]
    assert sleeps == [10, 30, 30, 10]


def test_disabled_aws_does_not_read_aws_config_or_credentials(configured, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("AWS was accessed while disabled")

    monkeypatch.setattr(cli, "load_aws_enrollment", forbidden)
    monkeypatch.setattr(cli, "capture_aws", forbidden)
    arguments = list(configured.arguments)
    at = arguments.index("--aws-enrollment")
    del arguments[at : at + 2]
    assert cli.main(arguments) == 0
    assert [event for event, _ in configured.events] == ["verify", "guard"]


def test_aws_interval_cannot_silently_enable_aws_collection(configured):
    arguments = list(configured.arguments)
    at = arguments.index("--aws-enrollment")
    del arguments[at : at + 2]
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments, "--aws-interval-seconds", "60"])
    assert error.value.code == 2
    assert configured.events == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("companyId", "other-company"),
        ("tenantId", "other-tenant"),
        ("accountId", "999988887777"),
    ],
)
def test_aws_enrollment_must_match_observer_and_cloud_scope(configured, field, value):
    configured.aws[field] = value
    if field == "accountId":
        configured.aws["expectedCallerArn"] = f"arn:aws:sts::{value}:assumed-role/MapReader/pilot"
    configured.save("aws", configured.aws)
    assert cli.main(configured.arguments) != 0
    assert configured.events == []


def test_aws_requires_explicit_cloud_account_allowlist_before_network(configured):
    arguments = list(configured.arguments)
    at = arguments.index("--cloud-scope")
    del arguments[at : at + 2]
    assert cli.main(arguments) != 0
    assert configured.events == []


@pytest.mark.parametrize("interval", ["0", "59", "86401"])
def test_aws_interval_is_bounded_before_network(configured, interval):
    with pytest.raises(SystemExit) as error:
        cli.main([*configured.arguments, "--aws-interval-seconds", interval])
    assert error.value.code == 2
    assert configured.events == []


def test_aws_collection_cannot_be_combined_with_receipt_replay(configured):
    with pytest.raises(SystemExit) as error:
        cli.main([*configured.arguments, "--replay-receipt", "a" * 64])
    assert error.value.code == 2
    assert configured.events == []


def test_aws_collection_cannot_be_combined_with_file_import(configured):
    arguments = list(configured.arguments)
    for option in ("--enrollment", "--archive-dir"):
        at = arguments.index(option)
        del arguments[at : at + 2]
    arguments.extend(
        ["--snapshot", str(FIXTURE), "--expected-source", str(configured.files["observer"])]
    )
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2
    assert configured.events == []


def test_a_second_ingestion_owner_cannot_reach_aws_or_guard(configured):
    with cli.ingestion_lock(configured.lock):
        assert cli.main(configured.arguments) != 0
    assert configured.events == []
