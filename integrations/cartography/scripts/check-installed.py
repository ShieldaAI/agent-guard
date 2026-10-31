#!/usr/bin/env python3
"""Check the installed wheel from an isolated uv environment, outside editable source."""

import importlib.metadata
import importlib.resources
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import agent_guard_cartography
from agent_guard_cartography.inventory import (
    load_snapshot,
    validate_manifest,
    validate_mcp_inventory,
    validate_snapshot,
)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    module_path = Path(agent_guard_cartography.__file__).resolve()
    if module_path.is_relative_to(root / "src"):
        raise RuntimeError("Run this consumer check in an isolated installed-wheel environment")
    for filename in (
        "agent-guard-inventory-v1.schema.json",
        "agent-guard-inventory-manifest-v1.schema.json",
        "agent-guard-mcp-inventory-v1.schema.json",
    ):
        resource = importlib.resources.files("agent_guard_cartography").joinpath(
            "schemas", filename
        )
        schema = json.loads(resource.read_text(encoding="utf-8"))
        canonical = root.parent.parent / "schemas" / filename
        if canonical.is_file() and schema != json.loads(canonical.read_text(encoding="utf-8")):
            raise RuntimeError("Installed schema differs from the repository contract")
    for path in sorted((root / "tests" / "fixtures").glob("*.json")):
        snapshot = load_snapshot(path)
        if "manifest" in snapshot:
            validate_manifest(snapshot["manifest"])
            host = snapshot
        else:
            manifest = validate_manifest(
                {
                    "schemaVersion": 1,
                    "evidenceKind": "host_asserted",
                    "source": snapshot["source"],
                    "manifestId": "installed-manifest",
                    "revision": 1,
                    "observedAt": snapshot["generatedAt"],
                    "agents": [],
                    "deployments": [],
                    "taskBindings": [],
                    "resourceBindings": [],
                    "executionBindings": [],
                }
            )
            host = validate_snapshot(
                {
                    **snapshot,
                    "profile": "host",
                    "manifest": manifest,
                    "coverage": {
                        **snapshot["coverage"],
                        "manifest": {"status": "complete", "observedAt": manifest["observedAt"]},
                    },
                }
            )
        expected_connections = {
            binding["connectionId"]
            for binding in host["manifest"]["executionBindings"]
            if binding["connectionId"] is not None
        }
        validate_snapshot(
            {
                **host,
                "profile": "host-mcp",
                "mcp": {
                    "observedAt": host["generatedAt"],
                    "connections": [
                        {"connectionId": identifier, "status": "unavailable", "reason": "missing"}
                        for identifier in sorted(expected_connections)
                    ],
                },
                "coverage": {
                    **host["coverage"],
                    "mcp": {
                        "status": "unavailable" if expected_connections else "complete",
                        "observedAt": host["generatedAt"],
                    },
                },
            }
        )
    validate_mcp_inventory(
        {
            "schemaVersion": 1,
            "identity": {
                "serverId": "installed-server",
                "transportRef": "opaque:" + "a" * 64,
                "principalId": "installed-principal",
                "tenantId": "installed-tenant",
            },
            "sessionId": "local-session",
            "revision": 0,
            "authorizationEpoch": 0,
            "metadataRevision": 0,
            "state": "connecting",
            "metadataState": "unobserved",
            "observedAt": "2026-10-30T00:00:00Z",
            "operations": [],
        }
    )
    # Import the executable integration against the real pinned dependency as well.
    from agent_guard_cartography.cli import main as cli_main
    from agent_guard_cartography.graph import import_snapshot

    assert callable(cli_main) and callable(import_snapshot)
    from cartography.intel.aws.permission_relationships import parse_permission_relationships_file

    from agent_guard_cartography.archive import SnapshotArchive
    from agent_guard_cartography.cloud import CloudJoinError, CloudScope, validate_cloud_scope
    from agent_guard_cartography.collector import validate_enrollment
    from agent_guard_cartography.pilot_recovery import create_backup, inspect_backup, restore_backup
    from agent_guard_cartography.reference_report import minimize_changes

    mapping = importlib.resources.files("agent_guard_cartography").joinpath(
        "data", "aws-permission-relationships.yaml"
    )
    with importlib.resources.as_file(mapping) as path:
        relationships = parse_permission_relationships_file(str(path))
    assert {entry["relationship_name"] for entry in relationships} == {
        "CAN_READ",
        "CAN_WRITE",
        "CAN_LIST",
    }
    validate_cloud_scope(
        {
            "companyId": "company",
            "tenantId": "tenant",
            "accounts": [{"partition": "aws", "accountId": "111122223333"}],
        }
    )
    for invalid_scope in (
        {
            "companyId": "company",
            "tenantId": "tenant",
            "accounts": [{"partition": "aws", "accountId": "١" * 12}],
        },
        CloudScope("company", "tenant", (("aws", "１" * 12),)),
        {
            "companyId": "\ufeff \ufeff",
            "tenantId": "tenant",
            "accounts": [{"partition": "aws", "accountId": "111122223333"}],
        },
        CloudScope("company", "\ufeff\x85\ufeff", (("aws", "111122223333"),)),
    ):
        try:
            validate_cloud_scope(invalid_scope)
        except CloudJoinError as error:
            assert error.code == "CLOUD_CONFIG_INVALID"
        else:
            raise AssertionError("Malformed cloud enrollment identifiers must be rejected")
    enrollment = validate_enrollment(
        {
            "source": snapshot["source"],
            "profile": snapshot["profile"],
            "endpoint": "http://127.0.0.1:8788/v1/inventory/snapshot",
            "tokenEnv": "GUARD_TEST_TOKEN",
        }
    )
    with (
        TemporaryDirectory() as directory,
        SnapshotArchive(Path(directory).resolve() / "archive") as archive,
    ):
        receipt = archive.store(snapshot)
        assert archive.load(receipt.receipt_id, enrollment.source, enrollment.profile) == snapshot
        archive_path = Path(directory).resolve() / "archive"
        backup_path = Path(directory).resolve() / "backup"
        restored_path = Path(directory).resolve() / "restored"
        lock_path = Path(directory).resolve() / "ingestion.lock"
        summary = create_backup(archive_path, backup_path, [enrollment], lock_file=lock_path)
        assert summary.snapshots == 1
        assert inspect_backup(backup_path)["summary"]["pending"] == 1
        restore_backup(backup_path, restored_path, lock_file=lock_path)
        with SnapshotArchive(restored_path) as restored:
            assert (
                restored.load(receipt.receipt_id, enrollment.source, enrollment.profile) == snapshot
            )
    from agent_guard_cartography.archive import REPLAY_PENDING, ArchiveError
    from agent_guard_cartography.lifecycle import main as lifecycle_main
    from agent_guard_cartography.lifecycle import transition_id, validate_transition
    from agent_guard_cartography.publish import publish_receipt

    transition = validate_transition(
        {
            "schemaVersion": 1,
            "profile": snapshot["profile"],
            "predecessor": snapshot["source"],
            "successor": {**snapshot["source"], "enrollmentGeneration": "installed-replacement"},
        }
    )
    assert callable(lifecycle_main) and len(transition_id(transition)) == 64
    scripts = importlib.metadata.distribution("agent-guard-cartography").entry_points
    assert any(entry.name == "agent-guard-source-lifecycle" for entry in scripts)
    with (
        TemporaryDirectory() as directory,
        SnapshotArchive(Path(directory).resolve() / "lifecycle") as archive,
    ):
        original = archive.store(snapshot)
        pending = archive.stage_transition(transition)
        assert pending["status"] == "pending"
        assert archive.stage_transition(transition) == pending
        assert archive.list_transitions() == (pending,)
        try:
            archive.store(snapshot)
        except ArchiveError as error:
            assert error.code == "ARCHIVE_SOURCE_SUPERSEDED"
        else:
            raise AssertionError("Pending supersession must fence predecessor snapshot writes")
        try:
            publish_receipt(object(), enrollment, archive, original.receipt_id)
        except ArchiveError as error:
            assert error.code == "ARCHIVE_SOURCE_SUPERSEDED"
        else:
            raise AssertionError("Pending supersession must fence existing receipt replay")
    with TemporaryDirectory() as directory:
        folder = Path(directory).resolve() / "recovery"
        with SnapshotArchive(folder) as archive:
            original = archive.store(snapshot)
            marker = folder / REPLAY_PENDING
            marker.write_text('{"schemaVersion":1}\n')
            marker.chmod(0o600)
            try:
                publish_receipt(object(), enrollment, archive, original.receipt_id)
            except ArchiveError as error:
                assert error.code == "ARCHIVE_RECOVERY_PENDING"
            else:
                raise AssertionError("Incomplete recovery must fence existing receipt replay")
    with TemporaryDirectory() as directory:
        folder = Path(directory).resolve() / "capacity"
        health_sources = [
            {**snapshot["source"], "sourceId": f"installed-health-{index}"} for index in range(5)
        ]
        with SnapshotArchive(folder, max_snapshots=1) as archive:
            for source in health_sources[:4]:
                archive.record_health(source, snapshot["profile"], error_code="COLLECTION_FAILED")
            before = {path.name: path.read_bytes() for path in folder.iterdir()}
            try:
                archive.record_health(
                    health_sources[4], snapshot["profile"], error_code="COLLECTION_FAILED"
                )
            except ArchiveError as error:
                assert error.code == "ARCHIVE_LIMIT_EXCEEDED"
            else:
                raise AssertionError("New archive files must not exceed the count limit")
            assert {path.name: path.read_bytes() for path in folder.iterdir()} == before
            archive.record_health(
                health_sources[0], snapshot["profile"], error_code="COLLECTION_FAILED"
            )
        with SnapshotArchive(folder, max_snapshots=1) as reopened:
            assert (
                reopened.read_health(health_sources[0], snapshot["profile"])["consecutiveFailures"]
                == 2
            )
    source_id = "a" * 64
    minimized = minimize_changes(
        {
            "operation": "get_changes",
            "data": {
                "sourceId": source_id,
                "from": None,
                "to": {"projectionId": "b" * 64},
                "coverageGap": True,
                "changes": {
                    "added": [
                        {"label": "GuardAgent", "name": "private-canary", "entityId": "hidden"}
                    ],
                    "changed": [],
                    "removed": [],
                },
            },
        },
        source_id,
    )
    assert minimized["counts"]["added"]["GuardAgent"] == 1
    assert "private-canary" not in json.dumps(minimized)
    assert agent_guard_cartography.__version__ == importlib.metadata.version(
        "agent-guard-cartography"
    )
    assert importlib.metadata.version("cartography") == "0.144.0"
    from dataclasses import replace
    from datetime import UTC, datetime

    import botocore.session
    from botocore.stub import Stubber

    from agent_guard_cartography.aws_capture import capture_from_clients
    from agent_guard_cartography.aws_config import validate_aws_enrollment
    from agent_guard_cartography.aws_graph import validate_aws_capture

    aws = validate_aws_enrollment(
        {
            "schemaVersion": 1,
            "companyId": "installed",
            "tenantId": "installed",
            "partition": "aws",
            "accountId": "111122223333",
            "region": "us-east-1",
            "expectedCallerArn": "arn:aws:sts::111122223333:assumed-role/Reader/installed",
            "accessKeyIdEnv": "INSTALLED_AWS_ACCESS",
            "secretAccessKeyEnv": "INSTALLED_AWS_SECRET",
            "sessionTokenEnv": "INSTALLED_AWS_SESSION",
        }
    )
    clients = {}
    session = botocore.session.get_session()
    try:
        for service in ("sts", "iam", "s3"):
            clients[service] = session.create_client(
                service,
                region_name="us-east-1",
                aws_access_key_id="installed-fake-access",
                aws_secret_access_key="installed-fake-secret",
                aws_session_token="installed-fake-session",
            )
        with (
            Stubber(clients["sts"]) as sts,
            Stubber(clients["iam"]) as iam,
            Stubber(clients["s3"]) as s3,
        ):
            for include_policy in (False, True):
                enrollment = replace(aws, include_iam_policy_evidence=include_policy)
                sts.add_response(
                    "get_caller_identity",
                    {
                        "Account": aws.account_id,
                        "Arn": aws.expected_caller_arn,
                        "UserId": "installed-fake-user",
                    },
                    {},
                )
                iam.add_response(
                    "list_roles", {"Roles": [], "IsTruncated": False}, {"MaxItems": 1000}
                )
                iam.add_response(
                    "list_users", {"Users": [], "IsTruncated": False}, {"MaxItems": 1000}
                )
                s3.add_response("list_buckets", {"Buckets": []}, {"MaxBuckets": 1000})
                if include_policy:
                    iam.add_response(
                        "get_account_authorization_details",
                        {
                            "UserDetailList": [],
                            "RoleDetailList": [],
                            "GroupDetailList": [],
                            "Policies": [],
                            "IsTruncated": False,
                        },
                        {
                            "Filter": [
                                "User",
                                "Role",
                                "Group",
                                "LocalManagedPolicy",
                                "AWSManagedPolicy",
                            ],
                            "MaxItems": 100,
                        },
                    )
                capture = capture_from_clients(
                    enrollment, clients, clock=lambda: datetime.now(UTC).timestamp()
                )
                assert validate_aws_capture(enrollment, capture) == capture
                assert ("policyEvidence" in capture) is include_policy
                if include_policy:
                    assert capture["policyEvidence"]["assessment"] == "unknown"
                    assert capture["policyEvidence"]["principals"] == []
                    assert capture["policyEvidence"]["edges"] == []
            for stub in (sts, iam, s3):
                stub.assert_no_pending_responses()
    finally:
        for client in clients.values():
            client.close()
    assert importlib.metadata.version("botocore") == "1.40.61"
    print(
        "Installed wheel validates schemas, collector/archive/recovery/report/lifecycle APIs, offline AWS metadata/policy capture and pinned mapping."
    )


if __name__ == "__main__":
    main()
