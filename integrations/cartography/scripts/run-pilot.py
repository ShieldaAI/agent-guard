#!/usr/bin/env python3
"""Create an owned local pilot; exercise the real observer, graph and reference service.

No existing database, executor ledger or Docker project may be supplied. Every
database/volume created here is disposable. Only safe result metadata is printed.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from hashlib import sha256
from pathlib import Path

from neo4j import GraphDatabase

from agent_guard_cartography.archive import SnapshotArchive
from agent_guard_cartography.cli import _model_diagnostics, ingestion_lock
from agent_guard_cartography.collector import validate_enrollment
from agent_guard_cartography.graph import source_key
from agent_guard_cartography.publish import collect_and_publish

ROOT = Path(__file__).resolve().parents[3]
INTEGRATION = Path(__file__).resolve().parents[1]
LABEL = "com.shielda.agent-guard.pilot"
spec = importlib.util.spec_from_file_location(
    "disposable", INTEGRATION / "scripts" / "test-disposable-neo4j.py"
)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def private_json(path: Path, value: dict) -> None:
    with open(path, "x", encoding="utf-8", opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
        json.dump(value, f, sort_keys=True)
        f.write("\n")


class Database:
    def __init__(self, directory: Path):
        self.run_id = uuid.uuid4().hex
        self.project = "agent-guard-pilot-" + self.run_id
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.password = secrets.token_urlsafe(32)
        auth = directory / "neo4j-auth.txt"
        with open(auth, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
            file.write("neo4j/" + self.password)
        self.env = {**os.environ, "PILOT_RUN_ID": self.run_id, "PILOT_AUTH_FILE": str(auth)}
        self.tunnel = None
        self.uri = ""
        self.container = None

    def compose(self, *args: str) -> str:
        return helpers.docker(
            "compose",
            "--file",
            str(ROOT / "deployment/cartography/compose.yaml"),
            "--project-name",
            self.project,
            *args,
            env=self.env,
            timeout=240,
        )

    def start(self):
        helpers.require_private_port_support()
        # Unique project names and explicit labels make teardown ownership reviewable.
        self.compose("up", "--detach", "--no-build")
        self.container = self.compose("ps", "--quiet", "neo4j")
        if not re.fullmatch(r"[a-f0-9]{64}", self.container):
            raise RuntimeError("PILOT_CONTAINER_INVALID")
        port = self.compose("port", "neo4j", "7687")
        if not re.fullmatch(r"127\.0\.0\.1:\d+", port):
            raise RuntimeError("PILOT_BINDING_UNSAFE")
        self.uri, self.tunnel = helpers.loopback_uri(port, self.directory)
        helpers.wait_ready(self.uri, self.password, self.tunnel)
        return self

    def connection(self) -> dict:
        return {"uri": self.uri, "username": "neo4j", "password": self.password}

    def driver(self):
        return GraphDatabase.driver(
            self.uri,
            auth=("neo4j", self.password),
            connection_timeout=5,
            max_transaction_retry_time=0,
            notifications_min_severity="OFF",
        )

    def close(self):
        if self.tunnel is not None:
            self.tunnel.terminate()
            try:
                self.tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tunnel.kill()
                self.tunnel.wait(timeout=5)
            self.tunnel = None
        # Check every matching resource, including partially started compose runs.
        for kind, listing in [
            ("container", ["ps", "--all", "--quiet"]),
            ("volume", ["volume", "ls", "--quiet"]),
            ("network", ["network", "ls", "--quiet"]),
        ]:
            ids = helpers.docker(
                *listing, "--filter", f"label=com.docker.compose.project={self.project}"
            ).splitlines()
            for identifier in ids:
                item = json.loads(helpers.docker(kind, "inspect", identifier))[0]
                labels = (
                    item.get("Config", {}).get("Labels", {})
                    if kind == "container"
                    else item.get("Labels", {})
                )
                if labels.get(LABEL) != self.run_id:
                    raise RuntimeError("PILOT_CLEANUP_OWNER_MISMATCH")
        self.compose("down", "--volumes", "--remove-orphans")


class Fixture:
    def __init__(self, configuration: Path):
        self.process = subprocess.Popen(
            ["node", str(ROOT / "examples/cartography-pilot.mjs"), "--config", str(configuration)],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            self.ready = self.read()
            if self.ready.get("event") != "ready":
                raise RuntimeError("PILOT_FIXTURE_START_FAILED")
        except Exception:
            self.close()
            raise

    def read(self) -> dict:
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=20):
                raise RuntimeError("PILOT_FIXTURE_TIMEOUT")
        line = self.process.stdout.readline(131_073)
        if not line or len(line) > 131_072:
            raise RuntimeError("PILOT_FIXTURE_RESPONSE_INVALID")
        return json.loads(line)

    def command(self, command: str, **values) -> dict:
        self.process.stdin.write(json.dumps({"command": command, **values}) + "\n")
        self.process.stdin.flush()
        return self.read()

    def close(self):
        if self.process.poll() is None:
            try:
                self.command("close")
            except (OSError, RuntimeError, ValueError):
                self.process.terminate()
        try:
            self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate(timeout=5)
        if self.process.returncode != 0:
            raise RuntimeError("PILOT_FIXTURE_CLOSE_FAILED")


def pointers(database: Database) -> list[dict]:
    with database.driver() as driver, driver.session() as session:
        return [
            dict(row)
            for row in session.run(
                "MATCH (s:GuardSource) MATCH (c:GuardSnapshot {id:s.current_snapshot_id}) "
                "OPTIONAL MATCH (p:GuardSnapshot {id:s.previous_snapshot_id}) "
                "RETURN s.id AS id,c.snapshot_id AS current,p.snapshot_id AS previous ORDER BY id"
            )
        ]


def logical_graph(database: Database) -> str:
    """Fingerprint the synthetic current/previous graph, excluding physical load metadata."""
    with database.driver() as driver, driver.session() as session:
        nodes = []
        for record in session.run(
            "MATCH (s:GuardSource) UNWIND [s.current_snapshot_id,s.previous_snapshot_id] AS id "
            "MATCH (p:GuardSnapshot {id:id}) MATCH (n)-[:G_IN_SNAPSHOT]->(p) "
            "RETURN p.snapshot_id AS snapshot,labels(n) AS labels,n.entity_id AS entity,properties(n) AS properties"
        ):
            properties = {
                k: v
                for k, v in record["properties"].items()
                if k not in {"id", "projection_id", "firstseen", "lastupdated"}
            }
            nodes.append(
                {
                    "snapshot": record["snapshot"],
                    "labels": sorted(record["labels"]),
                    "entity": record["entity"],
                    "properties": properties,
                }
            )
        edges = [
            dict(row)
            for row in session.run(
                "MATCH (s:GuardSource) UNWIND [s.current_snapshot_id,s.previous_snapshot_id] AS id "
                "MATCH (p:GuardSnapshot {id:id}) MATCH (n)-[:G_IN_SNAPSHOT]->(p) "
                "MATCH (n)-[r]->(m)-[:G_IN_SNAPSHOT]->(p) "
                "RETURN p.snapshot_id AS snapshot,n.entity_id AS source,type(r) AS kind,m.entity_id AS target"
            )
        ]
        records = [json.dumps(item, sort_keys=True) for item in nodes + edges]
        return sha256("\n".join(sorted(records)).encode()).hexdigest()


def authority(status: dict) -> dict:
    return {
        key: status[key] for key in ["ledgerRevision", "inventoryInstanceId", "calls", "executions"]
    }


def exercise_authority(fixture: Fixture) -> None:
    before = fixture.command("status")
    allowed = fixture.command("execute", task="blue")
    if (
        not allowed.get("ok")
        or allowed.get("executions") != before["executions"] + 1
        or allowed.get("calls", {}).get("blue") != before["calls"]["blue"] + 1
    ):
        raise RuntimeError("PILOT_EXECUTION_FAILED")
    for resource, code in [("red", "GRANT_DENIED"), ("beta", "TENANT_DENIED")]:
        denied = fixture.command("execute", task="blue", resource=resource)
        if (
            denied.get("ok") is not False
            or denied.get("code") != code
            or denied.get("executions") != allowed["executions"]
            or denied.get("calls") != allowed["calls"]
        ):
            raise RuntimeError("PILOT_DENIAL_CHECK_FAILED")


def run(directory: Path, serve: bool) -> dict:
    from agent_guard_cartography.pilot_recovery import (
        create_backup,
        inspect_backup,
        replay_published,
        restore_backup,
    )
    from agent_guard_cartography.reference_report import query_reference, write_report

    databases = []
    fixture = None
    started = time.monotonic()
    try:
        database = Database(directory / "database-original")
        databases.append(database)
        database.start()
        observer_token = "agi_v1." + secrets.token_urlsafe(32)
        tokens = {team: "agm_v1." + secrets.token_urlsafe(32) for team in ["blue", "red", "beta"]}
        config = directory / "fixture.json"
        (directory / "executor").mkdir(mode=0o700)
        private_json(
            config,
            {
                "stateDirectory": str(directory / "executor"),
                "observerToken": observer_token,
                "referenceTokens": tokens,
                "neo4j": database.connection(),
                "viewerDirectory": str(ROOT / "apps/agent-map/dist"),
            },
        )
        private_json(directory / "reader-credentials.json", tokens)
        fixture = Fixture(config)
        enrollments = [
            validate_enrollment(
                {
                    "source": source,
                    "profile": fixture.ready["profile"],
                    "endpoint": fixture.ready["observerEndpoint"],
                    "tokenEnv": "PILOT_OBSERVER_TOKEN",
                }
            )
            for source in fixture.ready["sources"]
        ]
        archive_dir, lock = directory / "archive", directory / "ingestion.lock"
        publication = []

        def collect():
            with (
                ingestion_lock(lock),
                SnapshotArchive(archive_dir) as archive,
                database.driver() as driver,
                _model_diagnostics(),
            ):
                for enrollment in enrollments:
                    with driver.session() as session:
                        result = collect_and_publish(session, enrollment, observer_token, archive)
                        publication.append(result.duration_ms)

        collect()
        if authority(fixture.ready["inventory"]) != authority(fixture.command("status")):
            raise RuntimeError("PILOT_COLLECTION_CHANGED_AUTHORITY")
        reference_url = fixture.ready["referenceUrl"] + "/v1/query"
        for team, token in tokens.items():
            response = query_reference(reference_url, token, "list_agents", {})
            if [agent["agentId"] for agent in response["data"]["agents"]] != ["pilot-" + team]:
                raise RuntimeError("PILOT_SCOPE_CHECK_FAILED")
        exercise_authority(fixture)
        collect()
        expected_pointers = pointers(database)
        expected_graph = logical_graph(database)
        alpha = next(item for item in enrollments if item.source["tenantId"] == "alpha")
        report = write_report(
            reference_url, tokens["blue"], source_key(alpha.source), directory / "reports"
        )
        backup = directory / "backup"
        create_backup(archive_dir, backup, enrollments, lock_file=lock)
        if serve:
            print(
                json.dumps(
                    {
                        "event": "ready",
                        "url": fixture.ready["referenceUrl"],
                        "credentialFile": str(directory / "reader-credentials.json"),
                        "mode": "synthetic-live-pilot",
                        "stateDirectory": str(directory),
                    }
                ),
                flush=True,
            )
            while True:
                time.sleep(1)
        stopped_observer = fixture.command("stop-observer")
        stopped_reference = fixture.command("stop-reference")
        if (
            not stopped_observer.get("ok")
            or not stopped_reference.get("ok")
            or stopped_reference.get("observerRunning") is not False
            or stopped_reference.get("referenceRunning") is not False
        ):
            raise RuntimeError("PILOT_ROLLBACK_STOP_FAILED")
        database.close()
        databases.remove(database)
        # The graph and both inventory interfaces are absent at this point.
        exercise_authority(fixture)
        authority_before_replay = authority(fixture.command("status"))
        restored = directory / "restored-archive"
        restore_backup(backup, restored, lock_file=directory / "restore.lock")
        replacement = Database(directory / "database-restored")
        databases.append(replacement)
        replacement.start()
        with replacement.driver() as driver, driver.session() as session, _model_diagnostics():
            replay = replay_published(
                session,
                restored,
                inspect_backup(backup)["manifest"]["sources"],
                replay_archive_directory=directory / "replay-archive",
                lock_file=directory / "restore.lock",
            )
        if pointers(replacement) != expected_pointers:
            raise RuntimeError("PILOT_RESTORE_POINTER_MISMATCH")
        if logical_graph(replacement) != expected_graph:
            raise RuntimeError("PILOT_RESTORE_CONTENT_MISMATCH")
        restarted = fixture.command("start-reference", neo4j=replacement.connection())
        restored_url = restarted.get("referenceUrl")
        if not restored_url:
            restored_url = fixture.command("status").get("referenceUrl")
        after = fixture.command("status")
        if authority_before_replay != authority(after):
            raise RuntimeError("PILOT_RESTORE_CHANGED_AUTHORITY")
        for team, token in tokens.items():
            restored_agents = query_reference(restored_url + "/v1/query", token, "list_agents", {})
            if [a["agentId"] for a in restored_agents["data"]["agents"]] != ["pilot-" + team]:
                raise RuntimeError("PILOT_RESTORE_QUERY_FAILED")
        return {
            "status": "passed",
            "profile": "synthetic-live-pilot",
            "scopeChecks": 3,
            "restoreSnapshotPointersMatch": True,
            "restoreLogicalContentMatches": True,
            "collectionPreservesAuthority": True,
            "executorSurvivesRollback": True,
            "authorityStatePreserved": True,
            "collectionDurationsMs": publication,
            "durationSeconds": round(time.monotonic() - started, 3),
            "replay": replay,
            "differenceReport": report.name,
        }
    finally:
        cleanup_failed = False
        if fixture is not None:
            try:
                fixture.close()
            except Exception:
                cleanup_failed = True
        for owned in reversed(databases):
            try:
                owned.close()
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("PILOT_CLEANUP_FAILED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Keep the live synthetic viewer open until interrupted.",
    )
    parser.add_argument(
        "--directory",
        type=Path,
        help="New private state directory; existing directories are refused.",
    )
    parser.add_argument(
        "--output", type=Path, help="New safe JSON verification report; never includes credentials."
    )
    args = parser.parse_args()
    if args.serve and args.directory is None:
        parser.error("--serve requires a new --directory")
    signal.signal(signal.SIGTERM, lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        if args.directory is None:
            # Colima shares the user's home by default, not macOS /private/var.
            # Compose secrets are file mounts; their private directory must be shared.
            with tempfile.TemporaryDirectory(
                prefix=".agent-guard-pilot-", dir=Path.home()
            ) as temporary:
                result = run(Path(temporary).resolve(), False)
        else:
            path = args.directory.absolute()
            if ".." in path.parts or path.parent.resolve() != path.parent:
                raise RuntimeError("PILOT_DIRECTORY_UNSAFE")
            path.mkdir(mode=0o700)
            result = run(path, args.serve)
        if args.output:
            private_json(args.output, result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        return 0 if args.serve else 130
    except Exception:
        print("PILOT_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
