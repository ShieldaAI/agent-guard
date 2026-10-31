#!/usr/bin/env python3
"""Measure the pilot on a newly owned disposable database; never accept a DB URL.

Run from integrations/cartography after ``npm run build`` in the repository root.
The acceptance profile persists 10,000 synthetic tasks and 100,000 grants. Each
publication is measured after that source's synthetic collection has completed;
the serial batch duration is reported separately, not called an atomic refresh.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from neo4j import GraphDatabase

from agent_guard_cartography.graph import import_snapshot
from agent_guard_cartography.pilot_benchmark import PROFILES, gates, synthetic_snapshot

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]
BRIDGE = ROOT / "tests" / "fixtures" / "benchmark-pilot.mjs"
spec = importlib.util.spec_from_file_location(
    "disposable_neo4j", ROOT / "scripts" / "test-disposable-neo4j.py"
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def physical_memory() -> int | None:
    try:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError, OSError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="smoke")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New JSON result file; existing files are not overwritten",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=40,
        help="40–200 sequential HTTP samples; includes the cold first request",
    )
    options = parser.parse_args()
    if not 40 <= options.samples <= 200:
        parser.error("--samples must be between 40 and 200")
    if options.output.exists() or not options.output.parent.is_dir():
        parser.error("--output must be a new file in an existing directory")
    node = shutil.which("node")
    if node is None or not (REPOSITORY / "packages" / "agent-map" / "dist" / "index.js").is_file():
        parser.error("Run npm run build in the repository root first")
    image = (ROOT / "neo4j-image.txt").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"neo4j:5\.26\.\d+-community@sha256:[0-9a-f]{64}", image):
        parser.error("Neo4j image must match the pinned compatibility baseline")
    run_id = uuid.uuid4().hex
    name = f"agent-guard-pilot-benchmark-{run_id}"
    password = secrets.token_urlsafe(32)
    docker_env = os.environ.copy()
    docker_env["NEO4J_AUTH"] = f"neo4j/{password}"
    tunnel = None
    report = {
        "schemaVersion": 1,
        "kind": "synthetic-pilot-benchmark",
        "profile": options.profile,
        "startedAt": datetime.now(UTC).isoformat(),
        "passed": False,
        "hardware": {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "hostLogicalCpus": os.cpu_count(),
            "hostMemoryBytes": physical_memory(),
            "containerCpus": 4,
            "containerMemoryBytes": 4 * 1024**3,
            "dataTmpfsBytes": 2 * 1024**3,
        },
        "versions": {
            "python": platform.python_version(),
            "cartography": importlib.metadata.version("cartography"),
            "neo4jPythonDriver": importlib.metadata.version("neo4j"),
            "neo4jImage": image,
        },
        "scope": "Synthetic host inventory, no AWS APIs or execution; one source per bounded query.",
        "limitations": [
            "Local hardware measurement, not a production capacity guarantee.",
            "Publication deadline applies per serially collected source; batch time is separate.",
            "Includes cold first HTTP sample; no warmup samples are excluded.",
            "Synthetic fixture generation replaces the observer network and is not a live cloud collection benchmark.",
        ],
    }

    def interrupted(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        report["versions"]["docker"] = runner.require_private_port_support()
        container_id = runner.docker(
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "--label",
            f"{runner.LABEL}={run_id}",
            "--publish",
            "127.0.0.1::7687",
            "--memory",
            "4g",
            "--cpus",
            "4",
            "--pids-limit",
            "256",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/data:rw,size=2g",
            "--env",
            "NEO4J_AUTH",
            "--env",
            "NEO4J_server_memory_heap_initial__size=512m",
            "--env",
            "NEO4J_server_memory_heap_max__size=1g",
            "--env",
            "NEO4J_server_memory_pagecache_size=512m",
            "--env",
            "NEO4J_dbms_usage__report_enabled=false",
            "--env",
            "NEO4J_db_tx__log_preallocate=false",
            "--env",
            "NEO4J_db_tx__log_rotation_size=16m",
            image,
            timeout=240,
            env=docker_env,
        )
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("PILOT_CONTAINER_INVALID")
        address = runner.docker("port", container_id, "7687/tcp")
        if not re.fullmatch(r"127\.0\.0\.1:\d+", address):
            raise RuntimeError("PILOT_LISTENER_INVALID")
        with tempfile.TemporaryDirectory(prefix="agent-guard-pilot-benchmark-") as directory:
            private = Path(directory)
            uri, tunnel = runner.loopback_uri(address, private)
            runner.wait_ready(uri, password, tunnel)
            config = private / "connection.json"
            config.write_text(
                json.dumps(
                    {
                        "containerId": container_id,
                        "runId": run_id,
                        "image": image,
                        "uri": uri,
                        "dockerPort": address.rsplit(":", 1)[1],
                        "username": "neo4j",
                        "password": password,
                    }
                ),
                encoding="utf-8",
            )
            config.chmod(0o600)
            publications = []
            source_ids = []
            snapshot_sizes = []
            tenant_ids = set()
            batch_start = time.perf_counter()
            with (
                GraphDatabase.driver(
                    uri,
                    auth=("neo4j", password),
                    connection_timeout=5,
                    max_transaction_retry_time=0,
                    notifications_min_severity="OFF",
                ) as driver,
                driver.session(database="neo4j") as session,
            ):
                session.run("CREATE (:GuardDisposableTestRun {id: $runId})", runId=run_id).consume()
                for number in range(PROFILES[options.profile]["sources"]):
                    snapshot = synthetic_snapshot(
                        options.profile, run_id, number, datetime.now(UTC)
                    )
                    snapshot_sizes.append(len(json.dumps(snapshot, separators=(",", ":")).encode()))
                    tenant_ids.add(snapshot["source"]["tenantId"])
                    started = time.perf_counter()
                    result = import_snapshot(session, snapshot, snapshot["source"])
                    publications.append(time.perf_counter() - started)
                    if not result.published or result.idempotent:
                        raise RuntimeError("PILOT_PUBLICATION_FAILED")
                    source_ids.append(result.source_id)
                    print(
                        f"Published synthetic source {number + 1}/{PROFILES[options.profile]['sources']}",
                        file=sys.stderr,
                        flush=True,
                    )
                batch_seconds = time.perf_counter() - batch_start
                company = snapshot["source"]["companyId"]
                counts = {}
                counts["sources"] = session.run(
                    "MATCH (s:GuardSource {company_id:$company}) WHERE s.current_snapshot_id IS NOT NULL RETURN count(s) AS n",
                    company=company,
                ).single(strict=True)["n"]
                for key, label in (("tasks", "GuardTask"), ("grants", "GuardGrant")):
                    counts[key] = session.run(
                        f"MATCH (s:GuardSource {{company_id:$company}}) MATCH (n:{label} {{source_id:s.id,projection_id:s.current_snapshot_id}}) RETURN count(n) AS n",
                        company=company,
                    ).single(strict=True)["n"]
                counts["databaseNodes"] = session.run("MATCH (n) RETURN count(n) AS n").single(
                    strict=True
                )["n"]
                counts["databaseRelationships"] = session.run(
                    "MATCH ()-[r]->() RETURN count(r) AS n"
                ).single(strict=True)["n"]
            query_env = os.environ.copy()
            for key in tuple(query_env):
                if key.startswith("NEO4J_") or key == runner.CONFIG_ENV:
                    query_env.pop(key)
            query_env[runner.CONFIG_ENV] = str(config)
            queried = subprocess.run(
                [node, str(BRIDGE)],
                input=json.dumps(
                    {
                        "sources": source_ids,
                        "samples": options.samples,
                        "scope": {
                            "subject": "synthetic-benchmark",
                            "companyId": company,
                            "tenantIds": sorted(tenant_ids),
                            "teamIds": ["team-0"],
                            "allTeams": False,
                        },
                    }
                ),
                capture_output=True,
                text=True,
                check=True,
                timeout=options.samples * 13 + 30,
                env=query_env,
            )
            measurements = json.loads(queried.stdout)
            result = gates(options.profile, publications, measurements["samples"], counts)
            report.update(
                {
                    "passed": result["passed"],
                    "gates": result,
                    "graph": counts,
                    "publicationSeconds": publications,
                    "batchSeconds": batch_seconds,
                    "snapshotBytes": {"maximum": max(snapshot_sizes), "total": sum(snapshot_sizes)},
                    "queries": measurements,
                }
            )
    except KeyboardInterrupt:
        report["error"] = "PILOT_INTERRUPTED"
    except Exception as error:
        # Imported values, database locations, stderr and credentials never enter reports.
        report["error"] = f"PILOT_FAILED_{type(error).__name__.upper()}"
    finally:
        if tunnel is not None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)
        try:
            runner.remove_owned_container(name, run_id)
            remaining = runner.docker(
                "ps", "--all", "--filter", f"label={runner.LABEL}={run_id}", "--format", "{{.ID}}"
            )
            report["disposableCleanup"] = not remaining
            if remaining:
                report["passed"] = False
        except (OSError, RuntimeError, subprocess.SubprocessError):
            report["disposableCleanup"] = False
            report["passed"] = False
        report["completedAt"] = datetime.now(UTC).isoformat()
        with options.output.open("x", encoding="utf-8") as destination:
            destination.write(json.dumps(report, indent=2, allow_nan=False) + "\n")
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "profile": options.profile,
                    "output": str(options.output),
                }
            )
        )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
