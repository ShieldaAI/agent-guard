"""Fixtures restrict integration tests to a container created by our runner."""

from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest
from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parents[1]
LABEL = "com.shielda.agent-guard.disposable-test"


@pytest.fixture(scope="session")
def neo4j_driver():
    config_path = os.environ.get("AGENT_GUARD_TEST_NEO4J_CONFIG")
    if not config_path:
        pytest.fail(
            "Integration tests require scripts/test-disposable-neo4j.py; "
            "existing Neo4j URLs are deliberately unsupported."
        )
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    if not re.fullmatch(r"[0-9a-f]{64}", config.get("containerId", "")):
        pytest.fail("Invalid disposable Neo4j container identifier")
    if not re.fullmatch(r"[0-9a-f]{32}", config.get("runId", "")):
        pytest.fail("Invalid disposable Neo4j ownership identifier")
    image = (ROOT / "neo4j-image.txt").read_text(encoding="utf-8").strip()
    if config.get("image") != image:
        pytest.fail("Disposable Neo4j image differs from the pinned test image")
    info = json.loads(
        subprocess.run(
            ["docker", "inspect", config["containerId"]],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    )[0]
    parsed = urlparse(config.get("uri", ""))
    if parsed.scheme != "bolt" or parsed.hostname != "127.0.0.1" or parsed.path:
        pytest.fail("Test Neo4j connection must use the runner's loopback Bolt endpoint")
    ports = info.get("NetworkSettings", {}).get("Ports", {}).get("7687/tcp")
    expected_ports = [{"HostIp": "127.0.0.1", "HostPort": config.get("dockerPort")}]
    if (
        info.get("Config", {}).get("Labels", {}).get(LABEL) != config["runId"]
        or info.get("Config", {}).get("Image") != image
        or not info.get("State", {}).get("Running")
        or ports != expected_ports
        or any(mount.get("Type") == "bind" for mount in info.get("Mounts", []))
    ):
        pytest.fail("Database does not belong to this disposable test run")
    with GraphDatabase.driver(
        config["uri"],
        auth=(config["username"], config["password"]),
        connection_timeout=5,
        max_transaction_retry_time=5,
    ) as driver:
        driver.verify_connectivity()
        with driver.session(database="neo4j") as session:
            marker = session.run(
                "MATCH (r:GuardDisposableTestRun {id: $runId}) RETURN count(r) AS count",
                runId=config["runId"],
            ).single(strict=True)
        if marker["count"] != 1:
            pytest.fail("Database connection does not have this runner's unique ownership marker")
        yield driver


@pytest.fixture
def neo4j_session(neo4j_driver):
    with neo4j_driver.session(database="neo4j") as session:
        yield session


@pytest.fixture
def snapshot_factory():
    """Each test owns a fresh source namespace; no whole-database deletion."""
    from agent_guard_cartography.inventory import load_snapshot

    suffix = uuid.uuid4().hex

    def make(name: str = "alpha-v1"):
        snapshot = load_snapshot(ROOT / "tests" / "fixtures" / f"{name}.json")
        snapshot["source"]["sourceId"] += f"-{suffix}"
        return snapshot

    return make
