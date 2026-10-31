"""The integration suite runs against the pinned authenticated server."""

import json
import os
from pathlib import Path

import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError

pytestmark = pytest.mark.integration


def test_pinned_authenticated_database(neo4j_session):
    record = neo4j_session.run(
        "CALL dbms.components() YIELD versions, edition RETURN versions[0] AS version, edition"
    ).single(strict=True)
    assert record["version"] == "5.26.32"
    assert record["edition"] == "community"
    config = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())
    with GraphDatabase.driver(
        config["uri"],
        auth=("neo4j", "deliberately-invalid-password"),
        connection_timeout=3,
        max_transaction_retry_time=0,
    ) as rejected:
        with pytest.raises(AuthError):
            rejected.verify_connectivity()
