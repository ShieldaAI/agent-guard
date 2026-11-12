"""The source-transition document: validation only, with no graph or archive access."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import NoReturn, cast

from agent_guard_cartography._ids import PROFILES, source_identity
from agent_guard_cartography._json import unique_object
from agent_guard_cartography.errors import AgentGuardCartographyError
from agent_guard_cartography.input_files import read_regular_file
from agent_guard_cartography.shapes import Source, Transition

MAX_TRANSITION_BYTES = 256 * 1024


class LifecycleError(AgentGuardCartographyError, RuntimeError):
    """Stable safe diagnostics, excluding host configuration and database details."""


def _fail(code: str = "SOURCE_TRANSITION_INVALID") -> NoReturn:
    raise LifecycleError(code)


def _source(value: object) -> Source:
    source = source_identity(value)
    if source is None:
        _fail()
    return cast(Source, source)


def validate_transition(value: object) -> Transition:
    """Detach a closed explicit predecessor/successor transition within one installation."""
    if (
        type(value) is not dict
        or value.keys() != {"schemaVersion", "predecessor", "successor", "profile"}
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
        or type(value["profile"]) is not str
        or value["profile"] not in PROFILES
    ):
        _fail()
    before, after = _source(value["predecessor"]), _source(value["successor"])
    if any(before[key] != after[key] for key in ("companyId", "sourceId", "tenantId")):
        _fail("SOURCE_TRANSITION_SCOPE_MISMATCH")
    if before["enrollmentGeneration"] == after["enrollmentGeneration"]:
        _fail()
    result: Transition = {
        "schemaVersion": 1,
        "predecessor": before,
        "successor": after,
        "profile": value["profile"],
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_TRANSITION_BYTES:
        _fail()
    return result


def transition_id(value: object) -> str:
    """The stable identifier of one validated transition."""
    transition = validate_transition(value)
    return sha256(
        json.dumps(transition, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def load_transition(path: Path | str) -> Transition:
    """Read and validate a transition file of at most 256 KiB."""
    try:
        contents = read_regular_file(path, MAX_TRANSITION_BYTES + 1)
        if len(contents) > MAX_TRANSITION_BYTES:
            _fail()
        return validate_transition(
            json.loads(contents.decode("utf-8"), object_pairs_hook=unique_object)
        )
    except FileNotFoundError:
        raise LifecycleError("SOURCE_TRANSITION_NOT_FOUND") from None
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        raise LifecycleError("SOURCE_TRANSITION_INVALID") from None
