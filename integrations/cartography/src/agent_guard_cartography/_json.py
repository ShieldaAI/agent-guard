"""Strict JSON decoding hooks and the canonical encoding used for hashes and files."""

from __future__ import annotations

import json
from typing import Any, NoReturn


class DuplicateKeyError(ValueError):
    """A JSON object repeated a member name."""


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that refuses a repeated member instead of keeping the last."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError()
        result[key] = value
    return result


def reject_constant(_value: str) -> NoReturn:
    """``parse_constant`` that refuses NaN and the infinities."""
    raise ValueError()


def loads_strict(text: str) -> Any:
    """Decode text, refusing repeated members and non-finite numbers."""
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def canonical_bytes(value: Any) -> bytes:
    """Sorted, compact UTF-8 JSON: the byte form archived files and their hashes use."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
