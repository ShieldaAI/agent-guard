"""Identifier rules shared by enrollment, lifecycle, cloud and AWS configuration."""

from __future__ import annotations

import re

SHA256_HEX = re.compile(r"[a-f0-9]{64}")
PROFILES = ("core", "host", "host-mcp")
SOURCE_FIELDS = frozenset(
    ("companyId", "sourceId", "enrollmentGeneration", "inventoryInstanceId", "tenantId")
)
MAX_IDENTIFIER_LENGTH = 4096
# 9999-12-31T23:59:59Z, the last second a four-digit-year timestamp can name.
MAX_TIMESTAMP_SECONDS = 253_402_300_799
# Commercial AWS regions only; China and GovCloud partitions are not supported.
AWS_REGION = re.compile(
    r"(?:af|ap|ca|eu|il|me|mx|sa|us)-"
    r"(?:central|east|west|north|south|northeast|northwest|southeast|southwest)-[1-9][0-9]?"
)


def is_identifier(value: object) -> bool:
    """A bounded string with visible content, no NUL and no lone surrogate."""
    return (
        type(value) is str
        and len(value) <= MAX_IDENTIFIER_LENGTH
        and any(character != "﻿" and not character.isspace() for character in value)
        and "\x00" not in value
        and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    )


def source_identity(value: object) -> dict[str, str] | None:
    """The exact five-field source with sorted keys, or ``None`` when it is not one."""
    if type(value) is not dict or value.keys() != SOURCE_FIELDS:
        return None
    if not all(is_identifier(value[key]) for key in SOURCE_FIELDS):
        return None
    return {key: value[key] for key in sorted(SOURCE_FIELDS)}
