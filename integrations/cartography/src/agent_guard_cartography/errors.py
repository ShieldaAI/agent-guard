"""The error base shared by every module: a stable code, never imported values."""

from __future__ import annotations

import re


def display_name(name: str) -> str:
    """A bounded printable basename for diagnostics; never a path or file content."""
    return re.sub(r"[^A-Za-z0-9._-]", "?", name)[:128]


class AgentGuardCartographyError(Exception):
    """A failure identified by ``code`` alone.

    The message is the code. Paths, response bodies, credentials and imported values
    never enter an error; ``file`` is at most the basename of one file that explains it.
    """

    def __init__(self, code: str, file: str | None = None) -> None:
        self.code = code
        self.file = None if file is None else display_name(file)
        super().__init__(code)
