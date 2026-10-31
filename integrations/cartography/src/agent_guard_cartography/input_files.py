"""Bounded reads of local input files, without waiting for FIFO writers."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def read_regular_file(path: str | Path, maximum: int) -> bytes:
    """Read at most ``maximum`` bytes, preserving symlinks to regular files.

    Check the opened descriptor, so a path replacement cannot turn the file
    type check into a blocking FIFO open. Callers retain their own size and
    JSON validation and translate I/O errors to their existing diagnostics.
    """
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nonblocking is None:
        raise OSError("nonblocking input files are unsupported")
    descriptor = os.open(path, os.O_RDONLY | nonblocking)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("local input is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read(maximum)
    finally:
        os.close(descriptor)
