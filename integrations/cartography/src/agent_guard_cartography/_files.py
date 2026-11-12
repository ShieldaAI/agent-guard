"""Private directories and files: owned by this user, closed to group and others."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class UnsafePathError(Exception):
    """The path is not a private, owned directory or single-link regular file."""


class FileTooLargeError(Exception):
    """The file holds more bytes than the caller accepts."""


def is_private_file(metadata: os.stat_result, *, links: tuple[int, ...] = (1,)) -> bool:
    """A regular file owned by this user, with no group/other access and no extra links."""
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_nlink in links
        and not metadata.st_mode & 0o077
    )


def open_private_directory(path: Path | str, *, create: bool = False) -> int:
    """Open ``path`` component by component without following symlinks.

    The final directory must be owned by this user with no group/other access.
    ``create`` makes that final component (mode 0700) when it is missing; parents
    are never created. Returns a descriptor the caller closes. Raises
    ``UnsafePathError`` for a relative escape or a shared directory, and ``OSError``
    (for example ``FileNotFoundError``) when a component cannot be opened.
    """
    absolute = Path(path).absolute()
    if ".." in absolute.parts:
        raise UnsafePathError()
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = absolute.parts[1:]
        for index, part in enumerate(parts):
            if create and index == len(parts) - 1:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise UnsafePathError()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_private_file(name: Path | str, maximum: int, *, dir_fd: int | None = None) -> bytes:
    """Read at most ``maximum`` bytes of a private regular file, never blocking on a FIFO.

    The opened descriptor is checked, so a replaced path cannot change what is read.
    Raises ``UnsafePathError``, ``FileTooLargeError`` or ``OSError``.
    """
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        metadata = os.fstat(descriptor)
        if not is_private_file(metadata):
            raise UnsafePathError()
        if metadata.st_size > maximum:
            raise FileTooLargeError()
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > maximum:
            raise FileTooLargeError()
        return bytes(result)
    finally:
        os.close(descriptor)
