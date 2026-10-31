"""Host-specific, descriptor-relative file binding for trusted read operations."""

from __future__ import annotations

import errno
import os
import posixpath
import sys

from langgraph.prebuilt.security.landlock import open_path_descriptor as _linux_open


def open_path_descriptor(path: str, *, no_symlinks: bool = False) -> int:
    """Pin all components; Darwin returns a readable, nonblocking descriptor.

    The caller must reject non-regular final objects before reading. Linux
    returns its original `O_PATH` descriptor, which requires a verified reopen.
    """
    if sys.platform != "darwin":
        return _linux_open(path, no_symlinks=no_symlinks)
    if not no_symlinks or not path.startswith("/") or posixpath.normpath(path) != path:
        raise OSError(errno.EINVAL, "canonical no-symlink path required")
    directory = os.open("/", os.O_SEARCH | os.O_CLOEXEC)
    try:
        components = path.lstrip("/").split("/")
        for component in components[:-1]:
            child = os.open(
                component, os.O_SEARCH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            os.close(directory)
            directory = child
        return os.open(
            components[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC,
            dir_fd=directory,
        )
    finally:
        os.close(directory)
