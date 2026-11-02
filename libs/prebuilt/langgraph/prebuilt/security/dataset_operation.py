"""Runtime operation `dataset_read`: a policy-checked, pinned read of operator data.

Contract. Given an authenticated `Principal` and a dataset id, `read_dataset`
returns the exact bytes of one operator-registered file, or raises
`UnsupportedFeatureError` with a fixed `dataset:*` code. The caller names an
id only. The file path, expected sha256, byte cap and format come from a
`DatasetRegistry` the operator configures; no caller-supplied path is ever
opened. In order:

1. Exact-type validation of principal, id, registry and authorizer.
2. Unknown id -> `dataset:unknown` (nothing is opened, policy is not asked).
3. Policy: `authorize(principal, DatasetReadRequest(...))` must return an
   exact `Decision` with `Verdict.ALLOW` and no constraints; anything else ->
   `dataset:denied`, before any open.
4. Pinned open: the registered canonical path is resolved beneath `/` with
   Linux `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` through
   `landlock.open_path_descriptor`, the same primitive `inprocess.read_text`
   uses. A symlink in any component, or a non-regular file -> `dataset:changed`.
   The read goes through that descriptor's inode only (reopened via its own
   `/proc/self/fd` entry and checked for the same device/inode), so a later
   pathname swap cannot redirect it.
5. Bounded read: at most `max_bytes + 1` bytes are read; more ->
   `dataset:too_large`.
6. The sha256 of exactly the bytes read must equal the pinned digest, else
   `dataset:changed`. The returned bytes are the hashed bytes, so a concurrent
   in-place write yields either the pinned content or a refusal.

The result is inert `bytes`; this module never parses or executes it.

Policy mechanism. Resource reads elsewhere are authorized per tool call
(`object_policy.CedarObjectAuthorizer.authorize` binds a grant to a tool name,
owner and call id) or as framework objects (`SecurityStack.object_permission`,
whose `FrameworkRequest` union in `objects.py` has no dataset operation).
`dataset_read` is called by trusted application code outside any tool call, so
neither entry point applies without inventing a fake tool call or a new
framework request kind. The runtime therefore wires an `authorize(principal,
request) -> Decision` callable, with the same shape and the same exact
`Decision`/`Verdict` records as the `SecurityModule` permission hooks, typically
backed by the deployment's stack or Cedar policy for the `dataset_read`
capability.

On macOS the directory walk uses `openat` with `O_SEARCH | O_NOFOLLOW`, holding
each directory descriptor until the next component is pinned. The final file
is opened read-only and nonblocking with `O_NOFOLLOW | O_NOCTTY`, checked as a
regular file before reading, and read through a duplicate of that same live
descriptor. No pathname is resolved again after pinning. `O_SEARCH` requests
traversal, not directory listing access. Byte caps and digest checks are shared.

Premises: Linux with `openat2` (5.6+) and a mounted `/proc`, or macOS with
descriptor-relative opens and `O_SEARCH`; other platforms refuse. The registry is configured by the operator
and its files are not writable by the attacker except as detected by the
digest. The caller is trusted application code (advisor decision D11): it may
pass attacker-influenced ids, which are only looked up, never resolved.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import hmac
import inspect
import os
import posixpath
import re
import stat
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from types import MappingProxyType

from langgraph.prebuilt.security._pinned_file import open_path_descriptor
from langgraph.prebuilt.security.types import (
    Decision,
    Principal,
    Verdict,
    _validate_principal,
)
from langgraph.prebuilt.security.unsupported import UnsupportedFeatureError

__all__ = [
    "DatasetEntry",
    "DatasetReadRequest",
    "DatasetRegistry",
    "aread_dataset",
    "read_dataset",
]

_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FORMATS = frozenset({"csv"})
_CHUNK = 1 << 16


def _require_id(value: object) -> str:
    if type(value) is not str or _ID.match(value) is None:
        raise TypeError("dataset id must be a plain identifier string")
    return value


@dataclass(frozen=True, slots=True)
class DatasetEntry:
    """One operator-pinned dataset: canonical path, digest, byte cap, format."""

    dataset_id: str
    path: str
    sha256: str
    max_bytes: int
    format: str = "csv"

    def __post_init__(self) -> None:
        _require_id(self.dataset_id)
        if (
            type(self.path) is not str
            or not self.path.startswith("/")
            or posixpath.normpath(self.path) != self.path
            or "\x00" in self.path
            or self.path == "/"
        ):
            raise ValueError("dataset path must be canonical and absolute")
        if type(self.sha256) is not str or _SHA256.match(self.sha256) is None:
            raise ValueError("dataset sha256 must be 64 lowercase hex digits")
        if type(self.max_bytes) is not int or self.max_bytes <= 0:
            raise ValueError("dataset max_bytes must be a positive int")
        if type(self.format) is not str or self.format not in _FORMATS:
            raise ValueError("dataset format must be 'csv'")


@dataclass(frozen=True, slots=True, init=False)
class DatasetRegistry:
    """Immutable operator registry mapping dataset ids to pinned entries."""

    entries: MappingProxyType[str, DatasetEntry]

    def __init__(self, entries: tuple[DatasetEntry, ...]) -> None:
        if type(entries) is not tuple:
            raise TypeError("dataset registry entries must be a tuple")
        table: dict[str, DatasetEntry] = {}
        for entry in entries:
            if type(entry) is not DatasetEntry:
                raise TypeError("dataset registry accepts only DatasetEntry")
            if entry.dataset_id in table:
                raise ValueError("duplicate dataset id")
            table[entry.dataset_id] = entry
        object.__setattr__(self, "entries", MappingProxyType(table))

    def lookup(self, dataset_id: str) -> DatasetEntry | None:
        """Return the pinned entry for an exact id, or `None`."""
        return self.entries.get(dataset_id)


@dataclass(frozen=True, slots=True)
class DatasetReadRequest:
    """The capability question put to policy: may `principal_id` read this id."""

    dataset_id: str
    principal_id: str

    def __post_init__(self) -> None:
        _require_id(self.dataset_id)
        if type(self.principal_id) is not str or not self.principal_id:
            raise TypeError("principal id must be a non-empty string")


Authorize = Callable[[Principal, DatasetReadRequest], Decision]
AsyncAuthorize = Callable[
    [Principal, DatasetReadRequest], "Awaitable[Decision] | Decision"
]


def _prepare(
    principal: Principal,
    dataset_id: str,
    registry: DatasetRegistry,
    authorize: object,
) -> tuple[DatasetEntry, DatasetReadRequest]:
    _validate_principal(principal)
    _require_id(dataset_id)
    if type(registry) is not DatasetRegistry:
        raise TypeError("registry must be an exact DatasetRegistry")
    if not callable(authorize):
        raise TypeError("authorize must be callable")
    entry = registry.lookup(dataset_id)
    if entry is None:
        raise UnsupportedFeatureError("dataset:unknown")
    return entry, DatasetReadRequest(dataset_id, principal.user_id)


def _require_allow(decision: object) -> None:
    if (
        type(decision) is not Decision
        or decision.verdict is not Verdict.ALLOW
        or decision.constraints != ()
    ):
        raise UnsupportedFeatureError("dataset:denied")


def _read_pinned(entry: DatasetEntry) -> bytes:
    if sys.platform not in {"linux", "darwin"}:
        raise UnsupportedFeatureError("dataset:unavailable")
    pinned = None
    readable = None
    try:
        try:
            pinned = open_path_descriptor(entry.path, no_symlinks=True)
        except OSError as exc:
            if exc.errno == errno.ELOOP or (
                sys.platform == "darwin" and exc.errno == errno.ENOTDIR
            ):
                raise UnsupportedFeatureError("dataset:changed") from None
            raise UnsupportedFeatureError("dataset:unavailable") from None
        identity = os.fstat(pinned)
        if not stat.S_ISREG(identity.st_mode):
            raise UnsupportedFeatureError("dataset:changed")
        if identity.st_size > entry.max_bytes:
            raise UnsupportedFeatureError("dataset:too_large")
        # Reopen our own live descriptor; this never re-resolves entry.path.
        readable = (
            os.dup(pinned)
            if sys.platform == "darwin"
            else os.open(
                f"/proc/self/fd/{pinned}",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY,
            )
        )
        opened = os.fstat(readable)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            identity.st_dev,
            identity.st_ino,
        ):
            raise UnsupportedFeatureError("dataset:changed")
        chunks: list[bytes] = []
        total = 0
        limit = entry.max_bytes + 1
        while total < limit:
            chunk = os.read(readable, min(_CHUNK, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > entry.max_bytes:
            raise UnsupportedFeatureError("dataset:too_large")
        data = b"".join(chunks)
    except UnsupportedFeatureError:
        raise
    except OSError:
        raise UnsupportedFeatureError("dataset:unavailable") from None
    finally:
        try:
            if readable is not None:
                os.close(readable)
        finally:
            if pinned is not None:
                os.close(pinned)
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), entry.sha256):
        raise UnsupportedFeatureError("dataset:changed")
    return data


def read_dataset(
    principal: Principal,
    dataset_id: str,
    *,
    registry: DatasetRegistry,
    authorize: Authorize,
) -> bytes:
    """Return the pinned bytes of `dataset_id` after policy allows the read.

    Raises `UnsupportedFeatureError` with `dataset:unknown`, `dataset:denied`,
    `dataset:too_large`, `dataset:changed` or `dataset:unavailable`, and
    `TypeError` for non-exact argument types.
    """
    entry, request = _prepare(principal, dataset_id, registry, authorize)
    decision = authorize(principal, request)
    if inspect.isawaitable(decision):
        if inspect.iscoroutine(decision):
            decision.close()
        raise UnsupportedFeatureError("dataset:denied")
    _require_allow(decision)
    return _read_pinned(entry)


async def aread_dataset(
    principal: Principal,
    dataset_id: str,
    *,
    registry: DatasetRegistry,
    authorize: AsyncAuthorize,
) -> bytes:
    """Asynchronous `read_dataset`; `authorize` may be sync or async.

    The pinned read runs in a worker thread so the event loop is not blocked.
    """
    entry, request = _prepare(principal, dataset_id, registry, authorize)
    decision = authorize(principal, request)
    if inspect.isawaitable(decision):
        decision = await decision
    _require_allow(decision)
    return await asyncio.to_thread(_read_pinned, entry)
