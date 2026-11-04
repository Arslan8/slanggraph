"""Bridge to the executable Lean worker-lifecycle decision core.

The operator pins a built binary. Its bytes are captured once. Linux loads a
sealed memfd; macOS loads a private, immutable snapshot and unlinks it after
native loading/execution. The controller and its same-UID runtime ownership are
trusted; same-UID debugging and malicious operator code are outside this loader
contract. There is no Python decision fallback. Lean proves the core
transition rules. Compiler/runtime, JSON transport, observation provenance and
placement of these calls in the executor are separate correspondence obligations.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from threading import RLock
from types import MemberDescriptorType
from typing import Any

try:
    import fcntl
except ImportError:
    fcntl = None

from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AdapterPlan,
    EnforcementMode,
    EnforcementPlan,
    ObligationAssignment,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied

_MAX_BINARY = 128 * 1024 * 1024
_MAX_NATIVE_RUNTIME = 256 * 1024 * 1024
_MAX_REQUEST = 1_048_576
_PROTOCOL = "worker-route-grant-v3"


@contextmanager
def _macos_snapshot(image: bytes):
    """Private immutable inode for dyld/exec; remove it after native loading."""
    with tempfile.TemporaryDirectory(prefix="argus-lean-") as directory:
        path = os.path.join(directory, "image")
        with open(path, "xb") as target:
            target.write(image)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(path, 0o500)
        os.chflags(path, stat.UF_IMMUTABLE)
        try:
            yield path
        finally:
            os.chflags(path, 0)


def _pinned_image(path: str, digest: str, *, maximum: int = _MAX_BINARY) -> bytes:
    descriptor = None
    image = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= maximum:
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                image = source.read(maximum + 1)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        image is None
        or len(image) > maximum
        or hashlib.sha256(image).hexdigest() != digest
    ):
        raise HostExecutionDenied("host:lean_binary_unavailable_or_changed")
    return image


def _sealed_library(image: bytes, *, global_symbols: bool) -> tuple[ctypes.CDLL, int]:
    if sys.platform == "darwin":
        # dyld needs a Mach-O pathname. Materialize captured bytes in a private
        # operator-owned directory, make the inode immutable during loading,
        # then unlink it. No original mutable input path is passed to dyld.
        # As with the rest of the controller, same-UID debugging/ptrace and
        # malicious operator code are outside this trusted-loader contract.
        with tempfile.TemporaryDirectory(prefix="argus-lean-") as directory:
            path = os.path.join(directory, "image.dylib")
            with open(path, "xb") as target:
                target.write(image)
                target.flush()
                os.fsync(target.fileno())
            os.chmod(path, 0o500)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.chflags(path, stat.UF_IMMUTABLE)
                mode = os.RTLD_NOW | (
                    os.RTLD_GLOBAL if global_symbols else os.RTLD_LOCAL
                )
                library = ctypes.CDLL(path, mode=mode)
                if (
                    _pinned_image(
                        path,
                        hashlib.sha256(image).hexdigest(),
                        maximum=_MAX_NATIVE_RUNTIME,
                    )
                    != image
                ):
                    raise OSError("native checker snapshot changed")
                return library, descriptor
            except BaseException:
                os.close(descriptor)
                raise
            finally:
                os.chflags(path, 0)
    if fcntl is None:
        raise OSError("sealed native libraries require fcntl")
    descriptor = _memfd()
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            target.write(image)
            target.flush()
        fcntl.fcntl(descriptor, 1033, 15)
        if fcntl.fcntl(descriptor, 1034) & 15 != 15:
            raise OSError("native checker sealing unconfirmed")
        mode = os.RTLD_NOW | (os.RTLD_GLOBAL if global_symbols else os.RTLD_LOCAL)
        return ctypes.CDLL(f"/proc/self/fd/{descriptor}", mode=mode), descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _memfd() -> int:
    # Fixed Linux UAPI: MFD_CLOEXEC | MFD_ALLOW_SEALING. Some supported CPython
    # builds omit the os wrapper/constants even when the kernel API is present.
    # Bind the same libc primitive; never fall back to a writable pathname.
    if sys.platform != "linux":
        raise OSError("Linux sealed executables required")
    function = ctypes.CDLL(None, use_errno=True).memfd_create
    function.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    descriptor = function(b"lean-worker-route", 3)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "memfd_create failed")
    return descriptor


def _charge(budget: list[int], size: int) -> None:
    budget[0] -= size
    if budget[0] < 0:
        raise HostExecutionDenied("host:lean_protocol_shape")


def _string(
    value: Any, *, nonempty: bool = False, budget: list[int] | None = None
) -> str:
    if type(value) is not str or len(value) > 4096 or (nonempty and not value):
        raise HostExecutionDenied("host:lean_protocol_shape")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise HostExecutionDenied("host:lean_protocol_shape")
    if budget is not None:
        _charge(budget, _string_size(value))
    return value


def _string_size(value: str) -> int:
    # Exact ensure_ascii JSON length, including quotes; no candidate conversion.
    size = 2
    for character in value:
        code = ord(character)
        if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
            size += 2
        elif code < 0x20 or 0x7F <= code <= 0xFFFF:
            size += 6
        elif code > 0xFFFF:
            size += 12
        else:
            size += 1
    return size


def _data(value: Any, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Copy only bounded native protocol data without candidate conversion."""
    if budget is None:
        budget = [_MAX_REQUEST - 1]  # Include the terminal newline.
    if depth > 12:
        raise HostExecutionDenied("host:lean_protocol_shape")
    if type(value) is str:
        _string(value)
        _charge(budget, _string_size(value))
        return value
    if type(value) is bool:
        _charge(budget, 4 if value else 5)
        return value
    if type(value) is list and len(value) <= 256:
        items = tuple(value)
        _charge(budget, 2 + max(0, len(items) - 1))
        return [_data(item, depth + 1, budget) for item in items]
    if type(value) is dict and len(value) <= 16:
        items = tuple(value.items())
        _charge(budget, 2 + max(0, len(items) - 1) + len(items))
        result = {}
        for key, item in items:
            _string(key)
            _charge(budget, _string_size(key))
            result[key] = _data(item, depth + 1, budget)
        return result
    raise HostExecutionDenied("host:lean_protocol_shape")


def _encoded(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def _slots(owner: type, names: tuple[str, ...]) -> tuple[MemberDescriptorType, ...]:
    namespace = type.__dict__["__dict__"].__get__(owner)
    pairs = tuple(namespace.items())
    if any(type(key) is not str for key, _ in pairs):
        raise RuntimeError("invalid native receipt record definition")
    result = []
    for name in names:
        slot = None
        for key, value in pairs:
            if key == name:
                slot = value
        if (
            type(slot) is not MemberDescriptorType
            or slot.__objclass__ is not owner
            or type(slot.__name__) is not str
            or slot.__name__ != name
        ):
            raise RuntimeError("invalid native receipt record definition")
        result.append(slot)
    return tuple(result)


_PLAN_SLOTS = _slots(
    EnforcementPlan,
    (
        "grant_digest",
        "host_digest",
        "mode",
        "assignments",
        "adapter_plans",
        "waived_obligations",
        "removed_wants",
    ),
)
_RECEIPT_SLOTS = _slots(
    ActivationReceipt,
    (
        "grant_digest",
        "plan_digest",
        "host_digest",
        "context_digest",
        "nonce",
        "artifact_digest",
        "deployment_digest",
        "runtime_digest",
        "mode",
        "activated_obligations",
        "removed_wants",
        "evidence",
    ),
)
_ASSIGNMENT_SLOTS = _slots(
    ObligationAssignment, ("obligation_id", "adapter_id", "support")
)
_NATIVE_PLAN_SLOTS = _slots(
    AdapterPlan, ("adapter_id", "native_plan_digest", "obligation_ids")
)
_EVIDENCE_SLOTS = _slots(
    ActivationEvidence,
    ("adapter_id", "native_plan_digest", "context_digest", "nonce", "obligation_ids"),
)


def _record(value: Any, owner: type, slots: tuple[MemberDescriptorType, ...]) -> tuple:
    if type(value) is not owner:
        raise HostExecutionDenied("host:lean_certificate_shape")
    return tuple(slot.__get__(value) for slot in slots)


def _rows(value: Any) -> tuple:
    if type(value) is not tuple or len(value) > 256:
        raise HostExecutionDenied("host:lean_certificate_shape")
    return value


def _strings(
    value: Any, *, unordered: bool = False, budget: list[int] | None = None
) -> list[str]:
    expected = frozenset if unordered else tuple
    if type(value) is not expected or len(value) > 256:
        raise HostExecutionDenied("host:lean_certificate_shape")
    if budget is not None:
        _charge(budget, 2 + max(0, len(value) - 1))
    result = [_string(item, nonempty=True, budget=budget) for item in value]
    return sorted(result) if unordered else result


def _mode(value: Any) -> str:
    if value is EnforcementMode.ENFORCED:
        return "enforced"
    if value is EnforcementMode.DEGRADED:
        return "degraded"
    raise HostExecutionDenied("host:lean_certificate_shape")


def _support(value: Any) -> str:
    if value is SupportLevel.EXACT:
        return "exact"
    if value is SupportLevel.TIGHTENED:
        return "tightened"
    raise HostExecutionDenied("host:lean_certificate_shape")


def _capture_receipt_certificate(
    plan: EnforcementPlan,
    receipt: ActivationReceipt,
    *,
    plan_digest: str,
    grant: dict,
    obligations: list,
) -> dict:
    """Detach the semantic certificate from exact native record slots.

    The caller supplies its validated plan digest. This projection does not
    invoke digest properties, verify signatures/freshness, or describe native
    plan payloads; those remain coordinator and observation-provenance premises.
    Framework class/descriptor binding and stability during capture are separate.
    """
    result = None
    try:
        result = _data(
            {
                "grant": grant,
                "obligations": obligations,
                **_capture_certificate(plan, receipt, plan_digest),
            }
        )
    except (AttributeError, RecursionError):
        pass
    if result is None:
        # Do not retain this locally caught missing-slot error and its .obj as
        # context/cause. Ambient caller exception state and tracebacks remain
        # possible; this is not a publication-safe exception sanitizer.
        raise HostExecutionDenied("host:lean_certificate_shape")
    return result


def _capture_controller_receipt_certificate(
    plan: EnforcementPlan,
    receipt: ActivationReceipt,
    *,
    plan_digest: str,
    grant: dict,
    obligations: list,
) -> dict:
    """Capture fresh native records around controller-owned checked data.

    The selected host route owns `grant` and `obligations`, and has already
    passed them through the grant checker. The returned plan and receipt rows
    are newly projected from exact native slots. Avoid detaching this complete
    controller-owned envelope again before immediately encoding it for Lean.
    """
    if type(grant) is not dict or type(obligations) is not list:
        raise HostExecutionDenied("host:lean_certificate_shape")
    result = None
    try:
        result = {
            "grant": grant,
            "obligations": obligations,
            **_capture_certificate(plan, receipt, plan_digest),
        }
    except (AttributeError, RecursionError):
        pass
    if result is None:
        raise HostExecutionDenied("host:lean_certificate_shape")
    return result


def _capture_certificate(plan: Any, receipt: Any, plan_digest: Any) -> dict:
    # Charge projected strings/arrays as they are inspected so an oversized
    # early row stops capture before later rows. The general capture's `_data`
    # walk or the controller route's final prepared encoding enforces the full
    # envelope limit, including fixed keys and punctuation.
    budget = [_MAX_REQUEST - 1]
    grant, host, mode, assignments, native_plans, waived, removed = _record(
        plan, EnforcementPlan, _PLAN_SLOTS
    )
    rows = []
    for row in _rows(assignments):
        obligation, adapter, support = _record(
            row, ObligationAssignment, _ASSIGNMENT_SLOTS
        )
        rows.append(
            {
                "obligation": _string(obligation, nonempty=True, budget=budget),
                "adapter": _string(adapter, nonempty=True, budget=budget),
                "support": _support(support),
            }
        )
    plans = []
    for row in _rows(native_plans):
        adapter, digest, obligations = _record(row, AdapterPlan, _NATIVE_PLAN_SLOTS)
        plans.append(
            {
                "adapter": _string(adapter, nonempty=True, budget=budget),
                "digest": _string(digest, nonempty=True, budget=budget),
                "obligations": _strings(obligations, unordered=True, budget=budget),
            }
        )
    plan_data = {
        "grant": _string(grant, nonempty=True, budget=budget),
        "host": _string(host, nonempty=True, budget=budget),
        "digest": _string(plan_digest, nonempty=True, budget=budget),
        "mode": _mode(mode),
        "assignments": rows,
        "nativePlans": plans,
        "waived": _strings(waived, budget=budget),
        "removedWants": _strings(removed, budget=budget),
    }
    (
        grant,
        plan_id,
        host,
        context,
        nonce,
        artifact,
        deployment,
        runtime,
        mode,
        activated,
        removed,
        evidence,
    ) = _record(receipt, ActivationReceipt, _RECEIPT_SLOTS)
    proofs = []
    for row in _rows(evidence):
        adapter, digest, observed_context, observed_nonce, obligations = _record(
            row, ActivationEvidence, _EVIDENCE_SLOTS
        )
        proofs.append(
            {
                "adapter": _string(adapter, nonempty=True, budget=budget),
                "digest": _string(digest, nonempty=True, budget=budget),
                "context": _string(observed_context, nonempty=True, budget=budget),
                "nonce": _string(observed_nonce, nonempty=True, budget=budget),
                "obligations": _strings(obligations, unordered=True, budget=budget),
            }
        )
    # The outer capture performs the single bounded detachment over the full
    # grant/certificate envelope. Re-copying this subtree here used to walk and
    # validate every immutable row twice on each invocation.
    return {
        "plan": plan_data,
        "receipt": {
            "grant": _string(grant, nonempty=True, budget=budget),
            "plan": _string(plan_id, nonempty=True, budget=budget),
            "host": _string(host, nonempty=True, budget=budget),
            "context": _string(context, nonempty=True, budget=budget),
            "nonce": _string(nonce, nonempty=True, budget=budget),
            "artifact": _string(artifact, nonempty=True, budget=budget),
            "deployment": _string(deployment, budget=budget),
            "runtime": _string(runtime, budget=budget),
            "mode": _mode(mode),
            "activated": _strings(activated, unordered=True, budget=budget),
            "removedWants": _strings(removed, budget=budget),
            "evidence": proofs,
        },
    }


def _response_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate checker response field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class LeanLifecycleChecker:
    """Operator-selected native form of the proved core, with pinned bytes.

    A matching digest identifies bytes; it is not a proof of their build. Use
    the proof project's checked build output and retain its artifact manifest.
    Executables use the native subprocess protocol. A `.so`/`.dylib` and its
    pinned generated-code runtime are loaded from captured images once and
    invoked inline. Arbitrary artifacts or forged build records are outside
    this contract.
    """

    binary_path: str
    binary_sha256: str
    runtime_path: str | None = None
    runtime_sha256: str | None = None
    _image: bytes = field(init=False, repr=False, compare=False)
    _native_libraries: tuple[ctypes.CDLL, ...] = field(
        init=False, repr=False, compare=False, default=()
    )
    _native_check: Any = field(init=False, repr=False, compare=False, default=None)
    _native_prepare: Any = field(init=False, repr=False, compare=False, default=None)
    _native_check_prepared: Any = field(
        init=False, repr=False, compare=False, default=None
    )
    _native_free_prepared: Any = field(
        init=False, repr=False, compare=False, default=None
    )
    _stats: dict[str, int] = field(init=False, repr=False, compare=False)
    _stats_lock: RLock = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_stats",
            {
                "loads": 0,
                "inline_calls": 0,
                "prepared_routes": 0,
                "prepared_calls": 0,
                "subprocess_calls": 0,
            },
        )
        object.__setattr__(self, "_stats_lock", RLock())
        if (
            type(self.binary_path) is not str
            or not self.binary_path.startswith("/")
            or type(self.binary_sha256) is not str
            or len(self.binary_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.binary_sha256)
        ):
            raise HostExecutionDenied("host:lean_binary_configuration")
        image = _pinned_image(self.binary_path, self.binary_sha256)
        object.__setattr__(self, "_image", image)
        if self.binary_path.endswith((".so", ".dylib")):
            if (
                type(self.runtime_path) is not str
                or not self.runtime_path.startswith("/")
                or type(self.runtime_sha256) is not str
                or len(self.runtime_sha256) != 64
                or any(char not in "0123456789abcdef" for char in self.runtime_sha256)
            ):
                raise HostExecutionDenied("host:lean_native_runtime_configuration")
            runtime_descriptor = None
            library_descriptor = None
            try:
                runtime, runtime_descriptor = _sealed_library(
                    _pinned_image(
                        self.runtime_path,
                        self.runtime_sha256,
                        maximum=_MAX_NATIVE_RUNTIME,
                    ),
                    global_symbols=True,
                )
                library, library_descriptor = _sealed_library(
                    image, global_symbols=False
                )
                function = library.argus_worker_route_check_json
                function.argtypes = (
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_char),
                    ctypes.c_size_t,
                )
                function.restype = ctypes.c_int
                prepare = library.argus_worker_route_prepare_json
                prepare.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
                prepare.restype = ctypes.c_void_p
                check_prepared = library.argus_worker_route_check_prepared_json
                check_prepared.argtypes = (
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_char),
                    ctypes.c_size_t,
                )
                check_prepared.restype = ctypes.c_int
                free_prepared = library.argus_worker_route_free_prepared
                free_prepared.argtypes = (ctypes.c_void_p,)
                free_prepared.restype = None
            except HostExecutionDenied:
                raise
            except (AttributeError, OSError) as exc:
                raise HostExecutionDenied("host:lean_native_unavailable") from exc
            finally:
                if runtime_descriptor is not None:
                    os.close(runtime_descriptor)
                if library_descriptor is not None:
                    os.close(library_descriptor)
            object.__setattr__(self, "_native_libraries", (runtime, library))
            object.__setattr__(self, "_native_check", function)
            object.__setattr__(self, "_native_prepare", prepare)
            object.__setattr__(self, "_native_check_prepared", check_prepared)
            object.__setattr__(self, "_native_free_prepared", free_prepared)
            self._stats["loads"] = 1
        elif self.runtime_path is not None or self.runtime_sha256 is not None:
            raise HostExecutionDenied("host:lean_native_runtime_configuration")

    @property
    def inline(self) -> bool:
        """Whether decisions use the once-loaded native checker in-process."""
        return self._native_check is not None

    def require_inline(self) -> None:
        """Refuse an optimized configuration that could spawn checker processes."""
        if not self.inline:
            raise HostExecutionDenied("host:lean_inline_required")

    def statistics(self) -> dict[str, int | bool]:
        """Return detached checker loading and invocation instrumentation."""
        with self._stats_lock:
            return {**self._stats, "inline": self.inline}

    def require(
        self,
        binding: dict,
        events: list,
        phase: str,
        *,
        certificate: dict,
        object_route: bool = False,
    ) -> None:
        """Require the compiled core's exact phase for this captured trace."""
        if type(self) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        if type(events) is not list or len(events) > 32:
            raise HostExecutionDenied("host:lean_protocol_shape")
        self._require(
            {
                "protocol": _PROTOCOL,
                "kind": "object-route" if object_route else "route",
                "binding": binding,
                "certificate": certificate,
                "events": events,
            },
            phase,
        )

    def require_grant(
        self, grant: dict, obligations: list, *, object_route: bool = False
    ) -> None:
        """Require canonical grant generation before negotiation/activation."""
        if type(self) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        self._require(
            {
                "protocol": _PROTOCOL,
                "kind": "object-grant" if object_route else "grant",
                "grant": grant,
                "obligations": obligations,
            },
            "grant_ready",
        )

    def prepare_route(
        self, binding: dict, certificate: dict, *, object_route: bool = False
    ) -> _PreparedLifecycleRoute:
        """Parse the stable binding and certificate into a retained Lean value."""
        if type(self) is not LeanLifecycleChecker or self._native_prepare is None:
            raise HostExecutionDenied("host:lean_inline_required")
        return self._prepare_captured_route(
            _data(binding), _data(certificate), object_route=object_route
        )

    def _prepare_captured_route(
        self, binding: dict, certificate: dict, *, object_route: bool
    ) -> _PreparedLifecycleRoute:
        """Prepare data already detached by the controller's native-slot capture."""
        request = _encoded(
            {
                "protocol": _PROTOCOL,
                "kind": "object-route" if object_route else "route",
                "binding": binding,
                "certificate": certificate,
            }
        )
        if len(request) > _MAX_REQUEST:
            raise HostExecutionDenied("host:lean_protocol_shape")
        with self._stats_lock:
            handle = self._native_prepare(request, len(request))
            if handle:
                self._stats["prepared_routes"] += 1
        if not handle:
            raise HostExecutionDenied("host:lean_lifecycle_refused")
        return _PreparedLifecycleRoute(self, handle)

    def require_prepared(
        self, prepared: _PreparedLifecycleRoute, events: list, phase: str
    ) -> None:
        """Run the proved transition over fresh events and a parsed certificate."""
        if (
            type(self) is not LeanLifecycleChecker
            or type(prepared) is not _PreparedLifecycleRoute
            or prepared.checker is not self
            or type(phase) is not str
            or type(events) is not list
            or len(events) > 32
        ):
            raise HostExecutionDenied("host:lean_binary_configuration")
        self._require_prepared_captured(prepared, _data(events), phase)

    def _require_prepared_captured(
        self, prepared: _PreparedLifecycleRoute, events: list, phase: str
    ) -> None:
        """Check a controller-owned event trace without another object walk."""
        handle = prepared.handle
        if handle is None or self._native_check_prepared is None:
            raise HostExecutionDenied("host:lean_lifecycle_refused")
        request = _encoded(events)
        if len(request) > _MAX_REQUEST:
            raise HostExecutionDenied("host:lean_protocol_shape")
        output = ctypes.create_string_buffer(32)
        with self._stats_lock:
            self._stats["inline_calls"] += 1
            self._stats["prepared_calls"] += 1
            size = self._native_check_prepared(
                handle, request, len(request), output, len(output)
            )
        if size <= 0 or output.raw[:size] != phase.encode():
            raise HostExecutionDenied("host:lean_lifecycle_refused")

    def _free_route(self, handle: int) -> None:
        function = self._native_free_prepared
        if function is not None:
            with self._stats_lock:
                function(handle)

    def _require(self, payload: dict, phase: str) -> None:
        if type(self) is not LeanLifecycleChecker or type(phase) is not str:
            raise HostExecutionDenied("host:lean_binary_configuration")
        image = None
        try:
            image = self._image
        except AttributeError:
            pass
        if type(image) is not bytes or fcntl is None:
            raise HostExecutionDenied("host:lean_binary_configuration")
        request = _encoded(_data(payload)) + b"\n"
        if len(request) > _MAX_REQUEST:
            raise HostExecutionDenied("host:lean_protocol_shape")
        native = self._native_check
        if native is not None:
            with self._stats_lock:
                self._stats["inline_calls"] += 1
            output = ctypes.create_string_buffer(257)
            size = native(request, len(request), output, len(output))
            response = None
            if 0 < size <= 256:
                try:
                    response = json.loads(
                        output.raw[:size], object_pairs_hook=_response_pairs
                    )
                except (UnicodeError, ValueError, RecursionError):
                    pass
            if (
                type(response) is not dict
                or set(response) != {"protocol", "schema", "phase"}
                or type(response["protocol"]) is not str
                or response["protocol"] != _PROTOCOL
                or type(response["schema"]) is not int
                or response["schema"] != 3
                or type(response["phase"]) is not str
                or response["phase"] != phase
            ):
                raise HostExecutionDenied("host:lean_lifecycle_refused")
            return
        descriptor = None
        response = None
        with self._stats_lock:
            self._stats["subprocess_calls"] += 1
        try:
            with ExitStack() as snapshots:
                if sys.platform == "darwin":
                    executable = snapshots.enter_context(_macos_snapshot(image))
                else:
                    descriptor = _memfd()
                    with os.fdopen(descriptor, "wb", closefd=False) as target:
                        target.write(image)
                        target.flush()
                    # F_ADD_SEALS/F_GET_SEALS, then verify all immutable-file seals.
                    fcntl.fcntl(descriptor, 1033, 15)
                    if fcntl.fcntl(descriptor, 1034) & 15 != 15:
                        raise OSError("binary sealing unconfirmed")
                    executable = f"/proc/self/fd/{descriptor}"
                completed = subprocess.run(
                    [executable],
                    input=request,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(descriptor,) if descriptor is not None else (),
                    close_fds=True,
                    timeout=5,
                    check=False,
                    env={"LANG": "C", "LC_ALL": "C"},
                )
            if completed.returncode == 0 and len(completed.stdout) <= 256:
                response = json.loads(
                    completed.stdout, object_pairs_hook=_response_pairs
                )
        except (AttributeError, OSError, ValueError, subprocess.SubprocessError):
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if (
            type(response) is not dict
            or set(response) != {"protocol", "schema", "phase"}
            or type(response["protocol"]) is not str
            or response["protocol"] != _PROTOCOL
            or type(response["schema"]) is not int
            or response["schema"] != 3
            or type(response["phase"]) is not str
            or response["phase"] != phase
        ):
            raise HostExecutionDenied("host:lean_lifecycle_refused")


class _PreparedLifecycleRoute:
    """One native Lean value owned by exactly one lifecycle session."""

    __slots__ = ("checker", "handle")

    def __init__(self, checker: LeanLifecycleChecker, handle: int) -> None:
        self.checker = checker
        self.handle = handle

    def close(self) -> None:
        handle = self.handle
        if handle is not None:
            self.handle = None
            self.checker._free_route(handle)

    def __del__(self) -> None:
        self.close()


class LeanLifecycleSession:
    """Controller-owned trace; a refused transition permanently closes it."""

    __slots__ = (
        "_checker",
        "_binding",
        "_certificate",
        "_events",
        "_failed",
        "_object_route",
        "_prepared",
    )

    def __init__(
        self,
        checker: LeanLifecycleChecker,
        binding: dict,
        certificate: dict,
        *,
        object_route: bool = False,
    ) -> None:
        if type(checker) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        self._checker = checker
        binding = _data(binding)
        certificate = _data(certificate)
        self._binding = binding
        self._certificate = certificate
        self._events = []
        self._failed = False
        self._object_route = object_route
        self._prepared = (
            checker._prepare_captured_route(
                binding, certificate, object_route=object_route
            )
            if checker.inline
            else None
        )

    @classmethod
    def _from_captured(
        cls,
        checker: LeanLifecycleChecker,
        binding: dict,
        certificate: dict,
        *,
        object_route: bool = False,
    ) -> LeanLifecycleSession:
        """Bind controller-captured data without another recursive copy."""
        if (
            cls is not LeanLifecycleSession
            or type(checker) is not LeanLifecycleChecker
            or type(binding) is not dict
            or type(certificate) is not dict
        ):
            raise HostExecutionDenied("host:lean_binary_configuration")
        session = object.__new__(cls)
        session._checker = checker
        session._binding = binding
        session._certificate = certificate
        session._events = []
        session._failed = False
        session._object_route = object_route
        session._prepared = (
            checker._prepare_captured_route(
                binding, certificate, object_route=object_route
            )
            if checker.inline
            else None
        )
        return session

    def permit_go(self, observed: dict, *, supported: bool) -> None:
        """Called only after grant negotiation and receipt validation succeed."""
        self._advance(
            [
                {"kind": "authorize", "binding": observed, "authorized": True},
                {
                    "kind": "activate",
                    "binding": observed,
                    "supported": supported,
                    "confirmed": True,
                },
                {"kind": "go", "binding": observed},
            ],
            "running",
        )

    def permit_success(self, observed: dict) -> None:
        """Called only after a valid result and confirmed cleanup return."""
        self._advance(
            [
                {"kind": "result", "binding": observed, "accepted": True},
                {"kind": "cleanup", "confirmed": True},
            ],
            "ready",
        )

    def _advance(self, events: list[dict], phase: str) -> None:
        if self._failed:
            raise HostExecutionDenied("host:lean_lifecycle_refused")
        try:
            candidate = self._events + _data(events)
            if self._prepared is not None:
                self._checker._require_prepared_captured(
                    self._prepared, candidate, phase
                )
            else:
                self._checker.require(
                    _data(self._binding),
                    _data(candidate),
                    phase,
                    certificate=_data(self._certificate),
                    **({"object_route": True} if self._object_route else {}),
                )
            self._events = candidate
            if phase == "ready" and self._prepared is not None:
                self._prepared.close()
        except BaseException:
            self._failed = True
            if self._prepared is not None:
                self._prepared.close()
            raise
