"""Bridge to the executable Lean worker-lifecycle decision core.

The operator pins a built binary. Its bytes are captured once and executed from
a sealed Linux memfd; there is no Python decision fallback. Lean proves the core
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
from dataclasses import dataclass, field
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


def _capture_certificate(plan: Any, receipt: Any, plan_digest: Any) -> dict:
    # Charge projected strings/arrays as they are inspected so an oversized
    # early row stops capture before later rows. _data below also accounts for
    # all fixed keys and punctuation in the complete detached certificate.
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
    return _data(
        {
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
    )


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
    An executable uses the legacy sealed subprocess protocol. A `.so` library
    and its pinned generated-code runtime are loaded from sealed memfds once and
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

    def __post_init__(self) -> None:
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
        if self.binary_path.endswith(".so"):
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
        elif self.runtime_path is not None or self.runtime_sha256 is not None:
            raise HostExecutionDenied("host:lean_native_runtime_configuration")

    def require(
        self, binding: dict, events: list, phase: str, *, certificate: dict
    ) -> None:
        """Require the compiled core's exact phase for this captured trace."""
        if type(self) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        if type(events) is not list or len(events) > 32:
            raise HostExecutionDenied("host:lean_protocol_shape")
        self._require(
            {
                "protocol": _PROTOCOL,
                "kind": "route",
                "binding": binding,
                "certificate": certificate,
                "events": events,
            },
            phase,
        )

    def require_grant(self, grant: dict, obligations: list) -> None:
        """Require canonical grant generation before negotiation/activation."""
        if type(self) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        self._require(
            {
                "protocol": _PROTOCOL,
                "kind": "grant",
                "grant": grant,
                "obligations": obligations,
            },
            "grant_ready",
        )

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
        try:
            descriptor = _memfd()
            with os.fdopen(descriptor, "wb", closefd=False) as target:
                target.write(image)
                target.flush()
            # F_ADD_SEALS/F_GET_SEALS and all four immutable-file seals from
            # linux/fcntl.h. Check the installed seals before executing bytes.
            fcntl.fcntl(descriptor, 1033, 15)
            if fcntl.fcntl(descriptor, 1034) & 15 != 15:
                raise OSError("binary sealing unconfirmed")
            completed = subprocess.run(
                [f"/proc/self/fd/{descriptor}"],
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(descriptor,),
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


class LeanLifecycleSession:
    """Controller-owned trace; a refused transition permanently closes it."""

    __slots__ = ("_checker", "_binding", "_certificate", "_events", "_failed")

    def __init__(
        self, checker: LeanLifecycleChecker, binding: dict, certificate: dict
    ) -> None:
        if type(checker) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        self._checker = checker
        self._binding = _encoded(_data(binding))
        self._certificate = _encoded(_data(certificate))
        self._events = b"[]"
        self._failed = False

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
            candidate = json.loads(self._events) + _data(events)
            captured = _encoded(candidate)
            self._checker.require(
                json.loads(self._binding),
                candidate,
                phase,
                certificate=json.loads(self._certificate),
            )
            self._events = captured
        except BaseException:
            self._failed = True
            raise
