"""Trusted handlers and DAC for framework objects routed through HostRouter."""

from __future__ import annotations

import hashlib
import hmac
import json
from _thread import RLock as _NativeRLock
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.store.base import (
    BaseStore,
    GetOp,
    Item,
    ListNamespacesOp,
    PutOp,
    SearchOp,
)

from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionResult,
)
from langgraph.prebuilt.security.host_boundary import StackBoundaryPolicy, ToolOrigin
from langgraph.prebuilt.security.objects import (
    DispatchRequest,
    FrameworkRequest,
    LabeledValue,
    ModelInvocationRequest,
    OutputRequest,
    SecurityLabels,
    StateOperation,
    StateRequest,
    ToolRegistryRequest,
)
from langgraph.prebuilt.security.output_data import (
    OutputDataError,
    validate_output_data,
    validate_output_request,
    validate_security_labels,
)
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    PolicyConstraint,
    Principal,
    Tool,
    Verdict,
    _validate_principal,
)

_STORE_ENVELOPE_METADATA = "__slanggraph_security__"
_STORE_ENVELOPE_VALUE = "__slanggraph_value__"


@dataclass(frozen=True, slots=True)
class ToolObjectDac:
    """Constructive state authority for one declared tool."""

    readable_channels: frozenset[str] = frozenset()
    readable_store_keys: frozenset[str] = frozenset()
    writable_store_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for values in (
            self.readable_channels,
            self.readable_store_keys,
            self.writable_store_keys,
        ):
            if any(not value for value in values):
                raise ValueError("object DAC resources must be non-empty")
        object.__setattr__(self, "readable_channels", frozenset(self.readable_channels))
        object.__setattr__(
            self, "readable_store_keys", frozenset(self.readable_store_keys)
        )
        object.__setattr__(
            self, "writable_store_keys", frozenset(self.writable_store_keys)
        )


class ObjectManagerPolicy(StackBoundaryPolicy):
    """Apply constructive object DAC before restrict-only module hooks."""

    def __init__(
        self,
        stack: SecurityStack,
        object_dacs: Mapping[str, ToolObjectDac] | None = None,
        *,
        transitions: frozenset[tuple[str, str]] = frozenset(),
    ) -> None:
        super().__init__(stack, transitions)
        object.__setattr__(
            self, "object_dacs", MappingProxyType(dict(object_dacs or {}))
        )

    def object_permission(self, principal: Principal, request: FrameworkRequest):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = self.stack.object_permission(principal, request)
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    async def aobject_permission(self, principal: Principal, request: FrameworkRequest):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = await self.stack.aobject_permission(principal, request)
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    def object_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = self.stack.object_resume_permission(
                principal, request, approval
            )
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    async def aobject_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = await self.stack.aobject_resume_permission(
                principal, request, approval
            )
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    def _dac(self, request: FrameworkRequest) -> Decision | None:
        if not isinstance(request, StateRequest) or not request.tool_name:
            return None
        profile = self.object_dacs.get(request.tool_name, ToolObjectDac())
        if request.operation is StateOperation.TOOL_READ:
            allowed = request.resource in profile.readable_channels
        elif request.operation is StateOperation.STORE_READ:
            allowed = request.resource in profile.readable_store_keys
        elif request.operation is StateOperation.STORE_WRITE:
            allowed = request.resource in profile.writable_store_keys
        else:
            return None
        if allowed:
            return None
        return Decision(Verdict.DENY, "dac:object_not_granted")


@dataclass(frozen=True, slots=True)
class StoreResource:
    """Owned and labeled persistent value."""

    owner_id: str
    value: Any = field(compare=False, repr=False)
    labels: SecurityLabels = SecurityLabels()


@dataclass(frozen=True, slots=True)
class CheckpointEnvelope:
    """Principal-bound checkpoint with an authenticated predecessor link."""

    checkpoint_id: str
    principal_id: str
    session_id: str
    sequence: int
    previous_hash: str
    payload: Any = field(compare=False, repr=False)
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.checkpoint_id or not self.principal_id or not self.session_id:
            raise ValueError("checkpoint identity must be non-empty")
        if self.sequence < 0:
            raise ValueError("checkpoint sequence must be non-negative")


class ObjectManagerHost:
    """Trusted framework-object effects after HostRouter authorization."""

    __slots__ = ("_checkpoint_key", "_state", "_store", "_tools", "_restored", "_lock")

    def __init__(
        self,
        *,
        checkpoint_key: bytes,
        tools: Mapping[str, Tool] | None = None,
    ) -> None:
        if not checkpoint_key:
            raise ValueError("checkpoint_key must be non-empty")
        self._checkpoint_key = bytes(checkpoint_key)
        self._state: dict[tuple[str, str, str, str], LabeledValue] = {}
        self._store: dict[str, StoreResource] = {}
        self._tools: dict[str, Tool] = dict(tools or {})
        # restored sequence/digest followed by the latest locally issued
        # sequence/digest.  Tracking both lets a later invocation restore the
        # tip that this host sealed while still rejecting a second restore of
        # that tip as a replay.
        self._restored: dict[tuple[str, str], tuple[int, str, int, str]] = {}
        self._lock = RLock()

    def dispatch(self, principal: Principal, request: FrameworkRequest) -> object:
        """Apply exactly one already-authorized framework operation."""
        if (
            type(request) is not DispatchRequest
            and type(request) is not ToolRegistryRequest
            and type(request) is not StateRequest
            and type(request) is not ModelInvocationRequest
            and type(request) is not OutputRequest
        ):
            raise TypeError("unknown framework request")
        with self._lock:
            if isinstance(request, DispatchRequest):
                return request.child
            if isinstance(request, ToolRegistryRequest):
                exists = request.tool.name in self._tools
                if request.override != exists:
                    raise PermissionError("registry:override_mismatch")
                self._tools[request.tool.name] = request.tool
                return request.tool
            if isinstance(request, StateRequest):
                return self._state_operation(principal, request)
            if isinstance(request, ModelInvocationRequest):
                return request.context
            if isinstance(request, OutputRequest):
                validate_output_request(request)
                if not request.labels.confidentiality.issubset(request.clearance):
                    raise PermissionError("output:clearance")
                return request.content
        raise TypeError("unknown framework request")

    async def adispatch(
        self, principal: Principal, request: FrameworkRequest
    ) -> object:
        return self.dispatch(principal, request)

    def origin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: Any
    ) -> Decision:
        return Decision(Verdict.DENY, "host:tool_execution_unavailable")

    async def aorigin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: Any
    ) -> Decision:
        return self.origin_permission(origin, parent, child, call)

    def invoke(
        self,
        principal: Principal,
        call: Any,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    async def ainvoke(
        self,
        principal: Principal,
        call: Any,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    def invoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: Any,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    async def ainvoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: Any,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    def _state_operation(self, principal: Principal, request: StateRequest) -> object:
        state_key = _state_key(principal, request)
        if request.operation is StateOperation.WRITE:
            self._state[state_key] = LabeledValue(
                request.resource, request.value, request.labels
            )
            return request.value
        if request.operation in (StateOperation.TOOL_READ, StateOperation.MODEL_READ):
            stored = self._state.get(state_key)
            if stored is None:
                return request.value
            if not isinstance(stored, LabeledValue):
                return stored
            if request.operation is StateOperation.MODEL_READ:
                return stored
            return stored.value
        if request.operation is StateOperation.STORE_WRITE:
            existing = self._store.get(request.resource)
            if existing is not None and existing.owner_id != principal.user_id:
                raise PermissionError("store:owner_mismatch")
            if request.owner_id != principal.user_id:
                raise PermissionError("store:owner_mismatch")
            self._store[request.resource] = StoreResource(
                principal.user_id, request.value, request.labels
            )
            return request.value
        if request.operation is StateOperation.STORE_READ:
            sealed = request.metadata.get("store_envelope")
            if sealed is not None:
                authoritative = authenticate_store_resource(
                    self._checkpoint_key, request.resource, sealed
                )
                if (
                    authoritative.owner_id != principal.user_id
                    or request.owner_id != authoritative.owner_id
                ):
                    raise PermissionError("store:owner_mismatch")
                if request.labels != authoritative.labels:
                    raise PermissionError("store:label_mismatch")
                registered = self._store.get(request.resource)
                if registered is not None and registered != authoritative:
                    raise PermissionError("store:metadata_mismatch")
                return request.value
            resource = self._store.get(request.resource)
            if resource is None:
                if request.value is None:
                    return None
                raise PermissionError("store:unknown_resource")
            if (
                resource.owner_id != principal.user_id
                or request.owner_id != resource.owner_id
            ):
                raise PermissionError("store:owner_mismatch")
            if request.labels != resource.labels:
                raise PermissionError("store:label_mismatch")
            if request.metadata.get("preflight") is True:
                return None
            return resource.value
        if request.operation is StateOperation.RESTORE:
            if not isinstance(request.value, CheckpointEnvelope):
                raise PermissionError("checkpoint:malformed")
            self._verify_checkpoint(principal, request.value)
            return request.value.payload
        if request.operation is StateOperation.CHECKPOINT_WRITE and isinstance(
            request.value, CheckpointEnvelope
        ):
            self._register_checkpoint(principal, request.value)
            return request.value
        if request.operation in (
            StateOperation.CHECKPOINT_READ,
            StateOperation.CHECKPOINT_WRITE,
        ):
            return request.value
        raise PermissionError("state:unsupported_operation")

    def labels_for_output(self, principal: Principal, value: Any) -> SecurityLabels:
        """Admit output data and conservatively inherit named channel labels.

        Matching keys inherit labels without comparing arbitrary payload values.
        This does not infer provenance for renamed or otherwise derived data.
        """
        if type(self) is not ObjectManagerHost:
            raise OutputDataError("output_data:state_shape")
        _validate_principal(principal)
        channel_labels: dict[str, SecurityLabels] = {}
        try:
            lock = self._lock
            if type(lock) is not _NativeRLock:
                raise OutputDataError("output_data:state_shape")
            with lock:
                state = self._state
                if type(state) is not dict or len(state) > 100_000:
                    raise OutputDataError("output_data:state_shape")
                for key, stored in tuple(dict.items(state)):
                    if (
                        type(key) is not tuple
                        or len(key) != 4
                        or any(type(part) is not str for part in key)
                    ):
                        raise OutputDataError("output_data:state_key")
                    if key[:3] == (principal.user_id, principal.session_id, ""):
                        if type(stored) is not LabeledValue:
                            raise OutputDataError("output_data:state_value")
                        channel_labels[key[3]] = validate_security_labels(stored.labels)
                return validate_output_data(value, channel_labels=channel_labels)
        except AttributeError:
            pass
        # Missing native slots attach their receiver to AttributeError.obj.
        # Refuse outside the handler without retaining that exception chain.
        raise OutputDataError("output_data:state_shape")

    def _verify_checkpoint(
        self, principal: Principal, checkpoint: CheckpointEnvelope
    ) -> None:
        authenticate_checkpoint(self._checkpoint_key, checkpoint, principal)
        key = (principal.user_id, principal.session_id)
        prior = self._restored.get(key)
        if prior is not None:
            restored_sequence, restored_digest, issued_sequence, issued_digest = prior
            if checkpoint.sequence <= restored_sequence:
                raise PermissionError("checkpoint:replay")
            issued_tip = (
                checkpoint.sequence == issued_sequence
                and checkpoint.digest == issued_digest
            )
            direct_child = checkpoint.previous_hash == restored_digest
            if not issued_tip and not direct_child:
                raise PermissionError("checkpoint:broken_chain")
        elif checkpoint.sequence and not checkpoint.previous_hash:
            raise PermissionError("checkpoint:broken_chain")
        issued_sequence = prior[2] if prior is not None else checkpoint.sequence
        issued_digest = prior[3] if prior is not None else checkpoint.digest
        self._restored[key] = (
            checkpoint.sequence,
            checkpoint.digest,
            issued_sequence,
            issued_digest,
        )

    def _register_checkpoint(
        self, principal: Principal, checkpoint: CheckpointEnvelope
    ) -> None:
        authenticate_checkpoint(self._checkpoint_key, checkpoint, principal)
        key = (principal.user_id, principal.session_id)
        prior = self._restored.get(key)
        if prior is None:
            if checkpoint.sequence != 0 or checkpoint.previous_hash:
                raise PermissionError("checkpoint:broken_chain")
            self._restored[key] = (-1, "", checkpoint.sequence, checkpoint.digest)
            return
        restored_sequence, restored_digest, issued_sequence, issued_digest = prior
        if checkpoint.sequence != issued_sequence + 1:
            raise PermissionError("checkpoint:invalid_sequence")
        if checkpoint.previous_hash != issued_digest:
            raise PermissionError("checkpoint:broken_chain")
        self._restored[key] = (
            restored_sequence,
            restored_digest,
            checkpoint.sequence,
            checkpoint.digest,
        )


def seal_checkpoint(
    checkpoint_key: bytes,
    *,
    checkpoint_id: str,
    principal: Principal,
    sequence: int,
    previous_hash: str,
    payload: Any,
) -> CheckpointEnvelope:
    """Create a canonical authenticated checkpoint envelope."""
    unsigned = CheckpointEnvelope(
        checkpoint_id,
        principal.user_id,
        principal.session_id,
        sequence,
        previous_hash,
        payload,
    )
    return CheckpointEnvelope(
        unsigned.checkpoint_id,
        unsigned.principal_id,
        unsigned.session_id,
        unsigned.sequence,
        unsigned.previous_hash,
        unsigned.payload,
        _checkpoint_digest(checkpoint_key, unsigned),
    )


def authenticate_checkpoint(
    checkpoint_key: bytes,
    checkpoint: CheckpointEnvelope,
    principal: Principal,
) -> None:
    """Authenticate a checkpoint without consuming restore replay state."""
    if (
        checkpoint.principal_id != principal.user_id
        or checkpoint.session_id != principal.session_id
    ):
        raise PermissionError("checkpoint:principal_mismatch")
    expected = _checkpoint_digest(checkpoint_key, checkpoint)
    if not checkpoint.digest or not hmac.compare_digest(checkpoint.digest, expected):
        raise PermissionError("checkpoint:invalid_hash")


def _checkpoint_digest(key: bytes, checkpoint: CheckpointEnvelope) -> str:
    encoded = json.dumps(
        {
            "checkpoint_id": checkpoint.checkpoint_id,
            "payload_hash": hashlib.sha256(
                json.dumps(
                    checkpoint.payload,
                    sort_keys=True,
                    default=repr,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "previous_hash": checkpoint.previous_hash,
            "principal_id": checkpoint.principal_id,
            "sequence": checkpoint.sequence,
            "session_id": checkpoint.session_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def seal_store_resource(
    store_key: bytes, resource: str, value: StoreResource
) -> dict[str, Any]:
    """Encode owner, labels, and value in a key-bound authenticated envelope."""
    metadata = {
        "version": 1,
        "owner_id": value.owner_id,
        "confidentiality": sorted(value.labels.confidentiality),
        "integrity": value.labels.integrity,
    }
    metadata["digest"] = _store_resource_digest(
        store_key, resource, metadata, value.value
    )
    return {
        _STORE_ENVELOPE_METADATA: metadata,
        _STORE_ENVELOPE_VALUE: value.value,
    }


def authenticate_store_resource(
    store_key: bytes, resource: str, sealed: Any
) -> StoreResource:
    """Decode one backing-store value only after authenticating all metadata."""
    if not isinstance(sealed, Mapping) or set(sealed) != {
        _STORE_ENVELOPE_METADATA,
        _STORE_ENVELOPE_VALUE,
    }:
        raise PermissionError("store:unverifiable_resource")
    metadata = sealed[_STORE_ENVELOPE_METADATA]
    value = sealed[_STORE_ENVELOPE_VALUE]
    if not isinstance(metadata, Mapping) or set(metadata) != {
        "version",
        "owner_id",
        "confidentiality",
        "integrity",
        "digest",
    }:
        raise PermissionError("store:malformed_resource_metadata")
    owner_id = metadata["owner_id"]
    confidentiality = metadata["confidentiality"]
    integrity = metadata["integrity"]
    digest = metadata["digest"]
    if (
        metadata["version"] != 1
        or not isinstance(owner_id, str)
        or not owner_id
        or not isinstance(confidentiality, list)
        or not all(isinstance(label, str) and label for label in confidentiality)
        or len(confidentiality) != len(set(confidentiality))
        or not isinstance(integrity, str)
        or not integrity
        or not isinstance(digest, str)
    ):
        raise PermissionError("store:malformed_resource_metadata")
    expected = _store_resource_digest(store_key, resource, metadata, value)
    if not hmac.compare_digest(digest, expected):
        raise PermissionError("store:invalid_resource_authentication")
    return StoreResource(
        owner_id,
        value,
        SecurityLabels(frozenset(confidentiality), integrity),
    )


def _store_resource_digest(
    key: bytes, resource: str, metadata: Mapping[str, Any], value: Any
) -> str:
    encoded = json.dumps(
        {
            "domain": "slanggraph-store-resource-v1",
            "resource": resource,
            "owner_id": metadata["owner_id"],
            "confidentiality": metadata["confidentiality"],
            "integrity": metadata["integrity"],
            "value_hash": hashlib.sha256(
                json.dumps(
                    value,
                    sort_keys=True,
                    default=repr,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


class MediatedStore(BaseStore):
    """Exact-key store facade that authorizes every operation through HostRouter."""

    def __init__(
        self,
        store: BaseStore,
        *,
        router: Any,
        principal: Principal,
        tool_name: str,
        store_key: bytes,
    ) -> None:
        if not store_key:
            raise ValueError("store_key must be non-empty")
        self._store = store
        self._router = router
        self._principal = principal
        self._tool_name = tool_name
        self._store_key = bytes(store_key)
        self.supports_ttl = store.supports_ttl
        self.ttl_config = store.ttl_config

    def batch(self, ops):
        operations = tuple(ops)
        effective = tuple(
            self._authorize(operation, asynchronous=False) for operation in operations
        )
        results = self._store.batch(effective)
        return self._authorize_results(operations, results, asynchronous=False)

    async def abatch(self, ops):
        operations = tuple(ops)
        effective = [
            await self._authorize(operation, asynchronous=True)
            for operation in operations
        ]
        results = await self._store.abatch(tuple(effective))
        return await self._authorize_results(operations, results, asynchronous=True)

    def _authorize_results(
        self, operations: Sequence[Any], results: Sequence[Any], *, asynchronous: bool
    ):
        if len(operations) != len(results):
            raise PermissionError("store:result_count_mismatch")
        if asynchronous:
            return _authorize_store_results_async(
                operations,
                results,
                router=self._router,
                principal=self._principal,
                tool_name=self._tool_name,
                store_key=self._store_key,
            )
        return [
            _authorize_store_result(
                operation,
                result,
                router=self._router,
                principal=self._principal,
                tool_name=self._tool_name,
                store_key=self._store_key,
            )
            for operation, result in zip(operations, results, strict=True)
        ]

    def _authorize(self, operation: Any, *, asynchronous: bool):
        if isinstance(operation, GetOp):
            state_operation = StateOperation.STORE_READ
            resource = _store_resource(operation.namespace, operation.key)
            value = None
            metadata = {"preflight": True}
        elif isinstance(operation, PutOp):
            state_operation = StateOperation.STORE_WRITE
            resource = _store_resource(operation.namespace, operation.key)
            value = operation.value
            metadata = {}
        elif isinstance(operation, (SearchOp, ListNamespacesOp)):
            raise PermissionError("store:enumeration_not_granted")
        else:
            raise PermissionError("store:operation_not_granted")
        request = StateRequest(
            state_operation,
            resource,
            self._principal.user_id,
            tool_name=self._tool_name,
            value=value,
            metadata=metadata,
        )
        if asynchronous:
            return _aeffective_store_operation(
                operation,
                self._router.astate(self._principal, request),
                principal=self._principal,
                resource=resource,
                store_key=self._store_key,
            )
        return _effective_store_operation(
            operation,
            self._router.state(self._principal, request),
            principal=self._principal,
            resource=resource,
            store_key=self._store_key,
        )


def _effective_store_operation(
    operation: Any,
    routed: Any,
    *,
    principal: Principal,
    resource: str,
    store_key: bytes,
) -> Any:
    """Apply a narrowed write value; reads carry no value to transform."""
    if isinstance(operation, PutOp):
        if routed is None:
            return operation._replace(value=None)
        if not isinstance(routed, Mapping):
            raise PermissionError("store:invalid_effective_write_value")
        sealed = seal_store_resource(
            store_key,
            resource,
            StoreResource(principal.user_id, dict(routed)),
        )
        return operation._replace(value=sealed)
    return operation


async def _aeffective_store_operation(
    operation: Any,
    routed: Any,
    *,
    principal: Principal,
    resource: str,
    store_key: bytes,
) -> Any:
    return _effective_store_operation(
        operation,
        await routed,
        principal=principal,
        resource=resource,
        store_key=store_key,
    )


def _authorize_store_result(
    operation: Any,
    result: Any,
    *,
    router: Any,
    principal: Principal,
    tool_name: str,
    store_key: bytes,
) -> Any:
    if not isinstance(operation, GetOp):
        return result
    if result is None:
        return None
    if not isinstance(result, Item):
        raise PermissionError("store:invalid_read_result")
    if result.namespace != operation.namespace or result.key != operation.key:
        raise PermissionError("store:result_identity_mismatch")
    resource = _store_resource(result.namespace, result.key)
    authoritative = authenticate_store_resource(store_key, resource, result.value)
    effective = router.state(
        principal,
        StateRequest(
            StateOperation.STORE_READ,
            resource,
            authoritative.owner_id,
            tool_name=tool_name,
            labels=authoritative.labels,
            value=authoritative.value,
            metadata={"store_envelope": result.value},
        ),
    )
    return _effective_store_item(result, effective)


async def _authorize_store_results_async(
    operations: Sequence[Any],
    results: Sequence[Any],
    *,
    router: Any,
    principal: Principal,
    tool_name: str,
    store_key: bytes,
) -> list[Any]:
    authorized: list[Any] = []
    for operation, result in zip(operations, results, strict=True):
        if not isinstance(operation, GetOp) or result is None:
            authorized.append(result)
            continue
        if not isinstance(result, Item):
            raise PermissionError("store:invalid_read_result")
        if result.namespace != operation.namespace or result.key != operation.key:
            raise PermissionError("store:result_identity_mismatch")
        resource = _store_resource(result.namespace, result.key)
        authoritative = authenticate_store_resource(store_key, resource, result.value)
        effective = await router.astate(
            principal,
            StateRequest(
                StateOperation.STORE_READ,
                resource,
                authoritative.owner_id,
                tool_name=tool_name,
                labels=authoritative.labels,
                value=authoritative.value,
                metadata={"store_envelope": result.value},
            ),
        )
        authorized.append(_effective_store_item(result, effective))
    return authorized


def _effective_store_item(item: Item, effective: Any) -> Item:
    if not isinstance(effective, Mapping):
        raise PermissionError("store:invalid_effective_read_value")
    return Item(
        value=dict(effective),
        key=item.key,
        namespace=item.namespace,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def _state_key(
    principal: Principal, request: StateRequest
) -> tuple[str, str, str, str]:
    graph_id = request.metadata.get("graph_id", "")
    if not isinstance(graph_id, str):
        raise PermissionError("state:invalid_graph_identity")
    return (principal.user_id, principal.session_id, graph_id, request.resource)


def _store_resource(namespace: tuple[str, ...], key: str) -> str:
    return "/".join((*namespace, str(key)))
