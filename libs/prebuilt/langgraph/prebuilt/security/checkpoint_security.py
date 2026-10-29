"""Principal-bound, hash-chained verification around any checkpointer."""

from __future__ import annotations

import builtins
import hashlib
import hmac
import json
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
)

from langgraph.prebuilt.security.binding import principal_from
from langgraph.prebuilt.security.host_router import HostRouter
from langgraph.prebuilt.security.object_manager import (
    authenticate_checkpoint,
    seal_checkpoint,
)
from langgraph.prebuilt.security.objects import StateOperation, StateRequest
from langgraph.prebuilt.security.types import Principal

_SECURITY_METADATA = "__slanggraph_security__"
_WRITE_WITNESS_CHANNEL = "__slanggraph_write_witness__"


class MediatedCheckpointer(BaseCheckpointSaver):
    """Authenticate checkpoint contents, ancestry, and principal on restore."""

    def __init__(
        self,
        inner: BaseCheckpointSaver,
        router: HostRouter,
        checkpoint_key: bytes,
        analysis: Any = None,
    ) -> None:
        super().__init__(serde=inner.serde)
        self.inner = inner
        self.router = router
        self.checkpoint_key = bytes(checkpoint_key)
        self.analysis = analysis

    @property
    def config_specs(self) -> builtins.list[Any]:
        return self.inner.config_specs

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        value = self.inner.get_tuple(config)
        return self._verify(config, value) if value is not None else None

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        value = await self.inner.aget_tuple(config)
        return await self._averify(config, value) if value is not None else None

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        if config is None:
            raise PermissionError("checkpoint:list_requires_principal")
        principal = _principal(config)
        effective = self.router.state(
            principal,
            StateRequest(
                StateOperation.CHECKPOINT_READ,
                _checkpoint_resource(config, "history"),
                principal.user_id,
                value={"filter": filter, "before": before, "limit": limit},
            ),
        )
        options = _checkpoint_options(effective)
        for value in self.inner.list(
            config,
            filter=options["filter"],
            before=options["before"],
            limit=options["limit"],
        ):
            yield self._verify_history(config, value)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        if config is None:
            raise PermissionError("checkpoint:list_requires_principal")
        principal = _principal(config)
        effective = await self.router.astate(
            principal,
            StateRequest(
                StateOperation.CHECKPOINT_READ,
                _checkpoint_resource(config, "history"),
                principal.user_id,
                value={"filter": filter, "before": before, "limit": limit},
            ),
        )
        options = _checkpoint_options(effective)
        async for value in self.inner.alist(
            config,
            filter=options["filter"],
            before=options["before"],
            limit=options["limit"],
        ):
            yield await self._averify_history(config, value)

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        principal = _principal(config)
        effective, secured = self._metadata(config, checkpoint, metadata, principal)
        return self.inner.put(config, effective, secured, new_versions)

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        principal = _principal(config)
        effective, secured = await self._ametadata(
            config, checkpoint, metadata, principal
        )
        return await self.inner.aput(config, effective, secured, new_versions)

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        principal = _principal(config)
        effective = self.router.state(
            principal,
            StateRequest(
                StateOperation.CHECKPOINT_WRITE,
                _checkpoint_resource(config, f"writes:{task_id}"),
                principal.user_id,
                value=tuple(writes),
            ),
        )
        authorized_writes = _checkpoint_writes(effective)
        witness = self._write_witness(config, authorized_writes, task_id, principal)
        self.inner.put_writes(
            config,
            (*authorized_writes, (_WRITE_WITNESS_CHANNEL, witness)),
            task_id,
            task_path,
        )

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        principal = _principal(config)
        effective = await self.router.astate(
            principal,
            StateRequest(
                StateOperation.CHECKPOINT_WRITE,
                _checkpoint_resource(config, f"writes:{task_id}"),
                principal.user_id,
                value=tuple(writes),
            ),
        )
        authorized_writes = _checkpoint_writes(effective)
        witness = self._write_witness(config, authorized_writes, task_id, principal)
        await self.inner.aput_writes(
            config,
            (*authorized_writes, (_WRITE_WITNESS_CHANNEL, witness)),
            task_id,
            task_path,
        )

    def delete_thread(self, thread_id: str) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    async def adelete_thread(self, thread_id: str) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    def delete_for_runs(self, run_ids: Sequence[str]) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    async def adelete_for_runs(self, run_ids: Sequence[str]) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    def copy_thread(self, source_thread_id: str, target_thread_id: str) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    async def acopy_thread(self, source_thread_id: str, target_thread_id: str) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    def prune(
        self, thread_ids: Sequence[str], *, strategy: str = "keep_latest"
    ) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    async def aprune(
        self, thread_ids: Sequence[str], *, strategy: str = "keep_latest"
    ) -> None:
        raise PermissionError("checkpoint:administrative_operation_requires_principal")

    def get_next_version(self, current: Any, channel: None) -> Any:
        return self.inner.get_next_version(current, channel)

    def _metadata(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        principal: Principal,
    ) -> tuple[Checkpoint, CheckpointMetadata]:
        predecessor = self.inner.get_tuple(config)
        previous_hash, sequence = _predecessor(predecessor)
        effective = _checkpoint(
            self.router.state(
                principal,
                StateRequest(
                    StateOperation.CHECKPOINT_WRITE,
                    _checkpoint_resource(config, checkpoint["id"]),
                    principal.user_id,
                    value=checkpoint,
                ),
            )
        )
        if self.analysis is not None:
            effective = dict(effective)
            effective["__slanggraph_analysis__"] = self._analysis_save(
                principal, effective["id"]
            )
        envelope = seal_checkpoint(
            self.checkpoint_key,
            checkpoint_id=effective["id"],
            principal=principal,
            sequence=sequence,
            previous_hash=previous_hash,
            payload=effective,
        )
        self.router.state(
            principal,
            StateRequest(
                StateOperation.CHECKPOINT_WRITE,
                f"checkpoint:{envelope.checkpoint_id}:issued",
                principal.user_id,
                value=envelope,
            ),
        )
        secured = dict(metadata)
        secured[_SECURITY_METADATA] = _envelope_metadata(envelope)  # type: ignore[typeddict-unknown-key]
        return effective, cast(CheckpointMetadata, secured)

    async def _ametadata(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        principal: Principal,
    ) -> tuple[Checkpoint, CheckpointMetadata]:
        predecessor = await self.inner.aget_tuple(config)
        previous_hash, sequence = _predecessor(predecessor)
        effective = _checkpoint(
            await self.router.astate(
                principal,
                StateRequest(
                    StateOperation.CHECKPOINT_WRITE,
                    _checkpoint_resource(config, checkpoint["id"]),
                    principal.user_id,
                    value=checkpoint,
                ),
            )
        )
        if self.analysis is not None:
            effective = dict(effective)
            effective["__slanggraph_analysis__"] = self._analysis_save(
                principal, effective["id"]
            )
        envelope = seal_checkpoint(
            self.checkpoint_key,
            checkpoint_id=effective["id"],
            principal=principal,
            sequence=sequence,
            previous_hash=previous_hash,
            payload=effective,
        )
        await self.router.astate(
            principal,
            StateRequest(
                StateOperation.CHECKPOINT_WRITE,
                f"checkpoint:{envelope.checkpoint_id}:issued",
                principal.user_id,
                value=envelope,
            ),
        )
        secured = dict(metadata)
        secured[_SECURITY_METADATA] = _envelope_metadata(envelope)  # type: ignore[typeddict-unknown-key]
        return effective, cast(CheckpointMetadata, secured)

    def _verify(
        self, config: RunnableConfig, value: CheckpointTuple
    ) -> CheckpointTuple:
        principal = _principal(config)
        value = self._verify_pending_writes(value, principal)
        envelope = _envelope(value, principal)
        if self.analysis is not None:
            authenticate_checkpoint(self.checkpoint_key, envelope, principal)
            self._analysis_restore(
                principal, envelope.payload.get("__slanggraph_analysis__")
            )
        effective = _checkpoint(
            self.router.state(
                principal,
                StateRequest(
                    StateOperation.RESTORE,
                    f"checkpoint:{envelope.checkpoint_id}",
                    principal.user_id,
                    value=envelope,
                ),
            )
        )
        return value._replace(checkpoint=effective)

    async def _averify(
        self, config: RunnableConfig, value: CheckpointTuple
    ) -> CheckpointTuple:
        principal = _principal(config)
        value = self._verify_pending_writes(value, principal)
        envelope = _envelope(value, principal)
        if self.analysis is not None:
            authenticate_checkpoint(self.checkpoint_key, envelope, principal)
            self._analysis_restore(
                principal, envelope.payload.get("__slanggraph_analysis__")
            )
        effective = _checkpoint(
            await self.router.astate(
                principal,
                StateRequest(
                    StateOperation.RESTORE,
                    f"checkpoint:{envelope.checkpoint_id}",
                    principal.user_id,
                    value=envelope,
                ),
            )
        )
        return value._replace(checkpoint=effective)

    def _verify_history(
        self, config: RunnableConfig, value: CheckpointTuple
    ) -> CheckpointTuple:
        principal = _principal(config)
        envelope = _envelope(value, principal)
        authenticate_checkpoint(self.checkpoint_key, envelope, principal)
        value = self._verify_pending_writes(value, principal)
        resource = _history_resource(config, value, envelope.checkpoint_id)
        effective = _history_checkpoint(
            self.router.state(
                principal,
                StateRequest(
                    StateOperation.CHECKPOINT_READ,
                    resource,
                    principal.user_id,
                    value=envelope.payload,
                ),
            ),
            envelope.checkpoint_id,
        )
        return value._replace(checkpoint=effective)

    async def _averify_history(
        self, config: RunnableConfig, value: CheckpointTuple
    ) -> CheckpointTuple:
        principal = _principal(config)
        envelope = _envelope(value, principal)
        authenticate_checkpoint(self.checkpoint_key, envelope, principal)
        value = self._verify_pending_writes(value, principal)
        resource = _history_resource(config, value, envelope.checkpoint_id)
        effective = _history_checkpoint(
            await self.router.astate(
                principal,
                StateRequest(
                    StateOperation.CHECKPOINT_READ,
                    resource,
                    principal.user_id,
                    value=envelope.payload,
                ),
            ),
            envelope.checkpoint_id,
        )
        return value._replace(checkpoint=effective)

    def _analysis_save(self, principal, checkpoint_id):
        from dataclasses import asdict

        from langgraph.prebuilt.analysis.provenance.checkpoint import CheckpointBinding

        refs = self.analysis.store.run_refs(
            self.analysis.tenant_id, self.analysis.run_id
        )
        binding = CheckpointBinding(
            self.analysis.store,
            self.checkpoint_key,
            self.analysis.config.policy_version,
        )
        return asdict(binding.save(principal, refs, checkpoint_id=checkpoint_id))

    def _analysis_restore(self, principal, data):
        from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
        from langgraph.prebuilt.analysis.provenance.checkpoint import CheckpointBinding
        from langgraph.prebuilt.security.object_manager import CheckpointEnvelope

        if not isinstance(data, dict):
            raise PermissionError("analysis:missing_checkpoint_metadata")
        envelope = CheckpointEnvelope(**data)
        binding = CheckpointBinding(
            self.analysis.store,
            self.checkpoint_key,
            self.analysis.config.policy_version,
        )
        refs = binding.restore(principal, envelope)
        BoundaryAdapter(self.analysis).value(
            {"checkpoint_id": envelope.checkpoint_id}, refs, "state.checkpoint.restore"
        )

    def _write_witness(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        principal: Principal,
    ) -> dict[str, Any]:
        checkpoint_id = _checkpoint_id(config)
        digest = self._pending_digest(
            checkpoint_id, task_id, writes, principal.user_id, principal.session_id
        )
        witness = {
            "checkpoint_id": checkpoint_id,
            "task_id": task_id,
            "principal_id": principal.user_id,
            "session_id": principal.session_id,
            "count": len(writes),
            "digest": digest,
        }

        if self.analysis is not None:
            witness["analysis"] = self._analysis_save(
                principal, f"{checkpoint_id}:writes:{task_id}"
            )
        return witness

    def _pending_digest(
        self,
        checkpoint_id: str,
        task_id: str,
        writes: Sequence[tuple[str, Any]],
        principal_id: str,
        session_id: str,
    ) -> str:
        mac = hmac.new(self.checkpoint_key, digestmod=hashlib.sha256)
        header = json.dumps(
            {
                "checkpoint_id": checkpoint_id,
                "principal_id": principal_id,
                "session_id": session_id,
                "task_id": task_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        mac.update(len(header).to_bytes(8, "big"))
        mac.update(header)
        for channel, item in writes:
            type_name, payload = self.serde.dumps_typed((channel, item))
            encoded_type = type_name.encode()
            mac.update(len(encoded_type).to_bytes(8, "big"))
            mac.update(encoded_type)
            mac.update(len(payload).to_bytes(8, "big"))
            mac.update(payload)
        return mac.hexdigest()

    def _verify_pending_writes(
        self, value: CheckpointTuple, principal: Principal
    ) -> CheckpointTuple:
        pending = value.pending_writes or []
        if not pending:
            return value
        writes_by_task: dict[str, list[tuple[str, Any]]] = {}
        witnesses: dict[str, dict[str, Any]] = {}
        visible = []
        for task_id, channel, item in pending:
            if channel == _WRITE_WITNESS_CHANNEL:
                if not isinstance(item, dict):
                    raise PermissionError("checkpoint:malformed_write_witness")
                witnessed_task = item.get("task_id")
                if (
                    not isinstance(witnessed_task, str)
                    or witnessed_task != task_id
                    or witnessed_task in witnesses
                ):
                    raise PermissionError("checkpoint:malformed_write_witness")
                witnesses[witnessed_task] = item
                continue
            visible.append((task_id, channel, item))
            writes_by_task.setdefault(task_id, []).append((channel, item))
        if set(writes_by_task) != set(witnesses):
            raise PermissionError("checkpoint:unverifiable_pending_writes")
        checkpoint_id = value.checkpoint["id"]
        for task_id, writes in writes_by_task.items():
            witness = witnesses[task_id]
            if (
                witness.get("checkpoint_id") != checkpoint_id
                or witness.get("principal_id") != principal.user_id
                or witness.get("session_id") != principal.session_id
                or witness.get("count") != len(writes)
            ):
                raise PermissionError("checkpoint:invalid_write_witness")
            expected = self._pending_digest(
                checkpoint_id,
                task_id,
                writes,
                principal.user_id,
                principal.session_id,
            )
            digest = witness.get("digest")
            if not isinstance(digest, str) or not hmac.compare_digest(expected, digest):
                raise PermissionError("checkpoint:invalid_write_witness")
            if self.analysis is not None:
                data = witness.get("analysis")
                if (
                    not isinstance(data, dict)
                    or data.get("checkpoint_id") != f"{checkpoint_id}:writes:{task_id}"
                ):
                    raise PermissionError("analysis:missing_write_metadata")
                self._analysis_restore(principal, data)
        return value._replace(pending_writes=visible)


def _principal(config: RunnableConfig) -> Principal:
    principal = principal_from(config)
    if principal is None:
        raise PermissionError("checkpoint:missing_principal")
    return principal


def _checkpoint_id(config: RunnableConfig) -> str:
    configurable = config.get("configurable")
    checkpoint_id = (
        configurable.get("checkpoint_id") if isinstance(configurable, dict) else None
    )
    if not isinstance(checkpoint_id, str) or not checkpoint_id:
        raise PermissionError("checkpoint:missing_checkpoint_id")
    return checkpoint_id


def _checkpoint_resource(config: RunnableConfig, suffix: str) -> str:
    return f"checkpoint:{_thread_id(config)}:{suffix}"


def _thread_id(config: RunnableConfig) -> str:
    configurable = config.get("configurable")
    thread_id = (
        configurable.get("thread_id") if isinstance(configurable, dict) else None
    )
    if not isinstance(thread_id, str) or not thread_id:
        raise PermissionError("checkpoint:missing_thread_id")
    return thread_id


def _checkpoint(value: Any) -> Checkpoint:
    if not isinstance(value, dict):
        raise PermissionError("checkpoint:invalid_effective_value")
    checkpoint_id = value.get("id")
    if not isinstance(checkpoint_id, str) or not checkpoint_id:
        raise PermissionError("checkpoint:invalid_effective_value")
    return cast(Checkpoint, value)


def _history_checkpoint(value: Any, checkpoint_id: str) -> Checkpoint:
    effective = _checkpoint(value)
    if effective["id"] != checkpoint_id:
        raise PermissionError("checkpoint:history_identity_mismatch")
    return effective


def _history_resource(
    config: RunnableConfig, value: CheckpointTuple, checkpoint_id: str
) -> str:
    requested_thread = _thread_id(config)
    if _thread_id(value.config) != requested_thread:
        raise PermissionError("checkpoint:history_identity_mismatch")
    configurable = value.config.get("configurable")
    returned_id = (
        configurable.get("checkpoint_id") if isinstance(configurable, dict) else None
    )
    if returned_id != checkpoint_id:
        raise PermissionError("checkpoint:history_identity_mismatch")
    return f"checkpoint:{requested_thread}:{checkpoint_id}"


def _checkpoint_options(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"filter", "before", "limit"}:
        raise PermissionError("checkpoint:invalid_effective_history_query")
    if value["filter"] is not None and not isinstance(value["filter"], dict):
        raise PermissionError("checkpoint:invalid_effective_history_query")
    if value["before"] is not None and not isinstance(value["before"], dict):
        raise PermissionError("checkpoint:invalid_effective_history_query")
    if value["limit"] is not None and (
        type(value["limit"]) is not int or value["limit"] < 0
    ):
        raise PermissionError("checkpoint:invalid_effective_history_query")
    return value


def _checkpoint_writes(value: Any) -> tuple[tuple[str, Any], ...]:
    if not isinstance(value, (tuple, list)):
        raise PermissionError("checkpoint:invalid_effective_writes")
    writes: list[tuple[str, Any]] = []
    for item in value:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
            or not isinstance(item[0], str)
            or item[0] == _WRITE_WITNESS_CHANNEL
        ):
            raise PermissionError("checkpoint:invalid_effective_writes")
        writes.append((item[0], item[1]))
    return tuple(writes)


def _predecessor(value: CheckpointTuple | None) -> tuple[str, int]:
    if value is None:
        return "", 0
    raw = value.metadata.get(_SECURITY_METADATA)
    if not isinstance(raw, dict):
        raise PermissionError("checkpoint:unverifiable_predecessor")
    digest = raw.get("digest")
    sequence = raw.get("sequence")
    if not isinstance(digest, str) or not digest or type(sequence) is not int:
        raise PermissionError("checkpoint:unverifiable_predecessor")
    return digest, sequence + 1


def _envelope(value: CheckpointTuple, principal: Principal):
    from langgraph.prebuilt.security.object_manager import CheckpointEnvelope

    raw = value.metadata.get(_SECURITY_METADATA)
    if not isinstance(raw, dict):
        raise PermissionError("checkpoint:missing_security_metadata")
    try:
        return CheckpointEnvelope(
            str(raw["checkpoint_id"]),
            str(raw["principal_id"]),
            str(raw["session_id"]),
            int(raw["sequence"]),
            str(raw["previous_hash"]),
            value.checkpoint,
            str(raw["digest"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PermissionError("checkpoint:malformed_security_metadata") from exc


def _envelope_metadata(envelope: Any) -> dict[str, Any]:
    return {
        "checkpoint_id": envelope.checkpoint_id,
        "digest": envelope.digest,
        "previous_hash": envelope.previous_hash,
        "principal_id": envelope.principal_id,
        "sequence": envelope.sequence,
        "session_id": envelope.session_id,
    }
