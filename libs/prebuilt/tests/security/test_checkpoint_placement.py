from __future__ import annotations

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from langgraph.prebuilt.security import Principal, SecurityConfig, with_principal
from langgraph.prebuilt.security.checkpoint_security import MediatedCheckpointer
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.objects import StateOperation
from langgraph.prebuilt.security.types import Decision, Verdict


class CheckpointState(TypedDict):
    value: int


def increment(state: CheckpointState) -> CheckpointState:
    return {"value": state["value"] + 1}


def _config(user: str = "alice") -> RunnableConfig:
    return with_principal(
        {"configurable": {"thread_id": "thread-1"}},
        Principal(user, frozenset({"user"}), frozenset(), "session-1"),
    )


def _graph(saver: InMemorySaver, *modules: SecurityModule):
    builder = StateGraph(CheckpointState)
    builder.add_node("increment", increment)
    builder.add_edge(START, "increment")
    builder.add_edge("increment", END)
    return builder.compile(
        checkpointer=saver,
        security=SecurityConfig(checkpoint_key=b"checkpoint-test-key", modules=modules),
    )


class RewriteCheckpoint(SecurityModule):
    name = "rewrite_checkpoint"

    def state_write(self, principal, request):
        if request.operation is StateOperation.CHECKPOINT_WRITE and isinstance(
            request.value, dict
        ):
            return Decision(
                Verdict.TRANSFORM,
                "test:rewrite_checkpoint",
                new_args={"value": {**request.value, "authorized": True}},
            )
        return Decision(Verdict.ALLOW, "test:allow")


class DenyCheckpointHistory(SecurityModule):
    name = "deny_checkpoint_history"

    def state_read(self, principal, request):
        if request.operation is StateOperation.CHECKPOINT_READ:
            return Decision(Verdict.DENY, "test:no_checkpoint_history")
        return Decision(Verdict.ALLOW, "test:allow")


class DenyCheckpointData(SecurityModule):
    name = "deny_checkpoint_data"

    def state_read(self, principal, request):
        if (
            request.operation is StateOperation.CHECKPOINT_READ
            and isinstance(request.value, dict)
            and "id" in request.value
        ):
            return Decision(Verdict.DENY, "test:no_checkpoint_data")
        return Decision(Verdict.ALLOW, "test:allow")


class RewriteCheckpointData(SecurityModule):
    name = "rewrite_checkpoint_data"

    def state_read(self, principal, request):
        if (
            request.operation is StateOperation.CHECKPOINT_READ
            and isinstance(request.value, dict)
            and "id" in request.value
        ):
            return Decision(
                Verdict.TRANSFORM,
                "test:rewrite_checkpoint_data",
                new_args={"value": {**request.value, "authorized": True}},
            )
        return Decision(Verdict.ALLOW, "test:allow")


async def _history(checkpointer, config, asynchronous: bool):
    if asynchronous:
        return [value async for value in checkpointer.alist(config)]
    return list(checkpointer.list(config))


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_graph_checkpoint_restore_is_hash_chained_and_principal_bound(
    asynchronous: bool,
) -> None:
    saver = InMemorySaver()
    graph = _graph(saver)

    result = (
        await graph.ainvoke({"value": 1}, _config())
        if asynchronous
        else graph.invoke({"value": 1}, _config())
    )
    assert result["value"] == 2
    assert isinstance(graph.checkpointer, MediatedCheckpointer)
    latest = saver.get_tuple(_config())
    assert latest is not None
    security = latest.metadata["__slanggraph_security__"]
    assert security["principal_id"] == "alice"
    assert security["digest"]

    with pytest.raises(PermissionError, match="checkpoint:principal_mismatch"):
        if asynchronous:
            await graph.checkpointer.aget_tuple(_config("bob"))
        else:
            graph.checkpointer.get_tuple(_config("bob"))


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_tampered_checkpoint_is_refused_before_state_restore(
    asynchronous: bool,
) -> None:
    saver = InMemorySaver()
    graph = _graph(saver)
    if asynchronous:
        await graph.ainvoke({"value": 1}, _config())
    else:
        graph.invoke({"value": 1}, _config())
    latest = saver.get_tuple(_config())
    assert latest is not None
    version = latest.checkpoint["channel_versions"]["value"]
    saver.blobs[("thread-1", "", "value", version)] = saver.serde.dumps_typed(999)

    with pytest.raises(PermissionError, match="checkpoint:invalid_hash"):
        if asynchronous:
            await graph.checkpointer.aget_tuple(_config())
        else:
            graph.checkpointer.get_tuple(_config())


def test_replayed_checkpoint_is_refused() -> None:
    saver = InMemorySaver()
    graph = _graph(saver)
    graph.invoke({"value": 1}, _config())

    assert graph.checkpointer.get_tuple(_config()) is not None
    with pytest.raises(PermissionError, match="checkpoint:replay"):
        graph.checkpointer.get_tuple(_config())


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_graph_can_continue_from_checkpoint_tip_issued_by_same_host(
    asynchronous: bool,
) -> None:
    graph = _graph(InMemorySaver())
    config = _config()

    if asynchronous:
        first = await graph.ainvoke({"value": 1}, config)
        second = await graph.ainvoke({"value": first["value"]}, config)
    else:
        first = graph.invoke({"value": 1}, config)
        second = graph.invoke({"value": first["value"]}, config)

    assert first["value"] == 2
    assert second["value"] == 3


def test_checkpoint_write_uses_effective_authorized_value() -> None:
    saver = InMemorySaver()
    builder = StateGraph(CheckpointState)
    builder.add_node("increment", increment)
    builder.add_edge(START, "increment")
    builder.add_edge("increment", END)
    graph = builder.compile(
        checkpointer=saver,
        security=SecurityConfig(
            checkpoint_key=b"checkpoint-test-key",
            modules=(RewriteCheckpoint(),),
        ),
    )

    graph.invoke({"value": 1}, _config())

    latest = saver.get_tuple(_config())
    assert latest is not None
    assert latest.checkpoint["authorized"] is True  # type: ignore[typeddict-item]


def test_checkpoint_history_and_administration_fail_closed() -> None:
    saver = InMemorySaver()
    builder = StateGraph(CheckpointState)
    builder.add_node("increment", increment)
    builder.add_edge(START, "increment")
    builder.add_edge("increment", END)
    graph = builder.compile(
        checkpointer=saver,
        security=SecurityConfig(
            checkpoint_key=b"checkpoint-test-key",
            modules=(DenyCheckpointHistory(),),
        ),
    )
    graph.invoke({"value": 1}, _config())

    with pytest.raises(PermissionError, match="test:no_checkpoint_history"):
        next(graph.checkpointer.list(_config()))
    with pytest.raises(
        PermissionError, match="administrative_operation_requires_principal"
    ):
        graph.checkpointer.delete_thread("thread-1")


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_checkpoint_history_publishes_only_effective_authorized_values(
    asynchronous: bool,
) -> None:
    saver = InMemorySaver()
    graph = _graph(saver, RewriteCheckpointData())
    if asynchronous:
        await graph.ainvoke({"value": 1}, _config())
    else:
        graph.invoke({"value": 1}, _config())

    history = await _history(graph.checkpointer, _config(), asynchronous)
    assert history
    assert all(value.checkpoint["authorized"] is True for value in history)
    raw = next(saver.list(_config()))
    assert "authorized" not in raw.checkpoint


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_checkpoint_history_rejects_denied_and_mismatched_identity(
    asynchronous: bool,
) -> None:
    denied_saver = InMemorySaver()
    denied_graph = _graph(denied_saver, DenyCheckpointData())
    if asynchronous:
        await denied_graph.ainvoke({"value": 1}, _config())
    else:
        denied_graph.invoke({"value": 1}, _config())
    with pytest.raises(PermissionError, match="test:no_checkpoint_data"):
        await _history(denied_graph.checkpointer, _config(), asynchronous)

    saver = InMemorySaver()
    graph = _graph(saver)
    if asynchronous:
        await graph.ainvoke({"value": 1}, _config())
    else:
        graph.invoke({"value": 1}, _config())
    with pytest.raises(PermissionError, match="checkpoint:principal_mismatch"):
        await _history(graph.checkpointer, _config("bob"), asynchronous)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_checkpoint_history_rejects_unauthenticated_data_without_replay(
    asynchronous: bool,
) -> None:
    saver = InMemorySaver()
    graph = _graph(saver)
    if asynchronous:
        await graph.ainvoke({"value": 1}, _config())
    else:
        graph.invoke({"value": 1}, _config())

    first = await _history(graph.checkpointer, _config(), asynchronous)
    second = await _history(graph.checkpointer, _config(), asynchronous)
    assert [value.checkpoint["id"] for value in first] == [
        value.checkpoint["id"] for value in second
    ]
    restored = (
        await graph.checkpointer.aget_tuple(_config())
        if asynchronous
        else graph.checkpointer.get_tuple(_config())
    )
    assert restored is not None

    latest = saver.get_tuple(_config())
    assert latest is not None
    version = latest.checkpoint["channel_versions"]["value"]
    saver.blobs[("thread-1", "", "value", version)] = saver.serde.dumps_typed(999)
    with pytest.raises(PermissionError, match="checkpoint:invalid_hash"):
        await _history(graph.checkpointer, _config(), asynchronous)


def test_pending_writes_are_authenticated_and_witness_is_not_exposed() -> None:
    saver = InMemorySaver()
    graph = _graph(saver)
    graph.invoke({"value": 1}, _config())
    latest = saver.get_tuple(_config())
    assert latest is not None
    secured_config = with_principal(latest.config, _principal_for_test())

    graph.checkpointer.put_writes(
        secured_config,
        (("result", {"safe": True}),),
        "task-1",
    )
    restored = graph.checkpointer.get_tuple(secured_config)
    assert restored is not None
    assert restored.pending_writes == [("task-1", "result", {"safe": True})]

    outer_key = ("thread-1", "", latest.checkpoint["id"])
    raw_writes = saver.writes[outer_key]
    result_key = next(key for key, item in raw_writes.items() if item[1] == "result")
    task_id, channel, _, task_path = raw_writes[result_key]
    raw_writes[result_key] = (
        task_id,
        channel,
        saver.serde.dumps_typed({"safe": False}),
        task_path,
    )

    with pytest.raises(PermissionError, match="checkpoint:invalid_write_witness"):
        graph.checkpointer.get_tuple(secured_config)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_checkpoint_history_authenticates_pending_writes(
    asynchronous: bool,
) -> None:
    saver = InMemorySaver()
    graph = _graph(saver)
    if asynchronous:
        await graph.ainvoke({"value": 1}, _config())
    else:
        graph.invoke({"value": 1}, _config())
    latest = saver.get_tuple(_config())
    assert latest is not None
    secured_config = with_principal(latest.config, _principal_for_test())

    if asynchronous:
        await graph.checkpointer.aput_writes(
            secured_config, (("result", {"safe": True}),), "task-1"
        )
    else:
        graph.checkpointer.put_writes(
            secured_config, (("result", {"safe": True}),), "task-1"
        )
    history = await _history(graph.checkpointer, _config(), asynchronous)
    with_writes = next(value for value in history if value.pending_writes)
    assert with_writes.pending_writes == [("task-1", "result", {"safe": True})]

    outer_key = ("thread-1", "", latest.checkpoint["id"])
    raw_writes = saver.writes[outer_key]
    result_key = next(key for key, item in raw_writes.items() if item[1] == "result")
    task_id, channel, _, task_path = raw_writes[result_key]
    raw_writes[result_key] = (
        task_id,
        channel,
        saver.serde.dumps_typed({"safe": False}),
        task_path,
    )
    with pytest.raises(PermissionError, match="checkpoint:invalid_write_witness"):
        await _history(graph.checkpointer, _config(), asynchronous)


def _principal_for_test() -> Principal:
    return Principal("alice", frozenset({"user"}), frozenset(), "session-1")
