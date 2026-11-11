"""Computation must not imply authority, including on repeated execution."""

import ast
import asyncio
import importlib.util
from inspect import Signature
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    HostExecutionDenied,
    Principal,
    SecurityConfigurationError,
    cedar_security,
    with_principal,
)
from langgraph.prebuilt.security._language_sandbox import LanguageProgram
from langgraph.prebuilt.security.inprocess import read_text
from langgraph.prebuilt.security.language_verification import TerminalContract
from tests.security.test_manifest_consistency import check as check_manifest
from tests.security.test_object_policy import _fake_cedar


def lower(source, terminal=None):
    terminals = {"read_text": terminal} if terminal is not None else {}
    contracts = (
        {"read_text": TerminalContract((("path", "str"),), frozenset({"str"}))}
        if terminals
        else {}
    )
    return LanguageProgram.lower(
        ast.parse(source).body[0], terminals, (), {}, contracts=contracts
    )


def test_input_dependent_while_is_not_statically_unrolled_or_capped():
    program = lower("""def total(count):
    n = int(count)
    i = 0
    total = 0
    while i < n:
        total += i
        i += 1
    return str(total)
""")
    assert program.invoke({"count": "10001"}) == str(sum(range(10001)))
    assert program.proof()["effects"] == []


def test_every_iteration_calls_the_captured_terminal():
    calls = []

    def terminal(path):
        calls.append(path)
        if len(calls) == 3:
            raise HostExecutionDenied("test:revoked")
        return "ok"

    program = lower(
        """def repeat(path, count):
    n = int(count)
    i = 0
    result = ''
    while i < n:
        result = read_text(path)
        i += 1
    return result
""",
        terminal,
    )
    with pytest.raises(HostExecutionDenied, match="revoked"):
        program.invoke({"path": "alice", "count": "5"})
    assert calls == ["alice"] * 3
    assert program.proof()["effects"] == ["read_text"]


@pytest.mark.parametrize("count,expected", [("0", "empty"), ("2", "inside")])
def test_while_else_and_return(count, expected):
    program = lower("""def select(count):
    i = 0
    while i < int(count):
        return 'inside'
    else:
        return 'empty'
""")
    assert program.invoke({"count": count}) == expected


@pytest.mark.parametrize(
    "body",
    [
        "i = 'changed'",
        "if i < 1:\n            i = 'changed'\n            return i",
        "open(path)",
        "path.__class__",
        "import os",
    ],
)
def test_loop_cannot_hide_type_changes_or_unmediated_effects(body):
    with pytest.raises(SecurityConfigurationError):
        lower(
            f"def bad(path):\n    i = 0\n    while i < 2:\n        {body}\n        i += 1\n    return path\n"
        )


@tool
def repeated_reader(path: str, count: str) -> str:
    """Read a grant-bound file repeatedly using an input-dependent loop."""
    i = 0
    result = ""
    while i < int(count):
        result = read_text(path)
        i += 1
    return result


@tool
def infinite_computation(path: str) -> str:
    """A pure nonterminating computation that must remain cancellable."""
    while True:
        pass
    return path


def test_production_admission_accepts_loop_and_preserves_grant_check():
    config = cedar_security(
        repeated_reader,
        manifest="runs inprocess\nfs read @{path} need",
        policy="permit(principal, action, resource);",
    )
    admission = config.host_executor.dispatcher.admission
    assert admission.invoke({"path": "unused", "count": "0"}) == ""
    with pytest.raises(HostExecutionDenied, match="resource_not_granted"):
        admission.invoke({"path": "ungranted", "count": "1"})


async def test_cancel_infinite_loop_waits_for_interpreter_to_stop():
    config = cedar_security(
        infinite_computation,
        manifest="runs inprocess",
        policy="permit(principal, action, resource);",
    )
    admission = config.host_executor.dispatcher.admission
    task = asyncio.create_task(admission.ainvoke({"path": "unused"}))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)


@pytest.mark.parametrize("start,stop,step", [(0, 8, 1), (7, -2, -2), (3, 3, 1)])
def test_range_loop_uses_independent_iterator_state(start, stop, step):
    program = lower("""def total(start, stop, step):
    total = 0
    for i in range(int(start), int(stop), int(step)):
        total += i
        i = 999
    else:
        total += 10
    return str(total)
""")
    assert program.invoke(
        {"start": str(start), "stop": str(stop), "step": str(step)}
    ) == str(sum(range(start, stop, step)) + 10)


def test_zero_range_step_refuses_even_for_empty_range():
    program = lower("""def total():
    for i in range(0, 0, 0):
        pass
    return 'done'
""")
    with pytest.raises(HostExecutionDenied, match="invalid_pure_operation"):
        program.invoke({})


def test_nested_for_and_while_share_no_iterator_state():
    program = lower("""def count(text):
    total = 0
    for character in text:
        i = 0
        while i < 3:
            if character == 'x':
                total += 1
            i += 1
    return str(total)
""")
    assert program.invoke({"text": "xax"}) == "6"


def test_native_list_and_dictionary_computation_remains_inert():
    program = lower("""def collect(count):
    values = [int(count), 2, 3]
    result = {"first": values[0], "size": len(values)}
    return result
""")
    assert program.invoke({"count": "7"}) == {"first": 7, "size": 3}
    assert program.proof()["result_types"] == ["dict"]


def test_numeric_equality_is_available_to_loop_branches():
    program = lower("""def total(count):
    total = 0
    for i in range(int(count)):
        if i % 2 == 0:
            total += i
    return str(total)
""")
    assert program.invoke({"count": "8"}) == "12"


def test_stable_terminal_alias_is_lowered_but_rebinding_refuses():
    program = lower(
        """def f(path):
    reader = read_text
    return reader(path)
""",
        lambda path: "value:" + path,
    )
    assert program.invoke({"path": "allowed"}) == "value:allowed"
    assert program.proof()["effects"] == ["read_text"]
    with pytest.raises(SecurityConfigurationError, match="terminal_alias_reassigned"):
        lower(
            """def f(path):
    reader = read_text
    reader = str
    return reader(path)
""",
            lambda path: path,
        )


@tool
def line_count(path: str) -> str:
    """Count newline-delimited records after a mediated file read."""
    text = read_text(path)
    lines = 0
    for character in text:
        if character == "\n":
            lines += 1
    return str(lines)


def test_graph_runs_file_processing_in_language_route(tmp_path):
    path = tmp_path / "records.txt"
    path.write_text("alice\nbob\ncarol\n")
    security = cedar_security(
        line_count,
        manifest="runs inprocess\nfs read @{path} need",
        policy="permit(principal, action, resource);",
        executable=_fake_cedar(tmp_path),
    )
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode([line_count]))
    graph.add_edge(START, "tools")
    compiled = graph.compile(security=security)
    result = compiled.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "line_count",
                            "args": {"path": str(path)},
                            "id": "count",
                        }
                    ],
                )
            ]
        },
        with_principal(
            {},
            Principal("alice", frozenset(), frozenset(), "session"),
            modules=security.modules,
        ),
    )
    assert result["messages"][-1].content == "3"
    assert security.host_executor.dispatcher.admission.language_proofs()["func"][
        "effects"
    ] == ["read_text"]


def test_loop_carried_resource_selector_is_not_assumed_constant():
    source = """def reader(path):
    current = path
    i = 0
    while i < 2:
        storage.read(current)
        current = '/secret'
        i += 1
    return path
"""
    assert not check_manifest(source)["consistent"]


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "def f():\n    total = 0\n    for i in range(5):\n        if i < 2:\n            continue\n        total += i\n    else:\n        total += 100\n    return str(total)\n",
            "109",
        ),
        (
            "def f():\n    total = 0\n    for i in range(5):\n        if i > 2:\n            break\n        total += i\n    else:\n        total += 100\n    return str(total)\n",
            "3",
        ),
        (
            "def f():\n    n = 0\n    for i in range(3):\n        for j in range(3):\n            break\n        n += 1\n    return str(n)\n",
            "3",
        ),
    ],
)
def test_break_continue_and_else(source, expected):
    assert lower(source).invoke({}) == expected


@pytest.mark.parametrize("control", ["break", "continue"])
def test_forged_loop_control_outside_loop_refuses(control):
    with pytest.raises(SecurityConfigurationError, match="outside_loop"):
        LanguageProgram(((control,),), Signature(), {}, {}).proof()


def test_effect_projection_refuses_unknown_instructions():
    # The proof audit must never erase an instruction it cannot translate.
    path = Path(__file__).resolve().parents[4] / "proofs/language-route/check.py"
    spec = importlib.util.spec_from_file_location("loop_audit", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError, match="unprojectable"):
        module.effect_stmts((("unknown",),))


def test_loop_else_type_changes_are_included_in_following_call_check():
    with pytest.raises(SecurityConfigurationError, match="terminal_argument_type"):
        lower(
            "def f(path):\n    while False:\n        pass\n    else:\n        path = 7\n    return read_text(path)\n",
            lambda path: path,
        )


def test_loop_else_assignment_does_not_hide_break_path_type():
    with pytest.raises(SecurityConfigurationError, match="terminal_argument_type"):
        lower(
            "def f(path):\n    n = 0\n    while True:\n        break\n    else:\n        n = path\n    return read_text(n)\n",
            lambda path: path,
        )
