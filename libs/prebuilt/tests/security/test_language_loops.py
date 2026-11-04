"""Computation must not imply authority, including on repeated execution."""

import ast
import asyncio

import pytest
from langchain_core.tools import tool

from langgraph.prebuilt.security import HostExecutionDenied, SecurityConfigurationError, cedar_security
from langgraph.prebuilt.security._language_sandbox import LanguageProgram
from langgraph.prebuilt.security.inprocess import read_text
from langgraph.prebuilt.security.language_verification import TerminalContract


def lower(source, terminal=None):
    terminals = {"read_text": terminal} if terminal is not None else {}
    contracts = {"read_text": TerminalContract((("path", "str"),), frozenset({"str"}))} if terminals else {}
    return LanguageProgram.lower(ast.parse(source).body[0], terminals, (), {}, contracts=contracts)


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
    program = lower("""def repeat(path, count):
    n = int(count)
    i = 0
    result = ''
    while i < n:
        result = read_text(path)
        i += 1
    return result
""", terminal)
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


@pytest.mark.parametrize("body", [
    "i = 'changed'",
    "if i < 1:\n            i = 'changed'\n            return i",
    "open(path)",
    "path.__class__",
    "import os",
])
def test_loop_cannot_hide_type_changes_or_unmediated_effects(body):
    with pytest.raises(SecurityConfigurationError):
        lower(f"def bad(path):\n    i = 0\n    while i < 2:\n        {body}\n        i += 1\n    return path\n")


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
    config = cedar_security(repeated_reader, manifest="runs inprocess\nfs read @{path} need", policy="permit(principal, action, resource);")
    admission = config.host_executor.dispatcher.admission
    assert admission.invoke({"path": "unused", "count": "0"}) == ""
    with pytest.raises(HostExecutionDenied, match="resource_not_granted"):
        admission.invoke({"path": "ungranted", "count": "1"})


async def test_cancel_infinite_loop_waits_for_interpreter_to_stop():
    config = cedar_security(infinite_computation, manifest="runs inprocess", policy="permit(principal, action, resource);")
    admission = config.host_executor.dispatcher.admission
    task = asyncio.create_task(admission.ainvoke({"path": "unused"}))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)
