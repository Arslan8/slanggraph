"""Python escape features must not reach the admitted execution language."""

import ast
import asyncio
import threading
from types import FunctionType

import pytest
from langchain_core.tools import StructuredTool

from langgraph.prebuilt.security import (
    HostExecutionDenied,
    SecurityConfigurationError,
    cedar_security,
)
from langgraph.prebuilt.security._language_sandbox import LanguageProgram
from langgraph.prebuilt.security.inprocess import read_text
from langgraph.prebuilt.security.language_verification import TerminalContract
from langgraph.prebuilt.security.object_policy import EnforcementKind
from tests.security.test_manifest_admission import (
    MANIFEST,
    PERMIT,
    constant_reader,
    raw_reader,
    reader,
)


@pytest.mark.parametrize("field", ["globals", "positional", "keywords", "constant"])
def test_function_metadata_refuses_foreign_protocols_before_source_comparison(
    monkeypatch, field
):
    calls = []

    class ForeignDict(dict):
        def __bool__(self):
            calls.append("truth")
            raise AssertionError("foreign metadata truth ran")

        def items(self):
            calls.append("items")
            raise AssertionError("foreign metadata items ran")

        def values(self):
            calls.append("values")
            raise AssertionError("foreign metadata values ran")

    class ForeignTuple(tuple):
        def __iter__(self):
            calls.append("iter")
            raise AssertionError("foreign metadata iteration ran")

    class ForeignConstant:
        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError("foreign constant equality ran")

    function = constant_reader.func
    if field == "globals":
        replacement = FunctionType(function.__code__, ForeignDict(function.__globals__))
        monkeypatch.setattr(constant_reader, "func", replacement)
    elif field == "positional":
        monkeypatch.setattr(function, "__defaults__", ForeignTuple(("default",)))
    elif field == "keywords":
        monkeypatch.setattr(function, "__kwdefaults__", ForeignDict(value="default"))
    else:
        constants = tuple(
            ForeignConstant() if type(value) is str else value
            for value in function.__code__.co_consts
        )
        monkeypatch.setattr(
            function, "__code__", function.__code__.replace(co_consts=constants)
        )
    with pytest.raises(SecurityConfigurationError):
        cedar_security(constant_reader, manifest=MANIFEST, policy=PERMIT)
    assert calls == []


def test_replaced_tool_callable_refuses_without_candidate_equality(monkeypatch):
    admission = cedar_security(
        constant_reader, manifest=MANIFEST, policy=PERMIT
    ).host_executor.dispatcher.admission
    calls = []

    class Foreign:
        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError("foreign callable equality ran")

    monkeypatch.setattr(constant_reader, "func", Foreign())
    with pytest.raises(HostExecutionDenied, match="tool_changed"):
        admission.invoke({"path": "ignored"})
    assert calls == []


def test_loaded_source_identity_includes_exception_table(monkeypatch):
    function = constant_reader.func
    if not hasattr(function.__code__, "co_exceptiontable"):
        pytest.skip("interpreter has no separate exception table")
    monkeypatch.setattr(
        function,
        "__code__",
        function.__code__.replace(co_exceptiontable=b"\x80\x01\x00\x00"),
    )
    with pytest.raises(SecurityConfigurationError, match="source does not match"):
        cedar_security(constant_reader, manifest=MANIFEST, policy=PERMIT)


@pytest.mark.parametrize(
    "body",
    [
        "return eval(path)",
        "exec(path)\n    return path",
        "import os\n    return os.getenv(path)",
        "from ctypes import CDLL\n    return path",
        "return __import__(path)",
        "return path.__class__.__mro__",
        'return getattr(path, "__class__")',
        "return globals()",
        "return locals()",
        "return (lambda: path)()",
        "reader.__code__ = path\n    return path",
        "global reader\n    reader = path\n    return path",
        "return privileged",
        'return compile(path, "x", "exec")',
        "return open(path)",
        'if path == "never":\n        import subprocess\n    return path',
    ],
)
def test_alternative_python_execution_paths_rejected(tmp_path, body):
    source = f'def candidate(path: str) -> str:\n    """Candidate body is never executed."""\n    {body}\n'
    file = tmp_path / "candidate.py"
    file.write_text(source)
    scope = {}
    # Test construction executes only the def statement, never the candidate body.
    exec(compile(source, str(file), "exec"), scope)
    candidate = StructuredTool.from_function(scope["candidate"])
    with pytest.raises(SecurityConfigurationError):
        cedar_security(candidate, policy=PERMIT)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("mutation", ["function", "code"])
async def test_post_validation_mutation_cannot_select_python_body(
    monkeypatch, asynchronous, mutation
):
    admission = cedar_security(
        constant_reader, manifest=MANIFEST, policy=PERMIT
    ).host_executor.dispatcher.admission
    original = admission.validate

    def change_after_check():
        original()
        if mutation == "function":
            monkeypatch.setattr(constant_reader, "func", raw_reader.func)
        else:
            monkeypatch.setattr(
                constant_reader.func, "__code__", raw_reader.func.__code__
            )

    monkeypatch.setattr(admission, "validate", change_after_check)
    result = (
        await admission.ainvoke({"path": "/must-not-read"})
        if asynchronous
        else admission.invoke({"path": "/must-not-read"})
    )
    assert result == "nothing"


def test_post_validation_monitor_code_mutation_cannot_bypass_grant(
    monkeypatch, tmp_path
):
    admission = cedar_security(
        reader, manifest=MANIFEST, policy=PERMIT
    ).host_executor.dispatcher.admission
    original = admission.validate

    def bypass(path):
        return "unmediated"

    def change_after_check():
        original()
        monkeypatch.setattr(read_text, "__code__", bypass.__code__)

    path = tmp_path / "file"
    path.write_text("private")
    monkeypatch.setattr(admission, "validate", change_after_check)
    with pytest.raises(HostExecutionDenied, match="resource_not_granted"):
        admission.invoke({"path": str(path)})


def test_privileged_terminal_result_is_rejected_without_object_protocols():
    class Privileged:
        def __str__(self):
            pytest.fail("privileged object protocol executed")

    entry = ast.parse("def tool(path): return terminal(path)").body[0]
    program = LanguageProgram.lower(
        entry,
        {"terminal": lambda path: Privileged()},
        (),
        {},
        contracts={
            "terminal": TerminalContract((("path", "str"),), frozenset({"str"}))
        },
    )
    with pytest.raises(HostExecutionDenied, match="non_data_result"):
        program.invoke({"path": "inert"})


def test_hostile_argument_mapping_is_not_executed():
    class Mapping(dict):
        def items(self):
            pytest.fail("hostile mapping executed")

    admission = cedar_security(
        constant_reader, policy=PERMIT
    ).host_executor.dispatcher.admission
    with pytest.raises(HostExecutionDenied, match="arguments_must_be_scalars"):
        admission.invoke(Mapping(path="inert"))


def test_legacy_enforcer_name_is_only_a_deprecated_alias():
    with pytest.warns(DeprecationWarning, match="language_sandbox"):
        legacy = EnforcementKind("trusted_tool")
    assert legacy is EnforcementKind.LANGUAGE_SANDBOX
    assert legacy.value == "language_sandbox"
    assert EnforcementKind.TRUSTED_TOOL is EnforcementKind.LANGUAGE_SANDBOX


async def test_cancellation_waits_for_terminal_completion(monkeypatch):
    admission = cedar_security(
        constant_reader, policy=PERMIT
    ).host_executor.dispatcher.admission
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def terminal(self, arguments):
        started.set()
        release.wait(5)
        finished.set()
        return "must not publish after cancellation"

    monkeypatch.setattr(LanguageProgram, "invoke", terminal)
    task = asyncio.create_task(admission.ainvoke({"path": "inert"}))
    assert await asyncio.to_thread(started.wait, 2)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert finished.is_set()
