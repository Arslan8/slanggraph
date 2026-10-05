"""Tests for conservative graph callback taint analysis."""

from pathlib import Path

from langgraph.prebuilt.security import EscapeKind, analyze_source


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source)
    return analyze_source(path)


def test_reports_unmediated_node_and_tainted_filesystem_sink(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from langgraph.graph import StateGraph

def node(state):
    with open(state["path"], "w") as handle:
        handle.write(state["value"])
    return state

builder = StateGraph(dict)
builder.add_node("writer", node)
""",
    )

    assert {finding.kind for finding in report.findings} == {
        EscapeKind.FILESYSTEM,
        EscapeKind.UNMEDIATED_NODE,
    }
    filesystem = next(
        finding for finding in report.findings if finding.kind is EscapeKind.FILESYSTEM
    )
    assert filesystem.tainted
    assert filesystem.function == "node"


def test_follows_local_helpers_and_alias_assignments(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
import subprocess as sp

def launch(command):
    argv = command
    return sp.run(argv)

def node(state):
    return launch(state["command"])

graph.add_node(node)
""",
    )

    process = [
        finding for finding in report.findings if finding.kind is EscapeKind.PROCESS
    ]
    assert len(process) == 1
    assert process[0].function == "launch"
    assert process[0].tainted


def test_reports_dynamic_dispatch_from_graph_state(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
def node(state):
    return state["callback"](state)

graph.add_node("dynamic", node)
""",
    )

    assert any(
        finding.kind is EscapeKind.DYNAMIC_DISPATCH for finding in report.findings
    )


def test_reports_tainted_call_into_unresolved_dependency(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from dependency import transform

def node(state):
    return transform(state["payload"])

graph.add_node(node)
""",
    )

    unknown = [
        finding
        for finding in report.findings
        if finding.kind is EscapeKind.UNKNOWN_CALL
    ]
    assert len(unknown) == 1
    assert unknown[0].symbol == "dependency.transform"


def test_reports_unknown_callback_instead_of_assuming_safe(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from package import callback

graph.add_conditional_edges("agent", callback)
""",
    )

    assert {finding.kind for finding in report.findings} == {
        EscapeKind.UNKNOWN_CALLBACK,
        EscapeKind.UNMEDIATED_NODE,
    }


def test_finds_sequence_entrypoint_and_default_handler_callbacks(
    tmp_path: Path,
) -> None:
    report = _scan(
        tmp_path,
        """
from langgraph.graph import StateGraph

def first(state): return state
def second(state): return state
def route(state): return "first"
def recover(state): return state

builder = StateGraph(dict)
builder.add_sequence([first, ("second", second)])
builder.set_conditional_entry_point(route)
builder.set_node_defaults(error_handler=recover)
""",
    )

    boundaries = {
        finding.symbol
        for finding in report.findings
        if finding.kind is EscapeKind.UNMEDIATED_NODE
    }
    assert boundaries == {"first", "second", "route", "recover"}


def test_reports_graph_compiled_without_security(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
compiled = builder.compile()
""",
    )

    assert [finding.kind for finding in report.findings] == [
        EscapeKind.UNPROTECTED_COMPILE
    ]


def test_accepts_explicit_security_at_compile_boundary(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
compiled = builder.compile(security=security)
""",
    )

    assert report.safe


def test_recognizes_tool_node_as_mediated_but_reports_retained_alias(
    tmp_path: Path,
) -> None:
    report = _scan(
        tmp_path,
        """
from langgraph.prebuilt import ToolNode

tools = ToolNode([send_email])
graph.add_node("tools", tools)
""",
    )

    assert [finding.kind for finding in report.findings] == [
        EscapeKind.RETAINED_CAPABILITY
    ]


def test_recognizes_guarded_tool_callback(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from langgraph.prebuilt.security import Effect, effects, guarded_tool

@guarded_tool(security=config)
@effects(Effect.NETWORK)
def send_email(address):
    client.send(address)

graph.add_node("sender", send_email)
""",
    )

    assert report.safe


def test_reports_tool_behavior_missing_from_effect_declaration(
    tmp_path: Path,
) -> None:
    report = _scan(
        tmp_path,
        """
from langchain_core.tools import tool
from langgraph.prebuilt.security import Effect, effects

@tool
@effects(Effect.READ)
def publish(url):
    return requests.post(url)
""",
    )

    finding = next(
        finding
        for finding in report.findings
        if finding.kind is EscapeKind.UNDECLARED_EFFECT
    )
    assert "Effect.NETWORK" in finding.message
    assert finding.tainted


def test_accepts_tool_behavior_covered_by_effect_declaration(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
from langchain_core.tools import tool
from langgraph.prebuilt.security import Effect, effects

@tool
@effects(Effect.NETWORK)
def publish(url):
    return requests.post(url)
""",
    )

    assert report.safe


def test_json_contains_fingerprint(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        """
def node(state):
    eval(state["code"])

graph.add_node(node)
""",
    )

    encoded = report.to_json()
    assert '"dynamic_code"' in encoded
    assert '"fingerprint"' in encoded


def test_excludes_requested_directories(tmp_path: Path) -> None:
    included = tmp_path / "src"
    excluded = tmp_path / "generated"
    included.mkdir()
    excluded.mkdir()
    (included / "safe.py").write_text("value = 1\n")
    (excluded / "unsafe.py").write_text(
        "def node(state): eval(state['x'])\ngraph.add_node(node)\n"
    )

    report = analyze_source(tmp_path, exclude=[excluded])

    assert report.safe
