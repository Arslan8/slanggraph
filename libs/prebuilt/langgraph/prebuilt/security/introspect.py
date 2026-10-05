"""Static inventory of tools reachable from a compiled graph."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from langgraph.prebuilt.security.descriptor import ToolDac, ToolDescriptor

if TYPE_CHECKING:
    from langgraph.prebuilt.tool_node import ToolNode


@dataclass(frozen=True, slots=True)
class ToolInventoryEntry:
    """One statically discoverable tool and its security declarations.

    Args:
        name: Public tool name.
        descriptor: Explicit or inferred tool descriptor.
        dac: Author DAC or restrictive inferred default.
        path: Graph and node names leading to the tool.
        source: `tool_node` or `guarded_tool`.
        labels: Read-only per-module security labels allocated at compile time.
    """

    name: str
    descriptor: ToolDescriptor
    dac: ToolDac
    path: tuple[str, ...]
    source: str = "tool_node"
    labels: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        frozen_labels = {
            module: MappingProxyType(dict(values))
            for module, values in self.labels.items()
        }
        object.__setattr__(self, "path", tuple(self.path))
        object.__setattr__(self, "labels", MappingProxyType(frozen_labels))


@dataclass(frozen=True, slots=True)
class ToolInventory:
    """Static tool inventory for a compiled graph.

    `complete` is false when middleware can supply tools dynamically or when a
    registered guarded tool is explicitly marked dynamic.
    """

    tools: tuple[ToolInventoryEntry, ...]
    complete: bool


_GUARDED_TOOLS: dict[str, ToolInventoryEntry] = {}


def introspect(graph: Any) -> ToolInventory:
    """Collect tool security metadata from a compiled graph and its subgraphs."""

    entries: list[ToolInventoryEntry] = []
    complete = True
    visited_graphs: set[int] = set()

    def walk_graph(current: Any, path: tuple[str, ...]) -> None:
        nonlocal complete
        identity = id(current)
        if identity in visited_graphs:
            return
        visited_graphs.add(identity)

        nodes = getattr(current, "nodes", None)
        if not isinstance(nodes, Mapping):
            complete = False
            return
        for node_name, node in nodes.items():
            if node_name == "__start__":
                continue
            found = tuple(_find_tool_nodes(node))
            for tool_node in found:
                entries.extend(_entries_for_tool_node(tool_node, path + (node_name,)))
                if (
                    tool_node._wrap_tool_call is not None
                    or tool_node._awrap_tool_call is not None
                ):
                    complete = False

        get_subgraphs = getattr(current, "get_subgraphs", None)
        if callable(get_subgraphs):
            for namespace, subgraph in get_subgraphs(recurse=False):
                walk_graph(subgraph, path + (str(namespace),))

    walk_graph(graph, ())
    for guarded in _GUARDED_TOOLS.values():
        entries.append(guarded)
        if guarded.descriptor.extra.get("dynamic") is True:
            complete = False
    entries.sort(key=lambda entry: (entry.path, entry.name, entry.source))
    return ToolInventory(tuple(entries), complete)


def _entries_for_tool_node(
    node: ToolNode, path: tuple[str, ...]
) -> Iterable[ToolInventoryEntry]:
    for name in sorted(node.tools_by_name):
        yield ToolInventoryEntry(
            name=name,
            descriptor=node.descriptors_by_name[name],
            dac=node.dacs_by_name[name],
            path=path,
        )


def _find_tool_nodes(root: Any) -> Iterable[ToolNode]:
    from langgraph.prebuilt.tool_node import ToolNode

    stack: list[tuple[Any, int]] = [(root, 0)]
    visited: set[int] = set()
    while stack:
        current, depth = stack.pop()
        if current is None or depth > 8 or id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, ToolNode):
            yield current
            continue
        if depth == 8 or hasattr(current, "nodes"):
            continue
        stack.extend((child, depth + 1) for child in _wrapped_children(current))


def _wrapped_children(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        yield from value.values()
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        yield from value
        return
    for attribute in (
        "bound",
        "func",
        "afunc",
        "runnable",
        "steps",
        "first",
        "middle",
        "last",
    ):
        child = getattr(value, attribute, None)
        if child is not None and child is not value:
            yield child
    closure = getattr(value, "__closure__", None)
    if closure:
        for cell in closure:
            try:
                yield cell.cell_contents
            except ValueError:
                continue


def _register_guarded_tool(entry: ToolInventoryEntry) -> None:
    """Register a tool mediated outside `ToolNode` for static inventory."""

    _GUARDED_TOOLS[entry.name] = entry


def _unregister_guarded_tool(name: str) -> None:
    """Remove a guarded-tool registration, primarily for test isolation."""

    _GUARDED_TOOLS.pop(name, None)
