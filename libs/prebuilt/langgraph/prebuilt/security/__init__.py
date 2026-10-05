"""Security framework for mediated tool calls.

The package exposes tool descriptors and discretionary access-control metadata.
Runtime mediation is added by the later security-framework modules.
"""

from langgraph.prebuilt.security.descriptor import (
    NORMALIZERS,
    DacOverrides,
    Effect,
    ResourceArg,
    ToolDac,
    ToolDescriptor,
    dac,
    effects,
    normalize_resource,
)
from langgraph.prebuilt.security.introspect import (
    ToolInventory,
    ToolInventoryEntry,
    introspect,
)

__all__ = (
    "NORMALIZERS",
    "DacOverrides",
    "Effect",
    "ResourceArg",
    "ToolDac",
    "ToolDescriptor",
    "ToolInventory",
    "ToolInventoryEntry",
    "dac",
    "effects",
    "introspect",
    "normalize_resource",
)
