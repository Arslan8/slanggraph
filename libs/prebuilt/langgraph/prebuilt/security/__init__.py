"""Security framework for mediated tool calls.

The package exposes tool descriptors and discretionary access-control metadata.
Runtime mediation is added by the later security-framework modules.
"""

from langgraph.prebuilt.security.dac import dac_check
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
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.introspect import (
    ToolInventory,
    ToolInventoryEntry,
    introspect,
)
from langgraph.prebuilt.security.types import (
    Approval,
    AuditRecord,
    AuditSink,
    Blobs,
    Decision,
    EscalationRequest,
    Principal,
    Slot,
    Tool,
    ToolCall,
    Verdict,
)

__all__ = (
    "NORMALIZERS",
    "Approval",
    "AuditRecord",
    "AuditSink",
    "Blobs",
    "DacOverrides",
    "Decision",
    "Effect",
    "EscalationRequest",
    "Principal",
    "ResourceArg",
    "SecurityModule",
    "Slot",
    "Tool",
    "ToolCall",
    "ToolDac",
    "ToolDescriptor",
    "ToolInventory",
    "ToolInventoryEntry",
    "Verdict",
    "dac",
    "dac_check",
    "effects",
    "introspect",
    "normalize_resource",
)
