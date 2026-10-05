"""Security framework for mediated tool calls.

The package exposes tool descriptors and discretionary access-control metadata.
Runtime mediation is added by the later security-framework modules.
"""

from langgraph.prebuilt.security.binding import (
    PRINCIPAL_CONFIG_KEY,
    SecurityBindingError,
    principal_from,
    with_principal,
)
from langgraph.prebuilt.security.blobs import allocate_blobs, copy_blobs
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
from langgraph.prebuilt.security.stack import CapModule, SecurityStack
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
    "PRINCIPAL_CONFIG_KEY",
    "Approval",
    "AuditRecord",
    "AuditSink",
    "Blobs",
    "CapModule",
    "DacOverrides",
    "Decision",
    "Effect",
    "EscalationRequest",
    "Principal",
    "ResourceArg",
    "SecurityModule",
    "SecurityBindingError",
    "SecurityStack",
    "Slot",
    "Tool",
    "ToolCall",
    "ToolDac",
    "ToolDescriptor",
    "ToolInventory",
    "ToolInventoryEntry",
    "Verdict",
    "allocate_blobs",
    "copy_blobs",
    "dac",
    "dac_check",
    "effects",
    "introspect",
    "normalize_resource",
    "principal_from",
    "with_principal",
)
