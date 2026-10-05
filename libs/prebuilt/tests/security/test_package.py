"""Tests for the public descriptor and DAC API."""

from langgraph.prebuilt import security


def test_security_package_exports_descriptor_api() -> None:
    """Keep the descriptor public surface deliberate."""
    assert security.__all__ == (
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
        "effects",
        "introspect",
        "normalize_resource",
    )
