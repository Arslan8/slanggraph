"""Tests for the public descriptor and DAC API."""

from langgraph.prebuilt import security


def test_security_package_exports_descriptor_api() -> None:
    """Keep the descriptor public surface deliberate."""
    assert security.__all__ == (
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
