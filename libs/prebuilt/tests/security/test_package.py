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
        "MemoryAuditSink",
        "Principal",
        "ResourceArg",
        "SecurityModule",
        "SecurityBindingError",
        "SecurityConfig",
        "SecurityDeniedError",
        "SecurityStack",
        "Slot",
        "SqliteAuditSink",
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
        "delegate",
        "effects",
        "guarded_tool",
        "introspect",
        "normalize_resource",
        "principal_from",
        "with_principal",
    )
