"""Tests for the public descriptor and DAC API."""

from langgraph.prebuilt import security


def test_security_package_exports_descriptor_api() -> None:
    """Keep the descriptor public surface deliberate."""
    assert security.__all__ == (
        "NORMALIZERS",
        "DacOverrides",
        "Effect",
        "ResourceArg",
        "ToolDac",
        "ToolDescriptor",
        "dac",
        "effects",
        "normalize_resource",
    )
