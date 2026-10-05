"""Tests for the initial security-package scaffold."""

from langgraph.prebuilt import security


def test_security_package_starts_with_no_public_api() -> None:
    """Keep the step-one package scaffold intentionally empty."""
    assert security.__all__ == ()
