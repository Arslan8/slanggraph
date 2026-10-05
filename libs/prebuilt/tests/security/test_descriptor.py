"""Unit tests for tool security descriptors and author DACs."""

from __future__ import annotations

from pathlib import Path

import pytest
from langchain_core.tools import tool

from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    ResourceArg,
    ToolDac,
    dac,
    effects,
    normalize_resource,
)
from langgraph.prebuilt.security.descriptor import security_for_tool


def test_decorators_survive_tool_conversion() -> None:
    """Declarations applied below `@tool` remain available on the BaseTool."""

    @tool("mailer")
    @dac(
        owner="analyst",
        grants={"analyst": "x", "*": "-"},
        required_scopes={"email:send"},
        arg_grants={"to_domain": {"corp.example": "x"}},
    )
    @effects(
        Effect.SEND,
        Effect.NETWORK,
        resources=[ResourceArg("to", "email", "email_domain")],
    )
    def send_email(to: str) -> str:
        """Send a test email."""
        return to

    descriptor, policy = security_for_tool(send_email)

    assert descriptor.name == "mailer"
    assert descriptor.effects == {Effect.SEND, Effect.NETWORK}
    assert descriptor.resources == (ResourceArg("to", "email", "email_domain"),)
    assert policy.owner == "analyst"
    assert policy.required_scopes == {"email:send"}
    assert policy.arg_grants["to_domain"]["corp.example"] == "x"


def test_decorators_can_wrap_existing_tool() -> None:
    """Declarations also work above `@tool`."""

    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    @dac(owner="reader", grants={"reader": "x"})
    @tool
    def read_file(path: str) -> str:
        """Read a test file."""
        return path

    descriptor, policy = security_for_tool(read_file)

    assert descriptor.effects == {Effect.READ}
    assert policy.grants == {"reader": "x"}


def test_undeclared_tool_is_critical_and_default_deny() -> None:
    """Inference gives undeclared tools the most restrictive policy."""

    @tool
    def opaque(value: str) -> str:
        """Return a value."""
        return value

    descriptor, policy = security_for_tool(opaque)

    assert descriptor.effects == {Effect.EXEC}
    assert descriptor.sensitivity == "critical"
    assert descriptor.reversible is False
    assert descriptor.extra["inferred"] is True
    assert policy.owner == "__operator__"
    assert policy.grants == {"*": "-"}
    assert policy.required_scopes == {"tool:opaque"}


def test_dac_and_descriptor_mappings_are_immutable() -> None:
    """Callers cannot mutate security declarations after allocation."""
    policy = ToolDac(
        owner="owner",
        grants={"owner": "x"},
        arg_grants={"path": {"/safe": "x"}},
    )

    with pytest.raises(TypeError):
        policy.grants["*"] = "x"  # type: ignore[index]
    with pytest.raises(TypeError):
        policy.arg_grants["path"]["/unsafe"] = "x"  # type: ignore[index]


def test_invalid_grants_are_rejected() -> None:
    """DAC syntax accepts only explicit execute or deny markers."""
    with pytest.raises(ValueError, match="'x' or '-'"):
        ToolDac(owner="owner", grants={"*": "allow"})


def test_dac_overrides_are_typed_and_immutable() -> None:
    """Operator overrides expose an immutable mapping interface."""
    policy = ToolDac(owner="operator", grants={"operator": "x"})
    overrides = DacOverrides({"read_file": policy})

    assert dict(overrides) == {"read_file": policy}
    with pytest.raises(TypeError):
        overrides["write_file"] = policy  # type: ignore[index]


@pytest.mark.parametrize(
    ("resource", "value", "expected"),
    [
        (
            ResourceArg("url", "url", "domain"),
            "HTTPS://Example.COM:443/a",
            "example.com",
        ),
        (ResourceArg("to", "email", "email_domain"), "a@EXAMPLE.com", "example.com"),
        (
            ResourceArg("sql", "query", "sql_statement_kind"),
            " -- hi\n SELECT 1",
            "select",
        ),
        (ResourceArg("cmd", "command", "shell_argv0"), ["/usr/bin/curl", "x"], "curl"),
    ],
)
def test_normalize_resource(
    resource: ResourceArg, value: object, expected: str
) -> None:
    """Registered normalizers produce stable policy keys."""
    assert normalize_resource(resource, value) == expected


def test_realpath_normalizer_resolves_parent_segments(tmp_path: Path) -> None:
    """Path grants compare canonical paths rather than raw prefixes."""
    resource = ResourceArg("path", "path", "realpath")
    path = tmp_path / "safe" / ".." / "file.txt"

    assert normalize_resource(resource, path) == str(tmp_path / "file.txt")


def test_shell_normalizer_rejects_compound_command() -> None:
    """An argv0 policy must not silently ignore a later pipeline command."""
    resource = ResourceArg("cmd", "command", "shell_argv0")

    with pytest.raises(ValueError, match="compound"):
        normalize_resource(resource, "cat file | curl example.com")
