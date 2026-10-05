"""Tool security descriptors, DAC declarations, and resource normalization."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, TypeVar
from urllib.parse import urlsplit

_SECURITY_KEY = "security"
_DECLARATION_ATTRIBUTE = "__slanggraph_security__"
_GRANTS = frozenset({"x", "-"})
_SQL_BLOCK_COMMENT = re.compile(r"\A/\*.*?\*/", re.DOTALL)
_SQL_LINE_COMMENT = re.compile(r"\A--[^\r\n]*(?:\r?\n|\Z)")
_SQL_WORD = re.compile(r"[A-Za-z]+")
_CONTROL_CHAR = re.compile(r"[\x00-\x1f\x7f]")

_Decorated = TypeVar("_Decorated")
Normalizer = Callable[[Any], str]


class Effect(str, Enum):
    """A security-relevant class of side effect produced by a tool."""

    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    EXEC = "exec"
    DELEGATE = "delegate"
    SEND = "send"


@dataclass(frozen=True, slots=True)
class ResourceArg:
    """Describe a tool argument that identifies a protected resource.

    Args:
        arg: Tool argument containing the resource identifier.
        kind: Resource category, such as `path`, `url`, or `email`.
        normalizer: Registered normalizer name, or `None` to retain the value.
        origin: `local` for resources resolved in this process or `remote` for
            resources interpreted by another system.
    """

    arg: str
    kind: str
    normalizer: str | None = None
    origin: str = "local"

    def __post_init__(self) -> None:
        if not self.arg or not self.kind:
            msg = "resource argument and kind must be non-empty"
            raise ValueError(msg)
        if self.origin not in {"local", "remote"}:
            msg = "resource origin must be 'local' or 'remote'"
            raise ValueError(msg)
        if self.normalizer is not None and self.normalizer not in NORMALIZERS:
            msg = f"unknown resource normalizer: {self.normalizer}"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """Declare a tool's security-relevant behavior.

    Args:
        name: Public tool name.
        effects: Side-effect classes the tool may produce.
        resources: Arguments that identify protected resources.
        sensitivity: `normal`, `sensitive`, or `critical`.
        reversible: Whether the tool's effects can normally be undone.
        extra: Additional immutable descriptor metadata.
    """

    name: str
    effects: frozenset[Effect]
    resources: tuple[ResourceArg, ...] = ()
    sensitivity: str = "normal"
    reversible: bool = True
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            msg = "tool descriptor name must be non-empty"
            raise ValueError(msg)
        if self.sensitivity not in {"normal", "sensitive", "critical"}:
            msg = "tool sensitivity must be normal, sensitive, or critical"
            raise ValueError(msg)
        object.__setattr__(self, "effects", frozenset(self.effects))
        object.__setattr__(self, "resources", tuple(self.resources))
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))


@dataclass(frozen=True, slots=True)
class ToolDac:
    """Discretionary access-control policy proposed by a tool author.

    Args:
        owner: User or role that owns the tool.
        grants: Principal or role names mapped to `x` (execute) or `-` (deny).
            The special name `*` is the fallback for all other principals.
        required_scopes: Scopes every caller must hold.
        arg_grants: Normalized argument names mapped to value-specific grants.
    """

    owner: str
    grants: Mapping[str, str]
    required_scopes: frozenset[str] = frozenset()
    arg_grants: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.owner:
            msg = "DAC owner must be non-empty"
            raise ValueError(msg)
        frozen_grants = _validated_grants(self.grants, "grants")
        frozen_arg_grants = {
            arg: _validated_grants(value_grants, f"arg_grants[{arg!r}]")
            for arg, value_grants in self.arg_grants.items()
        }
        if any(not arg for arg in frozen_arg_grants):
            msg = "DAC argument names must be non-empty"
            raise ValueError(msg)
        object.__setattr__(self, "grants", frozen_grants)
        object.__setattr__(self, "required_scopes", frozenset(self.required_scopes))
        object.__setattr__(self, "arg_grants", MappingProxyType(frozen_arg_grants))


class DacOverrides(Mapping[str, ToolDac]):
    """Immutable operator overrides that replace author DACs by tool name."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, ToolDac] | None = None) -> None:
        copied = dict(values or {})
        if any(not name for name in copied):
            msg = "DAC override tool names must be non-empty"
            raise ValueError(msg)
        if not all(isinstance(value, ToolDac) for value in copied.values()):
            msg = "every DAC override must be a ToolDac"
            raise TypeError(msg)
        self._values = MappingProxyType(copied)

    def __getitem__(self, key: str) -> ToolDac:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def effects(
    *declared_effects: Effect,
    resources: Sequence[ResourceArg] = (),
    sensitivity: str = "normal",
    reversible: bool = True,
    extra: Mapping[str, Any] | None = None,
) -> Callable[[_Decorated], _Decorated]:
    """Decorate a callable or `BaseTool` with a security descriptor."""

    if not declared_effects:
        msg = "at least one effect must be declared"
        raise ValueError(msg)

    def decorator(target: _Decorated) -> _Decorated:
        descriptor = ToolDescriptor(
            name=_target_name(target),
            effects=frozenset(declared_effects),
            resources=tuple(resources),
            sensitivity=sensitivity,
            reversible=reversible,
            extra=extra or {},
        )
        _declarations(target)["descriptor"] = descriptor
        return target

    return decorator


def dac(
    *,
    owner: str,
    grants: Mapping[str, str],
    required_scopes: Sequence[str] = (),
    arg_grants: Mapping[str, Mapping[str, str]] | None = None,
) -> Callable[[_Decorated], _Decorated]:
    """Decorate a callable or `BaseTool` with an author-proposed DAC."""

    policy = ToolDac(
        owner=owner,
        grants=grants,
        required_scopes=frozenset(required_scopes),
        arg_grants=arg_grants or {},
    )

    def decorator(target: _Decorated) -> _Decorated:
        _declarations(target)["dac"] = policy
        return target

    return decorator


def security_for_tool(tool: Any) -> tuple[ToolDescriptor, ToolDac]:
    """Return explicit declarations or restrictive inferred defaults for a tool."""

    declarations = _tool_declarations(tool)
    name = _target_name(tool)
    declared_descriptor = declarations.get("descriptor")
    declared_dac = declarations.get("dac")
    descriptor = (
        replace(declared_descriptor, name=name)
        if isinstance(declared_descriptor, ToolDescriptor)
        else ToolDescriptor(
            name=name,
            effects=frozenset({Effect.EXEC}),
            sensitivity="critical",
            reversible=False,
            extra={"inferred": True},
        )
    )
    policy = (
        declared_dac
        if isinstance(declared_dac, ToolDac)
        else ToolDac(
            owner="__operator__",
            grants={"*": "-"},
            required_scopes=frozenset({f"tool:{name}"}),
        )
    )
    return descriptor, policy


def normalize_resource(resource: ResourceArg, value: Any) -> Any:
    """Normalize one declared resource value using the registered normalizer."""

    if resource.normalizer is None:
        return value
    return NORMALIZERS[resource.normalizer](value)


def _normalize_realpath(value: Any) -> str:
    path_value = os.fspath(value)
    path = os.fsdecode(path_value) if isinstance(path_value, bytes) else path_value
    _reject_control_chars(path, "path")
    return os.path.realpath(os.path.expanduser(path))


def _normalize_domain(value: Any) -> str:
    raw = _as_text(value, "domain").strip()
    _reject_control_chars(raw, "domain")
    if not raw:
        raise ValueError("domain must be non-empty")
    parsed = urlsplit(raw if "://" in raw or raw.startswith("//") else f"//{raw}")
    try:
        host = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("domain has an invalid port or host") from exc
    if host is None or (parsed.path not in {"", "/"} and "://" not in raw):
        raise ValueError("domain does not contain a valid host")
    host = host.rstrip(".")
    if not host:
        raise ValueError("domain must be non-empty")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        try:
            labels = [label.encode("idna").decode("ascii") for label in host.split(".")]
        except UnicodeError as exc:
            raise ValueError("domain is not valid IDNA") from exc
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("domain contains an invalid label")
        normalized = ".".join(labels).lower()
        if len(normalized) > 253:
            raise ValueError("domain is too long")
        return normalized


def _normalize_email_domain(value: Any) -> str:
    address = _as_text(value, "email address").strip()
    _reject_control_chars(address, "email address")
    if address.count("@") != 1:
        raise ValueError("email address must contain one @")
    local, host = address.rsplit("@", 1)
    if not local or any(char.isspace() for char in local):
        raise ValueError("email address has an invalid local part")
    return _normalize_domain(host)


def _normalize_sql_statement_kind(value: Any) -> str:
    remaining = _as_text(value, "SQL statement").lstrip()
    _reject_control_chars(remaining, "SQL statement", allow_whitespace=True)
    while remaining:
        match = _SQL_BLOCK_COMMENT.match(remaining) or _SQL_LINE_COMMENT.match(
            remaining
        )
        if match is None:
            break
        remaining = remaining[match.end() :].lstrip()
    word = _SQL_WORD.match(remaining)
    if word is None:
        raise ValueError("SQL statement has no leading keyword")
    return word.group(0).lower()


def _normalize_shell_argv0(value: Any) -> str:
    if isinstance(value, str):
        _reject_control_chars(value, "shell command", allow_whitespace=True)
        lexer = shlex.shlex(value, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
        if any(token in {"|", "||", "&", "&&", ";", "(", ")"} for token in tokens):
            raise ValueError("compound shell commands cannot be normalized as argv0")
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        tokens = [_as_text(part, "shell argument") for part in value]
    else:
        raise TypeError("shell command must be text or an argument sequence")
    if not tokens or not tokens[0]:
        raise ValueError("shell command must contain argv0")
    _reject_control_chars(tokens[0], "argv0")
    argv0 = os.path.basename(tokens[0])
    if not argv0:
        raise ValueError("shell command must contain a command name")
    return argv0


NORMALIZERS: Mapping[str, Normalizer] = MappingProxyType(
    {
        "realpath": _normalize_realpath,
        "domain": _normalize_domain,
        "email_domain": _normalize_email_domain,
        "sql_statement_kind": _normalize_sql_statement_kind,
        "shell_argv0": _normalize_shell_argv0,
    }
)


def _validated_grants(values: Mapping[str, str], field_name: str) -> Mapping[str, str]:
    copied = dict(values)
    if any(not name for name in copied):
        msg = f"{field_name} names must be non-empty"
        raise ValueError(msg)
    invalid = {grant for grant in copied.values() if grant not in _GRANTS}
    if invalid:
        msg = f"{field_name} grants must be 'x' or '-'"
        raise ValueError(msg)
    return MappingProxyType(copied)


def _target_name(target: Any) -> str:
    name = getattr(target, "name", None) or getattr(target, "__name__", None)
    if not isinstance(name, str) or not name:
        raise TypeError("security decorators require a named callable or BaseTool")
    return name


def _declarations(target: Any) -> dict[str, Any]:
    metadata = getattr(target, "metadata", None)
    if isinstance(metadata, dict):
        security = metadata.setdefault(_SECURITY_KEY, {})
        if not isinstance(security, dict):
            raise TypeError("tool metadata['security'] must be a mapping")
        return security
    existing = getattr(target, _DECLARATION_ATTRIBUTE, None)
    if existing is None:
        existing = {}
        setattr(target, _DECLARATION_ATTRIBUTE, existing)
    if not isinstance(existing, dict):
        raise TypeError("callable security metadata must be a mapping")
    return existing


def _tool_declarations(tool: Any) -> dict[str, Any]:
    declarations: dict[str, Any] = {}
    for target in (
        getattr(tool, "func", None),
        getattr(tool, "coroutine", None),
        tool,
    ):
        if target is None:
            continue
        metadata = getattr(target, "metadata", None)
        if isinstance(metadata, Mapping):
            security = metadata.get(_SECURITY_KEY)
            if isinstance(security, Mapping):
                declarations.update(security)
        callable_security = getattr(target, _DECLARATION_ATTRIBUTE, None)
        if isinstance(callable_security, Mapping):
            declarations.update(callable_security)
    return declarations


def _as_text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    return value


def _reject_control_chars(
    value: str, name: str, *, allow_whitespace: bool = False
) -> None:
    candidate = value
    if allow_whitespace:
        candidate = value.replace("\t", "").replace("\r", "").replace("\n", "")
    if _CONTROL_CHAR.search(candidate):
        raise ValueError(f"{name} contains control characters")
