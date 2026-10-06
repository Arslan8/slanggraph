"""Parser and constructive evaluator for slangGraph `.slp` profiles."""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langgraph.prebuilt.security.descriptor import DacOverrides, ToolDac

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FS_OPERATIONS = frozenset({"read", "write", "create", "delete", "exec", "truncate"})
_NET_OPERATIONS = frozenset({"connect", "bind"})


class ProfileSyntaxError(ValueError):
    """Raised when a profile document does not match the frozen grammar."""

    def __init__(self, source: str, line: int, column: int, message: str) -> None:
        super().__init__(f"{source}:{line}:{column}: {message}")
        self.source = source
        self.line = line
        self.column = column


class Requirement(str, Enum):
    """Whether removing a constructive line denies the complete call."""

    NEED = "need"
    WANT = "want"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Location of a declaration in a profile document."""

    source: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class PathTemplate:
    """An exact path or a terminal `/**` subtree before argument binding."""

    value: str
    subtree: bool = False

    def __post_init__(self) -> None:
        value = self.value
        if value.endswith("/**"):
            if self.subtree:
                raise ValueError("path template must not encode a subtree twice")
            value = value[:-3] or "/"
            object.__setattr__(self, "value", value)
            object.__setattr__(self, "subtree", True)
        if not value:
            raise ValueError("path template must be non-empty")
        _reject_controls(value, "path template")
        if any(character in value for character in "*?["):
            raise ValueError("only a terminal '/**' subtree is supported")
        _validate_variables(value)
        if not (value.startswith("/") or value.startswith("${")):
            raise ValueError("path template must bind to an absolute path")

    def bind(self, values: Mapping[str, object]) -> BoundPath:
        """Bind variables and reject non-canonical path strings."""
        raw = _bind(self.value, values, "path")
        if not raw.startswith("/"):
            raise ValueError("bound path must be absolute")
        if raw != "/" and raw.endswith("/"):
            raise ValueError(f"bound path is not normalized: {raw!r}")
        if posixpath.normpath(raw) != raw:
            raise ValueError(f"bound path is not normalized: {raw!r}")
        return BoundPath(raw, self.subtree)


@dataclass(frozen=True, slots=True, order=True)
class BoundPath:
    """A canonical absolute path with exact or subtree matching semantics."""

    value: str
    subtree: bool = False

    def __post_init__(self) -> None:
        _reject_controls(self.value, "path")
        if (
            not self.value.startswith("/")
            or posixpath.normpath(self.value) != self.value
        ):
            raise ValueError("bound path must be canonical and absolute")
        if self.value != "/" and self.value.endswith("/"):
            raise ValueError("bound path must not have a trailing slash")

    def contains(self, other: BoundPath) -> bool:
        """Return whether this path rule contains the other path rule."""
        if not self.subtree:
            return not other.subtree and self.value == other.value
        return _is_at_or_below(other.value, self.value)


@dataclass(frozen=True, slots=True)
class FsRule:
    """A filesystem line in a tool, principal, or share profile."""

    operations: frozenset[str]
    path: PathTemplate
    requirement: Requirement | None = None
    location: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        operations = frozenset(self.operations)
        unknown = operations.difference(_FS_OPERATIONS)
        if not operations or unknown:
            raise ValueError(f"invalid filesystem operations: {sorted(unknown)!r}")
        object.__setattr__(self, "operations", operations)


@dataclass(frozen=True, slots=True)
class NetRule:
    """A TCP port line in a tool or principal profile."""

    operation: str
    port: str
    requirement: Requirement | None = None
    location: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if self.operation not in _NET_OPERATIONS:
            raise ValueError(f"invalid network operation: {self.operation}")
        _validate_variables(self.port)
        if not _VARIABLE.search(self.port):
            _validate_port(self.port)

    def bind(self, values: Mapping[str, object]) -> int:
        """Bind a port template to a TCP port number."""
        return _validate_port(_bind(self.port, values, "port"))


@dataclass(frozen=True, slots=True)
class ExecRule:
    """An executable path line in a tool or principal profile."""

    path: PathTemplate
    requirement: Requirement | None = None
    location: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class NamedRule:
    """A named service or credential with immutable string attributes."""

    kind: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    requirement: Requirement | None = None
    location: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.kind):
            raise ValueError(f"invalid named-rule kind: {self.kind!r}")
        attributes = dict(self.attributes)
        if any(not _NAME.fullmatch(key) for key in attributes):
            raise ValueError("named-rule attribute names must be identifiers")
        for value in attributes.values():
            _reject_controls(value, "named-rule attribute")
            _validate_variables(value)
        object.__setattr__(self, "attributes", MappingProxyType(attributes))

    def bind(self, values: Mapping[str, object]) -> BoundNamedRule:
        """Bind every named-rule attribute."""
        return BoundNamedRule(
            self.kind,
            {key: _bind(value, values, key) for key, value in self.attributes.items()},
            self.location,
        )


@dataclass(frozen=True, slots=True)
class BoundNamedRule:
    """A fully bound named-service rule."""

    kind: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    source: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class ShareRule:
    """A filesystem envelope shared with one user or role."""

    subject: str
    operations: frozenset[str]
    path: PathTemplate
    location: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.subject):
            raise ValueError(f"invalid share subject: {self.subject!r}")
        operations = frozenset(self.operations)
        unknown = operations.difference(_FS_OPERATIONS)
        if not operations or unknown:
            raise ValueError(f"invalid share operations: {sorted(unknown)!r}")
        object.__setattr__(self, "operations", operations)


@dataclass(frozen=True, slots=True)
class Limits:
    """Self-imposed resource ceilings from a tool profile."""

    cpu_ms: int | None = None
    memory_bytes: int | None = None
    pids: int | None = None
    nofile: int | None = None
    wall_ms: int | None = None

    def __post_init__(self) -> None:
        for name in ("cpu_ms", "memory_bytes", "pids", "nofile", "wall_ms"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class ToolProfile:
    """Constructive policy declared by a tool author."""

    name: str
    owner: str
    call_grants: frozenset[str] = frozenset()
    required_scopes: frozenset[str] = frozenset()
    runs: str = "inprocess"
    delegable: bool = False
    syscall_sets: frozenset[str] = frozenset({"minimal"})
    fs: tuple[FsRule, ...] = ()
    net: tuple[NetRule, ...] = ()
    exec: tuple[ExecRule, ...] = ()
    services: tuple[NamedRule, ...] = ()
    limits: Limits = Limits()
    returns: str = "normal"
    location: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name) or not _NAME.fullmatch(self.owner):
            raise ValueError("tool name and owner must be identifiers")
        if not _NAME.fullmatch(self.runs) or not _NAME.fullmatch(self.returns):
            raise ValueError("runs and returns values must be identifiers")
        if any(
            subject != "*" and not _NAME.fullmatch(subject)
            for subject in self.call_grants
        ):
            raise ValueError("call grant subjects must be identifiers or '*'")
        if any(not _NAME.fullmatch(name) for name in self.syscall_sets):
            raise ValueError("syscall set names must be identifiers")
        for scope in self.required_scopes:
            _reject_atom(scope, "required scope")
        object.__setattr__(self, "call_grants", frozenset(self.call_grants))
        object.__setattr__(self, "required_scopes", frozenset(self.required_scopes))
        object.__setattr__(self, "syscall_sets", frozenset(self.syscall_sets))
        object.__setattr__(self, "fs", tuple(self.fs))
        object.__setattr__(self, "net", tuple(self.net))
        object.__setattr__(self, "exec", tuple(self.exec))
        object.__setattr__(self, "services", tuple(self.services))

    def audit_payload(self) -> Mapping[str, object]:
        """Return a deterministic, JSON-compatible representation."""

        def path_value(path: PathTemplate) -> str:
            return path.value + ("/**" if path.subtree else "")

        def requirement(value: Requirement | None) -> str | None:
            return value.value if value is not None else None

        return {
            "call_grants": sorted(self.call_grants),
            "delegable": self.delegable,
            "exec": [
                {
                    "path": path_value(rule.path),
                    "requirement": requirement(rule.requirement),
                }
                for rule in self.exec
            ],
            "fs": [
                {
                    "operations": sorted(rule.operations),
                    "path": path_value(rule.path),
                    "requirement": requirement(rule.requirement),
                }
                for rule in self.fs
            ],
            "limits": {
                "cpu_ms": self.limits.cpu_ms,
                "memory_bytes": self.limits.memory_bytes,
                "nofile": self.limits.nofile,
                "pids": self.limits.pids,
                "wall_ms": self.limits.wall_ms,
            },
            "name": self.name,
            "net": [
                {
                    "operation": rule.operation,
                    "port": rule.port,
                    "requirement": requirement(rule.requirement),
                }
                for rule in self.net
            ],
            "owner": self.owner,
            "required_scopes": sorted(self.required_scopes),
            "returns": self.returns,
            "runs": self.runs,
            "services": [
                {
                    "attributes": dict(rule.attributes),
                    "kind": rule.kind,
                    "requirement": requirement(rule.requirement),
                }
                for rule in self.services
            ],
            "syscall_sets": sorted(self.syscall_sets),
        }

    def as_tool_dac(self) -> ToolDac:
        """Project call authorization into the legacy `ToolDac` surface."""
        from langgraph.prebuilt.security.descriptor import ToolDac

        grants = {subject: "x" for subject in self.call_grants}
        grants.setdefault("*", "-")
        return ToolDac(
            owner=self.owner,
            grants=grants,
            required_scopes=self.required_scopes,
        )


@dataclass(frozen=True, slots=True)
class PrincipalProfile:
    """A user's constructive resource envelope and outbound shares."""

    name: str
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    fs: tuple[FsRule, ...] = ()
    net: tuple[NetRule, ...] = ()
    exec: tuple[ExecRule, ...] = ()
    services: tuple[NamedRule, ...] = ()
    credentials: tuple[NamedRule, ...] = ()
    shares: tuple[ShareRule, ...] = ()
    location: SourceLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError("principal name must be an identifier")
        if any(not _NAME.fullmatch(role) for role in self.roles):
            raise ValueError("roles must be identifiers")
        for scope in self.scopes:
            _reject_atom(scope, "scope")
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "fs", tuple(self.fs))
        object.__setattr__(self, "net", tuple(self.net))
        object.__setattr__(self, "exec", tuple(self.exec))
        object.__setattr__(self, "services", tuple(self.services))
        object.__setattr__(self, "credentials", tuple(self.credentials))
        object.__setattr__(self, "shares", tuple(self.shares))


@dataclass(frozen=True, slots=True)
class BoundFsRule:
    """One surviving filesystem line in a constructive grant."""

    operations: frozenset[str]
    path: BoundPath
    source: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class BoundNetRule:
    """One surviving network line in a constructive grant."""

    operation: str
    port: int
    source: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class BoundExecRule:
    """One surviving executable line in a constructive grant."""

    path: BoundPath
    source: SourceLocation | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class ConstructiveGrant:
    """DAC output before mandatory-policy filtering and backend lowering."""

    subject: tuple[str, str]
    fs: tuple[BoundFsRule, ...] = ()
    net: tuple[BoundNetRule, ...] = ()
    exec: tuple[BoundExecRule, ...] = ()
    services: tuple[BoundNamedRule, ...] = ()
    syscall_sets: frozenset[str] = frozenset()
    limits: Limits = Limits()
    delegable: bool = False
    returns: str = "normal"


@dataclass(frozen=True, slots=True)
class RemovedLine:
    """A requested tool line removed by constructive intersection."""

    resource_class: str
    requirement: Requirement
    reason: str
    location: SourceLocation | None = None


@dataclass(frozen=True, slots=True)
class DacEvaluation:
    """Constructive result, including dropped wants and denied needs."""

    grant: ConstructiveGrant
    removed: tuple[RemovedLine, ...] = ()
    denied: bool = False
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ProfileDocument:
    """An immutable collection of parsed tool and principal blocks."""

    tools: Mapping[str, ToolProfile]
    principals: Mapping[str, PrincipalProfile]

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", MappingProxyType(dict(self.tools)))
        object.__setattr__(self, "principals", MappingProxyType(dict(self.principals)))

    def evaluate(
        self,
        tool_name: str,
        principal_name: str,
        normalized_args: Mapping[str, object],
        *,
        principal_bindings: Mapping[str, Mapping[str, object]] | None = None,
        dac_overrides: Mapping[str, ToolProfile] | DacOverrides | None = None,
    ) -> DacEvaluation:
        """Evaluate one call using this document's inbound shares."""
        override_values = getattr(dac_overrides, "profiles", dac_overrides) or {}
        try:
            tool = override_values.get(tool_name, self.tools[tool_name])
        except KeyError as exc:
            raise ValueError(f"unknown tool profile: {tool_name}") from exc
        if tool.name != tool_name:
            tool = replace(tool, name=tool_name)
        try:
            principal = self.principals[principal_name]
        except KeyError as exc:
            raise ValueError(f"unknown principal profile: {principal_name}") from exc
        bindings = principal_bindings or {}
        inbound: list[tuple[ShareRule, Mapping[str, object]]] = []
        subjects = principal.roles | {principal.name}
        for owner in self.principals.values():
            for share in owner.shares:
                if share.subject in subjects:
                    inbound.append((share, bindings.get(owner.name, {})))
        return evaluate_dac(
            tool,
            principal,
            normalized_args,
            principal_values=bindings.get(principal.name, {}),
            inbound_shares=inbound,
        )


def parse_profiles(text: str, *, source: str = "<string>") -> ProfileDocument:
    """Parse a complete `.slp` profile document."""
    tokens = _scan(text, source)
    tools: dict[str, ToolProfile] = {}
    principals: dict[str, PrincipalProfile] = {}
    index = 0
    while index < len(tokens):
        header = tokens[index]
        if header.kind != "text":
            raise _syntax(source, header, "expected 'tool NAME' or 'principal NAME'")
        words = _words(header.text, source, header)
        if len(words) != 2 or words[0] not in {"tool", "principal"}:
            raise _syntax(source, header, "expected 'tool NAME' or 'principal NAME'")
        block_kind, name = words
        if not _NAME.fullmatch(name):
            raise _syntax(source, header, f"invalid {block_kind} name: {name!r}")
        index += 1
        if index >= len(tokens) or tokens[index].kind != "{":
            raise _syntax(source, header, "expected '{' after block header")
        index += 1
        statements: list[_Token] = []
        while index < len(tokens) and tokens[index].kind != "}":
            if tokens[index].kind != "text":
                raise _syntax(source, tokens[index], "unexpected structural token")
            statements.append(tokens[index])
            index += 1
        if index >= len(tokens):
            raise _syntax(source, header, "unterminated block")
        index += 1
        location = SourceLocation(source, header.line, header.column)
        if block_kind == "tool":
            if name in tools:
                raise _syntax(source, header, f"duplicate tool block: {name}")
            tools[name] = _parse_tool(name, statements, location, source)
        else:
            if name in principals:
                raise _syntax(source, header, f"duplicate principal block: {name}")
            principals[name] = _parse_principal(name, statements, location, source)
    return ProfileDocument(tools, principals)


def evaluate_dac(
    tool: ToolProfile,
    principal: PrincipalProfile,
    normalized_args: Mapping[str, object],
    *,
    principal_values: Mapping[str, object] | None = None,
    inbound_shares: Sequence[tuple[ShareRule, Mapping[str, object]]] = (),
) -> DacEvaluation:
    """Construct a grant by intersecting tool needs, envelope, and shares."""
    subjects = principal.roles | {principal.name}
    empty = ConstructiveGrant(subject=(principal.name, tool.name))
    if "*" not in tool.call_grants and not subjects.intersection(tool.call_grants):
        return DacEvaluation(empty, denied=True, reason="call_not_granted")
    if not tool.required_scopes.issubset(principal.scopes):
        return DacEvaluation(empty, denied=True, reason="required_scope_missing")

    values = principal_values or {}
    fs_envelope = [(rule.operations, rule.path.bind(values)) for rule in principal.fs]
    for share, share_values in inbound_shares:
        if share.subject in subjects:
            fs_envelope.append((share.operations, share.path.bind(share_values)))
    net_envelope = {(rule.operation, rule.bind(values)) for rule in principal.net}
    exec_envelope = [rule.path.bind(values) for rule in principal.exec]
    service_envelope = [rule.bind(values) for rule in principal.services]

    fs: list[BoundFsRule] = []
    net: list[BoundNetRule] = []
    executable: list[BoundExecRule] = []
    services: list[BoundNamedRule] = []
    removed: list[RemovedLine] = []

    for line in tool.fs:
        requested = line.path.bind(normalized_args)
        survivors: set[tuple[frozenset[str], BoundPath]] = set()
        for operations, allowed in fs_envelope:
            intersection = _intersect_path(requested, allowed)
            common = line.operations & operations
            if intersection is not None and common:
                survivors.add((common, intersection))
        if survivors:
            fs.extend(
                BoundFsRule(operations, path, line.location)
                for operations, path in sorted(
                    survivors,
                    key=lambda item: (item[1].value, item[1].subtree, sorted(item[0])),
                )
            )
        else:
            removed.append(_removed("fs", line))

    for line in tool.net:
        target = (line.operation, line.bind(normalized_args))
        if target in net_envelope:
            net.append(BoundNetRule(*target, source=line.location))
        else:
            removed.append(_removed("net", line))

    for line in tool.exec:
        requested = line.path.bind(normalized_args)
        survivors = {
            intersection
            for allowed in exec_envelope
            if (intersection := _intersect_path(requested, allowed)) is not None
        }
        if survivors:
            executable.extend(
                BoundExecRule(path, line.location) for path in sorted(survivors)
            )
        else:
            removed.append(_removed("exec", line))

    for line in tool.services:
        requested = line.bind(normalized_args)
        if requested in service_envelope:
            services.append(requested)
        else:
            removed.append(_removed("service", line))

    grant = ConstructiveGrant(
        subject=(principal.name, tool.name),
        fs=tuple(fs),
        net=tuple(net),
        exec=tuple(executable),
        services=tuple(services),
        syscall_sets=tool.syscall_sets,
        limits=tool.limits,
        delegable=tool.delegable,
        returns=tool.returns,
    )
    denied = any(line.requirement is Requirement.NEED for line in removed)
    return DacEvaluation(
        grant,
        tuple(removed),
        denied=denied,
        reason="required_line_removed" if denied else None,
    )


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    text: str
    line: int
    column: int


def _scan(text: str, source: str) -> list[_Token]:
    tokens: list[_Token] = []
    buffer: list[str] = []
    line = column = 1
    start_line = start_column = 1
    quote: str | None = None
    escaped = False
    variable = False
    comment = False

    def flush() -> None:
        value = "".join(buffer).strip()
        if value:
            leading = len("".join(buffer)) - len("".join(buffer).lstrip())
            tokens.append(_Token("text", value, start_line, start_column + leading))
        buffer.clear()

    index = 0
    while index < len(text):
        character = text[index]
        if comment:
            if character == "\n":
                comment = False
                flush()
            else:
                index += 1
                column += 1
                continue
        elif escaped:
            buffer.append(character)
            escaped = False
        elif quote is not None:
            buffer.append(character)
            if character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif variable:
            buffer.append(character)
            if character == "}":
                variable = False
        elif character == "$" and index + 1 < len(text) and text[index + 1] == "{":
            if not buffer:
                start_line, start_column = line, column
            buffer.extend(("$", "{"))
            variable = True
            index += 1
            column += 1
        elif character in {'"', "'"}:
            if not buffer:
                start_line, start_column = line, column
            buffer.append(character)
            quote = character
        elif character == "#":
            comment = True
        elif character in "{}":
            flush()
            tokens.append(_Token(character, character, line, column))
            start_line, start_column = line, column + 1
        elif character in ";\n":
            flush()
            start_line, start_column = (
                (line + 1, 1) if character == "\n" else (line, column + 1)
            )
        else:
            if not buffer:
                start_line, start_column = line, column
            buffer.append(character)
        if character == "\n":
            line += 1
            column = 1
        else:
            column += 1
        index += 1
    if quote is not None:
        raise ProfileSyntaxError(source, line, column, "unterminated quoted string")
    if variable:
        raise ProfileSyntaxError(source, line, column, "unterminated variable")
    flush()
    return tokens


def _parse_tool(
    name: str,
    statements: Sequence[_Token],
    location: SourceLocation,
    source: str,
) -> ToolProfile:
    values: dict[str, object] = {}
    for statement in statements:
        words = _words(statement.text, source, statement)
        if not words:
            continue
        directive = words[0]
        if directive in values:
            raise _syntax(source, statement, f"duplicate tool directive: {directive}")
        try:
            if directive == "owner":
                values[directive] = _one_identifier(words, directive)
            elif directive == "grant":
                values[directive] = _parse_grant(statement.text)
            elif directive == "requires":
                values[directive] = frozenset(words[1:])
            elif directive in {"runs", "returns"}:
                values[directive] = _one_identifier(words, directive)
            elif directive == "delegable":
                if len(words) != 2 or words[1] not in {"yes", "no"}:
                    raise ValueError("delegable expects yes or no")
                values[directive] = words[1] == "yes"
            elif directive == "syscalls":
                if len(words) < 2 or any(
                    not word.startswith("@") for word in words[1:]
                ):
                    raise ValueError("syscalls expects one or more @set names")
                sets = [word[1:] for word in words[1:]]
                if any(not _NAME.fullmatch(item) for item in sets):
                    raise ValueError("invalid syscall set name")
                values[directive] = frozenset(sets)
            elif directive == "fs":
                values[directive] = _parse_fs(statement, source, tool=True)
            elif directive == "net":
                values[directive] = _parse_net(statement, source, tool=True)
            elif directive == "exec":
                values[directive] = _parse_exec(statement, source, tool=True)
            elif directive == "service":
                values[directive] = _parse_named_list(statement, source, tool=True)
            elif directive == "limits":
                values[directive] = _parse_limits(words[1:])
            else:
                raise ValueError(f"unknown tool directive: {directive}")
        except ValueError as exc:
            raise _syntax(source, statement, str(exc)) from exc
    if "owner" not in values:
        raise ProfileSyntaxError(
            source, location.line, location.column, "tool requires owner"
        )
    try:
        return ToolProfile(
            name=name,
            owner=values["owner"],  # type: ignore[arg-type]
            call_grants=values.get("grant", frozenset()),  # type: ignore[arg-type]
            required_scopes=values.get("requires", frozenset()),  # type: ignore[arg-type]
            runs=values.get("runs", "inprocess"),  # type: ignore[arg-type]
            delegable=values.get("delegable", False),  # type: ignore[arg-type]
            syscall_sets=values.get("syscalls", frozenset({"minimal"})),  # type: ignore[arg-type]
            fs=values.get("fs", ()),  # type: ignore[arg-type]
            net=values.get("net", ()),  # type: ignore[arg-type]
            exec=values.get("exec", ()),  # type: ignore[arg-type]
            services=values.get("service", ()),  # type: ignore[arg-type]
            limits=values.get("limits", Limits()),  # type: ignore[arg-type]
            returns=values.get("returns", "normal"),  # type: ignore[arg-type]
            location=location,
        )
    except ValueError as exc:
        raise ProfileSyntaxError(
            source, location.line, location.column, str(exc)
        ) from exc


def _parse_principal(
    name: str,
    statements: Sequence[_Token],
    location: SourceLocation,
    source: str,
) -> PrincipalProfile:
    values: dict[str, object] = {}
    for statement in statements:
        words = _words(statement.text, source, statement)
        if not words:
            continue
        directive = words[0]
        if directive in values:
            raise _syntax(
                source, statement, f"duplicate principal directive: {directive}"
            )
        try:
            if directive in {"roles", "scopes"}:
                values[directive] = frozenset(words[1:])
            elif directive == "fs":
                values[directive] = _parse_fs(statement, source, tool=False)
            elif directive == "net":
                values[directive] = _parse_net(statement, source, tool=False)
            elif directive == "exec":
                values[directive] = _parse_exec(statement, source, tool=False)
            elif directive in {"service", "credential"}:
                values[directive] = _parse_named_list(statement, source, tool=False)
            elif directive == "share":
                values[directive] = _parse_shares(statement, source)
            else:
                raise ValueError(f"unknown principal directive: {directive}")
        except ValueError as exc:
            raise _syntax(source, statement, str(exc)) from exc
    try:
        return PrincipalProfile(
            name=name,
            roles=values.get("roles", frozenset()),  # type: ignore[arg-type]
            scopes=values.get("scopes", frozenset()),  # type: ignore[arg-type]
            fs=values.get("fs", ()),  # type: ignore[arg-type]
            net=values.get("net", ()),  # type: ignore[arg-type]
            exec=values.get("exec", ()),  # type: ignore[arg-type]
            services=values.get("service", ()),  # type: ignore[arg-type]
            credentials=values.get("credential", ()),  # type: ignore[arg-type]
            shares=values.get("share", ()),  # type: ignore[arg-type]
            location=location,
        )
    except ValueError as exc:
        raise ProfileSyntaxError(
            source, location.line, location.column, str(exc)
        ) from exc


def _parse_fs(statement: _Token, source: str, *, tool: bool) -> tuple[FsRule, ...]:
    body = statement.text.split(None, 1)
    if len(body) != 2 or body[1].strip() == "none":
        if len(body) == 2 and body[1].strip() == "none":
            return ()
        raise ValueError("fs expects 'none' or a comma-separated rule list")
    rules: list[FsRule] = []
    for item in _split_commas(body[1]):
        words = shlex.split(item)
        requirement = _requirement(words, tool)
        if not words:
            raise ValueError("empty filesystem rule")
        if tool or "+" in words[0] or words[0] in _FS_OPERATIONS:
            if len(words) != 2:
                raise ValueError("filesystem rule expects OPERATIONS PATH")
            operations = _operations(words[0], _FS_OPERATIONS, "filesystem")
            path = words[1]
        else:
            if len(words) != 1:
                raise ValueError("principal filesystem rule expects [OPERATIONS] PATH")
            operations = _FS_OPERATIONS
            path = words[0]
        rules.append(
            FsRule(
                operations,
                PathTemplate(path),
                requirement,
                SourceLocation(source, statement.line, statement.column),
            )
        )
    return tuple(rules)


def _parse_net(statement: _Token, source: str, *, tool: bool) -> tuple[NetRule, ...]:
    body = statement.text.split(None, 1)
    if len(body) != 2 or body[1].strip() == "none":
        if len(body) == 2 and body[1].strip() == "none":
            return ()
        raise ValueError("net expects 'none' or a comma-separated rule list")
    rules = []
    for item in _split_commas(body[1]):
        words = shlex.split(item)
        requirement = _requirement(words, tool)
        if len(words) != 2:
            raise ValueError("network rule expects OPERATION PORT")
        rules.append(
            NetRule(
                words[0],
                words[1],
                requirement,
                SourceLocation(source, statement.line, statement.column),
            )
        )
    return tuple(rules)


def _parse_exec(statement: _Token, source: str, *, tool: bool) -> tuple[ExecRule, ...]:
    body = statement.text.split(None, 1)
    if len(body) != 2 or body[1].strip() == "none":
        if len(body) == 2 and body[1].strip() == "none":
            return ()
        raise ValueError("exec expects 'none' or a comma-separated rule list")
    rules = []
    for item in _split_commas(body[1]):
        words = shlex.split(item)
        requirement = _requirement(words, tool)
        if len(words) != 1:
            raise ValueError("exec rule expects PATH")
        rules.append(
            ExecRule(
                PathTemplate(words[0]),
                requirement,
                SourceLocation(source, statement.line, statement.column),
            )
        )
    return tuple(rules)


def _parse_named_list(
    statement: _Token, source: str, *, tool: bool
) -> tuple[NamedRule, ...]:
    body = statement.text.split(None, 1)
    if len(body) != 2 or body[1].strip() == "none":
        if len(body) == 2 and body[1].strip() == "none":
            return ()
        raise ValueError("named rule expects 'none' or a comma-separated rule list")
    rules = []
    for item in _split_commas(body[1]):
        requirement = None
        value = item.strip()
        match = re.fullmatch(r"(.*\S)\s+(need|want)", value)
        if match is not None:
            if not tool:
                raise ValueError("need/want is valid only in tool rules")
            value = match.group(1)
            requirement = Requirement(match.group(2))
        elif tool:
            raise ValueError("tool resource rules require need or want")
        kind, attributes = _parse_named(value)
        rules.append(
            NamedRule(
                kind,
                attributes,
                requirement,
                SourceLocation(source, statement.line, statement.column),
            )
        )
    return tuple(rules)


def _parse_shares(statement: _Token, source: str) -> tuple[ShareRule, ...]:
    body = statement.text.split(None, 1)
    if len(body) != 2 or body[1].strip() == "none":
        if len(body) == 2 and body[1].strip() == "none":
            return ()
        raise ValueError("share expects 'none' or a comma-separated rule list")
    rules = []
    for item in _split_commas(body[1]):
        subject, separator, rest = item.partition(":")
        words = shlex.split(rest)
        if not separator or len(words) != 2:
            raise ValueError("share expects SUBJECT: OPERATIONS PATH")
        rules.append(
            ShareRule(
                subject.strip(),
                _operations(words[0], _FS_OPERATIONS, "filesystem"),
                PathTemplate(words[1]),
                SourceLocation(source, statement.line, statement.column),
            )
        )
    return tuple(rules)


def _parse_grant(text: str) -> frozenset[str]:
    body = text.split(None, 1)
    if len(body) != 2:
        raise ValueError("grant expects SUBJECT...: call")
    subjects, separator, action = body[1].partition(":")
    if not separator or action.strip() != "call":
        raise ValueError("grant supports only the call operation")
    values = frozenset(shlex.split(subjects))
    if not values or any(
        value != "*" and not _NAME.fullmatch(value) for value in values
    ):
        raise ValueError("grant subjects must be identifiers")
    return values


def _parse_named(value: str) -> tuple[str, Mapping[str, str]]:
    if "(" not in value:
        if not _NAME.fullmatch(value):
            raise ValueError(f"invalid named rule: {value!r}")
        return value, {}
    if not value.endswith(")"):
        raise ValueError("named rule has an unterminated attribute list")
    kind, raw = value[:-1].split("(", 1)
    attributes: dict[str, str] = {}
    for item in _split_commas(raw):
        key, separator, attribute = item.partition(":")
        if not separator or not key.strip() or not attribute.strip():
            raise ValueError("named attributes use KEY:VALUE")
        if key.strip() in attributes:
            raise ValueError(f"duplicate named attribute: {key.strip()}")
        attributes[key.strip()] = attribute.strip()
    return kind, attributes


def _parse_limits(words: Sequence[str]) -> Limits:
    if not words or len(words) % 2:
        raise ValueError("limits expects NAME VALUE pairs")
    values: dict[str, int] = {}
    for name, value in zip(words[::2], words[1::2], strict=True):
        if name in values:
            raise ValueError(f"duplicate limit: {name}")
        if name in {"cpu", "wall"}:
            values[name] = _duration(value)
        elif name == "mem":
            values[name] = _bytes(value)
        elif name in {"pids", "nofile"}:
            if not value.isdecimal() or int(value) <= 0:
                raise ValueError(f"{name} must be a positive integer")
            values[name] = int(value)
        else:
            raise ValueError(f"unknown limit: {name}")
    return Limits(
        cpu_ms=values.get("cpu"),
        memory_bytes=values.get("mem"),
        pids=values.get("pids"),
        nofile=values.get("nofile"),
        wall_ms=values.get("wall"),
    )


def _duration(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)(ms|s|m)", value)
    if match is None:
        raise ValueError("duration must use ms, s, or m")
    multiplier = {"ms": 1, "s": 1000, "m": 60_000}[match.group(2)]
    return int(match.group(1)) * multiplier


def _bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([KMG](?:iB|B)?|B)?", value, re.IGNORECASE)
    if match is None:
        raise ValueError("memory must be bytes or use K, M, or G")
    unit = (match.group(2) or "B").upper()
    multiplier = {
        "B": 1,
        "K": 1024,
        "KB": 1024,
        "KIB": 1024,
        "M": 1024**2,
        "MB": 1024**2,
        "MIB": 1024**2,
        "G": 1024**3,
        "GB": 1024**3,
        "GIB": 1024**3,
    }[unit]
    return int(match.group(1)) * multiplier


def _requirement(words: list[str], required: bool) -> Requirement | None:
    if words and words[-1] in {"need", "want"}:
        if not required:
            raise ValueError("need/want is valid only in tool rules")
        return Requirement(words.pop())
    if required:
        raise ValueError("tool resource rules require need or want")
    return None


def _removed(resource_class: str, line: object) -> RemovedLine:
    requirement = getattr(line, "requirement")
    if requirement is None:
        raise AssertionError("tool lines always carry a requirement")
    return RemovedLine(
        resource_class,
        requirement,
        "outside_principal_envelope_and_shares",
        getattr(line, "location"),
    )


def _intersect_path(left: BoundPath, right: BoundPath) -> BoundPath | None:
    if left.contains(right):
        return right
    if right.contains(left):
        return left
    return None


def _operations(value: str, valid: frozenset[str], label: str) -> frozenset[str]:
    operations = frozenset(value.split("+"))
    unknown = operations.difference(valid)
    if not operations or unknown:
        raise ValueError(f"invalid {label} operations: {sorted(unknown)!r}")
    return operations


def _validate_port(value: str) -> int:
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError(f"port must be an integer from 1 through 65535: {value!r}")
    return int(value)


def _bind(template: str, values: Mapping[str, object], label: str) -> str:
    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise ValueError(f"missing binding for {name!r} in {label}")
        value = str(values[name])
        _reject_controls(value, f"binding {name!r}")
        return value

    result = _VARIABLE.sub(substitute, template)
    _validate_variables(result)
    return result


def _validate_variables(value: str) -> None:
    without_variables = _VARIABLE.sub("", value)
    if "${" in without_variables or "}" in without_variables:
        raise ValueError(f"malformed variable in {value!r}")


def _reject_controls(value: str, label: str) -> None:
    if _CONTROL.search(value):
        raise ValueError(f"{label} contains a control character")


def _reject_atom(value: str, label: str) -> None:
    _reject_controls(value, label)
    if not value or any(character.isspace() for character in value):
        raise ValueError(f"{label} must be a non-empty atom")


def _is_at_or_below(path: str, parent: str) -> bool:
    return parent == "/" or path == parent or path.startswith(parent + "/")


def _one_identifier(words: Sequence[str], directive: str) -> str:
    if len(words) != 2 or not _NAME.fullmatch(words[1]):
        raise ValueError(f"{directive} expects one identifier")
    return words[1]


def _split_commas(value: str) -> list[str]:
    parts: list[str] = []
    start = depth = 0
    quote: str | None = None
    for index, character in enumerate(value):
        if quote:
            if character == quote and (index == 0 or value[index - 1] != "\\"):
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unmatched ')' in rule list")
        elif character == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    if depth or quote:
        raise ValueError("unterminated group in rule list")
    parts.append(value[start:].strip())
    if any(not part for part in parts):
        raise ValueError("empty item in rule list")
    return parts


def _words(value: str, source: str, token: _Token) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError as exc:
        raise _syntax(source, token, str(exc)) from exc


def _syntax(source: str, token: _Token, message: str) -> ProfileSyntaxError:
    return ProfileSyntaxError(source, token.line, token.column, message)
