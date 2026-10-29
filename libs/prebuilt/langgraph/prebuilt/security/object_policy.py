"""Open object classes, constructive manifests, and Cedar authorization.

This module implements the v2 slangGraph policy model.  A manifest enumerates
the authority a tool requests; Cedar decides whether the tool owner, principal,
and mandatory policy permit each requested line.  The resulting grant remains
finite so an enforcement backend can lower every surviving line or reject it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import warnings
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from langchain_core.tools import BaseTool

if TYPE_CHECKING:
    from langgraph.prebuilt.analysis.static_flow import StaticFlowPolicy

from langgraph.prebuilt.security.config import SecurityConfig
from langgraph.prebuilt.security.descriptor import (
    DacOverrides,
    ToolDac,
    _has_declared_dac,
    security_for_tool,
)
from langgraph.prebuilt.security.enforcement import (
    ActivationReceipt,
    EnforcementMode,
    RuleEnforcement,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.profile import ProfileSyntaxError, Requirement
from langgraph.prebuilt.security.types import (
    Decision,
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
    Verdict,
)

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
_VARIABLE = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")
_TABLE_REF = re.compile(
    r"(?:(?P<schema>[A-Za-z_][A-Za-z0-9_$]*)\.)?"
    r"(?P<table>[A-Za-z_][A-Za-z0-9_$]*)\Z"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class EnforcementKind(str, Enum):
    """Component responsible for enforcing one object class."""

    KERNEL = "kernel"
    BROKER = "broker"
    RESOURCE_SIDE = "resource_side"
    FRAMEWORK = "framework"
    LANGUAGE_SANDBOX = "language_sandbox"
    # Source compatibility only; emitted manifests and receipts use the new name.
    TRUSTED_TOOL = "language_sandbox"

    @classmethod
    def _missing_(cls, value):
        if value == "trusted_tool":
            warnings.warn(
                "enforced_by trusted_tool is deprecated; use language_sandbox",
                DeprecationWarning,
                stacklevel=2,
            )
            return cls.LANGUAGE_SANDBOX
        return None


@dataclass(frozen=True, slots=True)
class NormalizedObject:
    """Canonical object identity and trusted attributes exposed to policy."""

    selector: str
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.selector, "normalized object selector")
        attributes = dict(self.attributes)
        if any(not _NAME.fullmatch(name) for name in attributes):
            raise ValueError("normalized object attribute names must be identifiers")
        for value in attributes.values():
            _text(value, "normalized object attribute")
        object.__setattr__(self, "attributes", MappingProxyType(attributes))


ObjectNormalizer = Callable[[str], NormalizedObject]


@dataclass(frozen=True, slots=True)
class ObjectClass:
    """One extensible policy and enforcement vocabulary entry."""

    name: str
    operations: frozenset[str]
    object_kind: str
    normalizer: str = "identity"
    attributes: frozenset[str] = frozenset()
    enforced_by: EnforcementKind = EnforcementKind.BROKER
    lowering: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.name, "class name"),
            (self.object_kind, "object kind"),
            (self.normalizer, "normalizer"),
        ):
            if not _NAME.fullmatch(value):
                raise ValueError(f"{label} must be an identifier")
        operations = frozenset(self.operations)
        attributes = frozenset(self.attributes)
        if not operations or any(not _NAME.fullmatch(item) for item in operations):
            raise ValueError("class operations must be non-empty identifiers")
        if any(not _NAME.fullmatch(item) for item in attributes):
            raise ValueError("class attributes must be identifiers")
        if self.lowering is not None and not _NAME.fullmatch(self.lowering):
            raise ValueError("class lowering must be an identifier")
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "attributes", attributes)

    @property
    def cedar_entity_type(self) -> str:
        """Return a deterministic Cedar entity type for this class."""
        return "".join(
            part[:1].upper() + part[1:] for part in (self.name, self.object_kind)
        )


_LANGUAGE_SANDBOX_CORE_CLASSES = (
    ObjectClass(
        name="fs",
        operations=frozenset({"read"}),
        object_kind="path",
        normalizer="fs.realpath",
        enforced_by=EnforcementKind.LANGUAGE_SANDBOX,
    ),
)


@runtime_checkable
class ObjectClassEnforcer(Protocol):
    """Enforcement adapter for one or more declared object classes."""

    @property
    def enforcer_id(self) -> str: ...

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool: ...


class ObjectClassRegistry:
    """Trusted registry of classes, normalizers, and available enforcers."""

    def __init__(
        self,
        *,
        normalizers: Mapping[str, ObjectNormalizer] | None = None,
        enforcers: Mapping[EnforcementKind, ObjectClassEnforcer] | None = None,
        classes: Iterable[ObjectClass] = (),
    ) -> None:
        values = dict(_BUILTIN_NORMALIZERS)
        values.update(normalizers or {})
        if any(
            not _NAME.fullmatch(name) or not callable(value)
            for name, value in values.items()
        ):
            raise ValueError("normalizers must map identifiers to callables")
        self._normalizers = MappingProxyType(values)
        self._enforcers = MappingProxyType(dict(enforcers or {}))
        self._classes: dict[str, ObjectClass] = {}
        for object_class in classes:
            self.register(object_class)

    @property
    def classes(self) -> Mapping[str, ObjectClass]:
        return MappingProxyType(dict(self._classes))

    def register(self, object_class: ObjectClass) -> None:
        """Register one class, rejecting ambiguous redefinition."""
        if object_class.name in self._classes:
            raise ValueError(f"duplicate object class: {object_class.name}")
        if object_class.normalizer not in self._normalizers:
            raise ValueError(f"unknown normalizer: {object_class.normalizer}")
        entity_type = object_class.cedar_entity_type
        if any(
            item.cedar_entity_type == entity_type for item in self._classes.values()
        ):
            raise ValueError(f"duplicate Cedar entity type: {entity_type}")
        self._classes[object_class.name] = object_class

    def normalize(self, class_name: str, value: str) -> NormalizedObject:
        """Normalize one bound object and validate its declared attributes."""
        object_class = self._classes[class_name]
        normalized = self._normalizers[object_class.normalizer](value)
        undeclared = set(normalized.attributes).difference(object_class.attributes)
        if undeclared:
            raise ValueError(
                f"normalizer returned undeclared attributes for {class_name}: "
                + ", ".join(sorted(undeclared))
            )
        return normalized

    def require_enforceable(self, lines: Sequence[ObjectGrantLine]) -> None:
        """Fail closed unless every grant line has a supporting enforcer."""
        for line in lines:
            object_class = self._classes[line.class_name]
            if not self.supports(line):
                raise ObjectPolicyDenied(
                    f"unsupported:{line.class_name}:{line.operation}:"
                    f"{object_class.enforced_by.value}"
                )

    def supports(self, line: ObjectGrantLine) -> bool:
        """Return whether the declared host adapter supports one exact line."""
        object_class = self._classes[line.class_name]
        enforcer = self._enforcers.get(object_class.enforced_by)
        return enforcer is not None and enforcer.supports(object_class, line)

    def defers_to_lowering(self, line: ObjectGrantLine) -> bool:
        """Whether host-specific enforceability is decided after authorization."""
        object_class = self._classes[line.class_name]
        enforcer = self._enforcers.get(object_class.enforced_by)
        return getattr(enforcer, "requires_host_negotiation", False) is True

    def require_registered_enforcer(self, class_name: str) -> None:
        """Reject a class whose declared enforcement locus is unavailable."""
        object_class = self._classes[class_name]
        if object_class.enforced_by not in self._enforcers:
            raise ObjectPolicyDenied(
                f"unsupported_class:{class_name}:{object_class.enforced_by.value}"
            )

    def cedar_schema(self) -> str:
        """Generate the complete Cedar schema for registered classes."""
        lines = [
            "namespace slangGraph {",
            "  entity User { roles: Set<String> };",
            "  entity Tool { owner: String };",
        ]
        for object_class in sorted(self._classes.values(), key=lambda item: item.name):
            fields = ["selector: String"]
            fields.extend(f"{name}: String" for name in sorted(object_class.attributes))
            lines.append(
                f"  entity {object_class.cedar_entity_type} {{ "
                + ", ".join(fields)
                + " };"
            )
        lines.append(
            '  action "call" appliesTo { principal: [User], resource: [Tool], '
            "context: {} };"
        )
        for object_class in sorted(self._classes.values(), key=lambda item: item.name):
            for operation in sorted(object_class.operations):
                lines.append(
                    f'  action "{object_class.name}::{operation}" appliesTo {{ '
                    f"principal: [User], resource: [{object_class.cedar_entity_type}], "
                    "context: { tool: Tool, requirement: String } };"
                )
        lines.append("}")
        return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class ManifestRule:
    """Unbound authority requested by one tool."""

    class_name: str
    operation: str
    pattern: str
    requirement: Requirement
    source: str = ""
    selector_arg: str | None = None
    selector_value: str | None = None

    def __post_init__(self) -> None:
        _text(self.pattern, "object pattern")
        _validate_template(self.pattern)
        if (self.selector_arg is None) != (self.selector_value is None):
            raise ValueError("manifest selector requires both argument and value")
        if self.selector_arg is not None:
            if not _NAME.fullmatch(self.selector_arg):
                raise ValueError("manifest selector argument must be an identifier")
            _atom(self.selector_value, "manifest selector value")


@dataclass(frozen=True, slots=True)
class ToolManifest:
    """Finite authority request for one tool artifact."""

    name: str
    runs: str
    rules: tuple[ManifestRule, ...]
    returns: str = "normal"

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name) or not _NAME.fullmatch(self.runs):
            raise ValueError("tool name and run locus must be identifiers")
        if not _NAME.fullmatch(self.returns):
            raise ValueError("tool return class must be an identifier")
        object.__setattr__(self, "rules", tuple(self.rules))


@dataclass(frozen=True, slots=True)
class SecurityManifest:
    """Parsed object classes and tool authority manifests."""

    registry: ObjectClassRegistry
    tools: Mapping[str, ToolManifest]

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", MappingProxyType(dict(self.tools)))

    def expand(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
        *,
        labels: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
    ) -> tuple[ObjectGrantLine, ...]:
        """Bind and normalize every requested line for one call."""
        try:
            tool = self.tools[tool_name]
        except KeyError as exc:
            raise ObjectPolicyDenied(f"unknown_tool:{tool_name}") from exc
        output: list[ObjectGrantLine] = []
        label_values = labels or {}
        selector_args = {
            rule.selector_arg for rule in tool.rules if rule.selector_arg is not None
        }
        if selector_args:
            selector_arg = next(iter(selector_args))
            if selector_arg not in arguments:
                raise ObjectPolicyDenied(f"missing_binding:{selector_arg}")
            selector_value = str(arguments[selector_arg])
            if not any(
                rule.selector_arg == selector_arg
                and rule.selector_value == selector_value
                for rule in tool.rules
            ):
                raise ObjectPolicyDenied(
                    f"unmapped_selector:{selector_arg}:{selector_value}"
                )
        for index, rule in enumerate(tool.rules):
            if (
                rule.selector_arg is not None
                and str(arguments[rule.selector_arg]) != rule.selector_value
            ):
                continue
            try:
                bound = _bind(rule.pattern, arguments)
                normalized = self.registry.normalize(rule.class_name, bound)
            except ObjectPolicyDenied:
                raise
            except ValueError as exc:
                raise ObjectPolicyDenied(
                    f"invalid_object:{rule.class_name}:{rule.operation}:{exc}"
                ) from None
            attributes = dict(normalized.attributes)
            attributes.update(
                label_values.get((rule.class_name, normalized.selector), {})
            )
            object_class = self.registry.classes[rule.class_name]
            unknown = set(attributes).difference(object_class.attributes)
            if unknown:
                raise ObjectPolicyDenied(
                    f"undeclared_labels:{rule.class_name}:{','.join(sorted(unknown))}"
                )
            output.append(
                ObjectGrantLine(
                    line_id=f"{tool_name}:{index}",
                    class_name=rule.class_name,
                    operation=rule.operation,
                    selector=normalized.selector,
                    attributes=attributes,
                    requirement=rule.requirement,
                    enforcer=object_class.enforced_by,
                    lowering=object_class.lowering,
                    provenance=(rule.source,) if rule.source else (),
                )
            )
        return tuple(output)


@dataclass(frozen=True, slots=True)
class ObjectGrantLine:
    """One exact, normalized, policy-authorized object capability."""

    line_id: str
    class_name: str
    operation: str
    selector: str
    attributes: Mapping[str, str]
    requirement: Requirement
    enforcer: EnforcementKind
    lowering: str | None = None
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (self.line_id, self.class_name, self.operation):
            _atom(value, "grant line field")
        _text(self.selector, "grant line selector")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))
        object.__setattr__(self, "provenance", tuple(self.provenance))

    def canonical(self) -> Mapping[str, object]:
        return {
            "attributes": dict(self.attributes),
            "class": self.class_name,
            "enforcer": self.enforcer.value,
            "line_id": self.line_id,
            "lowering": self.lowering,
            "operation": self.operation,
            "provenance": list(self.provenance),
            "requirement": self.requirement.value,
            "selector": self.selector,
        }


@dataclass(frozen=True, slots=True)
class ObjectGrant:
    """Complete finite authority authorized for one tool invocation."""

    principal_id: str
    tool_name: str
    call_id: str
    policy_digest: str
    lines: tuple[ObjectGrantLine, ...]
    enforcement_waivers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        waivers = dict(self.enforcement_waivers)
        line_ids = {line.line_id for line in self.lines}
        if not set(waivers).issubset(line_ids):
            raise ValueError("enforcement waivers must name grant lines")
        for reason in waivers.values():
            _text(reason, "enforcement waiver reason")
        object.__setattr__(self, "lines", tuple(self.lines))
        object.__setattr__(self, "enforcement_waivers", MappingProxyType(waivers))

    @property
    def digest(self) -> str:
        payload = {
            "call_id": self.call_id,
            "lines": [line.canonical() for line in self.lines],
            "enforcement_waivers": dict(self.enforcement_waivers),
            "policy_digest": self.policy_digest,
            "principal_id": self.principal_id,
            "tool_name": self.tool_name,
        }
        return hashlib.sha256(_json(payload).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class CedarPolicySet:
    """Graph-local Cedar policy partitions.

    `mac_forbids` is a legacy name for additional local restrictions. Mandatory
    operator policy is installed independently with `install_mac_policy`.
    """

    owner_permits: Mapping[str, str]
    principal_permits: str
    share_permits: str = ""
    mac_forbids: str = ""

    def __post_init__(self) -> None:
        owners = dict(self.owner_permits)
        if any(not _NAME.fullmatch(name) for name in owners):
            raise ValueError("owner policy keys must be tool identifiers")
        for source in owners.values():
            _require_policy_effect(source, "permit")
        _require_policy_effect(self.principal_permits, "permit")
        if self.share_permits.strip():
            _require_policy_effect(self.share_permits, "permit")
        if self.mac_forbids.strip():
            _require_policy_effect(self.mac_forbids, "forbid")
        object.__setattr__(self, "owner_permits", MappingProxyType(owners))

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            _json(
                {
                    "mac": self.mac_forbids,
                    "owners": dict(self.owner_permits),
                    "principal": self.principal_permits,
                    "shares": self.share_permits,
                }
            ).encode()
        ).hexdigest()


class ObjectPolicyDenied(PermissionError):
    """Raised when construction, policy, or enforcement fails closed."""


class CedarObjectAuthorizer:
    """Authorize an enumerable manifest using owner DAC, envelope DAC, and MAC."""

    def __init__(
        self,
        manifest: SecurityManifest,
        policies: CedarPolicySet,
        *,
        executable: str | Path = "cedar",
        timeout_s: float = 5.0,
        cache_entries: int = 1024,
        enforcement_waivers: Mapping[str, str] | None = None,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("Cedar timeout must be positive")
        if cache_entries < 0:
            raise ValueError("Cedar cache size cannot be negative")
        self.manifest = manifest
        self.policies = policies
        self.executable = os.fspath(executable)
        self.timeout_s = timeout_s
        self.cache_entries = cache_entries
        self._cedar_cache: OrderedDict[str, bool] = OrderedDict()
        self._cache_lock = RLock()
        self._artifact_root = Path(
            tempfile.mkdtemp(prefix="slanggraph-cedar-artifacts-")
        )
        self._artifact_root.chmod(0o700)
        self._artifact_directories: deque[Path] = deque(maxlen=1024)
        self._artifact_lock = RLock()
        waivers = dict(enforcement_waivers or {})
        unknown = set(waivers).difference(manifest.registry.classes)
        if unknown:
            raise ValueError(
                "enforcement waivers name unknown classes: "
                + ", ".join(sorted(unknown))
            )
        for reason in waivers.values():
            _text(reason, "enforcement waiver reason")
        self.enforcement_waivers = MappingProxyType(waivers)

    @property
    def artifact_root(self) -> Path:
        """Directory containing retained, private Cedar authorization bundles."""
        return self._artifact_root

    def authorization_artifacts(self) -> tuple[Path, ...]:
        """Return retained Cedar bundle directories in authorization order."""
        with self._artifact_lock:
            return tuple(self._artifact_directories)

    def authorize(
        self,
        *,
        principal_id: str,
        roles: Iterable[str],
        tool_name: str,
        tool_owner: str,
        call_id: str,
        arguments: Mapping[str, object],
        labels: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
    ) -> ObjectGrant:
        """Return the exact surviving grant or raise a fail-closed denial."""
        from langgraph.prebuilt.security.mac import runtime_mac_forbids

        operator_forbids = runtime_mac_forbids()
        mandatory_forbids = "\n".join((operator_forbids, self.policies.mac_forbids))
        candidates = self.manifest.expand(tool_name, arguments, labels=labels)
        executable = _resolve_executable(self.executable)
        if executable is None:
            raise ObjectPolicyDenied("cedar:executable_unavailable")
        engine = _engine_identity(executable)
        if engine is None:
            raise ObjectPolicyDenied("cedar:executable_unavailable")
        owner_policy = self.policies.owner_permits.get(tool_name)
        if owner_policy is None:
            raise ObjectPolicyDenied(f"cedar:owner_policy_missing:{tool_name}")
        schema = self.manifest.registry.cedar_schema()
        entities = _entities(
            self.manifest.registry,
            principal_id,
            roles,
            tool_name,
            tool_owner,
            candidates,
        )
        envelope_policy = "\n".join(
            value
            for value in (self.policies.principal_permits, self.policies.share_permits)
            if value.strip()
        )
        retained: list[ObjectGrantLine] = []
        root = Path(tempfile.mkdtemp(prefix="authorization-", dir=self._artifact_root))
        root.chmod(0o700)
        with self._artifact_lock:
            self._artifact_directories.append(root)
        try:
            schema_path = root / "schema.cedarschema"
            entities_path = root / "entities.json"
            schema_path.write_text(schema, encoding="utf-8")
            entities_json = _json(entities)
            entities_path.write_text(entities_json, encoding="utf-8")
            policy_parts = {
                "owner": owner_policy,
                "envelope": envelope_policy,
                "mac": self.policies.mac_forbids,
            }
            for name, source in policy_parts.items():
                if not source.strip() and name == "mac":
                    continue
                self._validate(
                    executable, engine, root, schema_path, schema, name, source
                )
            if operator_forbids:
                # Operator vocabulary spans graphs. A graph-local schema cannot
                # reject a forbid merely because its action belongs to another
                # graph; Cedar still parses it and fails closed on evaluation errors.
                operator_path = root / "operator-mac.cedar"
                operator_path.write_text(operator_forbids, encoding="utf-8")
                parse_key = _cedar_cache_key(engine, "parse", operator_forbids)
                cached, _ = self._cached(parse_key)
                if not cached:
                    parsed = self._run(
                        executable,
                        "check-parse",
                        "--policies",
                        os.fspath(operator_path),
                    )
                    if parsed.returncode != 0:
                        raise ObjectPolicyDenied("cedar:validation:operator-mac")
                    self._remember(parse_key, True)
            call_request = _call_request(principal_id, tool_name)
            if not self._allows(
                executable,
                engine,
                root,
                entities_path,
                entities_json,
                "owner-call",
                owner_policy,
                call_request,
            ):
                raise ObjectPolicyDenied(f"dac:call:{tool_name}")
            # For a resource-bearing manifest, caller eligibility is derived
            # from the manifest operations authorized below. Requiring a
            # separate principal-side `call` permit would duplicate that
            # authority. Resource-free tools still need an explicit call
            # permit because they have no finer-grained operation to derive it
            # from.
            if not candidates and not self._allows(
                executable,
                engine,
                root,
                entities_path,
                entities_json,
                "envelope-call",
                self.policies.principal_permits,
                call_request,
            ):
                raise ObjectPolicyDenied(f"dac:envelope_call:{tool_name}")
            if mandatory_forbids.strip() and not self._allows(
                executable,
                engine,
                root,
                entities_path,
                entities_json,
                "mac-call",
                _call_permit(principal_id, tool_name) + mandatory_forbids,
                call_request,
            ):
                raise ObjectPolicyDenied(f"mac:call:{tool_name}")
            for line in candidates:
                request = _request(
                    self.manifest.registry,
                    principal_id,
                    tool_name,
                    line,
                )
                if not self._allows(
                    executable,
                    engine,
                    root,
                    entities_path,
                    entities_json,
                    "owner",
                    owner_policy,
                    request,
                ):
                    if line.requirement is Requirement.NEED:
                        raise ObjectPolicyDenied(f"dac:owner:{line.line_id}")
                    continue
                if not self._allows(
                    executable,
                    engine,
                    root,
                    entities_path,
                    entities_json,
                    "envelope",
                    envelope_policy,
                    request,
                ):
                    if line.requirement is Requirement.NEED:
                        raise ObjectPolicyDenied(f"dac:envelope:{line.line_id}")
                    continue
                mac_policy = _candidate_permit(principal_id, line) + mandatory_forbids
                if not self._allows(
                    executable,
                    engine,
                    root,
                    entities_path,
                    entities_json,
                    "mac-eval",
                    mac_policy,
                    request,
                ):
                    if line.requirement is Requirement.NEED:
                        raise ObjectPolicyDenied(f"mac:forbid:{line.line_id}")
                    continue
                retained.append(line)
            if candidates and not retained:
                raise ObjectPolicyDenied(f"dac:no_manifest_access:{tool_name}")
        except BaseException:
            # Retain failed bundles too; their exact inputs are useful when
            # reviewing or experimenting with a policy denial.
            raise
        waived_lines: dict[str, str] = {}
        for line in retained:
            if self.manifest.registry.defers_to_lowering(line):
                continue
            if self.manifest.registry.supports(line):
                continue
            reason = self.enforcement_waivers.get(line.class_name)
            if reason is None:
                object_class = self.manifest.registry.classes[line.class_name]
                raise ObjectPolicyDenied(
                    f"unsupported:{line.class_name}:{line.operation}:"
                    f"{object_class.enforced_by.value}"
                )
            waived_lines[line.line_id] = reason
        return ObjectGrant(
            principal_id,
            tool_name,
            call_id,
            (
                hashlib.sha256(
                    (self.policies.digest + operator_forbids).encode()
                ).hexdigest()
                if operator_forbids
                else self.policies.digest
            ),
            tuple(retained),
            waived_lines,
        )

    def _validate(
        self,
        executable: str,
        engine: tuple[str, int, int, int, int, int],
        root: Path,
        schema_path: Path,
        schema: str,
        name: str,
        source: str,
    ) -> None:
        policy_path = root / f"{name}.cedar"
        policy_path.write_text(source, encoding="utf-8")
        cache_key = _cedar_cache_key(engine, "validate", schema, source)
        cached, _ = self._cached(cache_key)
        if cached:
            return
        result = self._run(
            executable,
            "validate",
            "--policies",
            os.fspath(policy_path),
            "--schema",
            os.fspath(schema_path),
            "--schema-format",
            "cedar",
        )
        if result.returncode != 0:
            raise ObjectPolicyDenied(f"cedar:validation:{name}")
        self._remember(cache_key, True)

    def _allows(
        self,
        executable: str,
        engine: tuple[str, int, int, int, int, int],
        root: Path,
        entities_path: Path,
        entities_json: str,
        name: str,
        source: str,
        request: Mapping[str, object],
    ) -> bool:
        request_json = _json(request)
        request_id = hashlib.sha256(request_json.encode()).hexdigest()[:16]
        policy_path = root / f"{name}-{request_id}.cedar"
        request_path = root / f"{name}-{request_id}.request.json"
        policy_path.write_text(source, encoding="utf-8")
        request_path.write_text(request_json, encoding="utf-8")
        cache_key = _cedar_cache_key(
            engine, "authorize", entities_json, source, request_json
        )
        cached, allowed = self._cached(cache_key)
        if cached:
            return allowed
        result = self._run(
            executable,
            "authorize",
            "--policies",
            os.fspath(policy_path),
            "--entities",
            os.fspath(entities_path),
            "--request-json",
            os.fspath(request_path),
        )
        decision = result.stdout.strip()
        if decision not in {"ALLOW", "DENY"}:
            raise ObjectPolicyDenied(f"cedar:evaluation:{name}")
        if result.returncode != 0 and decision != "DENY":
            raise ObjectPolicyDenied(f"cedar:evaluation:{name}")
        allowed = decision == "ALLOW"
        self._remember(cache_key, allowed)
        return allowed

    def _cached(self, key: str) -> tuple[bool, bool]:
        if not self.cache_entries:
            return False, False
        with self._cache_lock:
            if key not in self._cedar_cache:
                return False, False
            value = self._cedar_cache[key]
            self._cedar_cache.move_to_end(key)
            return True, value

    def _remember(self, key: str, value: bool) -> None:
        if not self.cache_entries:
            return
        with self._cache_lock:
            self._cedar_cache[key] = value
            self._cedar_cache.move_to_end(key)
            while len(self._cedar_cache) > self.cache_entries:
                self._cedar_cache.popitem(last=False)

    def _run(
        self, executable: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                (executable, *arguments),
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ObjectPolicyDenied(f"cedar:{type(exc).__name__}") from exc


@runtime_checkable
class ObjectGrantDispatcher(Protocol):
    """Trusted host that activates an object grant before executing a tool."""

    def invoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult: ...

    async def ainvoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult: ...

    def confirm_termination(self, recovery: TerminationRecovery) -> bool: ...


@runtime_checkable
class ObjectSandboxDispatcher(ObjectGrantDispatcher, ObjectClassEnforcer, Protocol):
    """Isolated dispatcher that also checks its registered execution artifacts."""

    def validate_tools(self, tool_names: Sequence[str]) -> None: ...


class ObjectPolicyHostExecutor:
    """Bridge open-class Cedar authorization into secured `ToolNode` dispatch.

    The dispatcher is part of the trusted enforcement layer.  It must activate
    every class enforcer and return a receipt whose grant digest matches the
    exact `ObjectGrant`; otherwise the outcome is treated as indeterminate.
    """

    authorizes_dac = True

    def __init__(
        self,
        authorizer: CedarObjectAuthorizer,
        dispatcher: ObjectGrantDispatcher,
        *,
        tool_owners: Mapping[str, str],
        labels: Callable[
            [Principal, ToolCall],
            Mapping[tuple[str, str], Mapping[str, str]],
        ]
        | None = None,
    ) -> None:
        owners = dict(tool_owners)
        if any(
            not _NAME.fullmatch(name) or not _NAME.fullmatch(owner)
            for name, owner in owners.items()
        ):
            raise ValueError(
                "tool owners must map tool identifiers to owner identifiers"
            )
        self.authorizer = authorizer
        self.dispatcher = dispatcher
        self.tool_owners = MappingProxyType(owners)
        self.labels = labels or (lambda _principal, _call: {})
        self._grants: deque[ObjectGrant] = deque(maxlen=1024)
        self._grant_lock = RLock()

    def authorization_grants(self) -> tuple[ObjectGrant, ...]:
        """Return a bounded snapshot of exact grants issued for execution."""
        with self._grant_lock:
            return tuple(self._grants)

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require a manifest, owner policy, and owner identity for every tool."""
        names = set(tool_names)
        missing_manifests = names.difference(self.authorizer.manifest.tools)
        missing_owners = names.difference(self.tool_owners)
        missing_policies = names.difference(self.authorizer.policies.owner_permits)
        if missing_manifests or missing_owners or missing_policies:
            parts = []
            if missing_manifests:
                parts.append("manifest=" + ",".join(sorted(missing_manifests)))
            if missing_owners:
                parts.append("owner=" + ",".join(sorted(missing_owners)))
            if missing_policies:
                parts.append("policy=" + ",".join(sorted(missing_policies)))
            raise ValueError("object policy tools incomplete: " + ";".join(parts))
        for name in sorted(names):
            for rule in self.authorizer.manifest.tools[name].rules:
                if rule.class_name in self.authorizer.enforcement_waivers:
                    continue
                try:
                    self.authorizer.manifest.registry.require_registered_enforcer(
                        rule.class_name
                    )
                except ObjectPolicyDenied as exc:
                    raise ValueError(f"object policy tool {name}: {exc}") from exc
        if isinstance(self.dispatcher, ObjectSandboxDispatcher):
            self.dispatcher.validate_tools(tool_names)

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Authorize, activate, and dispatch one synchronous call."""
        grant = self._authorize(principal, call, constraints)
        with self._grant_lock:
            self._grants.append(grant)
        result = self.dispatcher.invoke(principal, call, grant)
        return self._verify_result(result, grant)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Authorize, activate, and dispatch one asynchronous call."""
        grant = await asyncio.to_thread(self._authorize, principal, call, constraints)
        with self._grant_lock:
            self._grants.append(grant)
        result = await self.dispatcher.ainvoke(principal, call, grant)
        return self._verify_result(result, grant)

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        """Delegate retained-worker recovery to the enforcement host."""
        return self.dispatcher.confirm_termination(recovery)

    def _authorize(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> ObjectGrant:
        if constraints:
            raise HostExecutionDenied("object_policy:typed_constraints_unsupported")
        owner = self.tool_owners.get(call.tool.name)
        if owner is None:
            raise HostExecutionDenied("object_policy:tool_owner_missing")
        arguments = dict(call.args)
        arguments.update(call.normalized)
        try:
            return self.authorizer.authorize(
                principal_id=principal.user_id,
                roles=principal.roles,
                tool_name=call.tool.name,
                tool_owner=owner,
                call_id=call.call_id,
                arguments=arguments,
                labels=self.labels(principal, call),
            )
        except ObjectPolicyDenied as exc:
            raise HostExecutionDenied(f"object_policy:{exc}") from exc

    @staticmethod
    def _verify_result(
        result: HostExecutionResult, grant: ObjectGrant
    ) -> HostExecutionResult:
        if result.receipt.grant_digest != grant.digest:
            raise HostExecutionError(
                "object_policy:receipt_grant_mismatch",
                result.receipt,
                ExecutionOutcome.INDETERMINATE,
            )
        expected_mode = (
            EnforcementMode.DEGRADED
            if grant.enforcement_waivers
            else EnforcementMode.ENFORCED
        )
        if result.receipt.mode is not expected_mode:
            raise HostExecutionError(
                "object_policy:receipt_mode_mismatch",
                result.receipt,
                ExecutionOutcome.INDETERMINATE,
            )
        removed = set(result.receipt.removed_wants)
        optional = {
            line.line_id for line in grant.lines if line.requirement is Requirement.WANT
        }
        if not removed.issubset(optional) or len(removed) != len(
            result.receipt.removed_wants
        ):
            raise HostExecutionError(
                "object_policy:invalid_removed_authority",
                result.receipt,
                ExecutionOutcome.INDETERMINATE,
            )
        expected = {line.line_id for line in grant.lines} - removed
        reported = [item.rule_id for item in result.receipt.rule_enforcement]
        if len(reported) != len(set(reported)) or set(reported) != expected:
            raise HostExecutionError(
                "object_policy:incomplete_line_enforcement",
                result.receipt,
                ExecutionOutcome.INDETERMINATE,
            )
        unsupported = {
            item.rule_id
            for item in result.receipt.rule_enforcement
            if item.support is SupportLevel.UNSUPPORTED
        }
        if unsupported != set(grant.enforcement_waivers):
            raise HostExecutionError(
                "object_policy:waiver_evidence_mismatch",
                result.receipt,
                ExecutionOutcome.INDETERMINATE,
            )
        return result


class CedarCallPolicy(SecurityModule):
    """Cedar call-level DAC for ordinary in-process tools.

    Resource-bearing manifests require `ObjectPolicyHostExecutor`; this module
    deliberately accepts only tools with no object grant lines.
    """

    name = "cedar_call_dac"
    authorizes_inprocess_tools = True

    def __init__(
        self,
        authorizer: CedarObjectAuthorizer,
        tool_owners: Mapping[str, str],
    ) -> None:
        resource_tools = sorted(
            name for name, tool in authorizer.manifest.tools.items() if tool.rules
        )
        if resource_tools:
            raise ValueError(
                "resource-bearing Cedar manifests require ObjectPolicyHostExecutor: "
                + ", ".join(resource_tools)
            )
        external_tools = sorted(
            name
            for name, tool in authorizer.manifest.tools.items()
            if tool.runs != "inprocess"
        )
        if external_tools:
            raise ValueError(
                "Cedar call security requires runs inprocess: "
                + ", ".join(external_tools)
            )
        self.authorizer = authorizer
        self.tool_owners = MappingProxyType(dict(tool_owners))

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Authorize the final normalized call through owner, principal, and MAC."""
        owner = self.tool_owners.get(call.tool.name)
        if owner is None:
            return Decision(Verdict.DENY, "cedar_call:tool_owner_missing")
        arguments = dict(call.args)
        arguments.update(call.normalized)
        try:
            self.authorizer.authorize(
                principal_id=principal.user_id,
                roles=principal.roles,
                tool_name=call.tool.name,
                tool_owner=owner,
                call_id=call.call_id,
                arguments=arguments,
            )
        except ObjectPolicyDenied as exc:
            return Decision(Verdict.DENY, f"cedar_call:{exc}")
        return Decision(Verdict.ALLOW, "cedar_call:allow")


class _LanguageSandboxEnforcer:
    """Declare resource enforcement through the admitted language sandbox."""

    enforcer_id = "language-sandbox-host-intersection"

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        return object_class.enforced_by is EnforcementKind.LANGUAGE_SANDBOX


class _LanguageSandboxDispatcher:
    """Execute one admitted language program after authorizing its object grant."""

    enforcer_id = "language-sandbox-host-intersection"

    def __init__(
        self,
        tool: BaseTool,
        manifest: SecurityManifest,
        resources=(),
        *,
        static_flow: StaticFlowPolicy | None = None,
    ) -> None:
        from langgraph.prebuilt.security.inprocess import ManifestAdmission

        self.tool = tool
        self.admission = ManifestAdmission(tool, manifest, static_flow=static_flow)
        self.resources = resources

    def invoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        from langgraph.prebuilt.security.inprocess import _active_grant
        from langgraph.prebuilt.security.mediators.objects import (
            ResourceReleaseError,
            local_resources,
        )

        self.admission.validate()
        token = _active_grant.set(grant)
        try:
            with local_resources(self.resources, principal, call, grant):
                return HostExecutionResult(
                    self.admission.invoke(self._arguments(call)),
                    self._receipt(principal, call, grant),
                )
        except ResourceReleaseError as exc:
            raise HostExecutionError(
                str(exc),
                self._receipt(principal, call, grant),
                ExecutionOutcome.INDETERMINATE,
            ) from exc
        finally:
            _active_grant.reset(token)

    async def ainvoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        from langgraph.prebuilt.security.inprocess import _active_grant
        from langgraph.prebuilt.security.mediators.objects import (
            ResourceReleaseError,
            local_resources,
        )

        self.admission.validate()
        token = _active_grant.set(grant)
        try:
            with local_resources(self.resources, principal, call, grant):
                return HostExecutionResult(
                    await self.admission.ainvoke(self._arguments(call)),
                    self._receipt(principal, call, grant),
                )
        except ResourceReleaseError as exc:
            raise HostExecutionError(
                str(exc),
                self._receipt(principal, call, grant),
                ExecutionOutcome.INDETERMINATE,
            ) from exc
        finally:
            _active_grant.reset(token)

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        return True

    @staticmethod
    def _arguments(call: ToolCall) -> Mapping[str, object]:
        # Descriptor-normalized resource arguments replace their raw forms so
        # the language-sandbox tool acts on the same canonical identity policy observed.
        arguments = {
            name: call.normalized.get(name, value) for name, value in call.args.items()
        }
        if any(type(value) is not str for value in arguments.values()):
            raise HostExecutionDenied("manifest_consistency:arguments_must_be_strings")
        return arguments

    def _receipt(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> ActivationReceipt:
        context = hashlib.sha256(
            _json(
                {
                    "call": call.call_id,
                    "principal": principal.user_id,
                    "tool": self.tool.name,
                }
            ).encode()
        ).hexdigest()
        plan = hashlib.sha256(
            _json(
                {
                    "grant": grant.digest,
                    "mechanism": self.enforcer_id,
                }
            ).encode()
        ).hexdigest()
        return ActivationReceipt(
            grant_digest=grant.digest,
            plan_digest=plan,
            host_digest=self.enforcer_id,
            context_digest=context,
            nonce=call.call_id,
            mode=EnforcementMode.ENFORCED,
            evidence=(),
            activated_obligations=frozenset(line.line_id for line in grant.lines),
            valid_until=time.time() + 60,
            rule_enforcement=tuple(
                RuleEnforcement(line.line_id, SupportLevel.EXACT, self.enforcer_id)
                for line in grant.lines
            ),
        )


def cedar_security(
    tool: BaseTool,
    *,
    policy: str,
    manifest: str = "runs inprocess\nreturns normal",
    classes: str = "",
    mac_forbids: str = "",
    owner: str = "application",
    executable: str | Path = "cedar",
    modules: Sequence[SecurityModule] = (),
    normalizers: Mapping[str, ObjectNormalizer] | None = None,
    dispatcher: ObjectSandboxDispatcher | None = None,
    resources: Sequence[Any] = (),
    static_flow: StaticFlowPolicy | None = None,
    labels: Callable[
        [Principal, ToolCall],
        Mapping[tuple[str, str], Mapping[str, str]],
    ]
    | None = None,
) -> SecurityConfig:
    """Bind Cedar DAC to a language-sandbox tool or an isolated dispatcher.

    `manifest` is an unnamed SLP tool body. The tool's internal name is derived
    from `tool`, and exact owner permits are generated automatically. `classes`
    contains any class declarations used by resource rules. `policy` is the
    caller-facing Cedar permit policy. For resource-bearing manifests, access
    to the derived operations also determines caller eligibility; resource-free
    manifests require an explicit caller-side `call` permit. Resource grants
    use language-sandbox mediation intersected with host permissions.
    `mac_forbids` adds graph-local restrictions (legacy parameter name); it
    cannot replace or disable operator policy from `install_mac_policy`.
    `resources` registers object-bound implementations for admitted in-process
    tools; class declarations are generated automatically. For isolated tools,
    register resources on their dispatcher instead.

    For `runs linux` or `runs broker`, supply an isolated `dispatcher`; the
    registered schema tool is never executed in the coordinator. Kernel and
    broker classes must be supported by that dispatcher before execution.
    Language-sandbox bodies must pass source-only manifest consistency checking;
    unavailable source, unmodeled calls, and unsupported syntax deny admission.
    Resource access must use approved `security.inprocess` APIs or registered
    typed resource clients. Optional `static_flow` rejects incompatible or unknown
    confidentiality bounds during in-process admission, before execution.
    """
    if not isinstance(tool, BaseTool):
        raise TypeError("cedar_security requires a @tool-decorated BaseTool")
    if static_flow is not None and dispatcher is not None:
        raise ValueError("static_flow requires in-process manifest admission")
    tool_name = tool.name
    if not _NAME.fullmatch(tool_name):
        raise ValueError("tool name must be an identifier")
    _text(owner, "tool owner")
    if dispatcher is not None and not isinstance(dispatcher, ObjectSandboxDispatcher):
        raise TypeError("dispatcher must implement ObjectSandboxDispatcher")
    from langgraph.prebuilt.security.mediators.contracts import object_bindings

    if dispatcher is not None:
        if resources:
            raise ValueError("register resources on the dispatcher for isolated tools")
        resources = getattr(dispatcher, "resources", ())
    resources = tuple(resources)
    object_bindings(resources)  # Reject duplicate bindings before admission.
    declarations = {}
    for resource in resources:
        resource.adapter  # Require an implementation at registration.
        declaration = resource.class_declaration(
            enforced_by="language_sandbox" if dispatcher is None else "broker"
        )
        previous = declarations.setdefault(resource.class_name, declaration)
        if previous != declaration:
            raise ValueError("conflicting resource class definitions")
    classes = classes + "\n" + "\n".join(declarations.values())
    core_classes = (
        _LANGUAGE_SANDBOX_CORE_CLASSES
        if dispatcher is None
        else (
            ObjectClass(
                name="fs",
                operations=frozenset({"read", "write", "truncate"}),
                object_kind="path",
                normalizer="fs.realpath",
                enforced_by=EnforcementKind.KERNEL,
            ),
        )
    )
    parsed = parse_security_manifest(
        f"{classes}\ntool {tool_name} {{\n{manifest}\n}}",
        source=f"<{tool_name} manifest>",
        normalizers=normalizers,
        enforcers={
            EnforcementKind.LANGUAGE_SANDBOX: _LanguageSandboxEnforcer(),
        }
        if dispatcher is None
        else {
            EnforcementKind.KERNEL: dispatcher,
            EnforcementKind.BROKER: dispatcher,
        },
        classes=core_classes,
    )
    tool_manifest = parsed.tools[tool_name]
    if dispatcher is None and tool_manifest.runs != "inprocess":
        raise ValueError("cedar_security requires runs inprocess")
    if dispatcher is not None and tool_manifest.runs not in {"linux", "broker"}:
        raise ValueError("isolated cedar_security requires runs linux or runs broker")
    invalid_enforcers = sorted(
        {
            rule.class_name
            for rule in tool_manifest.rules
            if parsed.registry.classes[rule.class_name].enforced_by
            is not EnforcementKind.LANGUAGE_SANDBOX
        }
    )
    if dispatcher is None and invalid_enforcers:
        raise ValueError(
            "cedar_security resource classes must use enforced_by language_sandbox: "
            + ", ".join(invalid_enforcers)
        )
    policies = CedarPolicySet(
        {tool_name: _language_sandbox_owner_policy(tool_manifest)},
        policy,
        "",
        mac_forbids,
    )
    # Cedar replaces only inferred DAC defaults, never an explicit author gate.
    local_policy = (
        security_for_tool(tool)[1]
        if _has_declared_dac(tool)
        else ToolDac("__cedar__", {"*": "x"})
    )
    overrides = DacOverrides({tool_name: local_policy})
    authorizer = CedarObjectAuthorizer(parsed, policies, executable=executable)
    executor = ObjectPolicyHostExecutor(
        authorizer,
        dispatcher
        if dispatcher is not None
        else _LanguageSandboxDispatcher(
            tool, parsed, resources, static_flow=static_flow
        ),
        tool_owners={tool_name: owner},
        labels=labels,
    )
    executor.validate_tools((tool_name,))
    return SecurityConfig(
        modules=tuple(modules),
        host_executor=executor,
        dac_overrides=overrides,
    )


def parse_security_manifest(
    text: str,
    *,
    source: str = "<string>",
    normalizers: Mapping[str, ObjectNormalizer] | None = None,
    enforcers: Mapping[EnforcementKind, ObjectClassEnforcer] | None = None,
    classes: Iterable[ObjectClass] = (),
) -> SecurityManifest:
    """Parse v2 `.slp` class declarations and tool manifests.

    `classes` pre-registers trusted host or plugin vocabulary before textual
    declarations are parsed. `cedar_security` uses it for context-appropriate
    core classes; power users may use it for programmatic plugin registration.
    """
    blocks = _blocks(text, source)
    registry = ObjectClassRegistry(
        normalizers=normalizers,
        enforcers=enforcers,
        classes=classes,
    )
    for kind, name, statements, line in blocks:
        if kind == "class":
            registry.register(_parse_class(name, statements, source, line))
    tools: dict[str, ToolManifest] = {}
    for kind, name, statements, line in blocks:
        if kind != "tool":
            continue
        if name in tools:
            raise ProfileSyntaxError(source, line, 1, f"duplicate tool block: {name}")
        tools[name] = _parse_manifest_tool(name, statements, registry, source, line)
    return SecurityManifest(registry, tools)


def _parse_class(
    name: str, statements: Sequence[tuple[str, int]], source: str, line: int
) -> ObjectClass:
    values: dict[str, list[str]] = {}
    for statement, statement_line in statements:
        words = statement.split()
        if not words:
            continue
        if words[0] in values:
            raise ProfileSyntaxError(
                source, statement_line, 1, f"duplicate class directive: {words[0]}"
            )
        values[words[0]] = words[1:]
    required = {"operations", "object", "normalizer", "attrs", "enforced_by"}
    missing = required.difference(values)
    unknown = set(values).difference(required | {"lowering"})
    if missing or unknown:
        detail = (
            "missing " + ", ".join(sorted(missing))
            if missing
            else "unknown " + ", ".join(sorted(unknown))
        )
        raise ProfileSyntaxError(source, line, 1, f"invalid class {name}: {detail}")
    for directive in ("object", "normalizer", "enforced_by", "lowering"):
        if directive in values and len(values[directive]) != 1:
            raise ProfileSyntaxError(source, line, 1, f"{directive} expects one value")
    try:
        return ObjectClass(
            name,
            frozenset(values["operations"]),
            values["object"][0],
            values["normalizer"][0],
            frozenset(values["attrs"]),
            EnforcementKind(values["enforced_by"][0]),
            values.get("lowering", [None])[0],
        )
    except (IndexError, ValueError) as exc:
        raise ProfileSyntaxError(source, line, 1, str(exc)) from exc


def _parse_manifest_tool(
    name: str,
    statements: Sequence[tuple[str, int]],
    registry: ObjectClassRegistry,
    source: str,
    line: int,
) -> ToolManifest:
    runs = "inprocess"
    returns = "normal"
    rules: list[ManifestRule] = []
    seen_meta: set[str] = set()
    for statement, statement_line in statements:
        words = statement.split()
        if not words:
            continue
        directive = words[0]
        if directive in {"runs", "returns"}:
            if directive in seen_meta or len(words) != 2:
                raise ProfileSyntaxError(
                    source, statement_line, 1, f"invalid {directive}"
                )
            seen_meta.add(directive)
            if directive == "runs":
                runs = words[1]
            else:
                returns = words[1]
            continue
        selector_arg: str | None = None
        selector_value: str | None = None
        if directive == "map":
            if len(words) != 6 or "=" not in words[1]:
                raise ProfileSyntaxError(
                    source,
                    statement_line,
                    1,
                    "map line expects map ARG=VALUE CLASS OPERATION "
                    "OBJECT-PATTERN need|want",
                )
            selector_arg, selector_value = words[1].split("=", 1)
            if (
                not _NAME.fullmatch(selector_arg)
                or not selector_value
                or any(character.isspace() for character in selector_value)
            ):
                raise ProfileSyntaxError(
                    source, statement_line, 1, "invalid map argument selector"
                )
            directive = words[2]
            resource_words = words[2:]
        else:
            resource_words = words
        object_class = registry.classes.get(directive)
        if object_class is None:
            raise ProfileSyntaxError(
                source, statement_line, 1, f"unknown object class: {directive}"
            )
        if len(resource_words) != 4 or resource_words[-1] not in {"need", "want"}:
            raise ProfileSyntaxError(
                source,
                statement_line,
                1,
                "resource line expects CLASS OPERATION OBJECT-PATTERN need|want",
            )
        if resource_words[1] not in object_class.operations:
            raise ProfileSyntaxError(
                source,
                statement_line,
                1,
                f"operation {resource_words[1]!r} is not declared by class {directive}",
            )
        rules.append(
            ManifestRule(
                directive,
                resource_words[1],
                resource_words[2],
                Requirement(resource_words[3]),
                f"{source}:{statement_line}",
                selector_arg,
                selector_value,
            )
        )
    selector_args = {
        rule.selector_arg for rule in rules if rule.selector_arg is not None
    }
    if len(selector_args) > 1:
        raise ProfileSyntaxError(
            source,
            line,
            1,
            "one tool manifest may select operations from only one argument",
        )
    return ToolManifest(name, runs, tuple(rules), returns)


def _blocks(
    text: str, source: str
) -> list[tuple[str, str, tuple[tuple[str, int], ...], int]]:
    stripped = re.sub(r"#[^\n]*", "", text)
    pattern = re.compile(r"(?m)^\s*(class|tool)\s+([A-Za-z_][A-Za-z0-9_.-]*)\s*\{")
    blocks: list[tuple[str, str, tuple[tuple[str, int], ...], int]] = []
    position = 0
    while True:
        match = pattern.search(stripped, position)
        if match is None:
            if stripped[position:].strip():
                line = stripped.count("\n", 0, position) + 1
                raise ProfileSyntaxError(
                    source, line, 1, "expected class or tool block"
                )
            break
        if stripped[position : match.start()].strip():
            line = stripped.count("\n", 0, position) + 1
            raise ProfileSyntaxError(source, line, 1, "unexpected text outside a block")
        depth = 1
        index = match.end()
        while index < len(stripped) and depth:
            if stripped[index] == "{":
                depth += 1
            elif stripped[index] == "}":
                depth -= 1
            index += 1
        if depth:
            line = stripped.count("\n", 0, match.start()) + 1
            raise ProfileSyntaxError(source, line, 1, "unterminated block")
        body = stripped[match.end() : index - 1]
        body_line = stripped.count("\n", 0, match.end()) + 1
        statements: list[tuple[str, int]] = []
        for offset, raw_line in enumerate(body.splitlines()):
            for part in raw_line.split(";"):
                if part.strip():
                    statements.append((part.strip(), body_line + offset))
        line = stripped.count("\n", 0, match.start()) + 1
        blocks.append((match.group(1), match.group(2), tuple(statements), line))
        position = index
    return blocks


def _entities(
    registry: ObjectClassRegistry,
    principal_id: str,
    roles: Iterable[str],
    tool_name: str,
    tool_owner: str,
    lines: Sequence[ObjectGrantLine],
) -> list[Mapping[str, object]]:
    entities: list[Mapping[str, object]] = [
        _entity("slangGraph::User", principal_id, {"roles": sorted(set(roles))}),
        _entity("slangGraph::Tool", tool_name, {"owner": tool_owner}),
    ]
    for line in lines:
        object_class = registry.classes[line.class_name]
        attributes: dict[str, object] = {"selector": line.selector}
        attributes.update(
            {name: line.attributes.get(name, "") for name in object_class.attributes}
        )
        entities.append(
            _entity(
                f"slangGraph::{object_class.cedar_entity_type}",
                _resource_id(line),
                attributes,
            )
        )
    return entities


def _entity(
    entity_type: str, entity_id: str, attrs: Mapping[str, object]
) -> Mapping[str, object]:
    return {
        "attrs": dict(attrs),
        "parents": [],
        "uid": {"type": entity_type, "id": entity_id},
    }


def _request(
    registry: ObjectClassRegistry,
    principal_id: str,
    tool_name: str,
    line: ObjectGrantLine,
) -> Mapping[str, object]:
    object_class = registry.classes[line.class_name]
    return {
        "action": _entity_literal(
            "slangGraph::Action", f"{line.class_name}::{line.operation}"
        ),
        "context": {
            "requirement": line.requirement.value,
            "tool": {"__entity": {"type": "slangGraph::Tool", "id": tool_name}},
        },
        "principal": _entity_literal("slangGraph::User", principal_id),
        "resource": _entity_literal(
            f"slangGraph::{object_class.cedar_entity_type}", _resource_id(line)
        ),
    }


def _call_request(principal_id: str, tool_name: str) -> Mapping[str, object]:
    return {
        "action": _entity_literal("slangGraph::Action", "call"),
        "context": {},
        "principal": _entity_literal("slangGraph::User", principal_id),
        "resource": _entity_literal("slangGraph::Tool", tool_name),
    }


def _call_permit(principal_id: str, tool_name: str) -> str:
    return (
        '@id("constructive:call")\n'
        "permit (\n"
        f'  principal == slangGraph::User::"{_cedar(principal_id)}",\n'
        '  action == slangGraph::Action::"call",\n'
        f'  resource == slangGraph::Tool::"{_cedar(tool_name)}"\n'
        ");\n"
    )


def _tool_call_permit(tool_name: str) -> str:
    """Return the hidden owner ceiling for one directly bound tool."""
    return (
        '@id("bound-tool:call")\n'
        "permit (\n"
        "  principal,\n"
        '  action == slangGraph::Action::"call",\n'
        f'  resource == slangGraph::Tool::"{_cedar(tool_name)}"\n'
        ");\n"
    )


def _language_sandbox_owner_policy(tool: ToolManifest) -> str:
    """Generate the exact owner ceiling for a directly bound language-sandbox tool."""
    policies = [_tool_call_permit(tool.name)]
    operations = sorted({(rule.class_name, rule.operation) for rule in tool.rules})
    for class_name, operation in operations:
        policies.append(
            '@id("bound-tool:' + _cedar(class_name) + ":" + _cedar(operation) + '")\n'
            "permit (\n"
            "  principal,\n"
            f'  action == slangGraph::Action::"{_cedar(class_name)}::'
            f'{_cedar(operation)}",\n'
            "  resource\n"
            ") when {\n"
            f'  context.tool == slangGraph::Tool::"{_cedar(tool.name)}"\n'
            "};\n"
        )
    return "\n".join(policies)


def _candidate_permit(principal_id: str, line: ObjectGrantLine) -> str:
    return (
        '@id("constructive:' + _cedar(line.line_id) + '")\n'
        "permit (\n"
        f'  principal == slangGraph::User::"{_cedar(principal_id)}",\n'
        f'  action == slangGraph::Action::"{_cedar(line.class_name)}::{_cedar(line.operation)}",\n'
        "  resource\n"
        ");\n"
    )


def _resource_id(line: ObjectGrantLine) -> str:
    return hashlib.sha256(
        _json(
            {
                "class": line.class_name,
                "selector": line.selector,
                "attributes": dict(line.attributes),
            }
        ).encode()
    ).hexdigest()


def _require_policy_effect(source: str, expected: str) -> None:
    effects = _policy_effects(source)
    if not effects:
        raise ValueError(f"{expected} policy set must not be empty")
    unexpected = effects.difference({expected})
    if unexpected:
        raise ValueError(
            f"{expected} policy set contains forbidden effects: "
            + ", ".join(sorted(unexpected))
        )


def _policy_effects(source: str) -> frozenset[str]:
    """Extract top-level policy effects without trusting comments or strings."""
    cleaned: list[str] = []
    index = 0
    quote = False
    while index < len(source):
        if quote:
            if source[index] == "\\":
                index += 2
                continue
            if source[index] == '"':
                quote = False
            cleaned.append(" ")
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated Cedar block comment")
            index = end + 2
            continue
        if source[index] == '"':
            quote = True
            cleaned.append(" ")
        else:
            cleaned.append(source[index])
        index += 1
    if quote:
        raise ValueError("unterminated Cedar string")
    return frozenset(re.findall(r"\b(permit|forbid)\s*\(", "".join(cleaned)))


def _identity(value: str) -> NormalizedObject:
    _atom(value, "identity-normalized object")
    return NormalizedObject(value)


def _fs_realpath(value: str) -> NormalizedObject:
    _text(value, "filesystem path")
    try:
        resolved = Path(value).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("path does not exist or cannot be resolved") from exc
    return NormalizedObject(os.fspath(resolved))


def _sql_table_ref(value: str) -> NormalizedObject:
    match = _TABLE_REF.fullmatch(value.strip())
    if match is None:
        raise ValueError("SQL table reference must be an unquoted [schema.]table")
    schema = (match.group("schema") or "public").lower()
    table = match.group("table").lower()
    return NormalizedObject(f"{schema}.{table}", {"schema": schema})


def _mail_domain(value: str) -> NormalizedObject:
    address = value.strip()
    if address.count("@") != 1:
        raise ValueError("mail object must contain one @")
    local, domain = address.rsplit("@", 1)
    if not local or not domain or any(character.isspace() for character in address):
        raise ValueError("mail object is invalid")
    return NormalizedObject(
        domain.lower().rstrip("."), {"domain": domain.lower().rstrip(".")}
    )


_BUILTIN_NORMALIZERS: Mapping[str, ObjectNormalizer] = MappingProxyType(
    {
        "fs.realpath": _fs_realpath,
        "identity": _identity,
        "mail.domain": _mail_domain,
        "sql.table_ref": _sql_table_ref,
    }
)


def _bind(template: str, values: Mapping[str, object]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise ObjectPolicyDenied(f"missing_binding:{name}")
        value = str(values[name])
        _text(value, f"binding {name}")
        return value

    result = _VARIABLE.sub(replace, template)
    _validate_template(result)
    return result


def _validate_template(value: str) -> None:
    if "@{" in _VARIABLE.sub("", value) or "}" in _VARIABLE.sub("", value):
        raise ValueError(f"malformed object pattern: {value!r}")


def _text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or _CONTROL.search(value):
        raise ValueError(f"{label} must be non-empty text without controls")


def _atom(value: str, label: str) -> None:
    _text(value, label)
    if any(character.isspace() for character in value):
        raise ValueError(f"{label} must not contain whitespace")


def _cedar(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _entity_literal(entity_type: str, entity_id: str) -> str:
    return f'{entity_type}::"{_cedar(entity_id)}"'


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _resolve_executable(executable: str) -> str | None:
    if os.path.sep in executable:
        path = Path(executable)
        return os.fspath(path) if path.is_file() and os.access(path, os.X_OK) else None
    return shutil.which(executable)


def _engine_identity(executable: str) -> tuple[str, int, int, int, int, int] | None:
    """Bind cached Cedar results to the exact executable that produced them."""
    try:
        status = os.stat(executable)
    except OSError:
        return None
    return (
        executable,
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _cedar_cache_key(
    engine: tuple[str, int, int, int, int, int],
    operation: str,
    *inputs: str,
) -> str:
    """Identify a Cedar result by engine, operation, and every semantic input."""
    return hashlib.sha256(
        _json({"engine": engine, "operation": operation, "inputs": inputs}).encode()
    ).hexdigest()


__all__ = (
    "CedarObjectAuthorizer",
    "CedarPolicySet",
    "CedarCallPolicy",
    "EnforcementKind",
    "ManifestRule",
    "NormalizedObject",
    "ObjectClass",
    "ObjectClassEnforcer",
    "ObjectClassRegistry",
    "ObjectGrant",
    "ObjectGrantDispatcher",
    "ObjectGrantLine",
    "ObjectNormalizer",
    "ObjectPolicyDenied",
    "ObjectPolicyHostExecutor",
    "ObjectSandboxDispatcher",
    "SecurityManifest",
    "ToolManifest",
    "cedar_security",
    "parse_security_manifest",
)
