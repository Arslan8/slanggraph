"""Structured outcomes for unsupported features, policy denials and failures.

Every outcome here stops the operation. A record only explains a refusal; it
never selects a fallback, downgrades enforcement or lets an approval override
an unsupported mechanism. Diagnostics carry fixed codes and fixed text, never
credentials or candidate payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Literal


class RefusalCategory(str, Enum):
    """Why an operation stopped. Every category is a refusal."""

    UNSUPPORTED = "unsupported"
    POLICY_DENIED = "policy_denied"
    EXECUTION_FAILED = "execution_failed"


Phase = Literal["admission", "runtime"]


@dataclass(frozen=True, slots=True)
class UnsupportedFeature:
    """One stable refusal code and its fixed, payload-free description."""

    code: str
    category: RefusalCategory
    feature: str
    route: str
    reason: str
    phase: Phase


# Category defaults below are pending advisor confirmation. Shape, type and
# record codes are unsupported. Budget, depth and cycle codes are unsupported
# because they fall outside the supported bounded projection. Payload label
# codes are policy denials. Changing a category never changes the verdict:
# every code in this table stops the operation.
_U = RefusalCategory.UNSUPPORTED
_P = RefusalCategory.POLICY_DENIED

_OUTPUT_ROUTE = "output publication"
_DATASET_ROUTE = "runtime dataset read"
_OUTPUT_DATA = (
    ("budget", "output exceeding the bounded projection budget", _U),
    ("depth", "output nested beyond the bounded projection depth", _U),
    ("cycle", "cyclic output data", _U),
    ("string_required", "non-string output identifier or label", _U),
    ("native_dictionary_required", "non-native dictionary in output", _U),
    ("string_key_required", "non-string dictionary key in output", _U),
    ("native_string_set_required", "non-native label or clearance set", _U),
    ("labels_required", "output without native security labels", _U),
    ("nonfinite_float", "non-finite float in output", _U),
    ("interrupt_schema", "unrecognized interrupt record in output", _U),
    ("uuid", "non-native UUID in output", _U),
    ("record_shape", "unrecognized record shape in output", _U),
    ("model_extra", "model with extra fields in output", _U),
    ("model_private", "model with private attributes in output", _U),
    ("live_exception", "live exception object in output", _U),
    ("unsupported_type", "unsupported value type in output", _U),
    ("invalid_layout", "output request with an invalid native layout", _U),
    ("request_required", "non-native output request", _U),
    ("state_shape", "unrecognized state layout for output labeling", _U),
    ("state_key", "unrecognized state key for output labeling", _U),
    ("state_value", "unlabeled state value for output labeling", _U),
    ("payload_confidentiality", "output payload above declared labels", _P),
    ("payload_integrity", "low-integrity payload labeled trusted", _P),
)

_ENTRIES: tuple[UnsupportedFeature, ...] = (
    *(
        UnsupportedFeature(
            f"output_data:{name}", category, feature, _OUTPUT_ROUTE, name, "runtime"
        )
        for name, feature, category in _OUTPUT_DATA
    ),
    UnsupportedFeature(
        "output:unsupported_data",
        _U,
        "output data outside the supported projection",
        _OUTPUT_ROUTE,
        "output validator refused the data",
        "runtime",
    ),
    UnsupportedFeature(
        "output:unsupported_mediator",
        _U,
        "subclassed or replaced output mediator",
        _OUTPUT_ROUTE,
        "only the exact output mediator is supported",
        "runtime",
    ),
    UnsupportedFeature(
        "output:unsupported_router",
        _U,
        "subclassed or replaced host router",
        _OUTPUT_ROUTE,
        "only the exact host router is supported",
        "runtime",
    ),
    UnsupportedFeature(
        "host:missing_security_context",
        _U,
        "host tool execution without a bound security context",
        "host tool execution",
        "secured execution requires the bound security context",
        "runtime",
    ),
    UnsupportedFeature(
        "host:missing_router",
        _U,
        "host tool execution without a configured host router",
        "host tool execution",
        "secured execution requires the configured host router",
        "runtime",
    ),
    UnsupportedFeature(
        "host:artifact_changed",
        _P,
        "tool artifact bytes changed between verification and use",
        "isolated worker",
        "the pinned artifact must be byte-identical at activation",
        "runtime",
    ),
    UnsupportedFeature(
        "output:unsupported_host",
        _U,
        "subclassed or replaced object manager host",
        _OUTPUT_ROUTE,
        "only the exact object manager host is supported",
        "runtime",
    ),
    UnsupportedFeature(
        "unsupported:output:unknown",
        _U,
        "unrecognized output refusal",
        _OUTPUT_ROUTE,
        "output refusal without a registered code",
        "runtime",
    ),
    UnsupportedFeature(
        "unsupported:output:type_error",
        _U,
        "output request with an invalid principal or type",
        _OUTPUT_ROUTE,
        "output validation raised a type error",
        "runtime",
    ),
    UnsupportedFeature(
        "object:unsupported_request",
        _U,
        "non-native framework request",
        "framework object authorization",
        "only exact native request records are supported",
        "runtime",
    ),
    UnsupportedFeature(
        "state:unsupported_operation",
        _U,
        "unrecognized state operation",
        "object manager state mediation",
        "operation is not a supported state operation",
        "runtime",
    ),
    UnsupportedFeature(
        "resource:unsupported_inprocess_binding",
        _U,
        "in-process resource binding without exact enforcement",
        "in-process resource mediation",
        "adapter support is not exact or needs host capabilities",
        "runtime",
    ),
    UnsupportedFeature(
        "container:unsupported_authority",
        _U,
        "container grant line other than kernel-enforced file read",
        "container object dispatch",
        "container dispatch only supports kernel-enforced file reads",
        "runtime",
    ),
    UnsupportedFeature(
        "linux_object:unsupported_authority",
        _U,
        "Cedar object grant outside exact kernel-enforced file operations",
        "Linux object dispatch",
        "Linux object dispatch supports canonical regular-file reads and complete writable grants",
        "runtime",
    ),
    UnsupportedFeature(
        "host:unsupported_rule",
        _U,
        "grant rule without a host lowering",
        "Linux host execution",
        "no supported lowering exists for the rule",
        "runtime",
    ),
    UnsupportedFeature(
        "wasi:unsupported_rule",
        _U,
        "grant rule without a WASI lowering",
        "WASI host execution",
        "no supported lowering exists for the rule",
        "runtime",
    ),
    UnsupportedFeature(
        "mac:unsupported_execution_boundary",
        _U,
        "execution boundary other than a compiled graph or tool node",
        "mandatory access control",
        "MAC admits only compiled state graphs and tool nodes",
        "admission",
    ),
    UnsupportedFeature(
        "mac:unsupported_authorizer",
        _U,
        "object authorizer other than the Cedar object authorizer",
        "mandatory access control",
        "MAC admits only the Cedar object authorizer",
        "admission",
    ),
    UnsupportedFeature(
        "mac:unsupported_dispatcher",
        _U,
        "object dispatcher without a confined execution route",
        "mandatory access control",
        "MAC admits only confined object dispatchers",
        "admission",
    ),
    UnsupportedFeature(
        "language_sandbox:unsupported_expression",
        _U,
        "expression outside the language sandbox subset",
        "language sandbox",
        "expression kind is not in the supported subset",
        "admission",
    ),
    UnsupportedFeature(
        "language_sandbox:unsupported_statement",
        _U,
        "statement outside the language sandbox subset",
        "language sandbox",
        "statement kind is not in the supported subset",
        "admission",
    ),
    UnsupportedFeature(
        "language_proof:unsupported_expression",
        _U,
        "expression outside the language proof subset",
        "language sandbox verification",
        "expression kind is not in the verified subset",
        "admission",
    ),
    UnsupportedFeature(
        "language_proof:unsupported_statement",
        _U,
        "statement outside the language proof subset",
        "language sandbox verification",
        "statement kind is not in the verified subset",
        "admission",
    ),
    UnsupportedFeature(
        "host:special_resource_unsupported",
        _U,
        "pinned resource that is neither a regular file nor a directory",
        "Linux host execution",
        "descriptor binding supports only regular files and directories",
        "runtime",
    ),
    UnsupportedFeature(
        "inprocess:descriptor_read_unsupported",
        _U,
        "descriptor-pinned resource read outside Linux",
        "in-process resource mediation",
        "descriptor reads require Linux openat2 without a pathname fallback",
        "runtime",
    ),
    UnsupportedFeature(
        "object_policy:typed_constraints_unsupported",
        _U,
        "typed policy constraints on an object policy invocation",
        "object policy authorization",
        "object policy grants cannot carry typed constraints",
        "runtime",
    ),
    UnsupportedFeature(
        "object_policy:dispatcher_prewarm_unsupported",
        _U,
        "worker preflight on a dispatcher without a pool implementation",
        "object policy authorization",
        "the selected dispatcher does not implement exact-policy worker preflight",
        "runtime",
    ),
    *(
        UnsupportedFeature(
            f"admission:{name}",
            _U,
            "closed node/effect admission",
            "secured graph compilation/dispatch",
            reason,
            "runtime",
        )
        for name, reason in (
            ("unsupported_node_body", "node body is outside the admitted subset"),
            ("unsupported_branch", "branch is outside the admitted subset"),
            ("descriptor_changed", "admitted descriptor no longer matches the node"),
            ("unsupported_async", "asynchronous node body is not admitted"),
            ("closed_admission_required", "node runs without closed admission"),
            (
                "unsupported_callback",
                "graph-author reducer, cache key or retry predicate is outside the admitted inventory",
            ),
        )
    ),
    UnsupportedFeature(
        "output:missing_framework_envelope",
        _U,
        "stream output without the framework envelope",
        _OUTPUT_ROUTE,
        "stream publication requires the private framework envelope",
        "runtime",
    ),
    UnsupportedFeature(
        "host:lean_async_route_unavailable",
        _U,
        "asynchronous Linux route with the Lean checker selected",
        "isolated worker",
        "the Lean-checked route is synchronous only",
        "runtime",
    ),
    UnsupportedFeature(
        "mac:tool_requires_object_authorization",
        _U,
        "tool node without object authorization under runtime MAC",
        "secured graph compilation/dispatch",
        "runtime MAC admits only object-authorized tool nodes",
        "admission",
    ),
    UnsupportedFeature(
        "broker:unavailable",
        RefusalCategory.EXECUTION_FAILED,
        "resource broker unavailable for a brokered obligation",
        "isolated worker",
        "brokered grants require a reachable broker",
        "runtime",
    ),
    UnsupportedFeature(
        "language_proof:arguments_must_be_strings",
        _U,
        "language-sandbox terminal call with non-string arguments",
        "language sandbox",
        "the admitted language passes only exact strings",
        "admission",
    ),
    UnsupportedFeature(
        "manifest_consistency:async_tool_requires_ainvoke",
        _U,
        "asynchronous tool manifest without an ainvoke implementation",
        "language sandbox",
        "asynchronous admission requires a native ainvoke",
        "admission",
    ),
    # Runtime `dataset_read` (dataset_operation.py). A changed dataset is a
    # policy denial, like `host:artifact_changed`: the bytes, path or file
    # type no longer match what the operator pinned, so the authorized object
    # is not the one present; it is not a transient mechanism failure.
    UnsupportedFeature(
        "dataset:unknown",
        _U,
        "dataset id absent from the operator dataset registry",
        _DATASET_ROUTE,
        "only operator-registered dataset ids can be read",
        "runtime",
    ),
    UnsupportedFeature(
        "dataset:denied",
        _P,
        "dataset read without an exact policy allow",
        _DATASET_ROUTE,
        "policy did not return an unconstrained ALLOW for this dataset",
        "runtime",
    ),
    UnsupportedFeature(
        "dataset:too_large",
        _U,
        "dataset larger than its registered byte cap",
        _DATASET_ROUTE,
        "the read stops at the operator-pinned maximum size",
        "runtime",
    ),
    UnsupportedFeature(
        "dataset:changed",
        _P,
        "dataset whose path, file type or digest differs from its pin",
        _DATASET_ROUTE,
        "the pinned path must be a symlink-free regular file with the pinned sha256",
        "runtime",
    ),
    UnsupportedFeature(
        "dataset:unavailable",
        RefusalCategory.EXECUTION_FAILED,
        "dataset file or descriptor read mechanism unavailable",
        _DATASET_ROUTE,
        "the pinned file could not be opened or read through openat2",
        "runtime",
    ),
)

REGISTRY: MappingProxyType[str, UnsupportedFeature] = MappingProxyType(
    {entry.code: entry for entry in _ENTRIES}
)

# Codes completed at the refusal site by a dynamic suffix such as an
# obligation, rule, module or class identifier. The record describes the
# prefix; the suffix only names which item was refused. Prefixes that extend
# an exact registered code share that code's record.
_PREFIX_ENTRIES: tuple[UnsupportedFeature, ...] = (
    UnsupportedFeature(
        "adapter_rule_unsupported",
        _U,
        "enforcement obligation without a supporting adapter",
        "host enforcement negotiation",
        "no adapter supports the obligation and no waiver covers it",
        "runtime",
    ),
    UnsupportedFeature(
        "object_constraints_unsupported",
        _U,
        "typed constraints on a framework object decision",
        "framework object authorization",
        "object decisions cannot carry typed constraints",
        "runtime",
    ),
    UnsupportedFeature(
        "unsupported",
        _U,
        "object grant line without a supporting enforcer",
        "object policy authorization",
        "the declared enforcer does not support the class operation",
        "runtime",
    ),
    UnsupportedFeature(
        "unsupported_class",
        _U,
        "object class whose declared enforcer is unregistered",
        "object policy admission",
        "no enforcer is registered for the class",
        "admission",
    ),
    REGISTRY["host:unsupported_rule"],
    REGISTRY["wasi:unsupported_rule"],
    REGISTRY["language_sandbox:unsupported_expression"],
    REGISTRY["language_sandbox:unsupported_statement"],
)

PREFIXES: MappingProxyType[str, UnsupportedFeature] = MappingProxyType(
    {f"{entry.code}:": entry for entry in _PREFIX_ENTRIES}
)


def describe(code: str) -> UnsupportedFeature | None:
    """Return the record for an exact registered code, or `None`."""
    if type(code) is not str:
        return None
    return REGISTRY.get(code)


def _issue_suffix(issue_url: str | None) -> str:
    return f" Issue tracker: {issue_url}" if issue_url else ""


def admission_message(record: UnsupportedFeature, issue_url: str | None = None) -> str:
    """Render the fixed admission-time refusal message."""
    return (
        f"Unsupported feature: {record.feature}. slangGraph does not support "
        f"this feature in {record.route} yet, so this configuration was not "
        "admitted. Please open an issue with a minimal example and the "
        "capability you need, so support can be considered for a future "
        "release." + _issue_suffix(issue_url)
    )


def runtime_message(record: UnsupportedFeature, issue_url: str | None = None) -> str:
    """Render the fixed runtime refusal message."""
    return (
        f"Unsupported operation: {record.feature}. slangGraph blocked this "
        "operation before its protected effect. Earlier authorized operations "
        "may already have completed. Please open an issue with a minimal "
        "example and the capability you need." + _issue_suffix(issue_url)
    )


def output_message(record: UnsupportedFeature, issue_url: str | None = None) -> str:
    """Render the fixed output refusal message; publication, not computation."""
    return (
        f"Unsupported output: {record.feature}. slangGraph blocked publication "
        "of this output. The computation that produced it may already have "
        "completed. Please open an issue with a minimal example and the "
        "capability you need." + _issue_suffix(issue_url)
    )


def output_refusal_reason(exc: BaseException, output_error: type) -> str:
    """Map an output validator exception to a fixed caller-facing reason.

    Only an exact `output_error` instance whose first argument is an exact
    registered string is mapped. Policy denials collapse to one generic reason
    so the recipient does not learn which label class tripped.
    """
    if type(exc) is TypeError:
        return "unsupported:output:type_error"
    if type(exc) is not output_error or not exc.args:
        return "unsupported:output:unknown"
    record = describe(exc.args[0])
    if record is None:
        return "unsupported:output:unknown"
    if record.category is RefusalCategory.POLICY_DENIED:
        return "denied:output:policy"
    return f"unsupported:{record.code}"


class UnsupportedFeatureError(PermissionError):
    """A refusal whose `args[0]` stays the stable code string."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.record = describe(code)

    @property
    def code(self) -> str:
        return self.args[0]
