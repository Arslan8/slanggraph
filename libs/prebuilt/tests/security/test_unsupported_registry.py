"""Every unsupported gate code has a structured, payload-free record."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from langgraph.prebuilt.security import unsupported
from langgraph.prebuilt.security.objects import (
    LabeledValue,
    OutputRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.output_data import OutputDataError
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import Principal, Verdict
from langgraph.prebuilt.security.unsupported import (
    PREFIXES,
    REGISTRY,
    RefusalCategory,
    UnsupportedFeatureError,
    admission_message,
    describe,
    output_message,
    output_refusal_reason,
    runtime_message,
)

PACKAGE = Path(unsupported.__file__).parent

# Literals the scan finds that are demonstrably not refusal codes. Each entry
# names one literal and the reason it never reaches a `Decision` or exception.
NOT_REFUSAL_CODES: dict[str, str] = {
    "linux_adapter_unsupported": (
        "SupportAssessment reason label; EnforcementCoordinator._supporting "
        "drops UNSUPPORTED assessments and surfaces adapter_rule_unsupported:"
    ),
    "path_obligation_kind_unsupported": (
        "SupportAssessment reason label from _assess_path_obligation; never "
        "surfaced, the negotiation reason is adapter_rule_unsupported:"
    ),
    "path_operation_unsupported": (
        "SupportAssessment reason label from _assess_path_obligation; never "
        "surfaced, the negotiation reason is adapter_rule_unsupported:"
    ),
    "resource_limit_mechanism_unsupported": (
        "SupportAssessment reason label from _assess_limit_obligation; never "
        "surfaced, the negotiation reason is adapter_rule_unsupported:"
    ),
    "unsupported_expression": (
        "suffix passed to language_verification.reject(), which raises the "
        "registered code language_proof:unsupported_expression"
    ),
    "unsupported_statement": (
        "suffix passed to language_verification.reject(), which raises the "
        "registered code language_proof:unsupported_statement"
    ),
}


def _is_candidate(text: str) -> bool:
    return "unsupported" in text and " " not in text and (":" in text or "_" in text)


def _scan() -> tuple[dict[str, set[str]], set[str]]:
    """Return candidate literals by site and every `OutputDataError` code."""
    literals: dict[str, set[str]] = {}
    output_codes: set[str] = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name == "unsupported.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            text: str | None = None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.JoinedStr) and node.values:
                head = node.values[0]
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    text = head.value
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "OutputDataError"
            ):
                for arg in node.args:
                    assert isinstance(arg, ast.Constant), path
                    output_codes.add(arg.value)
            if text is not None and _is_candidate(text):
                site = f"{path.relative_to(PACKAGE)}:{node.lineno}"
                literals.setdefault(text, set()).add(site)
    return literals, output_codes


def test_every_unsupported_literal_is_registered_or_explained():
    literals, _ = _scan()
    assert "output_data:unsupported_type" in literals
    assert "mac:unsupported_dispatcher" in literals
    assert "adapter_rule_unsupported:" in literals
    unexplained = {
        text: sorted(sites)
        for text, sites in literals.items()
        if text not in REGISTRY
        and text not in PREFIXES
        and text not in NOT_REFUSAL_CODES
    }
    assert not unexplained, f"unregistered refusal literals: {unexplained}"
    ambiguous = {
        text
        for text in literals
        if (text in REGISTRY) + (text in PREFIXES) + (text in NOT_REFUSAL_CODES) > 1
    }
    assert not ambiguous
    stale = sorted(set(NOT_REFUSAL_CODES) - set(literals))
    assert not stale, f"NOT_REFUSAL_CODES entries without a site: {stale}"


def test_every_output_data_error_code_is_registered():
    _, output_codes = _scan()
    assert "output_data:payload_confidentiality" in output_codes
    missing = sorted(output_codes - set(REGISTRY))
    assert not missing, f"unregistered output refusal codes: {missing}"


def test_prefix_records_are_consistent():
    for prefix, record in PREFIXES.items():
        assert prefix.endswith(":")
        assert prefix[:-1] == record.code
        assert isinstance(record.category, RefusalCategory)
        assert record.phase in ("admission", "runtime")
        assert record.feature and record.route and record.reason
        if record.code in REGISTRY:
            assert REGISTRY[record.code] is record
    for prefix in (
        "adapter_rule_unsupported:",
        "object_constraints_unsupported:",
        "unsupported:",
        "unsupported_class:",
    ):
        assert PREFIXES[prefix].category is RefusalCategory.UNSUPPORTED
        assert PREFIXES[prefix].code not in REGISTRY
    assert PREFIXES["host:unsupported_rule:"] is REGISTRY["host:unsupported_rule"]


def test_registry_records_are_consistent():
    for code, record in REGISTRY.items():
        assert record.code == code
        assert isinstance(record.category, RefusalCategory)
        assert record.phase in ("admission", "runtime")
        assert record.feature and record.route and record.reason
    assert (
        REGISTRY["output_data:payload_confidentiality"].category
        is RefusalCategory.POLICY_DENIED
    )
    assert (
        REGISTRY["output_data:payload_integrity"].category
        is RefusalCategory.POLICY_DENIED
    )
    for name in ("budget", "depth", "cycle", "invalid_layout", "record_shape"):
        assert REGISTRY[f"output_data:{name}"].category is RefusalCategory.UNSUPPORTED
    for code in (
        "host:special_resource_unsupported",
        "inprocess:descriptor_read_unsupported",
        "inprocess:descriptor_write_unsupported",
        "object_policy:typed_constraints_unsupported",
        "admission:unsupported_node_body",
        "admission:unsupported_branch",
        "admission:descriptor_changed",
        "admission:unsupported_async",
        "admission:closed_admission_required",
    ):
        assert REGISTRY[code].category is RefusalCategory.UNSUPPORTED
        assert REGISTRY[code].phase == "runtime"


def test_describe_accepts_only_exact_registered_strings():
    assert (
        describe("mac:unsupported_dispatcher") is REGISTRY["mac:unsupported_dispatcher"]
    )
    assert describe("mac:unknown") is None
    assert describe("adapter_rule_unsupported:rule:1") is None
    assert describe("adapter_rule_unsupported") is None

    class Code(str):
        pass

    assert describe(Code("mac:unsupported_dispatcher")) is None
    assert describe(None) is None  # type: ignore[arg-type]


def test_message_templates_are_exact():
    record = REGISTRY["mac:unsupported_dispatcher"]
    assert admission_message(record) == (
        f"Unsupported feature: {record.feature}. slangGraph does not support "
        f"this feature in {record.route} yet, so this configuration was not "
        "admitted. Please open an issue with a minimal example and the "
        "capability you need, so support can be considered for a future release."
    )
    assert runtime_message(record) == (
        f"Unsupported operation: {record.feature}. slangGraph blocked this "
        "operation before its protected effect. Earlier authorized operations "
        "may already have completed. Please open an issue with a minimal example "
        "and the capability you need."
    )
    output = output_message(REGISTRY["output_data:unsupported_type"])
    assert "blocked publication" in output
    assert "may already have completed" in output
    for message in (admission_message(record), runtime_message(record), output):
        assert "http" not in message
    url = "https://example.invalid/issues"
    assert admission_message(record, url).endswith(f" Issue tracker: {url}")
    assert runtime_message(record, url).endswith(f" Issue tracker: {url}")


def test_messages_never_contain_payloads():
    secret = "sk-test-SECRET-payload"
    exc = OutputDataError("output_data:unsupported_type")
    exc.payload = secret  # type: ignore[attr-defined]
    for record in (*REGISTRY.values(), *PREFIXES.values()):
        for render in (admission_message, runtime_message, output_message):
            assert secret not in render(record)
    assert secret not in output_refusal_reason(exc, OutputDataError)


def test_unsupported_feature_error_keeps_code_as_text():
    error = UnsupportedFeatureError("mac:unsupported_authorizer")
    assert isinstance(error, PermissionError)
    assert str(error) == "mac:unsupported_authorizer"
    assert error.args == ("mac:unsupported_authorizer",)
    assert error.code == "mac:unsupported_authorizer"
    assert error.record is REGISTRY["mac:unsupported_authorizer"]
    with pytest.raises(PermissionError, match="mac:unsupported_authorizer"):
        raise error
    assert UnsupportedFeatureError("mac:other").record is None


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (
            OutputDataError("output_data:unsupported_type"),
            "unsupported:output_data:unsupported_type",
        ),
        (OutputDataError("output_data:budget"), "unsupported:output_data:budget"),
        (
            OutputDataError("output_data:payload_confidentiality"),
            "denied:output:policy",
        ),
        (OutputDataError("output_data:payload_integrity"), "denied:output:policy"),
        (OutputDataError("arbitrary attacker text"), "unsupported:output:unknown"),
        (OutputDataError(), "unsupported:output:unknown"),
        (OutputDataError(["output_data:budget"]), "unsupported:output:unknown"),
        (PermissionError("output_data:budget"), "unsupported:output:unknown"),
        (TypeError("anything"), "unsupported:output:type_error"),
    ],
)
def test_output_refusal_reason_uses_fixed_table(exc, expected):
    assert output_refusal_reason(exc, OutputDataError) == expected


def test_output_refusal_reason_rejects_subclasses():
    class Sub(OutputDataError):
        pass

    assert (
        output_refusal_reason(Sub("output_data:budget"), OutputDataError)
        == "unsupported:output:unknown"
    )


def _principal() -> Principal:
    return Principal("alice", frozenset({"user"}), frozenset(), "session")


async def _authorize(request: OutputRequest, asynchronous: bool):
    stack = SecurityStack(())
    try:
        if asynchronous:
            return await stack.aobject_permission(_principal(), request)
        return stack.object_permission(_principal(), request)
    finally:
        stack.close()


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_stack_refuses_unsupported_output_content_with_fixed_reason(
    asynchronous,
):
    request = OutputRequest("test", {"alpha", "beta"}, output_id="out-1")
    authorization = await _authorize(request, asynchronous)
    assert authorization.decision.verdict is Verdict.DENY
    assert authorization.decision.reason == "unsupported:output_data:unsupported_type"
    assert authorization.request is request


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_stack_collapses_output_label_escape_to_policy_denial(asynchronous):
    nested = LabeledValue("secret", "sk-live", SecurityLabels(frozenset({"secret"})))
    request = OutputRequest(
        "test",
        {"value": nested},
        labels=SecurityLabels(frozenset()),
        output_id="out-2",
    )
    authorization = await _authorize(request, asynchronous)
    assert authorization.decision.verdict is Verdict.DENY
    assert authorization.decision.reason == "denied:output:policy"
    assert "secret" not in authorization.decision.reason
    assert "sk-live" not in authorization.decision.reason
