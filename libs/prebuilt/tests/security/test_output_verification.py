"""Output correspondence derivations; candidate source is never executed."""

import ast
from pathlib import Path

import pytest

from langgraph.prebuilt.security.output_verification import verify_output_correspondence

_ROOT = Path(__file__).resolve().parents[2] / "langgraph/prebuilt/security"


def actual_sources():
    return (_ROOT / "object_manager.py").read_text(), (_ROOT / "objects.py").read_text()


def change_method(source, name, body):
    tree = ast.parse(source)
    host = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ObjectManagerHost"
    )
    method = next(
        node
        for node in host.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    method.body = ast.parse(body).body
    return ast.unparse(ast.fix_missing_locations(tree))


GOOD = """
with self._lock:
    if isinstance(request, OutputRequest):
        if not request.labels.confidentiality.issubset(request.clearance):
            raise PermissionError('output:clearance')
        return request.content
raise TypeError('unsupported request')
"""


def fixture_sources():
    """Explicit clearance/return fixture, not a production-dispatch certificate.

    The current production dispatch also invokes a recursive data validator.
    Its unproved source theorem is covered by a separate actual-source check.
    """
    host, objects = actual_sources()
    return change_method(host, "dispatch", GOOD), objects


def test_source_fixture_sync_and_async_outputs_have_conditional_correspondence():
    report = verify_output_correspondence(*fixture_sources())
    assert report["proved"], report
    assert not report["system_complete"]
    assert not report["runtime_binding_proved"]
    assert report["entry_premises"] and report["remaining_composition"]
    assert len(report["entries"]) == 2
    for entry in report["entries"]:
        assert entry["normal_returns"] == 1
        assert entry["refusals"] == 1
        for path in entry["paths"]:
            if path["exit"] == "return":
                assert path["result"] == ["request", "content"]
                assert path["clearance"] is True
            else:
                assert path["clearance"] is False
    assert report["forwardings"]


@pytest.mark.parametrize(
    "body",
    [
        GOOD.replace(
            "return request.content",
            "value = request.content\n        alias = value\n        return alias",
        ),
        GOOD.replace(
            "if not request.labels.confidentiality.issubset(request.clearance):\n            raise PermissionError('output:clearance')\n        return request.content",
            "if request.labels.confidentiality.issubset(request.clearance):\n            return request.content\n        raise PermissionError('output:clearance')",
        ),
        "alias = request\n"
        + GOOD.replace("isinstance(request", "isinstance(alias")
        .replace("request.labels", "alias.labels")
        .replace("request.clearance", "alias.clearance")
        .replace("request.content", "alias.content"),
    ],
)
def test_equivalent_alias_and_guard_derivations_pass(body):
    host, objects = fixture_sources()
    assert verify_output_correspondence(change_method(host, "dispatch", body), objects)[
        "proved"
    ]


@pytest.mark.parametrize(
    "body",
    [
        GOOD.replace("return request.content", "return request"),
        GOOD.replace("return request.content", "return principal"),
        GOOD.replace("return request.content", "return 'replacement'"),
        GOOD.replace("return request.content", "return (request.content, principal)"),
        GOOD.replace(
            "if not request.labels.confidentiality.issubset(request.clearance):",
            "if request.labels.confidentiality.issubset(request.clearance):",
        ),
        GOOD.replace(
            "if not request.labels.confidentiality.issubset(request.clearance):",
            "if False:",
        ),
        GOOD.replace(
            "request.labels.confidentiality.issubset(request.clearance)",
            "request.clearance.issubset(request.labels.confidentiality)",
        ),
        GOOD.replace(
            "return request.content",
            "request.content = principal\n        return request.content",
        ),
        GOOD.replace(
            "raise PermissionError('output:clearance')",
            "raise PermissionError(request.content)",
        ),
        GOOD.replace("with self._lock:", "with request.content:"),
        "publish(request.content)\n" + GOOD,
        "OutputRequest = request\n" + GOOD,
        "raise PermissionError('all disabled')",
    ],
)
def test_bad_projection_clearance_effect_or_refusal_blocks_derivation(body):
    host, objects = fixture_sources()
    report = verify_output_correspondence(
        change_method(host, "dispatch", body), objects
    )
    assert not report["proved"], report
    assert report["issues"]


@pytest.mark.parametrize(
    "body",
    [
        "return self.dispatch(request, principal)",
        "return self.dispatch(principal, principal)",
        "return await self.dispatch(principal, request)",
        "self.dispatch(principal, request)\nreturn request.content",
        "return self.other(principal, request)",
    ],
)
def test_async_forwarding_requires_source_implementation_and_original_inputs(body):
    host, objects = fixture_sources()
    report = verify_output_correspondence(
        change_method(host, "adispatch", body), objects
    )
    assert not report["proved"], report


def test_async_local_aliases_are_analyzed_without_an_opaque_helper_exemption():
    host, objects = fixture_sources()
    changed = change_method(
        host,
        "adispatch",
        "call = self.dispatch\nvalue = call(principal, request)\nreturn value",
    )
    assert verify_output_correspondence(changed, objects)["proved"]


@pytest.mark.parametrize(
    "change",
    [
        lambda text: text.replace(
            "class OutputRequest:", "class OutputRequest(StateRequest):"
        ),
        lambda text: text.replace(
            "class OutputRequest:", "class OutputRequest(metaclass=Unknown):"
        ),
        lambda text: text.replace(
            "class SecurityLabels:",
            "class SecurityLabels:\n    def __getattribute__(self, name):\n        return 'changed'",
        ),
        lambda text: text.replace(
            "@dataclass(frozen=True, slots=True)",
            "@dataclass(frozen=False, slots=True)",
        ),
        lambda text: text + "\nOutputRequest = StateRequest\n",
    ],
)
def test_request_classification_and_native_projection_layout_need_source_evidence(
    change,
):
    host, objects = fixture_sources()
    report = verify_output_correspondence(host, change(objects))
    assert not report["proved"], report


def test_host_descriptor_or_builtin_rebinding_invalidates_native_semantics():
    host, objects = fixture_sources()
    assert not verify_output_correspondence(host + "\nisinstance = None\n", objects)[
        "proved"
    ]
    changed = host.replace(
        "class ObjectManagerHost:",
        "class ObjectManagerHost:\n    @property\n    def _lock(self):\n        return unknown()",
    )
    assert not verify_output_correspondence(changed, objects)["proved"]


@pytest.mark.parametrize("name", ["isinstance", "OutputRequest", "PermissionError"])
def test_later_local_assignment_cannot_use_a_global_classifier_or_exception(name):
    host, objects = fixture_sources()
    body = GOOD + f"\n{name} = None\n"
    assert not verify_output_correspondence(
        change_method(host, "dispatch", body), objects
    )["proved"]


def test_hidden_module_heap_rebinding_is_not_a_native_binding_premise():
    host, objects = fixture_sources()
    assert not verify_output_correspondence(
        host + "\nglobals()['isinstance'] = replacement\n", objects
    )["proved"]


def test_other_request_branches_are_explicitly_outside_this_component():
    host, objects = fixture_sources()
    body = GOOD.replace(
        "    if isinstance(request, OutputRequest):",
        "    if isinstance(request, DispatchRequest):\n        return unverified_other_operation(request)\n    if isinstance(request, OutputRequest):",
    )
    changed = change_method(host, "dispatch", body)
    report = verify_output_correspondence(changed, objects)
    assert report["proved"], report
    assert not report["system_complete"]
    assert any(
        "every other request kind" in item for item in report["remaining_composition"]
    )


def test_unknown_candidate_code_is_not_executed(tmp_path):
    host, objects = fixture_sources()
    marker = tmp_path / "executed"
    changed = change_method(
        host,
        "dispatch",
        f"__import__('pathlib').Path({str(marker)!r}).write_text('bad')\n" + GOOD,
    )
    assert not verify_output_correspondence(changed, objects)["proved"]
    assert not marker.exists()


def test_hashes_bind_sources_and_unknown_or_exhausted_analysis_never_passes():
    host, objects = fixture_sources()
    before = verify_output_correspondence(host, objects)
    after = verify_output_correspondence(host + "\n# changed source\n", objects)
    assert before["source_sha256"] != after["source_sha256"]
    assert not verify_output_correspondence(host, objects, max_steps=1)["proved"]
    assert not verify_output_correspondence("syntax error (", objects)["proved"]
    assert not verify_output_correspondence("", "")["proved"]


@pytest.mark.parametrize(
    ("imports", "annotation"),
    [
        ("from typing import ClassVar", "ClassVar[Any]"),
        ("from typing import ClassVar as CV", "CV[Any]"),
        ("import typing", "typing.ClassVar[Any]"),
        ("from dataclasses import InitVar", "InitVar[Any]"),
        ("from dataclasses import InitVar as IV", "IV[Any]"),
        ("from typing import ClassVar", "'ClassVar[Any]'"),
        ("from typing import ClassVar\nAlias = ClassVar", "Alias[Any]"),
    ],
)
def test_pseudo_fields_and_unresolved_annotation_aliases_are_not_native_slots(
    imports, annotation
):
    host, objects = fixture_sources()
    changed = objects.replace(
        "from typing import Any", "from typing import Any\n" + imports
    )
    changed = changed.replace("content: Any", "content: " + annotation)
    report = verify_output_correspondence(host, changed)
    assert not report["proved"], report


@pytest.mark.parametrize(
    "default",
    [
        "property(lambda self: unknown())",
        "UnknownDescriptor()",
        "descriptor",
        "field(default=UnknownDescriptor())",
        "field(default_factory=unknown)",
        "field(default=None, default_factory=dict)",
    ],
)
def test_unknown_or_descriptor_field_defaults_do_not_create_projection_models(default):
    host, objects = fixture_sources()
    changed = objects.replace(
        "content: Any = field(compare=False, repr=False)", "content: Any = " + default
    )
    report = verify_output_correspondence(host, changed)
    assert not report["proved"], report


def test_record_property_and_rebound_field_are_not_native_slots():
    host, objects = fixture_sources()
    for method in (
        "    @property\n    def content(self):\n        return unknown()\n",
        "    def content(self):\n        return unknown()\n",
    ):
        changed = objects.replace(
            "    destination: str\n", method + "\n    destination: str\n"
        )
        assert not verify_output_correspondence(host, changed)["proved"]


def test_annotation_evaluation_and_constructor_bindings_remain_explicit_obligations(
    tmp_path,
):
    host, objects = fixture_sources()
    assert not verify_output_correspondence(
        host, objects.replace("from __future__ import annotations", "")
    )["proved"]
    assert not verify_output_correspondence(host, objects + "\nfrozenset = unknown\n")[
        "proved"
    ]
    marker = tmp_path / "module-initialized"
    changed = (
        host
        + f"\nsetup = __import__('pathlib').Path({str(marker)!r}).write_text('bad')\n"
    )
    report = verify_output_correspondence(changed, objects)
    assert report["proved"], report
    assert not report["initialization_proved"]
    assert not report["runtime_binding_proved"]
    assert any("assignment RHS evaluation" in item for item in report["entry_premises"])
    assert not marker.exists()


@pytest.mark.parametrize("field", ["content", "confidentiality"])
def test_parenthesized_annotations_do_not_declare_native_projection_slots(field):
    host, objects = fixture_sources()
    changed = objects.replace(field + ":", "(" + field + "):")
    report = verify_output_correspondence(host, changed)
    assert not report["proved"], report
    assert "parenthesized annotation" in report["issues"][0]["reason"]


@pytest.mark.parametrize(
    "layout",
    [
        None,
        "('_lock', '__dict__')",
        "('_lock', '_lock')",
        "('_lock', 'dispatch')",
        "('_state',)",
        "dynamic_slots()",
        "['_lock']",
    ],
)
def test_host_projection_requires_source_derived_fixed_slots(layout):
    host, objects = fixture_sources()
    tree = ast.parse(host)
    candidate = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ObjectManagerHost"
    )
    slot = next(
        node
        for node in candidate.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__slots__"
            for target in node.targets
        )
    )
    if layout is None:
        candidate.body.remove(slot)
    else:
        slot.value = ast.parse(layout, mode="eval").body
    report = verify_output_correspondence(ast.unparse(tree), objects)
    assert not report["proved"], report


def test_host_fixed_slot_layout_is_derived_without_claiming_runtime_admission():
    report = verify_output_correspondence(*actual_sources())
    assert not report["proved"], report
    assert report["host_layout"]["source_derived"]
    assert report["host_layout"]["slots"] == [
        "_checkpoint_key",
        "_state",
        "_store",
        "_tools",
        "_restored",
        "_historical_restores",
        "_lock",
    ]
    assert report["host_layout"]["instance_method_shadowing"] is False
    assert report["runtime_binding_proved"] is False
    assert report["initialization_proved"] is False


def test_actual_dispatch_validator_is_a_required_source_proof_dependency():
    host, objects = actual_sources()
    assert "validate_output_request(request)" in host
    report = verify_output_correspondence(host, objects)
    assert not report["proved"], report
    assert not report["system_complete"]
    assert report["entries"] == []
    assert len(report["unproved_dependencies"]) == 1
    dependency = report["unproved_dependencies"][0]
    assert dependency["kind"] == "reachable-input-validation"
    assert (
        dependency["target"]
        == "langgraph.prebuilt.security.output_data.validate_output_request"
    )
    assert dependency["proved"] is False
    assert dependency["required"]
    assert (
        "source-derived admission/effect-safety proof" in report["issues"][0]["reason"]
    )


@pytest.mark.parametrize(
    "call",
    ["validate_output_request(request)", "checked = validate_output_request(request)"],
)
def test_named_input_validator_is_never_an_opaque_source_exemption(call):
    host, objects = fixture_sources()
    body = GOOD.replace(
        "        return request.content",
        "        " + call + "\n        return request.content",
    )
    report = verify_output_correspondence(
        change_method(host, "dispatch", body), objects
    )
    assert not report["proved"], report
    assert report["unproved_dependencies"][0]["target"].endswith(
        ".validate_output_request"
    )


@pytest.mark.parametrize(
    "predicate",
    [
        "type(request) is not OutputRequest",
        "type(request) is DispatchRequest or type(request) is StateRequest",
        "type(request) is not DispatchRequest and type(request) is not OutputRequest",
    ],
)
def test_native_exact_class_guards_are_derived_before_conditional_return(predicate):
    host, objects = fixture_sources()
    body = "if " + predicate + ":\n    raise TypeError('unsupported request')\n" + GOOD
    report = verify_output_correspondence(
        change_method(host, "dispatch", body), objects
    )
    assert report["proved"], report


def test_type_query_cannot_use_rebound_builtin_or_custom_identity_inputs():
    host, objects = fixture_sources()
    body = (
        "if type(request) is not OutputRequest:\n    raise TypeError('unsupported')\n"
        + GOOD
    )
    changed = change_method(host, "dispatch", body)
    assert not verify_output_correspondence(changed + "\ntype = unknown\n", objects)[
        "proved"
    ]
    assert not verify_output_correspondence(
        change_method(
            host, "dispatch", body.replace("type(request)", "type(principal)")
        ),
        objects,
    )["proved"]
    assert not verify_output_correspondence(
        change_method(host, "dispatch", "type = unknown\n" + body), objects
    )["proved"]


def output_data_source():
    return (_ROOT / "output_data.py").read_text()


def test_actual_dispatch_validator_is_discharged_by_its_recomputed_contract():
    host, objects = actual_sources()
    report = verify_output_correspondence(
        host, objects, output_data_source=output_data_source()
    )
    assert report["proved"], report
    assert not report["system_complete"]
    assert not report["runtime_binding_proved"]
    assert not report["initialization_proved"]
    assert report["unproved_dependencies"] == []
    (dependency,) = report["dependencies"]
    assert dependency["proved"] and dependency["kind"] == "reachable-input-validation"
    assert dependency["entry_premises"] and dependency["external_layout_premises"]
    key = "langgraph.prebuilt.security.output_data"
    assert report["source_sha256"][key] == dependency["source_sha256"][key]
    for entry in report["entries"]:
        rules = [step["rule"] for path in entry["paths"] for step in path["derivation"]]
        # The validator's refusal is a distinct exit; a useful return remains.
        assert entry["normal_returns"] == 1
        assert "validator-refusal" in rules
        assert "source-derived-validator-contract" in rules
        assert "exact-cleared-content-return" in rules


@pytest.mark.parametrize(
    "original,replacement",
    [
        ('number = object.__getattribute__(value, "int")', "number = value.int"),
        ("if kind is dict:", "if isinstance(value, dict):"),
        ("    walker.walk(content)\n", ""),
        (
            "def _validate_output_request(value: object) -> None:\n",
            "def _validate_output_request(value: object) -> None:\n    return None\n",
        ),
    ],
)
def test_changed_validator_source_keeps_the_dependency_obligation(
    original, replacement
):
    host, objects = actual_sources()
    source = output_data_source()
    assert source.count(original) == 1
    report = verify_output_correspondence(
        host, objects, output_data_source=source.replace(original, replacement)
    )
    assert not report["proved"], report
    (dependency,) = report["unproved_dependencies"]
    assert dependency["kind"] == "reachable-input-validation"
    assert dependency["derivation_issues"]
    assert report["dependencies"] == []


@pytest.mark.parametrize(
    "call",
    [
        "validate_output_request(principal)",
        "validate_output_request(request, strict=True)",
        "validate_output_request(*[request])",
        "publish(request)",
    ],
)
def test_validator_contract_covers_only_the_exact_request_call(call):
    host, objects = fixture_sources()
    body = GOOD.replace(
        "        return request.content",
        "        " + call + "\n        return request.content",
    )
    report = verify_output_correspondence(
        change_method(host, "dispatch", body),
        objects,
        output_data_source=output_data_source(),
    )
    assert not report["proved"], report


@pytest.mark.parametrize(
    "prefix,reason",
    [
        ("request = principal", "covers only the unchanged effective request"),
        (
            "validate_output_request = request",
            "reachable call statement requires an effect derivation",
        ),
    ],
)
def test_validator_contract_does_not_follow_a_rebound_request_or_name(prefix, reason):
    host, objects = fixture_sources()
    body = GOOD.replace(
        "        return request.content",
        "        " + prefix + "\n        validate_output_request(request)\n"
        "        return request.content",
    )
    report = verify_output_correspondence(
        change_method(host, "dispatch", body),
        objects,
        output_data_source=output_data_source(),
    )
    assert not report["proved"], report
    assert reason in report["issues"][0]["reason"]


def test_a_named_no_op_validator_source_is_not_a_contract():
    host, objects = actual_sources()
    report = verify_output_correspondence(
        host,
        objects,
        output_data_source="def validate_output_request(value):\n    return None\n",
    )
    assert not report["proved"], report
    assert report["unproved_dependencies"][0]["derivation_issues"]


@pytest.mark.parametrize(
    "prefix,call",
    [
        (
            "import langgraph.prebuilt.security.output_data.validate_output_request\n",
            "langgraph(request)",
        ),
        (
            "import langgraph.prebuilt.security.output_data\n",
            "langgraph(request)",
        ),
    ],
)
def test_bare_dotted_imports_bind_only_the_top_level_module(prefix, call):
    # Sweep finding: `import a.b.c` must not bind `a` to the dotted path.
    host, objects = fixture_sources()
    body = GOOD.replace(
        "        return request.content",
        "        " + call + "\n        return request.content",
    )
    changed = prefix + change_method(host, "dispatch", body)
    report = verify_output_correspondence(
        changed, objects, output_data_source=output_data_source()
    )
    assert not report["proved"], report
