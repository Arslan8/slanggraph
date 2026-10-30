"""Execute the compiled Lean decision core; runtime evidence is not a proof."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import warnings
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security import lean_lifecycle
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AdapterPlan,
    EnforcementPlan,
    ObligationAssignment,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.lean_lifecycle import (
    LeanLifecycleChecker,
    LeanLifecycleSession,
    _capture_receipt_certificate,
    _slots,
)
from tests.security.test_enforcement import _composition


@pytest.fixture(scope="session")
def binary():
    path = Path(
        os.environ.get(
            "LANGGRAPH_LEAN_WORKER_BINARY",
            str(
                Path(__file__).resolve().parents[4]
                / "proofs/worker-route/.lake/build/bin/workerRoute"
            ),
        )
    )
    if not path.is_file():
        if os.environ.get("LANGGRAPH_REQUIRE_LEAN_WORKER") == "1":
            pytest.fail("required checked Lean worker binary is missing")
        pytest.skip("build proofs/worker-route or set LANGGRAPH_LEAN_WORKER_BINARY")
    return path


@pytest.fixture(scope="session")
def checker(binary):
    return LeanLifecycleChecker(
        str(binary), hashlib.sha256(binary.read_bytes()).hexdigest()
    )


@pytest.fixture(scope="session")
def native_checker():
    root = Path(__file__).resolve().parents[4]
    library = Path(
        os.environ.get(
            "LANGGRAPH_NATIVE_WORKER_LIBRARY",
            str(root / "proofs/worker-route/.lake/build/lib/libargus_worker_route.so"),
        )
    )
    manifest_path = library.with_suffix(library.suffix + ".json")
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    runtime_value = os.environ.get(
        "LANGGRAPH_NATIVE_WORKER_RUNTIME", manifest.get("native_runtime", "")
    )
    runtime = Path(runtime_value) if runtime_value else Path("/missing-native-runtime")
    if not library.is_file() or not runtime.is_file():
        pytest.skip("build the inline worker-route library and provide its runtime")
    return LeanLifecycleChecker(
        str(library),
        hashlib.sha256(library.read_bytes()).hexdigest(),
        str(runtime),
        hashlib.sha256(runtime.read_bytes()).hexdigest(),
    )


def binding():
    return {
        "principal": "alice",
        "session": "session",
        "call": "call",
        "tool": "tool",
        "artifact": "artifact",
        "deployment": "",
        "runtime": "",
        "grant": "grant",
        "intent": "intent",
        "policy": "policy",
        "plan": "plan",
        "nonce": "nonce",
        "host": "host",
        "context": "context",
        "worker": {"pid": "123", "startTime": "456", "bootId": "boot"},
    }


def certificate(bound=None, rule_count=1):
    if bound is None:
        bound = binding()
    domains = [
        "filesystem",
        "network",
        "process",
        "ipc",
        "service",
        "credential",
        "runtime",
        "delegation",
        "resource_limit",
    ]
    rules = [
        {
            "id": "read" if index == 0 else f"read-{index}",
            "domain": "filesystem",
            "operation": "read",
            "selector": "/data",
            "conditions": {"kind": "map", "value": []},
            "requirement": "need",
            "provenance": [],
            "baseline": False,
        }
        for index in range(rule_count)
    ]
    obligations = [
        {
            "id": f"rule:{row['id']}:operate",
            "rule": row["id"],
            "kind": "operate",
            "domain": row["domain"],
            "operation": row["operation"],
            "selector": row["selector"],
            "conditions": copy.deepcopy(row["conditions"]),
            "dependencies": [],
            "waivable": False,
        }
        for row in rules
    ]
    obligations += [
        {
            "id": f"domain:{domain}:deny_complement",
            "rule": f"domain:{domain}",
            "kind": "deny_complement",
            "domain": domain,
            "operation": "deny_unlisted",
            "selector": "*",
            "conditions": {"kind": "map", "value": []},
            "dependencies": [],
            "waivable": False,
        }
        for domain in domains
    ]
    groups = [
        ("fs", "native-fs", [row["id"] for row in obligations[:rule_count]]),
        ("process", "native-process", [row["id"] for row in obligations[rule_count:]]),
    ]
    return {
        "grant": {
            **{
                key: bound[key]
                for key in (
                    "principal",
                    "session",
                    "tool",
                    "artifact",
                    "call",
                    "intent",
                    "policy",
                    "deployment",
                    "runtime",
                )
            },
            "digest": bound["grant"],
            "rules": rules,
        },
        "obligations": obligations,
        "plan": {
            "grant": bound["grant"],
            "host": bound["host"],
            "digest": bound["plan"],
            "mode": "enforced",
            "assignments": [
                {"obligation": item, "adapter": adapter, "support": "exact"}
                for adapter, _, items in groups
                for item in items
            ],
            "nativePlans": [
                {"adapter": adapter, "digest": digest, "obligations": items.copy()}
                for adapter, digest, items in groups
            ],
            "waived": [],
            "removedWants": [],
        },
        "receipt": {
            **{
                key: bound[key]
                for key in (
                    "grant",
                    "plan",
                    "host",
                    "context",
                    "nonce",
                    "artifact",
                    "deployment",
                    "runtime",
                )
            },
            "mode": "enforced",
            "activated": [row["id"] for row in obligations],
            "removedWants": [],
            "evidence": [
                {
                    "adapter": adapter,
                    "digest": digest,
                    "context": bound["context"],
                    "nonce": bound["nonce"],
                    "obligations": items.copy(),
                }
                for adapter, digest, items in groups
            ],
        },
    }


def request(bound, events, proof=None):
    return {
        "protocol": "worker-route-grant-v3",
        "kind": "route",
        "binding": bound,
        "certificate": certificate(bound) if proof is None else proof,
        "events": events,
    }


def trace(bound):
    return [
        {"kind": "authorize", "binding": bound, "authorized": True},
        {"kind": "activate", "binding": bound, "supported": True, "confirmed": True},
        {"kind": "go", "binding": bound},
        {"kind": "result", "binding": bound, "accepted": True},
        {"kind": "cleanup", "confirmed": True},
    ]


def test_inline_native_checker_runs_without_per_decision_process(
    native_checker, monkeypatch
):
    def unexpected(*args, **kwargs):
        raise AssertionError("inline checker must not launch a subprocess")

    monkeypatch.setattr(subprocess, "run", unexpected)
    bound = binding()
    proof = certificate(bound)
    native_checker.require_grant(proof["grant"], proof["obligations"])
    native_checker.require(bound, trace(bound)[:3], "running", certificate=proof)
    native_checker.require(bound, trace(bound), "ready", certificate=proof)

    changed = copy.deepcopy(bound)
    changed["nonce"] = "different"
    with pytest.raises(HostExecutionDenied, match="lean_lifecycle_refused"):
        native_checker.require(changed, trace(bound)[:3], "running", certificate=proof)


def test_inline_native_checker_pins_generated_runtime(native_checker):
    with pytest.raises(HostExecutionDenied, match="lean_binary_unavailable_or_changed"):
        LeanLifecycleChecker(
            native_checker.binary_path,
            native_checker.binary_sha256,
            native_checker.runtime_path,
            "0" * 64,
        )


def raw_check(binary, payload):
    return subprocess.run(
        [str(binary)],
        input=payload,
        capture_output=True,
        timeout=5,
        check=False,
    )


@pytest.mark.parametrize("ensure_ascii", [True, False])
def test_raw_protocol_accepts_one_formatted_unicode_document(binary, ensure_ascii):
    bound = binding()
    bound["principal"] = "josé 😀 \ufffd"
    payload = (
        json.dumps(
            request(bound, trace(bound)),
            ensure_ascii=ensure_ascii,
            indent=2,
        ).encode()
        + b"\n \t\r\n"
    )
    result = raw_check(binary, payload)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "protocol": "worker-route-grant-v3",
        "schema": 3,
        "phase": "ready",
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ('"events":', '"events":[{"kind":"cancel"}],"events":'),
        ('"kind":"cleanup"', '"kind":"cancel","kind":"cleanup"'),
        ('"confirmed":true', '"confirmed":false,"confirmed":true'),
        ('"principal":"alice"', '"principal":"mallory","principal":"alice"'),
        ('"principal":"alice"', '"princ\\u0069pal":"mallory","principal":"alice"'),
        ('"pid":"123"', '"pid":"other","pid":"123"'),
    ],
    ids=["events", "kind", "boolean", "binding", "escaped-key", "worker"],
)
def test_raw_protocol_rejects_duplicate_keys_before_map_construction(
    binary, field, replacement
):
    bound = binding()
    payload = json.dumps(request(bound, trace(bound)), separators=(",", ":")).replace(
        field, replacement, 1
    )
    result = raw_check(binary, payload.encode())
    assert result.returncode != 0
    assert result.stdout == b""


@pytest.mark.parametrize("suffix", [b"\n{}\n", b"{}", b"\ntrailing garbage"])
def test_raw_protocol_rejects_input_after_complete_document(binary, suffix):
    bound = binding()
    payload = json.dumps(request(bound, trace(bound))).encode()
    result = raw_check(binary, payload + suffix)
    assert result.returncode != 0
    assert result.stdout == b""


@pytest.mark.parametrize("invalid", ["\ud800", "\udfff", "\ud800x", "\ud800\ud800"])
def test_raw_protocol_rejects_invalid_surrogates_before_identity_comparison(
    binary, invalid
):
    original = binding()
    original["principal"] = invalid
    observed = binding()
    # The former decoder normalized each unmatched surrogate to U+FFFD.
    observed["principal"] = "".join(
        "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in invalid
    )
    payload = json.dumps(request(original, trace(observed))).encode()
    result = raw_check(binary, payload)
    assert result.returncode != 0
    assert result.stdout == b""


@pytest.mark.parametrize(
    ("original_identity", "decoded_identity"),
    [("\ud800", "\ufffd"), ("\ud83d\ude00", "😀")],
    ids=["lone-surrogate", "paired-surrogates"],
)
def test_python_bridge_refuses_surrogate_identity_collisions_before_encoding(
    checker, monkeypatch, original_identity, decoded_identity
):
    original = binding()
    original["principal"] = original_identity
    observed = binding()
    observed["principal"] = decoded_identity

    def unexpected_encoding(*args, **kwargs):
        pytest.fail("invalid native identity reached the JSON encoder")

    monkeypatch.setattr(json, "dumps", unexpected_encoding)
    with pytest.raises(HostExecutionDenied, match="lean_protocol_shape"):
        checker.require(
            original, trace(observed), "ready", certificate=certificate(original)
        )


@pytest.mark.parametrize("key", ["\ud800", "\ud83d\ude00"])
def test_python_bridge_refuses_surrogate_keys_before_encoding(
    checker, monkeypatch, key
):
    original = binding()
    original[key] = "invalid"

    def unexpected_encoding(*args, **kwargs):
        pytest.fail("invalid native key reached the JSON encoder")

    monkeypatch.setattr(json, "dumps", unexpected_encoding)
    with pytest.raises(HostExecutionDenied, match="lean_protocol_shape"):
        checker.require(original, [], "ready", certificate=certificate(original))


@pytest.mark.parametrize("invalid", ["utf8", "budget"])
def test_raw_protocol_refuses_invalid_bytes_and_excess_input(binary, invalid):
    bound = binding()
    payload = json.dumps(request(bound, trace(bound))).encode()
    if invalid == "utf8":
        payload = payload.replace(b"alice", b"\xff", 1)
    else:
        payload += b" " * 1_048_576
    result = raw_check(binary, payload)
    assert result.returncode != 0
    assert result.stdout == b""


def test_compiled_core_preserves_useful_unicode_bound_route(checker):
    bound = binding()
    bound["principal"] = "josé 😀"
    events = trace(bound)
    checker.require(bound, events[:3], "running", certificate=certificate(bound))
    checker.require(bound, events, "ready", certificate=certificate(bound))
    session = LeanLifecycleSession(checker, bound, certificate(bound))
    session.permit_go(bound, supported=True)
    session.permit_success(bound)
    with pytest.raises(HostExecutionDenied):
        session.permit_success(bound)


@pytest.mark.parametrize(
    "field",
    [
        "principal",
        "session",
        "call",
        "tool",
        "artifact",
        "deployment",
        "runtime",
        "grant",
        "plan",
        "nonce",
        "host",
        "context",
        "worker.pid",
        "worker.startTime",
        "worker.bootId",
    ],
)
@pytest.mark.parametrize("index", range(4))
def test_every_identity_field_is_checked_at_every_bound_transition(
    checker, field, index
):
    original = binding()
    events = copy.deepcopy(trace(original))
    changed = copy.deepcopy(original)
    if field.startswith("worker."):
        changed["worker"][field.split(".")[1]] = "other"
    else:
        changed[field] = "other"
    events[index]["binding"] = changed
    with pytest.raises(HostExecutionDenied, match="lean_lifecycle_refused"):
        checker.require(original, events, "ready", certificate=certificate(original))


@pytest.mark.parametrize(
    "mutation",
    [
        "denied",
        "unsupported",
        "inactive",
        "result",
        "cleanup",
        "cancel",
        "order",
        "extra",
        "unknown",
        "field",
    ],
)
def test_compiled_core_rejects_failed_facts_and_unsupported_protocol(checker, mutation):
    bound = binding()
    events = trace(bound)
    if mutation == "denied":
        events[0]["authorized"] = False
    elif mutation == "unsupported":
        events[1]["supported"] = False
    elif mutation == "inactive":
        events[1]["confirmed"] = False
    elif mutation == "result":
        events[3]["accepted"] = False
    elif mutation == "cleanup":
        events[4]["confirmed"] = False
    elif mutation == "cancel":
        events.insert(3, {"kind": "cancel"})
    elif mutation == "order":
        events[0], events[1] = events[1], events[0]
    elif mutation == "extra":
        events += events
    elif mutation == "unknown":
        events[4] = {"kind": "assume_cleanup"}
    else:
        events[4]["unmodeled"] = True
    with pytest.raises(HostExecutionDenied, match="lean_lifecycle_refused"):
        checker.require(bound, events, "ready", certificate=certificate(bound))


def test_failed_session_cannot_retry_into_success(checker):
    bound = binding()
    session = LeanLifecycleSession(checker, bound, certificate(bound))
    with pytest.raises(HostExecutionDenied):
        session.permit_go(bound, supported=False)
    with pytest.raises(HostExecutionDenied):
        session.permit_go(bound, supported=True)


def test_binary_identity_is_checked_and_captured_before_runtime(binary, tmp_path):
    selected = tmp_path / "workerRoute"
    selected.write_bytes(binary.read_bytes())
    digest = hashlib.sha256(selected.read_bytes()).hexdigest()
    with pytest.raises(HostExecutionDenied, match="changed"):
        LeanLifecycleChecker(str(selected), "0" * 64)
    checker = LeanLifecycleChecker(str(selected), digest)
    selected.write_bytes(b"replaced after selection")
    bound = binding()
    checker.require(bound, trace(bound), "ready", certificate=certificate(bound))
    with pytest.raises(HostExecutionDenied, match="changed"):
        LeanLifecycleChecker(str(selected), digest)


def test_missing_native_checker_storage_is_a_literal_refusal():
    checker = object.__new__(LeanLifecycleChecker)
    with pytest.raises(HostExecutionDenied) as raised:
        checker.require(binding(), [], "ready", certificate=certificate())
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert not hasattr(raised.value, "obj")


def test_protocol_rejects_foreign_keys_without_hash_or_equality(checker):
    calls = []

    class Key:
        def __hash__(self):
            calls.append("hash")
            return 1

        def __eq__(self, other):
            calls.append("eq")
            return False

    forged = {Key(): "value"}
    calls.clear()
    with pytest.raises(HostExecutionDenied, match="protocol_shape"):
        checker.require(forged, [], "ready", certificate=certificate())
    assert calls == []


@pytest.mark.parametrize("reorder", [False, True])
def test_multi_adapter_certificate_is_checked_independent_of_row_order(
    checker, reorder
):
    bound = binding()
    bound["deployment"] = "tool-deployment"
    bound["runtime"] = "python-runtime"
    proof = certificate(bound)
    if reorder:
        proof["plan"]["assignments"].reverse()
        proof["plan"]["nativePlans"].reverse()
        proof["receipt"]["evidence"].reverse()
        proof["receipt"]["activated"].reverse()
    checker.require(bound, trace(bound), "ready", certificate=proof)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_evidence",
        "duplicate_evidence",
        "extra_evidence",
        "empty_activated",
        "extra_activated",
        "duplicate_activated",
        "empty_assignments",
        "duplicate_assignment",
        "cross_owner",
        "native_digest",
        "evidence_digest",
        "evidence_nonce",
        "evidence_context",
        "native_obligations",
        "evidence_obligations",
        "missing_native_plan",
        "duplicate_native_plan",
        "waiver",
        "degraded",
        "removed_wants",
        "plan_grant",
        "plan_host",
        "plan_digest",
        "receipt_grant",
        "receipt_plan",
        "receipt_host",
        "receipt_context",
        "receipt_nonce",
        "receipt_artifact",
        "receipt_deployment",
        "receipt_runtime",
    ],
)
def test_compiled_certificate_refuses_composition_mutations(checker, mutation):
    bound = binding()
    proof = certificate(bound)
    plan, receipt = proof["plan"], proof["receipt"]
    if mutation == "missing_evidence":
        receipt["evidence"].pop()
    elif mutation == "duplicate_evidence":
        receipt["evidence"][1] = copy.deepcopy(receipt["evidence"][0])
    elif mutation == "extra_evidence":
        receipt["evidence"].append({**receipt["evidence"][0], "adapter": "other"})
    elif mutation == "empty_activated":
        receipt["activated"] = []
    elif mutation == "extra_activated":
        receipt["activated"].append("extra")
    elif mutation == "duplicate_activated":
        receipt["activated"].append(receipt["activated"][0])
    elif mutation == "empty_assignments":
        plan["assignments"] = []
    elif mutation == "duplicate_assignment":
        plan["assignments"].append(copy.deepcopy(plan["assignments"][0]))
    elif mutation == "cross_owner":
        plan["assignments"][0]["adapter"] = "process"
    elif mutation == "native_digest":
        plan["nativePlans"][0]["digest"] = "changed"
    elif mutation == "evidence_digest":
        receipt["evidence"][0]["digest"] = "changed"
    elif mutation == "evidence_nonce":
        receipt["evidence"][0]["nonce"] = "changed"
    elif mutation == "evidence_context":
        receipt["evidence"][0]["context"] = "changed"
    elif mutation == "native_obligations":
        plan["nativePlans"][0]["obligations"] = ["read", "deny"]
    elif mutation == "evidence_obligations":
        receipt["evidence"][0]["obligations"] = ["read", "deny"]
    elif mutation == "missing_native_plan":
        plan["nativePlans"].pop()
    elif mutation == "duplicate_native_plan":
        plan["nativePlans"].append(copy.deepcopy(plan["nativePlans"][0]))
    elif mutation == "waiver":
        plan["waived"] = ["some-obligation"]
    elif mutation == "degraded":
        plan["mode"] = receipt["mode"] = "degraded"
    elif mutation == "removed_wants":
        receipt["removedWants"] = ["changed"]
    elif mutation.startswith("plan_"):
        plan[mutation.removeprefix("plan_")] = "changed"
    else:
        receipt[mutation.removeprefix("receipt_")] = "changed"
    with pytest.raises(HostExecutionDenied, match="lean_lifecycle_refused"):
        checker.require(bound, trace(bound), "ready", certificate=proof)


def test_session_certificate_cannot_be_replaced_through_input_or_observer_aliases(
    checker, monkeypatch
):
    bound = binding()
    original = certificate(bound)
    passed = copy.deepcopy(original)
    session = LeanLifecycleSession(checker, bound, passed)
    native_require = LeanLifecycleChecker.require
    observed = []

    def observe(self, actual_binding, events, phase, *, certificate):
        observed.append(copy.deepcopy(certificate))
        native_require(self, actual_binding, events, phase, certificate=certificate)
        # A caller retaining either argument must not mutate the next check.
        certificate["receipt"]["evidence"].clear()
        actual_binding["principal"] = "replacement"
        events.clear()

    monkeypatch.setattr(LeanLifecycleChecker, "require", observe)
    session.permit_go(bound, supported=True)
    passed["receipt"]["evidence"].clear()
    passed["plan"]["assignments"].clear()
    session.permit_success(bound)
    assert observed == [original, original]


def test_capture_uses_native_slots_and_detaches_actual_records(monkeypatch):
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest

    def forbidden_digest(self):
        raise AssertionError("candidate digest property was invoked")

    monkeypatch.setattr(EnforcementPlan, "digest", property(forbidden_digest))
    captured = _capture_receipt_certificate(
        plan, receipt, plan_digest=digest, grant={}, obligations=[]
    )
    before = copy.deepcopy(captured)
    assert captured["plan"]["digest"] == digest
    assert len(captured["receipt"]["evidence"]) == 2
    object.__setattr__(plan.assignments[0], "obligation_id", "mutated")
    object.__setattr__(receipt.evidence[0], "nonce", "mutated")
    object.__setattr__(receipt, "evidence", ())
    assert captured == before


@pytest.mark.parametrize(
    "row",
    [
        "plan",
        "receipt",
        "assignment",
        "native_plan",
        "evidence",
    ],
)
def test_capture_missing_native_slots_refuses_without_exception_payload(row):
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest
    if row == "plan":
        plan = object.__new__(EnforcementPlan)
    elif row == "receipt":
        receipt = object.__new__(ActivationReceipt)
    elif row == "assignment":
        plan = replace(plan, assignments=(object.__new__(ObligationAssignment),))
    elif row == "native_plan":
        plan = replace(plan, adapter_plans=(object.__new__(AdapterPlan),))
    else:
        receipt = replace(receipt, evidence=(object.__new__(ActivationEvidence),))
    with pytest.raises(HostExecutionDenied) as caught:
        _capture_receipt_certificate(
            plan, receipt, plan_digest=digest, grant={}, obligations=[]
        )
    assert caught.value.args == ("host:lean_certificate_shape",)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert not hasattr(caught.value, "obj")


@pytest.mark.parametrize(
    "field", ["assignments", "adapter_plans", "evidence", "activated", "mode", "digest"]
)
def test_capture_foreign_objects_are_refused_without_protocol_calls(field):
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest
    calls = []

    class Hostile:
        def __getattribute__(self, name):
            calls.append("attribute")
            raise AssertionError("foreign attribute")

        def __iter__(self):
            calls.append("iterate")
            raise AssertionError("foreign iteration")

        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError("foreign equality")

        def __str__(self):
            calls.append("string")
            raise AssertionError("foreign conversion")

    value = Hostile()
    if field in {"assignments", "adapter_plans", "mode"}:
        object.__setattr__(plan, field, value)
    elif field == "evidence":
        object.__setattr__(receipt, "evidence", value)
    elif field == "activated":
        object.__setattr__(receipt, "activated_obligations", value)
    else:
        digest = value
    with pytest.raises(HostExecutionDenied):
        _capture_receipt_certificate(
            plan, receipt, plan_digest=digest, grant={}, obligations=[]
        )
    assert calls == []


def test_capture_exact_bounded_empty_rows_are_left_to_compiled_semantics():
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest
    plan = replace(plan, assignments=(), adapter_plans=())
    receipt = replace(receipt, evidence=(), activated_obligations=frozenset())
    captured = _capture_receipt_certificate(
        plan, receipt, plan_digest=digest, grant={}, obligations=[]
    )
    assert captured["plan"]["assignments"] == []
    assert captured["receipt"]["evidence"] == []


@pytest.mark.parametrize(
    "row", ["plan", "receipt", "assignment", "native_plan", "evidence"]
)
def test_capture_refuses_record_subclasses_without_attribute_dispatch(row):
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest
    calls = []
    owner = {
        "plan": EnforcementPlan,
        "receipt": ActivationReceipt,
        "assignment": ObligationAssignment,
        "native_plan": AdapterPlan,
        "evidence": ActivationEvidence,
    }[row]

    def foreign_attribute(self, name):
        calls.append(name)
        raise AssertionError("subclass attribute hook must not execute")

    subclass = type("ForeignRecord", (owner,), {"__getattribute__": foreign_attribute})
    foreign = object.__new__(subclass)
    if row == "plan":
        plan = foreign
    elif row == "receipt":
        receipt = foreign
    elif row == "assignment":
        plan = replace(plan, assignments=(foreign,))
    elif row == "native_plan":
        plan = replace(plan, adapter_plans=(foreign,))
    else:
        receipt = replace(receipt, evidence=(foreign,))
    with pytest.raises(HostExecutionDenied, match="lean_certificate_shape"):
        _capture_receipt_certificate(
            plan, receipt, plan_digest=digest, grant={}, obligations=[]
        )
    assert calls == []


@pytest.mark.parametrize(
    "field", ["assignments", "native_plans", "evidence", "activated"]
)
def test_capture_refuses_oversized_native_collections(field):
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest
    if field == "assignments":
        plan = replace(plan, assignments=(plan.assignments[0],) * 257)
    elif field == "native_plans":
        plan = replace(plan, adapter_plans=(plan.adapter_plans[0],) * 257)
    elif field == "evidence":
        receipt = replace(receipt, evidence=(receipt.evidence[0],) * 257)
    else:
        receipt = replace(
            receipt, activated_obligations=frozenset(str(i) for i in range(257))
        )
    with pytest.raises(HostExecutionDenied, match="lean_certificate_shape"):
        _capture_receipt_certificate(
            plan, receipt, plan_digest=digest, grant={}, obligations=[]
        )


def test_capture_byte_budget_stops_before_inspecting_later_records(monkeypatch):
    _, _, plan, _, _, receipt = _composition()
    digest = plan.digest
    oversized = AdapterPlan(
        "adapter",
        frozenset(f"{index:04d}" + "x" * 4092 for index in range(256)),
        "native-digest",
    )
    later = object.__new__(AdapterPlan)
    plan = replace(plan, adapter_plans=(oversized, later))
    original = lean_lifecycle._record

    def observe(value, owner, slots):
        if value is later:
            pytest.fail("capture continued past the aggregate byte budget")
        return original(value, owner, slots)

    monkeypatch.setattr(lean_lifecycle, "_record", observe)
    with pytest.raises(HostExecutionDenied, match="lean_protocol_shape"):
        _capture_receipt_certificate(
            plan, receipt, plan_digest=digest, grant={}, obligations=[]
        )


def test_slot_capture_checks_all_class_keys_before_lookup_or_equality():
    calls = []

    class ForeignKey:
        def __hash__(self):
            calls.append("hash")
            return hash("field")

        def __eq__(self, other):
            calls.append("equality")
            return False

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        owner = type(
            "MalformedRecord", (), {ForeignKey(): None, "__slots__": ("field",)}
        )
    calls.clear()
    with pytest.raises(RuntimeError, match="invalid native receipt record definition"):
        _slots(owner, ("field",))
    assert calls == []


def test_general_certificate_arrays_support_256_useful_obligations(checker):
    bound = binding()
    proof = certificate(bound, rule_count=247)
    assert len(proof["obligations"]) == 256
    checker.require(bound, trace(bound), "ready", certificate=proof)


@pytest.mark.parametrize("field", ["plan", "receipt", "assignment", "evidence"])
def test_raw_certificate_duplicate_keys_are_rejected(binary, field):
    bound = binding()
    payload = json.dumps(request(bound, trace(bound)), separators=(",", ":"))
    target = {
        "plan": '"digest":"plan"',
        "receipt": '"artifact":"artifact"',
        "assignment": '"obligation":"rule:read:operate"',
        "evidence": '"digest":"native-fs","context"',
    }[field]
    replaced = {
        "plan": '"digest":"wrong","digest":"plan"',
        "receipt": '"artifact":"wrong","artifact":"artifact"',
        "assignment": '"obligation":"wrong","obligation":"rule:read:operate"',
        "evidence": '"digest":"wrong","digest":"native-fs","context"',
    }[field]
    assert target in payload
    result = raw_check(binary, payload.replace(target, replaced, 1).encode())
    assert result.returncode != 0
    assert result.stdout == b""


@pytest.mark.parametrize(
    "mutation",
    [
        "old_protocol",
        "missing_protocol",
        "extra_envelope",
        "missing_certificate",
        "extra_certificate",
        "extra_plan",
        "extra_receipt",
        "extra_row",
        "events_limit",
        "array_limit",
    ],
)
def test_raw_v3_protocol_refuses_unsupported_shapes(binary, mutation):
    bound = binding()
    payload = request(bound, trace(bound))
    if mutation == "old_protocol":
        payload["protocol"] = "worker-route-v1"
    elif mutation == "missing_protocol":
        del payload["protocol"]
    elif mutation == "extra_envelope":
        payload["trusted"] = True
    elif mutation == "missing_certificate":
        del payload["certificate"]
    elif mutation == "extra_certificate":
        payload["certificate"]["trusted"] = True
    elif mutation == "extra_plan":
        payload["certificate"]["plan"]["trusted"] = True
    elif mutation == "extra_receipt":
        payload["certificate"]["receipt"]["trusted"] = True
    elif mutation == "extra_row":
        payload["certificate"]["receipt"]["evidence"][0]["trusted"] = True
    elif mutation == "events_limit":
        payload["events"] = [{"kind": "cancel"}] * 33
    else:
        payload["certificate"]["receipt"]["activated"] = ["entry"] * 257
    result = raw_check(binary, json.dumps(payload).encode())
    assert result.returncode != 0
    assert result.stdout == b""


@pytest.mark.parametrize(
    "response",
    [
        b'{"schema":1,"phase":"ready"}',
        b'{"protocol":"worker-route-receipt-v1","schema":2,"phase":"ready"}',
        b'{"protocol":"worker-route-grant-v3","schema":1,"phase":"ready"}',
        b'{"protocol":"worker-route-grant-v3","schema":3,"phase":"ready","phase":"ready"}',
        b'{"protocol":"worker-route-grant-v3","schema":3,"phase":"ready","extra":true}',
    ],
)
def test_python_bridge_refuses_response_downgrade_and_duplicate_fields(
    checker, monkeypatch, response
):
    def respond(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout=response)

    monkeypatch.setattr(subprocess, "run", respond)
    bound = binding()
    with pytest.raises(HostExecutionDenied, match="lean_lifecycle_refused"):
        checker.require(bound, trace(bound), "ready", certificate=certificate(bound))


@pytest.mark.parametrize(
    "kind", ["events", "rows", "depth", "bytes", "string", "dictionary"]
)
def test_python_protocol_budget_refuses_before_native_execution(
    checker, monkeypatch, kind
):
    bound = binding()
    proof = certificate(bound)
    events = trace(bound)
    if kind == "events":
        events = [{"kind": "cancel"}] * 33
    elif kind == "rows":
        proof["receipt"]["activated"] = ["entry"] * 257
    elif kind == "depth":
        nested = "value"
        for _ in range(13):
            nested = [nested]
        proof["receipt"]["activated"] = nested
    elif kind == "bytes":
        proof["receipt"]["activated"] = ["\x7f" * 4096] * 256
    elif kind == "string":
        bound["principal"] = "x" * 4097
    else:
        proof = {str(index): "value" for index in range(17)}

    def unexpected(*args, **kwargs):
        pytest.fail("unbounded request reached native execution")

    monkeypatch.setattr(subprocess, "run", unexpected)
    with pytest.raises(HostExecutionDenied, match="lean_protocol_shape"):
        checker.require(bound, events, "ready", certificate=proof)


@pytest.mark.parametrize("remove_obligation_row", [False, True])
def test_v3_refuses_consistent_receipt_removal_against_independent_grant(
    checker, remove_obligation_row
):
    bound = binding()
    proof = certificate(bound)
    missing = proof["plan"]["assignments"][-1]["obligation"]
    proof["plan"]["assignments"].pop()
    for plan in proof["plan"]["nativePlans"]:
        plan["obligations"] = [item for item in plan["obligations"] if item != missing]
    for row in proof["receipt"]["evidence"]:
        row["obligations"] = [item for item in row["obligations"] if item != missing]
    proof["receipt"]["activated"].remove(missing)
    if remove_obligation_row:
        proof["obligations"] = [
            row for row in proof["obligations"] if row["id"] != missing
        ]
    with pytest.raises(HostExecutionDenied):
        checker.require(bound, trace(bound), "ready", certificate=proof)


@pytest.mark.parametrize(
    "field",
    [
        "principal",
        "session",
        "call",
        "tool",
        "artifact",
        "intent",
        "policy",
        "deployment",
        "runtime",
        "digest",
    ],
)
def test_v3_route_binds_captured_grant_identity(checker, field):
    bound = binding()
    proof = certificate(bound)
    proof["grant"][field] = "replacement"
    with pytest.raises(HostExecutionDenied):
        checker.require(bound, trace(bound), "ready", certificate=proof)


@pytest.mark.parametrize("entry", ["route", "grant"])
def test_public_checker_entries_reject_foreign_receiver_before_dispatch(entry):
    calls = []

    class Foreign:
        def __getattribute__(self, name):
            calls.append(name)
            raise AssertionError

    with pytest.raises(HostExecutionDenied, match="lean_binary_configuration"):
        if entry == "route":
            LeanLifecycleChecker.require(Foreign(), {}, [], "ready", certificate={})
        else:
            LeanLifecycleChecker.require_grant(Foreign(), {}, [])
    assert calls == []
