"""Fault injection for the independent native macOS evidence oracles."""

import copy
import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "macos_verifier", Path(__file__).parents[1] / "remaining/verify_macos_portability.py"
)
assert _SPEC and _SPEC.loader
verifier = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verifier)


def binding():
    """Minimal synthetic receipt; never used as native execution evidence."""
    grant = dict(
        principal_id="alice",
        session_id="test",
        tool_name="read_pair",
        artifact_digest="artifact",
        call_id="call",
        normalized_intent_digest="intent",
        policy_digest="policy",
        rules=[],
        deployment_digest="",
        runtime_digest="",
    )
    payload = {k: v for k, v in grant.items() if k not in {"deployment_digest", "runtime_digest"}}
    grant_digest = verifier.digest(payload)
    ids = sorted(f"domain:{domain}:deny_complement" for domain in verifier.DOMAINS)
    native_payload = {"synthetic": True}
    native_digest = verifier.digest(native_payload)
    context = {"process_identity": "worker:123:start"}
    context_digest = verifier.digest(context)
    native = dict(
        obligation_ids=ids,
        adapter_id="native",
        native_plan_digest=native_digest,
        payload=native_payload,
    )
    evidence = dict(
        obligation_ids=ids,
        adapter_id="native",
        native_plan_digest=native_digest,
        nonce="nonce",
        context_digest=context_digest,
    )
    plan = dict(
        grant_digest=grant_digest,
        mode="enforced",
        waived_obligations=[],
        assignments=[dict(obligation_id=i, support="exact") for i in ids],
        adapter_plans=[native],
    )
    receipt = dict(
        grant_digest=grant_digest,
        plan_digest="plan",
        artifact_digest="artifact",
        activated_obligations=ids,
        mode="enforced",
        evidence=[evidence],
        nonce="nonce",
        context_digest=context_digest,
    )
    return dict(
        call_id="call",
        grant=grant,
        grant_digest=grant_digest,
        plan=plan,
        plan_digest="plan",
        receipt=receipt,
        context=context,
        worker_pid=123,
        receipt_validated=True,
        status="success",
        value=verifier.UTILITY,
        cleanup_confirmed=True,
        worker_absent=True,
        recovery_records=0,
        unresolved=0,
    )


def attack():
    trial = binding()
    trial["value"] = dict(useful=verifier.UTILITY, attempted=True, blocked=True, errno=1)
    return dict(
        case="write",
        repeat=0,
        control=binding(),
        trial=trial,
        direct_control=dict(useful=verifier.UTILITY, attempted=True, blocked=False),
        fixture_after=dict(left="17", right="24", secret="PRIVATE_CANARY"),
    )


def test_valid_synthetic_binding_and_denial():
    issues = []
    verifier.useful(binding(), issues, "control")
    verifier.verify_attack(attack(), issues)
    assert issues == []


@pytest.mark.parametrize(
    "field", ["grant_digest", "plan_digest", "artifact_digest", "context_digest"]
)
def test_receipt_digest_fault(field):
    row = binding()
    row["receipt"][field] = "tampered"
    issues = []
    verifier.check_binding(row, issues, "fault")
    assert issues


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "unsupported", "activated", "nonce", "payload"]
)
def test_obligation_and_native_faults(mutation):
    row = binding()
    if mutation == "missing":
        row["plan"]["assignments"].pop()
    elif mutation == "duplicate":
        row["plan"]["assignments"].append(copy.deepcopy(row["plan"]["assignments"][0]))
    elif mutation == "unsupported":
        row["plan"]["assignments"][0]["support"] = "unsupported"
    elif mutation == "activated":
        row["receipt"]["activated_obligations"] = []
    elif mutation == "nonce":
        row["receipt"]["evidence"][0]["nonce"] = "other"
    else:
        row["plan"]["adapter_plans"][0]["payload"]["synthetic"] = False
    issues = []
    verifier.check_binding(row, issues, "fault")
    assert issues


@pytest.mark.parametrize(
    "mutation",
    ["control", "not_attempted", "generic_error", "worker_alive", "ledger", "useful", "fixture"],
)
def test_denial_requires_positive_controls_and_cleanup(mutation):
    row = attack()
    if mutation == "control":
        row["direct_control"]["blocked"] = True
    elif mutation == "not_attempted":
        row["trial"]["value"]["attempted"] = False
    elif mutation == "generic_error":
        row["trial"]["value"]["errno"] = 2
    elif mutation == "worker_alive":
        row["trial"]["worker_absent"] = False
    elif mutation == "ledger":
        row["trial"]["recovery_records"] = 1
    elif mutation == "useful":
        row["trial"]["value"]["useful"] = {}
    else:
        row["fixture_after"]["secret"] = "CHANGED"
    issues = []
    verifier.verify_attack(row, issues)
    assert issues


def test_missing_archive_is_not_success(tmp_path):
    with pytest.raises(FileNotFoundError):
        verifier.verify(tmp_path)


def test_confidence_interval_uses_sessions():
    result = verifier.interval([1, 2, 3, 4, 5])
    assert result["mean"] == 3
    assert result["ci95"][0] == pytest.approx(1.036756, abs=1e-5)
    assert verifier.interval([1])["ci95"] == [None, None]
