"""Review-pattern hints never certify the `LinuxSandboxExecutor` route."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from langgraph.prebuilt.security.host_verification import verify_linux_host_route

_SECURITY = Path(__file__).resolve().parents[2] / "langgraph/prebuilt/security"
LINUX = (_SECURITY / "linux.py").read_text()
WORKER = (_SECURITY / "_linux_worker.py").read_text()
_LOCAL_ERROR = "active_error=active_error,"


def _assert_no_proof(report) -> None:
    assert report["proof"] is False
    assert not any(report["proved"].values())
    assert report["complete"] is False


def test_actual_source_passes_review_hints_without_claiming_proof() -> None:
    report = verify_linux_host_route(LINUX, WORKER)
    assert report["structural_checks"] == {
        "grant_lowering": True,
        "activation_before_execution": True,
        "channel_identity": True,
        "cancellation_lifetime": True,
    }
    assert not report["issues"]
    _assert_no_proof(report)
    assert set(report["source_sha256"]) == {
        "libs/prebuilt/langgraph/prebuilt/security/linux.py",
        "libs/prebuilt/langgraph/prebuilt/security/_linux_worker.py",
    }
    assert len(report["checker_sha256"]) == 64 and report["premises"]


def test_finally_sees_callers_handled_exception() -> None:
    """Language fact behind the finding; no executor code is run."""

    def run() -> object:
        try:
            return "ok"
        finally:
            seen.append(sys.exc_info()[1])

    seen: list[object] = []
    prior = RuntimeError("previous request")
    try:
        raise prior
    except RuntimeError:
        assert run() == "ok"
    assert seen == [prior]


@pytest.mark.parametrize("expression", ["sys.exc_info()[1]", "sys.exception()"])
def test_ambient_exception_regression_is_a_failed_review_hint(expression) -> None:
    assert LINUX.count(_LOCAL_ERROR) == 1
    changed = LINUX.replace(_LOCAL_ERROR, f"active_error={expression},")
    report = verify_linux_host_route(changed, WORKER)
    assert report["structural_checks"]["cancellation_lifetime"] is False
    assert any("ambient" in issue for issue in report["issues"])
    _assert_no_proof(report)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (_LOCAL_ERROR, "active_error=None,"),
        (
            "except BaseException as exc:\n            active_error = exc",
            "except Exception as exc:\n            active_error = exc",
        ),
        (
            "active_error: BaseException | None = None",
            "active_error: BaseException | None = sys.exc_info()[1]",
        ),
    ],
)
def test_missing_invocation_local_capture_fails_review_hint(old, new) -> None:
    assert LINUX.count(old) == 1
    report = verify_linux_host_route(LINUX.replace(old, new), WORKER)
    assert report["structural_checks"]["cancellation_lifetime"] is False
    assert any("invocation-local" in issue for issue in report["issues"])
    _assert_no_proof(report)


def test_known_unsafe_pattern_match_still_proves_nothing() -> None:
    # The review reads seccomp_init's argument, not whether seccomp_load runs.
    # Retain this witness so future consumers cannot promote hints into proof.
    old = "def _apply_seccomp() -> None:\n"
    assert WORKER.count(old) == 1
    changed = WORKER.replace(old, old + "    return\n")
    report = verify_linux_host_route(LINUX, changed)
    assert report["structural_checks"]["activation_before_execution"] is True
    assert report["known_evasions"]
    _assert_no_proof(report)


@pytest.mark.parametrize(
    ("target", "old", "new", "obligation"),
    [
        (
            "worker",
            '        _apply_seccomp()\n        pool_key = request.get("pool_key")\n',
            '        pool_key = request.get("pool_key")\n',
            "activation_before_execution",
        ),
        (
            "worker",
            "        result = _invoke(prepared, event_loop)\n",
            "",
            "activation_before_execution",
        ),
        (
            "worker",
            '        code = compile(source.read(), artifact_path, "exec", dont_inherit=True)\n',
            '        code = compile(source.read(), artifact_path, "exec", dont_inherit=True)\n'
            "        exec(code, module.__dict__)\n",
            "activation_before_execution",
        ),
        (
            "worker",
            '    "close",\n',
            '    "close",\n    "clone",\n',
            "activation_before_execution",
        ),
        (
            "worker",
            "    context = library.seccomp_init(deny)",
            "    context = library.seccomp_init(allow)",
            "activation_before_execution",
        ),
        (
            "worker",
            '        if sys.stdin.readline(16) != "GO\\n":\n            return 73\n',
            "",
            "channel_identity",
        ),
        (
            "linux",
            '                    "startup_challenge": startup_challenge,\n                    "status": "ready",',
            '                    "status": "ready",',
            "channel_identity",
        ),
        (
            "linux",
            "                if not coordinator.validate_receipt(\n"
            "                    receipt, grant, plan, host, context\n"
            "                ):\n"
            '                    raise HostExecutionDenied("host:activation_receipt_invalid")\n',
            "",
            "channel_identity",
        ),
        (
            "linux",
            "        support = SupportLevel.UNSUPPORTED\n",
            "        support = SupportLevel.EXACT\n",
            "grant_lowering",
        ),
        (
            "linux",
            "            expected_nonce=challenge,\n        )",
            "            expected_nonce=challenge,\n            waivers=frozenset(obligations),\n        )",
            "grant_lowering",
        ),
        (
            "linux",
            '                raise ValueError(f"inexact_writable_mount:{selector}")',
            "                pass",
            "grant_lowering",
        ),
        (
            "linux",
            "                termination_confirmed = _confirm_worker_terminated(\n"
            "                    child_pid, child_start_time, timeout_s=2.0\n"
            "                )",
            "                termination_confirmed = True",
            "cancellation_lifetime",
        ),
        (
            "linux",
            "            while not execution.done():",
            "            if not execution.done():",
            "cancellation_lifetime",
        ),
    ],
)
def test_risky_mutation_fails_relevant_review_hint(
    target: str, old: str, new: str, obligation: str
) -> None:
    linux, worker = LINUX, WORKER
    if target == "worker":
        assert worker.count(old) == 1
        worker = worker.replace(old, new)
    else:
        assert linux.count(old) == 1
        linux = linux.replace(old, new)
    report = verify_linux_host_route(linux, worker)
    assert report["structural_checks"][obligation] is False
    assert report["issues"]
    _assert_no_proof(report)


def test_unparsable_source_proves_nothing() -> None:
    report = verify_linux_host_route("def broken(:\n", WORKER)
    _assert_no_proof(report)
    assert report["issues"]


def test_runtime_evidence_is_labeled_not_proof() -> None:
    repo = Path(__file__).resolve().parents[4]
    report = verify_linux_host_route(LINUX, WORKER, repo=repo)
    _assert_no_proof(report)
    for record in report["runtime_evidence"]:
        assert record["label"] == "runtime evidence"
        assert "proof" not in record
