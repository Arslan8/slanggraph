"""Language-sandbox route evidence: the execution choke point and fixed controls."""

from pathlib import Path

import pytest

from langgraph.prebuilt.security.language_route_verification import (
    verify_language_route,
)

_ROOT = Path(__file__).resolve().parents[2] / "langgraph/prebuilt/security"


def sources():
    return (
        (_ROOT / "_language_sandbox.py").read_text(),
        (_ROOT / "inprocess.py").read_text(),
    )


def test_actual_sources_prove_the_route_under_stated_premises():
    report = verify_language_route(*sources())
    assert report["proved"], report["issues"]
    assert report["system_complete"] is False
    assert len(report["premises"]) == 3
    assert all(item["proved"] for item in report["controls"]["useful"].values())
    forbidden = report["controls"]["forbidden"]
    assert forbidden and all(item["refused"] for item in forbidden.values())


@pytest.mark.parametrize(
    "original,replacement,reason",
    [
        (
            "        derive_program(body, signature, contracts)\n        if type(arguments)",
            "        if type(arguments)",
            "does not derive the captured snapshot",
        ),
        (
            "        body, signature, terminals, contracts = self._snapshot()\n        derive_program(body, signature, contracts)\n        if type(arguments)",
            "        body, signature, terminals, contracts = self._snapshot()\n        derive_program(body, signature, contracts)\n        contracts = {}\n        if type(arguments)",
            "rebinds a captured snapshot field",
        ),
        (
            "        body, signature, terminals, contracts = self._snapshot()\n        derive_program(body, signature, contracts)\n        if type(arguments)",
            "        body, signature, terminals, contracts = self.body, self.signature, self.terminals, self.contracts\n        derive_program(body, signature, contracts)\n        if type(arguments)",
            "capturing the program snapshot",
        ),
        ("        program.proof()\n", "", "does not prove the program at admission"),
    ],
)
def test_sandbox_mutations_leave_the_route_unproved(original, replacement, reason):
    sandbox, inprocess = sources()
    assert sandbox.count(original) == 1
    report = verify_language_route(sandbox.replace(original, replacement), inprocess)
    assert not report["proved"]
    assert any(reason in issue for issue in report["issues"]), report["issues"]


def test_terminal_execution_outside_invoke_is_unproved():
    sandbox, inprocess = sources()
    changed = (
        sandbox + "\n\ndef leak(terminals):\n    return terminals['read_text']('x')\n"
    )
    report = verify_language_route(changed, inprocess)
    assert not report["proved"]
    assert any("outside LanguageProgram.invoke" in i for i in report["issues"])


def test_rebound_checker_is_unproved():
    sandbox, inprocess = sources()
    changed = sandbox + "\n\ndef derive_program(*args):\n    return {}\n"
    report = verify_language_route(changed, inprocess)
    assert not report["proved"]
    assert any("rebound" in issue for issue in report["issues"])


@pytest.mark.parametrize("method", ["invoke", "ainvoke"])
def test_admission_must_validate_before_execution(method):
    sandbox, inprocess = sources()
    marker = (
        "    def invoke(self, arguments: Mapping[str, object]) -> object:\n"
        '        """Interpret the admitted program without invoking Python tool code."""\n'
        "        self.validate()\n"
        if method == "invoke"
        else "    async def ainvoke(self, arguments: Mapping[str, object]) -> object:\n"
        "        self.validate()\n"
    )
    assert inprocess.count(marker) == 1
    changed = inprocess.replace(marker, marker.replace("self.validate()", "pass"))
    report = verify_language_route(sandbox, changed)
    assert not report["proved"]
    assert any(f"{method} does not validate first" in i for i in report["issues"])


def test_validated_sync_path_must_still_use_the_admitted_program():
    sandbox, inprocess = sources()
    original = "        return program.invoke(dict(arguments))"
    assert inprocess.count(original) == 1
    changed = inprocess.replace(original, "        return dict(arguments)")
    report = verify_language_route(sandbox, changed)
    assert not report["proved"]
    assert any(
        "invoke does not execute through program.invoke" in issue
        for issue in report["issues"]
    )


def test_unparsable_source_is_unproved():
    _, inprocess = sources()
    report = verify_language_route("def (", inprocess)
    assert not report["proved"]
