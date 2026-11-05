"""Route-scoped acceptance verifier for `docs/security/supported-surface.json`.

The manifest names, per route, the SGV901/SGV902/SGV903 obligations and the
check identifiers whose evidence discharges them. This module recomputes
every named check from the current sources at verification time. No saved
report is ever read to satisfy a proof check; the only JSON inputs are the
manifest itself and runtime-evidence records, and those never count as proof.

Acceptance is route scoped: `complete` means every route the manifest marks
`supported` has every applicable obligation discharged, every exclusion of a
supported route is gated by a registered refusal code, and no exclusion is
ungated. It never promotes to whole-system completeness; `system_complete`
stays False.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security import unsupported
from langgraph.prebuilt.security.boundary_verification import verify_host_router
from langgraph.prebuilt.security.host_verification import verify_linux_host_route
from langgraph.prebuilt.security.output_data_verification import (
    verify_output_data_primitives,
)
from langgraph.prebuilt.security.output_verification import verify_output_correspondence

MANIFEST = "docs/security/supported-surface.json"
MANIFEST_SCHEMA_VERSION = 2
REPORT_SCHEMA_VERSION = 1
KIND = "route-scoped-acceptance"
OBLIGATION_IDS = ("SGV901", "SGV902", "SGV903")
CLAIM = (
    "Route-scoped acceptance only: every supported route in the manifest has "
    "its applicable SGV901/SGV902/SGV903 obligations discharged by checks "
    "recomputed from the current sources, and its exclusions are gated by "
    "registered refusal codes. This is not whole-system completeness; "
    "unsupported routes, ungated capabilities and the premises listed in the "
    "manifest remain open."
)
_SECURITY = "libs/prebuilt/langgraph/prebuilt/security/"
_LEAN_SUBPROCESS_TIMEOUT = 3600
_PASS_FIELDS = ("passed", "ok", "complete")
_HASH_KEYS = ("source_sha256", "source_identity", "sources")


class _CheckFailure(Exception):
    """A check cannot pass; the message is the recorded detail."""


@dataclass
class _Context:
    repo: Path
    run_lean_audit: bool
    evidence_dir: Path | None
    lake: Path | None
    results: dict[str, dict[str, Any]] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)

    def source(self, relative: str) -> str:
        path = self.repo / relative
        if not path.is_file():
            raise _CheckFailure(f"missing source: {relative}")
        return path.read_text(encoding="utf-8")

    def inside(self, relative: str) -> Path:
        """Refuse manifest paths that lexically escape the repository.

        Containment is checked on the normalised path, not the symlink
        target, so a repository may contain links while `..` escapes and
        absolute paths are refused.
        """
        root = os.path.normpath(os.path.abspath(self.repo))
        candidate = os.path.normpath(os.path.join(root, relative))
        if os.path.isabs(relative) or not candidate.startswith(root + os.sep):
            raise _CheckFailure(f"path escapes repository: {relative}")
        return Path(candidate)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _result(
    check_id: str,
    *,
    passed: bool,
    proof: bool,
    recomputed: bool,
    detail: str,
    source_sha256: dict[str, str] | None = None,
) -> dict[str, Any]:
    # A proof claim is never recorded for a failing or non-recomputed check.
    return {
        "id": check_id,
        "passed": bool(passed),
        "proof": bool(proof and passed and recomputed),
        "recomputed": bool(recomputed),
        "detail": detail,
        "source_sha256": dict(source_sha256 or {}),
    }


def _load_component(module: str, attribute: str) -> Callable[..., Any]:
    """Import a component lazily; a missing module or function is a failure."""
    try:
        loaded = importlib.import_module(module)
        function = getattr(loaded, attribute)
    except (ImportError, AttributeError) as exc:
        raise _CheckFailure(
            f"component missing: {module}.{attribute} ({type(exc).__name__})"
        ) from None
    if not callable(function):
        raise _CheckFailure(f"component missing: {module}.{attribute} not callable")
    return function


# --- fixed check ids ---------------------------------------------------------


def _check_router_source_proof(ctx: _Context, check_id: str) -> dict[str, Any]:
    report = verify_host_router()
    summary = report.get("summary") if isinstance(report, dict) else None
    if not isinstance(summary, dict):
        raise _CheckFailure("router report lacks a summary")
    verified, discovered = summary.get("verified"), summary.get("discovered")
    passed = (
        report.get("complete") is True
        and isinstance(verified, int)
        and isinstance(discovered, int)
        and discovered > 0
        and verified == discovered
    )
    binding = report.get("runtime_binding")
    hashes = {}
    if isinstance(binding, dict) and isinstance(binding.get("source_sha256"), str):
        hashes[_SECURITY + "host_router.py"] = binding["source_sha256"]
    audited = ctx.repo / _SECURITY / "host_router.py"
    if audited.is_file() and hashes.get(_SECURITY + "host_router.py") != _sha256_file(
        audited
    ):
        passed = False
        detail = "loaded router does not match the audited repository source"
    else:
        detail = (
            f"router source proof complete={report.get('complete')} "
            f"verified={verified} discovered={discovered}"
        )
    return _result(
        check_id,
        passed=passed,
        proof=True,
        recomputed=True,
        detail=detail,
        source_sha256=hashes,
    )


def _check_host_output_correspondence(ctx: _Context, check_id: str) -> dict[str, Any]:
    host = ctx.source(_SECURITY + "object_manager.py")
    objects = ctx.source(_SECURITY + "objects.py")
    output_data = ctx.source(_SECURITY + "output_data.py")
    report = verify_output_correspondence(host, objects, output_data_source=output_data)
    passed = isinstance(report, dict) and report.get("proved") is True
    return _result(
        check_id,
        passed=passed,
        proof=True,
        recomputed=True,
        detail=f"host-output correspondence proved={passed}",
        source_sha256={
            _SECURITY + "object_manager.py": _sha256_text(host),
            _SECURITY + "objects.py": _sha256_text(objects),
            _SECURITY + "output_data.py": _sha256_text(output_data),
        },
    )


def _check_output_validator_contract(ctx: _Context, check_id: str) -> dict[str, Any]:
    output_data = ctx.source(_SECURITY + "output_data.py")
    objects = ctx.source(_SECURITY + "objects.py")
    report = verify_output_data_primitives(output_data, objects)
    flags = ("proved", "validator_admission_proved", "effect_safety_proved")
    passed = isinstance(report, dict) and all(
        report.get(flag) is True for flag in flags
    )
    return _result(
        check_id,
        passed=passed,
        proof=True,
        recomputed=True,
        detail="output validator contract "
        + ", ".join(
            f"{flag}={report.get(flag) if isinstance(report, dict) else None}"
            for flag in flags
        ),
        source_sha256={
            _SECURITY + "output_data.py": _sha256_text(output_data),
            _SECURITY + "objects.py": _sha256_text(objects),
        },
    )


def _check_output_mediator_correspondence(
    ctx: _Context, check_id: str
) -> dict[str, Any]:
    verify = _load_component(
        "langgraph.prebuilt.security.output_mediator_verification",
        "verify_output_mediator_correspondence",
    )
    names = (
        "placement.py",
        "host_router.py",
        "output_data.py",
        "objects.py",
        "object_manager.py",
    )
    sources = {name: ctx.source(_SECURITY + name) for name in names}
    report = verify(
        sources["placement.py"],
        router_source=sources["host_router.py"],
        output_data_source=sources["output_data.py"],
        objects_source=sources["objects.py"],
        object_manager_source=sources["object_manager.py"],
    )
    passed = isinstance(report, dict) and report.get("proved") is True
    return _result(
        check_id,
        passed=passed,
        proof=True,
        recomputed=True,
        detail=f"output mediator correspondence proved={passed}",
        source_sha256={
            _SECURITY + name: _sha256_text(text) for name, text in sources.items()
        },
    )


def _admission_proved_mapping(report: Any) -> dict[str, Any]:
    """Return the per-obligation proved flags; any other shape is a failure.

    Accepted shapes: `proved` as a non-empty mapping of obligation to flag, or
    `proved` as a bool alongside a non-empty `obligations` mapping whose
    entries each carry their own `proved` flag. A bare bool without the
    per-obligation breakdown is not accepted.
    """
    if not isinstance(report, dict):
        raise _CheckFailure("admission report is not an object")
    proved = report.get("proved")
    if isinstance(proved, dict):
        if not proved:
            raise _CheckFailure("admission report proved mapping is empty")
        return dict(proved)
    obligations = report.get("obligations")
    if (
        isinstance(proved, bool)
        and isinstance(obligations, dict)
        and obligations
        and all(isinstance(item, dict) for item in obligations.values())
    ):
        flags = {
            str(key): item.get("proved") is True for key, item in obligations.items()
        }
        if proved and not all(flags.values()):
            raise _CheckFailure("admission report proved flag disagrees with items")
        return {key: value and proved for key, value in flags.items()}
    raise _CheckFailure("admission report lacks a per-obligation proved mapping")


def _check_language_derivation(ctx: _Context, check_id: str) -> dict[str, Any]:
    verify = _load_component(
        "langgraph.prebuilt.security.language_route_verification",
        "verify_language_route",
    )
    names = ("_language_sandbox.py", "inprocess.py")
    sources = {name: ctx.source(_SECURITY + name) for name in names}
    report = verify(sources["_language_sandbox.py"], sources["inprocess.py"])
    passed = isinstance(report, dict) and report.get("proved") is True
    issues = report.get("issues", []) if isinstance(report, dict) else []
    return _result(
        check_id,
        passed=passed,
        proof=True,
        recomputed=True,
        detail=(
            "language route proved under the threat-model premises (interpreter, "
            "terminals and admission trusted)"
            if passed
            else "language route unproved: " + "; ".join(map(str, issues))[:300]
        ),
        source_sha256={
            _SECURITY + name: _sha256_text(text) for name, text in sources.items()
        },
    )


def _check_dataset_read(ctx: _Context, check_id: str) -> dict[str, Any]:
    verify = _load_component(
        "langgraph.prebuilt.security.dataset_route_verification",
        "verify_dataset_route",
    )
    source = ctx.source(_SECURITY + "dataset_operation.py")
    report = verify(source)
    passed = isinstance(report, dict) and report.get("proved") is True
    issues = report.get("issues", []) if isinstance(report, dict) else []
    return _result(
        check_id,
        passed=passed,
        proof=True,
        recomputed=True,
        detail=(
            "dataset_read ordering derived and controls pass"
            if passed
            else "dataset_read unproved: " + "; ".join(map(str, issues))[:300]
        ),
        source_sha256={_SECURITY + "dataset_operation.py": _sha256_text(source)},
    )


def _check_operation_catalog(ctx: _Context, check_id: str) -> dict[str, Any]:
    verify = _load_component(
        "langgraph.prebuilt.security.operation_catalog", "verify_catalog"
    )
    report = verify(ctx.repo)
    passed = isinstance(report, dict) and report.get("complete") is True
    issues = report.get("issues", []) if isinstance(report, dict) else []
    return _result(
        check_id,
        passed=passed,
        proof=False,
        recomputed=True,
        detail=(
            "runtime operation catalog complete: every operation proved or a stated premise"
            if passed
            else "operation catalog incomplete: " + "; ".join(map(str, issues))[:300]
        ),
        source_sha256={
            "docs/security/runtime-operations.json": _sha256_text(
                ctx.source("docs/security/runtime-operations.json")
            )
        },
    )


def _check_admission_surface(ctx: _Context, check_id: str) -> dict[str, Any]:
    verify = _load_component(
        "langgraph.prebuilt.security.admission_verification",
        "verify_admission_surface",
    )
    names = ("admission.py", "config.py", "placement.py", "mac.py")
    sources = {name: ctx.source(_SECURITY + name) for name in names}
    report = verify(*(sources[name] for name in names))
    proved = _admission_proved_mapping(report)
    failing = sorted(str(key) for key, value in proved.items() if value is not True)
    return _result(
        check_id,
        passed=not failing,
        proof=True,
        recomputed=True,
        detail=f"admission surface proved for all {len(proved)} obligations"
        if not failing
        else "admission surface unproved: " + ", ".join(failing),
        source_sha256={
            _SECURITY + name: _sha256_text(text) for name, text in sources.items()
        },
    )


def _check_linux_host_route(ctx: _Context, check_id: str) -> dict[str, Any]:
    linux = ctx.source(_SECURITY + "linux.py")
    worker = ctx.source(_SECURITY + "_linux_worker.py")
    report = verify_linux_host_route(linux, worker, repo=ctx.repo)
    checks = report.get("structural_checks") if isinstance(report, dict) else None
    if not isinstance(checks, dict) or not checks:
        raise _CheckFailure("linux host route report lacks structural checks")
    failing = sorted(str(key) for key, value in checks.items() if value is not True)
    return _result(
        check_id,
        passed=not failing,
        proof=False,
        recomputed=True,
        detail=(
            f"structural regression check; {len(checks)} checks hold, no proof"
            if not failing
            else "structural regression check failing: " + ", ".join(failing)
        ),
        source_sha256={
            _SECURITY + "linux.py": _sha256_text(linux),
            _SECURITY + "_linux_worker.py": _sha256_text(worker),
        },
    )


# --- prefixed check ids ------------------------------------------------------


def _execute_lean_audit(check_py: Path, output: Path, lake: Path) -> dict[str, Any]:
    """Run the audit driver into a fresh directory and return its report."""
    command = [
        sys.executable,
        str(check_py),
        "--output",
        str(output),
        "--lake",
        str(lake),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(check_py.parent),
            capture_output=True,
            text=True,
            timeout=_LEAN_SUBPROCESS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise _CheckFailure("lean audit timed out") from None
    report_path = output / "report.json"
    if not report_path.is_file():
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise _CheckFailure(
            f"lean audit exited {completed.returncode} without report.json"
            + (f": {tail[-1]}" if tail else "")
        )
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _CheckFailure(f"lean audit report unreadable: {exc}") from None
    if not isinstance(report, dict):
        raise _CheckFailure("lean audit report is not an object")
    return report


def _lean_output_dir(ctx: _Context, relative: str) -> Path:
    if ctx.evidence_dir is None:
        raise _CheckFailure("lean audit needs an evidence_dir")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "__", relative.strip("/")) or "root"
    output = ctx.evidence_dir / "lean-audit" / slug
    if output.exists():
        raise _CheckFailure(f"refusing existing evidence directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def _check_lean_audit(ctx: _Context, check_id: str, relative: str) -> dict[str, Any]:
    directory = ctx.inside(relative)
    check_py = directory / "check.py"
    if not directory.is_dir() or not check_py.is_file():
        raise _CheckFailure(f"lean audit directory lacks check.py: {relative}")
    identities = {
        path.name: _sha256_file(path)
        for path in sorted(directory.glob("*.lean")) + [check_py]
    }
    if not ctx.run_lean_audit:
        return _result(
            check_id,
            passed=False,
            proof=False,
            recomputed=False,
            detail="lean audit not run",
            source_sha256={f"{relative}/{name}": h for name, h in identities.items()},
        )
    lake = ctx.lake or Path(os.environ.get("LAKE") or Path.home() / ".elan/bin/lake")
    if not lake.is_file():
        raise _CheckFailure(f"lake executable missing: {lake}")
    output = _lean_output_dir(ctx, relative)
    report = _execute_lean_audit(check_py, output, lake)
    flags = ("passed", "kernel_replay_checked", "kernel_typecheck_passed")
    failing = [flag for flag in flags if report.get(flag) is not True]
    recorded = report.get("source_after")
    if not isinstance(recorded, dict):
        raise _CheckFailure("lean audit report records no source_after identities")
    mismatched = sorted(
        name
        for name, digest in identities.items()
        if not isinstance(recorded.get(name), dict)
        or recorded[name].get("sha256") != digest
    )
    if failing or mismatched:
        detail = "lean audit failed: " + ", ".join(
            [*(f"{flag} is not true" for flag in failing)]
            + [f"identity mismatch {name}" for name in mismatched]
        )
        passed = False
    else:
        detail = (
            "kernel-checked captured finite model only; proof covers the model, "
            "not source/compiler/OS/runtime refinement; "
            f"{len(identities)} source identities match; output {output}"
        )
        passed = True
    return _result(
        check_id,
        passed=passed,
        proof=report.get("model_proved") is True,
        recomputed=True,
        detail=detail,
        source_sha256={f"{relative}/{name}": h for name, h in identities.items()},
    )


def _recorded_hashes(document: Any, found: list[tuple[str, str]]) -> None:
    """Collect `(path, sha256)` pairs from hash structures anywhere in a record."""
    if isinstance(document, dict):
        for key, value in document.items():
            if key in _HASH_KEYS and isinstance(value, dict):
                for path, entry in value.items():
                    digest = entry.get("sha256") if isinstance(entry, dict) else entry
                    if isinstance(path, str) and isinstance(digest, str):
                        found.append((path, digest))
            _recorded_hashes(value, found)
    elif isinstance(document, list):
        for item in document:
            _recorded_hashes(item, found)


def _check_runtime_evidence(
    ctx: _Context, check_id: str, relative: str
) -> dict[str, Any]:
    path = ctx.inside(relative)
    if not path.is_file():
        raise _CheckFailure(f"runtime evidence missing: {relative}")
    raw = path.read_text(encoding="utf-8")
    try:
        record = json.loads(raw)
    except ValueError as exc:
        raise _CheckFailure(f"runtime evidence unparsable: {exc}") from None
    if not isinstance(record, dict):
        raise _CheckFailure("runtime evidence is not an object")
    pass_field = next((name for name in _PASS_FIELDS if name in record), None)
    if pass_field is None:
        raise _CheckFailure(
            "runtime evidence has no pass field (" + "/".join(_PASS_FIELDS) + ")"
        )
    problems = []
    if record[pass_field] is not True:
        problems.append(f"{pass_field} is not true")
    for name in ("failures", "issues"):
        if isinstance(record.get(name), list) and record[name]:
            problems.append(f"{len(record[name])} recorded {name}")
    recorded: list[tuple[str, str]] = []
    _recorded_hashes(record, recorded)
    checked = 0
    for source_path, digest in recorded:
        candidate = ctx.repo / source_path
        if not candidate.is_file():
            continue
        checked += 1
        if _sha256_file(candidate) != digest:
            problems.append(f"source changed since recorded: {source_path}")
    if checked == 0:
        problems.append("no recorded source identities match the current tree")
    return _result(
        check_id,
        passed=not problems,
        proof=False,
        recomputed=False,
        detail="runtime evidence: "
        + (
            f"{pass_field} true, {checked} recorded source identities match; "
            "recorded run, not a proof and not recomputed"
            if not problems
            else "; ".join(problems)
        ),
        source_sha256={relative: _sha256_text(raw)},
    )


def _gate_registered(code: Any, *, prefix: bool) -> bool:
    if not isinstance(code, str) or not code:
        return False
    if code in unsupported.REGISTRY:
        return True
    if prefix:
        return code in unsupported.PREFIXES or f"{code}:" in unsupported.PREFIXES
    return False


def _check_gate(ctx: _Context, check_id: str, code: str) -> dict[str, Any]:
    exact = code in unsupported.REGISTRY
    prefixed = code in unsupported.PREFIXES or f"{code}:" in unsupported.PREFIXES
    return _result(
        check_id,
        passed=exact or prefixed,
        proof=False,
        recomputed=True,
        detail=(
            f"refusal code registered ({'exact' if exact else 'prefix'}); "
            "registration is not a proof of placement"
            if exact or prefixed
            else f"refusal code not registered: {code}"
        ),
    )


_FIXED_CHECKS: dict[str, Callable[[_Context, str], dict[str, Any]]] = {
    "router-source-proof": _check_router_source_proof,
    "host-output-correspondence": _check_host_output_correspondence,
    "output-validator-contract": _check_output_validator_contract,
    "output-mediator-correspondence": _check_output_mediator_correspondence,
    "language-derivation": _check_language_derivation,
    "dataset-read": _check_dataset_read,
    "operation-catalog": _check_operation_catalog,
    "admission-surface": _check_admission_surface,
    "host-route:linux-sandbox": _check_linux_host_route,
}
_PREFIXED_CHECKS: dict[str, Callable[[_Context, str, str], dict[str, Any]]] = {
    "lean-audit": _check_lean_audit,
    "runtime-evidence": _check_runtime_evidence,
    "gate": _check_gate,
}


def run_check(ctx: _Context, check_id: str) -> dict[str, Any]:
    """Recompute one check, memoised per verification run; never raises."""
    if check_id in ctx.results:
        return ctx.results[check_id]
    try:
        if not isinstance(check_id, str) or not check_id:
            raise _CheckFailure("check id is not a string")
        if check_id in _FIXED_CHECKS:
            result = _FIXED_CHECKS[check_id](ctx, check_id)
        else:
            kind, _, argument = check_id.partition(":")
            if kind in _PREFIXED_CHECKS and argument:
                result = _PREFIXED_CHECKS[kind](ctx, check_id, argument)
            else:
                ctx.unknown.append(check_id)
                raise _CheckFailure(f"unknown check id: {check_id}")
    except _CheckFailure as exc:
        result = _result(
            str(check_id), passed=False, proof=False, recomputed=False, detail=str(exc)
        )
    except Exception as exc:  # fail closed on any component error
        result = _result(
            str(check_id),
            passed=False,
            proof=False,
            recomputed=False,
            detail=f"check raised {type(exc).__name__}: {exc}",
        )
    ctx.results[str(check_id)] = result
    return result


# --- manifest ----------------------------------------------------------------


def _load_manifest(repo: Path) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    path = repo / MANIFEST
    if not path.is_file():
        return None, None, [f"manifest missing: {MANIFEST}"]
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return None, digest, [f"manifest unparsable: {exc}"]
    if not isinstance(manifest, dict):
        return None, digest, ["manifest is not an object"]
    version = manifest.get("schema_version")
    if version != MANIFEST_SCHEMA_VERSION:
        return (
            None,
            digest,
            [
                f"unsupported manifest schema_version: {version!r} "
                f"(expected {MANIFEST_SCHEMA_VERSION})"
            ],
        )
    if not isinstance(manifest.get("kind"), str) or not manifest["kind"]:
        return None, digest, ["manifest lacks a kind"]
    if not isinstance(manifest.get("routes"), list):
        return None, digest, ["manifest routes is not a list"]
    return manifest, digest, []


def _evaluate_obligation(
    ctx: _Context, route_id: str, obligation_id: str, declared: Any, issues: list[str]
) -> dict[str, Any]:
    if not isinstance(declared, dict):
        issues.append(f"{route_id}: obligation {obligation_id} not declared")
        return {
            "applicable": True,
            "reason": None,
            "required_evidence": [],
            "checks": [],
            "discharged": False,
        }
    applicable = declared.get("applicable")
    reason = declared.get("reason")
    evidence = declared.get("required_evidence")
    if applicable is not True and applicable is not False:
        issues.append(f"{route_id}: obligation {obligation_id} applicable not bool")
        applicable = True
    if not isinstance(reason, str) or not reason.strip():
        issues.append(f"{route_id}: obligation {obligation_id} has no reason")
    if not isinstance(evidence, list) or any(
        not isinstance(item, str) for item in evidence
    ):
        issues.append(f"{route_id}: obligation {obligation_id} evidence malformed")
        evidence = []
    checks = [run_check(ctx, check_id) for check_id in evidence]
    if applicable:
        discharged = bool(checks) and all(check["passed"] for check in checks)
    else:
        discharged = True
    return {
        "applicable": bool(applicable),
        "reason": reason if isinstance(reason, str) else None,
        "required_evidence": list(evidence),
        "checks": checks,
        "discharged": discharged,
    }


def _evaluate_route(
    ctx: _Context,
    route: Any,
    issues: list[str],
    ungated: list[dict[str, Any]],
    unregistered: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(route, dict) or not isinstance(route.get("id"), str):
        issues.append("route without a string id")
        route = (
            {"id": "<invalid>", "status": None}
            if not isinstance(route, dict)
            else {
                **route,
                "id": "<invalid>",
            }
        )
    route_id = route["id"]
    status = route.get("status")
    if status not in ("supported", "unsupported"):
        issues.append(f"{route_id}: unknown status {status!r}")
    supported = status == "supported"
    declared = route.get("obligations")
    if not isinstance(declared, dict):
        if supported:
            issues.append(f"{route_id}: obligations missing")
        declared = {}
    obligations = {}
    for obligation_id in OBLIGATION_IDS:
        route_issues: list[str] = []
        obligations[obligation_id] = _evaluate_obligation(
            ctx, route_id, obligation_id, declared.get(obligation_id), route_issues
        )
        if supported:
            issues.extend(route_issues)
    if supported and not any(item["applicable"] for item in obligations.values()):
        issues.append(f"{route_id}: no applicable obligation on a supported route")
    exclusions = []
    for raw in route.get("exclusions") or []:
        if not isinstance(raw, dict):
            if supported:
                issues.append(f"{route_id}: malformed exclusion")
            continue
        code = raw.get("gate_code")
        prefix = raw.get("gate_code_prefix") is True
        registered = _gate_registered(code, prefix=prefix)
        entry = {
            "feature": raw.get("feature"),
            "gate_code": code,
            "gate_code_prefix": prefix,
            "enforced_at": raw.get("enforced_at"),
            "registered": registered,
        }
        exclusions.append(entry)
        if supported and not code:
            ungated.append({"route": route_id, **entry})
        elif supported and not registered:
            unregistered.append({"route": route_id, **entry})
    discharged = all(item["discharged"] for item in obligations.values())
    gated = all(item["registered"] for item in exclusions)
    return {
        "id": route_id,
        "status": status,
        "accepted": bool(supported and discharged and gated),
        "obligations": obligations,
        "exclusions": exclusions,
    }


def verify_routes(
    repo: Path,
    *,
    run_lean_audit: bool = True,
    evidence_dir: Path | None = None,
    lake: Path | None = None,
) -> dict[str, Any]:
    """Recompute the manifest's route obligations against the current tree.

    `evidence_dir` receives fresh lean-audit output directories; an existing
    output directory is refused rather than reused. With `run_lean_audit`
    False every `lean-audit:` check fails as not run. Nothing here reads a
    previously saved verification report.
    """
    repo = Path(repo)
    ctx = _Context(
        repo=repo,
        run_lean_audit=run_lean_audit,
        evidence_dir=Path(evidence_dir) if evidence_dir is not None else None,
        lake=Path(lake) if lake is not None else None,
    )
    manifest, manifest_sha256, issues = _load_manifest(repo)
    routes: list[dict[str, Any]] = []
    ungated: list[dict[str, Any]] = []
    unregistered: list[dict[str, Any]] = []
    manifest_ok = manifest is not None
    if manifest is not None:
        listed = manifest.get("ungated_exclusions")
        if not isinstance(listed, list):
            issues.append("manifest ungated_exclusions is not a list")
        else:
            ungated.extend(
                item if isinstance(item, dict) else {"entry": item} for item in listed
            )
        for route in manifest["routes"]:
            routes.append(_evaluate_route(ctx, route, issues, ungated, unregistered))
        ids = [route["id"] for route in routes]
        if len(set(ids)) != len(ids):
            issues.append("duplicate route ids")
        if not any(route["status"] == "supported" for route in routes):
            issues.append("manifest declares no supported route")
        catalog = manifest.get("check_ids")
        if isinstance(catalog, dict):
            for check_id, result in ctx.results.items():
                entry = catalog.get(check_id)
                # A failing check claims nothing; only a passing result that
                # carries no proof contradicts a catalog entry marked as proof.
                if (
                    isinstance(entry, dict)
                    and entry.get("proof")
                    and result["passed"]
                    and not result["proof"]
                ):
                    issues.append(f"manifest overclaims proof for {check_id}")
    if ctx.unknown:
        issues.append("unknown check ids: " + ", ".join(sorted(set(ctx.unknown))))
    supported = [route for route in routes if route["status"] == "supported"]
    complete = bool(
        manifest_ok
        and not issues
        and supported
        and all(route["accepted"] for route in supported)
        and not ungated
        and not unregistered
        and not ctx.unknown
    )
    applicable = [
        item
        for route in supported
        for item in route["obligations"].values()
        if item["applicable"]
    ]
    failing = sorted(
        check_id for check_id, result in ctx.results.items() if not result["passed"]
    )
    return {
        "kind": KIND,
        "schema_version": REPORT_SCHEMA_VERSION,
        "manifest": MANIFEST,
        "manifest_ok": manifest_ok,
        "manifest_sha256": manifest_sha256,
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "claim": CLAIM,
        "system_complete": False,
        "complete": complete,
        "routes": routes,
        "checks": dict(sorted(ctx.results.items())),
        "ungated_exclusions": ungated,
        "unregistered_gates": unregistered,
        "unknown_check_ids": sorted(set(ctx.unknown)),
        "issues": issues,
        "lean_audit_run": bool(run_lean_audit),
        "evidence_dir": str(ctx.evidence_dir) if ctx.evidence_dir else None,
        "summary": {
            "routes": len(routes),
            "supported_routes": len(supported),
            "accepted_routes": sum(route["accepted"] for route in supported),
            "applicable_obligations": len(applicable),
            "discharged_obligations": sum(item["discharged"] for item in applicable),
            "checks_run": len(ctx.results),
            "checks_passed": len(ctx.results) - len(failing),
            "failing_checks": failing,
        },
    }


def _render_summary(report: dict[str, Any]) -> str:
    lines = [
        f"route-scoped acceptance: {'COMPLETE' if report['complete'] else 'NOT COMPLETE'}"
        " (system_complete=False)",
        f"manifest: {report['manifest']} sha256={report['manifest_sha256']}",
    ]
    for route in report["routes"]:
        obligations = route["obligations"].values()
        applicable = [item for item in obligations if item["applicable"]]
        discharged = sum(item["discharged"] for item in applicable)
        lines.append(
            f"  route {route['id']} [{route['status']}] accepted={route['accepted']} "
            f"obligations discharged {discharged}/{len(applicable)}"
        )
    summary = report["summary"]
    lines.append(f"checks: {summary['checks_passed']}/{summary['checks_run']} passed")
    for check_id in summary["failing_checks"]:
        lines.append(f"  FAIL {check_id}: {report['checks'][check_id]['detail']}")
    for entry in report["ungated_exclusions"]:
        lines.append(
            f"  ungated exclusion: {entry.get('route')}: {entry.get('feature')}"
        )
    for entry in report["unregistered_gates"]:
        lines.append(
            f"  unregistered gate: {entry.get('route')}: {entry.get('gate_code')}"
        )
    for issue in report["issues"]:
        lines.append(f"  issue: {issue}")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", type=Path, default=Path(__file__).resolve().parents[5]
    )
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    parser.add_argument(
        "--no-lean-audit",
        action="store_true",
        help="skip lean audits; every lean-audit check then fails as not run",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="directory for fresh lean-audit outputs (default: a new temp dir)",
    )
    parser.add_argument("--lake", type=Path, help="Lake executable")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"error: repository is not a directory: {repo}", file=sys.stderr)
        return 2
    evidence_dir = (
        args.evidence_dir.resolve() if args.evidence_dir is not None else None
    )
    if evidence_dir is None and not args.no_lean_audit:
        evidence_dir = Path(tempfile.mkdtemp(prefix="route-verification-"))
    report = verify_routes(
        repo,
        run_lean_audit=not args.no_lean_audit,
        evidence_dir=evidence_dir,
        lake=args.lake,
    )
    if args.output is not None:
        try:
            args.output.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
    print(_render_summary(report))
    if evidence_dir is not None:
        print(f"evidence dir: {evidence_dir}")
    if not report["manifest_ok"]:
        for issue in report["issues"]:
            print(f"error: {issue}", file=sys.stderr)
        return 2
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
