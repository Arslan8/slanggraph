"""Run the developer acceptance checks and print an actionable repair queue.

Default success is route scoped. It requires an empty regression queue and a
complete `route_verification.verify_routes` report: every route that
`docs/security/supported-surface.json` marks supported has its applicable
SGV901/SGV902/SGV903 obligations discharged by checks recomputed from the
current sources, and its exclusions are gated by registered refusal codes.

Whole-system completeness (`complete`) is still computed from the layered
evidence and still reported, and SGV901-SGV903 stay listed as verifier-owned
proof gaps; each gap now carries a `route_scope` naming the supported routes
on which the obligation is discharged or open. Regression-pattern absence is
reported separately and never turns missing evidence into an acceptance pass.
`--require-regression-clean` is an explicit CI mode that fails on known
implementation findings while continuing to report verifier-owned proof gaps;
it does not change or imply acceptance. `--require-complete` demands
whole-system completeness: the former default gate, which stays unreachable
until the SGV901-SGV903 proof work lands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.adapter_verification import RULES
from langgraph.prebuilt.security.layered_verification import verify_layers
from langgraph.prebuilt.security.route_verification import (
    OBLIGATION_IDS,
    verify_routes,
)

ROUTE_SCOPE_NOT_EVALUATED = "not evaluated"
ROUTE_SCOPE_DISCHARGED = "discharged on every supported route"


def _task(
    rule: str,
    owner: str,
    message: str,
    fix: str,
    *,
    path: str = "",
    line: int = 1,
    evidence: str = "",
) -> dict[str, Any]:
    identity = "\0".join((rule, path, evidence or message))
    return {
        "rule": rule,
        "owner": owner,
        "status": "unresolved",
        "path": path,
        "line": line,
        "symbol": "",
        "message": message,
        "fix": fix,
        "fingerprint": hashlib.sha256(identity.encode()).hexdigest(),
    }


def _supported_routes(routes: dict[str, Any] | None) -> list[dict[str, Any]]:
    if routes is None:
        return []
    return [
        route
        for route in routes.get("routes") or []
        if isinstance(route, dict) and route.get("status") == "supported"
    ]


def _obligation(route: dict[str, Any], rule: str) -> dict[str, Any] | None:
    obligations = route.get("obligations")
    if not isinstance(obligations, dict):
        return None
    item = obligations.get(rule)
    return item if isinstance(item, dict) else None


def _route_scope(rule: str, routes: dict[str, Any] | None) -> str:
    """Describe where a proof gap stands on the manifest's supported routes.

    The annotation never removes the gap: discharge on every supported route
    is a route-scoped statement and leaves the whole-system obligation open.
    A route whose obligation is undeclared or not discharged counts as open.
    """
    if routes is None:
        return ROUTE_SCOPE_NOT_EVALUATED
    supported = _supported_routes(routes)
    if not supported:
        return f"{ROUTE_SCOPE_NOT_EVALUATED} (manifest declares no supported route)"
    open_routes = []
    for route in supported:
        item = _obligation(route, rule)
        if item is None or item.get("discharged") is not True:
            open_routes.append(str(route.get("id")))
    if open_routes:
        return "open on " + ", ".join(open_routes)
    return ROUTE_SCOPE_DISCHARGED


def developer_report(
    evidence: dict[str, Any], routes: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Project fresh evidence into repair tasks; never accept saved pass flags.

    `routes` is a fresh `verify_routes` report or None when route-scoped
    verification did not run. Acceptance passes only when the regression
    queue is empty and `routes` is complete; `complete` stays the whole-system
    verdict and is unaffected by `routes`.
    """
    tasks = list(evidence["adapters"]["diagnostics"])
    for issue in evidence["placement"]["issues"]:
        tasks.append(
            _task(
                "SGV190",
                "verifier",
                issue,
                "Restore the input or extend the operation/adaptor inventory and its regression tests.",
            )
        )
    router = evidence["router"]
    if not router["complete"]:
        for issue in router["issues"] + router.get("runtime_binding", {}).get(
            "issues", []
        ):
            tasks.append(
                _task(
                    "SGV201",
                    "implementation",
                    issue,
                    "Restore the required router authorization protocol and exact input/effect binding.",
                )
            )
        for entry in router.get("source_proof", {}).get("entries", []):
            if entry["status"] != "verified":
                tasks.append(
                    _task(
                        "SGV201",
                        "implementation",
                        f"{entry['entry']}: {entry['status']}",
                        "Resolve the source-proof issues; see evidence.router.source_proof.entries.",
                        evidence=entry["entry"],
                    )
                )
        if not any(task["rule"] == "SGV201" for task in tasks):
            tasks.append(
                _task(
                    "SGV201",
                    "verifier",
                    "Router certificate is incomplete",
                    "Inspect the source proof and runtime-binding evidence.",
                )
            )
    for finding in evidence["escape_discovery"]["unwaived_findings"]:
        tasks.append(
            _task(
                "SGV301",
                "implementation",
                finding["message"],
                "Mediate or reject the path. If it is a false positive, review this exact finding; a waiver is not a proof.",
                path="libs/" + finding["path"],
                line=finding["line"],
                evidence=finding["fingerprint"],
            )
        )
    for issue in evidence["escape_discovery"]["errors"]:
        tasks.append(
            _task(
                "SGV302",
                "implementation",
                issue,
                "Reconcile stale/malformed waivers against current source. Do not shift fingerprints or accept new paths automatically.",
                path="docs/security/escape-waivers.json",
            )
        )
    gaps = []
    if not evidence["placement"]["path_cover_proved"]:
        gaps.append(
            _task(
                "SGV901",
                "verifier",
                "Complete placement proof is not implemented",
                "Extend the placement checker to prove all effect paths, supported shapes, inherited APIs, callbacks and exceptional exits. Regression-pattern absence is insufficient.",
            )
        )
    if not evidence["adapters"]["proof"] or not evidence.get("publications", {}).get(
        "complete", False
    ):
        gaps.append(
            _task(
                "SGV902",
                "verifier",
                "Adapter composition proof is not implemented",
                "Resolve source-bound API obligations and publication transfer issues in evidence.obligations and evidence.publications. Prove authoritative identity, labels, approval semantics and effect atomicity; passing review patterns is insufficient.",
            )
        )
    # The router explicitly assumes these adapter properties. They are not
    # discharged by trusting kernel MAC or by a passing source inventory.
    gaps.append(
        _task(
            "SGV903",
            "verifier",
            "Host adapter/isolation contract lacks composition evidence",
            "Bind confinement activation, worker-channel identity and lifetime to the exact request. Trust MAC correctness; do not infer adapter correctness from that premise.",
        )
    )
    for gap in gaps:
        gap["route_scope"] = _route_scope(gap["rule"], routes)
    complete = bool(evidence["complete"] and not tasks and not gaps)
    route_complete = routes is not None and routes.get("complete") is True
    acceptance_passed = bool(not tasks and route_complete)
    return {
        "schema_version": 2,
        "kind": "slanggraph-developer-verification",
        "regression_checks_passed": not tasks,
        "acceptance_passed": acceptance_passed,
        "complete": complete,
        "tasks": sorted(
            tasks,
            key=lambda item: (
                item["rule"],
                item["path"],
                item["line"],
                item["fingerprint"],
            ),
        ),
        "proof_gaps": gaps,
        "route_acceptance": routes,
        "summary": {
            "implementation_tasks": sum(
                task["owner"] == "implementation" for task in tasks
            ),
            "verifier_tasks": sum(task["owner"] == "verifier" for task in tasks)
            + len(gaps),
            "router": router["summary"],
            "host_output_correspondence_proved": evidence.get(
                "host_output_correspondence", {}
            ).get("proved", False),
            "output_data_primitive_contracts_complete": evidence.get(
                "output_data_primitives", {}
            ).get("primitive_contracts_complete", False),
            "admission_surface_proved": evidence.get("admission_surface", {}).get(
                "proved", False
            ),
            "declared_api_obligations": len(evidence.get("obligations", [])),
            "publication_model_closed": evidence.get("publications", {}).get(
                "complete", False
            ),
            "publication_analysis": evidence.get("publications", {})
            .get("proof", {})
            .get("summary", {}),
            "route_scoped_acceptance": bool(route_complete),
            "route_summary": routes.get("summary") if routes is not None else None,
        },
        "evidence": evidence,
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def compare_reports(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, list[str]]:
    """Compare task identities only; the previous report never grants approval."""
    if previous.get("kind") != "slanggraph-developer-verification" or previous.get(
        "schema_version"
    ) not in {1, 2}:
        raise ValueError(
            "comparison file must be a developer-verification report (schema 1 or 2)"
        )
    before = {item["fingerprint"] for item in previous["tasks"]}
    after = {item["fingerprint"] for item in current["tasks"]}
    return {
        "new": sorted(after - before),
        "resolved": sorted(before - after),
        "remaining": sorted(after & before),
    }


def _obligation_status(item: dict[str, Any] | None) -> str:
    if item is None:
        return "FAIL(undeclared)"
    if item.get("discharged") is True:
        return "ok" if item.get("applicable") else "ok (not applicable)"
    failing = [
        str(check.get("id"))
        for check in item.get("checks") or []
        if isinstance(check, dict) and check.get("passed") is not True
    ]
    return "FAIL(" + (", ".join(failing) or "no evidence") + ")"


def _route_lines(routes: dict[str, Any] | None) -> list[str]:
    if routes is None:
        return ["Route-scoped acceptance: FAIL (not evaluated)."]
    verdict = "PASS" if routes.get("complete") is True else "FAIL"
    lines = [f"Route-scoped acceptance: {verdict} (claim: {routes.get('claim')})"]
    lines.append(
        f"  Lean audit {'run' if routes.get('lean_audit_run') else 'skipped'}; "
        f"evidence dir: {routes.get('evidence_dir')}"
    )
    for route in _supported_routes(routes):
        statuses = ", ".join(
            f"{rule} {_obligation_status(_obligation(route, rule))}"
            for rule in OBLIGATION_IDS
        )
        lines.append(f"  {route.get('id')}: {statuses}")
    for entry in routes.get("ungated_exclusions") or []:
        if isinstance(entry, dict):
            label = entry.get("feature") or entry.get("entry") or entry
            lines.append(
                f"  Ungated exclusion: {entry.get('route') or '<manifest>'}: {label}"
            )
        else:
            lines.append(f"  Ungated exclusion: {entry}")
    for entry in routes.get("unregistered_gates") or []:
        if isinstance(entry, dict):
            lines.append(
                f"  Unregistered gate: {entry.get('route')}: {entry.get('gate_code')}"
            )
        else:
            lines.append(f"  Unregistered gate: {entry}")
    for issue in routes.get("issues") or []:
        lines.append(f"  Issue: {issue}")
    return lines


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    router = summary["router"]
    lines = [
        f"Router: {router['verified']}/{router['discovered']} verified.",
        f"Acceptance: {'PASS' if report['acceptance_passed'] else 'FAIL'}. System completeness: {'PROVED' if report['complete'] else 'NOT ESTABLISHED'}.",
        *_route_lines(report.get("route_acceptance")),
        f"Known regression checks: {'PASS' if report['regression_checks_passed'] else 'FAIL'} (not a proof).",
        f"Declared definition obligations: {summary['declared_api_obligations']}; conditional publication entry results: {summary['publication_analysis']}.",
        f"Publication source model closed: {summary['publication_model_closed']} (entry results alone do not establish closure).",
    ]
    for rule in sorted({task["rule"] for task in report["tasks"]}):
        tasks = [task for task in report["tasks"] if task["rule"] == rule]
        lines.append(f"\n{rule}: {len(tasks)} finding(s)")
        for task in tasks:
            location = (
                f"{task['path']}:{task['line']}" if task["path"] else task["symbol"]
            )
            lines.append(f"  [{task['owner']}] {location} {task['message']}")
        for fix in dict.fromkeys(task["fix"] for task in tasks):
            lines.append(f"  Fix: {fix}")
    lines.append(
        "\nVerifier-owned proof work (blocks whole-system completeness; not assigned to implementation authors):"
    )
    for gap in report["proof_gaps"]:
        lines.extend(
            (
                f"  {gap['rule']}: {gap['message']}",
                f"  Route scope: {gap.get('route_scope', ROUTE_SCOPE_NOT_EVALUATED)}",
                f"  Next: {gap['fix']}",
            )
        )
    if "comparison" in report:
        lines.append(
            "\nCompared with previous run: "
            + ", ".join(
                f"{len(values)} {name}" for name, values in report["comparison"].items()
            )
        )
    lines.append(
        "\nAcceptance is route scoped: it requires every supported route's proof obligations and an empty regression queue; it does not establish whole-system completeness. Unknown analysis, missing evidence and budget exhaustion cannot pass. JSON includes the source-bound API ledger, the route report and raw evidence."
    )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", type=Path, default=Path(__file__).resolve().parents[5]
    )
    parser.add_argument(
        "--output", type=Path, help="write full JSON evidence and repair tasks"
    )
    parser.add_argument(
        "--compare", type=Path, help="compare task fingerprints with a previous report"
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "exit 0 only on whole-system completeness instead of route-scoped "
            "acceptance; this is the former default gate and stays unreachable "
            "until the SGV901-SGV903 proof work lands"
        ),
    )
    parser.add_argument(
        "--require-regression-clean",
        action="store_true",
        help=(
            "fail on known implementation regressions, but report verifier-owned "
            "proof gaps without treating them as system acceptance"
        ),
    )
    parser.add_argument(
        "--no-lean-audit",
        action="store_true",
        help=(
            "skip the lean audits; every lean-audit check then fails as not run, "
            "so route-scoped acceptance cannot pass"
        ),
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "directory under which each lean audit writes a new output directory "
            "(an existing output directory is refused); default: a fresh "
            "temporary directory"
        ),
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="describe the shipped adapter checks without running them",
    )
    args = parser.parse_args(argv)
    if args.list_checks:
        for rule in RULES:
            print(f"{rule.id}: {rule.title}\n  {rule.fix}")
        print(
            "SGV201: Router proof; SGV301/302: Escape findings/waivers; SGV901–903: Verifier-owned proof gaps."
        )
        return 0
    try:
        repo = args.repo.resolve()
        evidence_dir = (
            args.evidence_dir.resolve() if args.evidence_dir is not None else None
        )
        if evidence_dir is None and not args.no_lean_audit:
            evidence_dir = Path(tempfile.mkdtemp(prefix="developer-verification-"))
        evidence = verify_layers(repo)
        routes = verify_routes(
            repo,
            run_lean_audit=not args.no_lean_audit,
            evidence_dir=evidence_dir,
        )
        report = developer_report(evidence, routes)
        if args.compare:
            report["comparison"] = compare_reports(
                report, json.loads(args.compare.read_text())
            )
        if args.output:
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"SGV190: Verification input/report error: {exc}")
        return 2
    print(render_text(report), end="")
    if args.require_regression_clean:
        return 0 if report["regression_checks_passed"] else 1
    if args.require_complete:
        return 0 if report["complete"] else 1
    return 0 if report["acceptance_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
