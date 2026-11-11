"""Production qualification for best-available nono and APF enforcement."""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from typing import Any

from campaign import ROOT

RUNNER = ROOT / "eval/campaigns/langgraph-demos-v3/permissive-comparators/run_campaign.py"
RAW = ROOT / "eval/campaigns/langgraph-demos-v3/raw"


def _runner():
    name = "unified_final_comparator_qualification"
    spec = importlib.util.spec_from_file_location(name, RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load comparator runner: {RUNNER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        name: row.get(name)
        for name in (
            "mode",
            "status",
            "correct",
            "process_wall_ms",
            "invocation_ms",
            "preparation_ms",
            "sandbox_preparation_ms",
            "sandbox_cleanup_ms",
            "sandbox_cleanup_confirmed",
            "preflight_ns",
            "runtime_start_ns",
            "runtime_end_ns",
            "runtime_ns",
            "ready_observed",
            "filesystem_and_network_policy_enforced",
            "semantic_resource_action_mediation",
        )
    }


def run() -> dict[str, Any]:
    """Run real enforcement probes and one live application in each comparator."""
    module = _runner()
    root = RAW / f"unified-final-comparator-{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=False)
    module.run_enforcement_probes(
        root,
        nono=module.DEFAULT_NONO,
        openshell=module.DEFAULT_OPENSHELL,
        endpoint="http://127.0.0.1:18080",
    )
    probes = json.loads((root / "enforcement-probes.json").read_text())
    tasks = json.loads((module.V1 / "tasks.json").read_text())
    rows = []
    for mode in ("NoNo-enforced", "APF-enforced"):
        job = module.base.Job("T5-prebuilt-multiply", 1, 0, mode)
        rows.append(
            module.execute_external(
                job,
                root,
                tasks,
                nono=module.DEFAULT_NONO,
                openshell=module.DEFAULT_OPENSHELL,
                endpoint="http://127.0.0.1:18080",
            )
        )
    passed = (
        all(probes["nono"].values())
        and all(probes["apf_openshell"].values())
        and all(row["status"] == "completed" and row["correct"] for row in rows)
        and all(row["ready_observed"] is True and row["runtime_ns"] > 0 for row in rows)
        and all(row["filesystem_and_network_policy_enforced"] is True for row in rows)
        and all(row["semantic_resource_action_mediation"] is False for row in rows)
    )
    return {
        "scope": "best available reduced enforcement; not Argus semantic equivalence",
        "application": "T5-prebuilt-multiply",
        "raw_evidence": str(root.relative_to(ROOT)),
        "enforcement_probes": probes,
        "application_rows": [_summary(row) for row in rows],
        "omitted_obligations": [
            "typed library object/action mediation",
            "admitted-language direct-bypass prevention",
        ],
        "passed": passed,
    }
