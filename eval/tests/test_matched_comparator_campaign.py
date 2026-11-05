from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN = ROOT / "eval/campaigns/langgraph-demos-v3/permissive-comparators"


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, CAMPAIGN / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_apf_arguments_bind_only_inputs_and_outputs() -> None:
    campaign = load_module("matched_comparator_campaign", "run_campaign.py")
    trial = Path("/host/trial")
    resource = Path("/host/resource/document.json")
    command = [
        "/python",
        "--document",
        str(resource),
        "--output",
        str(trial / "output.json"),
    ]

    remapped = campaign.remap_apf_arguments(
        command, trial, Path("/workspace/results"), [(resource, resource)]
    )

    assert remapped == [
        "/python",
        "--document",
        "/host/resource/document.json",
        "--output",
        "/workspace/results/output.json",
    ]


def test_apf_sandbox_names_fit_openshell_limit_and_separate_apps(tmp_path: Path) -> None:
    campaign = load_module("matched_comparator_campaign_names", "run_campaign.py")
    first = campaign.base.Job("T1-add-tools", 1, 4, "APF-enforced")
    second = campaign.base.Job("D5-support", 1, 4, "APF-enforced")

    names = {
        campaign.apf_sandbox_name(tmp_path, first),
        campaign.apf_sandbox_name(tmp_path, second),
    }

    assert len(names) == 2
    assert all(len(name) <= 19 for name in names)


def test_projected_apf_policy_contains_only_requested_resource(tmp_path: Path) -> None:
    campaign = load_module("matched_comparator_campaign_policy", "run_campaign.py")
    resource = Path("/data/resources/current-invocation.sqlite")

    projected = campaign.project_apf_policy(tmp_path, [resource])
    policy = json.loads(projected.read_text())

    read_only = policy["filesystem_policy"]["read_only"]
    assert str(resource) in read_only
    assert "/data/resources/other-invocation.sqlite" not in read_only
    assert "/data/langgraph" not in read_only


def test_committed_apf_projection_matches_official_projector(tmp_path: Path) -> None:
    campaign = load_module("matched_comparator_campaign_drift", "run_campaign.py")

    regenerated = json.loads(campaign.project_apf_policy(tmp_path, []).read_text())
    committed = json.loads(campaign.APF_PROJECTED_POLICY.read_text())

    assert regenerated == committed


def test_secured_wall_includes_apf_lifecycle_only() -> None:
    report = load_module("matched_comparator_report", "regenerate.py")

    assert report.metric_value({"mode": "Argus", "process_wall_ms": 8.0}, "secured_wall_ms") == 8.0
    assert (
        report.metric_value(
            {
                "mode": "APF-enforced",
                "process_wall_ms": 8.0,
                "end_to_end_wall_ms": 21.0,
            },
            "secured_wall_ms",
        )
        == 21.0
    )
