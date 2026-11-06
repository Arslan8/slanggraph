from __future__ import annotations

import importlib.util
import json
import sys
import time
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


def test_retained_bundle_copies_inputs_and_hashes_outputs(tmp_path: Path) -> None:
    report = load_module("matched_comparator_retention", "regenerate.py")
    raw = tmp_path / "raw"
    output = tmp_path / "retained"
    raw.mkdir()
    output.mkdir()
    for index, filename in enumerate(report.RETAINED_INPUTS):
        (raw / filename).write_text(f"input-{index}\n")
    (output / "RESULTS.md").write_text("results\n")
    (output / "statistics.json").write_text("{}\n")

    report.retain_inputs_and_checksums(raw, output)

    for filename in report.RETAINED_INPUTS:
        assert (output / filename).read_bytes() == (raw / filename).read_bytes()
    expected_files = {
        "RESULTS.md",
        "configuration.json",
        "enforcement-probes.json",
        "statistics.json",
        "trials.json",
    }
    checksum_lines = (output / "SHA256SUMS").read_text().splitlines()
    assert {line.split("  ", 1)[1] for line in checksum_lines} == expected_files


def test_retained_results_explicitly_disclose_known_gaps() -> None:
    results = (
        ROOT / "eval/campaigns/langgraph-demos-v3/retained/"
        "matched-comparators-final-c976a2070/RESULTS.md"
    ).read_text()

    for required in (
        "Explicit gaps, limitations, and non-equivalences",
        "Comparator semantic-policy equivalence",
        "NoNo network resource scope",
        "Argus language-route coverage",
        "Argus T10 checkpoint replay compatibility",
        "D3 application/model viability",
        "D4 comparator functionality",
        "Latency population",
        "Model-trajectory comparability",
        "APF timer boundary",
    ):
        assert required in results


def test_timeout_kills_entire_process_group(tmp_path: Path) -> None:
    campaign = load_module("matched_comparator_campaign_cleanup", "run_campaign.py")
    child_pid_file = tmp_path / "child.pid"
    parent = (
        "import pathlib, subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', "
        "'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)']); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
        "time.sleep(60)"
    )

    result = campaign.run_with_process_group_cleanup(
        [sys.executable, "-c", parent],
        cwd=tmp_path,
        env=None,
        timeout=0.2,
        cleanup_grace_seconds=2.0,
    )

    assert result.timed_out
    assert result.cleanup_confirmed
    assert not campaign._process_group_exists(result.process_group_id)
    child_pid = int(child_pid_file.read_text())
    deadline = time.monotonic() + 2.0
    while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not Path(f"/proc/{child_pid}").exists()
