"""Read-only verification of the existing application matrix; never invokes a model."""

import ast
import json
from collections import Counter

from host import ROOT, sha


def named(source, name):
    for node in ast.parse(source).body:
        if getattr(node, "name", None) == name or (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        ):
            return ast.dump(node, include_attributes=False)
    raise ValueError(f"missing oracle definition: {name}")


def verify():
    folders = [
        ROOT / "eval/campaigns" / name / "run-01"
        for name in ("macos-baseline-v1", "macos-argus-v1")
    ]
    configs, sources, observations, preflights = [], [], [], []
    for folder in folders:
        configs.append(json.loads((folder / "configuration.json").read_text()))
        source = json.loads((folder / "source-before.json").read_text())
        assert source == json.loads((folder / "source-after.json").read_text())
        sources.append(source)
        observations.append(
            [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
        )
        preflights.append(json.loads((folder / "fixture-preflight.json").read_text()))
    assert preflights[0] == preflights[1]
    for name in (
        "eval/campaigns/langgraph-demos-v1/tasks.json",
        "eval/campaigns/langgraph-demos-v3/run_campaign.py",
    ):
        assert sources[0][name] == sources[1][name]
        assert all(
            sha(folder / "sources" / source[name]) == source[name]
            for folder, source in zip(folders, sources, strict=True)
        )
    oracle_name = "eval/remaining/application_campaign.py"
    oracle_sources = [
        (folder / "sources" / source[oracle_name]).read_text()
        for folder, source in zip(folders, sources, strict=True)
    ]
    oracle_matches = {
        name: named(oracle_sources[0], name) == named(oracle_sources[1], name)
        for name in ("oracle", "TASKS", "ROWS")
    }
    assert all(oracle_matches.values())
    for key in ("model_digest", "demo_timeouts_seconds", "pandas_timeout_seconds"):
        assert configs[0][key] == configs[1][key]
    matrices = [
        Counter((r["application"], r.get("task", r.get("case_id")), r["repetition"]) for r in rows)
        for rows in observations
    ]
    assert matrices[0] == matrices[1] and sum(matrices[0].values()) == 225
    counts = []
    for rows in observations:
        demo, pandas = (
            [r for r in rows if r["application"] != "Pandas"],
            [r for r in rows if r["application"] == "Pandas"],
        )
        assert len(demo) == 175 and len(pandas) == 50
        counts.append(
            {
                "demo_attempts": len(demo),
                "demo_correct": sum(r["correct"] for r in demo),
                "pandas_attempts": len(pandas),
                "pandas_correct": sum(r["correct"] for r in pandas),
                "demo_applications": len({r["application"] for r in demo}),
                "outcomes_retained": dict(Counter(r["status"] for r in rows)),
            }
        )
    return {
        "verified": True,
        "timing_dataset_rerun": False,
        "baseline": counts[0],
        "argus": counts[1],
        "task_definitions_identical": True,
        "fixture_preflight_identical": True,
        "model_digest": configs[0]["model_digest"],
        "ordinary_oracle_source_identical": True,
        "pandas_oracle_and_task_ast_identical": oracle_matches,
        "demo_timeouts_seconds": configs[0]["demo_timeouts_seconds"],
        "pandas_timeout_seconds": configs[0]["pandas_timeout_seconds"],
        "setup_changes": [
            "native host dispatcher selection and private broker transport",
            "native persistent chart backend and descriptor-based dataset reads",
            "Darwin Lean image loading and object-grant obligation inventory",
            "pinned macOS Cedar/Lean/runtime setup; no certified aggregate CPU promise",
        ],
        "scope": (
            "Existing macOS cohorts verified, failures retained; "
            "historical Linux environment differences remain in original reports"
        ),
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
