from __future__ import annotations

import json

from slanggraph_eval.remote_tool import run


def test_toy_remote_tool_deployment(tmp_path) -> None:
    output = tmp_path / "remote-tool"
    summary = run(output)

    assert summary == json.loads((output / "summary.json").read_text())
    assert summary["passed"] is True
    assert summary["cases"] == 5
    assert summary["allowed_cases"] == 1
    assert summary["remote_executions"] == 1
    assert summary["separate_service_process"] is True

    trials = [json.loads(line) for line in (output / "trials.jsonl").read_text().splitlines()]
    assert [row["case_id"] for row in trials] == [
        "allowed_remote_call",
        "denied_principal",
        "denied_selector",
        "replayed_capability",
        "tampered_arguments",
    ]
    assert trials[0]["result"] == {
        "city": "paris",
        "forecast": "clear",
        "source": "toy-remote-weather-v1",
    }
    assert all(row["remote_executions"] == 0 for row in trials[1:])
