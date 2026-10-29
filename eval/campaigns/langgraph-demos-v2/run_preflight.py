from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
V1 = ROOT / "eval/campaigns/langgraph-demos-v1"
APPS = ROOT / "eval/apps/demos"


def run(command: list[str], output: Path, timeout: int) -> dict:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    record = {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    output.with_suffix(".process.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--run-id", default="preflight-local")
    args = parser.parse_args()
    destination = Path(__file__).with_name("raw") / args.run_id
    destination.mkdir(parents=True, exist_ok=False)
    tasks = json.loads((V1 / "tasks.json").read_text())
    selected = range(1, 2) if args.smoke else range(1, 6)

    for task_id in selected:
        trial = destination / f"D1-{task_id}"
        trial.mkdir()
        database = trial / "Chinook.db"
        shutil.copy2(V1 / tasks["D1"]["fixture"], database)
        run(
            [
                sys.executable,
                str(APPS / "sql_agent.py"),
                "--database",
                str(database),
                "--prompt",
                tasks["D1"]["tasks"][task_id - 1]["prompt"],
                "--events",
                str(trial / "events.jsonl"),
                "--output",
                str(trial / "output.json"),
                "--mode",
                "Argus",
            ],
            trial / "output.json",
            180,
        )

        trial = destination / f"D2-{task_id}"
        trial.mkdir()
        documents = [str(V1 / item) for item in tasks["D2"]["documents"]]
        run(
            [
                sys.executable,
                str(APPS / "agentic_rag.py"),
                "--documents",
                *documents,
                "--prompt",
                tasks["D2"]["tasks"][task_id - 1]["prompt"],
                "--output",
                str(trial / "output.json"),
                "--mode",
                "Argus",
            ],
            trial / "output.json",
            180,
        )

        year = tasks["D3"]["tasks"][task_id - 1]["year"]
        olympics_prompt = (
            f"For the Summer Olympics held in {year}, what was the host city, "
            "its country, and that country's currency at the time of the Games?"
        )
        trial = destination / f"D3-{task_id}"
        trial.mkdir()
        run(
            [
                sys.executable,
                str(APPS / "plan_execute.py"),
                "--corpus",
                str(V1 / tasks["D3"]["corpus"]),
                "--prompt",
                olympics_prompt,
                "--output",
                str(trial / "output.json"),
                "--mode",
                "Argus",
            ],
            trial / "output.json",
            180,
        )

        country = tasks["D4"]["tasks"][task_id - 1]["country"]
        chart_prompt = (
            f"Find the {country} annual GDP values for 2019 through 2023 in "
            "current US dollars and produce a line chart."
        )
        trial = destination / f"D4-{task_id}"
        trial.mkdir()
        run(
            [
                sys.executable,
                str(APPS / "multi_agent.py"),
                "--gdp",
                str(V1 / tasks["D4"]["fixture"]),
                "--prompt",
                chart_prompt,
                "--artifact",
                str(trial / "chart.png"),
                "--observer",
                str(trial / "observer.json"),
                "--output",
                str(trial / "output.json"),
                "--mode",
                "Argus",
            ],
            trial / "output.json",
            300,
        )

        trial = destination / f"D5-{task_id}"
        trial.mkdir()
        run(
            [
                sys.executable,
                str(APPS / "customer_support.py"),
                "--source-database",
                str(V1 / "fixtures/customer-support/travel2.sqlite"),
                "--database",
                str(trial / "travel.sqlite"),
                "--notebook",
                str(V1 / "upstream/docs/docs/tutorials/customer-support/customer-support.ipynb"),
                "--faq",
                str(V1 / "fixtures/customer-support/swiss_faq.md"),
                "--task-id",
                str(task_id),
                "--output",
                str(trial / "output.json"),
                "--mode",
                "Argus",
            ],
            trial / "output.json",
            300,
        )


if __name__ == "__main__":
    main()
