"""Force different arrival orders through one production macOS mediator."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
import time
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns/macos-resubmission-v1"
sys.path.insert(0, str(CAMPAIGN))
import advanced  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--single", type=int, choices=range(3))
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS-only stress case")
    output = args.output.resolve()
    if args.single is None:
        output.mkdir(parents=True, exist_ok=False)
        for seed in range(3):
            subprocess.run(
                [sys.executable, __file__, "--output", str(output), "--single", str(seed)],
                check=True,
            )
        observed = [json.loads((output / f"order-{seed}.json").read_text()) for seed in range(3)]
        if len({tuple(order) for order in observed}) < 2:
            raise AssertionError("arrival-order stress did not vary interleavings")
        print(json.dumps({"passed": True, "orders": observed, "raw": str(output)}, indent=2))
        return

    seed = args.single
    original = concurrent.futures.ThreadPoolExecutor

    class OrderedPool(original):
        def submit(self, fn, *call_args, **kwargs):
            if not call_args or type(call_args[0]) is not int:
                return super().submit(fn, *call_args, **kwargs)
            index = call_args[0]
            # Alice's two permitted calls arrive in opposite orders.
            delay = 0.06 if (index == 2 and seed == 1) or (index == 4 and seed == 0) else 0

            def delayed():
                time.sleep(delay)
                return fn(*call_args, **kwargs)

            return super().submit(delayed)

    try:
        advanced.concurrent.futures.ThreadPoolExecutor = OrderedPool
        folder = output / f"parallel_confusion-{seed}" / "Argus"
        advanced.one(folder, "parallel_confusion", "Argus", seed)
        row = json.loads((folder / "result.json").read_text())
        calls = [
            item["context"]["call_id"]
            for item in row["evidence"]["resource_invocations"]
            if item["line"]["class_name"] == "record"
        ]
        if len(calls) != 2 or any(
            item["line"]["selector"] != "notes/alice" or item["context"]["principal_id"] != "alice"
            for item in row["evidence"]["resource_invocations"]
            if item["line"]["class_name"] == "record"
        ):
            raise AssertionError(f"mediator confusion in seed {seed}")
        if row["after"]["records"]["bob"] != row["before"]["records"]["bob"]:
            raise AssertionError(f"Bob state changed in seed {seed}")
        (output / f"order-{seed}.json").write_text(
            json.dumps([int(call.rsplit("-", 1)[-1]) for call in calls]) + "\n"
        )
    finally:
        advanced.concurrent.futures.ThreadPoolExecutor = original


if __name__ == "__main__":
    main()
