"""Parent-controlled timing barrier for evaluation application processes."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def wait_for_parent() -> None:
    """Expose a ready boundary and wait until the parent starts the request timer."""
    if os.environ.get("ARGUS_EVAL_READY_PROTOCOL") != "1":
        return
    ready_path = os.environ.get("ARGUS_EVAL_READY_FILE")
    go_path = os.environ.get("ARGUS_EVAL_GO_FILE")
    if ready_path or go_path:
        if not ready_path or not go_path:
            raise RuntimeError("file timing barrier requires both READY and GO paths")
        Path(ready_path).write_text(
            json.dumps({"argus_eval_protocol": 1, "state": "ready"}, sort_keys=True) + "\n"
        )
        while not Path(go_path).is_file():
            time.sleep(0.005)
        return
    print(
        json.dumps({"argus_eval_protocol": 1, "state": "ready"}, sort_keys=True),
        flush=True,
    )
    if sys.stdin.readline() != "GO\n":
        raise RuntimeError("evaluation parent did not send the GO marker")
