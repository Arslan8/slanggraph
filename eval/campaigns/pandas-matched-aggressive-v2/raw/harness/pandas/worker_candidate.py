"""Integration feasibility candidate, not a completed application port.

Run the upstream sandbox program inside the already-fresh slangGraph worker,
retaining its AST/import/builtin checks, network shim and resource limits.
This replaces its outer subprocess launch and must be reported as a boundary change.
"""

import io
import json
import sys
from pathlib import Path


def compute(sandbox_source: str, code: str, data: dict) -> dict:
    module = {"__name__": "upstream_sandbox"}
    exec(compile(Path(sandbox_source).read_text(), sandbox_source, "exec"), module)
    payload = {
        "code": code,
        "function_name": "evaluate",
        "data": data,
        "memory_limit_mb": 512,
        "data_format": "dataframe",
    }
    original_input, original_output = sys.stdin, sys.stdout
    stream = io.StringIO()
    try:
        sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))
        sys.stdout = stream
        exec(module["SANDBOX_RUNNER_SCRIPT"], {"__name__": "__main__"})
        return json.loads(stream.getvalue())
    finally:
        sys.stdin, sys.stdout = original_input, original_output
