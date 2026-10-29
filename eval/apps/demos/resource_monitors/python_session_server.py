"""Long-lived, Landlock/seccomp-confined Python chart session."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import traceback
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--ruleset-fd", type=int, required=True)
    parser.add_argument("--runtime-root", action="append", default=[])
    args = parser.parse_args()
    sys.path[:0] = args.runtime_root

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from langgraph.prebuilt.security._linux_worker import (
        _apply_landlock,
        _apply_seccomp,
    )

    namespace = {"plt": plt}
    _apply_landlock(args.ruleset_fd)
    _apply_seccomp()
    print(json.dumps({"status": "ready"}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            code = request["code"]
            if type(code) is not str:
                raise TypeError("code must be a string")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                exec(compile(code, "<argus-python-session>", "exec"), namespace, namespace)
            figure = plt.gcf()
            lines = []
            for axis in figure.axes:
                for plotted in axis.lines:
                    lines.append(
                        {
                            "x": [str(value) for value in plotted.get_xdata().tolist()],
                            "y": [float(value) for value in plotted.get_ydata().tolist()],
                        }
                    )
            if lines:
                figure.savefig(args.artifact)
            response = {"artifact": str(args.artifact), "lines": lines, "stdout": output.getvalue()}
        except BaseException as exc:
            response = {
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(limit=3),
            }
        print(json.dumps(response, default=str), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
