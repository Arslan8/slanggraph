"""Persistent Python namespace entered only after native Seatbelt activation."""

import contextlib
import io
import json
import os
import sys
from pathlib import Path


def serve(artifact):
    artifact = Path(artifact)
    os.environ.update(
        HOME=str(artifact.parent), MPLCONFIGDIR=str(artifact.parent), MPLBACKEND="Agg"
    )
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    channel = os.dup(1)

    def emit(value):
        frame = (json.dumps(value, default=str) + "\n").encode()
        if len(frame) > 1_048_576:
            raise ValueError("Python session response exceeds protocol boundary")
        while frame:
            frame = frame[os.write(channel, frame) :]

    namespace = {"plt": plt}
    emit({"status": "ready"})
    while True:
        line = sys.stdin.buffer.readline(1_048_577)
        if not line:
            return None
        if len(line) > 1_048_576 or not line.endswith(b"\n"):
            raise ValueError("Python session request exceeds protocol boundary")
        try:
            code = json.loads(line)["code"]
            if type(code) is not str or len(code.encode()) > 100_000:
                raise ValueError("invalid Python session code")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                exec(compile(code, "<argus-python-session>", "exec"), namespace, namespace)
            figure = plt.gcf()
            lines = [
                {
                    "x": [str(value) for value in plotted.get_xdata().tolist()],
                    "y": [float(value) for value in plotted.get_ydata().tolist()],
                }
                for axis in figure.axes
                for plotted in axis.lines
            ]
            if lines:
                figure.savefig(artifact)
            result = {"artifact": str(artifact), "lines": lines, "stdout": output.getvalue()}
        except BaseException as exc:
            result = {"error": f"{type(exc).__name__}: {exc}"}
        emit(result)
