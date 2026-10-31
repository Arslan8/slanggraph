"""Direct Darwin CPU accounting probes; preserves every outcome, including failures."""

import argparse
import json
import platform
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path

PROFILE = (
    "(version 1)(deny default)(allow process-exec)(allow file-read*)"
    "(allow file-map-executable)(allow sysctl-read)"
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for repeat in range(5):
        for kind in ("computation", "syscall"):
            loop = (
                " pass"
                if kind == "syscall"
                else "\n for i in range(10000): value = (value * 1664525 + 1013904223) & 0xffffffff"
            )
            for condition in ("seatbelt_only", "rlimit_only", "seatbelt_and_rlimit"):
                code = "import json,resource,signal,time\n"
                if condition != "seatbelt_only":
                    code += "resource.setrlimit(resource.RLIMIT_CPU, (1,1))\n"
                code += (
                    "print(json.dumps({'stage':'entered','limits':resource.getrlimit(resource.RLIMIT_CPU),"
                    "'handler':signal.getsignal(signal.SIGXCPU)}),flush=True)\n"
                    "value=1\nstart=time.process_time()\nwhile time.process_time()-start < 2:"
                    + loop
                    + "\nu=resource.getrusage(resource.RUSAGE_SELF)\n"
                    "print(json.dumps({'stage':'completed','cpu_seconds':time.process_time()-start,"
                    "'user_seconds':u.ru_utime,'system_seconds':u.ru_stime}),flush=True)\n"
                )
                command = [sys.executable, "-I", "-c", code]
                if condition != "rlimit_only":
                    command = ["/usr/bin/sandbox-exec", "-p", PROFILE, *command]
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                start = time.monotonic()
                completed = subprocess.run(command, text=True, capture_output=True, timeout=12)
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                row = {
                    "kind": kind,
                    "condition": condition,
                    "repetition": repeat,
                    "command": command,
                    "returncode": completed.returncode,
                    "signal": signal.Signals(-completed.returncode).name
                    if completed.returncode < 0
                    else None,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "elapsed_seconds": time.monotonic() - start,
                    "parent_observed_user_seconds": after.ru_utime - before.ru_utime,
                    "parent_observed_system_seconds": after.ru_stime - before.ru_stime,
                }
                rows.append(row)
                (args.output / f"{kind}-{condition}-{repeat}.json").write_text(
                    json.dumps(row, indent=2) + "\n"
                )
                print(kind, condition, repeat, completed.returncode, flush=True)
    (args.output / "transcripts.json").write_text(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": sys.version,
                "profile": PROFILE,
                "rows": rows,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
