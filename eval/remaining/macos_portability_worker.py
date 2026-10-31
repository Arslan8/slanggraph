"""Frozen synthetic read-only workload and effect probes for native macOS evaluation."""

import _ctypes
import errno
import os
import socket
import time


def run(left, right, operation="utility", target="", port=0):
    """Compute a useful result, or witness a named effect attempt."""
    with open(left) as stream:
        a = int(stream.read())
    with open(right) as stream:
        b = int(stream.read())
    useful = {"left": a, "right": b, "sum": a + b, "equal": a == b}
    if operation == "utility":
        return useful
    attempted = operation != "raw_fork"
    try:
        if operation == "read":
            with open(target) as stream:
                effect = stream.read()
        elif operation == "write":
            with open(target, "w") as stream:
                stream.write("CHANGED")
            effect = "written"
        elif operation in {"fork", "raw_fork"}:
            if operation == "raw_fork":

                class CInt(_ctypes._SimpleCData):
                    _type_ = "i"

                class Fork(_ctypes.CFuncPtr):
                    _flags_ = 1 | 8  # C calling convention and thread-local errno.
                    _restype_ = CInt
                    _argtypes_ = ()

                fork = Fork(_ctypes.dlsym(_ctypes.dlopen(None), "fork"))
                attempted = True
                child = fork()
                if child == -1:
                    error = _ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
            else:
                child = os.fork()
            if child == 0:
                os._exit(0)
            os.waitpid(child, 0)
            effect = "forked"
        elif operation == "spawn":
            child = os.posix_spawn("/usr/bin/true", ["true"], {})
            os.waitpid(child, 0)
            effect = "spawned"
        elif operation == "exec":
            os.execve("/usr/bin/true", ["true"], {})
            raise AssertionError("exec returned")
        elif operation == "network":
            with socket.socket() as connection:
                connection.settimeout(1)
                connection.connect(("127.0.0.1", port))
            effect = "connected"
        elif operation == "signal":
            os.kill(port, 0)
            effect = "signal-authority"
        elif operation == "sleep":
            time.sleep(0.3)
            effect = "slept"
        elif operation == "cpu":
            deadline = time.process_time() + 2
            while time.process_time() < deadline:
                pass
            effect = "computed"
        elif operation == "descriptors":
            opened = []
            try:
                for _ in range(100):
                    opened.append(open(left))  # noqa: SIM115 - hold FDs until the ceiling
                effect = {"opened": len(opened), "errno": None}
            except OSError as exc:
                effect = {"opened": len(opened), "errno": exc.errno}
            finally:
                for stream in opened:
                    stream.close()
        elif operation == "nonfinite_frame":
            os.write(1, b'{"status":"ok","result":1e999}\n')
            time.sleep(0.3)
            effect = "invalid-frame-sent"
        else:
            raise ValueError("unknown operation")
        return {"useful": useful, "attempted": attempted, "blocked": False, "effect": effect}
    except OSError as exc:
        return {
            "useful": useful,
            "attempted": attempted,
            "blocked": exc.errno in {errno.EPERM, errno.EACCES},
            "errno": exc.errno,
            "error_type": type(exc).__name__,
        }
