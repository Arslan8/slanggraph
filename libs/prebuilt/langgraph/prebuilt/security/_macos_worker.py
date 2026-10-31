"""Trusted Python shim loaded by the already-confined native launcher."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import inspect
import json
import os
import resource
import sys
import time
import traceback
from types import ModuleType

_MAX_FRAME = 1_048_576
_PROTOCOL_FD = os.dup(1)


def _write(value):
    frame = json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(frame) > _MAX_FRAME:
        raise ValueError("response exceeds frame limit")
    offset = 0
    while offset < len(frame):
        offset += os.write(_PROTOCOL_FD, frame[offset:])


def _read():
    frame = sys.stdin.buffer.readline(_MAX_FRAME + 1)
    if len(frame) > _MAX_FRAME or not frame.endswith(b"\n"):
        raise ValueError("invalid request frame")
    return json.loads(frame)


def main():
    loop = None
    try:
        request = _read()
        source = base64.b64decode(request["source"], validate=True)
        if hashlib.sha256(source).hexdigest() != request["artifact_digest"]:
            raise ValueError("artifact digest mismatch")
        runtime_handles = []
        runtime_libraries = request.get("runtime_libraries", [])
        if runtime_libraries:
            import ctypes

            for item in runtime_libraries:
                with open(item["path"], "rb") as stream:
                    if hashlib.sha256(stream.read()).hexdigest() != item["sha256"]:
                        raise ValueError("runtime dependency changed")
                runtime_handles.append(
                    ctypes.CDLL(item["path"], mode=os.RTLD_NOW | os.RTLD_GLOBAL)
                )
        if request["asynchronous"]:
            loop = asyncio.new_event_loop()
        _write(
            {
                "status": "ready",
                "challenge": request["challenge"],
                "plan_digest": request["plan_digest"],
                "limits": {
                    "cpu_ms": resource.getrlimit(resource.RLIMIT_CPU)[1] * 1000,
                    "nofile": resource.getrlimit(resource.RLIMIT_NOFILE)[1],
                },
                "isolated": bool(sys.flags.isolated),
                "site_loaded": "site" in sys.modules,
                "startup_ports": globals()["__slanggraph_startup_ports"],
                **(
                    {"runtime_libraries": runtime_libraries}
                    if runtime_libraries
                    else {}
                ),
            }
        )
        if sys.stdin.buffer.readline(16) != b"GO\n":
            return
        if request["probe"]:
            time.sleep(0.001)
            result = True
        else:
            sys.path[:0] = request["runtime_roots"]
            if request.get("broker"):
                from langgraph.prebuilt.security import broker

                def pipe_request(frame):
                    _write({"status": "broker", "request": frame})
                    response = _read()
                    if response.get("status") != "ok":
                        raise PermissionError(response.get("error", "broker:denied"))
                    return response["result"]

                broker._pipe_transport = pipe_request
            name, _, attribute = request["entrypoint"].partition(":")
            module = ModuleType(name)
            module.__file__ = request["artifact_path"]
            module.__package__ = name.rpartition(".")[0]
            sys.modules[name] = module
            with contextlib.redirect_stdout(None), contextlib.redirect_stderr(None):
                exec(
                    compile(source, module.__file__, "exec", dont_inherit=True),
                    module.__dict__,
                )
                target = module
                for part in attribute.split("."):
                    target = getattr(target, part)
                result = target(**request["args"])
                if inspect.isawaitable(result):
                    if loop is None:
                        raise TypeError("async tool requires ainvoke")
                    result = loop.run_until_complete(result)
        _write({"status": "ok", "result": result})
    except BaseException as exc:
        try:
            _write(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "diagnostic": str(exc)[:512],
                    "traceback": traceback.format_exc(limit=8)[-4096:],
                }
            )
        except BaseException:
            pass
        raise SystemExit(70) from None
    finally:
        if loop is not None:
            loop.close()


main()
