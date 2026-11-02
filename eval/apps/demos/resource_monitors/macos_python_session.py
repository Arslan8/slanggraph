"""Native Seatbelt backend for the persistent chart resource."""

import hashlib
import json
import os
import secrets
import select
import threading
import time
from importlib import import_module
from pathlib import Path

macos_configuration = import_module(
    f"{__package__.rsplit('.', 1)[0]}.native_host" if "." in __package__ else "native_host"
).macos_configuration


class MacOSPythonSession:
    def __init__(self, artifact, runtime_roots):
        from langgraph.prebuilt.security import (
            MacOSNativeLauncher,
            MacOSSandboxExecutor,
            MacOSToolSpec,
            parse_profiles,
        )
        from langgraph.prebuilt.security.macos import (
            _RUNTIME_SYSCTLS,
            _digest,
            _read_frame,
            _runtime_map,
            _seatbelt_profile,
            _write_all,
        )

        cfg = macos_configuration()
        native = cfg["launcher"]
        launcher = MacOSNativeLauncher(
            Path(native["launcher"]),
            native["launcher_digest"],
            Path(native["library"]),
            native["library_digest"],
            Path(native["stdlib"]),
            Path(native["dynload"]),
        )
        source = Path(__file__).with_name("macos_python_session_worker.py")
        spec = MacOSToolSpec(
            "macos_python_session_worker:serve",
            source,
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )
        roots = tuple(
            dict.fromkeys(Path(path).resolve() for path in (*runtime_roots, *cfg["python_roots"]))
        )
        executor = MacOSSandboxExecutor(
            parse_profiles("tool session {\nowner resource\nruns macos\n}"),
            {"session": spec},
            launcher=launcher,
            experimental=True,
            recovery_directory=Path(cfg["recovery_directory"]),
            runtime_roots=roots,
            executable_roots=tuple(Path(path) for path in cfg["python_roots"]),
            runtime_aliases=native.get("runtime_aliases", {}),
            runtime_libraries=native.get("runtime_libraries", ()),
            startup_timeout_s=30,
            default_limits={"cpu_ms": 30000, "nofile": 128, "wall_ms": 300000},
        )
        runtime = (
            *executor._runtime_paths(),
            *((str(root), True) for root in roots),
            (str(artifact.parent), True),
        )
        profile = (
            _seatbelt_profile(runtime)
            + "\n"
            + "\n".join(_runtime_map(path, subtree) for path, subtree in executor._runtime_paths())
        )
        # Matches the original Linux resource's writable artifact directory.
        write = _seatbelt_profile(((str(artifact.parent), True),)).splitlines()[-1]
        profile += "\n" + write.replace("file-read-data file-read-metadata", "file-write*")
        profile += "\n" + "\n".join(
            f"(allow sysctl-read (sysctl-name {json.dumps(name)}))" for name in _RUNTIME_SYSCTLS
        )
        request = executor._request(
            dict(executor.default_limits),
            profile,
            _digest(profile),
            source.read_bytes(),
            spec,
            {"artifact": str(artifact)},
            False,
        )
        self.process = executor._spawn(request)
        self.executor = executor
        self.recovery = None
        try:
            identity = executor._ready(self.process, request)
            from langgraph.prebuilt.security.execution import TerminationRecovery

            self.recovery = TerminationRecovery(
                secrets.token_hex(16), self.process.pid, identity, executor._boot
            )
            executor._retain_recovery(self.recovery)
            executor._arm(self.process)
            _write_all(self.process.stdin, b"GO\n")
            ready = _read_frame(self.process, 30)
            if ready != {"status": "ready"}:
                raise RuntimeError(f"macOS Python session initialization failed: {ready}")
            os.set_blocking(self.process.stdin.fileno(), False)
            self.lock = threading.Lock()
        except BaseException:
            self.close()
            raise

    def execute(self, code, *, timeout=30):
        from langgraph.prebuilt.security.macos import _read_frame

        with self.lock:
            deadline = time.monotonic() + timeout
            try:
                pending = (json.dumps({"code": code}) + "\n").encode()
                if len(pending) > 1_048_576:
                    raise ValueError("Python session request exceeds protocol boundary")
                descriptor = self.process.stdin.fileno()
                while pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                        raise TimeoutError("Python session write timed out")
                    try:
                        count = os.write(descriptor, pending)
                    except BlockingIOError:
                        continue
                    if count <= 0:
                        raise RuntimeError("Python session channel closed")
                    pending = pending[count:]
                result = _read_frame(self.process, max(0, deadline - time.monotonic()))
                if set(result) not in ({"artifact", "lines", "stdout"}, {"error"}):
                    raise RuntimeError("invalid Python session response")
                return result
            except BaseException:
                self.close()
                raise

    def close(self):
        from langgraph.prebuilt.security.macos import _reap

        if getattr(self, "process", None) is not None and not _reap(self.process):
            raise RuntimeError("macOS Python session termination unconfirmed")
        if self.recovery is not None:
            self.executor._clear_recovery(self.recovery)
            self.recovery = None
