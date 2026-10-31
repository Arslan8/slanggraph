"""Operator build and supervision primitives for the experimental macOS route."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class MacOSNativeLauncher:
    """A native launcher built against this exact CPython configuration.

    Build and manifest must stay in operator-controlled storage. Digests bind
    primary images, not the complete transitive runtime or OS dependencies.
    """

    path: Path
    digest: str
    library: Path
    library_digest: str
    stdlib: Path
    dynload: Path

    def verify(self) -> None:
        if (
            file_digest(self.path) != self.digest
            or file_digest(self.library) != self.library_digest
        ):
            raise ValueError("macOS launcher or Python library changed")

    @classmethod
    def build(cls, output: Path) -> MacOSNativeLauncher:
        """Explicit operator action; never compile as an invocation side effect."""
        if platform.system() != "Darwin" or sys.implementation.name != "cpython":
            raise RuntimeError("macOS launcher requires macOS and CPython")
        output = output.resolve()
        output.mkdir(parents=True, exist_ok=False)
        source = Path(__file__).with_name("native") / "macos_launcher.c"
        include = sysconfig.get_config_var("INCLUDEPY")
        framework = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX")
        if framework:
            library = (
                Path(framework)
                / "Python.framework"
                / "Versions"
                / f"{sys.version_info.major}.{sys.version_info.minor}"
                / "Python"
            )
        else:
            library = Path(
                sysconfig.get_config_var("LIBDIR")
            ) / sysconfig.get_config_var("LDLIBRARY")
        library = library.resolve(strict=True)
        stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
        dynload = (stdlib / "lib-dynload").resolve(strict=True)
        target = output / "macos-launcher"
        command = [
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-deprecated-declarations",
            "-isysroot",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
            "-I",
            include,
            str(source),
            "-o",
            str(target),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode:
            raise RuntimeError(
                "native macOS launcher build failed:\n" + completed.stderr
            )
        target.chmod(0o555)
        launcher = cls(
            target, file_digest(target), library, file_digest(library), stdlib, dynload
        )
        manifest: dict[str, Any] = {
            "format": 1,
            "source_digest": file_digest(source),
            "python": sys.version,
            "command": command,
            "launcher": str(target),
            "launcher_digest": launcher.digest,
            "library": str(library),
            "library_digest": launcher.library_digest,
            "stdlib": str(stdlib),
            "dynload": str(dynload),
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return launcher


class MacOSWorkerProcess:
    """Worker protocol pipes plus a separate native guardian owned by the host."""

    def __init__(
        self,
        launcher: MacOSNativeLauncher,
        profile: str,
        shim: bytes,
        limits: dict[str, int],
        startup: float,
    ) -> None:
        import tempfile

        launcher.verify()
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        guardian = None
        try:
            with tempfile.TemporaryFile() as policy, tempfile.TemporaryFile() as code:
                policy.write(profile.encode())
                code.write(shim)
                policy.seek(0)
                code.seek(0)
                guardian = subprocess.Popen(
                    [
                        str(launcher.path),
                        "--guardian",
                        str(request_read),
                        str(response_write),
                        str(policy.fileno()),
                        str(code.fileno()),
                        str(launcher.library),
                        str(launcher.stdlib),
                        str(launcher.dynload),
                        str(limits["cpu_ms"] // 1000),
                        str(limits["nofile"]),
                        str(max(1, int(startup * 1000))),
                        str(limits["wall_ms"]),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env={},
                    cwd="/",
                    close_fds=True,
                    pass_fds=(
                        request_read,
                        response_write,
                        policy.fileno(),
                        code.fileno(),
                    ),
                    bufsize=0,
                )
            self.guardian = guardian
            self.stdin = os.fdopen(request_write, "wb", buffering=0)
            request_write = -1
            self.stdout = os.fdopen(response_read, "rb", buffering=0)
            response_read = -1
            self.stderr = None
            self.pid = 0
        except BaseException:
            if guardian is not None:
                guardian.kill()
                guardian.wait()
            raise
        finally:
            for descriptor in (
                request_read,
                request_write,
                response_read,
                response_write,
            ):
                if descriptor >= 0:
                    os.close(descriptor)

    def close(self) -> bool:
        """Request kill/reap via liveness EOF; caller checks reaping acknowledgement."""
        if self.guardian.stdin is not None:
            self.guardian.stdin.close()
        return self.guardian.poll() is not None
