"""Native setup only. Semantic policy and attack programs do not branch by OS."""

import dataclasses
import enum
import hashlib
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HOST = "macos" if sys.platform == "darwin" else "linux"
GIT = "/Library/Developer/CommandLineTools/usr/bin/git" if sys.platform == "darwin" else "git"


def bootstrap():
    sys.path[:0] = [
        str(ROOT / "libs" / name) for name in ("prebuilt", "langgraph", "checkpoint", "sdk-py")
    ]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def plain(value):
    if dataclasses.is_dataclass(value):
        return {
            field.name: plain(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (list, tuple, set, frozenset)):
        return [plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def roots(code):
    return (
        Path(code).resolve(),
        *(ROOT / "libs" / name for name in ("prebuilt", "langgraph", "checkpoint", "sdk-py")),
        *(
            Path(path).resolve()
            for path in sys.path
            if "site-packages" in path and Path(path).is_dir()
        ),
    )


def dispatcher(code, mediators, timeout):
    from langgraph.prebuilt.security import LinuxToolSpec

    source = Path(code) / "attacker.py"
    specs = {
        name: LinuxToolSpec("attacker:run", source, sha(source)) for name in ("probe", "narrow")
    }
    if HOST == "macos":
        import importlib.util

        path = ROOT / "eval/apps/demos/native_host.py"
        spec = importlib.util.spec_from_file_location("cross_host_native_setup", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.native_broker_dispatcher(
            specs, runtime_roots=roots(code), mediators=mediators, wall_timeout_s=timeout
        )
    from langgraph.prebuilt.security import ObjectBrokerDispatcher

    # Current WIP broker API has no lifecycle_checker parameter. Do not inject a
    # replacement executor to hide that integration gap.
    return ObjectBrokerDispatcher(
        specs, runtime_roots=roots(code), mediators=mediators, wall_timeout_s=timeout
    )


def isolation_capabilities():
    return (
        frozenset({"broker:spawn-bound", "seatbelt", "process:deny", "network:deny"})
        if HOST == "macos"
        else frozenset({"broker:spawn-bound", "seccomp:minimal"})
    )


def identity(pid):
    if HOST == "macos":
        from langgraph.prebuilt.security.macos import _process_identity

        return _process_identity(pid)
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rindex(")") + 2 :].split()
        return None if fields[0] == "Z" else fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def process_tree(parent):
    rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid="], text=True)
    pairs = [tuple(map(int, line.split())) for line in rows.splitlines() if line.strip()]
    selected = {parent}
    while True:
        children = {pid for pid, ppid in pairs if ppid in selected}
        if children.issubset(selected):
            break
        selected |= children
    return [
        {"pid": pid, "start": identity(pid), "confinement": confinement(pid)}
        for pid in sorted(selected)
        if identity(pid) is not None
    ]


def confinement(pid):
    if HOST != "linux":
        return None
    try:
        fields = dict(
            line.split(":", 1)
            for line in Path(f"/proc/{pid}/status").read_text().splitlines()
            if ":" in line
        )
        return {key: fields[key].strip() for key in ("NoNewPrivs", "Seccomp")}
    except (FileNotFoundError, ProcessLookupError):
        return None


def persistent_backend(artifact, *, protected):
    if protected:
        demos = ROOT / "eval/apps/demos"
        sys.path.insert(0, str(demos))
        from resource_monitors.backends import PersistentPythonBackend

        return PersistentPythonBackend(
            artifact, artifact.with_name("observer.json"), runtime_roots=roots(demos)
        )
    return PlainSession(artifact)


class PlainSession:
    """Run the identical production namespace server without native activation."""

    def __init__(self, artifact):
        source = ROOT / "eval/apps/demos/resource_monitors/macos_python_session_worker.py"
        code = (
            "import runpy; runpy.run_path("
            + repr(str(source))
            + ')["serve"]('
            + repr(str(artifact))
            + ")"
        )
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-u", "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        assert json.loads(self.process.stdout.readline()) == {"status": "ready"}

    def execute(self, code):
        self.process.stdin.write(json.dumps({"code": code}) + "\n")
        self.process.stdin.flush()
        return self.process.stdout.readline()

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
