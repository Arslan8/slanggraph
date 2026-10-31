"""Explicit host selection for the matched demos; application tools stay unchanged."""

import atexit
import json
import os
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

NATIVE_HOST = "macos" if sys.platform == "darwin" else "linux"


def framework_library(name):
    if name not in {"prebuilt", "langgraph", "checkpoint", "sdk-py"}:
        raise ValueError("unknown framework library")
    from langgraph.prebuilt import security

    root = Path(security.__file__).resolve().parents[5]
    return (root / "libs" / name).resolve(strict=True)


def macos_configuration():
    path = Path(os.environ["ARGUS_MACOS_CONFIGURATION"]).resolve(strict=True)
    return json.loads(path.read_text())


def selected_lifecycle_checker(worker_route=None, *, runtime_path=None, runtime_sha256=None):
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

    if sys.platform == "darwin":
        cfg = macos_configuration()["lean"]
        return LeanLifecycleChecker(
            str(worker_route.resolve()) if worker_route is not None else cfg["library"],
            cfg["sha256"],
            cfg["native_runtime"],
            cfg["native_runtime_sha256"],
        )
    import hashlib

    return LeanLifecycleChecker(
        str(worker_route),
        hashlib.sha256(worker_route.read_bytes()).hexdigest(),
        runtime_path,
        runtime_sha256,
    )


def _macos_dispatcher(tools, **kwargs):
    from langgraph.prebuilt.security import (
        MacOSNativeLauncher,
        MacOSObjectDispatcher,
        MacOSToolSpec,
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
    converted = {}
    for name, spec in tools.items():
        if getattr(spec, "deployment", None) is not None:
            raise ValueError("macOS does not implement Linux deployment specifications")
        converted[name] = MacOSToolSpec(spec.entrypoint, spec.artifact_path, spec.artifact_digest)
    roots = tuple(
        dict.fromkeys(
            (*kwargs.pop("runtime_roots", ()), *(Path(root) for root in cfg["python_roots"]))
        )
    )
    if kwargs.get("lifecycle_checker") is None:
        kwargs["lifecycle_checker"] = selected_lifecycle_checker()
    dispatcher = MacOSObjectDispatcher(
        converted,
        launcher=launcher,
        recovery_directory=Path(cfg["recovery_directory"]),
        runtime_roots=roots,
        executable_roots=tuple(Path(root) for root in cfg["python_roots"]),
        runtime_aliases=native.get("runtime_aliases", {}),
        runtime_libraries=native.get("runtime_libraries", ()),
        **kwargs,
    )
    destination = os.environ.get("ARGUS_NATIVE_EVIDENCE_DIRECTORY")
    if destination:
        folder = Path(destination).resolve()
        name = f"native-execution-{uuid.uuid4().hex}.json"

        def capture():
            folder.mkdir(parents=True, exist_ok=True)
            value = {
                "activation_receipts": [
                    dict(item.canonical()) for item in dispatcher.activation_receipts()
                ],
                "lowering_records": list(dispatcher.lowering_records()),
                "lifecycle_records": list(dispatcher.lifecycle_records()),
                "broker_audit": [asdict(item) for item in dispatcher.audit_records()],
            }
            (folder / name).write_text(json.dumps(value, indent=2) + "\n")

        atexit.register(capture)
    return dispatcher


def native_object_dispatcher(tools, **kwargs):
    if sys.platform == "darwin":
        return _macos_dispatcher(tools, **kwargs)
    from langgraph.prebuilt.security import LinuxObjectDispatcher

    return LinuxObjectDispatcher(tools, **kwargs)


def native_broker_dispatcher(tools, **kwargs):
    if sys.platform == "darwin":
        return _macos_dispatcher(tools, **kwargs)
    from langgraph.prebuilt.security import ObjectBrokerDispatcher

    return ObjectBrokerDispatcher(tools, **kwargs)
