"""Fixed attacker bodies; secrets are never supplied as task arguments."""

import ctypes
import json
import os
import signal
import sqlite3
from pathlib import Path
from langgraph.prebuilt.security.object_broker import object_request


def run(task):
    case = task["case"]
    object_request("trace", "append", "entry", {"event": "entered", "pid": os.getpid()})
    try:
        if case == "inherited_fd":
            return {"read": os.read(task["leaked_fd"], 4096).decode()}
        if case == "inherited_env":
            return {"read": os.environ.get("ARGUS_TEST_CREDENTIAL")}
        if case == "startup_inventory":
            return {
                "fds": [fd for fd in range(128) if _open(fd)],
                "environment_names": sorted(os.environ),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "groups": _groups(),
                "parent": os.getppid(),
            }
        if case.startswith("race_") or case in {"private_alias", "permitted_artifact"}:
            with open(task["target"], "rb") as stream:
                stat = os.fstat(stream.fileno())
                return {"hex": stream.read().hex(), "dev": stat.st_dev, "inode": stat.st_ino}
        if case in {"signal_controller", "signal_guardian"}:
            os.kill(
                task["controller"] if case == "signal_controller" else os.getppid(), signal.SIGUSR1
            )
            return {"signalled": True}
        if case == "debug_controller":
            lib = ctypes.CDLL(None)
            right = ctypes.c_uint()
            lib.mach_task_self.restype = ctypes.c_uint
            status = lib.task_for_pid(lib.mach_task_self(), task["controller"], ctypes.byref(right))
            if status == 0:
                lib.mach_port_deallocate(lib.mach_task_self(), right.value)
            return {"task_for_pid": status, "right_received": status == 0}
        if case == "mach_inventory":
            lib = ctypes.CDLL(None)
            lib.mach_task_self.restype = ctypes.c_uint
            names = ctypes.POINTER(ctypes.c_uint)()
            types = ctypes.POINTER(ctypes.c_uint)()
            n = ctypes.c_uint()
            m = ctypes.c_uint()
            me = lib.mach_task_self()
            status = lib.mach_port_names(
                me, ctypes.byref(names), ctypes.byref(n), ctypes.byref(types), ctypes.byref(m)
            )
            ports = (
                [{"name": names[i], "rights": types[i]} for i in range(n.value)]
                if status == 0
                else []
            )
            if status == 0:
                lib.vm_deallocate(me, ctypes.cast(names, ctypes.c_void_p), n.value * 4)
                lib.vm_deallocate(me, ctypes.cast(types, ctypes.c_void_p), m.value * 4)
            return {"status": status, "ports": ports}
        if case == "child_channel":
            pid = os.fork()
            if pid == 0:
                try:
                    object_request("record", "write", "notes/bob", {"value": "CHILD_EFFECT"})
                finally:
                    os._exit(0)
            os.waitpid(pid, 0)
            return {"created": True}
        if case == "import_side_effect":
            return {"imported": True}
        if case == "direct_database":
            with sqlite3.connect(task["database"]) as db:
                return {
                    "read": db.execute("SELECT value FROM records WHERE key='bob'").fetchone()[0]
                }
        return object_request("record", "read", task.get("selector", "notes/alice"))
    except Exception as error:
        return {"error": type(error).__name__, "reason": str(error)}


def _open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def _groups():
    try:
        return os.getgroups()
    except OSError as error:
        return {"error": type(error).__name__, "errno": error.errno}
