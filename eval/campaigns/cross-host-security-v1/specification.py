"""Common semantic requirements; host setup is defined separately."""

CASES = (
    "allowed_record_read",
    "allowed_record_update",
    "bob_read",
    "bob_update",
    "bob_delete",
    "direct_database_read",
    "direct_database_update",
    "direct_database_delete",
    "direct_wal",
    "direct_shm",
    "direct_journal",
    "retry_after_denial",
    "allowed_pump_inspect",
    "allowed_pump_set_flow",
    "pump_calibrate",
    "direct_device",
    "identity_principal",
    "identity_tool",
    "identity_invocation",
    "identity_session",
    "old_invocation_reuse",
    "private_file_read",
    "outside_artifact_write",
    "live_network",
    "process_fork",
    "process_subprocess",
    "process_exec",
    "timeout",
    "cancellation",
    "controller_termination",
    "session_own_state",
    "session_other_variable",
    "session_other_artifact",
    "session_other_artifact_write",
    "session_timeout",
    "session_cancellation",
    "session_controller_termination",
    "required_aggregate_cpu",
    "required_syscall_filter",
    "extensible_required_cpu",
    "extensible_required_syscalls",
    "missing_obligation",
    "altered_obligation",
    "admission_mutation",
)
ALLOWED = frozenset(
    {
        "allowed_record_read",
        "allowed_record_update",
        "allowed_pump_inspect",
        "allowed_pump_set_flow",
        "session_own_state",
    }
)
CLEANUP = frozenset(
    {
        "timeout",
        "cancellation",
        "controller_termination",
        "session_timeout",
        "session_cancellation",
        "session_controller_termination",
    }
)
GATES = frozenset(
    {
        "required_aggregate_cpu",
        "required_syscall_filter",
        "extensible_required_cpu",
        "extensible_required_syscalls",
        "missing_obligation",
        "altered_obligation",
        "admission_mutation",
    }
)
CLASSES = """class record {
operations read write delete
object row
normalizer identity
attrs
enforced_by broker
}
class pump {
operations inspect set_flow calibrate
object device
normalizer identity
attrs
enforced_by broker
}
class trace {
operations append
object log
normalizer identity
attrs
enforced_by broker
}
class session {
operations execute
object interpreter
normalizer identity
attrs
enforced_by broker
}
class host_cpu {
operations require
object contract
normalizer identity
attrs
enforced_by kernel
}
class host_syscalls {
operations require
object contract
normalizer identity
attrs
enforced_by kernel
}"""
REQUIREMENTS = """record read notes/alice need
record write notes/alice need
pump inspect pump-1 need
pump set_flow pump-1 need
trace append entry need
returns normal"""
POLICY = """permit(principal == slangGraph::User::"alice",
action in [slangGraph::Action::"record::read", slangGraph::Action::"record::write"], resource)
when { resource.selector == "notes/alice" };
permit(principal == slangGraph::User::"alice",
action in [slangGraph::Action::"pump::inspect", slangGraph::Action::"pump::set_flow"], resource)
when { resource.selector == "pump-1" };
permit(principal == slangGraph::User::"alice",
action == slangGraph::Action::"trace::append", resource)
when { resource.selector == "entry" };
permit(principal == slangGraph::User::"alice",
action == slangGraph::Action::"session::execute", resource)
when { resource.selector == "session-b" };
permit(principal == slangGraph::User::"alice",
action in [slangGraph::Action::"host_cpu::require",
slangGraph::Action::"host_syscalls::require"], resource);"""
MAC_POLICY = 'forbid(principal == slangGraph::User::"blocked", action, resource);'


def manifest(case, host, *, narrow=False):
    body = "trace append entry need\nreturns normal" if narrow else REQUIREMENTS
    if case.startswith("session_"):
        body += "\nsession execute session-b need"
    classes = CLASSES
    if case == "required_aggregate_cpu":
        body += "\ncpu aggregate 1000 need"
    elif case == "required_syscall_filter":
        body += "\nsyscalls @minimal need"
    elif case.startswith("extensible_required_"):
        kind = "cpu" if case.endswith("cpu") else "syscalls"
        contract = "aggregate-cpu-1000ms" if kind == "cpu" else "linux-minimal-syscalls"
        body += f"\nhost_{kind} require {contract} need"
    return classes, f"runs {host}\n{body}"
