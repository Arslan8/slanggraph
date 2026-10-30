"""Source-bound SGV903 structural review for the `LinuxSandboxExecutor` route.

The checker parses supplied source text with `ast`; it never imports or runs
candidate code. Each check is a review-pattern structural match (statement
position and call spelling) over the exact `linux.py` and `_linux_worker.py`
snapshot. It is not a path-cover or dataflow derivation and it proves nothing:
`report["proved"]` is always all-False, `report["complete"]` is always False,
and the structural booleans are exposed separately as
`report["structural_checks"]`. Kernel, bubblewrap, libseccomp and LSM
correctness are explicit premises. Runtime trial files are recorded as runtime
evidence and never discharge an obligation.
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

LINUX = "libs/prebuilt/langgraph/prebuilt/security/linux.py"
WORKER = "libs/prebuilt/langgraph/prebuilt/security/_linux_worker.py"
OBLIGATIONS = (
    "grant_lowering",
    "activation_before_execution",
    "channel_identity",
    "cancellation_lifetime",
)
_PROCESS_CREATION = frozenset(
    {"clone", "clone3", "fork", "vfork", "execve", "execveat", "socket"}
)
_ALLOW_ACTIONS = frozenset({0x7FFF0000, 0x7FFC0000, 0x7FC00000})
_LOADERS = frozenset({"exec", "compile", "__import__", "importlib.import_module"})
_AMBIENT_EXCEPTION = ("sys.exc_info()", "sys.exception()")
# Module-level rebinding of these names defeats the positional checks that
# assume the function bodies found by `_functions` are the ones that run.
_REBIND_SENSITIVE: dict[str, tuple[str, ...]] = {
    "_run_worker": ("channel_identity", "cancellation_lifetime"),
    "_cleanup_worker": ("cancellation_lifetime",),
    "_apply_seccomp": ("activation_before_execution",),
    "_apply_limits": ("activation_before_execution",),
    "_prepare_invocation": ("activation_before_execution",),
    "_invoke": ("activation_before_execution",),
    "main": ("activation_before_execution", "channel_identity"),
}
_RUNTIME_EVIDENCE = (
    "eval/campaigns/remediation-v2/raw/pandas-v19-full/verification.json",
    "eval/campaigns/remediation-v2/raw/native-filesystem-matrix/verification.json",
    "eval/campaigns/remediation-v2/raw/container-crash-full/verification.json",
    "eval/campaigns/remediation-v2/raw/container-crash-full-v2/verification.json",
    "eval/campaigns/remediation-v2/raw/container-dispatcher-full/verification.json",
    "eval/campaigns/remediation-v2/raw/container-mac-full/verification.json",
)
_ROUTE = {
    "pandas-v19-full": "LinuxSandboxExecutor (configuration C)",
    "native-filesystem-matrix": "ObjectBrokerDispatcher/LandlockSandboxExecutor; not this route",
}
PREMISES = (
    "Linux namespaces, bind mounts, PR_SET_PDEATHSIG, pid-namespace teardown, "
    "seccomp-bpf, rlimits and any LSM/MAC behave as documented.",
    "bubblewrap honors --unshare-all, --die-with-parent, --cap-drop ALL, "
    "--clearenv, --*-bind-fd and --json-status-fd; libseccomp encodes rules.",
    "The digest-pinned interpreter in -I -S mode imports only trusted stdlib "
    "modules before the worker shim's main runs.",
    "Policy evaluation (DAC/MAC) produced the authorized grant; this checker "
    "covers lowering and execution, not authorization.",
)
SCOPE = (
    "Review-pattern structural check over the source snapshot: statement "
    "position and call spelling are matched with `ast`. This is not a "
    "path-cover or dataflow derivation, proves no obligation, and reports "
    "`proved` as all-False and `complete` as False unconditionally. The "
    "booleans in `structural_checks` are review hints only; `known_evasions` "
    "lists confirmed ways the structural matching can be satisfied by unsafe "
    "source, of which items (1), (2 in part), (6), (7) and the rebinding case "
    "(5) have cheap mitigations applied in `hardening_applied`."
)
KNOWN_EVASIONS = (
    "(1) exact loader spellings and the expected prepare/invoke functions are "
    "checked, but aliases and equivalent loading APIs can evade the scan",
    "(2) loader detection is an exact-spelling set, so runpy/builtins.exec/eval pass",
    "(3) `_apply_seccomp` can be neutered while the checker still reports a "
    "deny default (only `seccomp_init` args are folded)",
    "(4) the syscall allowlist check reads only the first literal tuple",
    "(5) module-level monkeypatching can replace `_run_worker`/"
    "`_cleanup_worker` unnoticed",
    "(6) negotiation waivers can pass via `**kwargs` unpacking or a "
    "`self.negotiate` wrapper",
    "(7) the lifetime defect check matches only the spelling "
    "`sys.exc_info()`, so `sys.exception()` evades it",
    "(8) guard statements are matched by presence only (`and False` or "
    "neutered bodies pass)",
    "(9) an alternate `GO` send under a different spelling before receipt "
    "validation is accepted",
    "(10) `lower()`/`assess()`/policy filter can be widened while "
    'grant_lowering stays "proved"',
    "(11) lifetime needles are substring checks that dead code satisfies",
    "(12) a ready frame written before seccomp is unchecked",
)
HARDENING_APPLIED = (
    "(a) worker `main` is included in the payload-loading scan; "
    "`_prepare_invocation` and `_invoke` calls are accepted only in the "
    "ordered preflight/GO/execute sequence in `main`",
    "(b) both `sys.exc_info()` and `sys.exception()` in the cleanup call are "
    "the ambient-exception lifetime defect",
    "(c) any `*`/`**` argument or any `waivers`/`owners` keyword at the "
    "negotiate call fails grant lowering",
    "(d) a module-level `Assign`/`AugAssign`/`AnnAssign` whose target is "
    "`_run_worker`, `_cleanup_worker`, `_apply_seccomp`, `_apply_limits`, "
    "`_prepare_invocation`, `_invoke` or `main` (as a name or attribute) "
    "fails the corresponding checks",
)


def _functions(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    found: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    found[f"{node.name}.{item.name}"] = item  # type: ignore[assignment]
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.FunctionDef):
            found[node.name] = node
    return found


def _called(node: ast.AST) -> str:
    if isinstance(node, ast.Expr):
        node = node.value
    if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
        node = node.value
    if isinstance(node, ast.Call):
        return ast.unparse(node.func)
    return ""


def _index(body: list[ast.stmt], predicate: Any) -> int:
    for position, statement in enumerate(body):
        if predicate(statement):
            return position
    return -1


def _main_try(function: ast.FunctionDef | None) -> ast.Try | None:
    """Return the top-level `try` that owns a `finally` clause, if any."""
    if function is None:
        return None
    tries = [node for node in function.body if isinstance(node, ast.Try)]
    owning = [node for node in tries if node.finalbody]
    return (owning or tries or [None])[-1]


def _worker_body(run: ast.Try | None) -> list[ast.stmt]:
    """Find the worker statements inside the invocation-local error capture.

    This unwraps one syntactic layer for review hints; it does not establish
    dominance or the absence of other paths. `_check_lifetime` reviews the
    capture separately, and neither review is proof.
    """
    if run is None:
        return []
    if len(run.body) == 1 and isinstance(run.body[0], ast.Try):
        return run.body[0].body
    return run.body


def _tuple_strings(tree: ast.Module, name: str) -> frozenset[str] | None:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
            and isinstance(node.value, ast.Tuple)
        ):
            return frozenset(
                item.value
                for item in node.value.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            )
    return None


def _fold(node: ast.expr) -> int | None:
    """Fold integer constants and `|`; `errno.*` folds to a nonzero errno."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Attribute) and ast.unparse(node).startswith("errno."):
        return 1
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, right = _fold(node.left), _fold(node.right)
        return None if left is None or right is None else left | right
    return None


def _target_names(target: ast.expr) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        yield target.attr
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            yield from _target_names(element)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)


def _module_rebindings(tree: ast.Module) -> dict[str, set[str]]:
    """Map obligation -> names rebound by module-level assignment statements."""
    hit: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AugAssign | ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            for name in _target_names(target):
                for obligation in _REBIND_SENSITIVE.get(name, ()):
                    hit.setdefault(obligation, set()).add(name)
    return hit


def _check_lowering(fns: Mapping[str, ast.FunctionDef], issues: list[str]) -> bool:
    ok = True
    assess = fns.get("_LinuxBubblewrapAdapter.assess")
    statements = [
        s
        for s in (assess.body if assess else [])
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]
    first = statements[0] if statements else None
    if not (
        isinstance(first, ast.Assign)
        and ast.unparse(first.value) == "SupportLevel.UNSUPPORTED"
    ):
        issues.append("lowering: assess does not default to SupportLevel.UNSUPPORTED")
        ok = False
    invoke = fns.get("LinuxSandboxExecutor._invoke")
    negotiate = [
        n
        for n in (ast.walk(invoke) if invoke else ())
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith(".negotiate")
    ]
    if len(negotiate) != 1:
        issues.append("lowering: negotiation is missing or duplicated")
        ok = False
    else:
        call = negotiate[0]
        if any(k.arg is None or k.arg in {"waivers", "owners"} for k in call.keywords):
            issues.append(
                "lowering: negotiation accepts waivers/owners or unpacks `**` keywords"
            )
            ok = False
        if any(isinstance(a, ast.Starred) for a in call.args):
            issues.append("lowering: negotiation unpacks `*` positional arguments")
            ok = False
    refusal = invoke is not None and any(
        isinstance(n, ast.If)
        and "negotiation.allowed" in ast.unparse(n.test)
        and isinstance(n.body[0], ast.Raise)
        and "HostExecutionDenied" in ast.unparse(n.body[0])
        for n in ast.walk(invoke)
    )
    if not refusal:
        issues.append(
            "lowering: refused negotiation does not raise HostExecutionDenied"
        )
        ok = False
    lower = fns.get("_LinuxBubblewrapAdapter.lower")
    if lower is None or "inexact_writable_mount" not in ast.unparse(lower):
        issues.append("lowering: inexact writable mounts are not refused")
        ok = False
    return ok


def _check_activation(
    fns: Mapping[str, ast.FunctionDef], worker: ast.Module, issues: list[str]
) -> bool:
    ok = True
    body = getattr(_main_try(fns.get("main")), "body", [])
    seccomp = _index(body, lambda s: _called(s) == "_apply_seccomp")
    limits = _index(body, lambda s: _called(s) == "_apply_limits")
    prepare = _index(body, lambda s: _called(s) == "_prepare_invocation")
    gate = _index(
        body,
        lambda s: isinstance(s, ast.If) and "'GO\\n'" in ast.unparse(s.test),
    )
    payload = _index(body, lambda s: _called(s) == "_invoke")
    if not (
        0 <= seccomp < prepare < gate < payload
        and 0 <= limits < prepare
        and "_invoke(prepared, event_loop)" in ast.unparse(body[payload])
    ):
        issues.append(
            "activation: seccomp/limits/preflight/GO/invoke ordering is missing in main"
        )
        ok = False
    for name, fn in fns.items():
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            callee = ast.unparse(node.func)
            loader_allowed = (name, callee) in {
                ("_prepare_invocation", "compile"),
                ("_invoke", "exec"),
            }
            phase_call_allowed = name == "main" and callee in {
                "_prepare_invocation",
                "_invoke",
            }
            if (callee in _LOADERS and not loader_allowed) or (
                callee in {"_prepare_invocation", "_invoke"} and not phase_call_allowed
            ):
                issues.append(
                    f"activation: payload loading outside its worker phase in {name}"
                )
                ok = False
    allowed = _tuple_strings(worker, "_ALLOWED_SYSCALLS")
    if allowed is None or allowed & _PROCESS_CREATION:
        issues.append(
            "activation: seccomp allowlist permits process creation or is unknown"
        )
        ok = False
    apply = fns.get("_apply_seccomp")
    values: dict[str, int] = {}
    if apply is not None:
        for node in ast.walk(apply):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                value = node.value
                if isinstance(value, ast.Call) and value.args:
                    folded = _fold(value.args[0])
                    if folded is not None:
                        values[node.targets[0].id] = folded
    init = [
        n
        for n in (ast.walk(apply) if apply else ())
        if isinstance(n, ast.Call) and ast.unparse(n.func).endswith("seccomp_init")
    ]
    default = (
        values.get(ast.unparse(init[0].args[0]))
        if len(init) == 1 and init[0].args
        else None
    )
    if default is None or default in _ALLOW_ACTIONS:
        issues.append("activation: seccomp default action is not a derived deny action")
        ok = False
    return ok


def _check_channel(fns: Mapping[str, ast.FunctionDef], issues: list[str]) -> bool:
    run = fns.get("LinuxSandboxExecutor._run_worker")
    body = _worker_body(_main_try(run))
    text = [ast.unparse(s) for s in body]
    go = _index(body, lambda s: "b'GO\\n'" in ast.unparse(s))
    ready = _index(
        body,
        lambda s: (
            isinstance(s, ast.If)
            and "startup_challenge" in ast.unparse(s.test)
            and "plan_digest" in ast.unparse(s.test)
            and isinstance(s.body[0], ast.Raise)
        ),
    )
    receipt = _index(
        body,
        lambda s: (
            isinstance(s, ast.If)
            and "validate_receipt" in ast.unparse(s.test)
            and isinstance(s.body[0], ast.Raise)
        ),
    )
    context = _index(body, lambda s: "_execution_context(" in ast.unparse(s))
    ok = 0 <= ready < context < receipt < go
    if not ok:
        issues.append(
            "channel: GO is not dominated by ready-challenge check, kernel context and receipt validation"
        )
    main = _main_try(fns.get("main"))
    gate = main is not None and any(
        isinstance(s, ast.If) and "'GO\\n'" in ast.unparse(s.test) for s in main.body
    )
    if not gate or not any("startup_challenge" in t for t in text):
        issues.append("channel: worker GO gate or fresh startup challenge is missing")
        ok = False
    return ok


def _check_lifetime(fns: Mapping[str, ast.FunctionDef], issues: list[str]) -> bool:
    ok = True
    function = fns.get("LinuxSandboxExecutor._run_worker")
    run = _main_try(function)
    final = run.finalbody if run else []
    if len(final) != 1 or _called(final[0]) != "self._cleanup_worker":
        issues.append("lifetime: _run_worker finally does not call _cleanup_worker")
        ok = False
    else:
        cleanup_call = ast.unparse(final[0])
        ambient = [s for s in _AMBIENT_EXCEPTION if s in cleanup_call]
        if ambient:
            # A finally clause reached by `return` sees a caller's handled
            # exception, so cleanup can attribute this worker to another request.
            issues.append(
                f"lifetime: cleanup active_error comes from ambient {ambient[0]}; a "
                "successful call made while the thread handles a prior HostExecutionError "
                "returns success on unconfirmed termination and may mark that prior "
                "error termination_confirmed"
            )
            ok = False
        # Match the invocation-local capture rather than accepting an arbitrary
        # non-ambient expression (including None, which loses active failures).
        call = final[0].value if isinstance(final[0], ast.Expr) else None
        error = (
            next(
                (k.value for k in call.keywords if k.arg == "active_error"),
                None,
            )
            if isinstance(call, ast.Call)
            else None
        )
        name = error.id if isinstance(error, ast.Name) else None
        initialized = (
            name is not None
            and run is not None
            and function is not None
            and any(
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == name
                and isinstance(node.value, ast.Constant)
                and node.value.value is None
                for node in function.body[: function.body.index(run)]
            )
        )
        capture = (
            run.handlers[0] if run is not None and len(run.handlers) == 1 else None
        )
        captured = (
            capture is not None
            and isinstance(capture.type, ast.Name)
            and capture.type.id == "BaseException"
            and capture.name is not None
            and len(capture.body) == 2
            and isinstance(capture.body[0], ast.Assign)
            and len(capture.body[0].targets) == 1
            and isinstance(capture.body[0].targets[0], ast.Name)
            and capture.body[0].targets[0].id == name
            and isinstance(capture.body[0].value, ast.Name)
            and capture.body[0].value.id == capture.name
            and isinstance(capture.body[1], ast.Raise)
            and capture.body[1].exc is None
            and capture.body[1].cause is None
        )
        if not initialized or not captured:
            issues.append(
                "lifetime: cleanup lacks the invocation-local BaseException capture pattern"
            )
            ok = False
    cleanup = fns.get("LinuxSandboxExecutor._cleanup_worker")
    source = ast.unparse(cleanup) if cleanup else ""
    for needle, message in (
        ("process.kill()", "cleanup does not kill the bubblewrap supervisor"),
        ("_confirm_worker_terminated(", "cleanup does not confirm payload termination"),
        ("TerminationRecovery(", "unconfirmed termination is not retained"),
    ):
        if needle not in source:
            issues.append(f"lifetime: {message}")
            ok = False
    ainvoke = fns.get("LinuxSandboxExecutor.ainvoke")
    if ainvoke is None or not any(
        isinstance(n, ast.While) and "execution.done()" in ast.unparse(n.test)
        for n in ast.walk(ainvoke)
    ):
        issues.append(
            "lifetime: async cancellation does not wait for the worker thread"
        )
        ok = False
    return ok


def runtime_evidence(repo: Path) -> list[dict[str, Any]]:
    """Record existing trial files as runtime evidence only, never as proof."""
    import json

    records = []
    for relative in _RUNTIME_EVIDENCE:
        path = repo / relative
        record: dict[str, Any] = {
            "path": relative,
            "label": "runtime evidence",
            "route": _ROUTE.get(path.parent.name, "container route; not this route"),
        }
        if path.is_file():
            data = path.read_bytes()
            summary = json.loads(data)
            record.update(
                sha256=hashlib.sha256(data).hexdigest(),
                passed=summary.get("passed"),
                trials=summary.get("trials", summary.get("observations")),
                passes_by_configuration=summary.get("passes_by_configuration"),
                scope=summary.get("scope", summary.get("timing_scope")),
            )
        else:
            record["missing"] = True
        records.append(record)
    return records


def verify_linux_host_route(
    linux_source: str, worker_source: str, *, repo: Path | None = None
) -> dict[str, Any]:
    """Run the SGV903 structural review for `LinuxSandboxExecutor`.

    The returned report never claims a proof: `proved` is all-False and
    `complete` is False regardless of the structural outcome, which is
    exposed as `structural_checks`.
    """
    issues: list[str] = []
    checks = dict.fromkeys(OBLIGATIONS, False)
    try:
        linux, worker = ast.parse(linux_source), ast.parse(worker_source)
    except SyntaxError as exc:
        issues.append(f"unparsed source: {exc.lineno}")
    else:
        fns = {**_functions(linux), **_functions(worker)}
        checks["grant_lowering"] = _check_lowering(fns, issues)
        checks["activation_before_execution"] = _check_activation(fns, worker, issues)
        checks["channel_identity"] = _check_channel(fns, issues)
        checks["cancellation_lifetime"] = _check_lifetime(fns, issues)
        for tree in (linux, worker):
            for obligation, names in _module_rebindings(tree).items():
                issues.append(
                    f"{obligation}: module-level rebinding of {sorted(names)}"
                )
                checks[obligation] = False
    return {
        "schema_version": 2,
        "kind": "sgv903-linux-host-route",
        "route": "LinuxSandboxExecutor",
        "proof": False,
        "proved": dict.fromkeys(OBLIGATIONS, False),
        "complete": False,
        "structural_checks": checks,
        "scope": SCOPE,
        "known_evasions": list(KNOWN_EVASIONS),
        "hardening_applied": list(HARDENING_APPLIED),
        "premises": list(PREMISES),
        "issues": issues,
        "runtime_evidence": runtime_evidence(repo) if repo is not None else [],
        "source_sha256": {
            LINUX: hashlib.sha256(linux_source.encode()).hexdigest(),
            WORKER: hashlib.sha256(worker_source.encode()).hexdigest(),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
