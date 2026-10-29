"""Combined protected pandas configurations under closed admission (D11).

Configuration C-closed differs from C only in where the security boundary is
drawn. In C, the vendor graphs run without any admission and only the
generated computation passes a separate secured `ToolNode` graph. In C-closed:

- every vendor graph that runs (the outer `PandasDataAnalyst` graph and both
  nested agents, which the outer node bodies invoke directly) is recompiled
  from its own builder with `SecurityConfig(closed_admission=True, ...)`,
  declaring exactly that graph's node names in `trusted_application_nodes`
  and its conditional branches in `trusted_application_branches` (D11). The
  declarations are pinned in the manifest and must equal the builder's names;
  nothing is inferred;
- generated computation goes through the same compute route as C: an exact
  `ToolNode` dispatching to `LinuxSandboxExecutor` with the selected Lean
  grant-v3 lifecycle checker. That dispatch graph is also compiled under
  closed admission (it declares nothing trusted; its single node is admitted
  as an exact `ToolNode`);
- the input dataset is read through the `dataset_read` runtime operation
  (`read_dataset`) against an operator registry pinned to the frozen sales
  fixture digest, with an authorizer that allows exactly that dataset for the
  run principal;
- every graph's final output is returned through the `OutputMediator` that
  closed compilation installs on the compiled graph.

No vendor file is edited. The vendor compiled graphs are only used for their
`.builder`; the node functions, branches, prompts and state schema are the
vendor's own objects.
"""

import hashlib
import importlib.util
import io
import json
import types
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIGURATIONS = frozenset({"Baseline", "C-full", "C-full-lean"})
DATASET_ID = "sales"
PRINCIPAL_ID = "alice"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lifecycle_checker(request):
    """Select Lean only for the separately identified per-call configuration."""
    selection = request.get("lean_worker")
    if request.get("configuration") == "Baseline" and selection is None:
        return None
    if request.get("configuration") == "C-full" and selection is None:
        return None
    if (
        request.get("configuration") != "C-full-lean"
        or type(selection) is not dict
        or set(selection) != {"binary", "sha256", "protocol"}
        or selection["protocol"] != "worker-route-grant-v3"
    ):
        raise ValueError("C-full-lean requires a selected grant-v3 Lean worker route")
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

    return LeanLifecycleChecker(binary_path=selection["binary"], binary_sha256=selection["sha256"])


def run_principal(run_id):
    from langgraph.prebuilt.security import Principal

    return Principal(PRINCIPAL_ID, frozenset({"analyst"}), frozenset(), run_id)


def principal_config(principal, *, modules=()):
    from langgraph.prebuilt.security import with_principal

    return with_principal({}, principal, modules=modules)


# --- dataset_read -----------------------------------------------------------


def dataset_registry(path, sha256, max_bytes):
    from langgraph.prebuilt.security.dataset_operation import (
        DatasetEntry,
        DatasetRegistry,
    )

    return DatasetRegistry((DatasetEntry(DATASET_ID, str(path), sha256, max_bytes),))


def make_authorize(events):
    """Allow exactly `sales` for `alice`; deny everything else. Logs each decision."""
    from langgraph.prebuilt.security import Decision, Verdict

    def authorize(principal, request):
        allowed = (
            request.dataset_id == DATASET_ID
            and request.principal_id == PRINCIPAL_ID
            and principal.user_id == PRINCIPAL_ID
        )
        _event(
            events,
            {
                "kind": "dataset_authorize",
                "dataset_id": request.dataset_id,
                "principal_id": request.principal_id,
                "verdict": "allow" if allowed else "deny",
            },
        )
        if allowed:
            return Decision(Verdict.ALLOW, "pandas-closed: pinned sales fixture")
        return Decision(Verdict.DENY, "pandas-closed: dataset not granted")

    return authorize


STATE_NORMALIZATIONS = frozenset({"json-null-v1"})


def json_state(value):
    """JSON transport of controller state: string keys, non-finite floats -> null.

    `json-null-v1` (manifest-v21-closed). The vendor stores `df.to_dict()`
    (integer index keys, NaN for missing values) in graph state, which the
    closed graph's `OutputMediator` refuses (`output_data:string_key_required`,
    `output_data:nonfinite_float`). This applies the same JSON transport C
    already applies to the compute payload, plus NaN/Infinity -> `None`.
    """
    return json.loads(json.dumps(value), parse_constant=lambda _: None)


def normalization(request):
    selected = request.get("state_normalization")
    if selected is not None and selected not in STATE_NORMALIZATIONS:
        raise ValueError("Unsupported state normalization")
    return selected


def load_dataset(request, principal):
    """Read the pinned fixture via `read_dataset` and parse it as the vendor did."""
    import pandas as pd
    from langgraph.prebuilt.security.dataset_operation import read_dataset

    events = Path(request["events"])
    pin = request["dataset"]
    registry = dataset_registry(pin["path"], pin["sha256"], pin["max_bytes"])
    data = read_dataset(principal, DATASET_ID, registry=registry, authorize=make_authorize(events))
    _event(
        events,
        {
            "kind": "dataset_read",
            "dataset_id": DATASET_ID,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    )
    return pd.read_csv(io.BytesIO(data))


def load_dataset_baseline(request):
    """Read identical pinned bytes directly, without slangGraph mediation."""
    import pandas as pd

    pin = request["dataset"]
    path = Path(pin["path"])
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != pin["sha256"] or len(data) > pin["max_bytes"]:
        raise ValueError("Baseline dataset differs from the common pin")
    _event(
        request["events"],
        {
            "kind": "dataset_read_baseline",
            "bytes": len(data),
            "sha256": digest,
            "security_mediation": False,
        },
    )
    return pd.read_csv(io.BytesIO(data))


# --- closed compilation -----------------------------------------------------


def _security(declaration, audit, **extra):
    from langgraph.prebuilt.security import SecurityConfig

    return SecurityConfig(
        closed_admission=True,
        trusted_application_nodes=frozenset(declaration["nodes"]),
        trusted_application_branches=frozenset(declaration["branches"]),
        audit_sink=audit,
        **extra,
    )


def builder_names(builder):
    return (
        sorted(builder.nodes),
        sorted(
            f"{source}:branch:{name}"
            for source, named in builder.branches.items()
            for name in named
        ),
    )


def close_graph(label, compiled, declaration, audit):
    """Recompile a vendor graph's own builder under closed admission."""
    builder = compiled.builder
    nodes, branches = builder_names(builder)
    if nodes != sorted(declaration["nodes"]) or branches != sorted(declaration["branches"]):
        raise ValueError(f"Pinned trusted declaration differs from vendor graph: {label}")
    return builder.compile(
        checkpointer=compiled.checkpointer,
        name=compiled.name,
        security=_security(declaration, audit),
    )


def inventory(label, closed):
    from langgraph.prebuilt.security.admission import describe

    admitted = closed.builder._security_admission
    return {
        "graph": label,
        "descriptors": [describe(descriptor) for descriptor in admitted],
    }


# --- compute route (same executor, tool and policy as C) --------------------


def install_compute(request, audit):
    """Install the Cedar-authorized Linux bridge under closed admission.

    Returns the closed dispatch graph so its inventory can be recorded.
    """
    import ai_data_science_team.utils.sandbox as upstream

    original = upstream.run_code_sandboxed_subprocess
    serialization = request["sandbox_serialization"]
    codec = _load("pandas_sandbox_codec_closed", "sandbox_codec.py")
    if serialization not in codec.VERSIONS:
        raise ValueError("Unsupported sandbox serialization version")
    selected = types.FunctionType(
        original.__code__,
        {
            **original.__globals__,
            "SANDBOX_RUNNER_SCRIPT": codec.repair_runner(
                upstream.SANDBOX_RUNNER_SCRIPT,
                serialization,
                request.get("computation_api"),
            ),
        },
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    selected.__kwdefaults__ = original.__kwdefaults__
    source = Path(upstream.__file__).resolve()
    events = Path(request["events"])
    if request["configuration"] == "Baseline":

        def direct_bridge(
            *,
            code_snippet,
            function_name,
            data,
            timeout=10,
            memory_limit_mb=512,
            data_format="dataframe",
        ):
            payload = json.loads(
                json.dumps(
                    {
                        "code": code_snippet,
                        "function_name": function_name,
                        "data": data,
                        "memory_limit_mb": memory_limit_mb,
                        "data_format": data_format,
                        "sandbox_serialization": serialization,
                        "computation_api": request.get("computation_api"),
                    }
                )
            )
            _event(
                events,
                {
                    "kind": "computation",
                    "configuration": "Baseline",
                    "payload": payload,
                    "fault": None,
                    "added_boundary": False,
                },
            )
            return selected(
                code_snippet=payload["code"],
                function_name=payload["function_name"],
                data=payload["data"],
                timeout=timeout,
                memory_limit_mb=payload["memory_limit_mb"],
                data_format=payload["data_format"],
            )

        for module_name in ["data_wrangling_agent", "data_visualization_agent"]:
            module = importlib.import_module("ai_data_science_team.agents." + module_name)
            module.run_code_sandboxed_subprocess = direct_bridge
        return None

    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.security import (
        LinuxObjectDispatcher,
        LinuxToolSpec,
        cedar_security,
    )

    normalization(request)
    checker = lifecycle_checker(request)
    artifact = (HERE / "worker.py").resolve()
    dispatcher = LinuxObjectDispatcher(
        {
            "compute": LinuxToolSpec(
                "worker:compute",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(artifact.parent, source.parents[2]),
        wall_timeout_s=15,
        lifecycle_checker=checker,
    )
    (events.parent / "lifecycle-selection.json").write_text(
        json.dumps(request.get("lean_worker"), indent=2) + "\n"
    )

    @tool
    def compute(sandbox_source: str, payload: dict) -> dict:
        """Run the generated computation, preserving the upstream sandbox checks."""
        raise RuntimeError("Unconfined fallback is forbidden")

    security = cedar_security(
        compute,
        manifest="runs linux\nfs read @{sandbox_source} need",
        policy=request["principal_policy"],
        dispatcher=dispatcher,
    )
    security = replace(security, audit_sink=audit, closed_admission=True)

    builder = StateGraph(MessagesState)
    builder.add_node("dispatch", ToolNode([compute], security=security))
    builder.add_edge(START, "dispatch")
    node_graph = builder.compile(security=security)
    config = principal_config(run_principal(request["run_id"]), modules=security.modules)

    def bridge(
        *,
        code_snippet,
        function_name,
        data,
        timeout=10,
        memory_limit_mb=512,
        data_format="dataframe",
    ):
        payload = {
            "code": code_snippet,
            "function_name": function_name,
            "data": data,
            "memory_limit_mb": memory_limit_mb,
            "data_format": data_format,
            "sandbox_serialization": serialization,
            "computation_api": request.get("computation_api"),
        }
        if request.get("attack") is not None:
            payload["attack"] = request["attack"]
        payload = json.loads(json.dumps(payload))
        _event(
            events,
            {
                "kind": "computation",
                "configuration": request["configuration"],
                "payload": payload,
                "fault": None,
                "added_boundary": True,
            },
        )
        if timeout != 15 or memory_limit_mb != 512:
            raise ValueError("Version a new manifest for changed upstream sandbox limits")
        response = node_graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "compute",
                                "args": {"sandbox_source": str(source), "payload": payload},
                                "id": "compute-call",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        message = response["messages"][-1]
        _event(
            events,
            {
                "kind": "dispatch_result",
                "status": message.status,
                "content": message.content,
            },
        )
        (events.parent / "activation-receipts.json").write_text(
            json.dumps(
                [receipt.canonical() for receipt in dispatcher.activation_receipts()], indent=2
            )
            + "\n"
        )
        (events.parent / "lowered-restrictions.json").write_text(
            json.dumps([dict(record) for record in dispatcher.lowering_records()], indent=2) + "\n"
        )
        if message.status == "error":
            return None, message.content
        result = json.loads(message.content)
        if result.get("attack_observation") is not None:
            _event(
                events,
                {
                    "kind": "attack_observation",
                    **result["attack_observation"],
                },
            )
        if normalization(request) is not None:
            result = json_state(result)
        return result["result"], result["error"]

    for module_name in ["data_wrangling_agent", "data_visualization_agent"]:
        module = importlib.import_module("ai_data_science_team.agents." + module_name)
        module.run_code_sandboxed_subprocess = bridge
    return node_graph


def _event(events, record):
    with Path(events).open("a") as stream:
        stream.write(json.dumps(record, default=str) + "\n")
