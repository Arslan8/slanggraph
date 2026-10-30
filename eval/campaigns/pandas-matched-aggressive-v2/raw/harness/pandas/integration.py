"""Explicit added node-dispatch adapter; B is not a native tool-boundary ablation."""

import ast
import hashlib
import importlib
import json
import types
from pathlib import Path


def selected_lifecycle_checker(request):
    """Select the pinned grant/receipt checker for an explicit C configuration."""
    selection = request.get("lean_worker")
    if selection is None:
        return None
    if (
        request.get("configuration") != "C"
        or type(selection) is not dict
        or set(selection) != {"binary", "sha256", "protocol"}
        or selection["protocol"] != "worker-route-grant-v3"
    ):
        raise ValueError("Invalid selected Lean worker route")
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

    return LeanLifecycleChecker(binary_path=selection["binary"], binary_sha256=selection["sha256"])


def fault_variant(code, function_name, request):
    """A separately labeled controlled implementation variant, never a normal baseline."""
    fault = request.get("fault")
    if not fault:
        return code
    output = Path(request["fixture_root"]) / "outputs"
    target = request["effect_target"]
    operation = (
        f"pd.read_csv({target!r}).to_csv({str(output / 'read-receipt.csv')!r}, index=False)"
        if fault in {"internal-read", "extra-read"}
        else f"pd.DataFrame({{'marker': ['attempted']}}).to_csv({target!r}, index=False)"
    )
    snippet = f"""
import pandas as pd
pd.DataFrame({{'marker': ['attempted']}}).to_csv({str(output / "attempt.csv")!r}, index=False)
try:
    {operation}
except Exception as error:
    pd.DataFrame({{'error': [str(error)]}}).to_csv({str(output / "denial.csv")!r}, index=False)
"""
    tree = ast.parse(code)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    if not isinstance(function.body[-1], ast.Return):
        raise ValueError("Controlled variant requires a final return; no attempted effect claimed")
    function.body[-1:-1] = ast.parse(snippet).body
    return ast.unparse(ast.fix_missing_locations(tree))


def install(request):
    import ai_data_science_team.utils.sandbox as upstream

    original = upstream.run_code_sandboxed_subprocess
    serialization = request.get("sandbox_serialization")
    if serialization is not None:
        codec_spec = importlib.util.spec_from_file_location(
            "pandas_sandbox_codec", Path(__file__).with_name("sandbox_codec.py")
        )
        codec = importlib.util.module_from_spec(codec_spec)
        codec_spec.loader.exec_module(codec)
        if serialization not in codec.VERSIONS:
            raise ValueError("Unsupported sandbox serialization version")
        # Keep the selected runner local to this adapter. Installing a repaired
        # condition must not change a later original condition in this process.
        selected = types.FunctionType(
            original.__code__,
            {
                **original.__globals__,
                "SANDBOX_RUNNER_SCRIPT": codec.repair_runner(
                    upstream.SANDBOX_RUNNER_SCRIPT, serialization, request.get("computation_api")
                ),
            },
            original.__name__,
            original.__defaults__,
            original.__closure__,
        )
        selected.__kwdefaults__ = original.__kwdefaults__
        original = selected
    source = Path(upstream.__file__).resolve()
    events = Path(request["events"])
    configuration = request["configuration"]
    lifecycle_checker = selected_lifecycle_checker(request)
    node_graph = None
    executor = None
    principal_config = None
    audit = None
    if configuration in {"B", "C"}:
        from langchain_core.tools import tool
        from langgraph.graph import START, MessagesState, StateGraph
        from langgraph.prebuilt import ToolNode
        from langgraph.prebuilt.security import (
            DacOverrides,
            Effect,
            LinuxSandboxExecutor,
            LinuxToolSpec,
            Principal,
            ResourceArg,
            SecurityConfig,
            SqliteAuditSink,
            dac,
            effects,
            parse_profiles,
            with_principal,
        )

        audit = SqliteAuditSink(events.parent / "security.sqlite")
        profiles = parse_profiles(
            Path(request["effective_policy"]).read_text(), source="frozen-application.slp"
        )
        if configuration == "C":
            artifact = Path(__file__).with_name("worker.py").resolve()
            executor = LinuxSandboxExecutor(
                profiles,
                {
                    "compute": LinuxToolSpec(
                        "worker:compute",
                        artifact,
                        hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    )
                },
                runtime_roots=(artifact.parent, source.parents[2]),
                default_wall_timeout_s=15,
                lifecycle_checker=lifecycle_checker,
            )
            if lifecycle_checker is not None:
                (events.parent / "lifecycle-selection.json").write_text(
                    json.dumps(request["lean_worker"], indent=2) + "\n"
                )
        security = SecurityConfig(
            dac_overrides=DacOverrides(profiles=profiles.tools) if executor else DacOverrides(),
            host_executor=executor,
            audit_sink=audit,
        )

        @tool
        @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
        @effects(
            Effect.EXEC, Effect.READ, resources=[ResourceArg("sandbox_source", "path", "realpath")]
        )
        def compute(sandbox_source: str, payload: dict) -> dict:
            """Run the generated computation, preserving the upstream sandbox checks."""
            if executor is not None:
                raise RuntimeError("Unconfined fallback is forbidden")
            result, error = original(
                code_snippet=payload["code"],
                function_name=payload["function_name"],
                data=payload["data"],
                memory_limit_mb=payload["memory_limit_mb"],
                data_format=payload["data_format"],
                timeout=15,
            )
            return {"result": result, "error": error}

        builder = StateGraph(MessagesState)
        builder.add_node("dispatch", ToolNode([compute], security=security))
        builder.add_edge(START, "dispatch")
        node_graph = builder.compile()
        principal_config = with_principal(
            {}, Principal("alice", frozenset({"analyst"}), frozenset(), request["run_id"])
        )

    def bridge(
        *,
        code_snippet,
        function_name,
        data,
        timeout=10,
        memory_limit_mb=512,
        data_format="dataframe",
    ):
        code_snippet = fault_variant(code_snippet, function_name, request)
        payload = {
            "code": code_snippet,
            "function_name": function_name,
            "data": data,
            "memory_limit_mb": memory_limit_mb,
            "data_format": data_format,
            "sandbox_serialization": serialization,
            "computation_api": request.get("computation_api"),
        }
        # Match the upstream subprocess JSON transport, including integer index keys.
        payload = json.loads(json.dumps(payload))
        with events.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "kind": "computation",
                        "configuration": configuration,
                        "payload": payload,
                        "fault": request.get("fault"),
                        "added_boundary": configuration != "A",
                    }
                )
                + "\n"
            )
        if node_graph is None:
            return original(
                code_snippet=code_snippet,
                function_name=function_name,
                data=data,
                timeout=timeout,
                memory_limit_mb=memory_limit_mb,
                data_format=data_format,
            )
        if timeout != 15 or memory_limit_mb != 512:
            raise ValueError("Version a new manifest for changed upstream sandbox limits")
        from langchain_core.messages import AIMessage

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
            config=principal_config,
        )
        message = response["messages"][-1]
        if executor:
            (events.parent / "activation-receipts.json").write_text(
                json.dumps(
                    [receipt.canonical() for receipt in executor.activation_receipts()], indent=2
                )
                + "\n"
            )
        if message.status == "error":
            return None, message.content
        result = json.loads(message.content)
        return result["result"], result["error"]

    for module_name in ["data_wrangling_agent", "data_visualization_agent"]:
        module = importlib.import_module("ai_data_science_team.agents." + module_name)
        module.run_code_sandboxed_subprocess = bridge
