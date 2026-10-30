"""Closed-admission inventory of the unchanged pandas vendor graph (D11 step 1).

Run in the upstream environment:

    .venv/bin/python eval/apps/pandas/closed_inventory.py OUTPUT_DIR

Builds the vendor `PandasDataAnalyst` exactly as `apps/backend.py` does (with a
fake chat model; no model is called and no graph is invoked), then, for the
outer graph and both nested agents, records every node and branch of the
compiled builder and tries `builder.compile(security=SecurityConfig(
closed_admission=True, trusted_application_nodes=<all node names>))`.

Admission is never relaxed. A diagnostic compile of a shallow builder copy with
its branches removed is recorded only to show whether branches are the sole
blocker; that copy is never invoked. The output directory must not exist.
"""

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FROZEN_SOURCES = (
    "libs/prebuilt/langgraph/prebuilt/security/admission.py",
    "libs/prebuilt/langgraph/prebuilt/security/config.py",
    "libs/prebuilt/langgraph/prebuilt/security/dataset_operation.py",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _refusal(call):
    try:
        call()
    except PermissionError as error:
        return str(error)
    return None


def inventory_graph(label, compiled):
    from langgraph.prebuilt.security import SecurityConfig
    from langgraph.prebuilt.security.admission import admit_node

    builder = compiled.builder
    declared = frozenset(builder.nodes)
    config = SecurityConfig(closed_admission=True, trusted_application_nodes=declared)
    undeclared = SecurityConfig(closed_admission=True)
    nodes = []
    for name, spec in builder.nodes.items():
        runnable = spec.runnable
        function = getattr(runnable, "func", None)
        record = {
            "name": name,
            "runnable_type": type(runnable).__name__,
            "function_type": type(function).__name__,
            "qualname": getattr(function, "__qualname__", None),
            "module": getattr(function, "__module__", None),
            "is_compiled_subgraph": type(runnable).__name__ == "CompiledStateGraph",
        }
        try:
            record["declared_kind"] = admit_node(name, runnable, config=config).kind.value
        except PermissionError as error:
            record["declared_refusal"] = str(error)
        record["undeclared_refusal"] = _refusal(
            lambda name=name, runnable=runnable: admit_node(name, runnable, config=undeclared)
        )
        nodes.append(record)
    branches = []
    from langgraph.prebuilt.security.admission import admit_branch

    for source, named in builder.branches.items():
        for branch_name, branch in named.items():
            function = getattr(branch.path, "func", None)
            placement = f"{source}:branch:{branch_name}"
            branches.append(
                {
                    "placement": placement,
                    "path_type": type(branch.path).__name__,
                    "qualname": getattr(function, "__qualname__", None),
                    "module": getattr(function, "__module__", None),
                    "ends": dict(branch.ends or {}),
                    "refusal": _refusal(
                        lambda placement=placement, branch=branch: admit_branch(
                            placement, branch, config=config
                        )
                    ),
                }
            )
    channels = {
        name: {
            "type": type(channel).__name__,
            "reducer": getattr(getattr(channel, "operator", None), "__qualname__", None),
        }
        for name, channel in builder.channels.items()
    }
    compile_refusal = _refusal(lambda: builder.compile(security=config))
    stripped = copy.copy(builder)
    stripped.branches = {}
    diagnostic = _refusal(lambda: stripped.compile(security=config))
    return {
        "graph": label,
        "trusted_application_nodes": sorted(declared),
        "nodes": nodes,
        "branches": branches,
        "channels": channels,
        "closed_compile": "admitted" if compile_refusal is None else "refused",
        "closed_compile_refusal": compile_refusal,
        "diagnostic_compile_without_branches": ("admitted" if diagnostic is None else diagnostic),
    }


def main(output: Path) -> dict:
    sys.path[:0] = [
        str(ROOT / "libs/prebuilt"),
        str(ROOT / "libs/langgraph"),
        str(ROOT / "libs/checkpoint"),
    ]
    import ai_data_science_team
    from ai_data_science_team import (
        DataVisualizationAgent,
        DataWranglingAgent,
        PandasDataAnalyst,
    )
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    output.mkdir(parents=True, exist_ok=False)
    llm = FakeListChatModel(responses=["{}"])
    # Same constructor arguments as apps/backend.py.
    wrangling = DataWranglingAgent(
        model=llm, log=False, bypass_recommended_steps=True, n_samples=100
    )
    visualization = DataVisualizationAgent(model=llm, n_samples=100, log=False)
    agent = PandasDataAnalyst(
        model=llm, data_wrangling_agent=wrangling, data_visualization_agent=visualization
    )
    graphs = [
        inventory_graph("pandas_data_analyst", agent._compiled_graph),
        inventory_graph("data_wrangling_agent", wrangling._compiled_graph),
        inventory_graph("data_visualization_agent", visualization._compiled_graph),
    ]
    vendor = Path(ai_data_science_team.__file__).resolve().parent
    blockers = [
        {"graph": graph["graph"], **branch}
        for graph in graphs
        for branch in graph["branches"]
        if branch["refusal"] is not None
    ] + [
        {"graph": graph["graph"], **node}
        for graph in graphs
        for node in graph["nodes"]
        if "declared_refusal" in node
    ]
    report = {
        "schema_version": 1,
        "purpose": "D11 closed-admission inventory of the unchanged pandas vendor graph",
        "vendor_package": str(vendor),
        "vendor_sources_sha256": {
            str(path.relative_to(vendor)): _sha(path)
            for path in sorted(vendor.rglob("*.py"))
            if path.parent.name in {"multiagents", "agents", "templates"}
        },
        "frozen_security_sources_sha256": {name: _sha(ROOT / name) for name in FROZEN_SOURCES},
        "adapter_sha256": _sha(Path(__file__).resolve()),
        "model": "FakeListChatModel (construction only; never invoked)",
        "graphs": graphs,
        "compiles_under_closed_admission": all(
            graph["closed_compile"] == "admitted" for graph in graphs
        ),
        "blockers": blockers,
    }
    (output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    result = main(Path(sys.argv[1]))
    print(
        json.dumps(
            {
                "compiles": result["compiles_under_closed_admission"],
                "blockers": [
                    (
                        b["graph"],
                        b.get("placement") or b.get("name"),
                        b.get("refusal") or b.get("declared_refusal"),
                    )
                    for b in result["blockers"]
                ],
            },
            indent=2,
        )
    )
