"""Native SQL agent adaptation: bounded resource mediator covers metadata and queries."""

import hashlib
import importlib
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "libs/prebuilt"),
    str(ROOT / "libs/langgraph"),
    str(Path(__file__).parent),
]
import bounded_sql  # noqa: E402 - repository path setup

CLASSES = """class sales {
 operations schema select
 object dataset
 normalizer identity
 attrs
 enforced_by broker
 lowering sqlite.select.v1
}"""
MANIFEST = """runs linux
map operation=schema sales schema @{selector} need
map operation=select sales select @{selector} need
returns sensitive"""
POLICY = """permit(principal == slangGraph::User::"alice",
 action in [slangGraph::Action::"sales::schema",slangGraph::Action::"sales::select"],resource)
 when { resource.selector == "sales/alice" };"""


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    folder = Path(request["output"]).parent
    import pandas as pd
    import sqlalchemy as sql
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.security import (
        EnforcementKind,
        LinuxToolSpec,
        ObjectBrokerDispatcher,
        Principal,
        ResourceMediatorAdapter,
        ResourceSupport,
        SqliteAuditSink,
        SupportLevel,
        Tool,
        ToolCall,
        ToolDac,
        cedar_security,
        with_principal,
    )

    sys.path.insert(0, str(ROOT / "eval/scripts"))
    from evidence_utils import serial

    agent_module = importlib.import_module("ai_data_science_team.agents.sql_database_agent")
    database = Path(request["database"])
    trace = []
    spans = []
    principal = Principal("alice", frozenset(), frozenset(), request["run_id"])
    mode = request["configuration"]

    def emit(event):
        with Path(request["events"]).open("a") as stream:
            stream.write(json.dumps(event, default=str) + "\n")

    class Observer(BaseCallbackHandler):
        def on_chat_model_start(self, serialized, messages, **kwargs):
            emit(
                dict(
                    kind="model_start",
                    monotonic=time.perf_counter(),
                    messages=[[m.model_dump() for m in batch] for batch in messages],
                )
            )

        def on_llm_end(self, response, **kwargs):
            emit(
                dict(
                    kind="model_end", monotonic=time.perf_counter(), response=response.model_dump()
                )
            )

    settings = request["model"]
    llm = ChatOpenAI(
        model=settings["name"],
        base_url=settings["base_url"],
        api_key="ollama",
        temperature=0,
        seed=settings["seed"],
        timeout=120,
        max_retries=0,
        reasoning_effort="none",
        callbacks=[Observer()],
    )
    security = None
    dispatcher = None
    if mode != "A":

        def assess(line, host):
            if (
                line.class_name != "sales"
                or line.operation not in {"schema", "select"}
                or line.selector != "sales/alice"
                or line.attributes
                or line.enforcer is not EnforcementKind.BROKER
                or line.lowering != "sqlite.select.v1"
            ):
                return ResourceSupport(
                    SupportLevel.UNSUPPORTED, "unsupported sales selector/conditions"
                )
            return ResourceSupport(
                SupportLevel.EXACT,
                "bounded SELECT; principal ownership bound in trusted SQL",
                witness="eval/tests/test_bounded_sql_evaluation.py",
                protected_paths=(str(database.parent),),
                required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
            )

        def dispatch(line, payload, context):
            if set(payload) != {"query"} or context.principal_id != "alice":
                raise PermissionError("payload/identity")
            start = time.perf_counter()
            try:
                if line.operation == "schema":
                    return bounded_sql.metadata(database, context.principal_id, trace)
                return bounded_sql.execute(database, context.principal_id, payload["query"], trace)
            except bounded_sql.UnsupportedQuery as error:
                return {"unsupported": str(error)}
            finally:
                spans.append(
                    dict(
                        phase="mediator",
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                        nesting="inside dispatch",
                    )
                )

        worker = Path(__file__).with_name("sql_worker.py")
        dispatcher = ObjectBrokerDispatcher(
            {
                "sql_access": LinuxToolSpec(
                    "sql_worker:run", worker, hashlib.sha256(worker.read_bytes()).hexdigest()
                )
            },
            runtime_roots=tuple(Path(p).resolve() for p in sys.path if p and Path(p).is_dir()),
            mediators=(ResourceMediatorAdapter("sqlite.select.v1", assess, dispatch),),
        )

        @tool("sql_access")
        def sql_access(operation: str, query: str, selector: str) -> dict:
            """Request schema or a bounded SELECT over owned sales records."""
            raise RuntimeError("no unconfined fallback")

        receipts = []
        original_dispatch = dispatcher.invoke

        def capture_dispatch(principal, call, grant):
            response = original_dispatch(principal, call, grant)
            receipts.append(serial(response.receipt))
            return response

        dispatcher.invoke = capture_dispatch
        security = cedar_security(
            sql_access, manifest=MANIFEST, classes=CLASSES, policy=POLICY, dispatcher=dispatcher
        )
        security = replace(
            security,
            audit_sink=SqliteAuditSink(folder / "audit.sqlite", durability="trusted-async"),
        )
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode([sql_access]))
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        counter = 0

        def access(operation, query):
            nonlocal counter
            counter += 1
            start = time.perf_counter()
            args = dict(operation=operation, query=query, selector="sales/alice")
            try:
                if mode == "B":
                    call = ToolCall(
                        Tool("sql_access", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                        args,
                        {},
                        str(counter),
                        0,
                    )
                    grant = security.host_executor._authorize(principal, call, ())
                    emit(dict(kind="call_authorization", grant=serial(grant)))
                    return None
                response = graph.invoke(
                    {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[dict(name="sql_access", args=args, id=str(counter))],
                            )
                        ]
                    },
                    config=with_principal({}, principal, modules=security.modules),
                )
                message = response["messages"][-1]
                if getattr(message, "status", None) == "error":
                    raise PermissionError(str(message.content))
                value = json.loads(message.content)
                if "unsupported" in value:
                    raise bounded_sql.UnsupportedQuery(value["unsupported"])
                return value
            finally:
                spans.append(
                    dict(
                        phase="framework_dispatch",
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                        nesting="includes policy,worker,mediator,audit",
                    )
                )

        original_metadata = agent_module.get_database_metadata
        original_execute = agent_module.node_func_execute_agent_from_sql_connection

        def metadata(connection, n_samples=1):
            data = access("schema", "")
            return data if mode == "C" else original_metadata(connection, n_samples=n_samples)

        def execute(**kwargs):
            state = kwargs["state"]
            try:
                value = access("select", state["sql_query_code"])
                if mode == "B":
                    return original_execute(**kwargs)
                return {
                    kwargs["result_key"]: pd.DataFrame(
                        value["rows"], columns=value["columns"]
                    ).to_dict(),
                    kwargs["error_key"]: None,
                }
            except (bounded_sql.UnsupportedQuery, PermissionError) as error:
                return {kwargs["result_key"]: None, kwargs["error_key"]: str(error)}

        agent_module.get_database_metadata = metadata
        agent_module.node_func_execute_agent_from_sql_connection = execute
    engine = sql.create_engine(
        "sqlite:///:memory:" if mode == "C" else "sqlite:///" + str(database)
    )
    try:
        with engine.connect() as connection:
            agent = agent_module.SQLDatabaseAgent(
                model=llm,
                connection=connection,
                n_samples=3,
                log=False,
                bypass_recommended_steps=True,
                bypass_explain_code=True,
                safe_mode=True,
            )
            agent.invoke_agent(user_instructions=request["task"], max_retries=0)
            table = agent.get_data_sql()
            output = dict(
                table=pd.DataFrame(table).to_dict(orient="records") if table is not None else None,
                sql=agent.get_sql_query_code(),
                state=agent.response,
            )
            Path(request["output"]).write_text(json.dumps(output, default=str, indent=2))
    finally:
        engine.dispose()
        (folder / "resource-trace.json").write_text(json.dumps(trace, default=str, indent=2))
        (folder / "spans.json").write_text(json.dumps(spans, indent=2))
        if security:
            (folder / "activation-receipts.json").write_text(json.dumps(receipts, indent=2))
            (folder / "grants.json").write_text(
                json.dumps(serial(security.host_executor.authorization_grants()), indent=2)
            )
            (folder / "lowering.json").write_text(
                json.dumps(serial(dispatcher.lowering_records()), indent=2)
            )
            (folder / "broker-audit.json").write_text(
                json.dumps(serial(dispatcher.audit_records()), indent=2)
            )


if __name__ == "__main__":
    main()
