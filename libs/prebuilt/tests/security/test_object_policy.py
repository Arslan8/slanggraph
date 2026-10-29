"""Open object-class manifests and Cedar DAC/MAC authorization."""

from __future__ import annotations

import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    ActivationReceipt,
    CedarObjectAuthorizer,
    CedarPolicySet,
    Effect,
    EnforcementKind,
    EnforcementMode,
    HostExecutionError,
    HostExecutionResult,
    ObjectClass,
    ObjectGrantLine,
    ObjectPolicyDenied,
    ObjectPolicyHostExecutor,
    Principal,
    ProfileSyntaxError,
    ResourceArg,
    RuleEnforcement,
    SecurityConfig,
    SupportLevel,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    effects,
    parse_security_manifest,
    with_principal,
)
from langgraph.prebuilt.security.inprocess import read_text

MANIFEST = """
class db {
  operations select insert update delete ddl
  object table
  normalizer sql.table_ref
  attrs owner schema
  enforced_by broker
  lowering postgres.role_grant
}

class secret {
  operations read
  object item
  normalizer identity
  attrs owner
  enforced_by broker
}

tool run_report {
  runs broker
  db select reports.@{quarter} need
  secret read reporting_api_key want
  returns sensitive
}
"""


class _Broker:
    enforcer_id = "test-broker"

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        return object_class.enforced_by is EnforcementKind.BROKER


class _Dispatcher:
    def __init__(self) -> None:
        self.grants = []

    def invoke(self, principal, call, grant):
        self.grants.append(grant)
        return HostExecutionResult("brokered report", _receipt(grant.digest))

    async def ainvoke(self, principal, call, grant):
        return self.invoke(principal, call, grant)

    def confirm_termination(self, recovery):
        return True


class _IncompleteDispatcher(_Dispatcher):
    def invoke(self, principal, call, grant):
        self.grants.append(grant)
        return HostExecutionResult("brokered report", _receipt(grant.digest, ()))


class _CountingCedarObjectAuthorizer(CedarObjectAuthorizer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.run_count = 0

    def _run(
        self, executable: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        self.run_count += 1
        return super()._run(executable, *arguments)


def test_manifest_registers_classes_and_expands_normalized_lines() -> None:
    manifest = parse_security_manifest(
        MANIFEST,
        source="report.slp",
        enforcers={EnforcementKind.BROKER: _Broker()},
    )

    lines = manifest.expand(
        "run_report",
        {"quarter": "Q4"},
        labels={
            ("db", "reports.q4"): {"owner": "finance"},
            ("secret", "reporting_api_key"): {"owner": "platform"},
        },
    )

    assert manifest.registry.classes["db"].cedar_entity_type == "DbTable"
    assert [line.selector for line in lines] == [
        "reports.q4",
        "reporting_api_key",
    ]
    assert lines[0].attributes == {"owner": "finance", "schema": "reports"}
    assert lines[0].lowering == "postgres.role_grant"
    manifest.registry.require_enforceable(lines)


def test_manifest_maps_a_closed_argument_set_to_fixed_operations() -> None:
    manifest = parse_security_manifest(
        """
        class pump {
          operations inspect start stop set_flow calibrate
          object device
          normalizer identity
          attrs
          enforced_by language_sandbox
        }
        tool control_pump {
          runs inprocess
          map operation=inspect pump inspect pump-1 need
          map operation=start pump start pump-1 need
          map operation=stop pump stop pump-1 need
          map operation=set_flow pump set_flow pump-1 need
          map operation=calibrate pump calibrate pump-1 need
          returns sensitive
        }
        """
    )

    selectors = []
    for operation in ("inspect", "start", "stop", "set_flow", "calibrate"):
        lines = manifest.expand(
            "control_pump",
            {"device_id": "pump-1", "operation": operation},
        )
        assert len(lines) == 1
        assert lines[0].operation == operation
        selectors.append(lines[0].selector)

    assert selectors == ["pump-1"] * 5
    with pytest.raises(
        ObjectPolicyDenied,
        match="unmapped_selector:operation:arbitrary::Cedar::Action",
    ):
        manifest.expand(
            "control_pump",
            {"device_id": "pump-1", "operation": "arbitrary::Cedar::Action"},
        )


def test_manifest_rejects_multiple_operation_selector_arguments() -> None:
    with pytest.raises(
        ProfileSyntaxError,
        match="select operations from only one argument",
    ):
        parse_security_manifest(
            """
            class pump {
              operations inspect start
              object device
              normalizer identity
              attrs
              enforced_by language_sandbox
            }
            tool control_pump {
              map operation=inspect pump inspect pump-1 need
              map mode=start pump start pump-1 need
            }
            """
        )


def test_unknown_class_operation_fails_during_manifest_parsing() -> None:
    with pytest.raises(ProfileSyntaxError, match="is not declared by class db"):
        parse_security_manifest(
            MANIFEST.replace("db select", "db vacuum", 1),
            source="bad.slp",
        )


def test_missing_enforcer_fails_closed() -> None:
    manifest = parse_security_manifest(MANIFEST)
    lines = manifest.expand("run_report", {"quarter": "Q4"})

    with pytest.raises(ObjectPolicyDenied, match="unsupported:db:select:broker"):
        manifest.registry.require_enforceable(lines)


def test_missing_enforcer_rejects_toolnode_configuration(tmp_path: Path) -> None:
    manifest = parse_security_manifest(MANIFEST)
    permit = "permit(principal, action, resource);"
    executor = ObjectPolicyHostExecutor(
        CedarObjectAuthorizer(
            manifest,
            CedarPolicySet({"run_report": permit}, permit),
            executable=_fake_cedar(tmp_path),
        ),
        _Dispatcher(),
        tool_owners={"run_report": "reporting"},
    )

    with pytest.raises(ValueError, match="unsupported_class:db:broker"):
        executor.validate_tools(("run_report",))


def test_explicit_enforcement_waiver_records_degraded_lines(tmp_path: Path) -> None:
    manifest = parse_security_manifest(MANIFEST)
    permit = "permit(principal, action, resource);"
    authorizer = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=_fake_cedar(tmp_path),
        enforcement_waivers={
            "db": "database broker is not deployed on this development host",
            "secret": "secret broker is not deployed on this development host",
        },
    )
    executor = ObjectPolicyHostExecutor(
        authorizer,
        _Dispatcher(),
        tool_owners={"run_report": "reporting"},
    )
    executor.validate_tools(("run_report",))

    grant = authorizer.authorize(
        principal_id="alice",
        roles=(),
        tool_name="run_report",
        tool_owner="reporting",
        call_id="call-1",
        arguments={"quarter": "Q4"},
    )

    assert set(grant.enforcement_waivers) == {"run_report:0", "run_report:1"}
    assert grant.digest


def test_enforcement_waiver_requires_a_reason() -> None:
    manifest = parse_security_manifest(MANIFEST)
    permit = "permit(principal, action, resource);"

    with pytest.raises(ValueError, match="waiver reason"):
        CedarObjectAuthorizer(
            manifest,
            CedarPolicySet({"run_report": permit}, permit),
            enforcement_waivers={"db": ""},
        )


def test_cedar_policy_partitions_are_monotone() -> None:
    permit = "permit(principal, action, resource);"
    forbid = "forbid(principal, action, resource);"

    with pytest.raises(ValueError, match="forbidden effects: permit"):
        CedarPolicySet(
            {"run_report": permit},
            permit,
            mac_forbids=permit,
        )
    with pytest.raises(ValueError, match="forbidden effects: forbid"):
        CedarPolicySet(
            {"run_report": forbid},
            permit,
        )


def test_dynamic_schema_contains_class_actions_and_attributes() -> None:
    manifest = parse_security_manifest(MANIFEST)
    schema = manifest.registry.cedar_schema()

    assert "entity DbTable" in schema
    assert "owner: String" in schema
    assert "schema: String" in schema
    assert 'action "db::select"' in schema
    assert 'action "secret::read"' in schema


def test_normalizer_failure_is_a_concise_object_policy_denial() -> None:
    manifest = parse_security_manifest(
        """
        class fs {
          operations read
          object path
          normalizer fs.realpath
          attrs
          enforced_by language_sandbox
        }
        tool read_file {
          runs inprocess
          fs read @{path} need
          returns sensitive
        }
        """
    )

    with pytest.raises(
        ObjectPolicyDenied,
        match=("invalid_object:fs:read:path does not exist or cannot be resolved"),
    ) as raised:
        manifest.expand("read_file", {"path": "/path/that/does/not/exist"})

    assert raised.value.__cause__ is None


def test_authorizer_intersects_owner_envelope_and_mac(tmp_path: Path) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    policies = CedarPolicySet(
        {"run_report": permit},
        permit,
        mac_forbids=(
            "forbid(principal, action, resource)\n"
            'when { resource.schema == "private" };'
        ),
    )
    authorizer = CedarObjectAuthorizer(manifest, policies, executable=cedar)

    grant = authorizer.authorize(
        principal_id="alice",
        roles={"analyst"},
        tool_name="run_report",
        tool_owner="reporting",
        call_id="call-1",
        arguments={"quarter": "Q4"},
        labels={
            ("db", "reports.q4"): {"owner": "finance"},
            ("secret", "reporting_api_key"): {"owner": "platform"},
        },
    )

    assert [(line.class_name, line.selector) for line in grant.lines] == [
        ("db", "reports.q4"),
        ("secret", "reporting_api_key"),
    ]
    assert grant.digest
    artifacts = authorizer.authorization_artifacts()
    assert len(artifacts) == 1
    artifact_dir = artifacts[0]
    assert artifact_dir.parent == authorizer.artifact_root
    assert stat.S_IMODE(authorizer.artifact_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact_dir.stat().st_mode) == 0o700
    assert (artifact_dir / "schema.cedarschema").is_file()
    assert (artifact_dir / "entities.json").is_file()
    assert list(artifact_dir.glob("owner-*.request.json"))
    assert list(artifact_dir.glob("envelope-*.request.json"))


def test_authorizer_reuses_exact_cedar_results_and_retains_artifacts(
    tmp_path: Path,
) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    authorizer = _CountingCedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=cedar,
    )
    inputs = {
        "principal_id": "alice",
        "roles": {"analyst"},
        "tool_name": "run_report",
        "tool_owner": "reporting",
        "arguments": {"quarter": "Q4"},
    }

    first = authorizer.authorize(call_id="call-1", **inputs)
    first_run_count = authorizer.run_count
    second = authorizer.authorize(call_id="call-2", **inputs)

    assert first_run_count > 0
    assert authorizer.run_count == first_run_count
    assert first.call_id == "call-1"
    assert second.call_id == "call-2"
    assert len(authorizer.authorization_artifacts()) == 2
    assert list(authorizer.authorization_artifacts()[1].glob("owner-*.request.json"))


def test_authorizer_cache_tracks_cedar_executable_identity(tmp_path: Path) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    authorizer = _CountingCedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=cedar,
    )
    inputs = {
        "principal_id": "alice",
        "roles": (),
        "tool_name": "run_report",
        "tool_owner": "reporting",
        "arguments": {"quarter": "Q4"},
    }

    authorizer.authorize(call_id="call-1", **inputs)
    first_run_count = authorizer.run_count
    cedar.write_text(cedar.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    authorizer.authorize(call_id="call-2", **inputs)

    assert authorizer.run_count > first_run_count


def test_authorizer_cache_can_be_disabled(tmp_path: Path) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    authorizer = _CountingCedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=cedar,
        cache_entries=0,
    )
    inputs = {
        "principal_id": "alice",
        "roles": (),
        "tool_name": "run_report",
        "tool_owner": "reporting",
        "arguments": {"quarter": "Q4"},
    }

    authorizer.authorize(call_id="call-1", **inputs)
    first_run_count = authorizer.run_count
    authorizer.authorize(call_id="call-2", **inputs)

    assert authorizer.run_count > first_run_count


def test_authorizer_rejects_negative_cache_size() -> None:
    manifest = parse_security_manifest(MANIFEST)
    permit = "permit(principal, action, resource);"

    with pytest.raises(ValueError, match="cache size"):
        CedarObjectAuthorizer(
            manifest,
            CedarPolicySet({"run_report": permit}, permit),
            cache_entries=-1,
        )


def test_authorizer_uses_cedar_cli_request_encoding() -> None:
    cedar = shutil.which("cedar")
    if cedar is None:
        pytest.skip("Cedar CLI is not installed")
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"

    grant = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=cedar,
    ).authorize(
        principal_id="alice",
        roles={"analyst"},
        tool_name="run_report",
        tool_owner="reporting",
        call_id="call-1",
        arguments={"quarter": "Q4"},
        labels={
            ("db", "reports.q4"): {"owner": "finance"},
            ("secret", "reporting_api_key"): {"owner": "platform"},
        },
    )

    assert [line.selector for line in grant.lines] == [
        "reports.q4",
        "reporting_api_key",
    ]


def test_resource_access_derives_call_but_resource_free_tool_requires_call() -> None:
    cedar = shutil.which("cedar")
    if cedar is None:
        pytest.skip("Cedar CLI is not installed")
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    owner = "permit(principal, action, resource);"
    operation_only = (
        'permit(principal, action == slangGraph::Action::"db::select", resource);'
    )
    grant = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": owner}, operation_only),
        executable=cedar,
    ).authorize(
        principal_id="alice",
        roles=(),
        tool_name="run_report",
        tool_owner="reporting",
        call_id="call-1",
        arguments={"quarter": "Q4"},
    )

    assert [(line.class_name, line.operation) for line in grant.lines] == [
        ("db", "select")
    ]

    resource_free = parse_security_manifest(
        """
        class db {
          operations select
          object table
          normalizer sql.table_ref
          attrs schema
          enforced_by broker
        }
        tool status {
          runs inprocess
          returns normal
        }
        """
    )
    with pytest.raises(ObjectPolicyDenied, match="dac:envelope_call:status"):
        CedarObjectAuthorizer(
            resource_free,
            CedarPolicySet({"status": owner}, operation_only),
            executable=cedar,
        ).authorize(
            principal_id="alice",
            roles=(),
            tool_name="status",
            tool_owner="reporting",
            call_id="call-2",
            arguments={},
        )


def test_mac_removal_of_need_denies_and_want_is_removed(tmp_path: Path) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    authorizer = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet(
            {"run_report": permit},
            permit,
            mac_forbids=(
                "forbid(principal, action, resource)\n"
                'when { resource.owner == "blocked" };'
            ),
        ),
        executable=cedar,
    )

    grant = authorizer.authorize(
        principal_id="alice",
        roles={"analyst"},
        tool_name="run_report",
        tool_owner="reporting",
        call_id="call-1",
        arguments={"quarter": "Q4"},
        labels={
            ("db", "reports.q4"): {"owner": "finance"},
            ("secret", "reporting_api_key"): {"owner": "blocked"},
        },
    )
    assert [line.class_name for line in grant.lines] == ["db"]

    with pytest.raises(ObjectPolicyDenied, match="mac:forbid:run_report:0"):
        authorizer.authorize(
            principal_id="alice",
            roles={"analyst"},
            tool_name="run_report",
            tool_owner="reporting",
            call_id="call-2",
            arguments={"quarter": "Q4"},
            labels={
                ("db", "reports.q4"): {"owner": "blocked"},
                ("secret", "reporting_api_key"): {"owner": "platform"},
            },
        )


def test_object_policy_executor_is_used_by_tool_node(tmp_path: Path) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    authorizer = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=cedar,
    )
    dispatcher = _Dispatcher()
    executor = ObjectPolicyHostExecutor(
        authorizer,
        dispatcher,
        tool_owners={"run_report": "reporting"},
        labels=lambda _principal, _call: {
            ("db", "reports.q4"): {"owner": "finance"},
            ("secret", "reporting_api_key"): {"owner": "platform"},
        },
    )
    security = SecurityConfig(host_executor=executor)

    @tool
    def run_report(quarter: str) -> str:
        """Schema stub whose in-process body must never run."""
        raise AssertionError("untrusted tool body ran in the coordinator")

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([run_report]))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    config = with_principal({}, principal, modules=security.modules)
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "run_report",
                            "args": {"quarter": "Q4"},
                            "id": "call-1",
                        }
                    ],
                )
            ]
        },
        config=config,
    )

    response = result["messages"][-1]
    assert response.status == "success", response.content
    assert response.content == "brokered report"
    assert dispatcher.grants[0].tool_name == "run_report"


def test_cedar_security_runs_an_ordinary_toolnode(tmp_path: Path) -> None:
    cedar = _fake_cedar(tmp_path)

    @tool
    @effects(Effect.READ, sensitivity="normal")
    def greet(name: str) -> str:
        """Return a greeting."""
        return f"Hello, {name}!"

    security = cedar_security(
        greet,
        manifest="""
        runs inprocess
        returns normal
        """,
        policy="permit(principal, action, resource);",
        executable=cedar,
    )

    assert isinstance(security.host_executor, ObjectPolicyHostExecutor)
    assert set(security.host_executor.authorizer.manifest.tools) == {"greet"}

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([greet]))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    principal = Principal("alice", frozenset(), frozenset(), "session")
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "greet",
                            "args": {"name": "Alice"},
                            "id": "call-1",
                        }
                    ],
                )
            ]
        },
        config=with_principal({}, principal, modules=security.modules),
    )

    assert result["messages"][-1].content == "Hello, Alice!"


def test_cedar_security_derives_and_enforces_trusted_resource_grant(
    tmp_path: Path,
) -> None:
    cedar = _fake_cedar(tmp_path)
    document = tmp_path / "report.txt"
    document.write_text("quarterly report", encoding="utf-8")

    @tool
    @effects(
        Effect.READ,
        resources=[ResourceArg("path", "path", "realpath")],
        sensitivity="sensitive",
    )
    def read_file(path: str) -> str:
        """Read one file."""
        return read_text(path)

    security = cedar_security(
        read_file,
        manifest="""
        runs inprocess
        fs read @{path} need
        returns sensitive
        """,
        policy="permit(principal, action, resource);",
        executable=cedar,
    )

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([read_file]))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    principal = Principal("alice", frozenset(), frozenset(), "session")
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "read_file",
                            "args": {"path": str(document)},
                            "id": "call-1",
                        }
                    ],
                )
            ]
        },
        config=with_principal({}, principal, modules=security.modules),
    )

    assert result["messages"][-1].content == "quarterly report"
    assert isinstance(security.host_executor, ObjectPolicyHostExecutor)
    grant = security.host_executor.authorization_grants()[-1]
    assert [
        (line.class_name, line.operation, line.selector) for line in grant.lines
    ] == [("fs", "read", str(document.resolve()))]
    owner_policy = security.host_executor.authorizer.policies.owner_permits["read_file"]
    assert 'action == slangGraph::Action::"fs::read"' in owner_policy


def test_cedar_security_rejects_non_sandbox_resource_enforcer() -> None:
    @tool
    def read_record(record_id: str) -> str:
        """Read one record."""
        return record_id

    with pytest.raises(ValueError, match="must use enforced_by language_sandbox"):
        cedar_security(
            read_record,
            classes="""
            class record {
              operations read
              object item
              normalizer identity
              attrs
              enforced_by broker
            }
            """,
            manifest="record read @{record_id} need",
            policy="permit(principal, action, resource);",
        )


def test_cedar_security_accepts_unused_custom_class_permission() -> None:
    @tool
    def read_record(record_id: str) -> str:
        """Read one record."""
        return record_id

    security = cedar_security(
        read_record,
        classes="""
    class record {
      operations read
      object item
      normalizer identity
      attrs owner
      enforced_by language_sandbox
    }
    """,
        manifest="record read @{record_id} need",
        policy="permit(principal, action, resource);",
    )
    report = security.host_executor.dispatcher.admission.reports[0]
    assert report["inferred_subset_of_manifest"] is True
    assert report["inferred"] == []
    assert report["unused_rules"] == [0]


def test_cedar_security_requires_a_tool_object() -> None:
    with pytest.raises(TypeError, match="@tool-decorated BaseTool"):
        cedar_security(  # type: ignore[arg-type]
            "greet",
            policy="permit(principal, action, resource);",
        )


def test_cedar_security_manifest_body_must_not_repeat_the_tool_block() -> None:
    @tool
    def greet(name: str) -> str:
        """Return a greeting."""
        return f"Hello, {name}!"

    with pytest.raises(ProfileSyntaxError):
        cedar_security(
            greet,
            manifest="tool greet { runs inprocess }",
            policy="permit(principal, action, resource);",
        )


def test_object_policy_executor_rejects_incomplete_enforcement_receipt(
    tmp_path: Path,
) -> None:
    cedar = _fake_cedar(tmp_path)
    manifest = parse_security_manifest(
        MANIFEST,
        enforcers={EnforcementKind.BROKER: _Broker()},
    )
    permit = "permit(principal, action, resource);"
    authorizer = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"run_report": permit}, permit),
        executable=cedar,
    )
    dispatcher = _IncompleteDispatcher()
    executor = ObjectPolicyHostExecutor(
        authorizer,
        dispatcher,
        tool_owners={"run_report": "reporting"},
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")

    call = ToolCall(
        tool=Tool(
            "run_report",
            ToolDac("reporting", {"alice": "x"}),
            frozenset(),
            (),
        ),
        args={"quarter": "Q4"},
        normalized={},
        call_id="call-1",
        call_index=0,
    )
    with pytest.raises(
        HostExecutionError,
        match="object_policy:incomplete_line_enforcement",
    ):
        executor.invoke(principal, call, ())


def _receipt(
    grant_digest: str,
    line_ids: tuple[str, ...] = ("run_report:0", "run_report:1"),
) -> ActivationReceipt:
    return ActivationReceipt(
        grant_digest=grant_digest,
        plan_digest="plan",
        host_digest="host",
        context_digest="context",
        nonce="nonce",
        mode=EnforcementMode.ENFORCED,
        evidence=(),
        activated_obligations=frozenset(),
        valid_until=time.time() + 60,
        rule_enforcement=tuple(
            RuleEnforcement(line_id, SupportLevel.EXACT, "test-broker")
            for line_id in line_ids
        ),
    )


def _fake_cedar(tmp_path: Path) -> Path:
    executable = tmp_path / "cedar"
    executable.write_text(
        """#!/usr/bin/env python3
import json
import pathlib
import sys

command = sys.argv[1]
if command == "validate":
    raise SystemExit(0)
policy = pathlib.Path(sys.argv[sys.argv.index("--policies") + 1]).read_text()
entities = json.loads(
    pathlib.Path(sys.argv[sys.argv.index("--entities") + 1]).read_text()
)
request = json.loads(
    pathlib.Path(sys.argv[sys.argv.index("--request-json") + 1]).read_text()
)
resource = request["resource"]
resource_id = (
    resource["id"]
    if isinstance(resource, dict)
    else resource.rsplit('::"', 1)[1][:-1]
)
resource = next(item for item in entities if item["uid"]["id"] == resource_id)
attrs = resource["attrs"]
denied = (
    ('resource.schema == "private"' in policy and attrs.get("schema") == "private")
    or ('resource.owner == "blocked"' in policy and attrs.get("owner") == "blocked")
)
print("DENY" if denied else "ALLOW")
raise SystemExit(1 if denied else 0)
""",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable
