# Open object classes

For the exhaustive syntax, directive, normalization, Cedar-mapping, and
validation reference, see [security manifest language](manifests.md). This page
focuses on the architecture and Python wiring.

For a tool that only needs call authorization and does not access a protected
resource, use the high-level helper:

```python
security = cedar_security(
    greet,
    manifest="""
        runs inprocess
        returns normal
    """,
    policy=caller_policy,
)
```

The helper derives the internal tool identity from `greet.name`; neither the
manifest body nor the Cedar policy needs to repeat it. It also generates the
tool-owner ceiling internally. A resource-free tool needs no host dispatcher,
receipt, class, or normalizer.

The same helper accepts resource operations for source-admitted language-sandbox
tools:

```python
security = cedar_security(
    read_file,
    manifest="""
        runs inprocess
        fs read @{path} need
        returns sensitive
    """,
    policy=caller_and_resource_policy,
)
```

`fs read` is built into `cedar_security`; ordinary users do not declare it.
The helper supplies its `FsPath` Cedar entity, `fs.realpath` normalizer, and
language-sandbox enforcement binding.

The helper expands and normalizes the invocation, evaluates every operation in
Cedar, constructs an exact `ObjectGrant`, canonicalizes descriptor-declared
resource arguments before dispatch, and records enforcement evidence. Call
`security.host_executor.authorization_grants()` to review the issued grants.
Call `security.host_executor.authorizer.authorization_artifacts()` to locate
the retained Cedar schema, entity set, policies, and requests for each decision.
Only classes declared with `enforced_by language_sandbox` use this convenience path;
other enforcement loci require an explicit dispatcher.

### Isolated tools

Pass `ObjectBrokerDispatcher` to the same helper for a separate Linux worker.
The registered `BaseTool` supplies the schema; its body is never executed. The
dispatcher selects a pinned implementation artifact, activates Landlock,
seccomp, limits, and a cleared environment before import, and exposes only a
channel bound to the invocation for brokered resource operations.

```python
import hashlib
from pathlib import Path

from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ResourceMediatorAdapter,
    ResourceSupport,
    SupportLevel,
    EnforcementKind,
    cedar_security,
)

artifact = Path("/opt/report-worker/report_worker.py").resolve(strict=True)

def assess_record(line, host):
    if (line.class_name != "record" or line.operation != "read"
        or line.enforcer is not EnforcementKind.BROKER
        or line.lowering != "database.record.v1" or line.attributes
        or not database.is_canonical_record_id(line.selector)):
        return ResourceSupport(SupportLevel.UNSUPPORTED, "unsupported record semantics")
    return ResourceSupport(
        SupportLevel.EXACT, "read one canonical record by ID",
        witness="operator-reviewed-record-adapter-v1",
        protected_paths=("/run/secrets/database-token",),
        required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
    )

def read_record(line, payload, context):
    if payload:
        raise ValueError("read_record takes no payload")
    # This client and its credentials stay in the coordinator. The selector
    # comes from the authorized grant, never a resource name in the payload.
    return database.read_record(line.selector)

dispatcher = ObjectBrokerDispatcher(
    {report_tool.name: LinuxToolSpec(
        "report_worker:run", artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()
    )},
    mediators=(ResourceMediatorAdapter("database.record.v1", assess_record, read_record),),
    runtime_roots=("/opt/report-worker", "/opt/report-dependencies"),
)
security = cedar_security(
    report_tool,
    dispatcher=dispatcher,
    manifest="""
        runs linux
        fs read @{path} need
        record read @{record_id} need
    """,
    classes="""
        class record {
          operations read
          object item
          normalizer identity
          attrs
          enforced_by broker
          lowering database.record.v1
        }
    """,
    policy=caller_and_resource_policy,
)
```

The worker implementation can use ordinary `open(path)` for its kernel-granted
file and `object_request("record", "read", record_id)` for its brokered record.
Use `security` with `ToolNode` or `StateGraph.compile` as above. The manifest and
argument inspection run before dispatch. Broker requests are checked against
the surviving grant on every operation; changing the object, operation, or
claimed identity cannot expand it. Unsupported classes and enforcement waivers
deny execution, with no in-process fallback.

The helper's isolated `fs` class supports `read`, `write`, and `truncate` of
existing regular files. Directory selectors are rejected rather than expanded
into recursive authority. Canonical paths are opened without symlink traversal
at lowering; rules are attached to those kernel objects. This is live file
access, not a content snapshot. The tool's primary source is separately copied
from verified bytes before launch to prevent artifact-path replacement.

Runtime authority is additional, explicit operator configuration: the Python
runtime, `/usr`, tool code, dependency roots, a private temporary directory, and
protocol descriptors are available. Runtime roots must contain only code and
public runtime data, never secrets or broker-protected resources. Dependency
contents are not pinned by the primary artifact digest. Landlock confines file
content access; it does not hide all filesystem metadata. Direct sockets,
process creation, executable replacement, and ptrace are blocked by seccomp.

The dispatcher negotiates an obligation graph before import: host confinement,
a channel bound to this invocation, credential custody, bypass prevention, and
the semantic operation each need an owner. A missing required capability denies
execution. Unsupported `want` lines are removed, including their broker routes;
`receipt.removed_wants` and `dispatcher.lowering_records()` expose the reduction.
Ambiguous adapter ownership denies execution.

`ResourceMediatorAdapter(assess=..., invoke=..., preflight=..., activate=..., release=...)`
is the extension point for resources the host cannot interpret. `assess`
receives the complete canonical line and host attestation and returns
`ResourceSupport` with `EXACT`, useful `STRICTER`, or `UNSUPPORTED`.
It must recognize the selector, attributes, operation, and lowering strategy.
Supported assessments require a `witness` reference to an operator-reviewed
contract or conformance tests; this is not an automatically verified proof.
Declare all protected credential/data paths and required host capabilities.
The host rejects declared paths overlapping runtime or file grants. Operators
must also exclude aliases/hardlinks and undeclared resource access from readable
code roots; a pathname declaration does not discover them automatically.

`preflight` can prepare immutable or invocation-local state before activation;
`activate` can establish resource-side authority before tool import; `release`
tears it down after worker and broker activity stops. `invoke` receives a
parent-authenticated `ResourceInvocation` and untrusted JSON payload.
Support is rechecked before activation and each request. Bare handler maps are
rejected because callback existence does not establish enforceability.
The executable backend currently requires Linux Landlock ABI 5+; portable
negotiation contracts do not imply executors exist for every OS.

Custom mediators remain trusted reference monitors. They must validate payload
fields, use the supplied selector and operation, bound external I/O, and avoid
background work. A handler's arbitrary Python semantics cannot be inferred from
SLP. Terminating the worker does not undo a broker operation already in flight;
an unfinished handler produces an indeterminate outcome. Cancellation waits for
worker cleanup instead of abandoning a running invocation. Requests and results
are JSON-only and frame-limited; injected coordinator objects require explicit
broker interfaces. Permissions do not impose invocation counts or rate limits.

### SQLite record mediator

Reusable resource backends live in
[`security/mediators/`](../../libs/prebuilt/langgraph/prebuilt/security/mediators/README.md).
The SQLite implementation is `mediators/sqlite.py`. For a new backend, copy
`mediators/template.py` and follow the directory's developer guide. The template
is deliberately unimplemented and reports `UNSUPPORTED`; registration alone
does not establish enforcement.

`sqlite_record_mediator(path, database_id="notes")` is a concrete database
adapter. Register its return value in `ObjectBrokerDispatcher(mediators=...)`.
Workers import `records` from `security.mediators.records` and call its typed
`read(record)`, `write(record, value)`, and `delete(record)` methods. `RecordsAPI`
defines the shared interface; `RECORDS.class_declaration()` generates the class
below, and `RECORDS.bind_backend` validates and dispatches the implementation.
The manifest checker recognizes the registered client and its effect mappings.
It requires Python 3.11+ and the isolated Linux backend's normal prerequisites.
Create the database yourself, in a dedicated directory outside all readable
runtime roots, using the exported `SQLITE_RECORD_SCHEMA`:

```sql
CREATE TABLE records (key TEXT PRIMARY KEY, value TEXT NOT NULL)
```

Declare the resource class and select operations through a closed manifest map:

```text
class db_record {
  operations read write delete
  object record
  normalizer identity
  attrs
  enforced_by broker
  lowering sqlite.record.v1
}
tool manage_record {
  runs linux
  map operation=read   db_record read   @{record} need
  map operation=write  db_record write  @{record} need
  map operation=delete db_record delete @{record} need
}
```

A selector such as `notes/alice` identifies one key in the configured database.
Both database IDs and keys accept 1–128 ASCII letters, digits, underscores, or
hyphens. `read` accepts no payload and returns `{"found": true, "value": "..."}`
or `{"found": false, "value": null}`. `write` accepts only `{"value": "..."}`
and inserts or replaces that key's value; `delete` accepts no payload. Writes
and deletes return `{"ok": true}` without exposing the old value or whether
the key existed. Values are UTF-8 text limited to 8192 bytes.

The worker cannot supply SQL, table names, predicates, or connection options.
Fixed parameterized statements determine the row; SQLite's authorizer adds a
statement-level allowlist. The exact schema and absence of record triggers
are checked at activation and again inside each operation's transaction.
Unsupported views, virtual tables, generated columns, and trigger side effects
fail closed. This adapter does not provide arbitrary SQL or adapt an existing
application schema automatically.

Connections exist only in parent callbacks. The protected resource is the
entire database directory, covering the database, rollback journal, WAL, and
shared-memory files. The host refuses overlapping file/runtime grants.
Operators must exclude readable aliases/hardlinks and keep code roots separate.
SQLite lock waits use `timeout_s` (default one second); query work also has a
deadline and instruction budget. These bounds do not promise cancellation of
an operating-system I/O stall or reversal of an already committed transaction.

Run [the database example](../../workspace/06_database/demo.py) to exercise
real Cedar permissions through a ToolNode: Alice may manage her record, Bob
may only read his, and cross-record requests are denied. The untrusted
[worker](../../workspace/06_database/worker.py) receives only record selectors.

### Language-sandbox resources

The effective permission of language-sandbox execution is the
intersection of slangGraph authorization and the coordinator's existing host
permission. A host allow does not grant an operation denied by slangGraph, and
a slangGraph allow does not overcome a host denial. The tool runs under the
coordinator's host identity. The interpreter and mediated terminals enforce the
slangGraph side of the intersection; the tool body is not trusted to honor it.
This is not a per-call kernel sandbox. The operating system independently enforces
the host side of the intersection.

The object-policy API lets a tool plugin add resources such as database tables,
secrets, queues, browser origins, or store keys without changing the `.slp`
grammar. A class declares its operations, canonicalizer, Cedar attributes, and
enforcement locus. A tool manifest then enumerates the objects it needs or
wants.

For a language-sandbox tool, a power user can add a class directly through
the same helper:

```python
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
    policy=caller_and_record_policy,
    labels=trusted_record_labels,
)
```

Plugins may instead construct `ObjectClass` values and pass them through the
`classes=` keyword of `parse_security_manifest`. Textual and programmatic class
declarations receive the same duplicate-name, normalizer, operation, schema,
and enforcement validation.

```slp
class db {
  operations  select insert update delete ddl
  object      table
  normalizer  sql.table_ref
  attrs       owner schema
  enforced_by broker
  lowering    postgres.role_grant
}

class secret {
  operations  read
  object      item
  normalizer  identity
  attrs       owner
  enforced_by broker
}

tool run_report {
  runs    broker
  db      select reports.@{quarter} need
  secret  read reporting_api_key    want
  returns sensitive
}
```

Parse this with `parse_security_manifest`. The registry generates a Cedar schema
containing `Action::"db::select"`, `Action::"secret::read"`, and entity types
whose attributes come from the class declarations.

```python
from langgraph.prebuilt.security import (
    CedarObjectAuthorizer,
    CedarPolicySet,
    EnforcementKind,
    ObjectPolicyHostExecutor,
    SecurityConfig,
    parse_security_manifest,
)

manifest = parse_security_manifest(
    text,
    normalizers={"my.normalizer": normalize_object},
    enforcers={EnforcementKind.BROKER: broker_enforcer},
)
policies = CedarPolicySet(
    owner_permits={"run_report": owner_cedar},
    principal_permits=principal_cedar,
    share_permits=shares_cedar,
    mac_forbids=operator_forbids_cedar,
)
authorizer = CedarObjectAuthorizer(
    manifest,
    policies,
    executable="cedar",
    enforcement_waivers={},
)
executor = ObjectPolicyHostExecutor(
    authorizer,
    dispatcher,
    tool_owners={"run_report": "reporting"},
    labels=trusted_labels,
)
security = SecurityConfig(host_executor=executor)
```

Pass `security` to `ToolNode` or `StateGraph.compile`. The executor replaces the
legacy descriptor DAC for that ToolNode. The generated owner ceiling must
permit the bound tool call, while caller eligibility is derived from the
principal/share policy's access to the manifest-derived resource lines. A
resource-free manifest still requires an explicit caller-side `call` permit.
MAC can only remove lines. Removing a `need` line denies the call; removing a
`want` line omits it from the grant, and a resource-bearing call with no
surviving lines is denied.

Normalizers and label providers are trusted code. Policy sees only their
canonical selector and declared attributes, never the raw argument. The built-in
normalizers are `identity`, `fs.realpath`, `sql.table_ref`, and `mail.domain`. A
normalizer may only return attributes listed by its class.

The dispatcher is also trusted. It receives the finite `ObjectGrant`, activates
the declared kernel, broker, resource-side, or framework controls, and returns
an `ActivationReceipt`. Each surviving line must have exactly one
`RuleEnforcement` entry marked `exact` or `tightened`; missing, duplicate,
additional, or digest-mismatched evidence makes the result indeterminate.
ToolNode configuration fails when a manifest class lacks an enforcer for its
declared locus. An operator may explicitly waive a class with a non-empty reason
through `enforcement_waivers`; every affected line is then bound into the grant
digest, must be reported as `unsupported`, and requires a `degraded` receipt.

The policy partitions are intentionally monotone:

- owner, principal, and share policy sets may contain only Cedar `permit`
  policies;
- the MAC policy set may contain only Cedar `forbid` policies;
- the owner and principal/share sides must both allow each line;
- class operations absent from the declaration fail manifest parsing;
- Cedar validation or evaluation errors deny.

## Object-bound custom resources

For one concrete resource per binding, omit `resource_parameter` when constructing
`ResourceContract`. The framework owns its identity. A tool calls, for example,
`counter.increment(2)`; neither the backend nor mediator needs a `"jobs"` selector.
The bound mediator receives only requests for its own object after grant checks.

Register `resources=(resource,)` on `ObjectBrokerDispatcher` and declare access
with `resource.permission("increment")`. `cedar_security` derives compatible
class declarations from the registered objects. For admitted language-sandbox tools,
register resources directly on `cedar_security`. Multiple instances can share the
same class while retaining distinct identities and grants. Constructor binding
and deferred `.bind(...)` are both supported.

The [mediator guide](../../libs/prebuilt/langgraph/prebuilt/security/mediators/README.md)
explains registration, lowering, static inference, and the raw OS broker protocol.
[Demo 08](../../workspace/08_custom_mediator/README.md) shows the app-owned counter.
Selector-based services such as the built-in multi-record SQLite API remain
supported separately.
