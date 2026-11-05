# Implementing a resource mediator

Implement reusable mediators in this directory, or application-specific mediators
in your application's package. Registration is explicit; importing this package
does not discover plugins or open resources.

| File | Purpose |
| --- | --- |
| `contracts.py` | Typed interfaces, generated clients, inference models, and binding |
| `objects.py` | Object references and grant-scoped in-process dispatch |
| `records.py` | Shared record API and client |
| `sqlite.py` | Built-in SQLite record implementation |
| `randomness.py` | Bounded booking values backed by Python `secrets` |
| `retrieval.py` | Bounded scikit-learn and LangChain text retrieval |
| `readonly_sqlite.py` | Read-only SQLite metadata and query operations |
| `airline_sqlite.py` | Principal-bound ACE airline reads and ticket mutations |
| `template.py` | Empty object-bound tutorial; denies all authority until implemented |

The complete application example is [demo 08](../../../../../../workspace/08_custom_mediator/README.md).
Demo 06 uses the existing SQLite mediator; demo 08 extends the framework with a
new counter mediator.

## Supported library contracts

| Integration | Typed operations | Cedar resource/action | Resource identity and validation | Routes and host requirements |
| --- | --- | --- | --- | --- |
| SQLite records | `read(record: str) -> RecordRead`, `write(record: str, value: str) -> RecordMutation`, `delete(record: str) -> RecordMutation` | `db_record` with `read`, `write`, or `delete`; `record` is the selector | `<database_id>/<key>`; both components are bounded ASCII names, values are at most 8192 UTF-8 bytes, and the schema is exactly `records(key TEXT PRIMARY KEY, value TEXT NOT NULL)` | Language: exact because the admitted interpreter has no filesystem, module, or connection values. Broker: Python 3.11+, `broker:spawn-bound`, `seccomp:minimal`, and custody of the database directory. |
| Random booking values | `appointment_time() -> str`, `booking_reference() -> str` | one opaque `random_source` resource with the matching action | The setup-bound generator is the resource. Results are fixed-shape strings; no generator object or state is returned. | Language and broker; Python 3.11+ `secrets`; no extra host capability. |
| Text retrieval/search | `search(query: str) -> str` | one opaque `text_index` resource with action `search` | The setup-bound index/retriever is the resource. Queries are at most 4096 UTF-8 bytes and results at most 65536 bytes. `sklearn_json_search_resource` emits a JSON array containing only registered URLs and content. | Language and broker. The scikit-learn factories assume the compatible `TfidfVectorizer` API (tested with 1.x). The LangChain factory assumes synchronous `invoke(str)` returning documents with string `page_content`. Network and credential availability remain coordinator deployment requirements. |
| Read-only SQLite | `list_tables() -> str`, `schema(table_names: str) -> str`, `query(query: str) -> str` | one opaque `readonly_sqlite` database resource with the corresponding action | The setup-bound database is the resource. Table names are validated, queries are one `SELECT`/`WITH` statement, results are capped at 1000 rows and 262144 UTF-8 bytes. | Language and broker; Python 3.11+ `sqlite3`. Connections use read-only and query-only modes. No connection, path, or backend object is returned. |
| Airline SQLite | `fetch_user() -> str`, `search_flights(...) -> str`, `update_ticket(ticket_no: str, new_flight_id: int) -> str`, `cancel_ticket(ticket_no: str) -> str` | one opaque `airline_sqlite` database resource with the corresponding action | Trusted setup binds the database, passenger, principal, and policy clock. Every request rechecks the invocation principal; mutations use parameterized SQL and ownership predicates. | Language and broker; the ACE airline SQLite schema and Python 3.11+ `sqlite3`. Database paths, connections, and passenger bindings stay in trusted setup. |

All integrations return only validated inert data. SQLite connections, random-library
state, vectorizers, LangChain retrievers, credentials, and backend instances
remain in trusted setup or mediator code. The framework checks the effective
invocation grant immediately before every call; an import alias locates an
interface and never adds an operation or resource to that grant.

Library and mediator implementations are trusted to meet these contracts. The
Lean language-route theorem proves that accepted effect traces name registered
terminals; it does **not** inspect or verify the Python, SQLite, scikit-learn, or
LangChain implementation source.

## One resource object, one binding

Define a typed interface with required scalar arguments and scalar, union, or
fixed `TypedDict` results. Interfaces directly extend `ABC`, have empty slots,
and contain only abstract methods. Defaults, variadic arguments, arbitrary
objects, reflection, and dynamic method selection are unsupported.

Typed payloads require native string keys before copying or lookup. Broker
handoffs use a validated immutable argument record; an arbitrary mapping proxy
does not establish that its backing mapping is safe. Fixed `TypedDict` results
are checked through a native item snapshot before key equality or field lookup.
Backend registration and its annotations remain operator-controlled setup.

```python
class CounterAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def increment(self, amount: int) -> int:
        raise NotImplementedError


COUNTER = ResourceContract(
    CounterAPI,
    class_name="counter",
    object_kind="counter",
    lowering="counter.local.v1",
)
counter = COUNTER.client(export="my_app.api.counter")
```

Omitting `resource_parameter` selects object-bound operation. The framework
allocates an opaque identity; callers use `counter.increment(2)`, without a
resource name or ID argument. The parent binds that object:

```python
resource = COUNTER.bind(
    implementation=CounterBackend(),
    mediator=CounterMediator(),
)
```

`.bind(...)` creates a binding preserving the definition's identity and existing
clients. For a different resource, construct a different `ResourceContract`.
The combined constructor form is also supported:

```python
resource = ResourceContract(
    CounterAPI,
    class_name="counter",
    object_kind="counter",
    lowering="counter.local.v1",
    implementation=CounterBackend(),
    mediator=CounterMediator(),
)
```

The framework rejects duplicate object identities and the same implementation
object registered under multiple identities in one resource list. It cannot
detect whether two distinct backend wrappers refer to the same external database
or device; trusted setup must choose canonical bindings for shared resources.
Each binding owns its adapter. Generated clients retain only the definition,
never the implementation, custom mediator, or lifecycle hooks.

## Registration and permissions

For an OS-sandboxed tool:

```python
dispatcher = ObjectBrokerDispatcher(
    worker_specs,
    runtime_roots=runtime_roots,
    resources=(resource,),
)
security = cedar_security(
    tool,
    dispatcher=dispatcher,
    manifest="runs linux\n" + resource.permission("increment"),
    policy=policy,
)
```

Broker decision logging is disabled by default and is not part of enforcement.
Pass `record_audit=True` when an application needs the bounded, in-memory records
returned by `dispatcher.audit_records()`. The dispatcher still validates the
effective invocation grant and the mediator contract on every call when logging
is disabled.

`cedar_security` derives the class declarations from these bindings. Multiple
objects can share a compatible class and lowering contract. The manifest helper
emits access to the exact object; do not persist or hand-author its opaque ID.
IDs are generated during setup, not stable names across application restarts.
Register the shared generated clients before constructing the dispatcher. Worker
imports recreate their API definitions, but the broker resolves their registered
export aliases to the parent's identity before checking the grant. An export
alias is a locator, not authority.

For a source-admitted language-sandbox tool:

```python
security = cedar_security(
    tool,
    resources=(resource,),
    manifest="runs inprocess\n" + resource.permission("increment"),
    policy=policy,
)
```

Tool inputs and defaults may use exact inert scalar values (`str`, `int`,
`float`, and `bool`); typed resource calls may use scalar literals. Mandatory admission
infers the exact object and operation from the registered client. It checks `inferred ⊆ manifest` and that effects use approved operations.
Unused manifest permissions remain valid. Methods with no arguments are checked
too. Runtime dispatch still checks the effective DAC/MAC grant for every call;
removing an optional permission does not leave a usable client capability.

Registered imports are resolved while preparing admission. For example, this
tool never receives a Python module object; `db` is lowered directly to the
registered `RecordsAPI.read` terminal:

```python
def read_note(record: str) -> dict:
    from langgraph.prebuilt.security.mediators.records import records as db

    return db.read(record)
```

Minimal SQLite setup:

```python
resource = sqlite_records_resource("/srv/private/records.sqlite", database_id="notes")
security = cedar_security(
    tool,
    resources=(resource,),
    manifest="runs inprocess\ndb_record read @{record} need",
    policy=caller_policy,
)
```

Only imports that resolve to a registered export are accepted. Method aliases
and module aliases preserve the same fixed interface. Arbitrary imports,
unregistered members, dynamic attribute selection, callbacks, and traversal to
the client or backend object remain unavailable. Candidate imports are not
executed during preparation.

In-process bindings require `EXACT` support with no OS capability or protected-path
requirements. Unsupported retained permissions fail closed, including `want`
permissions; this path does not perform the OS negotiator's optional-authority
pruning. Its host description explicitly represents language-sandbox execution in the coordinator,
not OS isolation. The counter demo requires broker/seccomp protection and therefore
uses the OS path. Do not claim those protections for an in-process backend.

Module loading, setup, backend implementations, and mediator callbacks remain
trusted code. Source verification of tool bodies is not a proof of arbitrary
Python module initialization or the entire interpreter. Load untrusted modules
only behind an appropriate boundary.

## What the mediator implements

```python
class CounterMediator:
    def assess(self, line, host):
        # Framework has already matched this resource, operation and contract.
        return ResourceSupport(
            SupportLevel.EXACT,
            "bounded operations on the parent-owned counter",
            witness="tests/test_counter.py",
            required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
        )

    def validate(self, operation, arguments, context):
        if not 1 <= arguments["amount"] <= 3:
            raise ValueError("amount must be 1, 2, or 3")
```

`assess(line, host)` is a **policy-lowering hook**: describe how the backend can
enforce the abstract permission and what host protection it needs. It is not
DAC/MAC authorization, resource naming, allocation, or per-request validation.
For object-bound contracts the framework checks the exact identity before calling
it. Assessments must be repeatable and must not perform the requested operation.

Supported results require a conformance-test witness. Declare protected paths
and required host capabilities accurately. The OS negotiator rejects unsupported
required permissions and removes unsupported optional ones. It checks host
requirements and rechecks support before activation and during invocation.

`validate(operation, arguments, context)` receives immutable, type-checked
arguments after exact-grant authorization. Return `None` to permit the backend
call, or raise to reject it. It cannot rewrite arguments or skip authorization.
Other return values reject the request. The backend implements the interface to
perform the bounded operation; inheritance here checks signatures, not trust.

A custom mediator is optional. Supply `assess=` without `mediator=` to omit extra
application validation while retaining grant and type checks. Supplying both an
assessment callback and a mediator is rejected: the mediator owns its assessment.

Optional `activate(lines, context)` and `release(context)` hooks establish and
clean up invocation-specific resources. Roll back partial activation. Do not
close resources shared with other invocations. `current_invocation()` supplies
authenticated principal, session, tool, call, grant, and worker context inside a
backend method. Payloads cannot inject that context or choose a different object.

## OS tools without a language sandbox

Object binding also works without static admission. The OS sandbox confines the
tool, and the authenticated broker enforces each operation. `resource.reference`
is an immutable `ResourceReference` containing an opaque `.service` address.
Trusted setup can pass it as inert configuration to the worker. Python callers
can use `reference.request(operation, payload)`; other languages use the same
newline-delimited JSON protocol on inherited `SLANGGRAPH_BROKER_FD`:

```text
{"service": "<reference.service>", "operation": "increment", "payload": {"amount": 2}}
```

The response is `{"status":"ok","result":...}` or a denial. The broker binds
requests to the spawned invocation and checks the exact object and operation in
its effective grant. Knowing or forging an address, or substituting another
object's address, does not confer permission. The existing launcher loads Python
entry points; this protocol description does not add a native executable launcher.

## Existing selector-based services

SQLite intentionally exposes a service containing many records. Its shared
`RecordsAPI.read(record)`, `write(record, value)`, and `delete(record)` continue to
use `resource_parameter="record"`. The supplied selector is checked against the
grant and injected into the backend by typed dispatch. It cannot be replaced in
the payload. Selector-specific support remains the service mediator's responsibility.

Use `sqlite_records_resource(...)` for either language or broker registration.
The language route relies on interpreter confinement and keeps every connection
in trusted mediator code. It must not be described as OS confinement.

Existing `bind_backend` and `ResourceMediatorAdapter` APIs, plus
`ObjectBrokerDispatcher(mediators=...)`, remain supported for these services.
They require explicit class declarations and manifest selectors. The compatibility
import `security.sqlite_record_mediator` still points to `mediators/sqlite.py`.

## Start with the empty template

Copy `template.py`, rename its interface, definition, client, implementation, and
factory, then implement bounded operations and the mediator's support/validation
hooks. Keep credentials and implementation construction in trusted parent setup.

```python
resource = example_resource()
# Register resources=(resource,) and declare resource.permission("read").
# Worker-facing API after implementation:
value = example.read()
```

As shipped, assessment returns `UNSUPPORTED`, and activation/validation/operation
stubs raise. Changing the assessment to `EXACT` alone does not implement an
enforcer. Tests must establish its semantics and bypass prevention first.

Test allowed operations, incorrect objects and operations, malformed payloads,
missing host capabilities, lifecycle cleanup, and direct-access bypass attempts.
`test_object_resources.py` covers object identity, static admission, sync/async
in-process grants, and raw OS broker requests. `test_sqlite_mediator.py` covers
the selector-based database service. A witness string or source availability is
not proof of arbitrary mediator code: implementations and their custody claims
remain part of the trusted computing base.

When adding or upgrading an integration, review the upstream library version and
behavior, update the typed interface and lowering identifier for semantic
changes, validate every returned field before it crosses the boundary, and rerun
the allowed/denied resource, import-alias, lifecycle, proof-drift, and direct
backend-access regressions. Never retain an old lowering name when an upstream
change widens effects or result semantics.
