# Static manifest consistency checks

## Supported verification contract

The static contract has two checks: **inferred ⊆ manifest** and
**inferred ⊆ allowed operations**. The manifest is a permission ceiling, not an
obligation to perform every declared operation. "Allowed operations" means the
framework-approved, monitored API vocabulary, not caller permissions. A manifest
cannot approve an arbitrary library. These checks cover the supported function
body, not module loading or the entire Python runtime (see
[Loading and trust boundary](#loading-and-trust-boundary)).

1. **Closed-world resource access.** Every call must resolve to an approved,
   monitored API. Unsupported Python and unresolved calls reject admission,
   including after a return or in a branch excluded by a closed selector map.
2. **Manifest coverage.** Let `I` overapproximate effects of admitted invocations
   and `M` be the active manifest. Every inferred effect must be covered: `I ⊆ M`.
   Unused declarations are valid. An inferred operation or resource outside the
   manifest is rejected before execution.

Let `A` be approved resource operations and `G` the grant after DAC, then MAC:

```text
static:   I ⊆ M and I ⊆ A
runtime:  successful resource effects ⊆ G, where G ⊆ M
```

A hardcoded return has `I = {}` and passes even with unused read permission.
A body that reads and writes fails a read-only manifest because the write is
outside `M`. A body reading both public and private resources must declare both;
otherwise admission fails. Adding `requests.get` or `os.execve` fails the approved
API check even if the author adds a corresponding manifest declaration.

Runtime checks remain necessary: concrete resource identities and caller grants
are dynamic. DAC or MAC may remove optional declared permission; the resource
monitor denies its use. Admission does not guarantee that code handles this
denial gracefully. [Demo 07](../../workspace/07_manifest_verification/demo.py) uses a real
`@tool` and automatic admission. Returning a constant passes with unused read
permission; restoring a read requires the manifest to cover its resource.
[Demo 7's companion examples](../../workspace/07_manifest_verification/bypasses.py)
reject direct library and reflection bypasses before execution.
[Demo 9](../../workspace/09_no_internet/demo.py) demonstrates MAC removing
optional authority or denying required authority. Resource names can remain
symbolic during static analysis.

Reflection and dynamic execution are **unsupported**, not features deferred to
runtime tracing: `getattr`, `globals`, `locals`, `vars`, `eval`, `exec`, dynamic
imports, arbitrary attribute access, native libraries, and indirect callbacks
do not enter the admitted language. Imports inside the function body are also
rejected. The framework does not infer “all effects” for unknown code and then
let a resource monitor discover its behavior at runtime.
Process execution such as `os.execve` and `subprocess.run`, and native-library
loading such as `ctypes.CDLL`, are not approved tool-body operations. They reject
admission even if the manifest otherwise matches, including in unreachable code.
The monitor implementations and their dependencies remain reviewed trusted code;
registering an API is not proof that its implementation cannot escape.

## Mandatory language-sandbox admission

`cedar_security` now requires this check for every in-process tool, including
tools with resource-free manifests. It reads the actual sync and async function
bodies, compares the retrieved source with the loaded bytecode, and rejects
`mismatch`, `unknown`, unavailable source, closures, wrappers, and custom tool
subclasses. There is no opt-out or caller-supplied passing report. Source hashes
and reports are retained on the in-process dispatcher's `admission.reports`.
Isolated `runs linux`/`runs broker` tools retain their host confinement path.

Only approved framework APIs are modeled during admission. The local file API is:

```python
from langgraph.prebuilt.security.language_sandbox import read_text, write_text

@tool
def read_document(path: str) -> str:
    """Read a granted UTF-8 file."""
    return read_text(path)
```

Declare `fs read @{path} need` in its manifest. `read_text` checks the current
invocation's surviving grant; an optional permission removed by MAC cannot be
used. Import this function directly at module scope (an alias is supported).
For an existing designated output, `write_text(path, value)` is modeled by
`fs write @{path} need`; it rejects symbolic and hard-link aliases and closes
the pinned write descriptor before the result is released.
Direct `open`, `Path.read_text`, arbitrary helpers, and unregistered resource
APIs are rejected. Source availability alone does not approve a helper or its
transitive libraries: without a reviewed terminal contract or complete supported
analysis, it is unknown. General helper expansion and more approved resource APIs
are future work. There is no automatic isolation fallback or verification bypass.

### Typed resource clients

Broker-backed resources use typed clients defined in `security.mediators`:

```python
from langgraph.prebuilt.security.mediators.records import records as db

def update_record(record: str, value: str):
    return db.write(record, value)
```

The registered `RecordsAPI` contract maps this method to `db_record::write` on
`record`. The same definition generates the client, SLP class declaration, and
backend signature/dispatch checks. The checker recognizes approved canonical
imports and aliases without importing candidate modules. For a live tool,
admission resolves actual registered client instances and pins their generated
methods; matching a variable or method name alone is insufficient.

Unknown methods, extra/missing/duplicate arguments, known argument-type
mismatches, reflection, and unregistered objects reject verification. A typed
argument with an unresolved type is unknown, never silently accepted. Inert
resource aliases and supported expressions still participate in effect inference,
and `inferred ⊆ manifest` remains the admission rule. The declared resource class
must agree with the client's lowering and enforcement contract (broker, or
language-sandbox enforcement for registered object-bound in-process resources).

Object-bound APIs omit the selector argument: `counter.increment(2)` infers the
identity of that registered counter object and the `increment` operation. Declare
it using `resource.permission("increment")`. `.bind(...)` preserves the identity;
a separately constructed contract represents a different object, even with the
same interface. A manifest granting one object does not cover another. The checker
also validates zero-argument methods. Runtime grants remain mandatory after
admission. See the [mediator guide](../../libs/prebuilt/langgraph/prebuilt/security/mediators/README.md).

Ordinary type checkers also see typed method signatures and return values.
Both constructor binding and `.bind(...)` check implementation methods against
that same interface. Optional custom mediation adds pre-effect validation without
changing generated client or inference mappings. This does not prove the backend's resource semantics: it remains
trusted code with conformance tests. Runtime validation and authorization remain
mandatory because worker requests, resource identities, and grants are dynamic.
These generated clients use the authenticated worker broker; they do not create
an in-process database connection. Raw `object_request` remains available to
isolated workers as a transport API, but is not an approved terminal in the
restricted typed source model.

Execution rechecks callable, bytecode, default-argument, and terminal bindings.
Arguments and defaults must be strings, as required by the checker's model.
The dispatcher lowers the admitted body to an immutable data program and
interprets it; it never invokes the original Python function or custom
`BaseTool` validators or callbacks through `tool.invoke`. Tool schemas remain
declarations for the surrounding framework, not executable admission evidence.
Resource-free tools also use the verified dispatcher, preventing substitution
of a different same-named tool body after authorization.

### Loading and trust boundary

The high-level API receives an **already-created** tool. It cannot prevent
effects that occurred during module initialization, import-time dependency code,
decorators, default-expression evaluation, or tool/schema construction. These
are operator-trusted setup, outside the function-body certificate. Do not import
an arbitrary untrusted tool module into the coordinator and treat a later passing
report as retroactive protection. A verified loader that checks the complete
module/dependency initialization before execution is not implemented here.

The interpreter, resource monitors, normalizers, and coordinator are enforcement
code. Binding checks reject stale callables; captured program and terminal code
also prevent a post-check mutation of the original tool or client function from
selecting a different executable body. Tool reflection and monkey-patching are
prohibited by the language. Hostile code already running in the coordinator can
still corrupt the enforcement implementation; it requires process isolation.
Filesystem replacement races are not covered. This is a restricted language
boundary, not arbitrary-Python confinement or a complete-system proof.
Legacy `SecurityConfig` without
Cedar manifests and custom host executors are not certified by this gate.
`CedarCallPolicy` alone is a low-level authorization policy, not verified tool
admission. Use `cedar_security` for the mandatory admission path.

## Standalone analysis

`check_manifest_consistency` compares a Python tool function's resource effects
with its `.slp` security manifest without importing or executing the source.
It infers modeled effects and checks that each has a matching class, operation,
and resource expression in an active manifest rule. Extra inferred effects are
rejected; unused manifest rules are allowed.

```python
from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    check_manifest_consistency,
)
from langgraph.prebuilt.security import parse_security_manifest

manifest = parse_security_manifest("""
class fs {
  operations read write
  object path
  normalizer identity
  attrs
  enforced_by language_sandbox
}
tool read_document {
  fs read @{path} need
}
""")
source = """
from document_store import read

def read_document(path):
    return read(path)
"""
report = check_manifest_consistency(
    source,
    manifest,
    tool_name="read_document",
    operations=(
        ManifestOperation("document_store.read", "fs", "read", "path"),
    ),
)
assert report["consistent"]
```

The operation model is an explicit, reviewed trust assumption: this API performs
only the named operation on the resource argument at `position` (default zero)
or keyword `parameter`. Other arguments and the result must be inert data; the
API must not execute callbacks or defer effects. Models must include all effects
of the terminal API, and its resource monitor must check the active grant before
performing them. Do not model an arbitrary helper as a terminal to silence
an unknown result. General helpers currently produce `unknown`. The standalone
API accepts operator-reviewed models for analysis; a standalone report cannot
register a library with the in-process admission gate or replace its fixed API
catalog. Its contracts are assumptions, not proof of library implementations.

The checker supports top-level function bodies, local argument aliases, imported
API aliases, literal resources, simple f-string templates, and `if`/`else`
branches comparing inert string variables to literals with `==` or `!=`.
Unknown comparisons within this supported form explore both branches and merge
local bindings conservatively; ambiguous resource values remain unknown. It
checks every declared value of a closed manifest selector against that value's
active rules. The runtime rejects unmapped values before dispatch. Without a
closed map it explores all supported branches. The whole-body audit still
inspects every branch and unreachable statement for unapproved APIs. Resource expressions are
compared structurally before normalization; wildcard/pattern containment and
arbitrary normalization equivalence are not proved. A subset relation the
checker cannot establish is not accepted.

Reports have three outcomes:

- `consistent`: the supported analysis is complete and `I ⊆ M` holds.
- `mismatch`: a manifest argument is missing, or an inferred effect is
  outside the active manifest. Other parts of the function can still be
  unknown; inspect `issues` for both kinds of findings.
- `unknown`: unsupported Python, unresolved resources, or unmodeled calls prevent
  a conclusion. Unknown is never accepted as consistent.

Version 3 reports include source line numbers, `inferred` effects (`observed` is
retained as an alias), matching rule indices, `outside_manifest` effect indices,
`unused_rules`, and the source SHA-256. `inference_complete` distinguishes a
complete supported overapproximation from a partial result.
`inferred_subset_of_manifest` is null when inference is incomplete, true when
coverage is established, and false when complete inference exceeds the manifest.
This replaces the reversed `manifest_subset_of_inferred` field from version 2.
`outside_manifest` identifies uncovered effects in their selector cases;
`unused_rules` is informational and never a requirement to exercise permission.
Reports explicitly identify `verified_scope: function_body_only` and
`initialization_verified: false`; consumers must not promote them to module-loader
or whole-runtime certificates.

This initial checker assumes inert string inputs and trusted terminal bindings.
It does not verify module initialization, decorators, default argument
expressions, monkey patching, arbitrary object behavior, `runs`, `returns`, or
runtime authorization. In particular, matching a `want` declaration does not
prove the tool handles a denied optional grant. It complements authorization
and enforcement checks; it does not prove Python confinement. Unsupported loops,
exception handling, helper calls, and dynamic dispatch remain unknown.

## Command line

Save reviewed operation models as a JSON array:

```json
[
  {
    "target": "document_store.read",
    "class_name": "fs",
    "operation": "read",
    "parameter": "path",
    "position": 0
  }
]
```

Run from an environment containing `langgraph-prebuilt`:

```sh
python -m langgraph.prebuilt.security.manifest_consistency \
  tools.py tools.slp --tool read_document --operations operations.json \
  --output consistency.json
```

`--function` selects a Python function whose name differs from the manifest tool
name. Omitting `--operations` leaves all calls unmodeled. The command exits zero
only for `consistent`; mismatches, unknown behavior, and invalid inputs exit one.

Failures also produce framework-owned diagnostics on stderr. In terminals, every
diagnostic label before the colon is red and its message after the colon is
yellow. File paths and line numbers stay plain. `NO_COLOR` disables highlighting,
and redirected diagnostics and JSON reports remain uncolored.
Programmatic command-line frontends can pass a checker report to
`manifest_verification_exit_code(report, source_name=...)` and propagate its
return value with `SystemExit`. It emits diagnostics on failure and returns 1;
success is silent and returns 0. This presentation helper does not replace
mandatory admission or turn a standalone report into an execution certificate.
In-process admission uses the same diagnostic formatter in its
`SecurityConfigurationError`. Demo 07 exercises that automatic path; correcting
its manifest changes setup from rejection to success.

### Language-sandbox terminology and Python execution boundary

A **language-sandbox tool** means source was available, admission succeeded for
the supported restricted language, and execution uses that admitted program.
It does not mean the author or tool body is trusted to obey policy. The canonical
class directive is `enforced_by language_sandbox`. `trusted_tool` is a deprecated
parser alias and `EnforcementKind.TRUSTED_TOOL` is a compatibility alias; new
receipts and generated declarations use `language_sandbox`. `runs inprocess`
continues to describe location, not an enforcement mechanism. The canonical
resource API imports are `langgraph.prebuilt.security.language_sandbox.read_text`
and `langgraph.prebuilt.security.language_sandbox.write_text`; the older
`security.inprocess` import remains compatible.

Checking `eval` and `exec` is insufficient. The executable boundary is an
immutable data program lowered from the checked AST, with no Python bytecode
execution for the candidate body. The language's value environment contains only
inert data. Unsupported syntax rejects admission even in unreachable branches.

| Python feature | Disposition in the admitted tool body |
| --- | --- |
| `eval`, `exec`, `compile`, generated functions and lambdas | Prohibited; no generic execution operation exists in the interpreter. |
| Imports, `__import__`, import hooks and dynamic loading | Prohibited in the body. Imports performed during application setup are outside this boundary; unreviewed modules must not be loaded into the coordinator. |
| Reflection, descriptors and dunder access | Prohibited. Attribute syntax is accepted only as an exact registered terminal name, never resolved on a candidate-supplied object. |
| Monkey-patching and global/nonlocal mutation | Prohibited. Assignments target local data names only. |
| Mutable function bindings, defaults, globals and client methods | The original function is never invoked. Admission captures an immutable program, inert defaults, and reviewed terminal code/bindings. Validation additionally rejects changed originals. |
| Native extensions and arbitrary library calls | No direct call path. A supported operation must have an explicit reviewed terminal contract and runtime mediation; other calls reject admission. |
| Privileged library objects and callbacks | Never enter the language environment. Exact scalar/data results are validated and copied; objects, callables, generators and custom conversion/equality protocols reject. |
| Exceptions and asynchronous entrypoints | Candidate exception handlers, generators, `await` expressions and background task creation are unsupported. Async entrypoints execute the same restricted program; they do not invoke the original coroutine. |

The interpreter, typed terminal contracts, resource implementations, grant
monitors, Python runtime and coordinator remain enforcement dependencies. An
arbitrary hostile Python thread already inside that process can modify those
dependencies; this is not process isolation against a compromised coordinator.
Use an isolated dispatcher for unsupported Python. Existing operator-hosted graph
nodes (`NodeTrust` in the legacy placement API) are a separate boundary and do
not acquire language-sandbox admission merely from being called `trusted`.

### Checked program derivations

Admission now also derives types and effects for the lowered immutable program.
The checker in `security.language_verification` covers every instruction and both
sides of every branch, including unreachable syntax. Its environments contain
only inert data types. Calls require statically named terminal contracts with
exact argument types; their effects are accumulated conservatively. Unknown
instructions, unbound locals, mutable instruction sequences, unsupported types,
contract mismatches and analysis-budget exhaustion reject admission. Execution
recomputes this derivation before the first terminal call, so a cached success
flag cannot authorize a changed program. Terminal results are checked against
their declared data types before becoming local values.

`admission.language_proofs()` returns the derivations and source/program hashes.
These are type/effect proofs for the admitted language under terminal contracts.
They do not, by themselves, prove that the interpreter implements those semantics,
that terminal implementations authorize every effect, or that graph/host
composition is complete. Those dependencies stay explicit in each result, and
`system_complete` remains false. The independent source-to-manifest check is
still required; a type derivation does not grant access to a resource.
