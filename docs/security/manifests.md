# Security manifest language reference

This page is the complete reference for the open-class security manifest
language parsed by `parse_security_manifest`. A manifest describes the finite
set of object capabilities a tool requests. Cedar policies separately decide
which principals may receive those capabilities.

Use the [static consistency checker](manifest-consistency.md) to compare a
tool function's modeled resource effects with these declarations. Unsupported
source is reported as unknown rather than accepted as consistent.

This language uses the `.slp` suffix, but it is not the older constructive
profile grammar documented in [slangGraph profile grammar](profiles.md). In
particular, this manifest language has `class` and `tool` blocks and does not
have `principal`, `owner`, `grant`, or `policy` directives.

## Two input forms

The high-level `cedar_security` helper accepts an unnamed manifest body bound
directly to one Python tool:

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

The helper derives the internal tool identity from `greet.name` and behaves as
if the body had been wrapped in a `tool greet { ... }` block. `runs` must resolve
to `inprocess`. The helper pre-registers its core classes, currently `fs` with
the `read` and `write` operations. Additional resource classes are passed through `classes=`
and must use `enforced_by language_sandbox`. Other enforcement loci use the
standalone form and lower-level host API.

The standalone form accepted by `parse_security_manifest` contains any number
of named `class` and `tool` blocks:

```slp
class db {
  operations  select insert update delete ddl
  object      table
  normalizer  sql.table_ref
  attrs       owner schema
  enforced_by broker
  lowering    postgres.role_grant
}

tool run_report {
  runs    broker
  db      select reports.@{quarter} need
  returns sensitive
}
```

Use the unnamed form when authoring call authorization for an ordinary Python
tool. Use the standalone form when defining new object classes, describing
resource requirements, or loading manifests independently of Python tool
objects.

### Built-in and custom classes

The high-level `cedar_security` helper supplies this context-specific core
class automatically:

| Class | Operations | Object | Normalizer | Enforced by |
| --- | --- | --- | --- | --- |
| `fs` | `read`, `write` | `path` | `fs.realpath` | `language_sandbox` |

Therefore a normal tool manifest can simply write `fs read @{path} need`.
Standalone parsing does not assume an enforcement host and consequently does
not install context-specific core classes. Plugins can declare classes in the
document or pre-register `ObjectClass` values with
`parse_security_manifest(..., classes=plugin_classes)`. Duplicate class names
fail closed; an application cannot silently replace the helper's core meaning
of `fs`.

The built-in `read_text(path)` terminal accepts only an exact `str`, requires an
active matching `fs read` grant, and supports regular files on Linux. After
checking the canonical pathname, it pins the file with `openat2`, rejecting
symlinks in every canonical path component. It reads through its owned descriptor
after verifying the reopened descriptor's device and inode. Missing `openat2` or
procfs descriptor support denies the read; there is no pathname-read fallback.

This grant names a canonical path. The terminal binds the object at its open,
not an inode or content snapshot from authorization time. Later pathname
replacement cannot redirect the pinned read. This does not promise metadata
secrecy, a historical inode identity, or immutable file contents. Invalid UTF-8
produces a payload-free `HostExecutionDenied`: the exposed exception has no
decoder exception in its cause or context containing file bytes. Owned
descriptors close on success and failure.

The built-in `write_text(path, value)` terminal similarly requires an exact
matching `fs write` grant. It overwrites one existing regular UTF-8 file through
a pinned descriptor and closes it before returning. It rejects symlinked paths,
multi-linked files, non-string arguments, and payloads larger than 1 MiB. It
does not expose file handles, create files, or fall back to a pathname write.

## Lexical syntax

A complete standalone document has this shape:

```text
document       = { class-block | tool-block }
class-block    = "class" IDENTIFIER "{" { statement } "}"
tool-block     = "tool" IDENTIFIER "{" { statement } "}"
statement      = tokens (NEWLINE | ";")
```

The concrete rules are:

- A statement ends at a newline or semicolon. Multiple statements may appear
  on one line when separated by semicolons.
- `#` begins a comment extending to the end of the line.
- Blank lines and empty semicolon-separated statements are ignored.
- There is no quoting or escaping syntax. Whitespace separates fields, so an
  object pattern cannot contain literal whitespace.
- Text outside a `class` or `tool` block is invalid in the standalone form.
- Blocks must have balanced braces.
- Block names and other identifiers match
  `[A-Za-z_][A-Za-z0-9_.-]*`: they begin with an ASCII letter or underscore
  and may then contain ASCII letters, digits, `_`, `.`, or `-`.
- Control characters are rejected from bound object values. Normalizers may
  impose stricter rules.
- Class and tool blocks may appear in either order. All classes are registered
  before any tool block is parsed.
- Class names and tool names must be unique within one document.

There are no includes, imports, macros, conditionals, expressions, lists,
quoted strings, or user-defined functions in a manifest. Put authorization
conditions in Cedar, not in the manifest.

## Class blocks

A class extends the vocabulary of resources and operations understood by the
manifest, generated Cedar schema, and enforcement layer.

```slp
class CLASS_NAME {
  operations  OPERATION...
  object      OBJECT_KIND
  normalizer  NORMALIZER_NAME
  attrs       ATTRIBUTE...
  enforced_by ENFORCEMENT_KIND
  lowering    LOWERING_NAME
}
```

Every directive except `lowering` is required. Each directive may occur only
once.

| Directive | Cardinality | Meaning |
| --- | --- | --- |
| `operations` | One or more identifiers | Complete set of operations that tool rules may request for this class. |
| `object` | Exactly one identifier | Kind of object named by a rule, such as `table`, `item`, or `origin`. It contributes to the generated Cedar entity type. |
| `normalizer` | Exactly one identifier | Trusted normalizer that converts a bound pattern into a canonical selector and trusted attributes. |
| `attrs` | Zero or more identifiers | Attributes the normalizer and trusted label provider may expose to Cedar. Write the directive with no following values when the class has no attributes. |
| `enforced_by` | Exactly one supported value | Component responsible for enforcing every surviving grant line. |
| `lowering` | Zero or one identifier | Optional adapter-specific lowering strategy recorded on each grant line. |

`operations` must not be empty. An operation used in a tool rule must appear in
this set. Attribute names must be valid identifiers. Two classes may not
generate the same Cedar entity type.

### Enforcement kinds

`enforced_by` accepts exactly these values:

| Value | Intended enforcement point |
| --- | --- |
| `kernel` | An operating-system mechanism such as Landlock, seccomp, or AppArmor. |
| `broker` | A trusted broker performs an application-semantic operation for a worker that lacks direct access. |
| `resource_side` | A remote resource enforces a scoped credential or server-side policy. |
| `framework` | A slangGraph hook enforces access to a framework-owned object. |
| `language_sandbox` | The source-admitted restricted language executes only mediated terminals; native host DAC independently restricts the coordinator identity. |

The declaration is a promise, not an implementation. The host must register an
enforcer for the selected kind, and that enforcer must report support for the
exact grant line. Missing support fails closed unless an operator supplies an
explicit, non-empty enforcement-waiver reason. Waived lines remain visible in
the grant and must be reported as unsupported by the activation receipt.

### Cedar entity type generation

The Cedar entity type is formed by capitalizing the first character of the
class name and object kind and concatenating them:

| Declaration | Cedar entity type |
| --- | --- |
| `class db` with `object table` | `slangGraph::DbTable` |
| `class secret` with `object item` | `slangGraph::SecretItem` |

Every generated resource entity has a `selector: String` attribute plus one
string attribute for every name in `attrs`.

## Tool blocks

A standalone tool block has this form:

```slp
tool TOOL_NAME {
  runs RUN_LOCUS
  CLASS OPERATION OBJECT_PATTERN need|want
  map ARGUMENT=VALUE CLASS OPERATION OBJECT_PATTERN need|want
  returns RETURN_CLASS
}
```

`runs` and `returns` are optional metadata directives. Resource rules are
optional and repeatable.

| Entry | Cardinality | Default | Meaning |
| --- | --- | --- | --- |
| `runs RUN_LOCUS` | Zero or one | `inprocess` | Identifier naming the execution locus. The high-level helper accepts language-sandbox `inprocess`, or `linux`/`broker` with an explicit isolated dispatcher. |
| `returns RETURN_CLASS` | Zero or one | `normal` | Identifier classifying the tool result, such as `normal` or `sensitive`. The manifest parser records the identifier; downstream policy gives it meaning. |
| `CLASS OPERATION OBJECT_PATTERN need` | Zero or more | None | Required resource capability. Removing or denying it denies the complete call. |
| `CLASS OPERATION OBJECT_PATTERN want` | Zero or more | None | Optional resource capability. Removing or denying it omits the line but does not by itself deny the call. |
| `map ARGUMENT=VALUE CLASS OPERATION OBJECT_PATTERN need\|want` | Zero or more | None | Include this fixed resource rule only when the named invocation argument exactly equals the literal value. |

`RUN_LOCUS` and `RETURN_CLASS` are syntactically open identifiers. The parser
does not maintain a global enumeration for them. The selected execution path
is responsible for accepting or rejecting a particular value.

### Language sandbox and host permission intersection

For `runs inprocess`, the admitted language program executes under the
coordinator's host identity. Its effective permission is:

`effective permission = slangGraph permission ∩ host permission`

Both sides must allow an operation. slangGraph evaluates the application
principal, action, and resource. The host independently evaluates its native
identity and controls, such as Unix UID/GID and ACLs, database roles, service
credentials, or container policy. Neither permission system can turn the
other's denial into an allow.

There is no implied mapping from a slangGraph `Principal` to a Unix user or
other host identity. In the ordinary deployment, the host sees the coordinator
service account. The language sandbox executes the admitted immutable program,
not the original Python function. Imports, reflection, dynamic code, and
arbitrary library objects are unavailable in that language. Framework terminals
mediate resource access. Use an isolated host and broker for Python outside this
restricted language. `inprocess` alone is never an enforcement guarantee.

Admission validates native function metadata before comparing loaded code with
source. Code identity includes native constants and exception tables without
candidate equality operations. Program execution captures its signature,
terminal contracts and bindings, proves that captured program, then uses the
same captured inputs. Forged nested signature/contract fields are rejected
before their protocols run. Signature capture requires a native inspect layout
whose mapping-proxy backing can be inspected without mapping dispatch; unknown
layouts are unsupported. Annotations are not interpreted as executable input.

A resource rule has exactly four whitespace-separated fields:

```text
CLASS OPERATION OBJECT_PATTERN REQUIREMENT
```

- `CLASS` must name a class declared in the same standalone document.
- `OPERATION` must appear in that class's `operations` directive.
- `OBJECT_PATTERN` is one whitespace-free literal/template token.
- `REQUIREMENT` is exactly `need` or `want`.

Rules are retained in source order. Their stable grant-line identifiers are
`TOOL_NAME:INDEX`, where `INDEX` is zero-based among that tool's resource
rules.

### Closed operation maps

An interactive tool may expose several operations through one argument while
keeping the Cedar vocabulary closed:

```slp
map operation=inspect   pump inspect   @{device_id} need
map operation=set_flow  pump set_flow  @{device_id} need
map operation=calibrate pump calibrate @{device_id} need
```

The selector has the form `ARGUMENT=VALUE`, with an identifier argument and a
non-empty, whitespace-free literal value. A tool may select on only one
argument, although several rules may share one selector value when an operation
requires several resources. Unconditional rules may coexist with mapped rules.

At expansion time, exactly matching mapped rules are retained alongside all
unconditional rules. A missing selector argument or a value absent from the
closed map denies before Cedar evaluation and before dispatch. The value never
becomes an action name: the class and operation remain fixed, parser-validated
tokens in each manifest rule. Consequently an argument cannot inject a Cedar
action, entity type, or policy fragment.

## Object patterns and argument binding

An object pattern is literal text containing zero or more argument variables:

```text
@{VARIABLE_NAME}
```

Variable names begin with an ASCII letter or underscore and continue with
ASCII letters, digits, or underscores. For example:

```slp
db select reports.@{quarter} need
queue publish tenant-@{tenant}.events want
```

At call time the framework:

1. Looks up every variable in the normalized tool arguments.
2. Converts the argument value to text with `str(value)`.
3. Substitutes the value literally into the pattern.
4. Rejects missing variables, empty values, control characters, and malformed
   `@{...}` syntax.
5. Passes the complete bound value to the class normalizer.

Manifests do not provide globs, regular expressions, escaping, or path
semantics. Any special interpretation belongs to the selected normalizer and
enforcer. A pattern such as `reports.@{quarter}` is string construction, not a
policy expression.

## Normalizers

A normalizer runs before Cedar and turns a raw bound value into a
`NormalizedObject` containing:

- one canonical, non-empty, whitespace-free `selector`; and
- zero or more string attributes declared by the class's `attrs` directive.

Normalizers are part of the trusted computing base. Cedar and the enforcer see
the normalized result, not the original argument text. Returning an undeclared
attribute is an error.

Four normalizers are built in:

| Name | Accepted input | Canonical output and attributes |
| --- | --- | --- |
| `fs.realpath` | A path resolving to an existing filesystem object. Relative paths are accepted and resolved against the coordinator's working directory. | Absolute canonical path with symlinks resolved; no attributes. |
| `identity` | Already-canonical, non-empty text without whitespace or control characters. | Selector is unchanged; no attributes. |
| `sql.table_ref` | An unquoted `table` or `schema.table`; each component begins with an ASCII letter or underscore and then uses letters, digits, `_`, or `$`. Surrounding whitespace is removed. | Lowercase `schema.table`; omitted schema becomes `public`; emits `schema`. |
| `mail.domain` | An address containing exactly one `@`, non-empty local and domain parts, and no whitespace. Surrounding whitespace is removed. | Lowercase recipient domain with trailing dots removed; emits `domain`. |

Custom normalizers are supplied to `parse_security_manifest`:

```python
manifest = parse_security_manifest(
    text,
    normalizers={"browser.origin": normalize_origin},
    enforcers={EnforcementKind.BROKER: broker_enforcer},
)
```

The mapping key must be a valid identifier and match the class's `normalizer`
value. The callable accepts one string and returns `NormalizedObject`.

## Trusted labels and attributes

After normalization, a trusted label provider may add attributes for a
specific `(class_name, normalized_selector)` pair. Normalizer attributes and
labels share the namespace declared by `attrs`. Labels replace normalizer
values with the same name. Any attribute not declared by the class denies the
call.

When Cedar entities are built, every declared attribute exists. A declared
attribute not supplied by the normalizer or label provider has the empty string
as its value.

Tool authors cannot use a manifest to assign mandatory security types or
invent Cedar attributes. Those values must come from trusted normalization or
operator-controlled labeling.

## Generated Cedar schema and requests

The registry generates one Cedar schema in namespace `slangGraph`.

| Manifest concept | Cedar representation |
| --- | --- |
| Invocation principal | `User` entity with `roles: Set<String>` |
| Bound Python tool | `Tool` entity with `owner: String` |
| Tool invocation | `Action::"call"` applied to a `Tool`; empty context |
| Class operation | `Action::"CLASS::OPERATION"` applied to the generated class entity |
| Normalized object | Generated entity with `selector` and declared string attributes |
| Resource-rule context | `tool: Tool` and `requirement: String` |

For the `db` example, the resource authorization request uses:

```cedar
action == slangGraph::Action::"db::select"
```

against a `slangGraph::DbTable` resource. Cedar policy can inspect
`resource.selector`, `resource.schema`, `resource.owner`, `context.tool`, and
`context.requirement` because those fields come from the manifest-generated
schema.

The resource entity ID is an opaque hash of the class, normalized selector, and
attributes. Policies should inspect typed attributes rather than depend on that
ID.

## Authorization and enforcement sequence

For each tool call, the object-policy path performs these steps:

1. Select the bound tool manifest.
2. Bind argument variables and normalize every object.
3. Add trusted labels and create finite candidate grant lines.
4. Validate Cedar policy sets against the generated schema.
5. Require the tool-owner permit set to allow the bound tool call. For a
   resource-free manifest, also require the principal permit set to allow
   `Action::"call"`.
6. For a resource-bearing manifest, derive caller eligibility from the
   principal's access to the candidate resource lines instead of requiring a
   duplicate caller-side `Action::"call"` permit. Require both the owner and
   principal/share permit sides to allow each `need` line.
7. Apply operator and module `forbid` policies; forbids can only remove lines.
8. Deny the call if a `need` line was removed; omit a removed `want` line.
9. Require an enforcer or explicit waiver for every surviving line.
10. Bind the surviving lines, policy digest, principal, tool, call, and waivers
    into an `ObjectGrant` digest.
11. Dispatch through the trusted host and verify its activation receipt.

The high-level helper requires [manifest consistency admission](manifest-consistency.md)
for all language-sandbox tool bodies, including resource-free tools. Resource-free
manifests still receive the Cedar call check and run through the verified
dispatcher. For `language_sandbox` resource manifests, it performs the complete expansion
and grant construction sequence, canonicalizes descriptor-declared resource
arguments before executing the admitted language program, and records each issued grant and
an exact language-sandbox/host-intersection receipt. It generates the owner ceiling
internally. The caller-facing `policy` permits the resource operations; access
to those manifest-derived operations determines whether the invocation may be
dispatched. Resource-free manifests still require an explicit caller-facing
`Action::"call"` permit.

Admission requires a complete supported effect overapproximation and
`inferred effects ⊆ manifest`, plus rejection of unmonitored APIs and reflection.
An approved resource call outside the manifest is permitted in the source but
denied by its monitor during execution. A manifest cannot grant an effect absent
from inference, or turn an arbitrary library into an approved resource API.

Every evaluation also leaves a private bundle below
`CedarObjectAuthorizer.artifact_root`. Each directory returned by
`authorization_artifacts()` contains the generated `schema.cedarschema`,
`entities.json`, validated policies, and exact per-decision request files. The
runtime has already decided from that snapshot, so editing a retained bundle is
safe for Cedar CLI experimentation and cannot mutate an issued grant.

## Validation and failure behavior

Manifest parsing rejects:

- unexpected text outside blocks;
- malformed, unterminated, or duplicate blocks;
- missing required class directives;
- duplicate or unknown class directives;
- empty operation sets or invalid identifiers;
- unknown normalizers;
- invalid enforcement kinds;
- a `cedar_security` resource class not enforced by `language_sandbox`;
- duplicate `runs` or `returns` directives;
- unknown resource classes or undeclared operations;
- resource rules that do not have exactly four fields;
- malformed `map` rules, multiple selector arguments in one tool, or mapped
  operations not declared by their class;
- requirements other than `need` and `want`; and
- malformed object-variable syntax.

Configuration or authorization rejects:

- a Python tool not covered by the configured manifest/owner binding;
- a resource class without its promised enforcer;
- a missing variable binding;
- invalid normalizer output or undeclared attributes;
- an unavailable Cedar executable;
- Cedar syntax or schema-validation errors;
- owner, principal, share, or MAC denial of a required line; and
- incomplete, duplicate, additional, unsupported, or digest-mismatched host
  enforcement evidence.

Failures are closed: a validation or evaluation error does not become an
allow. Cedar CLI validation currently occurs when authorization runs, so an
invalid Cedar policy may be detected on the first attempted call rather than
when the graph is compiled.

## Complete standalone example

```slp
# Classes may be declared before or after tools.
class db {
  operations  select insert update delete ddl
  object      table
  normalizer  sql.table_ref
  attrs       owner schema classification
  enforced_by broker
  lowering    postgres.role_grant
}

class secret {
  operations  read
  object      item
  normalizer  identity
  attrs       owner classification
  enforced_by broker
}

class mail {
  operations  send
  object      recipient
  normalizer  mail.domain
  attrs       domain
  enforced_by broker
}

tool run_report {
  runs broker
  db select reports.@{quarter} need
  secret read reporting_api_key need
  mail send @{recipient} want
  returns sensitive
}
```

In a call such as:

```python
{"quarter": "Q4", "recipient": "auditor@example.com"}
```

the candidate selectors are `reports.q4`, `reporting_api_key`, and
`example.com`. The database normalizer also supplies `schema == "reports"`,
and the mail normalizer supplies `domain == "example.com"`. Trusted labels may
fill the declared `owner` and `classification` fields before Cedar evaluates
the requests.

## What does not belong in a manifest

Do not put these concerns in the manifest:

- identities, roles, or decisions about who may call a tool: use Cedar
  `permit` policies;
- mandatory denials or information-flow rules: use operator/module Cedar
  `forbid` policies and security modules;
- conditional expressions or argument-dependent authorization logic: expose
  normalized attributes and test them in Cedar;
- implementation code: provide a trusted normalizer, label provider, enforcer,
  broker handler, or framework hook; or
- credentials and secrets: refer to canonical object identities and let the
  broker or resource-side issuer retain the credential.

The manifest enumerates requested authority. Cedar authorizes it. The declared
enforcement component must then realize the surviving grant.
