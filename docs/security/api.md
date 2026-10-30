# Public security API

Everything exported by `langgraph.prebuilt.security` is listed here. Most
applications need only declarations, `Principal`, `SecurityConfig`, a mediation
entry point, and an audit sink. The lower-level records are public so policy,
analysis, and operator tooling can use stable typed values instead of private
framework objects.

## Constants and registries

| Name | Contract |
| --- | --- |
| `PRINCIPAL_CONFIG_KEY` | Reserved `RunnableConfig` key used by `with_principal` and `principal_from`. Application state and model-visible data must not write it. |
| `NORMALIZERS` | Immutable registry of built-in resource normalizers: `realpath`, `domain`, `email_domain`, `sql_statement_kind`, and `shell_argv0`. |

## Tool declarations and author DAC

| Name | Contract |
| --- | --- |
| `Effect` | Enum containing `READ`, `WRITE`, `NETWORK`, `EXEC`, `DELEGATE`, and `SEND`. |
| `ResourceArg` | Declares a resource-bearing argument, its resource kind, optional normalizer, and whether the resource is local or remote. |
| `ToolDescriptor` | Immutable materialized tool name, effects, resources, sensitivity, reversibility, and extra metadata. |
| `ToolDac` | Immutable author DAC: owner, execute grants, required scopes, and value-specific normalized argument grants. |
| `DacOverrides` | Immutable operator replacements. `values` replaces legacy `ToolDac` entries; `profiles` replaces complete `ToolProfile` entries. Unknown tool names fail configuration. |
| `effects` | Decorator that attaches a descriptor to a function or `BaseTool`. At least one effect is required. |
| `dac` | Decorator that attaches author-proposed call authorization to a function or `BaseTool`. |
| `normalize_resource` | Applies the normalizer selected by a `ResourceArg`; it returns the original value when no normalizer is named. Errors fail the call closed. |
| `dac_check` | Pure decision function over a `Principal`, `Tool`, and normalized argument map. It runs before policy modules. |

The common declarations are:

```python
@dac(
    owner="analyst",
    grants={"analyst": "x", "*": "-"},
    required_scopes={"fs:read"},
)
@effects(
    Effect.READ,
    resources=[ResourceArg("path", "path", "realpath")],
)
def read_file(path: str) -> str:
    ...
```

An undeclared tool is inferred as critical, irreversible execution with a
default-deny DAC. A declaration describes intended behavior; it does not
confine the implementation.

## Open object-class policy

| Name | Contract |
| --- | --- |
| `EnforcementKind` | Declares whether a class is enforced by the kernel, a broker, a remote resource, or the framework. |
| `NormalizedObject` | Canonical selector and trusted attributes returned by an object normalizer. |
| `ObjectNormalizer` | Callable contract that converts one raw bound argument into a `NormalizedObject`. |
| `ObjectClass` | Immutable class vocabulary: operations, object kind, normalizer, attributes, enforcement locus, and optional lowering. |
| `ObjectClassEnforcer` | Trusted adapter contract that identifies support for normalized grant lines. |
| `ObjectClassRegistry` | Registers preloaded and open classes, normalizers, and enforcers and generates their Cedar schema. `cedar_security` preloads its context-specific core vocabulary; plugins may pre-register `ObjectClass` values through `parse_security_manifest(classes=...)`. |
| `ManifestRule` | One unbound class-operation-pattern authority request with `need` or `want` semantics and an optional closed argument-value selector. |
| `ToolManifest` | Finite collection of manifest rules for one tool. |
| `SecurityManifest` | Parsed class registry and tool manifests; expands bound arguments into normalized candidate lines. |
| `parse_security_manifest` | Parses `.slp` `class` and `tool` blocks and rejects unknown classes, operations, directives, and normalizers. |
| `CedarPolicySet` | Separates tool-owner, principal, and share permits from additional graph-local forbids and rejects mixed effects. Operator MAC is installed independently. |
| `install_mac_policy` | Installs immutable runtime-wide operator forbids before execution. Deployment policy from `LANGGRAPH_MAC_DIR/mac.cedar` (default `/etc/langgraph`) loads automatically and cannot be replaced by this API. |
| `CedarObjectAuthorizer` | Intersects owner and principal/share DAC, applies MAC, preserves `need`/`want`, and returns a finite grant. Explicit class enforcement waivers require reasons and are bound into the grant. `artifact_root` and `authorization_artifacts()` expose retained private Cedar bundles for review and experimentation. |
| `CedarCallPolicy` | Low-level Cedar call authorization only; does not certify source or provide verified admission. Use `cedar_security` for language-sandbox admission. |
| `cedar_security` | Binds an unnamed SLP manifest and caller-facing Cedar policy to a tool. In-process mode interprets a source-admitted language program with mediated terminals; `dispatcher=ObjectBrokerDispatcher(...)` with `runs linux` or `runs broker` uses an isolated worker with kernel and broker enforcement. Derives identity and owner ceilings and constructs inspectable grants. |
| `ObjectSandboxDispatcher` | Protocol combining isolated dispatch, exact-line support checks, and pinned-tool configuration validation. |
| `ObjectBrokerDispatcher` | Linux Landlock/seccomp dispatcher negotiating host and semantic obligations for custom broker classes and exact-file kernel grants; records optional reductions and refuses missing required authority. |
| `ResourceMediatorAdapter` | Operator-supplied exact resource assessment and invocation, with optional preflight/activation/release hooks. Semantic implementation is trusted. |
| `ResourceSupport` | Exact/stricter/unsupported assessment, reviewed contract reference, protected paths, and required host capabilities. |
| `sqlite_record_mediator` | Concrete parent-owned SQLite adapter for exact `db_record` read/write/delete grants with `lowering sqlite.record.v1`; fixed parameterized SQL and protected database directory. Requires Python 3.11+. |
| `ResourceContract` (`security.mediators.contracts`) | Typed resource definition. Bind `implementation` and `mediator` (with `assess` and `validate` methods) during construction or with `.bind(...)`; omit `resource_parameter` for an object-bound API. Register `resources=(resource,)` on the broker dispatcher or on `cedar_security` for admitted language-sandbox tools. `.permission(operation)` declares the exact object without application-managed IDs. Generates client methods, checker effects, declarations, and validated dispatch. |
| `ResourceReference` (`security.mediators`) | Opaque `.service` address for OS broker clients. Available as `resource.reference`; possession never substitutes for an invocation grant. |
| `ResourceMediator` (`security.mediators.contracts`) | Owns `assess(line, host)` for lowering support and synchronous `validate(operation, arguments, context)` for request checks. Binding wires both methods; authorization and typed checks remain mandatory. |
| `records` (`security.mediators.records`) | Registered typed record client with `read`, `write`, and `delete`; execution still requires an authenticated worker channel and a matching grant. |
| `SQLITE_RECORD_SCHEMA` | Exact operator-created records-table schema required by the SQLite mediator. |
| `ResourceInvocation` | Parent-authenticated principal, session, tool, call, grant, and worker context passed to mediator callbacks. |
| `ObjectLoweringRecord` | Candidate and retained grants, host attestation, obligation graph, and negotiated plan returned by `lowering_records()`. |
| `negotiate_object_grant` | Platform-neutral obligation negotiation that drops unsupported optional authority and rechecks the requirement ledger; required authority and default-deny obligations fail closed. |
| `object_request` | Worker-side request for a concrete class, operation, and object over the invocation-bound broker channel. |
| `ObjectGrantLine` | One exact normalized and policy-authorized object capability. |
| `ObjectGrant` | Complete call-bound object authority with a canonical digest. |
| `ObjectGrantDispatcher` | Trusted host contract that activates a grant and executes the tool outside the coordinator. |
| `ObjectPolicyHostExecutor` | ToolNode host bridge that authorizes with Cedar and verifies complete per-line activation evidence. `authorization_grants()` exposes a bounded snapshot of exact grants issued for execution. |
| `ObjectPolicyDenied` | Fail-closed denial raised by manifest expansion, Cedar evaluation, or enforcement negotiation. |

See the exhaustive [manifest language reference](manifests.md) for accepted
syntax and [open object classes](object-classes.md) for the wiring model.

## Identity, calls, and private module state

| Name | Contract |
| --- | --- |
| `Principal` | Authenticated user ID, immutable roles and scopes, session ID, optional delegator, and private module blobs. |
| `Tool` | Security representation used by policy: public name, DAC, effects, resources, and private module blobs. |
| `ToolCall` | Immutable physical-call request containing raw arguments, normalized resources, call ID and index, and prior audit history. Raw arguments must not be copied into audit or approval payloads. |
| `Slot` | Thread-safe mutable mapping owned by one module for one principal or tool. `snapshot()` returns an immutable copy. |
| `Blobs` | Thread-safe mapping from module name to independent `Slot` values. |
| `allocate_blobs` | Allocates one empty slot for each unique module name. |
| `copy_blobs` | Copies all or selected slots without sharing their mutable mappings. |
| `with_principal` | Admits native config dictionaries, prepares module credential slots, and binds an exact `Principal` outside graph state. Supported runtime/context mirrors are copied before binding. |
| `principal_from` | Reads an exact `Principal` from the authoritative configurable dictionary, or from an exact `Runtime` with a supported dictionary context when the direct binding is absent. Returns `None` when absent; unsupported identity-source shapes fail closed. |
| `SecurityBindingError` | Raised when a module fails while preparing a principal binding. |
| `SecurityConfigurationError` | Raised when secured execution would lose its explicit or inherited configuration. |

Principal binding accepts `None` or an exact native `dict` for the config, and
`None` or an exact native `dict` for `configurable`. Every key at these levels
must be an exact `str`. Native item snapshots are checked before constructing a
fresh dictionary or looking up reserved keys, so custom key equality, mapping
methods and truth tests are not part of identity extraction. `Principal`
subclasses, custom `Mapping` implementations and dictionary subclasses are not
accepted as replacements for these admitted shapes.

The direct `configurable.__principal__` value is authoritative. When it is
absent, `principal_from` accepts only an exact `langgraph.runtime.Runtime` whose
context is `None` or an exact dictionary with exact string keys. Arbitrary
attribute-based contexts, including dataclass contexts carrying a principal
attribute, cannot establish identity. An unrelated runtime or opaque context is
not inspected when the direct principal is present. These checks validate the
binding shape; authentication and ownership of the reserved principal slot remain
the caller's control-plane responsibilities.

`principal_from(config, include_runtime_context=False)` reads only the direct
binding and returns `None` when it is absent, without inspecting a runtime or its
context. The switch must be an exact boolean. Unsecured `ToolNode` request hooks
use this mode to retain an explicit bound principal without treating arbitrary
application contexts as identity sources; secured routes retain strict runtime
context admission.

Accepted principals have exact native strings for user and session IDs, an exact
native string or `None` for the delegator, and exact frozensets of exact strings
for roles and scopes. Their credential storage must
use exact `Blobs` and `Slot` objects, native dictionaries with exact string keys,
and native reentrant locks. Admission rejects substituted allocation, mapping or
lock protocols before credential preparation or identity extraction. Policy-owned
slot payload values remain opaque and mutable; validation does not inspect or
copy them, authenticate their meaning, or seal credentials against later changes.
Policy code and the control plane must preserve these native container shapes
and stable bindings while using them.

When `with_principal` mirrors identity into a supported runtime context, it
returns a new `Runtime` and a shallow copy of the context dictionary. The
original runtime/context and a parent binding retain their previous principal,
including when child bindings are prepared concurrently. Other context values
remain shared references. Opaque runtimes and unsupported context shapes are
left untouched and do not become additional identity sources.

`Principal`, `Tool`, and `ToolCall` are frozen records. Their nested `Blobs`
remain mutable, and policy modules own the slot contents.

## Decisions, modules, and mediation

| Name | Contract |
| --- | --- |
| `Verdict` | Enum containing `ALLOW`, `DENY`, `TRANSFORM`, and `ESCALATE`. |
| `ExecutionOutcome` | Durable execution state: denied before dispatch, succeeded, failed, or indeterminate. It is separate from an authorization verdict. |
| `Decision` | Immutable verdict plus a reason. `TRANSFORM` and `REDACT` require `new_args`; `ESCALATE` requires an `EscalationRequest`; allow and deny carry neither. Transform arguments require exact native dictionaries with exact string keys or the internal admitted argument record. They are stored in a tuple-backed read-only mapping and revalidated before narrowing. Custom mappings and mapping proxies are unsupported; values require separate admission. |
| `EscalationRequest` | Redacted request ID, reason, tool and call IDs, and safe metadata. `to_payload()` never includes tool arguments. |
| `Approval` | Human response containing request ID, boolean decision, approver, and optional reason. |
| `SecurityModule` | Base class exposing the seven hooks: allocation, credential preparation and transfer, call preparation, call permission, post-call observation, and resume permission. |
| `CapModule` | Framework-owned first module. It prevents scope growth and rejects negative approval input. Applications do not register it manually. |
| `SecurityStack` | Restrictive composition engine for DAC, capability checks, ordered modules, timeout handling, audit, and observation. Application code normally creates `SecurityConfig` instead. |
| `SecurityConfig` | Frozen configuration for modules, DAC overrides, audit sink, observer, policy timeout, principal requirement, flow policy, and optional host executor. It configures `ToolNode` directly or through `StateGraph.compile`. |
| `SecurityDeniedError` | `PermissionError` subclass raised when a guarded direct call or delegation is denied. `ToolNode` instead returns an error `ToolMessage`. |
| `SecurityAuditError` | Raised when a required audit record cannot be persisted before dispatch. |
| `SecurityIndeterminateError` | Raised after dispatch when the operation may have executed but its outcome cannot be durably recorded. |
| `guarded_tool` | Wraps a callable or `BaseTool` so direct sync and async invocation crosses the same security stack as `ToolNode`. Other aliases to the original callable remain unguarded. |
| `delegate` | Wraps a child runnable with an explicit scope subset, independent copied blobs, and `delegated_by` provenance. Scope growth is denied. |

Modules are independently restrictive. An allow never overrides another deny.
Malformed return values, exceptions, and timeouts become denials. A transform is
normalized and checked by DAC again before permission hooks run.

## Framework object manager

These records define the non-tool operations accepted by `HostRouter`. The
router authorizes an immutable request, binds that exact request into an
`ObjectAuthorization`, and dispatches it to `ObjectManagerHost` only after an
allow verdict.

| Name | Contract |
| --- | --- |
| `DispatchKind` | Closed set of subgraph, `Send`, parallel-branch, subagent, and nested-agent dispatch forms. |
| `DispatchRequest` | Parent/child authority-transfer request; every form performs the child-subset check and `cred_transfer`, including identity transfers. |
| `ToolRegistryRequest` | Static or dynamic tool registration and override request. Dynamic allocation runs `tool_alloc_security`; undeclared tools remain default-deny. |
| `StateOperation` | Closed set of state write, restore, tool/model/store reads, and store writes. |
| `StateRequest` | One state or store operation with resource, labels, and optional value or checkpoint data. |
| `ModelInvocationRequest` | Model invocation input whose labeled context can be stripped before prompt assembly. |
| `OutputRequest` | Labeled output and destination-clearance request supporting allow, deny, redact, or escalate. |
| `FrameworkRequest` | Union of all immutable object-manager request records. |
| `ObjectAuthorization` | Exact request and successful decision passed across the router/host boundary. |
| `SecurityLabels` | Confidentiality, integrity, and compartment labels attached to state, context, and output. |
| `LabeledValue` | Immutable value plus `SecurityLabels`. |
| `ToolObjectDac` | Tool-specific readable state channels and readable/writable store keys. An undeclared tool receives empty sets. |
| `ObjectManagerPolicy` | Operator configuration for per-tool object DAC and destination clearances. |
| `StoreResource` | Store key identity with authenticated owner and labels. |
| `CheckpointEnvelope` | Principal-bound hash-chain checkpoint record with replay sequence and payload digest. |
| `seal_checkpoint` | Creates a keyed checkpoint envelope bound to its principal, predecessor, and sequence. |
| `ObjectManagerHost` | Reference host for registry, state, store, checkpoint, model, output, and dispatch effects after router authorization. |

## Exact grants and enforcement activation

These types implement the platform-neutral enforcement contract. They do not
make a native mechanism trustworthy by declaration: an `EnforcementAdapter` is a
TCB component and must pass its platform contract suite.

| Name | Contract |
| --- | --- |
| `AuthorityDomain` | Closed-world authority domain such as filesystem, network, process, service, credential, or runtime. |
| `GrantRule` | One exact operation, selector, conditions, need/want requirement, provenance, and baseline marker. |
| `Grant` | Immutable authority for one principal, session, artifact, normalized intent, policy, and call. Its canonical digest binds all rules. |
| `GrantCompilation` | A final `Grant` paired with its source-to-rule `RequirementLedger`. |
| `compile_grant` | Converts a successful constructive DAC evaluation into exact attributed rules, rejecting denied evaluations and unmarked runtime baseline authority. |
| `compile_obligations` | Expands every grant rule into an operation obligation and adds a non-waivable deny-complement obligation for every authority domain, including domains with no allow rule. |
| `RequirementEntry` | Connects one source `need` or `want` to its descendant final grant rules. |
| `RequirementLedger` | Rechecks source requirements after mandatory filtering, lowering, and activation reductions. |
| `RequirementCheck` | Revalidation result listing missing needs and removed wants. |
| `ObligationKind` | Operation, closed-world complement, bypass prevention, credential custody, authenticated channel, resource limit, or evidence obligation. |
| `EnforcementObligation` | One exact, independently assigned guarantee with resource conditions and dependency IDs. |
| `SupportLevel` | Adapter relation `EXACT`, `STRICTER`, or `UNSUPPORTED`. |
| `RuleEnforcement` | Per-rule receipt relation recorded as exact, tightened, or unsupported with the responsible mechanism. |
| `SupportAssessment` | One adapter's rule-specific assessment and evidence requirements for one obligation. |
| `HostAttestation` | Fresh, nonce-bound host statement whose digest is meaningful only after trust-anchor verification. |
| `HostAttestationVerifier` | Protocol that authenticates a `HostAttestation` against deployment trust anchors. |
| `HostExecutionDenied` | Fail-closed error raised before tool code runs when an exact host plan cannot be activated. |
| `HostExecutionError` | Post-activation failure carrying the verified receipt, outcome, termination status, and an operator recovery identity when termination is uncertain. |
| `HostExecutionResult` | Successful host result paired with the verified receipt that must enter durable audit before its value is accepted. |
| `HostToolExecutor` | Portable execution bridge used by `ToolNode` and `guarded_tool` after authorization. |
| `LinuxSandboxExecutor` | Linux implementation that lowers supported filesystem and resource grants into a fresh bubblewrap worker. Before releasing the startup barrier, it verifies the payload process's namespace, capability, seccomp, no-new-privileges, thread, mount-table, credential, and process state. Frames are capped at 1 MiB, response structure is bounded, and termination is confirmed by boot ID, PID, and start time. The defaults name `RLIMIT_AS` as `address_space_bytes` and per-file `RLIMIT_FSIZE` as `file_size_bytes`; profile `memory_bytes` is unsupported. `activation_receipts()` exposes a bounded operational snapshot. An optional `lifecycle_checker` selects the synchronous Lean decision route described below. |
| `LeanLifecycleChecker` | Captures an operator-selected, SHA-256-pinned form of the proved worker decision core. The preferred native-library mode loads the generated checker and its pinned runtime from sealed Linux storage once and calls it inline before `GO` and after cleanup; the legacy executable mode starts a sealed process per decision. Missing execution, unsupported traces and selected async calls refuse. The Lean model proof does not establish Python placement, observation truth, compiler/FFI/decoder correspondence or OS enforcement. See the [worker lifecycle guide](lean-worker-route.md). |
| `LinuxObjectDispatcher` | Native object-policy dispatcher that lowers exact Cedar filesystem grants into fresh `LinuxSandboxExecutor` workers. It accepts canonical regular-file `read`, `write`, and `truncate` lines only, refuses waivers and unsupported authority, records the native lowering, and optionally applies the pinned Lean lifecycle checker. Mutable files must have a single link. |
| `LinuxToolSpec` | Trusted manifest binding a tool name to an importable entry point and operator-verified primary-source digest. `from_deployment` and `from_selection` additionally bind validated OSTree content before authorization. Legacy dependencies and runtime roots are not covered by the primary digest; they enter `sys.path` only after confinement. |
| `BundleManifest` | Closed versioned `bundle.json` schema naming the tool, entry point, primary file, import roots, and optional dependency lock. |
| `CleanupReport` | Reference-aware cleanup result listing retained commits and removed materialized checkouts. |
| `DeploymentBinding` | Framework-owned exact tool commit, manifest digest, and primary artifact digest selected before preparation and approval. |
| `DeploymentError` | Fail-closed publication, selection, checkout-validation, or recovery failure. |
| `DeploymentLease` | Durable set of exact commits retained while a worker is live or termination remains uncertain. |
| `RuntimeManifest` | Closed manifest naming a runtime identity, interpreter, and import roots supplied by an OSTree root. |
| `RuntimeBinding` | Exact runtime commit and manifest digest included in approval, grant, and activation identities. |
| `RuntimeDeployment` | Validated runtime-root checkout with host and guest interpreter locations. |
| `ToolDeployment` | Validated exact-commit checkout with its manifest, authority binding, primary source, and import roots. |
| `TrustedRemote` | Immutable operator-approved remote identity containing its URL and pinned public-key digest. |
| `OstreeDeploymentManager` | Trusted publisher, immutable-release selector, verified remote importer, channel manager, force-copy materializer, checkout validator, durable per-call binding store, and reference-aware cleanup coordinator. |
| `LinuxCapabilities` | Direct per-boot probe result for Landlock ABI, cgroup v2 delegation and `cgroup.kill`, unprivileged user namespaces, BPF LSM, Landlock audit, and pidfd support. |
| `probe_landlock_abi` | Calls `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` and returns the kernel-reported ABI number. |
| `probe_linux_capabilities` | Runs the direct host capability probes used by checks and execution attestation. |
| `RuleLowering` | One Landlock grant rule's exact, tightened, or unsupported lowering result. |
| `LandlockRuleset` | Parent-built Landlock ruleset descriptor and its per-rule lowering results. |
| `open_path_descriptor` | Resolves a grant path beneath a trusted root with `openat2` and returns an `O_PATH` descriptor. |
| `build_ruleset` | Builds the complete Landlock ruleset in the trusted parent, including filesystem, execute, and supported port rules. |
| `LandlockSandboxExecutor` | Namespace-free Linux executor that creates a fresh worker, passes only the ruleset descriptor, closes inherited descriptors, applies `restrict_self`, seccomp and limits, then imports the tool. |
| `EnforcementAdapter` | Protocol for exact assessment, conservative lowering, worker activation, and activation-evidence verification. |
| `AdapterPlan` | Opaque native plan digest and the exact obligation IDs assigned to it. |
| `ObligationAssignment` | One obligation's primary adapter and conservative support relation. |
| `EnforcementMode` | `ENFORCED` when all guarantees are active or `DEGRADED` after an explicit permissible waiver. |
| `EnforcementPlan` | Complete assignments, adapter plans, reductions, and canonical plan digest for one grant and host. |
| `NegotiationResult` | Fail-closed result containing either a complete plan or a precise denial reason. |
| `ExecutionContext` | Worker, process, boot, namespaces, credentials, cgroup, and broker epoch bound into activation. |
| `ActivationEvidence` | Adapter-signed statement that one native plan is active for one execution context and freshness window. |
| `ActivationReceipt` | Verified evidence bundle covering every assigned obligation before worker release. |
| `EnforcementCoordinator` | Verifies host evidence, negotiates exact obligations, lowers plans, and validates worker-specific activation. |

Mandatory policy modules return bounded typed restrictions on an `ALLOW`
decision; they never return Cedar source or another backend's policy text. The
framework attributes each restriction to the emitting module before passing it
to the configured backend.

| Name | Purpose |
| --- | --- |
| `RulePredicate` | Matches a bounded authority domain, operation set, selector relation, and immutable conditions. A subtree predicate may list `exempt_subtrees` and `exempt_paths`, matching only the selector minus those resources. |
| `SelectorMatch` | Selects any, exact, or canonical path-subtree matching for filesystem and runtime rules. |
| `ForbidConstraint` | Removes or soundly subtracts matching authority from the candidate grant. |
| `ForbidCombination` | Rejects combinations such as sensitive reads plus outbound communication. |
| `PolicyConstraint` | Union of the two accepted forbid-only constraint records. |
| `MandatoryPolicyBackend` | Replaceable filtering interface used by Cedar or another policy engine. |
| `CedarPolicyBackend` | Default fail-closed two-level backend. `optimization_level="no"` uses uncached individual Cedar checks for debugging, `"normal"` adds validation and exact-result caching, and the default `"aggressive"` returns typed denials directly and checks residual grants in one Cedar CLI batch. Missing engines, diagnostics, timeouts, or decision mismatches deny. |
| `TypedPolicyBackend` | Built-in fail-closed reference backend with broad-path subtraction, conservative rejection of unrepresentable differences, aggregate checks, and requirement revalidation. |
| `PolicyFilterResult` | Filtered no-broader grant, remapped requirement ledger, removals, and fail-closed diagnostics. |

A decision carrying constraints is denied with
`policy:constraints_require_host_executor` when no `host_executor` is configured,
because there is no grant to which the restrictions could apply.

`ResourceBoundary` is the shipped reference mandatory module built only on the
constraint interface above. See [resource boundaries](users/resource-boundary.md).

| Name | Purpose |
| --- | --- |
| `ResourceBoundary` | Module that turns a `ResourceBoundaryPolicy` into attributed filesystem and runtime forbids. It never transforms, escalates, or builds enforcement plans. |
| `ResourceBoundaryPolicy` | Operator policy: identifier, version, controlled `/**` scope, allowances, and forbidden selectors. Overlaps intersect; forbids win; unlisted paths in scope receive nothing. |
| `ResourceAllowance` | Maximum filesystem operations for one exact path or subtree inside the scope. |
| `resource_path` | Normalizes a policy selector with the `.slp` path grammar and the `realpath` argument normalizer. |

`ConfinementPolicy` builds AppArmor-style, tool-attached profiles on the same
forbid-only interface. It is framework policy rather than a Linux AppArmor
profile; native enforcement is still supplied by the configured host executor.

| Name | Purpose |
| --- | --- |
| `ConfinementDeny` | One named typed deny rule over a grant domain, operation, selector, and conditions. |
| `ConfinementProfile` | Versioned tool attachment with a default-deny path scope, path permission ceilings, and explicit deny rules. |
| `ConfinementPolicy` | Mandatory module that intersects every matching wildcard and tool-specific profile and denies unprofiled tools by default. |

Session IFC uses a conservative program-counter label: after a classified source
may run, the entire session remains at least that sensitive. This deliberately
over-taints model context and graph state so it does not depend on inference.

| Name | Purpose |
| --- | --- |
| `Confidentiality` | Ordered built-in lattice: public, internal, confidential, and secret. |
| `ToolFlowRule` | Operator-owned bound on everything an operation may read and optional maximum label from which it may cause an outward effect. It is a policy input, not evidence about hostile code. |
| `SessionFlowPolicy` | Atomically schedules operator-classified sources and sinks, guards named non-tool operations, and propagates labels across mediated session transfers. Classifications are assumptions unless validated by confinement. |
| `FlowStateStore` | Atomic label and execution-reservation storage keyed by authenticated user and session identity. |
| `MemoryFlowStateStore` | Thread-safe process-local implementation. |
| `SqliteFlowStateStore` | Durable SQLite WAL implementation that survives principal reconstruction and restarts. |

## Audit and observability

| Name | Contract |
| --- | --- |
| `AuditRecord` | One hash-chainable stage record: call index, tool, user and session IDs, argument hash, stage, module, verdict, optional execution outcome, reason, previous hash, and record hash. |
| `AuditSink` | Protocol requiring append, chain verification, external sealing, and seal verification. |
| `AuditSeal` | Signed commitment to a stream identity, retained record count, chain head, and issuance time. |
| `AuditWitness` | External signing and verification protocol for detecting valid-prefix truncation. |
| `HmacAuditWitness` | SHA-256 HMAC witness implementation; production deployments keep its key outside the audited process. |
| `MemoryAuditSink` | Thread-safe process-local hash-chained sink. Useful for tests and short-lived runs. |
| `SqliteAuditSink` | Thread-safe SQLite WAL sink using full synchronization and a SHA-256 chain. Call `close()` during shutdown. |
| `SecurityEvent` | Redacted policy observation with stage, module, verdict, reason, latency, identity, call index, and argument hash. |
| `SecurityObserver` | Protocol consuming `SecurityEvent` values. |
| `MemorySecurityObserver` | Thread-safe event collector with verdict counters. |
| `LoggingSecurityObserver` | Emits structured, argument-free records through standard logging. |
| `OpenTelemetrySecurityObserver` | Adapter for compatible tracer and counter objects without adding a hard OpenTelemetry dependency. |
| `langsmith_metadata` | Converts a `SecurityEvent` into redacted metadata suitable for a LangSmith run. |

Audit is decision evidence, not kernel evidence. The current records cannot show
that an allowed tool stayed within its declaration; see [implementation status](status.md).

## Inventory and escape analysis

| Name | Contract |
| --- | --- |
| `ToolInventoryEntry` | One statically discoverable tool, descriptor, DAC, graph path, source, and compile-time labels. |
| `ToolInventory` | Tuple of entries plus `complete`, which is false when dynamic sources prevent a complete static inventory. |
| `introspect` | Walks a compiled graph, nested wrappers, and registered guarded tools to produce a `ToolInventory`. |
| `EscapeKind` | Enum classifying unmediated nodes, unknown callbacks and calls, dynamic dispatch, unprotected compilation, retained capabilities, direct invocation, dangerous sinks, and undeclared effects. |
| `EscapeSeverity` | Finding priority enum. |
| `EscapeFinding` | Source path, location, kind, severity, symbol, enclosing function, taint flag, message, and stable fingerprint. |
| `TaintReport` | Immutable findings and parse errors. Its JSON form is used by CI tooling. |
| `analyze_source` | Scans one or more Python paths and optional exclusions for routes around tool mediation. |

The `langgraph-security-taint` command is the CLI over `analyze_source`. It exits
nonzero for findings or parse errors. Today it is an explicit CI command; wiring
it into `compile()` with audited exceptions is planned, not shipped.

## Placement, checkpoint, and host adapters

| Name | Contract |
| --- | --- |
| `MediatedCheckpointer` | Principal-bound checkpoint adapter that mediates reads and writes, authenticates contents and pending writes, and refuses administrative calls without principal authority. |
| `NodeKind` | Framework role used to choose the mandatory placement route for a node. |
| `NodeTrust` | Legacy operator-hosted versus isolated node classification; this is separate from language-sandbox tool admission. |
| `PlacementSpec` | Resolved node name, trust, kind, and audited promotion evidence. |
| `UntrustedNodeHost` | Protocol for a separate-process untrusted-node host with no coordinator capabilities. |
| `OutputApprovalRequired` | Withheld output carrying a redacted approval payload and single-use resume functions. |
| `WasiSandboxExecutor` | WASI execution adapter for grants representable by the configured WASI runtime. |
| `WasiToolSpec` | Immutable WASI module and entrypoint description. |

## Credentials, broker, and MCP adapters

| Name | Contract |
| --- | --- |
| `BrokerAuditRecord` | Redacted broker decision record for one credential request. |
| `BrokerSession` | Authenticated worker-side broker channel with explicit lifetime management. |
| `CredentialBroker` | Host-owned credential broker that binds requests to an activated worker grant. |
| `CredentialIssuer` | Protocol for issuing request-scoped credentials after broker authorization. |
| `GitHubAppIssuer` | GitHub App installation-token issuer used behind the credential broker. |
| `IssuedCredential` | Credential payload plus its expiration time and redacted kind. |
| `SpawnRecord` | Host-authenticated worker identity and confinement record used to open a broker session. |
| `StsSessionIssuer` | AWS STS session issuer used behind the credential broker. |
| `broker_request` | Worker helper for one authenticated credential request over the installed broker channel. |
| `McpServerSpec` | Immutable MCP stdio server command and environment declaration. |
| `McpStdioProxy` | Host-side MCP proxy that confines server startup and mediates calls. |
| `mcp_service_map` | Builds the service-to-tool mapping used for MCP policy validation. |

## Escape disposition

| Name | Contract |
| --- | --- |
| `WaiverDisposition` | Exact split of current findings into reviewed, unreviewed, and malformed or stale waiver entries. |
| `apply_waivers` | Applies exact source fingerprints and rejects stale, duplicate, or malformed waiver entries. |

## Constructive profile model

The profile objects are immutable. Most users call `parse_profiles` and
`ProfileDocument.evaluate`; policy generators and tests may construct the
lower-level records directly.

`ProfileSupport` is the per-profile/per-rule result returned by
`check_profiles`. The `slanggraph check --backend X profiles/` command uses the
same API and exits nonzero when an unsupported class lacks an explicit
class-level waiver and reason.

| Name | Contract |
| --- | --- |
| `Requirement` | Enum with `NEED` and `WANT`. Removing a need denies the call; removing a want records the loss and continues. |
| `SourceLocation` | Source name, line, and column for diagnostics and provenance. |
| `PathTemplate` | Absolute path template with variable binding and an optional terminal `/**` subtree. |
| `BoundPath` | Canonical absolute path plus subtree flag. `contains()` implements exact/subtree containment without filesystem resolution. |
| `FsRule` | Filesystem operations, path template, optional requirement, and source location. |
| `NetRule` | TCP `connect` or `bind`, a literal or bound port, optional requirement, and source location. |
| `ExecRule` | Executable path template, optional requirement, and source location. |
| `NamedRule` | Service or credential kind with immutable string attributes, optional requirement, and source location. |
| `ShareRule` | Filesystem authority shared with one user or role. |
| `Limits` | Optional positive CPU milliseconds, memory bytes, PID count, open-file count, and wall-clock milliseconds. |
| `ToolProfile` | Parsed tool-owned constructive policy: callers, scopes, run locus, delegability, syscall sets, resources, limits, and output class. |
| `PrincipalProfile` | Principal roles, scopes, resource envelope, credentials, and outbound shares. |
| `BoundFsRule` | Surviving filesystem operations and bound path with source provenance. |
| `BoundNetRule` | Surviving TCP operation and integer port with source provenance. |
| `BoundExecRule` | Surviving executable path with source provenance. |
| `BoundNamedRule` | Surviving service kind and bound attributes with source provenance. |
| `ConstructiveGrant` | Result of DAC intersection before mandatory policy and adapter lowering. `compile_grant` converts it to the platform-neutral final `Grant`. |
| `RemovedLine` | Resource class, need/want requirement, reason, and source for a candidate removed during intersection. |
| `DacEvaluation` | Constructive grant, removed lines, denial flag, and optional denial reason. |
| `ProfileDocument` | Immutable tool and principal maps. `evaluate()` also gathers applicable inbound shares and supports full operator overrides. |
| `ProfileSyntaxError` | Parse error carrying source, line, column, and message. |
| `parse_profiles` | Parses a complete `.slp` string into a `ProfileDocument`. |
| `evaluate_dac` | Low-level intersection of one `ToolProfile`, one `PrincipalProfile`, normalized arguments, principal bindings, and prefiltered inbound shares. |

Canonical path strings are a parser/evaluator invariant, not a TOCTOU defense.
Each enforcing adapter must resolve resource objects safely for its platform. The
Linux reference adapter retains path descriptors while bubblewrap constructs
the worker mount namespace. Other platforms may use different native object
identities behind the same contract.

`HostAttestation` is separate from both the final `Grant` and adapter set. It is
a fresh, authenticated inventory of capabilities and execution context on the
current machine. Execution fails closed when a grant requires a capability the
selected host cannot provide, even if another platform adapter implements it.

## Exceptions and fail-closed behavior

The package deliberately uses ordinary Python exception families at its
boundaries:

- declaration and profile construction errors use `TypeError` or `ValueError`;
- profile text errors use `ProfileSyntaxError`;
- principal preparation errors use `SecurityBindingError`;
- guarded runtime denials use `SecurityDeniedError`;
- required audit failures use `SecurityAuditError` before dispatch and `SecurityIndeterminateError` after dispatch; and
- `ToolNode` converts runtime denials into error tool messages.

Policy exceptions do not escape as authorization success. The stack attributes
them to the module, audits the failure when configured, and denies the call.

## Runtime-wide operator MAC

Trusted bootstrap calls `install_mac_policy(forbids)` before the first graph or
ToolNode execution in each controller interpreter. Installation is one-shot:
there is no replacement, reset, or per-graph opt-out. The policy is evaluated
on every Cedar object authorization and included in the resulting policy digest.
The legacy `cedar_security(mac_forbids=...)` and `CedarPolicySet.mac_forbids`
remain additional local restrictions, not the operator policy source.

The core sync/async Pregel entry points and direct ToolNodes gate execution.
Unsecured graphs, remote graphs, raw Pregel/functional programs, arbitrary Python nodes,
branches, wrappers, custom authorization backends, and enforcement waivers
are refused under MAC. Supported tool execution uses `ObjectPolicyHostExecutor`
with the object broker or admitted in-process resource monitor. Policies also
apply to graphs constructed before installation, and across threads and sessions.
Operator forbids are parsed independently of each graph's schema, so an
internet prohibition also works on graphs that declare only filesystem access.
Cedar parse or evaluation failures fail closed.

This boundary trusts controller code, callbacks, runtime services, and startup
configuration. It does not install an OS LSM or govern unrelated interpreters.
Every deployment controller must install the policy before accepting work;
untrusted Python controller code requires a separate OS security boundary.

For deployment-wide installation, put `mac.cedar` in a persistent directory.
The default is `/etc/langgraph`. Set `LANGGRAPH_MAC_DIR` in the deployment's
launcher or service environment to choose another directory:

```bash
mkdir -p "$HOME/my-deployment/policy"
cp workspace/09_no_internet/no_internet.cedar "$HOME/my-deployment/policy/mac.cedar"
export LANGGRAPH_MAC_DIR="$HOME/my-deployment/policy"
python3 workspace/09_no_internet/demo.py
```

Every controller launched with that setting loads the same policy automatically.
Keep the setting in the deployment launcher to retain it across shell sessions.
Relative directories resolve against the controller's startup working directory;
absolute paths are recommended. An explicitly configured empty or missing directory,
missing `mac.cedar`, or unreadable/invalid policy fails closed.
The default `/etc/langgraph` directory and policy must be root-owned. Custom
directories and policies may be owned by root or the deployment user. Neither
may be group/world writable, and symlinks are refused. Without a custom setting,
an absent default policy preserves normal operation.

The directory is selected at first policy load, not per graph or session.
Changing the environment afterward cannot replace the loaded policy, and
`install_mac_policy` cannot override it. Restart controllers after policy changes.
This trusts the deployment launcher and controller account; untrusted code must
run behind an OS boundary. Each container needs access to the configured directory.
