# Security properties and composition boundaries

slangGraph separates four properties that must not be collapsed into a single
claim:

1. **Invocation authorization** decides whether a principal may request a
   concrete operation.
2. **Worker confinement** limits the authority one worker can exercise while
   that operation runs.
3. **Classified session scheduling** prevents configured sources and sinks from
   overlapping or running in an order forbidden by operator-supplied bounds.
4. **Intent integrity** establishes that an allowed operation is authorized for
   the user's current purpose, rather than merely inside the principal's maximum
   envelope.

An exact per-call grant proves only the first two properties. Classified
session scheduling requires an independently configured `SessionFlowPolicy`;
it is not inferred from descriptors, grants, or per-call decisions. It becomes
an information-flow guarantee only when configured labels bound everything an
operation can actually read and every outward effect is mediated or confined.
Neither mechanism proves safe model behavior or alignment with user intent.

## Complete-mediation composition model

The finite [Lean composition model](../../proofs/composition-route/README.md)
proves that every physical tool invocation reachable in its transition system
has first crossed either the route-selected language sandbox or the
route-selected resource mediator. An unclassified route cannot invoke, and
both classified routes have constructive successful traces.

This is a path-coverage theorem, not a monitor-correctness theorem. Production
use of the result requires a separate refinement argument showing that every
physical Python tool entry point follows the modeled transition system, that
route classification is exhaustive, and that no raw-callable or fallback path
exists. The theorem does not establish policy correctness, monitor internals,
runtime/compiler correspondence, or operating-system enforcement.

## Cross-call information flow and pooled authority

A read-confined worker can return sensitive data to graph state and a later
network-confined worker can transmit it. Parent-child subset checks likewise do
not prevent siblings from pooling authority through checkpoints, messages,
files, IPC, or the orchestrator.

`SessionFlowPolicy` implements a coarse session program-counter label for every
call mediated by the same configured `ToolNode` and `guarded_tool` trust domain.
The operator must classify every reachable operation with a possible-read label
and optional outward-effect ceiling. `output_label` is retained as the API name,
but must bound all information the operation can read, not merely what it claims
to return. `sink_ceiling` covers effects during execution as well as returned
data. Before a parallel batch fans out, the framework atomically
joins every proposed source label into durable state keyed by authenticated user
and session. Each sink then checks that accumulated label. This deliberately
overtaints: a denied or unused source in a parallel batch may still raise the
session label, but a sink cannot win a race against a source. The SQLite store
preserves labels across reconstructed principals, checkpoints, and process
restarts. Atomic source/sink reservations also prevent separately invoked graphs
or workers from overlapping an incompatible source with an already-running
egress operation. A source-and-sink operation joins its possible reads before
checking its own sink ceiling. A crashed sink reservation fails closed until it
is released or repaired by the operator.

The implemented reservation lasts through the mediated physical call, post
hooks, and outcome audit. The Linux reference worker cannot create descendants
or background processes under its default-deny syscall policy and is killed at
call completion. The language-sandbox path does not supervise descendants or
background work; such work is forbidden in that protected model. A future
adapter that permits descendants must retain both reservation and confinement
lease until every descendant exits.

Session identifiers are not declassification tokens. `transfer_session()`
atomically joins the source label into the target before a mediated checkpoint,
artifact, or inter-session copy. A copy that bypasses this operation is outside
the protected model. Only trusted application code may create security sessions
or authorize deliberate declassification.

This is a scheduling guarantee over operator classifications, not by itself
proof of noninterference against hostile tool implementations. Source-admitted
language programs can call only modeled, mediated terminals; correctness of
those terminals and their declared information-flow contracts remains required.
General Python in the coordinator is outside this language-sandbox guarantee. For the Linux executor's supported
subset, the effective filesystem inputs, no-network/no-process baseline, and
runtime roots are kernel-bounded and must conservatively validate the configured
label. Unsupported outward authority denies. Model requests, tracing, telemetry,
callbacks, renderers, and artifact handlers are sinks too. Route each through
`guard_operation()` with a rule or treat it as an explicitly trusted
destination. Static inventory and escape analysis are diagnostics; they cannot
prove arbitrary Python has no unmediated effects outside the worker boundary.

## Untrusted results and confused deputies

Every tool result is untrusted, including structured objects, paths, URLs,
commands, markup, artifact references, callback payloads, and checkpoint data.
Trusted observers, renderers, stores, model clients, artifact handlers, and
callbacks must not interpret a result as authority.

Any framework-generated external action derived from a result is a new security
operation. It must receive a fresh normalized intent, grant, policy decision,
enforcement plan, and audit transaction under the originating security context.
Code that performs such an action without mediation belongs to the TCB and is a
confused-deputy vulnerability. Merely escaping or validating a value is not a
substitute for authorization.

## Resource identity and time of use

Each selector declares one resolution mode:

- **stable object**: lowering resolves and verifies an object identity, retains
  a race-resistant handle, and enforces use through that handle;
- **dynamic name**: the enforcing broker resolves the name and reauthorizes the
  resolved identity at every operation boundary.

An adapter may not authorize a pathname, alias, group name, DNS name, or service
label at decision time and later use an independently resolved object. If the
platform cannot retain or revalidate the binding, exact lowering is unsupported.

## Preparation is a separate execution

Built-in pure normalizers are TCB code. A custom transformation receives its own
minimal preflight grant, with no ambient resource or service authority unless an
operator explicitly authorizes it. Its output is untrusted.

The main request must remain no broader than the request presented to preflight,
not merely within the principal's envelope. Strings, paths, mappings, and sets
do not carry a generic authority ordering. The implemented in-process
`TRANSFORM` path permits non-resource rewrites only when normalized authority is
identical. A resource-changing transformation must use the typed grant algebra
and a framework-owned semantic attenuator comparing actions, normalized resource
sets, conditions, and task constraints. Until that path is wired into execution,
such a transform denies. The transformed request still passes normalization,
DAC, and mandatory policy again.

## Runtime baseline ownership

Runtime authority is an operator-owned request, not an adapter entitlement.
Adapters may report missing requirements, but may not add them to a grant.
Baseline lines are non-waivable `need` rules, pass through mandatory and
combination policy, participate in delegation comparisons, and receive the same
closed-world obligations and activation evidence as tool-requested authority.
An insufficient baseline denies execution.

Declared effects and descriptors are also requests and optimization hints. They
are not proof of what hostile code can do. Mandatory combination checks use the
complete effective grant, including baseline authority and authenticated
channels. Native confinement, not an author declaration, establishes that
unlisted effects are unavailable.

For the source-admitted language-sandbox Cedar path, [source admission](manifest-consistency.md)
separately requires statically resolved monitored APIs and `inferred effects ⊆ manifest`. Inference overapproximates possible effects; it never grants them.
Every attempted resource effect must still pass its monitor against the final
grant. Unmonitored libraries, reflection, and dynamic code are rejected rather
than admitted for runtime tracing. This function-body contract does not certify
module initialization or importing untrusted dependencies into the coordinator.

Degradation never means retaining authority while waiving its restriction. An
optional `want` that cannot be enforced is removed. If an advisory obligation is
waived, the execution is `DEGRADED`, carries the conservative effective-authority
upper bound, and receives no grant-subset or confidentiality claim. Flow labels
must be computed from that upper bound; if it is unknown, no ordinary label can
justify an outward effect.

## Revocation and irreversible effects

An activation receipt proves a bounded startup condition. Revalidation detects
stale evidence but does not itself withdraw authority already issued.

- Brokers check live grant and lease state at each request and revoke credentials
  or channels when a lease ends.
- Local supervisors terminate or quarantine workers and descendants when a
  required lease is lost. Race-free revocation requires platform support.
- Open files, accepted remote requests, emitted messages, and other committed
  side effects may be irrevocable. Each adapter documents its commit point.
- After a commit point, cancellation means “stop further effects,” not rollback.

The audit outcome is `INDETERMINATE` whenever the framework cannot establish
whether an irrevocable operation crossed its commit point.

## Authority is not purpose

A principal envelope states maximum authority. It does not prove that an
operation is appropriate for the current task. Consequential operations require
task-scoped authority issued by a trusted application boundary and bound to the
principal, artifact, normalized concrete parameters, policy version, expiry,
and replay rules. Human approval is one possible issuer; model text and tool
output are not.

Even with exact confinement, a compromised model can maliciously select an
allowed file, recipient, or query. slangGraph must claim that such an operation
was exactly authorized and confined—not that it was beneficial, intended, or
safe—unless task-specific authority independently establishes that property.
