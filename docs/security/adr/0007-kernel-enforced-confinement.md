# 0007: Enforce tool grants outside the Python process

Status: Proposed

## Context

The existing security layer mediates configured `ToolNode` and `guarded_tool`
calls. It does not confine an ordinary graph node, a tool implementation, a
native extension, or a child process. Once admitted, tool code has the ambient
authority of the framework process and may exceed its declared effects. A
benign path-handling bug is therefore enough to turn attacker-controlled tool
arguments into privilege escalation.

Python cannot repair this boundary from inside the same process. A Python
timeout cannot reliably stop running native or synchronous code, a descriptor
is only a claim about behavior, and wrappers do not mediate direct system calls.
The framework must authorize a concrete least-privilege grant and place
untrusted code in a security domain where the operating system or resource
owner enforces that grant.

This decision refines ADRs 0001, 0003, 0004, and 0006. Their hook framework,
ordering, private blobs, principal binding, approvals, auditing, delegation,
and fail-closed behavior remain. Where an earlier ADR treats the Python hook as
the enforcement boundary, this decision supersedes it.

## Trust model

Trusted components are the framework, operator node code, evaluator, broker,
kernel, backend implementation, and hook-placement gate. Untrusted components
are the model, every tool implementation, all input and retrieved data, native
tool dependencies, and every subagent.

Operator node code is trusted to implement application computation, but its
security-sensitive operations are still subject to the compile gate. An
exception requires a stable allow-list entry with an operator-written reason;
the exception is an audit record rather than an implicit assumption.

The Python layer authenticates, decides, audits, and dispatches. It is not the
resource enforcer. A denial still prevents dispatch, but an allowed tool's
filesystem, network, process, and resource consequences are bounded outside its
Python interpreter.

## Decision

Use one policy pipeline and three enforcement loci:

1. Local code runs in a fresh worker confined by a kernel backend before any
   untrusted tool module is imported.
2. Operations whose semantics or credentials cannot be represented by the
   kernel go through a trusted broker.
3. Remote operations use short-lived credentials whose remote permissions are
   no broader than the authorized grant.

The pipeline is:

```text
profile + principal envelope + shares
                  |
                  v
       constructive DAC candidates
                  |
                  v
      Cedar operator forbids, per line
                  |
                  v
        approval for surviving lines
                  |
                  v
         canonical, attributed Grant
             /          |          \
            v           v           v
         kernel       broker     resource side
```

Default deny applies at every stage. A backend that cannot enforce a required
rule class reports it instead of silently lowering the rule to something
broader.

## Constructive DAC profiles

The `.slp` profile grammar contains `tool` and `principal` blocks. This is the
only new policy syntax. Tool authors describe the resources and limits a call
needs; users describe their resource envelope, credentials, and shares. The
effective DAC candidate is:

```text
profile(tool, normalized arguments) ∩ envelope(principal) ∩ shares
```

Variables bind only to typed, normalized arguments. `need` lines deny the call
when their intersection is empty. Empty `want` lines are removed and audited.
Operator `dac_overrides` replace complete profile lines and are audited.

Undeclared tools have no callers, filesystem, network, executable, service, or
credential grants and receive only the minimal runtime syscall set. They cannot
run until an explicit declaration or operator override supplies authority.

DAC is constructive: it can only propose concrete authority owned by the tool
author or user. Cross-tool rules, information-flow labels, organization-wide
ceilings, escalation, and separation of duty belong to mandatory policy.

The profile grammar freezes after the profile parser and monotonic DAC evaluator
land. Property tests define monotonicity over set inclusion: reducing the tool
profile, principal envelope, or applicable shares cannot enlarge the resulting
candidate.

## Mandatory policy with Cedar

Cedar is the default mandatory-policy engine. OPA may be supplied behind the
same `Policy` interface by deployments that already operate it.

Each surviving DAC line is authorized independently. The evaluator creates one
ephemeral Cedar `permit` matching exactly that candidate line, combines it with
the operator-owned `forbid` set, and submits the typed domain, action, resource,
and call context. A line survives only when Cedar returns `Allow` and reports no
diagnostic or evaluation error. Any error denies that line. A removed `need`
line denies the call.

`forbid` always wins. Student modules may set labels and emit syntactically
validated `forbid` policies only. They cannot emit `permit`, alter the ephemeral
base permit, or contribute escalation policy. A module requests human review by
returning the existing `ESCALATE` verdict. The escalation policy set is
operator-owned and is consulted only after no mandatory policy forbids the
candidate.

Cedar's symbolic compiler is used offline to validate properties of operator
policy sets. It is not run as a per-request containment proof for module output.

Reference operator policy covers ceilings, per-tool confinement, typed-domain
compartmentalization, non-exfiltration, integrity, delegation depth, human
oversight, quotas, supply-chain manifests, backend attestation, separation of
duty, and audit requirements.

## Grant IR

An allowed call becomes an immutable `Grant`. It identifies the subject domain
as `(principal, tool)` and contains filesystem operations, TCP port operations,
executable authority, syscall classes, resource limits, broker service rules,
and provenance for every surviving line.

The IR does not treat a `realpath()` string as filesystem authority. Filesystem
lowering resolves an existing object relative to a trusted root with `openat2`
using `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, opens an `O_PATH` descriptor,
and supplies that descriptor as the Landlock rule's `parent_fd`. Create rights
are attached to the resolved parent directory. Display paths may be retained
for audit, but enforcement is compiled from descriptors.

The `Grant` type and Cedar request construction freeze together after the Cedar
integration lands.

## Backend capability contract

A backend reports its supported rule classes, compiles a `Grant` into a
`Sandbox`, and produces an attestation describing its enforcement features and
how they were detected. Before execution:

```text
missing = grant.classes() - backend.capabilities()
```

An empty set may run. A non-empty set denies with
`backend_cannot_enforce:<classes>` unless operator policy marks every missing
class `advisory-ok` for that subject. An advisory exception records the complete
`unenforced` set and attestation on every decision and execution audit record.

Lowering is conservative. A backend may implement a rule exactly, implement a
strict subset, or report the class missing. It may never implement a superset.
Property tests compare each backend's effective authority with its input
`Grant`.

The `advisory` backend enforces nothing and makes that fact conspicuous in trace
output. It exists for development and laptop compatibility, not as evidence of
confinement. The backend and audit contracts freeze after this capability
contract, advisory backend, and attestation path land.

## Linux kernel backend

The first enforcing backend targets Landlock, seccomp-BPF, cgroup v2, rlimits,
and a trusted supervisor:

| Rule | Enforcement |
| --- | --- |
| filesystem read, write, create, delete, execute, truncate | Landlock filesystem rights compiled from `O_PATH` descriptors |
| TCP `connect(port)` and `bind(port)` | Landlock network rights |
| UDP and raw sockets | denied by seccomp regardless of available Landlock ABI |
| syscall allow-set | seccomp-BPF resolved for the worker architecture |
| executable target | Landlock `EXECUTE`; seccomp only admits or rejects `execve` and `execveat` as syscall classes |
| fork, clone, signal, ptrace | seccomp, Landlock scoping where available, PID isolation, and Yama |
| CPU, memory, PIDs | cgroup v2 |
| open-file count | `RLIMIT_NOFILE` |
| wall clock | supervisor timer followed by pidfd or cgroup termination |

The backend queries `LANDLOCK_CREATE_RULESET_VERSION` and derives capabilities
from the returned ABI. It never infers Landlock features from a kernel release
number. TCP port rules require ABI 4 or later. Domain and destination-address
policy is not represented as Landlock network authority; it requires the broker
or an egress proxy.

The trusted parent creates a result pipe and broker socketpair, prepares the
cgroup, and forks the worker behind a synchronization barrier. The parent places
the worker PID in the cgroup before releasing it. The worker uses inherited
`O_PATH` descriptors to add Landlock rules, closes those rule descriptors and
every descriptor except the result pipe and broker socket, installs
`no_new_privs`, calls `restrict_self`, applies seccomp and rlimits, and only then
imports the untrusted tool. Because files opened before Landlock confinement
are not retroactively restricted, the clean descriptor table is mandatory.

The worker inherits only the result descriptor and its authenticated broker
descriptor. After confinement, seccomp denies `socket()` and `connect()` for
broker-only tools. The worker communicates over the inherited socketpair; it
does not create or connect a socket.

Landlock and seccomp restrictions stack and are inherited by permitted child
processes. They can only tighten local kernel authority. This is defense in
depth, not a replacement for evaluator and broker subset checks.

## Broker and remote enforcement

At fork time, the broker binds its socketpair endpoint to a spawn record
containing the principal, tool identity, `Grant` hash, and nonce. Worker
requests name only the desired broker operation and arguments. The broker
ignores any worker-supplied identity, grant, or claimed scope and re-evaluates
the operation against the spawn record and bound principal.

Credentials never enter the worker environment, filesystem, or descriptor
table. The broker holds credentials and mints a token no broader than the
service rule. Every mint performs an explicit child-subset check. Initial token
issuers are AWS STS role sessions with session policies and GitHub App
installation tokens restricted by repository and permission. The audit records
issuer, effective scope, expiry, grant hash, and request identity, but never the
credential value.

Named services such as mail recipients, chat channels, SQL statements, HTTP
domains, databases, browsers, and remote MCP servers are broker or proxy
operations. Remote tools that declare local rule classes fail the capability
contract unless operator policy explicitly permits advisory execution.

## Delegation and worker lifecycle

The evaluator and broker perform an explicit subset check for every delegated
grant and minted credential. A child must be no more authoritative than its
parent. Inherited kernel restrictions reinforce this property only for local
kernel resources.

The default is one fresh worker per call. If benchmarks require pooling, a
trusted template process with no untrusted tool code loaded forks a new child
for each call. That child tightens to the call's grant before importing the
tool. A reusable template is keyed by enforcement-envelope hash, subject, tool
artifact hash, and taint class. Arbitrary tool state never crosses subjects or
grant keys.

## Verified hook placement

Hook placement is verified rather than assumed. The source analyzer is a
compile gate for graphs built with `security=...`. Compilation fails when
model-controlled data can reach an unmediated sink, an unresolved call, an
unprotected execution path, or tool behavior absent from its declaration.

An operator may allow-list a finding only with a non-empty reason. Each entry is
matched narrowly, included in the graph's security fingerprint, and written as
an audit record at compile time. The framework's own findings must either be
removed or carry a justification suitable for publication.

This follows the authorization-hook-placement tradition established by Zhang,
Edwards, and Jaeger's static verification of complete mediation and Jaeger,
Edwards, and Zhang's consistency analysis of the relationship between hooks and
security-sensitive operations.

## Tool execution routes

The tool manifest selects the locus through its `runs` field:

| Tool form | Route |
| --- | --- |
| Python function or native extension | fresh worker under the kernel backend |
| CLI or subprocess | confined worker with Landlock executable authority |
| local MCP server | server envelope plus MCP proxy; strict mode starts a server per call |
| code execution | WASI or microVM backend |
| browser or computer use | confined launcher plus URL proxy |
| database | broker-selected database role and row-level security |
| HTTP API, SaaS, remote MCP | broker-held credential and resource-side token |
| non-Python runtime | language-neutral `slanggraph-exec` launcher |

Local MCP per-call narrowing is broker enforcement inside a kernel-enforced
server envelope. It does not claim that an already-running server's kernel
domain can be widened or reset.

## Audit and failure behavior

The audit chain records candidate lines, removed lines and policy identifiers,
normalization and descriptor-resolution failures, approval state, final grant
and provenance, backend capabilities, attestation, unenforced classes,
delegation subset results, broker requests, effective token scope, worker exit,
supervisor termination, and kernel denial evidence when available.

Failure to parse, bind, normalize, resolve, authorize, lower, attest, isolate,
or audit denies execution. No platform backend silently degrades. Policy hook
timeouts still deny the decision, but timeout of untrusted tool execution is
enforced by the supervisor rather than a Python thread timeout.

## Delivery and freeze

Phase one is five weeks and contains:

1. profile grammar and monotonic constructive DAC evaluator;
2. attributed `Grant` IR with descriptor-based path compilation;
3. Cedar integration and reference mandatory policies;
4. backend interface, capability contract, attestation, audit changes, and
   `advisory`; and
5. the Linux Landlock backend.

Broker custody, MCP proxying, the native launcher, a second enforcing backend,
and benchmark evaluation are phase two and are scoped after phase one.

The seven existing hook names and their invocation structure remain stable.
The course contract promises that modules return a verdict and may optionally
emit forbid policies. The detailed return type is not frozen until Cedar
integration. The profile grammar freezes after step 1; `Grant` and Cedar request
construction freeze after step 3; backend and audit contracts freeze after step
4.

## Consequences

Tool startup becomes more expensive and platform-specific. Correctness takes
priority over the provisional 1-to-3 millisecond estimate: the phase-one target
is less than 5 milliseconds of Landlock-backend overhead per call and less than
2 percent of an AgentDojo run, measured before pooling is considered. Advisory
mode retains the previous sub-millisecond decision target but provides no
resource confinement.

Profiles, normalizers, path resolution, backend feature detection, and broker
authentication become security-critical code. Operators must provision Linux
hosts with the required LSM, cgroup, namespace, and seccomp support. Portable
deployments must either select another enforcing backend or explicitly accept
advisory classes.

The architecture gains a defensible distinction between authorization and
enforcement: interface mediation decides what should happen, while the kernel,
broker, or remote resource bounds what can happen when tool code is buggy or
hostile.

## Non-goals

This decision does not claim confinement of model final text, domain-level
network policy without a broker or proxy, protection against kernel or backend
bugs, or enforcement by a remote service whose API provides no suitable scoping
mechanism.

## References

- Xiaolan Zhang, Antony Edwards, and Trent Jaeger. [Using CQUAL for Static
  Analysis of Authorization Hook Placement](https://www.usenix.org/legacy/event/sec02/full_papers/zhang/zhang_html/).
  11th USENIX Security Symposium, pages 33-48, 2002.
- Trent Jaeger, Antony Edwards, and Xiaolan Zhang. [Consistency Analysis of
  Authorization Hook Placement in the Linux Security Modules
  Framework](https://research.ibm.com/publications/consistency-analysis-of-authorization-hook-placement-in-the-linux-security-modules-framework).
  ACM Transactions on Information and System Security 7(2), pages 175-205,
  2004.
- Linux kernel documentation. [Landlock: unprivileged access
  control](https://docs.kernel.org/userspace-api/landlock.html).
- Linux kernel documentation. [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html).
- Cedar Policy Language Reference Guide. [Authorization](https://docs.cedarpolicy.com/auth/authorization.html).
