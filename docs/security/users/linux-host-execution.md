# Linux host execution

Use `LinuxSandboxExecutor` when a local Python tool is not trusted to honor its
descriptor. Authorization remains platform-neutral: `.slp`, mandatory modules,
and the final `Grant` do not mention bubblewrap or Linux. The executor is one
adapter that lowers supported obligations to Linux mechanisms.

## Prerequisites

The host needs Linux, bubblewrap, and `libseccomp.so.2`. Unprivileged user
namespaces must be available to the application account. Construction fails if
bubblewrap or libseccomp is unavailable. Construction also runs a real namespace
preflight and checks the exact bubblewrap features used by the launcher, so an
installed but unusable sandbox fails before the graph accepts traffic.

Put the callable imported by the worker in a module that is separate from the
trusted schema stub registered with LangGraph. The operator manifest binds that
module file by canonical path and SHA-256 digest.

```python
import hashlib
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    Principal,
    ResourceArg,
    SecurityConfig,
    dac,
    effects,
    parse_profiles,
    with_principal,
)

artifact = Path("/opt/research_tools/report_tools.py").resolve(strict=True)
artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

profiles = parse_profiles(
    """
tool read_report {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read ${path} need
  limits cpu 2s pids 1 nofile 64 wall 5s
}
principal alice {
  roles analyst
  fs read /srv/reports/**
}
""",
    source="security.slp",
)

executor = LinuxSandboxExecutor(
    profiles,
    {
        "read_report": LinuxToolSpec(
            "report_tools:read_report",
            artifact,
            artifact_digest,
        )
    },
    runtime_roots=(artifact.parent,),
)
security = SecurityConfig(
    dac_overrides=DacOverrides(profiles=profiles.tools),
    host_executor=executor,
)

@tool
@dac(owner="analyst", grants={"analyst": "x", "*": "-"})
@effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
def read_report(path: str) -> str:
    """Schema stub. The Linux executor never calls this body."""
    raise RuntimeError("in-process execution is forbidden")

node = ToolNode([read_report], security=security)
principal = Principal(
    "alice",
    frozenset({"analyst"}),
    frozenset(),
    "authenticated-session-id",
)
config = with_principal({}, principal, modules=security.modules)
result = node.invoke(tool_call_input, config=config)
```

The module at `/opt/research_tools/report_tools.py` exports the real
`read_report(path: str)` function. The schema stub and manifest key must have the
same tool name. Every tool reachable from a secured node needs a `LinuxToolSpec`;
missing manifests fail during configuration.

## What happens for each call

1. The normal DAC and mandatory-module stack authorizes normalized arguments.
2. The profile candidate is compiled into an immutable grant. Mandatory typed
   constraints filter that grant and requirements are rechecked.
3. Exact operation, selector, condition, default-deny, syscall, and resource
   obligations are negotiated. Any unsupported required obligation denies.
4. The verified artifact bytes are copied into a private launch file. Python
   starts with `-I -S -B`; runtime roots are not placed on its startup path.
   The trusted shim applies limits and seccomp before the parent releases it,
   and only then adds runtime roots and compiles the pinned source directly. It
   never consults a bytecode cache. A fresh bubblewrap worker receives only
   explicit mounts, an ephemeral `/tmp`, a clear environment, dropped
   capabilities, isolated namespaces, a default-deny seccomp allowlist, and
   resource ceilings.
   Each resource mount is opened by descriptor and its device, inode, and object
   type are revalidated against the authorized canonical path before release.
5. The trusted worker reports a parent challenge and plan digest only after
   installing limits and seccomp. The parent independently verifies the actual
   PID, start time, distinct namespaces, zero capability sets, `NoNewPrivs`,
   seccomp mode, single-thread state, mount-table digest, credentials, cgroup,
   boot identity, and adapter evidence. It verifies an activation receipt
   covering every obligation, then sends `GO`.
6. The worker imports the pinned module, executes exactly one JSON-serializable
   request, returns a bounded and depth-limited JSON result, and exits. Request
   and response frames are capped at 1 MiB. Tool stdout is retained only inside
   the worker's address-space limit, stderr is a bounded pipe, and protocol
   errors contain only an exception type. The supervisor kills a worker that
   times out or survives completion and confirms that its PID/start-time pair
   is gone before returning or releasing flow reservations.

Every successful or failed post-activation call writes the complete canonical
receipt into the normal hash-chained audit stream before its result is accepted.
With `SqliteAuditSink`, that evidence survives restart and participates in
external audit seals. Recent receipts are also available for operational access:

```python
receipts = executor.activation_receipts()
receipt = receipts[-1]
assert receipt.activated_obligations
assert receipt.context_digest
```

The snapshot is bounded to the most recent 1,024 receipts and is not an audit
archive. Production deployments must use `SqliteAuditSink` and retain externally
witnessed chain seals.

## Versioned OSTree tool deployments

Use `OstreeDeploymentManager` when executable identity must cover imported
helpers, packaged dependencies, and read-only tool data in addition to the
primary source file. The manager uses a local `bare-user-only` OSTree
repository, rejects symlinks and special files, normalizes bundle modes, and
publishes exact commits under immutable release refs. It retains all releases
and materialized checkouts; automated pruning is intentionally unsupported.

Each source tree contains `bundle.json`:

```json
{
  "format_version": 1,
  "tool_id": "demo",
  "entrypoint": "tool:run",
  "primary_file": "tool.py",
  "import_roots": ["."],
  "dependency_lock": "requirements.lock"
}
```

`dependency_lock` is optional. All paths are normalized relative POSIX paths.
The primary file, import roots, and optional lock must exist. Publication
rejects path traversal, duplicate or unknown manifest fields, symlinks,
privileged mode bits, devices, sockets, FIFOs, and a source tree that changes
while it is copied.

```python
from pathlib import Path

from langgraph.prebuilt.security import (
    LinuxSandboxExecutor,
    LinuxToolSpec,
    OstreeDeploymentManager,
)

manager = OstreeDeploymentManager(Path("/var/lib/slanggraph/tools"))
release = manager.publish_bundle(
    Path("./demo-bundle"), "tools/demo/releases/2026-10-18"
)
manager.update_channel("tools/demo/stable", release.binding.tool_commit)

executor = LinuxSandboxExecutor(
    profiles,
    {
        "demo": LinuxToolSpec.from_selection(
            manager,
            tool_id="demo",
            selection="tools/demo/stable",
        )
    },
    runtime_roots=(Path("/opt/slanggraph/runtime"),),
)
```

For every new physical call, the host selects the channel before policy
preparation and records the exact commit in the manager's operator-controlled
binding database. The approval subject includes that binding. Replaying an
approval, retrying the call, or restoring it after restart therefore recovers
the original commit instead of resolving the channel again. A different call
may select a newly published channel value.

The grant retains `artifact_digest` as the primary-file SHA-256 and separately
binds the full OSTree commit as `deployment_digest`. Both values are included
in activation receipts and durable activation audit evidence. The checkout is
mounted read-only by descriptor, and validated bundle import roots precede
operator-configured fixed runtime roots. Imported bundle files execute only
after the existing `GO` barrier.

The repository, checkout parent, and selection database must remain controlled
by the trusted operator account. Read-only modes and the worker's read-only
mount prevent worker modification, but they do not defend against a malicious
process with the deployment manager's own host identity. Production systems
should put that identity in a separate service account or privilege boundary.
Configure a durable graph checkpointer and reuse an operator-managed
`SecurityConfig.checkpoint_key` across restarts; the deployment database does
not replace checkpoint principal, session, and ancestry authentication.
The deployment regression suite interrupts a call for approval, closes its
SQLite checkpointer, moves the channel, reconstructs the manager, executor, and
graph, and verifies that the authenticated resume still executes the original
commit.

Remote ingestion is opt-in. `configure_remote` copies an operator-selected GPG
public key into the protected manager root, records its digest and immutable
remote URL, and configures OSTree commit verification. `pull_verified_release`
and `pull_verified_runtime_release` accept content only from such a remote,
request bare-user-only file checks, validate and materialize the fetched tree,
and create the local immutable release ref only after those checks succeed. A
checksum without this trusted publisher configuration is not accepted as
remote publication authority.

Cleanup is explicit and reference-aware. `release_invocation` removes one
completed principal/session/tool/call reference only when the supplied exact
binding matches. `retire_release` refuses to remove a release still named by an
invocation. `cleanup` retains every commit reachable from an OSTree ref or the
durable binding database, removes only other checkouts, and then asks OSTree to
prune objects unreachable from refs. Prepared, pending-approval, retried, and
suspended calls therefore retain their deployments until an operator declares
the invocation complete. Channel refs also retain their current target. The
executor additionally creates a durable `DeploymentLease` immediately before
worker launch. Normal confirmed termination releases it; indeterminate
termination retains it with the recovery record. `active_leases` lets an
operator reconcile those conservative records after supervisor restart, and
cleanup treats every leased commit as reachable even if an invocation or
release is finalized concurrently.

### Independently versioned runtimes

A runtime root contains `runtime.json`, the selected interpreter, its standard
library, native libraries, and explicitly required runtime data. The closed
manifest has `format_version`, `runtime_id`, a relative `interpreter`, and
relative `import_roots`. Runtime publication preserves only normalized
read-only or read-executable regular files and rejects symlinks, special files,
and privileged bits.

Publish it with `publish_runtime`, then pass the resulting
`RuntimeDeployment` and its manager to
`LinuxSandboxExecutor.runtime_deployment` and `runtime_manager`, optionally set
`runtime_selection` to a trusted runtime channel, and pass an empty
`runtime_roots` sequence. The manager resolves that channel before security
preparation and retains the exact runtime commit under the same
principal/session/call identity used for the tool deployment. At launch, the
executor mounts each committed
top-level runtime directory into the guest root by verified read-only
descriptor and starts the guest interpreter path. It does not mount host
`/usr`, `/lib`, or `/lib64` in this mode. The worker receives only the runtime's
declared guest import roots. Reserved mutable or kernel-backed roots such as
`/tmp`, `/dev`, `/proc`, and `/sys` cannot be supplied by a runtime; the adapter
creates its private `/tmp` and narrowly binds `/dev/urandom` itself.

The complete approval subject contains both the tool and runtime bindings. The
grant and activation receipt record the tool commit as `deployment_digest` and
the runtime commit as `runtime_digest`. The interpreter bytes are also measured
in host attestation. To update a runtime, publish and materialize the new
runtime release and move the trusted runtime channel with
`update_runtime_channel`. New calls select the new value. Prepared,
pending-approval, retried, and checkpoint-restored calls recover their original
runtime even when a restarted executor seeds itself from the moved channel.

The trusted worker shim remains operator code outside the runtime commit and is
mounted separately only after its digest is checked. Kernel enforcement
capabilities remain host evidence and continue through normal negotiation.

See [OSTree deployment measurements](../ostree-deployment-measurements.md) for
the initial A/B fixture costs and measurement boundary.

### Runtime integrity rechecks

`integrity_recheck` controls how a prepared Linux executor rechecks the
bubblewrap binary, Python interpreter, and worker shim when issuing fresh host
attestation:

- `IntegrityRecheckMode.FULL` is the default and hashes every complete file on
  every attestation. It preserves the original behavior.
- `IntegrityRecheckMode.MERKLE_SAMPLE` commits to position-bound file chunks
  during preflight, checks file size, and verifies fresh unpredictable chunk
  samples and their Merkle authentication paths on every attestation. Configure
  chunk size and sample count with `integrity_chunk_bytes` and
  `integrity_samples`. This is probabilistic detection: an unsampled same-size
  modification can escape one invocation's check.
- `IntegrityRecheckMode.PREFLIGHT_ONLY` hashes each file during executor
  preparation and performs no later content rehash. Fresh worker identity,
  kernel activation state, nonce binding, and signed activation evidence remain
  required, but content changes after preflight are outside this mode's
  detection guarantee.

The mode, chunk parameters, and Merkle roots are signed host evidence and are
part of the prepared-host identity. A runtime cannot silently claim a worker
prepared under another integrity mode. Use the weaker modes only when the
artifacts are supplied by an immutable deployment or another trusted mechanism
prevents post-preflight modification.

## Supported authority

The reference adapter currently supports:

- canonical existing files and directory subtrees mounted read-only;
- exact existing files mounted writable only when the grant includes every
  operation the mount exposes: `read`, `write`, and `truncate`;
- writable directory subtrees only when the grant includes `read`, `write`,
  `create`, `delete`, and `truncate`;
- `@minimal`, implemented as a default-deny syscall allowlist that excludes
  sockets, process creation, executable replacement, namespace changes, mounts,
  ptrace, kernel-key access, and similar escape surfaces; and
- CPU time, address space, per-file size, private `/tmp` size, process count,
  descriptor count, and wall-clock ceilings. Conservative defaults apply even
  when the profile omits limits; operators may replace the complete
  `default_limits` mapping when constructing `LinuxSandboxExecutor`.

Filesystem grants have live path-subtree semantics. A directory grant
authorizes matching children that exist or appear beneath that same mounted
directory object during the call; it is not a snapshot of initial descendants.
External processes permitted to mutate the backing object may do so, and the
worker observes those mutations. Canonical symlink-free selectors and stable
mount descriptors bind the mounted root object, but do not claim content
immutability. Deployments that need snapshot semantics must provide immutable
artifacts or a snapshotting resource adapter.

Selectors must name regular files or directories. FIFOs, sockets, device nodes,
and other special files require another adapter. A directory containing a
nested host mount is also rejected: each mount boundary needs its own explicit
grant. Existing descendant symlinks retain ordinary live-name semantics, but
can resolve only to objects separately visible in the worker namespace.

The writable-mount operation set is deliberately closed. A writable existing
file is accepted only with `read+write+truncate`; a writable directory subtree
requires `read+write+create+delete+truncate`. Narrower mutation sets fail
lowering. Rename, hard-link, symbolic-link, ownership, mode, timestamp, device,
and extended-attribute operations are absent from `@minimal` and therefore
denied. Authorization is path based; independently named hard-link or bind-mount
aliases are not treated as the same policy entity. Operators needing
object-identity policy must exclude such aliases or use an object-aware broker.

Profiles used by this adapter must declare exactly `syscalls @minimal`. Injected
state, store, or `ToolRuntime` arguments are rejected during configuration
because the worker protocol does not carry coordinator capabilities.

The adapter rejects rather than approximates network, HTTP, mail, database,
service, credential, delegation, and executable authority. Those operations need
a broker, service adapter, resource adapter, or another host backend that owns
their exact obligations. A future Windows adapter consumes the same grant and
obligations; applications and mandatory modules do not depend on bubblewrap.

## Runtime baseline and trust boundary

`/usr`, the trusted worker shim, the pinned artifact, every `runtime_roots`
entry, ephemeral `/tmp`, the exact cleared-environment values, parent protocol
descriptors, and default resource ceilings are explicit baseline grant lines.
Mandatory aggregate policy sees them. Interpreter, worker, bubblewrap, and tool
artifact digests are rechecked at dispatch. Keep runtime roots minimal: mounting
an application source tree makes that tree readable by the worker.

"Pinned tool" means the manifest's primary source file only. Runtime roots,
imported Python modules, native extensions, and runtime data are not included in
that artifact digest. They are mounted read-only and cannot initialize through
`PYTHONPATH`, `site`, `.pth`, or `sitecustomize` before confinement, but they may
execute after `GO` with the worker's granted authority. Pin a deployment image
or separately verify dependency artifacts when dependency identity matters.

## Production deployment checklist

A filesystem-only Linux deployment is supported when all of the following hold:

- the orchestrator, policy modules, profiles, schema stubs, and host executor are
  trusted and cannot be modified by the tool account;
- each untrusted entry point is a plain JSON-input/JSON-output Python callable
  with a pinned canonical source file and no injected LangGraph arguments;
- runtime roots contain only required code and data authorized for every tool
  that receives those roots;
- each flow classification conservatively includes all data readable through
  the tool grant, `/usr`, runtime roots, and the private runtime baseline;
- every requested operation fits the supported filesystem/resource subset;
  unsupported network, service, credential, executable, or delegation rules are
  allowed to fail closed;
- `SqliteAuditSink` is on protected storage and its chain head is periodically
  sealed with a separately retained witness key;
- `langgraph-security-taint` reports no unmediated effect path, and the original
  in-process tool aliases are not reachable; and
- deployment tests run on each kernel/distribution image used in production;
- the operator has selected explicit CPU, virtual-address-space, file-size,
  temporary-storage, process, descriptor, and wall-time ceilings for the
  workload. The adapter calls the `RLIMIT_AS` baseline
  `address_space_bytes` and the per-file `RLIMIT_FSIZE` baseline
  `file_size_bytes`. Profile `mem` requests remain `memory_bytes` and are
  rejected because this adapter has no RSS or cgroup-memory mechanism.

`cpu_ms` is accepted only in whole-second increments because the active
mechanism is `RLIMIT_CPU`. `tmpfs_bytes` is an aggregate ceiling for the private
ephemeral `/tmp`; `file_size_bytes` is a per-file ceiling and does not bound
aggregate persistent writable-storage consumption.

Within that boundary, this is a deployable enforcement implementation, not a
simulation. It is not a general-purpose container service or a substitute for a
network/service broker.

The schema stub, decorators, built-in normalizers, principal construction,
profiles, mandatory modules, policy backend, executor, bubblewrap, libseccomp,
and kernel are trusted. The entry-point artifact is not. The local attestation is
authenticated with an executor-private process key; it proves that this process
observed and activated this local worker, not that a remote or compromised host
is trustworthy.

Ordinary graph nodes, callbacks, model clients, checkpoint handlers, and an
unwrapped tool alias remain outside the host-execution boundary. Run escape
analysis in CI and mediate every effectful path. Session-flow policy is still
required when separate allowed calls could compose a sensitive read with a later
outward effect.
