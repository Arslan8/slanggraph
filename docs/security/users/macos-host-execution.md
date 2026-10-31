# Experimental macOS host execution

`MacOSSandboxExecutor` is the first native implementation milestone of the
macOS portability experiment. It is disabled unless the operator explicitly
passes `experimental=True`. Closed graph admission continues to refuse this
new executor; it has not been added to a certified route allowlist.

**Known limitation (CPU qualification deferred):** the native evaluation on macOS build 25G332 found
that a syscall-heavy worker exceeded a one-second CPU limit in all five trials.
The current CPU `exact` classification is contradicted by that evidence.
Configured hard rlimits do not establish an effective aggregate CPU ceiling.
The experimental adapter remains unqualified; see the
[full evaluation](../../../eval/campaigns/macos-portability-v1/RESULTS.md).

The native guardian forks a worker into a separate process group. The worker
closes unrelated descriptors, inventories Mach rights, destroys unclassified
rights and verifies their removal. It retains explicitly declared task, thread,
host, bootstrap, clock-service and clock-semaphore baseline rights, plus
worker-local receive rights and self-task inspection rights. It applies hard CPU and descriptor limits
and a default-deny Seatbelt profile **before** loading `libpython` through
`dlopen`. It does not exec an interpreter after installing the sandbox.

Python starts with isolated `PyConfig`, explicit standard-library paths, no
`site`, ignored environment variables, no startup tool roots, and no bytecode
writes. A pinned trusted shim reports the challenge, limits and startup-right
inventory and waits for `GO`. The controller independently checks the worker's
PID/start time, sandbox-presence result (exactly 1), and receipt coverage. The
inventory digest is bound into the execution context.

## Build and configure

Use macOS, CPython and the Xcode Command Line Tools. The current build helper
selects `/Library/Developer/CommandLineTools/usr/bin/clang` and its SDK. It
compiles against the running interpreter's headers, loads that interpreter's
library dynamically, and writes a manifest recording source, launcher and
library digests. Build into a new operator-controlled directory:

```python
from pathlib import Path
from langgraph.prebuilt.security import MacOSNativeLauncher

launcher = MacOSNativeLauncher.build(Path("/absolute/new/launcher-build"))
```

The constructor requires the launcher and a protected recovery directory:

```python
from langgraph.prebuilt.security import MacOSSandboxExecutor, MacOSToolSpec

executor = MacOSSandboxExecutor(
    profiles,
    {"read_report": MacOSToolSpec("report:read_report", source, source_sha256)},
    launcher=launcher,
    recovery_directory=Path("/absolute/protected/recovery"),
    experimental=True,
)
```

Tool profiles must declare `runs macos`. Every reachable tool needs a manifest.
The source is measured and transferred as bytes; the worker never reopens the
original source or reads its bytecode cache. Imported dependencies and runtime
data must remain controlled by the operator. Primary library/source hashes do
not identify the complete runtime dependency tree. Disk-image runtime pinning
is not implemented yet.

The current profile parser defaults to `syscalls @minimal`; that obligation is
unsupported on macOS. The native pilot fixtures use the existing immutable
profile type to set an empty syscall-set collection explicitly. This is a test
fixture configuration, not a portable-profile language extension. The shared
Linux/macOS successful-workload criterion remains open; neither the parser nor
Linux's requirements were weakened to manufacture a passing comparison.

## Supported subset and evidence

The pilot supports read-only canonical existing files and directory subtrees,
plain synchronous and asynchronous JSON callables, descriptor limits, and
guardian-enforced wall deadlines. It configures CPU rlimits in whole seconds,
but their effective aggregate ceiling failed qualification on the tested build. Unknown conditions,
excluded subtrees, mutations, network/service grants, memory ceilings,
`@minimal` and delegation are refused. Optional-authority waiver paths are not
enabled. `assess_grant` emits classifications directly from the actual lowerer.

The runtime baseline includes explicit read and executable-mapping lines for
the selected Python runtime and system library roots, known retained Mach
rights (including libSystem's `clock_sem`, needed for `nanosleep`), protocol pipes and default limits. Mandatory typed constraints see
these baseline lines. Data grants receive only read-data and read-metadata
rules, never executable-mapping permission. Path semantics are live and do not
provide snapshots or object-provenance isolation against hard-link aliases.

The guardian receives an ARM acknowledgement before the controller releases
execution. It enforces an independent monotonic deadline and kills/reaps the
worker on controller-pipe EOF. The worker never inherits that liveness pipe.
The guardian remains outside the worker's process group. With process creation
denied, the guardian owns the only worker PID until waitpid, preventing PID
reuse while it may signal that child.

Before GO, the controller fsyncs a unique recovery record containing PID, start
time and boot identity. Confirmed reaping clears it; uncertainty retains it.
New executors reload records. `confirm_termination` only confirms absence of the
retained identity; it does not signal a reusable numeric PID. A surviving
guardian is a lifecycle premise. The current native source binds private
libSystem details such as `clock_sem` and requires per-build qualification. Guardian failure produces unknown cleanup and
requires operator recovery rather than accepting an outcome.

The executor uses existing grants, obligations, negotiation, activation receipts
and host-router interfaces unchanged. Recent receipts are bounded; use the
existing durable audit infrastructure for retention. Tests exercise actual
native confinement and controller SIGKILL, not simulated activation.

## Remaining portability work

This milestone does not establish production support or confinement
completeness. Outstanding work includes:

- A host-neutral process restriction and a successful shared-profile campaign.
- macOS transport for the pinned Lean decision core. The current loader uses
  Linux-only sealed memfds; no Python-checker fallback was added.
- Closed-route admission, source-bound route verification, and P3/P4/P5 audits.
- Operation-specific activation probes with validated native argument/result
  handling. Sandbox presence alone does not identify the installed profile.
- Full filesystem-root admission for cloud, network and TCC-protected locations,
  alias/mount/rename cases, and per-build baseline qualification.
- Immutable transitive runtime identity and the declared OS/architecture matrix.

Run the native pilot on macOS from `libs/prebuilt`:

```sh
uv run pytest tests/security/test_macos_execution.py
```

Native cases skip on other platforms. A skip supplies no native evidence.
