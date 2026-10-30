# Lean worker lifecycle, grant, and receipt decision core

The synchronous Linux worker route can opt into an executable decision core
whose finite lifecycle and receipt-composition models are checked by Lean. The
implemented v3 protocol requires a grant-derived certificate before `GO` and
successful result release. It does **not** close whole-system SGV901–903: faithful Python projection, call
placement, observation provenance, executable correspondence, and OS enforcement
remain separate obligations.

## What is checked

[WorkerRoute.lean](../../proofs/worker-route/WorkerRoute.lean) contains 30 public theorems.
Its main result, `success_iff_exact_route`, characterizes success exactly as:

1. matching authorization with an allowed decision;
2. matching activation with supported enforcement and confirmed activation;
3. matching `GO`;
4. a matching, accepted result;
5. confirmed cleanup.

The binding includes principal, session, call, tool, artifact, grant, plan,
activation nonce, host digest, context digest, deployment, runtime, and worker
PID, start time, and boot ID. Each identity-bearing event compares the whole binding. Refusal is
permanent. Cancellation, unknown cleanup, a mismatched binding, unsupported
activation, or an unexpected event cannot lead to success. The useful trace is
accepted for every binding in the lifecycle model.

[ReceiptCoverage.lean](../../proofs/worker-route/ReceiptCoverage.lean) adds 24 public
theorems. Its executable `runCertified` requires both binding equality and exact
finite coverage: unique supported assignments, exact native-plan ownership,
one matching evidence row per adapter, and activated IDs equal to the assigned
and evidenced IDs. Waivers are unique and disjoint from assignments; their
presence determines degraded mode. Receipt mode and the ordered `removedWants`
list must equal the plan's. The model preserves useful arbitrary multi-adapter
partitions, including valid degraded cases. The selected Linux route continues
to require enforced, waiver-free activation.

The combined theorems characterize the exact pre-GO prefix and full successful
route, including certificate validity. Coverage concerns **assigned obligations**;
the v3 `GrantCoverage` model separately requires those assigned obligations to
equal one full-semantic row for every admitted grant rule plus all nine fixed
default-deny domain complements. It refuses missing, extra, duplicate, or
semantically substituted obligations, and the selected route requires the same
generated inventory in assignments, evidence, and activated IDs with no waiver.
This does not prove the earlier Python policy filter, grant provenance, digest
preimages, or Python-to-model projection.
All digests remain opaque strings. The CLI requires nonempty identities except
the optional deployment/runtime metadata, plus a bounded typed JSON message.
Neither identifier encoding nor the decoder has a refinement proof. See the
[proof project](../../proofs/worker-route/README.md) and
[receipt contract](lean-receipt-composition-plan.md) for the precise API and scope.

## Build a captured artifact

From the repository root, with the pinned Lean toolchain available through Lake:

```sh
python3 proofs/worker-route/check.py --output /absolute/path/to/new-worker-audit
```

The output directory must not exist. `--lake /absolute/path/to/lake` selects a
specific Lake launcher; `--timeout` bounds each subprocess. The script captures
the sources in a fresh directory, checks the `leanprover/lean4:v4.34.1` pin,
builds all three models and the executable there, and typechecks 72 fixed semantic
obligations in a generated `KernelAudit.lean`. These obligations check theorem
types, not merely the presence of theorem names. Additional typed construction
and projection witnesses check every binding and certificate record field,
arbitrary useful partitions, and concrete multi-adapter and degraded cases.
Five negative controls must fail at their expected type errors.
The audit records the required theorems' axiom
dependencies and accepts only Lean's listed standard axioms; it rejects missing
results and custom security axioms.

From `libs/prebuilt`, the equivalent component target is
`make security-verify-lean LEAN_REPORT=/absolute/path/to/new-worker-audit`.
Put the pinned `lake` launcher on `PATH` when it is not already available. This target does not
replace `make security-verify` or discharge its open system obligations.

Lean's own `leanchecker --fresh` must also replay the audit; missing replay
support fails the check. This is not an independently implemented verifier.
Source hashes before and after the audit must agree. Sources,
commands, logs, copied compiled artifacts, executable hash, and failure reports
are retained under the new directory; a failed observation is not overwritten.
The audit driver also has 20 self-tests for its parsing and refusal behavior,
run with `python3 -m unittest discover -s proofs/worker-route -p test_check.py`.

Use the fresh successful report to establish the proved source revision. Build
the inline library from that exact revision with `build_native.py`; its emitted
manifest pins the library, generated-code runtime, sources, and toolchain. A
report or manifest is evidence from that run, not a runtime authorizer or a
replacement for recomputation. Hashes identify bytes; they do not prove
compiler, linker, loader, C-shim, FFI, or decoder correctness.

## Select the synchronous route

The following wiring assumes `profiles`, `tool_specs`, `runtime_roots`, and
`policy_backend` are the application's existing operator-configured Linux
executor inputs. Run the captured audit successfully first and keep its output
under operator control.

```python
from pathlib import Path

from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.linux import LinuxSandboxExecutor

library = Path("/absolute/path/to/libargus_worker_route.so")
runtime = Path("/absolute/path/to/libleanshared.so")
checker = LeanLifecycleChecker(
    binary_path=str(library),
    binary_sha256="<sha256 from the native build manifest>",
    runtime_path=str(runtime),
    runtime_sha256="<runtime sha256 from the native build manifest>",
)
executor = LinuxSandboxExecutor(
    profiles,
    tool_specs,
    runtime_roots=runtime_roots,
    policy_backend=policy_backend,
    lifecycle_checker=checker,
)
```

The checker captures both selected regular files and verifies their SHA-256
digests. It loads them once from separate Linux `memfd` objects after installing
and checking write, grow, shrink, and further-sealing restrictions. Decisions
then call the narrow native ABI inline; they do not copy an executable, start a
process, or use a response pipe. Unavailable storage, unconfirmed sealing,
missing symbols, malformed output, or a refused transition blocks the
operation. There is no Python decision or writable-path fallback. The legacy
two-argument executable configuration remains supported for artifact replay,
but is not the optimized production path.

The request protocol is `worker-route-grant-v3`. Before attestation, a preflight
request with `kind: "grant"` must contain the detached admitted grant and compiled
obligation inventory and return `grant_ready`. Every route request must contain
`kind: "route"`, `binding`, `certificate`, and `events`; the certificate contains
the same grant and obligations plus the actual plan and receipt. The response must match that
protocol and schema 3. Missing certificates, old executables/responses, unknown
fields and enum values, duplicate decoded keys, invalid UTF-8 or surrogate
identities, extra input documents, and exceeded budgets refuse. There is no
fallback to the earlier boolean-only protocol. Requests are limited to 1 MiB,
depth 12, 256 entries per certificate array, and 32 events; identities are at
most 4096 Unicode scalar values. Exceeding a bound refuses the operation rather
than truncating its certificate.

The current executor calls the core after its existing startup, kernel-context,
and activation-receipt checks, and before writing `GO`. It projects the actual
plan and receipt through admitted native record slots, including deployment and
runtime metadata. The session stores detached binding, certificate and event
history as immutable JSON bytes and reconstructs fresh arguments for each check.
Both gates reuse that captured certificate. The alias regression exercises
caller mutation and an observing checker callback that mutates its received
arguments; neither changes the next check. This is bounded runtime evidence,
not a proof against controller/module rebinding or arbitrary same-process code.
After a valid worker response,
cleanup must return normally before the core permits result release. Unknown
termination raises and retains recovery evidence. A checker refusal after the
worker ran becomes `HostExecutionError` with an indeterminate outcome and
confirmed termination, rather than a pre-execution denial. Cleanup tracks the
current invocation's exception rather than a caller's previously handled error.

Cleanup now opens a pidfd before checking the recorded process start time and
signals only that handle. It requires process-exit readiness before confirming
termination; unavailable handle operations or ambiguous poll results remain
unconfirmed. The handle is acquired during cleanup, rather than retained from
activation, so the original PID/start-time observation and stable procfs remain
premises. This repair does not prove lifetime correspondence or descendant
cleanup. Resource descriptors also use `openat2` with full-component symlink
refusal; that does not freeze file contents, discover hardlink aliases, or prove
namespace stability.

This selected route supports synchronous invocation only. `ainvoke` refuses with
`host:lean_async_route_unavailable`; it does not fall back to the unselected
route. The model's cancellation theorems do not establish native async
correspondence. Omitting `lifecycle_checker` retains the previous route and its
previous proof status.

## Evidence and reruns

The current [v3 model audit summary](../../eval/campaigns/current-implementation-v1/lean-contribution.md)
passed all 72 required typed obligations, five negative controls, 20 driver
tests, and fresh Lean kernel replay with stable sources. It captures the binary
with SHA-256 `6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08`.
Its source, runtime, compiler, decoder, OS refinement, and system-complete flags
remain false. The earlier
[v1 audit](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-formal-v3/report.json)
is retained historical evidence; its binary is incompatible with the v2 bridge.

The current [bridge/integration run record](../../eval/campaigns/remediation-v2/raw/grant-integration-v1/grant-focused-final-v1.json)
and [test log](../../eval/campaigns/remediation-v2/raw/grant-integration-v1/grant-focused-final-v1.log)
record **349 passing tests** against the captured v3 executable, with stable
bridge/test sources and binary bytes. The checks cover certificate capture,
transport, malformed shapes, composition mutations, protocol refusal, and
caller/callback alias mutation. They are finite runtime regressions, separate
from the model proof and from actual native confinement tests.

The retained [cross-adapter scope probe](../../eval/campaigns/remediation-v2/raw/checks/receipt-cross-adapter-scope-v2/result.json)
used the separately identified development v2 executable. Crossed evidence
ownership refused. Consistently changing assignment owners, native-plan rows
and evidence rows while retaining the same opaque digest strings was accepted.
This demonstrates the boundary of the finite predicate: hash preimages and the
provenance of the projected signed objects are not established by string
equality. It is not evidence that production signature checks were bypassed.

An earlier v1 [focused integration log](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-runtime-integration-final-v3.log)
records 68 passing tests across the selected-route integration, cleanup-context,
review-checker, and existing lifetime tests. The selected-route cases execute the
compiled Lean binary and a real child using the startup/`GO`/result pipe protocol.
Activation is a fixture and uncertain termination is injected. This establishes
the exercised bridge behavior, not actual confinement for that child. The
[before-repair log](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-cleanup-before-v1.log)
retains two reproduced cleanup-context failures; the
[first integration pilot](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-runtime-integration-v1.log)
retains the unavailable-Python-API failures and a test fixture error.

To run the executable bridge and worker integration tests against a captured
binary, from `libs/prebuilt`:

```sh
LANGGRAPH_LEAN_WORKER_BINARY=/absolute/path/to/new-worker-audit/artifacts/workerRoute \
LANGGRAPH_REQUIRE_LEAN_WORKER=1 \
uv run pytest tests/security/test_lean_lifecycle.py tests/security/test_lean_linux_lifecycle.py
```

Required mode fails on a missing binary. Optional local runs may skip when the
binary has not been built; such a skip is not execution evidence. Runtime test
results are separate from the model audit.

The [security workflow](../../.github/workflows/slanggraph-security.yml) builds
the isolated audit with a checksum-pinned Lean distribution, then requires both
compiled-checker and native-route tests against that captured executable. It
retains sources, proof logs, executable and runtime test evidence. The workflow
has been inspected locally; this change has not been run on GitHub Actions yet.

Actual native tests are a separate opt-in suite. They exercise the selected
executor's real grant lowering, activation, bubblewrap worker, seccomp, receipt
validation, and cleanup without replacing those mechanisms with fixtures:

```sh
LANGGRAPH_LEAN_WORKER_BINARY=/absolute/path/to/new-worker-audit/artifacts/workerRoute \
LANGGRAPH_REQUIRE_LEAN_WORKER=1 LANGGRAPH_REQUIRE_LEAN_NATIVE=1 \
uv run pytest tests/security/test_lean_native_execution.py -s
```

This suite requires a host that can run the production bubblewrap configuration.
When explicitly enabled, missing support fails the run. Leaving it disabled
skips these native cases and provides no native execution evidence.

The current [v3 native validation record](../../eval/campaigns/current-implementation-v1/VALIDATION.md)
records **3/3 direct native cases passing** against the `codex-grant-lean-audit-v2`
executable: useful granted file access, denied undeclared file access, and denied
fork. A separate observer-assisted rerun also passed 3/3; its observer records
and delegates the checker subprocess call. Both observations retain stable
selected sources and binary bytes. The outer Docker harness ran as container
UID 0 with AppArmor, seccomp and system-path restrictions disabled; the actual
inner executor activated bubblewrap, seccomp and resource limits. These are
finite inner-worker observations, not confinement of the outer harness or a
native refinement theorem. The
[earlier failed selection](../../eval/campaigns/remediation-v2/raw/receipt-integration-v1/native-selected.json)
remains recorded: its actual command selected the incompatible v1 executable.

The historical v1 [native run](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-native-v5.log)
passed all three cases against the executable copied by the `formal-v3` audit:
a granted read returned its useful content, an undeclared file read raised
`FileNotFoundError`, and fork raised `PermissionError`. Each case recorded real
`ENFORCED` activation evidence and confirmed cleanup. The
[run record](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-native-v5.json)
retains the exact command, image ID, binary digest, source hashes, timestamps,
and stable-source check. The outer `slg-linux-test` Docker harness ran as
container UID 0 with AppArmor, seccomp, and system-path restrictions disabled
so the inner production bubblewrap boundary could activate. This is evidence
for those three inner-worker executions, not confinement of the outer harness
or a universal runtime guarantee.

Native setup pilots remain recorded separately: v1 failed before container
startup because of a UID mapping, and v2/v3 refused nested mounts introduced by
the test runner inside baseline-grant directories. v4 passed against the earlier
captured executable. The final v5 run did not replace any of these observations
or any historical application cohort.

Historical v1/v2 observations remain separate from the current v3 diagnostics.
The fresh [Pandas grant-v3 cohort](../../eval/campaigns/remediation-v2/raw/pandas-grant-v3-full-v1/verification.json)
retains the complete frozen denominator and passes 150/150 utility trials (50/50
in A, B, and C) against the exact audited v3 binary. Its verification record
binds seven worker implementation sources and five Pandas route/harness sources.
This is useful-path runtime evidence, not a security proof or a claim about the
outer vendor graph.

## Remaining boundary

The following must still be established for a production composition claim:

- Python imports, stable bindings, call placement, exceptional paths, and every
  effectful route, including outer-graph execution, correspond to the checked model.
- The certificate faithfully projects the negotiated objects; required grant
  obligations, `RuleEnforcement`, support claims, waiver authorization and digest
  preimages are correct. Adapter signatures, freshness and expiry remain actual
  Python checks outside this model.
- Authorization, lowering support, activation, identity, result acceptance,
  cleanup, and cancellation observations are truthful, complete, and ordered.
- Serialization, decoding, the Lean/C compiler chain, native loader, and deployed
  artifact preserve the checked definitions and inputs.
- Kernel namespaces, seccomp, LSMs, resource limits, and lifetime mechanisms
  enforce the claimed properties for the actual worker and relevant descendants.

This work provides no universal confinement or metadata-secrecy guarantee, no
publication or complete-mediation proof, and no persistent-container cleanup
proof. A fresh worker is not cleanup evidence. Existing unselected routes and
historical cohorts gain no new proof status from this component.
