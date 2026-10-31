# macOS native portability evaluation

**Review scope: CPU qualification deferred by the user.** All 125 non-CPU
attack observations passed, together with all 100 measured useful calls.
The frozen full campaign remains **125/130 passed**, with five CPU failures;
its verifier still reports failure. This is not a production, certified, or
full application-route qualification.

Run: `run-01`, macOS 26.7.2 / build 25G332, Apple M4 Pro arm64, CPython 3.13.1.
Base revision: `fc6d2aafff281611d101daa9951aeb354075a058`; branch `macOS`,
with all tested source bytes preserved in the run's content-addressed archive.

## Application-level parity has not been evaluated

**We have not run the same demos on Linux and macOS.** This campaign measures a
two-file calculation and native attack/control cases. Its sampling structure
resembles the Linux microbenchmarks, but the workloads, hardware, measurement
boundaries, and enabled protections differ. Its timings are not an OS performance
comparison. This is component-level portability evidence only.

| Evaluation | Linux | macOS |
| --- | --- | --- |
| 15-application dataset, 350 attempts | Run in the ordinary-demo campaign | Not run |
| Pandas case study | Attempted; latest protected cohort failed activation | Not run |
| Native confinement tests | Linux-specific tests | Separate macOS-specific tests |
| Complete admitted route with runtime Lean checks | Implemented | Not integrated |

See the [ordinary-demo results](../langgraph-demos-v3/RESULTS.md), the
[latest Pandas results](../pandas-matched-aggressive-v3-20261030/RESULTS.md), and
[requirements for a matched application campaign](APPLICATION-PARITY.md).
CPU qualification remains deferred independently of these application-route gaps.

## Observed results

| Check | Result |
| --- | --- |
| Fresh controller sessions | 5 |
| Measured useful calls | 100/100 exact expected outputs |
| Retained first-use / warmup calls | 5 / 50 |
| Paired unconfined primitive calls | 155, all outputs correct |
| Native attack/control observations | 125/130 passed; CPU case failed in 5/5 repeats |
| Receipt coverage and binding | Passed for all activated observations |
| Durable audit | 155 receipts; all five SQLite/export hash chains agree |
| Cleanup | Activated trials reaped; worker identities absent; recovery ledgers empty |
| Source hashes | Before/after inventories identical; archived bytes verified |
| Test gates | 237 passed, 53 skipped, one pytest warning |
| Oracle fault injection | 20 unit cases passed; 11 mutations of real records rejected |
| Lowerer census | 21 obligations: reports 13 exact, 8 unsupported; CPU exact claim contradicted |

The 26 cases per repeat include permission denials for reads, writes, process
creation/exec, local TCP and signal authority; authorized and denied aliases;
symlink escape; inside/outside hard links; descriptor exhaustion; CPU and wall
limits; typed policy denial; principal/artifact substitution; four receipt
faults; and a nonfinite response frame. Positive controls demonstrate that the
unconfined effect works and the protected worker can still perform useful work.
Authorized hard-link reads deliberately demonstrate pathname semantics, **not**
object-provenance isolation. This matrix does not exhaust every domain complement.

The native test gate also exercises cancellation, controller SIGKILL,
guardian reaping and persistent recovery-ledger reload. Those lifecycle tests
are separate from the five-repeat attack matrix. Skipped Linux-specific gates
are not credited as macOS passes.

## Deferred CPU result

Each CPU trial requested `cpu_ms=1000` with a separate 5000 ms wall deadline.
The worker completed its two-second `time.process_time()` loop and returned
success. The verifier rejects that observation even though later cleanup succeeds
and the recorded receipt validates. Cleanup's SIGKILL is not a CPU-limit witness.

The standalone syscall-heavy reproducer also exits successfully with soft/hard
`RLIMIT_CPU=(1,1)`, about 2.00 measured CPU seconds (0.77 user / 1.25 system in this
observation), and the default SIGXCPU disposition. A separate computation-heavy
loop terminates with SIGXCPU. These observations narrow the failure; they do not
establish its kernel root cause or behavior on other macOS builds.

See `run-01/cpu-syscall-reproducer.json`, `cpu-reproducer.json`, and all five
`cpu` records in `attacks/trials.jsonl`. The current lowerer must not be qualified
as enforcing an exact aggregate CPU ceiling based only on successful
`setrlimit` / `getrlimit`. A different enforcement mechanism or a conservative
refusal is required before qualification. No policy or test threshold was weakened
to turn the failed campaign green.

## Diagnostic timing on the failed configuration

Same sampling structure as the Linux campaign: five fresh controller sessions,
one first-use call, ten warmups, then twenty measured calls per session, each
paired with a direct primitive baseline. Confidence intervals use Student t,
df=4, over the five session means; individual calls are not independent replicates.

| Quantity | Mean (95% CI) |
| --- | --- |
| Protected end-to-end call | 64.68 ms (56.01–73.36) |
| Paired primitive | 0.08 ms (0.06–0.09) |
| Added latency vs primitive | 64.61 ms (55.95–73.27) |
| First use | 66.48 ms (60.25–72.72) |
| Preparation, typed policy, negotiation | 2.45 ms (2.23–2.67) |
| Native activation | 57.26 ms (49.06–65.46) |
| Worker execution | 1.58 ms (1.31–1.85) |
| Durable audit | 0.35 ms (0.25–0.45) |
| Cleanup | 2.93 ms (2.88–2.98) |

The additive ledger includes a measured residual and rejects overlapping phases.
Observation-wrapper and audit costs are included. Preparation is not a standalone
Cedar or Lean measurement. Native build and executor setup are retained separately.
CPU affinity is uncontrolled. The primitive is a tiny two-file calculation;
its ratio is not application overhead, and these numbers cannot support a
cross-host speedup claim against Linux. Timing on a failed security configuration
is diagnostic only.

## Coverage relative to the Linux evaluation

| Evidence category | Here |
| --- | --- |
| Frozen protocol, complete denominators, raw trials and source archive | Implemented |
| Native enforcement with positive controls, useful-output and cleanup oracles | Implemented, with CPU failure |
| Receipt/obligation binding and durable audit replay | Implemented |
| Session-level timing statistics and retained first-use/warmups | Implemented |
| Lean-certified route and P3/P4/P5 pipeline | Not run; Linux memfd transport, no local `lake` |
| Closed graph admission | Still refuses this executor |
| Cedar/full LLM/Pandas application cohort | Not run / unqualified |
| Shared successful Linux/macOS profile | Open: macOS fixtures explicitly omit unsupported `@minimal` |
| Cross-host equivalence and OS/architecture matrix | Not established |

The full `make test` could not start because Docker is absent; its log is retained.
`make format`, `make lint` (including type checking), and the focused test gates
passed. This is the same evidence discipline for the native component, not equal
coverage of the complete Linux system.

## Reproduce and inspect

From the repository root, use the prebuilt environment and a **new** directory:

```sh
libs/prebuilt/.venv/bin/python eval/remaining/macos_portability_campaign.py \
  --output eval/campaigns/macos-portability-v1/new-run
libs/prebuilt/.venv/bin/python eval/remaining/verify_macos_portability.py \
  eval/campaigns/macos-portability-v1/new-run
libs/prebuilt/.venv/bin/pytest -q eval/tests/test_macos_portability.py
```

The verifier exits **1** for `run-01`, with exactly five CPU failures.
`acceptance.json` summarizes the retained `run-01/verification.json`.
`run-01/checksums.json` indexes evidence bytes; this is an integrity aid, not a
signed provenance guarantee. Offline verification recomputes structural bindings
and audit hashes; signature validity is a recorded live-controller observation,
not independently reverified without the controller's ephemeral key.

The complete `run-01` evidence is distributed as [run-01.tar.gz](run-01.tar.gz),
with its SHA-256 in `acceptance.json`. Extract it beside this report to replay
the verifier. The bundle includes the frozen source archive, raw observations,
SQLite audits, checksums, test logs, and CPU reproducers. The native launcher in
the bundle is an observed build artifact; build a fresh launcher for new trials.

Raw run directories follow the repository's existing ignored-output rule.
Failed pilot directories remain local and are not included in the bundle:
`pilot-01` (ctypes import/positive control failure), `pilot-02` (probe API error),
and `pilot-03` (CPU failure plus JUnit classifier issue). `run-01` is the complete
campaign; failed pilot records were not edited to manufacture successes.
