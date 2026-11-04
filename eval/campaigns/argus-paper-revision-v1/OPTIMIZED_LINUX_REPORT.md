# Final Linux object-broker runtime result

## Evaluated configuration

The final evaluated implementation is commit
`f76cbebf85c28cfef520cc779a2c180914808d44`. The measurement route is:

`ToolNode -> Cedar object authorization -> ObjectBrokerDispatcher -> prepared
single-use Landlock worker -> spawn-bound SQLite Records mediator -> result and
cleanup validation -> synchronous SQLite audit`.

All enforcement was enabled. The route retained exact structural prepared-worker
selection, fresh principal/call/argument/grant binding, resource mediation,
channel-to-grant binding, inline Lean grant/pre-execution/result checks, and
confirmed cleanup before result release. There were no pool misses, checker
subprocesses, fallbacks, or online policy re-lowerings in the measured calls.
The broker still uses the parent-bound Unix socketpair: the worker supplies no
principal or grant identity, and no network-style authentication was added.

The native checker was built with Lean 4.34.1:

- `libargus_worker_route.so` SHA-256:
  `c0ec5c5715bebea6c7e9eaacb59d78e76b336794c8224c4d4e140cd69ed4b153`
- `libleanshared.so` SHA-256:
  `6b30cc963d065fc9d2f87f7e9cbe0682b23000ae5425bccd769c5d477fa74f13`

The checker retains a parsed Lean `PreparedRoute` containing the stable binding
and certificate. Each gate supplies the fresh cumulative event trace to the same
`GrantCoverage.runCertified` or `ResourceGrantCoverage.runCertified` definition.
This is an interface and parsing optimization, not a replacement validator.

The library implementations, resource mediators, native shim, and generated
Lean executable are trusted to satisfy their contracts. The Lean model checks
the certificate and lifecycle definitions; it does not verify the source code
of those trusted implementations.

## Matched performance

The accepted run used Linux 6.17.0-1033-oem, Python 3.13.11, Landlock ABI 7,
and CPU 30. Its 30-second qualification observed 0.10% utilization on that CPU;
the host remains shared and dynamically frequency-scaled. Five independent
sessions each used ten warmups and twenty measured pairs, for 100 matched pairs.

| Steady-state statistic | Direct SQLite | Final Argus | Prior Argus reference |
| --- | ---: | ---: | ---: |
| Mean | 0.113 ms | 85.476 ms | 98.100 ms |
| Median | 0.109 ms | 82.797 ms | 94.914 ms |
| p95 | 0.151 ms | 140.808 ms | 152.940 ms |
| Standard deviation | 0.014 ms | 15.600 ms | 14.309 ms |
| Coefficient of variation | 12.23% | 18.25% | 14.59% |

Relative to the matched prior Argus configuration, final mean latency is 12.9%
lower, median is 12.8% lower, and p95 is 7.9% lower. The shared-host limitation
applies to both the absolute values and the comparison.

The final non-overlapping online mean breakdown reconciles exactly to
85.476 ms:

| Online work | Mean ms |
| --- | ---: |
| Cedar authorization | 0.975 |
| Invocation binding and activation, excluding listed Lean checks | 44.341 |
| Inline Lean grant check | 3.626 |
| Inline Lean pre-execution check, including certificate preparation | 1.460 |
| Worker transport, excluding resource and checker work | 24.022 |
| SQLite resource execution | 0.190 |
| Inline Lean result/cleanup check | 0.635 |
| Required worker release | 0.162 |
| Synchronous audit | 6.362 |
| Framework residual | 3.704 |

The compiled-check total fell from 14.692 ms to 5.721 ms (61.1%), audit fell
from 8.513 ms to 6.362 ms (25.3%), and binding/activation fell from 47.685 ms
to 44.341 ms (7.0%). Transport did not improve in this accepted shared-host run:
it increased from 22.578 ms to 24.022 ms. The reusable serving executor remains
in the final configuration because it removes per-session thread construction
without changing channel binding, but no transport-speedup claim is made.

The measured activation subspans include 0.043 ms prepared-worker selection,
0.443 ms grant construction, 4.466 ms mediator setup (including 3.798 ms
prepared-policy binding), 0.046 ms channel/thread setup, 4.829 ms certificate
construction, 0.695 ms receipt validation, 0.874 ms Lean certificate
preparation, 0.013 ms request encoding, and 0.074 ms worker-ready wait. These
subspans overlap where noted and therefore are diagnostic rather than an
additive decomposition.

Preparation remains outside invocation latency:

| Preparation item | Mean ms |
| --- | ---: |
| Load and pin inline checker/runtime | 531.692 |
| Construct dispatcher and reusable broker executor | 0.458 |
| Closed admission and policy setup | 341.918 |
| First confined worker and reusable host-plan template | 170.796 |
| Recurring single-use worker replenishment | 90.434 |

Recurring replenishment had median 90.398 ms and p95 93.661 ms. It can delay a
subsequent request and is not represented as one-time preparation.

## Audit contract

Synchronous audit uses three transactions per successful invocation: one makes
authorization and dispatch durable before execution, one makes activation
evidence durable after the effect, and one makes post/outcome records durable
before result release. Denials and standalone records remain immediately
durable. The final audit mean is 6.362 ms; no record, ordering, hash-chain, or
durability requirement was disabled.

## Security and application results

The native affected suite passed 337 tests with three host-dependent skips. The
retained adversarial campaign passed all 51 cases covering forbidden actions
and resources, identity substitution, stale or cross-invocation reuse,
execution before authorization, cancellation, controller failure, and cleanup
before release. The complete `make test` attempt reported 5,790 passed, 50
skipped, and 64 failures. Sixty-three failures require a bubblewrap user
namespace that this host cannot create. The other failure was a test expectation
that required natural exit even when confirmed single-use cleanup won the race
and delivered `SIGKILL`; that expectation was corrected and its targeted
regression passes. The optimized Landlock object-broker route and its native
tests were available and passed.

The reusable SQLite Records macro cohort ran 56 fixed trials. Its final
production route is host isolation: a prepared Landlock worker with a
spawn-bound SQLite mediator and inline Lean lifecycle checks. All three allowed
read/write/delete controls succeeded, all three policy-denied requests refused,
and all eight bypass/substitution cases produced zero forbidden resource
effects. Production-route mean was 467.975 ms and median was 583.489 ms; that
scope includes per-trial worker preparation and application setup. The existing
Pandas application route is `LinuxSandboxExecutor`, not this prepared
object-broker route, and its Ollama service was unavailable, so no Pandas result
is claimed for this run.

No macOS runtime campaign was run.

## Reproduction and retained evidence

Run the final configuration with:

```sh
eval/campaigns/argus-runtime-optimization-v1/reproduce.sh \
  /tmp/argus-runtime-optimization
```

The command builds and pins the native checker, requires a successful host
qualification before performance measurement, runs the matched microbenchmark,
the adversarial regressions, and the SQLite application cohort. Raw session
JSONL, accepted and refused qualifications, environment, preflight, compressed
application traces, and adversarial logs are retained under
`eval/campaigns/argus-runtime-optimization-v1/raw/`.
