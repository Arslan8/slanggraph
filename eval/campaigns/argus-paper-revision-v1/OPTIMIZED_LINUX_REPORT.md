# Optimized Linux object-broker result

## Result and configuration

The optimized `ObjectPolicyHostExecutor` -> `ObjectBrokerDispatcher` route was
measured at implementation commit `32a85f4cd`. It retains Cedar authorization,
object-grant negotiation, grant checking, pre-execution checking, typed SQLite
mediation, result/cleanup checking, audit, and confirmed cleanup. It does not
subtract any work from the previously reported 373.781 ms measurement.

The accepted run used Linux 6.17.0-1033-oem, Python 3.13.11, Landlock ABI 7,
and CPU 29 on a shared, dynamically frequency-scaled host. The accepted
30-second qualification observed 0.13% utilization on that CPU and load-1 from
2.39 to 1.73. Two earlier qualification attempts are retained and marked
`otherwise_quiet: false`; they were not used.

The current native artifacts are:

- checker library:
  `proofs/worker-route/.lake/build/lib/libargus_worker_route.so`, SHA-256
  `9a57b42c4ce73a027f2341accd886b198bf8a316f97a6c0718b52f607871b90f`
- Lean runtime: Lean 4.34.1 `libleanshared.so`, SHA-256
  `6b30cc963d065fc9d2f87f7e9cbe0682b23000ae5425bccd769c5d477fa74f13`
- object-grant proof source `ResourceGrantCoverage.lean`, SHA-256
  `9720ba2cdbe838447700455ac707663b7b127721a969a7ab0c6bb79a8c690a23`

The preflight records all proof-source hashes and verifies the native manifest,
library, runtime, branch, and implementation-source cleanliness. The checker is
loaded and pinned once during preparation. Optimized mode requires an inline
checker and fails closed instead of falling back to executable invocation.

An earlier native library with SHA-256
`6723590136270fcf1bbe6851d5df6b8c4ea9ecbc8f4a23b34b86f057ad099bc2`
disagreed with the executable for object grants because its build
manifest omitted `ResourceGrantCoverage.lean`; it refused valid object grants.
It was rejected, rebuilt from the current proof sources, and was not measured.
The rebuilt inline and executable checkers agree on all five retained valid and
invalid certificate cases: running, ready, wrong nonce, missing assignment, and
early result.

## Preparation boundary

Five independent sessions each used one first-invocation pair, ten warmup pairs,
and twenty measured steady-state pairs. Preparation means, in milliseconds,
were:

| Preparation item | Mean ms |
| --- | ---: |
| Load and pin inline checker/runtime | 526.962 |
| Construct dispatcher | 0.410 |
| Closed admission, policy parsing, reusable decision logic | 333.009 |
| First confined worker and reusable host-plan template | 198.622 |

The worker is confined before it waits, but it has no grant, principal,
resource-serving thread, or executable authorization. At invocation, the route
authorizes the actual request, validates the prepared authority key, binds the
actual principal, arguments, invocation, grant, host plan, and activation, then
releases the worker. Workers are single-use. A replacement worker is prepared
synchronously after each call and therefore can delay the next request; this is
a recurring cost, not one-time preparation. Its mean was 92.089 ms, median
90.995 ms, p95 96.999 ms, standard deviation 5.809 ms, and CV 6.31%.

Policy, tool-artifact, runtime-root, resource configuration, or prepared-plan
mismatches refuse or explicitly invalidate the prepared worker. No path silently
reuses an incompatible context or pre-authorizes unknown arguments.

## Invocation results

| Boundary | Baseline | Optimized Argus | Difference / ratio |
| --- | ---: | ---: | ---: |
| First invocation mean (5 pairs) | 0.122 ms | 99.465 ms | +99.342 ms / 812.61x |
| Steady mean (100 pairs) | 0.113 ms | 98.100 ms | +97.987 ms / 865.56x |
| Steady median | 0.109 ms | 94.914 ms | — |
| Steady p95 | 0.146 ms | 152.940 ms | — |
| Steady standard deviation | 0.013 ms | 14.309 ms | — |
| Steady coefficient of variation | 11.44% | 14.59% | — |

The baseline operation, SQLite fixtures, correctness checks, and interleaving
are unchanged. All 100 measured pairs are retained.

The non-overlapping online mean breakdown reconciles exactly to 98.100 ms:

| Online work | Mean ms |
| --- | ---: |
| Cedar authorization | 0.804 |
| Invocation binding and activation, excluding listed checks | 47.685 |
| Inline Lean grant check | 3.497 |
| Inline Lean pre-execution check | 5.233 |
| Worker transport, excluding listed resource/check work | 22.578 |
| SQLite resource execution | 0.183 |
| Inline Lean result/cleanup check | 5.962 |
| Required cleanup | 0.179 |
| Audit | 8.513 |
| Framework residual | 3.465 |

Instrumentation observed inline checking in every session, one checker load per
session during preparation, zero checker subprocess calls, one reusable policy
lowering per session, no online repeat lowering, zero unexpected fallbacks, zero
re-preparations, and zero pool misses. All three required checker spans were
positive.

## Enforcement evidence

The affected Linux matrix was run through `make test` with the same checker
library and runtime as the performance run: 316 passed, one warning, in 33.31
seconds. It includes authorized Alice controls and forbidden Bob requests,
direct database/side-file and socket bypasses with independent resource-state
observations, missing or altered grant obligations, principal/invocation/grant/
activation binding errors, execution before authorization/activation, release
before cleanup, cancellation and worker/controller failures, and reuse across
principals and grants. Added regressions prove that optimized invocation creates
no checker subprocess and that changed policy or tool bytes do not consume or
execute an incompatible prepared worker.

The repository-wide `make test` was also attempted. Broader tests are not clean
on this host; the additional direct `LinuxSandboxExecutor`/`LinuxObjectDispatcher`
tests fail host preflight because bubblewrap user-namespace isolation is
unavailable. The source-review invariant tests pass. This host limitation does
not affect the measured Landlock `ObjectBrokerDispatcher` route, and it is not
represented as a passing whole-repository result.

## Application applicability

The Linux application and Pandas harnesses were inspected before deciding
whether to rerun. Pandas already selects the shared checker plus native runtime
and runs through `LinuxSandboxExecutor`, not the object-broker pool changed here.
The application cohorts that instantiate `ObjectBrokerDispatcher` retain the
default pool capacity of zero. The optimized pool is explicit opt-in, so neither
measured application path changed. Their existing matched cohorts, including
refusals and timeouts, remain applicable; no application correctness results
were substituted into a different timing cohort. No macOS campaign was run.

## Reproduction and evidence

Run the complete build, qualification, preflight, five-session measurement, and
summary with:

```sh
eval/campaigns/argus-paper-revision-v1/reproduce_optimized_linux.sh \
  /tmp/argus-optimized-linux
```

Raw session JSONL, accepted and refused host qualifications, exact environment,
preflight/example records, the reproducible summary, and security logs are under
`raw/linux-optimized-32a85f4cd/`.
