# `fixed-weather` and `parallel-weather` language-route overhead

This investigation uses the repository workload names and implementations in
`eval/apps/demos/tool_calling_protected.py`. `fixed-weather` makes one
constant-returning call to `get_weather("San Francisco")`.
`parallel-weather` makes that call plus one constant-returning call to
`get_coolest_cities`. Neither workload invokes a model or performs external
I/O.

## What these workloads do and do not represent

These are local `ToolNode` microbenchmarks, not MCP or legacy-server
benchmarks. They resemble the *shape* of invoking a registered backend
operation, but the tool implementations are ordinary local Python functions
that immediately return constant strings. There is no MCP client or server,
transport, process boundary, network request, credential, backend parsing, or
resource access in the measured operation.

That distinction creates an enforcement gap in the comparator result. Argus
authorizes each logical tool call, checks the admitted language program, binds
the current invocation, and mediates result release. APF and NoNo enforce OS
effects. Since these two functions perform no OS-visible effect, APF and NoNo
have effectively nothing application-specific to mediate after activation.
Their near-Baseline result therefore does not show equivalent enforcement of
the logical tool-call policy.

The comparison is still useful as a worst-case fixed-cost microbenchmark, but
it must not be described as an MCP-server comparison or as evidence that the
systems enforce the same property. A real legacy service behind MCP would add
transport and backend work and would require either a mediated registered
client operation or host enforcement of its process/network/resource effects.
Those costs and checks are intentionally absent here.

## Evaluated configuration

- Base revision: `b544949050a42a24e54ea1470659b7c0f68be972` (`wip`).
- The exact tracked runtime/test diff used for the measurements is retained as
  `raw/runtime-final/relevant.diff`; its SHA-256 is recorded in
  `raw/runtime-final/aggregate.json`. The evaluation scripts and raw records are
  retained in this artifact directory.
- Host: Linux 6.17.0-1033-oem, x86-64; Python 3.11.14; Cedar 4.5.
- Audit disabled. Operator MAC installed. Principal `alice`, with a fresh
  session ID and fresh tool-call IDs for every invocation.
- Thirty independent processes per workload and mode. Each process measures
  preparation, its first invocation, then 20 invocations of the same prepared
  graph. P95 is nearest-rank. Mode order alternates by process index.
- Every Argus process asserted the exact `_LanguageSandboxDispatchers` route
  and admitted tool inventory. Every invocation asserted correct output and a
  newly issued grant carrying its fresh call ID. There was no host fallback.

## Runtime-only latency results

The primary result excludes preparation, policy compilation, sandbox
activation, process startup, the first invocation, and cleanup. Each cell
pools 600 unprofiled runtime invocations from 30 independent processes. The
graph remains prepared, while Argus binds a fresh principal session, call ID,
and grant on every invocation.

| Workload | Mode | Runtime mean/median/p95 | Mean delta from Baseline |
|---|---|---:|---:|
| `fixed-weather` | Baseline | 1.540 / 1.402 / 2.430 | — |
| `fixed-weather` | Argus language | 2.724 / 2.672 / 3.727 | +1.184 ms (1.77x) |
| `fixed-weather` | NoNo | 1.618 / 1.443 / 2.500 | +0.078 ms (1.05x) |
| `fixed-weather` | APF | 1.660 / 1.509 / 2.577 | +0.120 ms (1.08x) |
| `parallel-weather` | Baseline | 2.001 / 1.936 / 3.068 | — |
| `parallel-weather` | Argus language | 3.957 / 3.895 / 4.866 | +1.956 ms (1.98x) |
| `parallel-weather` | NoNo | 1.966 / 1.811 / 2.955 | -0.035 ms (0.98x) |
| `parallel-weather` | APF | 2.006 / 1.838 / 3.016 | +0.005 ms (1.00x) |

The tiny negative NoNo delta is ordinary measurement noise, not a speedup.
The semantic gap described above matters: Argus authorizes one or two logical
tool calls, while the constant-returning tools exercise no OS effect for NoNo
or APF to mediate.

Preparation and the first invocation remain diagnostics only:

| Workload | Mode | Preparation mean | First mean/median/p95 |
|---|---|---:|---:|
| `fixed-weather` | Baseline | 0.912 | 3.774 / 3.800 / 4.537 |
| `fixed-weather` | Argus language | 115.244 | 15.676 / 15.640 / 17.336 |
| `parallel-weather` | Baseline | 0.977 | 4.206 / 4.140 / 4.791 |
| `parallel-weather` | Argus language | 123.216 | 17.393 / 17.379 / 18.334 |

Raw Baseline/Argus records and exact commands are under
`raw/runtime-final/`; comparator records are under
`raw/comparator-runtime-final/`.

## Root cause and fix

Before this change, a first `fixed-weather` invocation launched six Cedar CLI
processes: two immutable schema/policy validations, one parse of the immutable
operator policy, and three request-dependent authorization decisions. A first
`parallel-weather` invocation launched twelve. Its two executor threads raced
through separate authorizations and each repeated the common immutable
validation and operator parse.

The shared `CedarObjectAuthorizer.prepare()` path now validates the immutable
schema and owner/envelope/MAC policies and parses the currently sealed operator
MAC during trusted graph preparation. `cedar_security` and
`cedar_security_many` call it before returning the security configuration.
Validation cache keys still contain the Cedar executable identity; replacing
the executable invalidates prepared results and restores fail-closed runtime
validation. A validation lock single-flights cold validation after such an
invalidation. Retained diagnostic authorization bundles are not polluted with
synthetic preparation attempts, and a missing Cedar executable is still
refused at authorization.

After the fix, preparation launches three Cedar processes for `fixed-weather`
(two unique validations and one operator parse) and four for
`parallel-weather` (three unique validations and one operator parse). The
first invocation launches only the three request-dependent authorization
processes per tool. Steady invocations use the exact structural authorization
cache but still bind a new grant to the current call ID and run the admission,
grant, dispatch, result, and MAC checks.

No source inspection, Python parsing, manifest construction, policy
validation subprocess, operator-policy parsing subprocess, or module
initialization occurs in steady invocation. The dispatcher still executes
ordinary cached import statements, which resolve already-loaded modules and
are included in the lifecycle measurement. The diagnostic counters show
source inspection, Python parsing, manifest parsing, and Cedar validation only
in preparation.

`graph.invoke()` previously mediated every internal stream chunk even though
those chunks never leave the invocation collector. The final implementation
mediates the returned value once when auditing and custom output hooks are
absent. Public `stream()` still mediates every emitted item; audited,
observed, redacting, denying, and escalating configurations retain their
per-emission behavior. Existing callback and output-policy regression tests
cover both sync and async paths.

## Diagnostic breakdown

These are single profiled diagnostic invocations, not the final latency
numbers above. Intervals are partitioned by wall-clock occupancy, including
thread overlap, so every row reconciles exactly to its end-to-end total.

| Workload / phase | Graph dispatch | Tool dispatch / synchronization | Authorization | Serialization / copying | Interpretation | Receipt | Lifecycle / cleanup | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `fixed-weather` first | 2.824 | 1.726 | 9.781 | 0.107 | 0.114 | 0.019 | 0.301 | 14.872 |
| `fixed-weather` runtime | 1.707 | 0.594 | 0.295 | 0.024 | 0.108 | 0.020 | 0.225 | 2.974 |
| `parallel-weather` first | 2.664 | 1.527 | 12.601 | 0.243 | 0.062 | 0.016 | 0.243 | 17.356 |
| `parallel-weather` runtime | 2.013 | 0.609 | 1.949 | 0.066 | 0.068 | 0.015 | 0.290 | 5.010 |

The first `parallel-weather` tool host spans ran on two distinct threads and
overlapped: weather from +3.170 to +15.524 ms and coolest-cities from +4.102
to +16.365 ms relative to invocation start. The shared executor therefore did
not serialize authorization. The sub-millisecond language dispatches followed
their respective authorization completions; their offset is not material
waiting, and the final unprofiled p95 does not show a concurrency stall.

Full event traces and operation counts are retained under `raw/diagnostic/`.

## Why the two older cohorts differ

The older main application cohort and comparator cohort used the same source
digest, disabled audit, the language route, the same application timer, and
five fresh-process repetitions, but evaluated different commits. Their exact
samples are copied with source artifact paths into `historical_cohorts.json`.

| Cohort | Workload | Baseline mean | Argus mean | Argus median | Argus samples |
|---|---|---:|---:|---:|---|
| Main applications (`bd035dd0`) | `fixed-weather` | 3.947 | 28.244 | 28.966 | 28.966, 29.660, 29.931, 27.122, 25.542 |
| Comparator (`c976a207`) | `fixed-weather` | 3.818 | 29.028 | 28.259 | 26.928, 30.283, 27.980, 31.690, 28.259 |
| Main applications (`bd035dd0`) | `parallel-weather` | 3.894 | 27.313 | 27.176 | 28.204, 27.175, 27.178, 26.479, 27.532 |
| Comparator (`c976a207`) | `parallel-weather` | 4.172 | 42.111 | 30.610 | 35.303, 27.671, **87.021**, 30.610, 29.952 |

The reported 42.111 ms comparator mean is caused by one 87.021 ms sample in a
five-sample cell. That same process also had anomalous 291.203 ms preparation
and 1460.050 ms process wall time, versus roughly 107-114 ms preparation for
the other comparator repetitions. The comparator median is 30.610 ms. Thus
there is no separate 42 ms `parallel-weather` execution configuration to
explain; it is a small-sample outlier on top of the same cold-validation path.
Each cohort's Baseline and Argus values remain paired within that cohort.

## Reproduction

From the repository root:

```bash
eval/.venv/bin/python \
  eval/campaigns/t3-t4-language-overhead-v1/run_campaign.py \
  --processes 30 --repeats 20 \
  --output-dir eval/campaigns/t3-t4-language-overhead-v1/raw/runtime-final

eval/.venv/bin/python \
  eval/campaigns/t3-t4-language-overhead-v1/run_comparator_runtime.py \
  --processes 30 --repeats 20 \
  --output eval/campaigns/t3-t4-language-overhead-v1/raw/comparator-runtime-final

eval/.venv/bin/python \
  eval/campaigns/t3-t4-language-overhead-v1/profile_invocation.py \
  --demo fixed-weather \
  --output eval/campaigns/t3-t4-language-overhead-v1/raw/diagnostic/fixed-weather.json

eval/.venv/bin/python \
  eval/campaigns/t3-t4-language-overhead-v1/profile_invocation.py \
  --demo parallel-weather \
  --output eval/campaigns/t3-t4-language-overhead-v1/raw/diagnostic/parallel-weather.json
```

Because the fix changes shared `cedar_security`, `cedar_security_many`, and
the no-custom-output-policy `graph.invoke()` path, affected application
runtime results need refreshing. Audited, observed, custom-output-policy, and
public-stream paths deliberately retain per-emission mediation.

## Validation

- `make format`: passed.
- `make lint`: passed, including Ruff and `ty`.
- Core LangGraph suite: 1,772 passed and 295 skipped.
- Targeted security/proof regression suite: 118 passed. This includes allowed and
  denied Cedar paths, cache invalidation when the Cedar executable changes,
  exact grant/call rebinding, operator parse/evaluation denial, retained
  artifact behavior, language admission and proof drift, output mediation,
  runtime MAC, and concurrent validation single-flight.
- `TEST=tests make test`: 5,799 passed and 51 skipped. Remaining native Linux
  host-route failures report that bubblewrap isolation is unavailable on this
  bare host. One unrelated public-export documentation failure comes from
  separate dirty remote-tool work in the shared tree. The language-route
  verifier initially rejected the new validated fast path; its proof model
  and drift test were updated, and the focused suite passes.
- The first literal `make test` attempt encountered an unrelated collection-name
  collision inside the pre-existing untracked `security-route-evidence`
  directories. Those user artifacts were not changed.
