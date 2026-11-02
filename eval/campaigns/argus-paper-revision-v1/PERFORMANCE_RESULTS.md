# Complete-configuration performance status

## Final-measurement gate

No final timing headline is published from the current interactive development
host. Dedicated/quiet execution, CPU-frequency control and background-load
qualification have not been established. Launching a large campaign here would
violate the measurement protocol.

Historical `cross-host-security-v2` broker measurements (59.200 ms mean over
100 measured calls) do **not** include the Linux broker Lean integration and are
not a complete-configuration result. Direct Linux Lean and broker/MAC timings
have different guard mixes and must not be pooled.

## Required frozen protocol

The final runner must use the implementation commit recorded after the library
gates and must abort if source hashes change. Each of five or more independent
process sessions interleaves baseline and protected conditions, retains one cold
call, excludes only declared warmups, and measures at least 20 steady calls.
Useful work is the same exact Alice SQLite read in both conditions.

Report these non-overlapping boundaries:

| Boundary | Included work |
| --- | --- |
| Preparation | policy parse/validation, Cedar artifact preparation, lowering, Lean grant verification, artifact/runtime integrity, graph admission and worker preparation |
| Cold invocation | first end-to-end protected call after preparation |
| Steady state | later calls under explicitly documented reuse rules; no setup work silently omitted |

The per-call reconciliation is:

`elapsed = authorization + lowering/activation + Lean lifecycle + transport + resource execution + validation + audit + cleanup + residual`.

Nested spans must be subtracted. Residual remains named and is instrumented when
substantial; it is not called generic framework overhead.

Host evidence must include kernel, architecture, CPU affinity, governor and
frequency settings, turbo/boost state, background load, Python, Cedar, Lean,
checker/native-runtime hashes, Landlock ABI, seccomp state, cgroup delegation,
dependency lock hashes and source-before/source-after inventories.

Diagnostic runs and any later code fix use separate directories. A measured-path
fix invalidates and reruns the affected cohort.

`run_performance.py` enforces an explicit controlled-host acknowledgement,
runs the complete trace preflight, records load/frequency metadata and source
hashes, and invokes the interleaved broker runner with a mandatory pinned
checker. Omitting the checker or the host acknowledgement, failing any complete
route assertion, or changing a measured source aborts the campaign.
