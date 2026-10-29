# Timing boundaries used by the full campaign

The readiness pilots prove only that the selected current paths execute on the
frozen host; their pytest walls are deliberately ineligible for performance
claims. The full route records use the boundaries below.

For each measured call, the harness will retain monotonic start/end timestamps
for a parent call and the following mutually exclusive phases:

| Phase | Starts | Ends | Excludes |
| --- | --- | --- | --- |
| admission/setup | construction or request binding begins | runnable plan and immutable inputs are ready | Cedar, Lean, activation, body, audit write, cleanup |
| Cedar authorization | canonical Cedar request is ready | ALLOW/DENY and exact grant are returned | request normalization and grant activation |
| Lean checking | sealed checker invocation starts | the required phase response is parsed | surrounding worker setup or execution; each checker call is retained separately and also summed once |
| activation | host starts route activation | receipt has been validated and the worker is released to run | Lean checker subprocess time |
| execution | worker/interpreter is released | complete result or refusal is received | activation and cleanup; for a fresh Python broker worker this includes module import, the Unix-socket request/response, and the tool body |
| audit | finalized record is presented to the sink | durable sink acknowledges the hash-chained record | policy and execution |
| cleanup | result/refusal is fixed and teardown begins | termination/removal/release is confirmed or marked indeterminate | post-cleanup Lean release check, which stays in Lean |

The instrumentation wrappers use monotonic nanosecond clocks and write the
resulting component durations to each raw call record. Where one instrumented
span contains another, the harness subtracts the inner duration before writing
the additive outer phase (for example, dispatcher minus execution, or activation
minus Lean). It records `framework_residual_ms = parent_ms - sum(phases)`; the
statistics script rejects a residual below -0.1 ms as overlap. The tolerance is
for independent clock-read/float rounding, not an unreported work category.

Setup has two scopes: cold session setup and per-call setup. Container creation
and final removal are cold lifecycle rows, never folded into reused call latency.
The first call after each fresh process/session is retained separately; ten warmups
are excluded; the following 20 calls are measured. A container identity may be
reused only when principal, policy, grant authority, runtime, image, artifact, and
plan identities all match.

Route-specific `N/A` values are required rather than zeros. The immutable-language
route has no Lean checker. The current container and object-broker routes do not
claim the Linux worker's Lean lifecycle proof. Broker decision/audit time is
separate from the outer Cedar decision. Refusals retain the phase reached and are
never silently replaced.
