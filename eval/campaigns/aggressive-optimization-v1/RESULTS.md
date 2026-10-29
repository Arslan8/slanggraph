# Aggressive optimization route costs

All routes use five fresh process sessions, ten warmups, and 20 measured calls per session. Intervals in the route table are Student-t intervals over session means.

| Route | Optimization applicability | First use (ms) | Reused call (ms) | Added ms vs matching direct baseline |
|---|---|---:|---:|---:|
| language | object/language authorizer; aggressive typed Cedar not applicable | 58.75 [57.32, 60.17] | 11.77 [11.49, 12.05] | 11.72 [11.44, 12.00] |
| landlock-aggressive | typed Cedar aggressive | 511.76 [507.75, 515.77] | 466.70 [460.94, 472.46] | 466.65 [460.89, 472.41] |
| container | object authorizer; aggressive typed Cedar not applicable | 1643.31 [1225.22, 2061.41] | 148.24 [147.32, 149.17] | 148.19 [147.27, 149.12] |
| broker | object authorizer; aggressive typed Cedar not applicable | 175.14 [167.24, 183.04] | 140.84 [140.20, 141.49] | 140.73 [140.09, 141.38] |

## Direct Cedar-mode comparison

On the Lean-backed Landlock route, first use was 640.06 ms in `normal` mode and 511.76 ms in `aggressive` mode. The ratio is 0.800x (independent-session bootstrap 95% CI 0.793-0.805), a 20.0% reduction.

After ten warmups, reused calls were 480.64 ms and 466.70 ms, ratio 0.971x (95% CI 0.954-0.985). Exact-result caching makes Cedar authorization a sub-millisecond phase on reused calls, so the large cold-path batching benefit should not be generalized to the full reused-call runtime.

The language, container, broker, Pandas, and ordinary-demo cohorts do not traverse `CedarPolicyBackend`; they are regression/control measurements under the aggressive-default revision.
