# Inline lifecycle-checker performance

The proved decision procedure is loaded once from a sealed native library and called inline. The measured call boundary includes every recurring authorization, lifecycle decision, activation, execution, audit, cleanup, and framework cost; library loading is recorded separately as setup.

| Result | Sealed subprocess | Inline native | Change |
|---|---:|---:|---:|
| Reused Landlock call | 476.88 ms | 182.78 ms | 61.7% reduction |
| Lifecycle decision phase | 285.86 ms | 15.03 ms | 94.7% reduction |

The reused-call ratio is **0.383x** with an independent-session bootstrap 95% interval of **[0.380, 0.386]** (100,000 resamples, seed 20261030). Because the campaigns were sequential rather than interleaved, the comparison can include host drift.

## Current phase means

| Phase | Mean ms |
|---|---:|
| authorization | 0.47 |
| native lifecycle decision | 15.03 |
| activation | 91.48 |
| execution | 13.62 |
| audit | 8.35 |
| cleanup | 0.08 |
| framework_residual | 53.75 |

First use is 248.25 ms. Loading and digest-checking the pinned native artifacts costs 302.19 ms per fresh process session and is reported as setup, not recurring execution overhead.
