# Matched ordinary-demo results

Run `parity-matched-20261029` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 14/25 | 12/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 7915.7 | 10895.7 | 1.376x [1.314, 1.460] |
| D2-rag | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 5358.1 | 5413.0 | 1.010x [1.000, 1.019] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 17871.1 | 19499.7 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 16/25 | 22/25 | C18/F7/E0/T0 / C22/F0/E0/T3 | 53969.3 | 52148.5 | 0.966x [0.503, 1.789] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 49697.0 | 53846.0 | 1.083x [1.046, 1.141] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2603.8 | 3476.3 | 1.335x [1.259, 1.428] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2761.6 | 3163.2 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2067.5 | 2849.9 | 1.378x [1.310, 1.455] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 948.0 | 1832.3 | 1.933x [1.917, 1.948] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1158.9 | 1906.4 | 1.645x [1.298, 2.073] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2369.5 | 3018.0 | 1.274x [0.998, 1.482] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1629.3 | 2434.0 | 1.494x [1.455, 1.533] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1670.6 | 2672.3 | 1.600x [1.331, 1.958] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2609.8 | 3964.0 | 1.519x [1.385, 1.710] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3596.3 | 5484.6 | 1.525x [1.408, 1.736] |

The suite result is the geometric mean of per-application ratios, not a pooled ratio or arithmetic mean of percentages.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Geometric-mean ratio: **1.370x** (95% paired-block CI 1.299-1.439); overhead **37.0%**.

No defensible overhead average exists over all 15 applications: D3 has no completed trial in either mode and T10 has no completed Argus trial.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.414x** (95% CI 1.357-1.476); overhead **41.4%** across 11 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
