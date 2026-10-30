# Matched ordinary-demo results

Run `worker-broker-opt-full-20261029` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 11/25 | 16/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 8605.1 | 10511.4 | 1.222x [1.172, 1.265] |
| D2-rag | 16/25 | 18/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 5227.9 | 5563.3 | 1.064x [1.006, 1.122] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 18021.6 | 21336.3 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 12/25 | 19/25 | C14/F10/E0/T1 / C19/F5/E0/T1 | 84047.0 | 56936.6 | 0.677x [0.323, 1.132] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 18596.5 | 20132.3 | 1.083x [1.074, 1.094] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2756.8 | 3423.2 | 1.242x [1.107, 1.345] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2723.4 | 3190.4 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2040.9 | 3230.1 | 1.583x [1.339, 1.928] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 978.1 | 1844.3 | 1.886x [1.731, 2.058] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 926.4 | 1899.5 | 2.050x [1.994, 2.102] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2299.6 | 2993.4 | 1.302x [1.097, 1.445] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1640.0 | 2469.8 | 1.506x [1.458, 1.543] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1545.4 | 2530.7 | 1.638x [1.573, 1.704] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2632.7 | 3524.7 | 1.339x [1.286, 1.398] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3583.5 | 5314.7 | 1.483x [1.387, 1.625] |

The suite result is the geometric mean of per-application ratios, not a pooled ratio or arithmetic mean of percentages.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Geometric-mean ratio: **1.343x** (95% paired-block CI 1.284-1.390); overhead **34.3%**.

No defensible overhead average exists over all 15 applications: D3 has no completed trial in either mode and T10 has no completed Argus trial.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.486x** (95% CI 1.455-1.518); overhead **48.6%** across 10 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
