# Matched ordinary-demo results

Run `final-fcbc8ce49-20261105` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 11/25 | 12/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 9217.3 | 11125.2 | 1.207x [1.081, 1.334] |
| D2-rag | 21/25 | 19/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 6641.9 | 6068.7 | 0.914x [0.869, 0.959] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 18503.3 | 21466.9 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 17/25 | 22/25 | C17/F7/E0/T1 / C22/F0/E0/T3 | 62818.7 | 53683.7 | 0.855x [0.409, 1.404] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 21412.8 | 25483.9 | 1.190x [1.043, 1.373] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2796.7 | 3680.2 | 1.316x [1.209, 1.490] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 3125.9 | 5130.7 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2454.1 | 3319.7 | 1.353x [1.236, 1.558] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1146.7 | 2106.8 | 1.837x [1.564, 2.170] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1176.6 | 1885.5 | 1.602x [1.474, 1.731] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3841.2 | 3054.6 | 0.795x [0.584, 1.216] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1934.9 | 2495.2 | 1.290x [1.138, 1.429] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1930.1 | 3242.1 | 1.680x [1.401, 2.015] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2815.2 | 4148.5 | 1.474x [1.195, 1.988] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3834.0 | 4898.7 | 1.278x [1.218, 1.356] |

The suite result is the geometric mean of per-application attempt-duration ratios, not a pooled ratio or arithmetic mean of percentages. Because utility and failure status differ for some included applications, it is not a pure enforcement-only overhead estimate.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Geometric-mean ratio: **1.255x** (95% paired-block CI 1.224-1.278); overhead **25.5%**.

No defensible overhead average exists over all 15 applications. Excluded applications have no completed trial in at least one mode; their failed-attempt durations are retained in the table but never treated as successful latency.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.351x** (95% CI 1.286-1.431); overhead **35.1%** across 10 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
