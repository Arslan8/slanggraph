# Matched ordinary-demo results

Run `aggressive-inline-20261030` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 11/25 | 12/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 8417.2 | 10121.9 | 1.203x [1.093, 1.313] |
| D2-rag | 21/25 | 19/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 5784.4 | 5685.0 | 0.983x [0.934, 1.034] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 17527.4 | 19111.1 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 17/25 | 22/25 | C17/F7/E0/T1 / C22/F0/E0/T3 | 61455.9 | 52669.6 | 0.857x [0.395, 1.421] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 18823.1 | 20061.1 | 1.066x [1.046, 1.088] |
| T1-add-tools | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2618.8 | 2300.7 | not reported (no completed trial in at least one mode) |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2717.4 | 3499.4 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2057.7 | 2088.5 | not reported (no completed trial in at least one mode) |
| T3-fixed-weather | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 975.7 | 1419.4 | not reported (no completed trial in at least one mode) |
| T4-parallel-weather | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 961.9 | 1435.8 | not reported (no completed trial in at least one mode) |
| T5-prebuilt-multiply | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2652.0 | 2146.5 | not reported (no completed trial in at least one mode) |
| T6-return-direct | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 1652.5 | 2046.5 | not reported (no completed trial in at least one mode) |
| T7-forced-tool | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 1605.7 | 2283.0 | not reported (no completed trial in at least one mode) |
| T8-serial-tools | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2626.7 | 2691.3 | not reported (no completed trial in at least one mode) |
| T9-add-memory | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 3614.2 | 2336.8 | not reported (no completed trial in at least one mode) |

The suite result is the geometric mean of per-application attempt-duration ratios, not a pooled ratio or arithmetic mean of percentages. Because utility and failure status differ for some included applications, it is not a pure enforcement-only overhead estimate.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support.
Excluded applications: D3-plan-execute, T1-add-tools, T10-time-travel, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Geometric-mean ratio: **1.019x** (95% paired-block CI 0.849-1.126); overhead **1.9%**.

No defensible overhead average exists over all 15 applications. Excluded applications have no completed trial in at least one mode; their failed-attempt durations are retained in the table but never treated as successful latency.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.066x** (95% CI 1.046-1.088); overhead **6.6%** across 1 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
