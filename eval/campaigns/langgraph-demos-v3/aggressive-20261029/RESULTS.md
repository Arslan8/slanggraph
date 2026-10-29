# Matched ordinary-demo results

Run `aggressive-full-20261029` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 11/25 | 16/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 8668.0 | 10553.4 | 1.218x [1.170, 1.266] |
| D2-rag | 16/25 | 18/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 5241.0 | 5636.3 | 1.075x [1.017, 1.143] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 18012.6 | 21485.8 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 12/25 | 19/25 | C14/F10/E0/T1 / C19/F5/E0/T1 | 83985.1 | 57034.5 | 0.679x [0.324, 1.134] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 19231.9 | 21355.0 | 1.110x [1.070, 1.158] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2756.3 | 3363.4 | 1.220x [1.080, 1.323] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2753.9 | 3850.2 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2029.3 | 3172.2 | 1.563x [1.349, 1.909] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 985.4 | 1931.0 | 1.960x [1.791, 2.152] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 970.9 | 1897.4 | 1.954x [1.932, 1.977] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2337.4 | 3025.9 | 1.295x [1.072, 1.462] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1667.1 | 2539.0 | 1.523x [1.503, 1.556] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1568.6 | 2568.5 | 1.637x [1.576, 1.700] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2643.5 | 3579.5 | 1.354x [1.278, 1.434] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3589.8 | 5466.6 | 1.523x [1.410, 1.685] |

The suite result is the geometric mean of per-application ratios, not a pooled ratio or arithmetic mean of percentages.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Geometric-mean ratio: **1.347x** (95% paired-block CI 1.288-1.395); overhead **34.7%**.

No defensible overhead average exists over all 15 applications: D3 has no completed trial in either mode and T10 has no completed Argus trial.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.490x** (95% CI 1.454-1.528); overhead **49.0%** across 10 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
