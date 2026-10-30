# Matched ordinary-demo results

Run `aggressive-inline-docker-cedar-20261030` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 11/25 | 12/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 8444.6 | 10101.5 | 1.196x [1.075, 1.309] |
| D2-rag | 21/25 | 19/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 5688.2 | 5547.0 | 0.975x [0.926, 1.023] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 17372.1 | 20247.4 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 17/25 | 22/25 | C17/F7/E0/T1 / C22/F0/E0/T3 | 61087.8 | 52456.9 | 0.859x [0.404, 1.418] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 19058.6 | 21027.0 | 1.103x [1.071, 1.153] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2641.6 | 3274.7 | 1.240x [1.174, 1.300] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2744.8 | 3442.8 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2075.5 | 2731.8 | 1.316x [1.250, 1.389] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 982.0 | 1811.0 | 1.844x [1.647, 2.127] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 961.1 | 1755.6 | 1.827x [1.724, 1.939] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2648.5 | 2844.0 | 1.074x [0.860, 1.345] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1665.6 | 2312.6 | 1.388x [1.328, 1.464] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1586.4 | 2505.5 | 1.579x [1.452, 1.768] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2645.0 | 3584.7 | 1.355x [1.232, 1.541] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3595.3 | 4644.8 | 1.292x [1.280, 1.303] |

The suite result is the geometric mean of per-application attempt-duration ratios, not a pooled ratio or arithmetic mean of percentages. Because utility and failure status differ for some included applications, it is not a pure enforcement-only overhead estimate.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Geometric-mean ratio: **1.281x** (95% paired-block CI 1.243-1.304); overhead **28.1%**.

No defensible overhead average exists over all 15 applications. Excluded applications have no completed trial in at least one mode; their failed-attempt durations are retained in the table but never treated as successful latency.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.380x** (95% CI 1.343-1.431); overhead **38.0%** across 10 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
