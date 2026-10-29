# Matched ordinary-demo results

Run `optimized-matched-20261029-v3` contains 350 retained attempts in 5 paired repetition blocks. The primary timer includes process startup.

| Application | Baseline success | Argus success | Status B/A | Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|
| D1-sql | 11/25 | 16/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 8667.7 | 10613.9 | 1.225x [1.185, 1.261] |
| D2-rag | 16/25 | 18/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 5249.3 | 5517.6 | 1.051x [0.993, 1.107] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 18036.5 | 21484.5 | not reported (no completed trial in at least one mode) |
| D4-multi-agent | 12/25 | 19/25 | C14/F10/E0/T1 / C19/F5/E0/T1 | 84076.7 | 57161.5 | 0.680x [0.326, 1.135] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 19501.2 | 21105.4 | 1.082x [1.053, 1.106] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2716.7 | 3436.4 | 1.265x [1.110, 1.406] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 2727.5 | 3871.7 | not reported (no completed trial in at least one mode) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2065.4 | 3185.1 | 1.542x [1.315, 1.889] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1006.5 | 1839.1 | 1.827x [1.589, 2.056] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 961.2 | 1904.5 | 1.981x [1.921, 2.052] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2354.7 | 3001.0 | 1.274x [1.085, 1.427] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1679.4 | 2564.2 | 1.527x [1.418, 1.642] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 1581.6 | 2597.2 | 1.642x [1.552, 1.712] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 2626.1 | 3542.6 | 1.349x [1.263, 1.454] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 3614.5 | 5270.2 | 1.458x [1.376, 1.582] |

The suite result is the geometric mean of per-application ratios, not a pooled ratio or arithmetic mean of percentages.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Geometric-mean ratio: **1.333x** (95% paired-block CI 1.283-1.368); overhead **33.3%**.

No defensible overhead average exists over all 15 applications: D3 has no completed trial in either mode and T10 has no completed Argus trial.

As a secondary sensitivity analysis, applications with the same success count in both modes have geometric-mean ratio **1.473x** (95% CI 1.445-1.505); overhead **47.3%** across 10 applications.

Timeout-capped attempts, failures, and refusals remain in the per-mode means. Success counts are reported separately so a failed fast run is not presented as useful speed.
