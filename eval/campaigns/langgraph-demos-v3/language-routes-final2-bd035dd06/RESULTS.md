# Matched ordinary-demo results

Run `language-routes-final2-bd035dd06` contains 350 retained attempts in 5 paired repetition blocks. The primary timer begins after application and Argus preparation. Audit is disabled in both primary modes.

| Application | Baseline success | Argus success | Status B/A | Matched pairs | Preparation B/A (ms) | Invocation B/A (ms) | Ratio [95% CI] |
|---|---:|---:|---|---:|---:|---:|---:|
| D1-sql | 12/25 | 14/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 11 | 59.0/217.3 | 4387.2/4540.9 | 1.035x [0.993, 1.082] |
| D2-rag | 21/25 | 18/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 17 | 58.5/227.7 | 4370.4/4553.5 | 1.042x [1.019, 1.070] |
| D3-plan-execute | 0/25 | 0/25 | C0/F0/E25/T0 / C0/F0/E25/T0 | 0 | 38.4/238.6 | n/a/n/a | not reported (no pair completed correctly in both modes) |
| D4-multi-agent | 18/25 | 20/25 | C18/F7/E0/T0 / C22/F3/E0/T0 | 16 | 39.4/987.3 | 14565.8/15724.1 | 1.080x [1.052, 1.102] |
| D5-support | 20/25 | 20/25 | C25/F0/E0/T0 / C25/F0/E0/T0 | 20 | 70.1/362.0 | 6060.4/7301.6 | 1.205x [1.133, 1.332] |
| T1-add-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 31.0/836.6 | 1593.0/1646.9 | 1.034x [0.982, 1.088] |
| T10-time-travel | 5/5 | 0/5 | C5/F0/E0/T0 / C0/F5/E0/T0 | 0 | 31.4/n/a | n/a/n/a | not reported (no pair completed correctly in both modes) |
| T2-custom-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 32.6/130.6 | 1039.3/1003.9 | 0.966x [0.899, 1.046] |
| T3-fixed-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 1.0/99.0 | 3.9/28.2 | 7.156x [6.298, 7.840] |
| T4-parallel-weather | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 1.1/100.3 | 3.9/27.3 | 7.014x [6.842, 7.227] |
| T5-prebuilt-multiply | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 31.8/130.3 | 1189.7/1133.4 | 0.953x [0.794, 1.097] |
| T6-return-direct | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 31.8/126.3 | 606.9/615.2 | 1.014x [0.929, 1.077] |
| T7-forced-tool | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 31.5/132.4 | 530.1/695.0 | 1.311x [1.063, 1.687] |
| T8-serial-tools | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 32.3/141.0 | 1562.8/1763.5 | 1.128x [0.982, 1.332] |
| T9-add-memory | 5/5 | 5/5 | C5/F0/E0/T0 / C5/F0/E0/T0 | 5 | 31.7/907.6 | 2519.9/2594.9 | 1.030x [0.998, 1.061] |

The primary suite result pools invocation time from task/repetition pairs that completed correctly in both modes. It excludes preparation, interpreter startup, audit logging, failures, and timeout caps.
Status abbreviations: C=completed, F=compatibility failure, E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.

Included applications: D1-sql, D2-rag, D4-multi-agent, D5-support, T1-add-tools, T2-custom-weather, T3-fixed-weather, T4-parallel-weather, T5-prebuilt-multiply, T6-return-direct, T7-forced-tool, T8-serial-tools, T9-add-memory.
Excluded applications: D3-plan-execute, T10-time-travel.
Pooled matched invocation ratio: **1.097x** (95% paired-block CI 1.071-1.124); overhead **9.7%**.

Configured-route breakdown (same matched-successful population and invocation timer):

| Argus route | Applications included/configured | Matched pairs | Baseline mean/median/p95 (ms) | Argus mean/median/p95 (ms) | Ratio [95% CI] |
|---|---:|---:|---:|---:|---:|
| host | 1/1 | 16 | 14565.8/15134.9/18127.5 | 15724.1/16106.5/19543.0 | 1.080x [1.052, 1.102] |
| language | 12/14 | 93 | 3107.7/2684.1/8520.1 | 3450.9/2919.8/8987.7 | 1.110x [1.079, 1.151] |

Excluded applications have no task/repetition pair that completed correctly in both modes. Their failures remain in the status table but are never treated as successful latency.

The secondary equal-application-weight geometric mean is **1.429x** (95% CI 1.408-1.448); overhead **42.9%**. It is retained as a sensitivity analysis because very short applications can dominate ratios.

Preparation and parent-process wall time remain in `statistics.json` as separate diagnostics. Audit-on performance is a separate special case and is not called Argus overhead.
