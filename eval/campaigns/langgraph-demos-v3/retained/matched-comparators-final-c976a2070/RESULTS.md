# Argus versus enforceable host comparators

Run `matched-comparators-final-c976a2070` contains 700 fixed-population attempts in 5 paired repetition blocks.

**Security scope:** NoNo and APF/OpenShell enforce every filesystem, process, and network restriction used by this campaign. They cannot express Argus's typed library resource/action mediation, so this is the closest enforceable host-policy comparison rather than semantic security equivalence.

| Application | Baseline correct/status | Argus correct/status | NoNo-enforced correct/status | APF-enforced correct/status |
|---|---:|---:|---:|---:|
| D1-sql | 12/25 (C25/F0/E0/T0) | 12/25 (C25/F0/E0/T0) | 10/25 (C25/F0/E0/T0) | 12/25 (C25/F0/E0/T0) |
| D2-rag | 16/25 (C25/F0/E0/T0) | 17/25 (C25/F0/E0/T0) | 19/25 (C25/F0/E0/T0) | 19/25 (C25/F0/E0/T0) |
| D3-plan-execute | 0/25 (C0/F0/E25/T0) | 0/25 (C0/F0/E25/T0) | 0/25 (C0/F0/E25/T0) | 0/25 (C0/F0/E25/T0) |
| D4-multi-agent | 17/25 (C17/F8/E0/T0) | 18/25 (C18/F7/E0/T0) | 0/25 (C13/F10/E0/T2) | 0/25 (C11/F14/E0/T0) |
| D5-support | 20/25 (C25/F0/E0/T0) | 20/25 (C25/F0/E0/T0) | 20/25 (C25/F0/E0/T0) | 20/25 (C25/F0/E0/T0) |
| T1-add-tools | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T10-time-travel | 5/5 (C5/F0/E0/T0) | 0/5 (C0/F5/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T2-custom-weather | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T3-fixed-weather | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T4-parallel-weather | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T5-prebuilt-multiply | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T6-return-direct | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T7-forced-tool | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T8-serial-tools | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |
| T9-add-memory | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) | 5/5 (C5/F0/E0/T0) |

Pairwise pooled results use only task/repetition pairs that completed correctly in Argus and the named comparison mode. Ratios below are Argus/comparison: values below 1.0 mean Argus is faster.

| Comparison | Timer | Matched pairs | Argus mean/median/p95 (ms) | Other mean/median/p95 (ms) | Argus/other [95% CI] |
|---|---|---:|---:|---:|---:|
| Baseline | invocation_ms | 103 | 5051.9/3053.5/16496.2 | 4420.6/3046.6/14621.9 | 1.186x [1.081, 1.214] |
| Baseline | process_wall_ms | 103 | 9014.6/4943.5/21876.1 | 8030.6/4550.4/19558.9 | 1.149x [1.087, 1.164] |
| Baseline | secured_wall_ms | 103 | 9014.6/4943.5/21876.1 | 8030.6/4550.4/19558.9 | 1.149x [1.087, 1.164] |
| NoNo-enforced | invocation_ms | 90 | 3411.4/2787.1/8686.9 | 3075.8/2809.0/8640.2 | 1.157x [1.043, 1.202] |
| NoNo-enforced | process_wall_ms | 90 | 7427.2/4658.5/21472.8 | 7079.3/4331.5/20334.5 | 1.069x [0.997, 1.102] |
| NoNo-enforced | secured_wall_ms | 90 | 7427.2/4658.5/21472.8 | 7079.3/4331.5/20334.5 | 1.069x [0.997, 1.102] |
| APF-enforced | invocation_ms | 92 | 3443.4/2869.5/8685.1 | 2622.9/2502.3/6781.9 | 1.385x [1.223, 1.437] |
| APF-enforced | process_wall_ms | 92 | 7409.1/4705.7/21442.1 | 8384.3/5130.9/21491.2 | 0.946x [0.746, 1.069] |
| APF-enforced | secured_wall_ms | 92 | 7409.1/4705.7/21442.1 | 15067.6/11621.5/27801.6 | 0.514x [0.429, 0.565] |

Common successful population across all four modes: 89 pairs.

`invocation_ms` excludes external sandbox activation and transport. `process_wall_ms` includes per-dispatch NoNo activation or OpenShell exec transport, along with Python startup for every mode. `secured_wall_ms` also includes fresh APF sandbox creation, policy admission, input binding, and confirmed deletion because those steps provide APF's invocation isolation.
