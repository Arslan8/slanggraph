# Unified final campaign report

Campaign `unified-final-v1`; configuration `d8fdb318506dd84466339a78d433c290b467bbde379a379b5fef0798c33f468c`.

## Evaluation 1: Macrobenchmarks

The fixed common-success population contains 732 tuples. Headline values are ratios of summed post-preflight runtimes, not equal-workload averages.

| Mode | Correct/scheduled | Sum runtime (ms) | Ratio | 95% CI | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 778/990 | 3316880.156 | 1.0000 | reference | 0.00% |
| argus | 792/990 | 3641712.294 | 1.0979 | [1.0950, 1.1014] | 9.79% |
| nono | 774/990 | 3331506.556 | 1.0044 | [0.9976, 1.0136] | 0.44% |
| apf | 774/990 | 3396020.139 | 1.0239 | [1.0205, 1.0272] | 2.39% |

The common-success set contains 732 of 990 scheduled tuple positions. Exact membership, per-application status counts, raw full-population runtimes, and preflight measurements are in `summary.json`.

## Evaluation 2: Host security portability

This is a security-portability comparison. Distinct cases, applicability, positive controls, and effect oracles are reported separately from repetitions.

| Backend | Distinct cases | Prevented | Rejected before execution | Allowed controls | Inconclusive | Positive controls |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| linux | 45 | 35 | 5 | 5 | 0 | 45/45 |

Required-obligation rejections are reported separately from effect-level prevention. The macOS manifest and runner are supplied for the other student; no macOS outcomes are claimed here.

## Evaluation 3: Identical-workload language/host microbenchmarks

Request latency uses 30 samples clustered within five sessions. Sustained results remain part of this evaluation and include drain and inventory-restoration endpoints.

Request latency:

| Workload | Mode | Mean (us) | Median (us) | p95 (us) | Failures |
| --- | --- | ---: | ---: | ---: | ---: |
| read-32 | argus-host | 32571.969 | 29697.206 | 41849.074 | 0 |
| read-32 | argus-language | 484.940 | 454.940 | 611.385 | 0 |
| read-32 | baseline | 8.812 | 8.038 | 12.429 | 0 |
| read-64k | argus-host | 33540.842 | 31077.435 | 41740.700 | 0 |
| read-64k | argus-language | 487.973 | 471.438 | 593.230 | 0 |
| read-64k | baseline | 23.259 | 20.404 | 37.744 | 0 |
| write-32 | argus-host | 34515.410 | 31121.424 | 46492.536 | 0 |
| write-32 | argus-language | 586.425 | 571.258 | 712.191 | 0 |
| write-32 | baseline | 154.051 | 138.648 | 178.295 | 0 |

Sustained 32-byte read (means of five 60-second session results):

| Mode | Concurrency | Completions/s | p50 (us) | p95 (us) | p99 (us) | Failures | Pool misses | Replenishments |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| argus-host | 1 | 6.42 | 154624.993 | 163870.611 | 190776.152 | 0 | 0 | 2280 |
| argus-host | 2 | 6.42 | 310717.362 | 336809.869 | 352063.936 | 0 | 0 | 2288 |
| argus-host | 4 | 6.46 | 620729.337 | 657761.079 | 670590.987 | 0 | 0 | 2309 |
| argus-host | 8 | 6.53 | 1244395.833 | 1287644.274 | 1298871.094 | 0 | 0 | 2347 |
| argus-language | 1 | 2280.75 | 382.872 | 487.321 | 540.676 | 0 | 0 | 0 |
| argus-language | 2 | 1496.85 | 1195.315 | 1607.304 | 2041.859 | 0 | 0 | 0 |
| argus-language | 4 | 1053.58 | 3424.170 | 5089.791 | 7154.928 | 0 | 0 | 0 |
| argus-language | 8 | 1049.19 | 6603.638 | 10240.861 | 12237.402 | 0 | 0 | 0 |
| baseline | 1 | 145587.70 | 6.206 | 6.969 | 8.580 | 0 | 0 | 0 |
| baseline | 2 | 60356.50 | 32.323 | 43.542 | 57.525 | 0 | 0 | 0 |
| baseline | 4 | 29624.13 | 112.194 | 309.773 | 440.306 | 0 | 0 | 0 |
| baseline | 8 | 21091.02 | 309.298 | 887.346 | 1230.709 | 0 | 0 | 0 |

## Evaluation 4: Pandas case study

The fixed common-success population contains 300 tuples. Headline values are ratios of summed post-preflight runtimes, not equal-workload averages.

| Mode | Correct/scheduled | Sum runtime (ms) | Ratio | 95% CI | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 300/300 | 2714106.400 | 1.0000 | reference | 0.00% |
| argus | 300/300 | 2857004.461 | 1.0527 | [1.0464, 1.0618] | 5.27% |

The common-success set contains 300 of 300 scheduled tuple positions. Exact membership, per-application status counts, raw full-population runtimes, and preflight measurements are in `summary.json`.

Pandas resource controls:

| Attack | Outcome | Raw evidence |
| --- | --- | --- |
| read_bob | prevented | raw/evaluation-4-read_bob |
| update_bob | prevented | raw/evaluation-4-update_bob |

## Policy comparison

| Scope | nono | APF/OpenShell | Omitted obligation |
| --- | --- | --- | --- |
| D1-sql | best-available-reduced-enforcement | best-available-reduced-enforcement | query-level read-only SQL actions and prevention of direct database reads |
| D2-rag | best-available-reduced-enforcement | best-available-reduced-enforcement | registered retriever/top-k action mediation and prevention of direct corpus reads |
| D3-plan-execute | best-available-reduced-enforcement | best-available-reduced-enforcement | registered frozen-search action mediation and prevention of direct corpus reads |
| D4-multi-agent | best-available-reduced-enforcement | best-available-reduced-enforcement | typed retrieval action mediation inside the generated-code workflow |
| D5-support | best-available-reduced-enforcement | best-available-reduced-enforcement | passenger/row ownership, typed travel actions, and prevention of direct SQLite access |
| T1-add-tools,T2-custom-weather,T5-prebuilt-multiply,T6-return-direct,T7-forced-tool,T8-serial-tools | best-available-reduced-enforcement | best-available-reduced-enforcement | tool-call object/action authorization and admitted-language direct-bypass prevention |
| T9-add-memory,T10-time-travel | best-available-reduced-enforcement | best-available-reduced-enforcement | principal-bound authenticated checkpoint history and branch authorization |

## Supporting validation

Admission/interpreter fuzzing generated 10000 programs across 5 fixed seeds: 8000 admitted, 2000 rejected, 0 timeouts, 0 crashes, 0 mismatches, and 0 security violations.

## Limitations

Performance intervals use five session blocks on one Linux machine. Request-latency tail quantiles are descriptive for 30 clustered samples; the sustained subtest supplies the higher-volume tails. APF/OpenShell and nono are best-available reduced-enforcement comparisons, not equivalent-policy rankings. macOS was not executed locally.
