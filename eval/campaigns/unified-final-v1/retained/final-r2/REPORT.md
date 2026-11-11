# Unified final campaign report

Campaign `unified-final-v1`; configuration `0fb5bdc04419ce1c05f3d5010f22c6949c787a64e4991b7c5d8f82c136ec71e8`.

## Evaluation 1: Macrobenchmarks

The fixed common-success population contains 468 tuples. Headline values are ratios of summed post-preflight runtimes, not equal-workload averages.

| Mode | Correct/scheduled | Sum runtime (ms) | Ratio | 95% CI | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 602/990 | 1606210.568 | 1.0000 | reference | 0.00% |
| argus | 621/990 | 1867437.202 | 1.1626 | [1.0750, 1.2667] | 16.26% |
| nono | 534/990 | 1625134.557 | 1.0118 | [1.0049, 1.0184] | 1.18% |
| apf | 546/990 | 2187699.053 | 1.3620 | [1.2976, 1.4247] | 36.20% |

The common-success set contains 468 of 990 scheduled tuple positions. Exact membership, per-application status counts, raw full-population runtimes, and preflight measurements are in `summary.json`.

## Evaluation 2: Host security portability

This is a security-portability comparison. Distinct cases, applicability, positive controls, and effect oracles are reported separately from repetitions.

| Backend | Distinct cases | Prevented | Allowed controls | Inconclusive | Positive controls |
| --- | ---: | ---: | ---: | ---: | ---: |
| linux | 45 | 33 | 5 | 7 | 44/45 |

The direct-shared-memory probe is inconclusive and excluded from prevention counts because its positive control did not observe the protected canary. The macOS manifest and runner are supplied for the other student; no macOS outcomes are claimed in this Linux collection.

## Evaluation 3: Identical-workload language/host microbenchmarks

Request latency uses 30 samples clustered within five sessions. Sustained results remain part of this evaluation and include drain and inventory-restoration endpoints.

Request latency:

| Workload | Mode | Mean (us) | Median (us) | p95 (us) | Failures |
| --- | --- | ---: | ---: | ---: | ---: |
| read-32 | argus-host | 533419.557 | 527456.168 | 564675.578 | 0 |
| read-32 | argus-language | 484.940 | 454.940 | 611.385 | 0 |
| read-32 | baseline | 8.812 | 8.038 | 12.429 | 0 |
| read-64k | argus-host | 542404.925 | 536079.276 | 572272.439 | 0 |
| read-64k | argus-language | 487.973 | 471.438 | 593.230 | 0 |
| read-64k | baseline | 23.259 | 20.404 | 37.744 | 0 |
| write-32 | argus-host | 544840.753 | 537160.896 | 580624.825 | 0 |
| write-32 | argus-language | 586.425 | 571.258 | 712.191 | 0 |
| write-32 | baseline | 154.051 | 138.648 | 178.295 | 0 |

Sustained 32-byte read (means of five 60-second session results):

| Mode | Concurrency | Completions/s | p50 (us) | p95 (us) | p99 (us) | Failures | Pool misses | Replenishments |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| argus-host | 1 | 1.88 | 517732.708 | 555671.865 | 960387.433 | 0 | 0 | 657 |
| argus-host | 2 | 3.43 | 547001.830 | 807684.159 | 1068607.926 | 0 | 0 | 1202 |
| argus-host | 4 | 5.09 | 676232.584 | 1217186.880 | 1265767.572 | 0 | 0 | 1808 |
| argus-host | 8 | 5.11 | 1597975.594 | 1971855.697 | 2345067.576 | 0 | 0 | 1798 |
| argus-language | 1 | 2280.75 | 382.872 | 487.321 | 540.676 | 0 | 0 | 0 |
| argus-language | 2 | 1496.85 | 1195.315 | 1607.304 | 2041.859 | 0 | 0 | 0 |
| argus-language | 4 | 1053.58 | 3424.170 | 5089.791 | 7154.928 | 0 | 0 | 0 |
| argus-language | 8 | 1049.19 | 6603.638 | 10240.861 | 12237.402 | 0 | 0 | 0 |
| baseline | 1 | 145587.70 | 6.206 | 6.969 | 8.580 | 0 | 0 | 0 |
| baseline | 2 | 60356.50 | 32.323 | 43.542 | 57.525 | 0 | 0 | 0 |
| baseline | 4 | 29624.13 | 112.194 | 309.773 | 440.306 | 0 | 0 | 0 |
| baseline | 8 | 21091.02 | 309.298 | 887.346 | 1230.709 | 0 | 0 | 0 |

## Evaluation 4: Pandas case study

The fixed common-success population contains 180 tuples. Headline values are ratios of summed post-preflight runtimes, not equal-workload averages.

| Mode | Correct/scheduled | Sum runtime (ms) | Ratio | 95% CI | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 180/300 | 1145247.494 | 1.0000 | reference | 0.00% |
| argus | 180/300 | 1216323.623 | 1.0621 | [1.0589, 1.0654] | 6.21% |

The common-success set contains 180 of 300 scheduled tuple positions. Exact membership, per-application status counts, raw full-population runtimes, and preflight measurements are in `summary.json`.

Pandas resource controls:

| Attack | Outcome | Raw evidence |
| --- | --- | --- |
| read_bob | prevented | raw/evaluation-4-read_bob |
| update_bob | prevented | raw/evaluation-4-update_bob |

## Policy comparison

| Scope | nono | APF/OpenShell | Omitted obligation |
| --- | --- | --- | --- |
| D1,D2,D3,D5,T1,T2,T5,T6,T7,T8,T9,T10 | best-available-reduced-enforcement | best-available-reduced-enforcement | typed library object/action mediation and admitted-language direct-bypass prevention |
| D4-multi-agent | best-available-reduced-enforcement | best-available-reduced-enforcement | typed retrieval object/action mediation |

## Supporting validation

Admission/interpreter fuzzing generated 10000 programs across 5 fixed seeds: 8000 admitted, 2000 rejected, 0 timeouts, 0 crashes, 0 mismatches, and 0 security violations.

## Limitations

Performance intervals use five session blocks on one Linux machine. Request-latency tail quantiles are descriptive for 30 clustered samples; the sustained subtest supplies the higher-volume tails. APF/OpenShell and nono are best-available reduced-enforcement comparisons, not equivalent-policy rankings. macOS was not executed locally.
