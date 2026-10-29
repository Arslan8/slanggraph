# Current-implementation results

All intervals are 95% Student-t intervals over five independent session means. Warmups are excluded and first-use calls are reported separately.

## Absolute route latency

| Route | Measured calls | Mean ms [95% CI] | First use ms |
| --- | ---: | ---: | ---: |
| language_typed_authorization_only | 100 | 22.570 [21.842, 23.297] | 24.098 [20.973, 27.223] |
| broker_authorization_only | 100 | 628.366 [621.092, 635.640] | 628.673 [619.258, 638.088] |
| language | 100 | 46.301 [46.182, 46.419] | 58.685 [57.054, 60.315] |
| landlock | 100 | 610.509 [597.656, 623.362] | 638.322 [627.811, 648.834] |
| container | 100 | 172.837 [170.749, 174.925] | 1501.742 [1156.351, 1847.133] |
| broker | 100 | 651.435 [650.777, 652.094] | 658.528 [647.917, 669.139] |

## Cold setup and final teardown

| Route | Admission/setup ms | Dispatcher/executor ms | Checker setup ms | Final removal ms |
| --- | ---: | ---: | ---: | ---: |
| language_typed_authorization_only | N/A | N/A | N/A | N/A |
| broker_authorization_only | N/A | N/A | N/A | N/A |
| language | 326.042 | N/A | N/A | N/A |
| landlock | 348.610 | 55.126 | 116.264 | N/A |
| container | 315.430 | 60.136 | N/A | 646.212 |
| broker | 303.906 | 0.799 | N/A | N/A |

## Additive route phases

| Route | Authorization ms | Lean ms | Activation ms | Execution ms | Audit ms | Cleanup ms | Residual ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| language_typed_authorization_only | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| broker_authorization_only | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| language | 35.685 | N/A | 0.134 | 0.309 | 7.170 | N/A | 3.002 |
| landlock | 153.223 | 279.777 | 94.798 | 15.558 | 11.106 | 0.091 | 55.956 |
| container | 27.374 | N/A | 115.264 | 19.127 | 7.580 | N/A | 3.491 |
| broker | 28.474 | N/A | 116.359 | 486.341 | 15.787 | 0.574 | 3.900 |

For the broker route, `execution_ms` includes isolated Python startup, trusted-module import, the Unix-socket broker round trip, and the tool body. It is not a transport-only measurement.

## Appendix: primitive-relative ratios

The ratios below divide whole protected calls by in-process primitive baselines. They are retained for completeness and are not the headline comparison for an LLM-driven tool invocation.

| Route | Baseline ms [95% CI] | Runtime multiple | Overhead |
| --- | ---: | ---: | ---: |
| language_typed_authorization_only | 0.000983 [0.000787, 0.001179] | 23378.74x [19267.34, 27490.13] | 2337773.7% [1926634.4, 2748912.9] |
| broker_authorization_only | 0.000983 [0.000787, 0.001179] | 653199.19x [516144.26, 790254.12] | 65319819.1% [51614326.4, 79025311.8] |
| language | 0.046736 [0.045275, 0.048197] | 991.23x [958.23, 1024.23] | 99022.9% [95722.9, 102322.8] |
| landlock | 0.047276 [0.045478, 0.049073] | 12918.54x [12648.25, 13188.83] | 1291754.1% [1264725.4, 1318782.9] |
| container | 0.052041 [0.050686, 0.053395] | 3322.22x [3237.80, 3406.65] | 332122.0% [323679.5, 340564.5] |
| broker | 0.139912 [0.138462, 0.141363] | 4656.28x [4608.20, 4704.36] | 465528.2% [460720.3, 470336.1] |

## Pandas utility and wall time

### Matched v19 A/B/C

| Mode | Utility | Mean task wall ms [95% CI] | vs A | Overhead vs A |
| --- | ---: | ---: | ---: | ---: |
| A | 50/50 | 9888.3 [9762.5, 10014.0] | 1.000x [1.000, 1.000] | 0.0% [0.0, 0.0] |
| B | 50/50 | 10489.8 [10388.7, 10590.9] | 1.061x [1.057, 1.065] | 6.1% [5.7, 6.5] |
| C | 50/50 | 11743.4 [11624.3, 11862.5] | 1.188x [1.177, 1.198] | 18.8% [17.7, 19.8] |

### C-closed v21

| Mode | Utility | Mean task wall ms [95% CI] | vs A | Overhead vs A |
| --- | ---: | ---: | ---: | ---: |
| C-closed | 45/50 | 13866.8 [13812.6, 13920.9] | N/A | N/A |

Raw records and failure details are under `raw/`; `statistics.json` is the machine-readable source for these tables.
