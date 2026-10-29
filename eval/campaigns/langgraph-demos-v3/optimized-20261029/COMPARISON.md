# Before/after comparison

The primary geometric mean covers the same 13 runnable applications in both
campaigns. D3 has no completed attempt in either mode, and T10 has no completed
Argus attempt, so there is no defensible all-15 runtime average.

| Result | Before optimization | Optimized rerun | Change |
|---|---:|---:|---:|
| 13-application geometric-mean overhead | 37.0% [29.9%, 43.9%] | 33.3% [28.3%, 36.8%] | -3.7 percentage points |
| D1 SQL overhead | 37.6% | 22.5% | -15.2 percentage points |
| T8 serial-tools overhead | 51.9% | 34.9% | -17.0 percentage points |
| T9 memory overhead | 52.5% | 45.8% | -6.7 percentage points |
| D5 support overhead | 8.3% | 8.2% | -0.1 percentage points |

The suite-level reduction must not be attributed entirely to policy caching.
D4 is highly variable: its ratio changed from 0.966x to 0.680x while the new run
contained one 300-second timeout in each mode and different compatibility-failure
counts. Excluding D4 as a sensitivity check, the same-application geometric mean
is essentially unchanged: 41.08% before versus 41.01% after. The targeted cache
signal is clearest in repeated-authorization workloads such as D1 and T8; several
single-call demos are dominated by process startup, model time, and isolation.

Utility and status also remain separate from timing. The optimized run records
109/175 correct Baseline attempts and 118/175 correct Argus attempts, with 139
completed attempts, 25 D3 execution errors, 10 compatibility failures, and one
D4 timeout in each mode. The runtime-only optimization did not resolve D3 or T10.
