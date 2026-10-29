# Comparison with the preceding matched Pandas campaign

| Result | Previous campaign | Aggressive-default revision |
|---|---:|---:|
| Baseline success | 50/50 | 50/50 |
| Argus success | 45/50 | 45/50 |
| Baseline mean | 10366.9 ms | 10204.4 ms |
| Argus mean | 13225.2 ms | 13832.3 ms |
| Complete-cohort overhead | 27.6% [26.4%, 29.0%] | 35.6% [34.7%, 36.6%] |

The increase is not an optimizer regression measurement: this Pandas route does
not invoke the optimized typed Cedar backend. Model and system variance moved
the two means in opposite directions. The direct Landlock comparison in
`../aggressive-optimization-v1/` is the experiment that exercises batching.
