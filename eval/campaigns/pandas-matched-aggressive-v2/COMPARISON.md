# Comparison with the preceding aggressive Pandas campaign

| Result | Previous | Current optimized revision |
|---|---:|---:|
| Baseline success | 50/50 | 50/50 |
| Argus success | 45/50 | 45/50 |
| Baseline mean | 10204.4 ms | 10249.9 ms |
| Argus mean | 13832.3 ms | 13951.4 ms |
| Complete-cohort overhead | 35.6% [34.7%, 36.6%] | 36.1% [35.1%, 37.0%] |

This is not evidence of a Pandas speedup. The measured overhead is slightly
higher, and the intervals overlap. The optimized worker/broker hot paths are
measured directly in `../worker-broker-optimization-v1/`; application-level
model and host variance can dominate their contribution here.
