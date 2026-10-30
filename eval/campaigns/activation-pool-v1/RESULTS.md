# Exact-policy worker-pool evaluation

Workers are single-use and enter the pool only after exact mounts, namespaces, limits, seccomp, and pinned source compilation are installed. Idle workers contain no principal grant or invocation credential. Every claim receives a fresh host attestation, grant, nonce, execution-context binding, activation receipt, and `GO`.

| Route | Calls | Online mean (95% CI) | Preflight mean | Activation mean |
|---|---:|---:|---:|---:|
| linux | 100 | 133.24 ms [132.05, 134.43] | 157.53 ms | 0.93 ms |
| linux-lean | 100 | 162.85 ms [161.66, 164.05] | 163.02 ms | 10.62 ms |

All measured calls must be valid pool hits for regeneration to succeed. Preflight is reported separately and is not counted as recurring online execution overhead; deployments that cannot keep an exact worker ready must pay that provisioning cost.
