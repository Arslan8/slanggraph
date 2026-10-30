# Aggressive execution-cost rerun

Revision `41ea67d74530de858b59e3a565a7d15a13428cfb`; five fresh sessions, five warmups, and twenty measured calls per session. Admission, policy preparation/lowering, integrity setup, and worker prewarming are preflight and outside the online timer.

| Route | Valid calls | Mean ms | 95% session-block interval | Added ms |
|---|---:|---:|---:|---:|
| Direct | 100/100 | 0.041 | [0.040, 0.042] | — |
| Argus language | 100/100 | 5.238 | [5.169, 5.308] | 5.197 |

The protected mean comprises authorization 0.833 ms, activation 0.109 ms, execution 0.366 ms, trusted-async audit acceptance 0.281 ms, and framework residual 3.649 ms. Runtime policy lowering and runtime Lean are both 0.000 ms.

The pooled Linux routes could not run: mandatory bubblewrap isolation was unavailable during preflight. The configuration failed closed; no isolation option was weakened, and no runtime number is reported.
