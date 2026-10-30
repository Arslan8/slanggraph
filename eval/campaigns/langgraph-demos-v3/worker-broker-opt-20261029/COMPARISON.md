# Ordinary-demo comparison

| Campaign | 13-runnable-application geometric-mean overhead |
|---|---:|
| Original | 37.0% [29.9%, 43.9%] |
| Exact-cache optimized | 33.3% [28.3%, 36.8%] |
| Aggressive-default revision | 34.7% [28.8%, 39.5%] |
| Worker/broker optimized revision | 34.3% [28.4%, 39.0%] |

D3 remains excluded because neither mode completes, and T10 remains excluded
because Argus does not complete. The current run has 278 completed trials, 50
execution errors, 20 compatibility failures, and two timeouts across both
modes. D4 remains noisy and has different success/failure composition between
modes, so the small suite-level movement must not be attributed solely to the
optimization. Route-local before/after measurements are in
`../../worker-broker-optimization-v1/`.
