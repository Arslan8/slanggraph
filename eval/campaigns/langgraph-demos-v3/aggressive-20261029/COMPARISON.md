# Ordinary-demo comparison

| Campaign | 13-runnable-application geometric-mean overhead |
|---|---:|
| Original | 37.0% [29.9%, 43.9%] |
| Exact-cache optimized | 33.3% [28.3%, 36.8%] |
| Aggressive-default revision | 34.7% [28.8%, 39.5%] |

D3 remains excluded because neither mode completes; T10 remains excluded because
Argus does not complete. The aggressive-default cohort has 139 completed trials
in each mode, 25 execution errors in each mode, ten compatibility failures in
each mode, and one timeout in each mode.

The differences between these suite estimates must not be attributed to typed
Cedar batching because this application harness uses the object authorizer.
D4 remains especially noisy: its ratio is 0.679x with a 0.324-1.134 interval and
different success/failure composition between modes. The direct optimizer result
is reported in `../../aggressive-optimization-v1/`.
