# Prepared host-policy follow-up

This follow-up corrects the phase boundary exposed by `activation-pool-v1`.
See `RESIDUAL-AUDIT.md` for the source-level decomposition and
`diagnostic.json` for the controller-only measurements.

The full rerun command, on a host capable of the sealed bubblewrap route, is:

```bash
libs/prebuilt/.venv/bin/python eval/distributed/common_linux_costs.py \
  --output eval/campaigns/policy-preflight-v1/raw
```

The runner performs five fresh sessions, five warmups, and twenty measured
calls per route and session by default. Each call is prewarmed before its
online timer. `worker_preflight_ms` is retained separately and is never added
to online invocation overhead.
