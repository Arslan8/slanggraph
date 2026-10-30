# Exact-policy worker-pool campaign

This campaign measures the aggressive Argus Linux route after moving invariant
worker activation into explicit preflight. It keeps fresh per-invocation
authorization and activation binding online and records preflight separately.

Reproduce:

```bash
libs/prebuilt/.venv/bin/python eval/distributed/common_linux_costs.py \
  --output eval/campaigns/activation-pool-v1/raw \
  --sessions 5 --warmups 5 --measured 20
libs/prebuilt/.venv/bin/python \
  eval/campaigns/activation-pool-v1/regenerate.py
```

The protocol uses five independent process sessions for each route, five
warmups, and 20 measured calls. Each invocation receives a newly provisioned
exact-policy worker before the online timer; this provisioning time is retained
as `worker_preflight_ms`. A pool miss or invalid result invalidates the campaign.
