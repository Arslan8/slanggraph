# Aggressive optimization route evaluation

This campaign measures four current execution routes with five fresh process
sessions, one first invocation, ten warmups, and 20 retained measured calls per
session. It also compares `normal` and `aggressive` Cedar modes on the same
Lean-backed Landlock workload at the same source revision.

Evaluated pre-commit revision:
`62875ce699533e81842bf084025ab494469cbbbd`. Aggressive-mode implementation:
`f35c79aadedf48712bdb669b4fa53548e3ea4504`. Host: Linux
`6.17.0-1033-oem`, Intel Xeon w5-3435X, 32 logical CPUs. The route processes pin
themselves to one CPU. The pinned Lean worker digest is
`6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08`.

Only the Landlock route invokes `CedarPolicyBackend`, so only that route is a
direct aggressive-mode experiment. Language, container, and object-broker runs
are same-revision controls using their matching direct baselines. Container and
broker baselines are workload-specific; the broker is never divided by the
file-read baseline.

Reproduce into fresh output directories:

```sh
libs/prebuilt/.venv/bin/python \
  eval/campaigns/current-implementation-v1/scripts/run_language_useful_work.py \
  --output /tmp/argus-aggressive-language
libs/prebuilt/.venv/bin/python \
  eval/campaigns/current-implementation-v1/scripts/run_landlock_costs.py \
  --output /tmp/argus-aggressive-landlock --optimization-level aggressive
libs/prebuilt/.venv/bin/python \
  eval/campaigns/current-implementation-v1/scripts/run_landlock_costs.py \
  --output /tmp/argus-normal-landlock --optimization-level normal
libs/prebuilt/.venv/bin/python \
  eval/campaigns/current-implementation-v1/scripts/run_container_costs.py \
  --output /tmp/argus-aggressive-container
libs/prebuilt/.venv/bin/python \
  eval/campaigns/current-implementation-v1/scripts/run_broker_costs.py \
  --output /tmp/argus-aggressive-broker
uv run --python 3.11 --project eval python \
  eval/campaigns/aggressive-optimization-v1/regenerate.py
```

`raw/` contains every setup row, first use, warmup, measured call, phase ledger,
matching direct call, validity result, and session log.
