# Worker/broker optimization rerun

This campaign reruns the four route-specific execution-cost experiments on
revision `3ce6e3a6d620a5df454061f9cf5a58fc6e77cf4c` after the worker activation,
mediator validation, broker indexing, and lifecycle optimizations.

Reproduce from the repository root:

```bash
libs/prebuilt/.venv/bin/python eval/campaigns/current-implementation-v1/scripts/run_language_useful_work.py --output eval/campaigns/worker-broker-optimization-v1/raw/language
libs/prebuilt/.venv/bin/python eval/campaigns/current-implementation-v1/scripts/run_landlock_costs.py --output eval/campaigns/worker-broker-optimization-v1/raw/landlock-aggressive --optimization-level aggressive
libs/prebuilt/.venv/bin/python eval/campaigns/current-implementation-v1/scripts/run_container_costs.py --output eval/campaigns/worker-broker-optimization-v1/raw/container
libs/prebuilt/.venv/bin/python eval/campaigns/current-implementation-v1/scripts/run_broker_costs.py --output eval/campaigns/worker-broker-optimization-v1/raw/broker
libs/prebuilt/.venv/bin/python eval/campaigns/worker-broker-optimization-v1/regenerate.py
```

The timer excludes one-time campaign preparation and includes recurring
authorization, activation, execution/transport, audit, cleanup, and framework
work. Setup records and every raw call are retained under `raw/`.
