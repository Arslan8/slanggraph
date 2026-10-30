# Inline lifecycle-checker evaluation

This campaign evaluates implementation commit `c1bdeff5c`, which exports the
Lean-defined and proved worker-route decision procedure as generated native
code and invokes it inline through a narrow C ABI. Both the checker library and
its generated-code runtime are digest-pinned and loaded from sealed memfds once
per process. No checker subprocess is created per decision.

Reproduce after building the pinned native artifacts:

```bash
python3 proofs/worker-route/build_native.py \
  --lake /home/faculty/abk6349/.elan/bin/lake \
  --output proofs/worker-route/.lake/build/lib/libargus_worker_route.so
libs/prebuilt/.venv/bin/python \
  eval/campaigns/current-implementation-v1/scripts/run_landlock_costs.py \
  --output eval/campaigns/native-lifecycle-v1/raw/landlock-aggressive \
  --optimization-level aggressive
libs/prebuilt/.venv/bin/python \
  eval/campaigns/native-lifecycle-v1/regenerate.py
```

The protocol uses five independent sessions, one first-use call, ten warmups,
and twenty measured calls per session. The prior sealed-subprocess campaign is
used only for the explicitly labeled sequential before/after comparison.

The pinned proof audit replay passed all 72 selected semantic obligations, five
negative controls, 20 driver tests, and fresh kernel replay. Its report and
compact logs are retained under `proof-audit/`. The implementation validation
also passed `make format`, `make lint`, and the complete prebuilt test suite:
5,709 passed and three explicitly prerequisite-gated native tests skipped.
