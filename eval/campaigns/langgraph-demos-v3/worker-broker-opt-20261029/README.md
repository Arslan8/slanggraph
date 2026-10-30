# Ordinary-demo rerun after worker/broker optimization

This report regenerates raw run `worker-broker-opt-full-20261029`, evaluated at
revision `3ce6e3a6d620a5df454061f9cf5a58fc6e77cf4c`. It contains 350 retained
attempts across 15 applications and five paired repetition blocks.

The parent subprocess boundary includes startup, model calls, tool work, every
enabled recurring Argus check, and shutdown. Campaign preflight, frozen-fixture
preparation, and shared model warmup are excluded symmetrically. D4-D5 use the
fixed 300-second cap; the remaining applications use 180 seconds. One D4 trial
timed out in each mode, and both capped values remain in the means.

Regenerate without rerunning:

```bash
uv run --python 3.11 --project eval --with matplotlib \
  python eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id worker-broker-opt-full-20261029 \
  --output-dir eval/campaigns/langgraph-demos-v3/worker-broker-opt-20261029
```

Raw records are under `../raw/worker-broker-opt-full-20261029/`. Repeated
per-trial database/font-cache copies are omitted from Git; frozen fixtures,
hashes, before/after state, outputs, traces, and trial records are retained.
