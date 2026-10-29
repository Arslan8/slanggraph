# Aggressive-default ordinary-demo rerun

This directory contains regenerated outputs for raw run
`aggressive-full-20261029`, evaluated at pre-commit revision
`62875ce699533e81842bf084025ab494469cbbbd`. It retains 350 attempts across 15
applications and five paired repetition blocks. Baseline and Argus jobs were
shuffled within each block with seed `20261028`.

The parent subprocess timer includes process startup, model calls, tool work,
all enabled Argus checks, and shutdown. D4-D5 use a 300-second cap and the other
applications use 180 seconds. One D4 attempt timed out in each mode; both capped
durations and every failure remain in the means.

These applications use the object-policy authorizer. The new typed
`CedarPolicyBackend` batching path is not active, so this is a full-application
regression/control run on the aggressive-default revision, not a direct batching
benchmark.

Regenerate without rerunning:

```sh
uv run --python 3.11 --project eval --with matplotlib \
  python eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id aggressive-full-20261029 \
  --output-dir eval/campaigns/langgraph-demos-v3/aggressive-20261029
```

The raw records are in `../raw/aggressive-full-20261029/`. Per-trial Chinook and
travel database copies are omitted because the frozen source fixtures, hashes,
and recorded before/after states reproduce them.
