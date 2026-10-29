# Optimized runtime-overhead rerun

This directory contains the regenerated tables and graph for raw run
`optimized-matched-20261029-v3`. The evaluated source revision is
`00c46fe25189cd67df0ea98ced9186af024926ca` (`perf(security): cache Cedar
evaluation paths`). The application harness, task/source/fixture digests, model
digest, job order, correctness checks, timer boundaries, and bootstrap method
match the earlier `parity-matched-20261029` campaign.

The run contains 350 attempts: 15 applications, five paired repetition blocks,
and 175 attempts in each of Baseline and Argus. The parent-process timer includes
process startup, model calls, tool execution, every enabled Argus runtime check,
and shutdown. D4-D5 use a 300-second cap; all other applications use 180 seconds.
One D4 attempt timed out in each mode and both capped durations remain in the
primary means.

Regenerate these outputs without rerunning trials:

```bash
uv run --python 3.11 --project eval --with matplotlib \
  python eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id optimized-matched-20261029-v3 \
  --output-dir eval/campaigns/langgraph-demos-v3/optimized-20261029
```

The raw records and frozen configuration are under
`../raw/optimized-matched-20261029-v3/`. Per-trial reset database copies are
reproducible from the frozen fixtures and are intentionally excluded from the
published raw directory; the JSON records preserve fixture hashes and before/after
resource state.
