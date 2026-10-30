# Aggressive inline ordinary-demo campaign

This directory contains the generated analysis for run
`aggressive-inline-20261030`. The matching raw record is
`../raw/aggressive-inline-20261030/trials.json`; it retains all 350 attempted
trials, including failures, timeout-capped durations, stdout, stderr, and
security evidence summaries. `configuration.json` records the frozen task,
fixture, source, model, and worker-route digests.

## Reproduction

From the repository root, with the pinned Ollama model service available:

```bash
uv run --python 3.11 --project eval \
  --with langchain-openai==1.7.2 \
  --with scikit-learn \
  --with pandas \
  --with langchain-community \
  --with langchain-experimental \
  --with matplotlib \
  --with pytz \
  python eval/campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id aggressive-inline-20261030 \
  --repetitions 5
```

Regenerate the tables, statistics, confidence intervals, and graph with:

```bash
uv run --python 3.11 --project eval --with matplotlib \
  python eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id aggressive-inline-20261030 \
  --output-dir eval/campaigns/langgraph-demos-v3/aggressive-inline-20261030
```

The run used five paired repetition blocks and shuffled modes within each
block with seed `20261028`. The primary timer is parent subprocess wall time,
including process startup. Argus used aggressive Cedar evaluation,
preflight-only immutable-artifact checking, and the inline native lifecycle
checker recorded in `configuration.json`.

## Interpretation boundary

The 1.019x suite summary is an attempt-duration geometric mean over the four
applications with completed trials in both modes. It is not a clean
enforcement-only overhead estimate because utility and terminal status differ
for some applications. The equal-success-count sensitivity result contains
only D5 and is 1.066x. There is no defensible all-15 overhead average: D3
failed in both modes, and T1-T10 could not activate Argus because bubblewrap
is unavailable on the evaluated host.

Large per-trial disposable SQLite fixture copies and chart files remain in the
local campaign workspace but are intentionally not stored in Git. Their
source fixture hashes and the complete scalar/raw trial records are retained.
