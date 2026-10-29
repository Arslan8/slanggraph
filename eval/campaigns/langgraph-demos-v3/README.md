# Argus ordinary-demo matched campaign

This campaign evaluates all 15 selected ordinary LangGraph demos with one protocol.
Each application uses five paired repetition blocks. Baseline and Argus jobs are
shuffled within each block with seed `20261028`; every selected task stays in its
repetition block. The primary timer is parent-process wall clock, including process
startup and shutdown. Model calls and model wall time are also recorded inside the
workflow. Failures and timeout-capped attempts are retained.

The ten historical tutorial demos each retain their one frozen upstream task. D1-D5
retain all five frozen tasks. This gives 350 attempted trials: 100 for the ten
one-task demos and 250 for D1-D5.

Run the campaign with the pinned local `qwen3:8b` service available at
`127.0.0.1:11434`:

```bash
uv run --python 3.11 --project eval \
  --with langchain-openai==1.7.2 --with scikit-learn --with pandas \
  --with langchain-community --with langchain-experimental \
  --with matplotlib --with pytz \
  python eval/campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id reproduction-local --repetitions 5

uv run --python 3.11 --project eval --with matplotlib \
  python eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id reproduction-local
```

Choose a fresh run ID if `reproduction-local` already exists. To regenerate the
committed paper outputs without rerunning trials, use
`--run-id parity-matched-20261029` only with `regenerate.py`.

The evaluated source revision is
`d9b643785df06a3b9c9dc003098b340e11e170d0`. That revision adds a preflight
assertion requiring identical model-visible tool names, descriptions, and argument
schemas across modes. The earlier preliminary run is excluded from the committed
artifact because its protected D1-D5 adapters used different tool descriptions; it
must not be used for paper results.

The primary raw artifact is `raw/parity-matched-20261029/`. Per-trial reset copies of
the Chinook and travel databases are not duplicated in the committed artifact: their
frozen source fixtures and SHA-256 hashes are retained, and every D5 output records
the before/after resource state. The runner recreates fresh copies for every trial.

Per-application overhead is the ratio of complete-cohort mean wall times. Its 95%
interval resamples the five paired repetition blocks and keeps all tasks in a block
together. The suite result is the geometric mean of valid per-application ratios.
It excludes an application when either mode has no completed trial; exclusions and
success counts remain visible.
