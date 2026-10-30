# Matched Pandas rerun after worker/broker optimization

This campaign reruns the same ten-task protocol in five paired repetition
blocks on revision `3ce6e3a6d620a5df454061f9cf5a58fc6e77cf4c`.
`Baseline` is the adapted application without Argus. `slangGraph` is internal
configuration `C-full-lean`, including closed admission, principal and sealed
operator policies, Linux isolation, resource mediation, audit, publication
validation, and per-call Lean runtime validation.

Common preflight and model warmup are excluded symmetrically and recorded in
`raw/setup.json`. The matched subprocess timer includes process startup, model
calls, retries, application computation, and every recurring Argus check.

Regenerate and validate without rerunning:

```bash
libs/prebuilt/.venv/bin/python eval/apps/pandas/analyze_matched.py \
  --raw eval/campaigns/pandas-matched-aggressive-v2/raw \
  --output eval/campaigns/pandas-matched-aggressive-v2
libs/prebuilt/.venv/bin/python eval/apps/pandas/validate_matched.py \
  eval/campaigns/pandas-matched-aggressive-v2/raw \
  --output eval/campaigns/pandas-matched-aggressive-v2/validation.json
```

All 100 attempts are retained. The five protected non-finite-output refusals
remain in the primary comparison. The locally retained `raw/workerRoute`
binary is omitted from Git because of its size; its digest is frozen in the
raw configuration records.
