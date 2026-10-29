# Matched Pandas rerun on the aggressive-default revision

This campaign reruns the same ten-task matched Pandas protocol in five paired
repetition blocks. Reader-facing `Baseline` is the adapted application without
Argus enforcement. Reader-facing `slangGraph` is internal configuration
`C-full-lean`: closed admission, principal and sealed operator policies, Linux
isolation, resource mediation, audit, publication validation, and the per-call
Lean runtime contract are all included in the measured wall time.

The evaluated pre-commit source revision is
`62875ce699533e81842bf084025ab494469cbbbd`; the aggressive Cedar implementation
it contains is commit `f35c79aadedf48712bdb669b4fa53548e3ea4504`. Pandas uses
`CedarObjectAuthorizer`, not the typed `CedarPolicyBackend`, so this is a
complete-system regression/control rerun under the aggressive-default revision.
It does not measure the new batching path directly.

The raw artifact is `raw/`. `preflight.json` freezes the tasks, fixture, source
digests, model digest/settings, treatment inventory, timeout, timer boundary,
and job order. `trials.jsonl` retains all 100 attempts. The selected Lean binary
is retained locally as `raw/workerRoute`; it is omitted from Git if the hosting
limit rejects it, while its SHA-256 remains recorded.

Regenerate and validate without rerunning:

```sh
libs/prebuilt/.venv/bin/python eval/apps/pandas/analyze_matched.py \
  --raw eval/campaigns/pandas-matched-aggressive-v1/raw \
  --output eval/campaigns/pandas-matched-aggressive-v1
libs/prebuilt/.venv/bin/python eval/apps/pandas/validate_matched.py \
  eval/campaigns/pandas-matched-aggressive-v1/raw \
  --output eval/campaigns/pandas-matched-aggressive-v1/validation.json
```

The primary interval is a paired repetition-block bootstrap. It retains the
five protected non-finite-output refusals and does not treat the 100 task trials
as independent repetitions.
