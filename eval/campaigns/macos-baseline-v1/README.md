# macOS frozen baseline campaign

Baseline-only execution of the existing ordinary-demo and Pandas workloads.
This does not execute or qualify the protected macOS application route and does
not establish a cross-OS performance effect.

The launcher reuses the ordinary-demo v3 command builder, task definitions,
fixtures, timeout limits and correctness oracles, and the latest matched Pandas
backend, ten tasks, dataset, workflow contract, computation API and oracle.
It selects the Baseline jobs from each original paired/shuffled schedule.

The ordinary-demo runner's Linux protection preflight and Pandas campaign's
unconditional Lean capture and `taskset` launcher are omitted for these baseline
jobs. Application graph and generated-code semantics are unchanged. macOS CPU
affinity is uncontrolled; model/runtime and Python dependency differences are
recorded. The Pandas upstream vendor sandbox is retained, including its existing
best-effort platform-specific resource-limit behavior.

Full denominators: 175 ordinary-demo baseline trials (35 tasks × 5 repetitions)
and 50 Pandas baseline trials (10 tasks × 5 repetitions). The 350 ordinary-demo
and 100 Pandas paired-condition denominators require a protected condition,
which this campaign does not run. First-task pilot observations remain separate.

Reproduce after serving the pinned `qwen3:8b` model locally:

```sh
eval/.venv/bin/python eval/remaining/macos_baseline_campaign.py \
  --output eval/campaigns/macos-baseline-v1/new-run \
  --upstream eval/vendor/ai-data-science-team
eval/.venv/bin/python eval/remaining/verify_macos_baseline.py \
  eval/campaigns/macos-baseline-v1/new-run
```

The output directory must be new. The upstream checkout must be pinned to
`4ffeb7f38178aa250917f29b01355f8b89ba809e`. Raw subprocess records, outputs,
transcripts, fixture resets, source bytes and setup metadata are retained.
The verifier recomputes the frozen oracles from raw outputs, checks the full
matrix and archive identities, and rejects any protected evidence in a baseline.
Failures and timeout-capped attempts remain in the denominator.

## Host setup used for this campaign

The runtime was installed locally under ignored `eval/vendor/`, not as a system
service. Ollama v0.40.13 served `qwen3:8b` on loopback; its API-reported digest
was checked against the frozen pin before each cohort. `runtime-install.json`
retains binary/archive hashes and `model-runtime.json` records the loaded context.
The model uses the M4 Pro Metal backend. Python is a separate managed 3.11.18
virtual environment under `eval/.venv/`.

The setup installed the repository's editable checkpoint, prebuilt and core
libraries, `langchain-openai==1.7.2`, `langchain-core==1.7.0`, `openai==3.37.0`,
scikit-learn, Pandas, langchain-community, langchain-experimental, matplotlib,
pytz, the pinned upstream Pandas application, `ipython==9.17.1` and
beautifulsoup4. Exact resolved versions are retained in each run. Some versions
differ from the historical Linux intake environment; those differences are
explicit in `dependency-comparison.json` and prohibit an OS-only timing inference.

The customer-support database must first be decompressed from the committed
`travel2.sqlite.gz`; its uncompressed SHA-256 must be
`7646259e80230dc9bd92914466e13874bba82f461473d6a66552e819898eb66b`.
The full runner validates every frozen demo fixture, the task-definition digest,
the upstream checkout revision and the served model digest before timed trials.


Completed results and the evidence bundle are in [RESULTS.md](RESULTS.md).
To restart the retained local model service for a rerun, run this from the
repository root in a separate terminal:

```sh
OLLAMA_HOST=127.0.0.1:11434 OLLAMA_MODELS="$PWD/eval/vendor/macos-models" \
  eval/vendor/macos-runtime/ollama serve
```
