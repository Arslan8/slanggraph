# Final language-route ordinary-demo campaign

This artifact contains the clean 350-trial application campaign evaluated at
commit `bd035dd0643eea4bdfd409fb302a35f7bfceb913`. It uses five paired
repetition blocks over all 15 applications. The in-process baseline remains
inside LangGraph and differs from Argus only by the Argus enforcement path.

The primary result is a **1.097x pooled matched invocation ratio (9.7%
overhead)** over 109 task/repetition pairs that completed correctly in both
modes. The paired-block 95% interval is 1.071x-1.124x. Preparation, process
startup, audit logging, failures, and timeout caps are excluded from this
timer. Audit was disabled in both primary modes.

Argus selected language isolation for 14 of 15 applications. The language
route contributed 93 matched pairs with a 1.110x ratio (11.0% overhead;
95% CI 1.079x-1.151x). D4 is the only host-routed application because it
executes model-generated Python; its 16 matched pairs have a 1.080x ratio
(8.0% overhead; 95% CI 1.052x-1.102x).

D3 and T10 remain in the fixed evaluated population but are excluded from the
latency ratio because neither has a pair that completed correctly in both
modes. D3 fails in both modes in graph execution. T10 completes in baseline
and fails its Argus checkpoint-chain compatibility check. These are functional
outcomes, not language-admission rejections.

`trials.json` is the complete aggregate record, including status, route,
timing, model, error, security-evidence, and embedded output fields for every
attempt. Disposable per-trial SQLite reset copies and chart files remain local
and are not committed. `configuration.json` pins tasks, fixtures, sources,
model, routes, executables, timer boundaries, and audit mode.

## Reproduction

Start the pinned `qwen3:8b` model service on `127.0.0.1:11434`, then run from
the repository root in the same permissive outer Docker harness used for the
campaign. The outer container permits the production inner
bubblewrap/Landlock/seccomp boundary to activate; it is not an additional
confinement claim.

```bash
docker run --rm --user 0:0 --network host \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v /data/langgraph:/data/langgraph \
  -v /data/.cache/uv:/data/.cache/uv \
  -v /home/faculty/abk6349/.local/share/uv:/home/faculty/abk6349/.local/share/uv:ro \
  -v /home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1:/home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1:ro \
  -v /home/faculty/abk6349/.cargo/bin/cedar:/opt/cedar/cedar:ro \
  -e PATH=/opt/cedar:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -w /data/langgraph slg-linux-test:latest \
  /data/langgraph/eval/.venv/bin/python \
  eval/campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id reproduction-language-routes
```

Regenerate the tables, statistics, and plot from the retained aggregate:

```bash
MPLBACKEND=Agg /data/langgraph/eval/.venv/bin/python \
  eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id language-routes-final2-bd035dd06 \
  --output-dir \
  eval/campaigns/langgraph-demos-v3/language-routes-final2-bd035dd06
```
