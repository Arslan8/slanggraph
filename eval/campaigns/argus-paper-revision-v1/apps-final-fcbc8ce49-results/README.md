# Final 15-application rerun

This artifact summarizes the fixed 15-application population rerun at repository
HEAD `fcbc8ce49fc0b2d5911a9db7371685736936be5f`. The relevant runner,
application, and Argus runtime sources matched that revision; unrelated working
tree edits did not touch the measured paths. The run contains 350 attempts:
five deterministically shuffled paired blocks, five tasks for D1-D5, one task
for T1-T10, and both Baseline and Argus for every task.

The baseline condition still runs inside LangGraph. It disables Argus admission
and enforcement but retains the same adapted graph, prompts, fixtures, model,
and task oracle. The Argus condition uses the application's declared protected
route: the language worker route for admitted tool code and the registered
resource-mediator broker where the application requires SQL, retrieval, search,
Python-session, or travel resources.

The pinned configuration was:

- Ollama `qwen3:8b` digest
  `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
- Native Lean checker digest
  `aa2bcfbb000cae794fd4667228bca1476544db987a8f3092a04a411a30219502`.
- Temperature 0, generation seed 20261005, and no reasoning effort.
- 180-second timeout for D1-D3 and T1-T10; 300 seconds for D4-D5.
- Parent subprocess wall clock, including process startup, as the primary timer.
- Docker image `slg-linux-test` with host networking and the established
  unconfined outer profiles so the inner Argus route could use bubblewrap.

## Results

- 13/15 applications had at least one completed trial in both modes.
- The 10 applications with identical correctness counts in both modes have a
  geometric-mean ratio of **1.351x**, or **35.1% overhead** (95% paired-block
  CI `1.286x-1.431x`). This is the defensible utility-matched secondary result.
- The broader 13-application attempt-duration summary is `1.255x` (25.5%), but
  it includes differing correctness and D4 failure/timeout behavior and is not
  a pure enforcement-overhead estimate.
- D3 plan-execute completed 0/25 in both modes. Its exact failures are
  `GraphRecursionError` at recursion limit 50 and `IndexError: list index out
  of range`.
- T10 time-travel completed 5/5 in Baseline and 0/5 in Argus. Every Argus run
  was rejected with `PermissionError: checkpoint:broken_chain`; checkpoint
  integrity was not disabled to make the demo pass.
- D4 multi-agent completed 17/25 Baseline attempts and 22/25 Argus attempts.
  Baseline had seven recursion-limit compatibility failures and one timeout;
  Argus had three timeouts. Timeout durations remain capped at 300 seconds in
  the reported means.
- All T1-T9 trials were correct in both modes: 45/45 Baseline and 45/45 Argus.

`RESULTS.md` contains every application's attempts, correctness, status counts,
means, ratios, and paired-block intervals. `statistics.json` is the
machine-readable result, and `application-overhead.png` is the generated plot.

The complete raw record, including commands, stdout/stderr, exact tracebacks,
per-trial security evidence, and timing fields, remains locally at
`eval/campaigns/langgraph-demos-v3/raw/final-fcbc8ce49-20261105/`. Its
`trials.json` SHA-256 is
`e2dcbd16378df6849680ecfce1cc05e52a57a02f494041b286884ba3da356d76`.

## Reproduction

With the pinned Ollama model and native checker available, run:

```sh
docker run --rm --user 0:0 --network host \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v /data/langgraph:/data/langgraph \
  -v /home/faculty/abk6349/.local/share/uv/python:/home/faculty/abk6349/.local/share/uv/python:ro \
  -v /home/faculty/abk6349/.elan:/home/faculty/abk6349/.elan:ro \
  -v /home/faculty/abk6349/.cargo/bin/cedar:/opt/cedar/cedar:ro \
  -v /home/faculty/abk6349/.cache/uv:/root/.cache/uv \
  -e PATH=/opt/cedar:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -w /data/langgraph slg-linux-test \
  uv run --python 3.11 --project eval \
  --with langchain-openai==1.7.2 --with scikit-learn --with pandas \
  --with langchain-community --with langchain-experimental \
  --with matplotlib --with pytz \
  python eval/campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id final-fcbc8ce49-20261105 --repetitions 5

python3 eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id final-fcbc8ce49-20261105 \
  --output-dir eval/campaigns/argus-paper-revision-v1/apps-final-fcbc8ce49-results
```
