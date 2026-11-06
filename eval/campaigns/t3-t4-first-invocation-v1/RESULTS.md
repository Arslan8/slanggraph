# First-invocation weather workload rerun

This campaign reruns only `fixed-weather` and `parallel-weather` from
`eval/apps/demos/tool_calling_protected.py` using the retained four-mode
application-comparison protocol. The evaluated revision is
`d3b246a1d6bebd1638fe55af916cab7b2f4820e7` on `wip`.

## Protocol

- Five repetition blocks, with both workloads and all four modes shuffled
  within each block using seed `20261028`.
- Forty sequential executions on the same Linux host. Every execution used a
  fresh child process; no attempts were retried, removed, or replaced.
- The application prepared its graph and policy before starting the primary
  timer. The timer covers exactly the first `graph.invoke()`; there was no
  warmup invocation.
- Interpreter startup, preparation, NoNo activation, APF sandbox creation,
  and cleanup are outside `invocation_ms` and retained in their original
  separate timing fields.
- Audit logging was disabled. Argus installed the operator MAC, used the
  authenticated `alice` principal with a fresh session, and reported the
  language route in all five executions of both workloads. There was no host
  fallback.
- NoNo used its retained read-only code/runtime grants, fresh writable trial
  directory, blocked network with only port 11434 allowed, disabled audit,
  and disabled rollback. APF used the retained projected policy, image, local
  relay configuration, and fresh sandbox lifecycle.
- The original demo reconstructs its tool calls in every fresh process but
  uses deterministic, process-local textual call labels (`fixed-weather`,
  `parallel-weather`, and `parallel-cities`). This is unchanged from the
  retained application-comparison protocol. Because each measurement is a
  fresh process and fresh principal session, no authorization or call state is
  reused across measurements.

Exact command:

```bash
PYTHONDONTWRITEBYTECODE=1 eval/.venv/bin/python \
  eval/campaigns/t3-t4-first-invocation-v1/run_campaign.py \
  --run-id first-invocation-d3b246a1d
```

## Invocation results

All 40 executions completed and produced the expected tool results. P95 uses
nearest rank. Baseline-relative overhead is calculated from the five-sample
arithmetic means for the same workload.

| Workload | Mode | n | Correct | Mean (ms) | Median (ms) | P95 (ms) | Delta (ms) | Relative overhead |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `fixed-weather` | Baseline | 5 | 5/5 | 3.905 | 3.691 | 4.419 | 0.000 | 1.000x (0.0%) |
| `fixed-weather` | Argus | 5 | 5/5 | 19.149 | 16.246 | 31.207 | +15.244 | 4.904x (+390.4%) |
| `fixed-weather` | NoNo-enforced | 5 | 5/5 | 4.457 | 3.736 | 7.481 | +0.552 | 1.141x (+14.1%) |
| `fixed-weather` | APF-enforced | 5 | 5/5 | 4.750 | 4.403 | 6.861 | +0.845 | 1.216x (+21.6%) |
| `parallel-weather` | Baseline | 5 | 5/5 | 4.167 | 4.216 | 4.345 | 0.000 | 1.000x (0.0%) |
| `parallel-weather` | Argus | 5 | 5/5 | 17.967 | 18.136 | 18.248 | +13.800 | 4.312x (+331.2%) |
| `parallel-weather` | NoNo-enforced | 5 | 5/5 | 4.100 | 4.063 | 4.806 | -0.066 | 0.984x (-1.6%) |
| `parallel-weather` | APF-enforced | 5 | 5/5 | 4.213 | 4.259 | 4.462 | +0.046 | 1.011x (+1.1%) |

The negative NoNo delta for `parallel-weather` is measurement noise, not a
speedup claim. Likewise, NoNo and APF enforce OS-visible effects but do not
mediate these constant-returning logical tool calls as typed resource/action
terminals; the retained comparator semantic gap remains.

## Retained evidence

- `raw/first-invocation-d3b246a1d/configuration.json`: evaluated revision,
  host, source and binary digests, retained enforcement configuration, and
  top-level command.
- `raw/first-invocation-d3b246a1d/schedule.json`: exact shuffled order of all
  40 sequential executions.
- `raw/first-invocation-d3b246a1d/trials.json`: all per-execution records in
  execution order.
- Each `rep-*` leaf contains the raw application output and `trial.json` with
  the exact child or sandbox command, invocation/preparation/process timing,
  and APF activation/cleanup timing where applicable.
- `raw/first-invocation-d3b246a1d/summary.json`: machine-readable summary and
  every invocation sample.

Post-run checks found 40 trial records, 40 completed statuses, 40 correct
outputs, no censored executions, no APF cleanup failure, and no remaining
OpenShell sandbox.
