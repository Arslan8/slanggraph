# Linux final-r4 handoff

Campaign `unified-final-v1`, configuration
`d8fdb318506dd84466339a78d433c290b467bbde379a379b5fef0798c33f468c`,
build `85a93be0f72c7c2ea305256780779786b75c5dcd2aa4078ca9ee0b1e0cbf8391`.

## Final implementation and reporting repairs

- The Linux host backend previously had no lowering for the
  `aggregate_cpu_ms` obligation. The production worker already enforces one
  process (`pids=1`) and denies process creation with seccomp, so aggregate
  CPU is exactly the worker CPU. The backend now lowers an exact whole-second
  aggregate limit to `RLIMIT_CPU` under that invariant and rejects values it
  cannot represent exactly. Five independent attack repetitions entered the
  protected worker, exhausted the budget, were terminated before their
  forbidden effect, and passed the external oracle.
- The direct-shared-memory test previously reused a canary that the positive
  control did not reliably observe. It now has a distinct protected canary
  outside SQLite's live WAL-index bytes. The unprotected positive control
  observes it and all five protected attacks fail to affect it.
- The unified adapter previously mislabeled an upstream
  `Rejected before execution` result as `inconclusive`. The source category is
  now preserved and validated. Rejection is reported separately from an attack
  that entered the worker and was prevented.
- The prior application fixes remain frozen: D3 planning termination, T10
  principal-bound one-use checkpoint restore, D4 handoff/termination and APF
  integration, D5 leg-scoped updates, Pandas date/aggregation/oracle repairs,
  the minimal optimized host microbenchmark adapter, matched write effects,
  and symmetric APF submit-to-safe-return timing. Detailed causes and
  representative evidence are in `DEBUGGING-QUALIFICATION.md`.

## Final outcomes

- Validation passes with zero errors: 5,635 request records, 225 Linux host
  security records, and 60 sustained-load records.
- All 45 Linux cases are decisive: 35 attacks are prevented after entering the
  protected path, 5 invalid or unsupported obligation requests are rejected
  before execution, and 5 authorized positive controls succeed. Every case has
  five repetitions and an independent oracle. There are zero inconclusive,
  failed, or unsupported cases.
- The repaired D3, D4, D5, and T10 cells have no execution or compatibility
  failures. D4, D5, and T10 pass every measured oracle. D3 retains genuine
  model-answer errors: baseline 66/150 correct; Argus, nono, and APF each
  60/150 correct.
- Pandas passes 300/300 measured trials in each of baseline and Argus. The
  retained, compatible `read_bob` and `update_bob` resource probes are both
  prevented with unchanged protected state.
- Optimized host request-latency means are 32.6--34.5 ms. Sustained host
  throughput is 6.4--6.5 requests/s because safe worker replacement is a
  recurring lifecycle cost and remains inside the lifecycle accounting.
- APF/OpenShell and nono remain best-available reduced-enforcement
  comparisons. `policy_mapping.json` names the exact missing restriction for
  each application; no result is labeled equivalent merely because a
  comparator uses a different mechanism.
- No macOS outcome is claimed. The shared manifest and runner remain available
  for the macOS student.

## Rerun and retention decision

The aggregate-CPU lowering, shared-memory oracle, and category repair affect
only Evaluation 2. All 45 Linux host-security cases were therefore rerun on
the newly qualified and frozen build. Evaluation 1, Evaluation 3, Evaluation
4, and the Pandas resource probes are retained from `final-r3`; their runtime,
policy, fixtures, routes, and timing implementations are unchanged.
`retained-lineage.json` records source hashes and the compatibility rule.

## Reproduction

From the repository root:

```bash
uv run --project eval python eval/campaigns/unified-final-v1/run.py prepare \
  --result eval/campaigns/unified-final-v1/results/final-r4
uv run --project eval python eval/campaigns/unified-final-v1/run.py qualify \
  --result eval/campaigns/unified-final-v1/results/final-r4
uv run --project eval python eval/campaigns/unified-final-v1/run.py \
  retain-final-r3-performance \
  --result eval/campaigns/unified-final-v1/results/final-r4
uv run --project eval python eval/campaigns/unified-final-v1/run.py freeze \
  --result eval/campaigns/unified-final-v1/results/final-r4
uv run --project eval python eval/campaigns/unified-final-v1/run.py collect \
  --result eval/campaigns/unified-final-v1/results/final-r4 --evaluation 2
uv run --project eval python eval/campaigns/unified-final-v1/validate.py \
  eval/campaigns/unified-final-v1/results/final-r4 \
  --output eval/campaigns/unified-final-v1/results/final-r4/validation.json
uv run --project eval python eval/campaigns/unified-final-v1/report.py \
  eval/campaigns/unified-final-v1/results/final-r4
```

The committed, checksum-authenticated bundle is
`eval/campaigns/unified-final-v1/retained/final-r4/`.
