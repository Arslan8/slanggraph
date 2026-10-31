# macOS application baseline results

**The baselines ran on macOS without changing the application logic.** All eight
ordinary-demo application source files and their frozen task definitions match
the Linux aggressive-inline campaign byte for byte. The Pandas execution backend,
integration, workflow contract, computation API and oracle are reused unchanged.
The historical Pandas postprocessing script `analyze_matched.py` differs; it is
not used to execute or grade this campaign. Both source identities are retained.

Run `run-01`: 175 ordinary-demo baseline attempts and 50 Pandas baseline attempts,
five repetitions each. The 16-observation setup pilot is retained locally and excluded from the published
full-run bundle.

## Results

| Cohort | Attempts | Correct under frozen checks | Execution errors | Timeouts |
| --- | ---: | ---: | ---: | ---: |
| Ordinary demos, 15 applications / 35 tasks | 175 | **115** | 25 | 10 |
| Pandas, 10 tasks | 50 | **50** | 0 | 0 |
| Total | 225 | **165** | 25 | 10 |

Every tutorial-demo attempt passed: **50/50** across T1–T10. All 25 plan/execute
attempts produced the recorded `IndexError: list index out of range` execution
error. Multi-agent GDP tasks 2 (France) and 4 (Japan) hit the original 300-second
limit in all five repetitions. SQL, RAG and customer support also produced
completed-but-incorrect answers: 15, 5 and 5 respectively. None was dropped or
reclassified as successful. Each ordinary-demo repetition produced 23/35 correct
results, five execution errors and two timeouts.

| Application | Correct / attempts | Execution status counts | Mean attempt wall time (s) |
| --- | ---: | --- | ---: |
| D1-sql | 10/25 | completed: 25 | 11.957 |
| D2-rag | 20/25 | completed: 25 | 8.056 |
| D3-plan-execute | 0/25 | execution_error: 25 | 23.209 |
| D4-multi-agent | 15/25 | completed: 15, timeout: 10 | 140.320 |
| D5-support | 20/25 | completed: 25 | 15.611 |
| Pandas | 50/50 | completed: 50 | 15.181 |
| T1-add-tools | 5/5 | completed: 5 | 3.403 |
| T10-time-travel | 5/5 | completed: 5 | 3.421 |
| T2-custom-weather | 5/5 | completed: 5 | 2.750 |
| T3-fixed-weather | 5/5 | completed: 5 | 1.103 |
| T4-parallel-weather | 5/5 | completed: 5 | 1.279 |
| T5-prebuilt-multiply | 5/5 | completed: 5 | 3.596 |
| T6-return-direct | 5/5 | completed: 5 | 2.071 |
| T7-forced-tool | 5/5 | completed: 5 | 2.069 |
| T8-serial-tools | 5/5 | completed: 5 | 3.494 |
| T9-add-memory | 5/5 | completed: 5 | 5.591 |

“Completed” describes process/workflow completion; it includes incorrect answers.
Means include every attempt and the original timeout caps. They describe attempt
durations, not successful execution overhead or an OS speed comparison. No
protected macOS application trial, overhead ratio or OS speedup is reported.

## What was required

No demo graph, prompt, tool schema, task, dataset or correctness check was ported.
Host setup installed the pinned local model, application dependencies and pinned
upstream Pandas checkout, and decompressed the existing customer-support fixture.
The first pilot retained its missing-fixture failure and plan/execute error;
its Pandas task passed. The restored fixture matched its existing Linux SHA-256
before the full campaign began.

A new **baseline-only launcher** reuses the existing demo runner's command
builder, execution wrapper and oracles. It omits the campaign entry point's
unconditional Linux protection preflight. For Pandas it reuses `backend_closed.py`
in `Baseline` mode, the same ten tasks and 212-byte dataset, v22 common settings,
three graph retries, recursive JSON v2, request-preserving workflow v5, period
aggregation API v1 and JSON-null state normalization. Its launch omits Linux
`taskset` and protected-only Lean capture. The original vendor computation
subprocess and its existing checks remain enabled. These are baseline harness
and environment adaptations, not a port of the protected route.

The job order filters Baseline jobs from the original paired/shuffled schedules:
seed 20261028 for demos and 20261026 for Pandas. The primary timer includes each
subprocess's startup and shutdown. Shared setup/model warmup is recorded and
excluded. The existing 180/300-second demo and 180-second Pandas limits remain.
The omitted protected condition means this is **175**, not 350, ordinary-demo
attempts, and **50**, not 100, Pandas attempts.

## Evidence and verification

- The independent verifier regraded every raw application output using the frozen
  oracles and checked the complete task/repetition matrix: **valid, no issues**.
- Before/after source inventories match; archived source bytes verify.
- All **283 copied Python source files** match their original recorded hashes.
- Frozen fixture hashes, upstream revision and served model digest were checked
  before execution. Per-trial baseline evidence contains no Argus activation,
  admission, policy, broker or audit treatment.
- Five harness tests passed; scoped Ruff checks and formatting passed. A mutation
  of real stored correctness flags was rejected against the unchanged raw output.

`evidence_valid=true` means the observations are complete and internally
consistent. It does not mean every application answer was correct or any
protected route was qualified. The overall utility result is **165/225**.

Download [the evidence bundle](run-01.tar.gz); its SHA-256 and machine-readable
results are in [acceptance.json](acceptance.json). The bundle contains raw trials,
outputs, transcripts, charts, fixtures, source bytes, copied execution inputs,
model/runtime and dependency metadata, logs and verification. Per-trial reset
Chinook/travel database copies are omitted, as in the Linux artifact; their
hashes, frozen source bytes and recorded resource-state outputs remain available.
The checksum index is an integrity aid, not authenticated host attestation.

## Environment and limits

Host: Apple M4 Pro arm64, 24 GiB, macOS 26.7.2 (25G332), Python 3.11.18.
Ollama 0.40.13 used Metal with loaded context 4096. The `qwen3:8b` model digest
matches the Linux pin:
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
Pandas upstream revision: `4ffeb7f38178aa250917f29b01355f8b89ba809e`.
Framework base revision: `588fc14`, with the evaluated baseline harness and source
bytes retained in the archive. Complete package versions and runtime hashes are
recorded. Some packages differ from the historical Linux intake freeze, including
NumPy 2.4.6 versus 2.5.4; `dependency-comparison.json` names all differences and
its reference scope. CPU affinity is uncontrolled; BLAS/OMP thread counts are 1.

This establishes that the frozen **baseline workloads execute on macOS** and
reports their actual utility outcomes. It does not establish matched protected
application portability, a complete admitted macOS route, runtime Lean integration
or a causal OS performance comparison. CPU qualification remains separately
deferred; no native CPU failure was erased by this baseline run.

See [README.md](README.md) for setup and reproduction. Extract the evidence bundle
beside this report and replay with:

```sh
eval/.venv/bin/python eval/remaining/verify_macos_baseline.py \
  eval/campaigns/macos-baseline-v1/run-01
```

The verifier exits 0 for this complete valid dataset while retaining all utility
failures. The task-owned model service was stopped after the run; its downloaded
runtime/model and the Python environment remain available locally for reruns.
