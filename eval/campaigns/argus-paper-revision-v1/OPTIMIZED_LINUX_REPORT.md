# Current Linux object-broker runtime result

## Evaluated configuration

The evaluated implementation is commit
`070d2f4bf69be7748b0368dc4ec41ce481a210f5`. The baseline and protected
conditions both execute the same compiled LangGraph graph, one `ToolNode`, the
same tool schema and arguments, the same SQLite database, and the same result
validation. The baseline omits Argus. Direct SQLite is retained only as a
diagnostic and is not used to calculate overhead.

The protected route is:

`ToolNode -> Cedar object authorization -> ObjectBrokerDispatcher -> prepared
single-use Landlock worker -> spawn-bound SQLite Records mediator -> inline Lean
grant/pre-execution/result checks -> confirmed cleanup -> result release`.

The invocation still binds the fresh principal, arguments, call identity, and
effective grant to prepared state. The worker cannot supply its principal or
select another invocation's grant. Prepared-worker selection is structural;
there is no invocation-time authentication rehash, policy re-lowering, mediator
construction, checker subprocess, or lifecycle JSON parsing.

Durable audit and bounded broker decision logging are optional and disabled in
this measured configuration. Disabling logging does not disable authorization,
mediation, lifecycle checks, channel-to-grant binding, or cleanup validation.
Pass `--audit` for durable audit and `record_audit=True` for in-memory broker
records when those artifacts are required.

The native checker was built with Lean 4.34.1:

- `libargus_worker_route.so` SHA-256:
  `aa2bcfbb000cae794fd4667228bca1476544db987a8f3092a04a411a30219502`
- `libleanshared.so` SHA-256:
  `6b30cc963d065fc9d2f87f7e9cbe0682b23000ae5425bccd769c5d477fa74f13`

Library implementations, resource mediators, the native shim, and generated
Lean executable are trusted against their contracts. The Lean model checks the
certificate and lifecycle definitions; it does not verify those trusted source
implementations.

## Matched development measurement

This is a shared-host development measurement, not yet a controlled-host paper
result. Ten independent sessions alternated route order. Each route used ten
warmups and 50 measured invocations, producing 500 samples per condition. All
500 protected invocations returned the expected record, with no pool miss,
checker subprocess, fallback, online policy re-lowering, audit write, or broker
audit record.

| Steady-state statistic | LangGraph baseline | Argus | Incremental Argus |
| --- | ---: | ---: | ---: |
| Mean | 1.159 ms | 4.533 ms | **3.374 ms** |
| Median | 1.111 ms | 4.388 ms | 3.277 ms |
| p95 | 1.231 ms | 5.459 ms | 4.228 ms |

The ratio of condition means is 3.911x. The incremental median and p95 above
are differences between the reported condition quantiles, not paired-sample
quantiles. This run replaces the withdrawn direct-SQLite comparison; direct
SQLite is not the baseline.

Selected protected-route diagnostics are:

| Diagnostic span | Mean | Median | p95 |
| --- | ---: | ---: | ---: |
| Cedar authorization | 0.206 ms | 0.169 ms | 0.208 ms |
| Activation | 0.741 ms | 0.687 ms | 1.138 ms |
| Lean grant check | 0.075 ms | 0.058 ms | 0.116 ms |
| Lean pre-execution check | 0.012 ms | 0.012 ms | 0.015 ms |
| Lean result check | 0.020 ms | 0.019 ms | 0.021 ms |
| Mediator transport | 1.216 ms | 1.076 ms | 1.949 ms |
| SQLite operation | 0.193 ms | 0.192 ms | 0.216 ms |
| Cleanup | 0.158 ms | 0.163 ms | 0.184 ms |
| Audit | 0.000 ms | 0.000 ms | 0.000 ms |
| Framework residual | 1.914 ms | 1.901 ms | 2.039 ms |

The diagnostic spans overlap in places and must not be summed as an exclusive
decomposition. The baseline's complete LangGraph path is already 1.159 ms.

Preparation remains outside invocation latency:

| Preparation item | Mean | Median | p95 |
| --- | ---: | ---: | ---: |
| Load and pin checker/runtime | 534.977 ms | 531.321 ms | 559.620 ms |
| Closed admission and policy setup | 353.096 ms | 328.797 ms | 551.552 ms |
| Construct dispatcher/reusable serving executor | 0.440 ms | 0.443 ms | 0.454 ms |
| Recurring single-use worker replenishment | 74.065 ms | 72.506 ms | 77.914 ms |

Worker replenishment is deliberately reported separately. It preserves
single-use workers and may constrain throughput if preparation cannot keep up;
it is not hidden inside the 4.533 ms invocation number.

## Validation

- Native checker preflight and the useful SQLite example passed.
- `make format` and `make lint` passed in `libs/prebuilt`.
- The complete `make test` attempt reported 5,798 passed, 50 skipped, and 63
  failures. Every failure was the host's known inability to create the
  bubblewrap user namespace.
- The 69 affected Linux-isolation tests passed in the established unconfined
  `slg-linux-test` container with the pinned Cedar executable. The focused
  object-broker file passed 38/38.
- No macOS runtime campaign was run.

The ordinary-application smoke block is retained separately from this runtime
measurement. Twelve applications completed correctly in both modes. D3 failed
identically in both modes at the graph recursion limit. T10 completed in the
baseline and the protected replay was refused as `checkpoint:broken_chain`.
D5's protected trial hit its 300-second cap once, then the same protected task
completed in 32 seconds on immediate diagnostic reproduction. A new five-block,
350-trial application campaign is still required before publishing updated
macrobenchmark results.

The separate final-commit Pandas macrobenchmark is complete. All ten frozen
tasks passed in all five repetition blocks under both conditions (50/50
Baseline, 50/50 Argus), with no timeout or validation failure. Complete-system
means were 10,228.4 ms and 11,388.9 ms respectively: 1.113x, or 11.3% overhead,
with a paired-block 95% interval of 10.7%-12.1%. The independent matched
validator reported zero issues; compact results are under
`pandas-final-0db4bf9f3-results/`.

## Reproduction

Build and preflight the checker:

```sh
PATH=/home/faculty/abk6349/.elan/bin:$PATH \
python3 proofs/worker-route/build_native.py \
  --output proofs/worker-route/.lake/build/lib/libargus_worker_route.so

libs/prebuilt/.venv/bin/python \
  eval/campaigns/argus-paper-revision-v1/preflight.py \
  --checker-library proofs/worker-route/.lake/build/lib/libargus_worker_route.so \
  --checker-runtime /home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so \
  --output /tmp/argus-preflight --run-example
```

Run the matched microbenchmark:

```sh
libs/prebuilt/.venv/bin/python \
  eval/campaigns/cross-host-security-v2/microbenchmarks/run_broker_costs.py \
  --output /tmp/argus-matched-no-broker-audit-10x50 \
  --sessions 10 --warmups 10 --measured 50 \
  --checker-library proofs/worker-route/.lake/build/lib/libargus_worker_route.so \
  --checker-runtime /home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so
```

Run the fixed 350-trial application population with the pinned `qwen3:8b`
service available at `127.0.0.1:11434`:

```sh
uv run --python 3.11 --project eval \
  --with langchain-openai==1.7.2 --with scikit-learn --with pandas \
  --with langchain-community --with langchain-experimental \
  --with matplotlib --with pytz \
  python eval/campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id final-070d2f4bf --repetitions 5
```
