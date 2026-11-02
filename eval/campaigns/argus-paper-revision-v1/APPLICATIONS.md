# Application compatibility and adaptation evidence

The existing macOS coverage is retained without a new runtime campaign: 175
baseline + 175 Argus attempts across 15 applications, and 50 baseline + 50 Argus
Pandas attempts. Conditions were separate cohorts, so these are compatibility
and coverage results, not cross-host timing evidence.

| Application | Baseline | Argus | Notes |
| --- | ---: | ---: | --- |
| D1 SQL | 10/25 | 10/25 | native SQL resource mediator |
| D2 RAG | 20/25 | 20/25 | model did not select retrieval in frozen trials; separate deterministic route control |
| D3 plan-execute | 0/25 | 0/25 | baseline `IndexError`; protected recursion limit; difficult workload |
| D4 multi-agent | 15/25 | 14/25 | ten baseline/Argus chart timeouts plus one protected correctness difference |
| D5 support | 20/25 | 18/25 | travel/policy/search mediators |
| T1 add-tools | 5/5 | 5/5 | supported |
| T2 custom-weather | 5/5 | 5/5 | supported |
| T3 fixed-weather | 5/5 | 5/5 | supported |
| T4 parallel-weather | 5/5 | 5/5 | parallel calls, ten certificates |
| T5 prebuilt-multiply | 5/5 | 5/5 | supported |
| T6 return-direct | 5/5 | 5/5 | supported |
| T7 forced-tool | 5/5 | 5/5 | supported |
| T8 serial-tools | 5/5 | 5/5 | serial calls, ten certificates |
| T9 add-memory | 5/5 | 5/5 | memory path, ten certificates |
| T10 time-travel | 5/5 | 0/5 | `checkpoint:broken_chain`; integrity checks retained |
| Pandas | 50/50 | 45/50 | five `monthly_mean` non-finite publication refusals |

Reliable-baseline subset: T1–T10 and Pandas are 100/100 baseline-correct; D3 is
kept visible despite 0/25. D1/D2/D4/D5 are reported individually rather than
letting easy workloads hide difficult ones.

## Revision and patch provenance

- Frozen task/model/fixture/oracle definitions:
  `../langgraph-demos-v1/tasks.json`, `../langgraph-demos-v3/SOURCES.md`, and
  `../macos-portability-v1/APPLICATION-PARITY.md`.
- Exact protected application sources and raw records are retained in
  `../macos-argus-v1/run-01.tar.gz`; baseline sources are in
  `../macos-baseline-v1/run-01.tar.gz`. Archive checksums are in each acceptance
  record.
- The upstream Pandas revision is
  `4ffeb7f38178aa250917f29b01355f8b89ba809e`; integration patches and policy
  manifests are under `../../apps/pandas/patches/` and `../../apps/pandas/policy/`.
- Environment-only changes select the native host, trusted runtime roots and
  dependency paths. Security-integration changes add admission, manifests,
  Cedar, mediators and host dispatch. Task prompts, fixtures and correctness
  oracles are application logic and were unchanged.

The existing archives provide exact source snapshots but do not yet contain a
single generated table splitting changed lines into environment/security/app
logic for every application or counting every manifest/Cedar file. That
adaptation-effort extraction remains a reporting gap and must not be guessed.

## Known failures

`monthly_mean` now uses the versioned `period-aggregation-v1` primitive in
`apps/pandas/sandbox_codec.py`. It completes missing mean periods with NaN only
inside Pandas, then the existing recursive JSON codec emits `null`; sums/counts
alone use zero. The strict non-finite output rule and correctness oracle are
unchanged. `eval/tests/test_pandas_period_api.py` and
`test_pandas_workflow_contract.py` pass, but no fresh matched model campaign has
been run, so the historical 45/50 result is not retroactively changed.

T10 restoration is not repaired by disabling integrity. The observed restored
checkpoint is not a valid continuation of the authenticated current chain, so
the present behavior is a genuine conflict between time travel and the intended
history policy. A future solution needs an explicit authenticated branch/
continuation transition and fresh matched runs.
