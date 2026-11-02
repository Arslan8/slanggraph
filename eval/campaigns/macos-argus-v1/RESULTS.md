# macOS protected application results

The native macOS object route is implemented and the complete Argus matrix has
run: **175 demo attempts, 107 correct; 50 Pandas attempts, 45 correct**. All
**225 attempts** remain in the results. The verifier accepted the observations
and replayed **341 retained successful-call certificates**, across 178 trials,
through the compiled native Lean core.

Together with the earlier baseline, this covers the original **350 demo attempts
across 15 applications** and **100 Pandas attempts** on macOS. Conditions ran in
separate cohorts. This is application execution evidence under the declared
macOS protections; full functional parity and an OS performance effect remain
unestablished.

## Utility and retained protected execution

The same task definitions, fixtures, model pin, model-visible tools, correctness
checks and timeout boundaries were reused. Application changes select native
host plumbing and confinement. No task, prompt or oracle was changed to improve
these results.

| Application | Baseline correct | Argus correct | Retained native certificates |
| --- | ---: | ---: | ---: |
| D1-sql | 10/25 | 10/25 | 56 |
| D2-rag | 20/25 | 20/25 | 0 |
| D3-plan-execute | 0/25 | 0/25 | 69 |
| D4-multi-agent | 15/25 | 14/25 | 29 |
| D5-support | 20/25 | 18/25 | 57 |
| T1-add-tools | 5/5 | 5/5 | 5 |
| T2-custom-weather | 5/5 | 5/5 | 5 |
| T3-fixed-weather | 5/5 | 5/5 | 5 |
| T4-parallel-weather | 5/5 | 5/5 | 10 |
| T5-prebuilt-multiply | 5/5 | 5/5 | 5 |
| T6-return-direct | 5/5 | 5/5 | 5 |
| T7-forced-tool | 5/5 | 5/5 | 5 |
| T8-serial-tools | 5/5 | 5/5 | 10 |
| T9-add-memory | 5/5 | 5/5 | 10 |
| T10-time-travel | 5/5 | 0/5 | 5 |
| Pandas | 50/50 | 45/50 | 65 |
| **Demos total** | **115/175** | **107/175** | **276** |
| **Combined** | **165/225** | **152/225** | **341** |

Correctness and protected execution are separate measurements. A tool can
complete inside an application that later fails. The frozen RAG trials answered
without choosing retrieval; their answers do not establish protected retrieval
execution. A supplemental deterministic control selected that tool through the
original admitted graph, matched the baseline retrieval bytes, and replayed its
native certificate. It made no model request and is excluded from the cohort
and all utility rates.

Journal export occurs at orderly application exit. Timeout-killed applications
can lose in-memory journals, so **341 is a lower bound on executed calls**, not
an exhaustive count. Online Lean gates still precede tool release and result
delivery; published replay counts credit retained certificates only.

## Failures retained

Process outcomes: 175 completed, 25 execution errors, ten compatibility failures,
ten timeouts and five Pandas errors. Of the completed processes, 23 failed their
existing correctness oracle.

- All 25 plan-execute attempts reached the graph recursion limit. The baseline
  also had zero correct results, with a different `IndexError` failure.
- Ten multi-agent chart attempts reached the original 300-second cap. The
  baseline also retained ten such timeouts.
- Five time-travel attempts failed checkpoint restore with
  `checkpoint:broken_chain`, after a successful native tool call. The existing
  checkpoint integrity policy was retained.
- Five additional demo attempts failed native startup or their worker channel.
  All five diagnostic intervals overlap sleep/wake events. Local system
  documentation confirms that the guardian's `CLOCK_MONOTONIC` deadline includes
  sleep, while Python's elapsed-time clock uses `mach_absolute_time`, which
  excludes it. This supports a suspension explanation but is not a per-failure
  proof. Idle-sleep prevention was added at 13:30:21 EDT for the remainder;
  interrupted observations were retained without replacement.
- All five Pandas monthly-mean attempts completed native computation, then
  failed the application output boundary with `output_data:nonfinite_float`.
  The computation response contains a null missing-period value; subsequent
  application state reaches a nonfinite-float guard. The output rule was retained.

## Implemented protection scope

`MacOSObjectDispatcher` connects Cedar object authorization, sealed operator MAC
policy and closed admission to per-call Seatbelt workers. The native launcher
installs confinement before loading Python. Private inherited pipes bind broker
requests to the original principal, tool, grant and spawn context. Semantic
resource operations and credentials stay in the trusted parent. Persistent
Python chart sessions have a separate native guardian and confined artifact
writes. Direct filesystem grants support exact read-only regular files.

The compiled Lean extension checks the generated resource-obligation inventory
and certificate coverage, bound activation/GO transition, and result release
after confirmed cleanup. Controller, decoder, mediator and OS correspondence
remain explicit premises; replay is not a proof of all native behavior.

**CPU qualification remains deferred.** The certified application inventory
promises no aggregate CPU ceiling. The hard rlimit remains a best-effort
restriction. No Linux syscall-filter capability is advertised. The earlier
component campaign's five CPU failures remain unchanged in
[its historical report](../macos-portability-v1/RESULTS.md).

## Verification and evidence

The [89,121,132-byte evidence bundle](run-01.tar.gz) was safely extracted and
verified again with its checksum index required. SHA-256:
`7dd859658046e5b4234dcf806a61ccd8e38b142563488c06f693dcd594158508`.
Machine-readable results and scope are in [acceptance.json](acceptance.json).

Verification checked the full matrix, raw-output oracles, record copies, model
identity, matching before/after source inventories, all **333 copied Python
execution files**, native build-source identities and every retained native
certificate. Six mutations were rejected: changed obligation selector,
unconfirmed cleanup, changed receipt context, and changed/missing/extra
execution sources. All ten retained recovery records referred to absent original
processes; no native workers remained after the campaign.

Validation retained 16 passing native object-route tests, a broader group with
339 passed/23 skipped, 196 passing Lean lifecycle tests, and ten passing resource
and harness tests. These groups overlap and must not be added as distinct tests.
Library `make format` and `make lint` passed. `make test` could not start Docker
services because Docker is absent; direct pytest runs completed.

The bundle retains raw trials, process/model logs, outputs, charts, resource
observations, native journals, original sources, frozen execution copies,
native Lean images, launcher, manifests and validation logs. Fifty per-trial
database copies are omitted with sizes and hashes retained. The redundant
uncompressed travel source blob is also omitted; the verifier reconstructs its
exact pinned bytes from retained gzip. Checksums are integrity aids, not
authenticated host attestation.

Evaluated implementation: `e19bf343ef341fa6541025d8ca263b6e91205a2a`, branch
`macOS`. Host: Apple M4 Pro arm64, 24 GiB, macOS 26.7.2, Python 3.11.18.
Ollama 0.40.13 served the frozen `qwen3:8b` digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`
with Metal and context 4096. Cedar CLI is 4.13.0; Lean is 4.34.1.
Dependencies differ from the historical Linux environment and are recorded.
CPU affinity is uncontrolled. Suspension and separate scheduling also prevent
an overhead or cross-OS timing inference.

See [README.md](README.md) for reproduction. Original failed startup probes
remain in [PREFLIGHT.md](PREFLIGHT.md); they precede this implementation.
