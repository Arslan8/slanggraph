# macOS application compatibility

The final pinned macOS implementation revision is `794b17338eea0b71b67e084b720eb8d6d604b413`. The complete current-revision 15-application correctness cohorts are **115/175 baseline** and **110/175 Argus**: five repetitions of the unchanged 35-task dataset in each condition. The frozen source inventories are byte-for-byte identical, and both conditions use the same upstream task/oracle revision `4ffeb7f38178aa250917f29b01355f8b89ba809e`, `qwen3:8b` model digest, and Python package inventory. The verifier recomputed correctness from each output and replayed 285 successful native lifecycle records in the Argus cohort; both reports have `evidence_valid=true` and no issues. This is a correctness run, not a runtime-overhead study.

| Application | Baseline | Argus | Retained failure or status |
| --- | ---: | ---: | --- |
| D1 SQL | 10/25 | 10/25 | All completed; 15 oracle failures in each condition |
| D2 RAG | 20/25 | 20/25 | All completed; five oracle failures in each condition |
| D3 plan/execute | 0/25 | 0/25 | 15 `IndexError` and 10 recursion-limit errors in each condition |
| D4 multi-agent | 15/25 | 15/25 | 10 timeouts in each condition |
| D5 support | 20/25 | 20/25 | All completed; five oracle failures in each condition |
| T1 add tools | 5/5 | 5/5 | Completed |
| T2 custom weather | 5/5 | 5/5 | Completed |
| T3 fixed weather | 5/5 | 5/5 | Completed |
| T4 parallel weather | 5/5 | 5/5 | Completed |
| T5 prebuilt multiply | 5/5 | 5/5 | Completed |
| T6 return direct | 5/5 | 5/5 | Completed |
| T7 forced tool | 5/5 | 5/5 | Completed |
| T8 serial tools | 5/5 | 5/5 | Completed |
| T9 add memory | 5/5 | 5/5 | Completed |
| T10 time travel | 5/5 | 0/5 | Five Argus `checkpoint:broken_chain` compatibility failures |

The earlier complete Argus cohorts were **107/175** for the 15 applications and **45/50** for Pandas. They remain historical results, separate from the current-revision cohorts. On the final pinned source revision, the complete affected Pandas cohort is **50/50**: 10 tasks × 5 repetitions, all completed. All five monthly-mean cases now pass.

The legitimate missing period was serialized as JSON `null` by the compute response. The trusted vendor graph constructed a Pandas `DataFrame` and `to_dict()` converted that missing cell to `NaN`. `OutputMediator` correctly refused the non-finite value. The macOS application adapter now transports `NaN` in `data_wrangled` as `None` before the unchanged output guard. The targeted regression records separate `output_data:nonfinite_float` refusals for **positive and negative infinity**. `application_regressions.py` reproduces the original conversion and validates the corrected boundary. The task definitions, prompts, model pin and oracle were not changed.

The five time-travel failures were `checkpoint:broken_chain` under authenticated linear checkpoint ancestry. A targeted historical checkpoint regression is refused with `checkpoint:invalid_sequence`. `ObjectManagerHost._verify_checkpoint` accepts the current issued tip or a direct child of the restored digest and rejects replay/broken ancestry; `_register_checkpoint` requires the next sequence and prior issued digest. The missing operation is an **authenticated branch/restore transition** that names an old checkpoint, authorizes the principal to fork it into a new lineage, binds the new lineage to an explicit parent digest and sequence, and records that transition before execution resumes. The existing generic `RESTORE` path does not authorize such a fork. The integrity checks remain enabled, so historical time travel stays a documented application failure rather than a manufactured pass.

Five native startup/channel errors in the historical cohort overlapped recorded sleep/wake intervals. The new full demo cohort has no startup/channel status; its retained failures are the recursion errors, timeouts, checkpoint refusals, and completed-but-incorrect outputs listed above. `SIGSTOP`/`SIGCONT` experiments in `advanced-run-02` are controlled suspensions, not actual host sleep/wake. The historical overlap and clock behavior support a suspension hypothesis but do not prove the cause of each error.

The pinned local `qwen3:8b` service was started from the installed Ollama bundle, and its model digest was checked. The successful complete Pandas rerun is `pandas-argus-rerun-11`. `verify_macos_resubmission_app.py` checked all 50 raw trials against the unchanged task definitions and oracle, frozen harness and framework sources, dataset-read events, 65 enforced activation receipts, and audit databases; it reports `evidence_valid=true` with no issues. Earlier `pandas-argus-rerun-01` through `-10` are retained as incomplete or failed pilots and are excluded from the updated total. The final demo runs are `app-baseline-final-03` and `app-argus-final-02`; interrupted source-freeze pilots and the Argus run interrupted after overnight Mac suspension are excluded. No corrected trials were spliced into the historical cohort.

The changes are in macOS application integration and campaign wiring: `eval/apps/pandas/backend_closed.py`, `integration_closed.py`, `worker.py`, and `closed_campaign.py`. The generic output validator and task logic are unchanged. Reproduce the deterministic regression with `eval/.venv/bin/python eval/campaigns/macos-resubmission-v1/application_regressions.py`; reproduce the Pandas cohort with `eval/.venv/bin/python eval/apps/pandas/closed_campaign.py --output <new-directory> --configuration C-full-lean --repetitions 5 --runtime-manifest eval/campaigns/macos-resubmission-v1/macos-pandas-runtime-manifest.json` while the pinned `qwen3:8b` service is running. Verify it with `eval/.venv/bin/python eval/remaining/verify_macos_resubmission_app.py <new-directory>`. The portable Pandas rows are in `pandas-trials.jsonl.gz`; full local trial records are in `pandas-argus-rerun-11/`.

Reproduce each full demo condition with `eval/.venv/bin/python eval/remaining/macos_baseline_campaign.py --mode Baseline --only demos --repetitions 5 --output <new-baseline-directory>` and the same command with `--mode Argus --output <new-argus-directory>`. Set `ARGUS_MACOS_CONFIGURATION` to `eval/vendor/macos-argus-configuration.json`, put `eval/vendor/macos-toolchains/cedar/bin` on `PATH`, and use the pinned local Ollama model. Verify each output directory with `eval/.venv/bin/python eval/remaining/verify_macos_baseline.py <directory>`. `app-baseline-trials.jsonl.gz`, `app-argus-trials.jsonl.gz`, and the two `app-*-outputs.tar.gz` archives are compact portable evidence; complete frozen source blobs and copied input fixtures remain in the ignored local run directories.
