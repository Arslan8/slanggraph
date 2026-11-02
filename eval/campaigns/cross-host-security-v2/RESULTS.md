# Matched-host security and Linux application follow-up

Implementation: `79c6309604835277333393d426a0c7fc22eb49e0`. Run date: October 31, 2026. Both hosts executed the same 44 cases, five protected/control pairs per case: 440 trials per host, 880 main trials total. Linux also retained two initial condition attempts from one incomplete observer-race pair, for 882 main-plus-harness condition attempts. These extra attempts are not silently discarded. The complete source inventories, policies, attack bodies, fixtures and outcome criteria match. The Linux host is an ARM64 VM on this Mac, not historical WIP evidence.

| Classification (paired comparisons) | macOS | Linux |
| --- | ---: | ---: |
| Enforced | 185 | 190 |
| Rejected before execution | 35 | 20 |
| Inconclusive | 0 | 10 |
| Failed | 0 | 0 |
| Positive controls demonstrated | 220/220 | 220/220 |
| Allowed operations succeeded | 25/25 | 25/25 |

Mac evidence includes 170 successful lifecycle certificates independently replayed through the pinned compiled Lean core. Linux uses the production object broker, which has no corresponding Lean lifecycle/grant checker integration: its missing/altered-obligation hooks never reach a checker. Those ten pairs are inconclusive; they are not credited as successful refusal or checker validation. No blanket cross-platform equivalence follows from the category totals.

Linux initially produced one observer `ESRCH` while a process exited. The incomplete pair was retained under `harness-attempts/`, then rerun without changing frozen source bytes. The complete matrix has the counts above; the [all-attempt ledger](attempt-ledger-linux-all.jsonl) includes an additional inconclusive harness comparison: 221 comparison attempts, 442 condition attempts, 441 complete condition records and one incomplete record. Original failed verification logs remain; `security-reverification.log` and `security-ledger-after-resumption.log` verify the resumed matrix. [Accounting and resolution record](linux-all-attempts-summary.json).

## CPU and host-control findings

The native Mac launcher already installed equal soft/hard RLIMIT_CPU at the original pilot revision and this revision, before Seatbelt and Python. Linux also installs per-process limits with setrlimit. Optional Linux cgroup `cpu.max` limits bandwidth, not cumulative process-tree CPU time.

Direct qualification preserved 30 Mac observations and 20 Linux observations. Both computation-heavy and syscall-heavy unlimited loops complete two CPU seconds. Linux kills both bodies under RLIMIT_CPU (1,1), five/five each. On this macOS 26.7.2 build, computation-heavy limited bodies die at about one CPU second, but syscall-heavy limited bodies complete about two CPU seconds with or without Seatbelt, five/five in each condition. This reproduces the earlier failure; it does not justify a total-CPU enforcement claim. See [complete command/output transcripts](CPU-TRANSCRIPTS.txt), [machine-readable Mac transcripts](cpu-sanity-macos.json), [Linux transcripts](cpu-sanity-linux.json) and [source provenance](cpu-mechanism-provenance.json).

The parser now recognizes CPU and syscall requirements independently of platform. The Mac lowerer refuses unsupported/unqualified requirements with original object grant, native candidate, actual host capabilities, obligation IDs/parameters and adapter assessments, before body release. Aggregate CPU and minimal syscall cases produce five attributable Mac refusals each. Five separately selected per-process CPU pairs also produce attributable refusals; these ten supplementary trials are not pooled with the 44-case matrix. Linux refuses aggregate CPU and enforces the requested minimal syscall filter.

The revised syscall body attempts fork followed by a forbidden Bob update. Linux enforcement requires the minimal-filter assignment, matching activated-obligation receipt, observed NoNewPrivs=1/Seccomp=2 on the entered worker, and no forbidden resource effect. This body differs from the earlier gate-entry probe; v1 results are preserved, not reclassified with the new body.

| Requirement/control case | macOS (five pairs) | Linux (five pairs) |
| --- | --- | --- |
| Aggregate CPU | Unsupported refusal | Unsupported refusal |
| Minimal syscall filter | Unsupported refusal | Enforced |
| Per-process total CPU (additional case) | Unqualified refusal | Direct primitive qualification only; not an additional admitted-policy matrix case |
| Missing Lean obligation | Refused by checker | Inconclusive: checker not integrated |
| Altered Lean obligation | Refused by checker | Inconclusive: checker not integrated |

The two extensible CPU/syscall-named contracts remain unsupported generic kernel contracts on both hosts. Their names do not supply actual CPU/filter semantics. The mandatory admission mutation is rejected on both hosts. A Linux diagnostic found a persistent-session orphan after controller death; the backend now installs a parent-death kill signal before imports and checks its expected parent. All five frozen Linux controller-termination session pairs pass after that fix. Diagnostic failures remain in the development archive.

## Per-case results

| Case | macOS | Linux |
| --- | --- | --- |
| `allowed_record_read` | Enforced: 5/5 | Enforced: 5/5 |
| `allowed_record_update` | Enforced: 5/5 | Enforced: 5/5 |
| `bob_read` | Enforced: 5/5 | Enforced: 5/5 |
| `bob_update` | Enforced: 5/5 | Enforced: 5/5 |
| `bob_delete` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_database_read` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_database_update` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_database_delete` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_wal` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_shm` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_journal` | Enforced: 5/5 | Enforced: 5/5 |
| `retry_after_denial` | Enforced: 5/5 | Enforced: 5/5 |
| `allowed_pump_inspect` | Enforced: 5/5 | Enforced: 5/5 |
| `allowed_pump_set_flow` | Enforced: 5/5 | Enforced: 5/5 |
| `pump_calibrate` | Enforced: 5/5 | Enforced: 5/5 |
| `direct_device` | Enforced: 5/5 | Enforced: 5/5 |
| `identity_principal` | Enforced: 5/5 | Enforced: 5/5 |
| `identity_tool` | Enforced: 5/5 | Enforced: 5/5 |
| `identity_invocation` | Enforced: 5/5 | Enforced: 5/5 |
| `identity_session` | Enforced: 5/5 | Enforced: 5/5 |
| `old_invocation_reuse` | Enforced: 5/5 | Enforced: 5/5 |
| `private_file_read` | Enforced: 5/5 | Enforced: 5/5 |
| `outside_artifact_write` | Enforced: 5/5 | Enforced: 5/5 |
| `live_network` | Enforced: 5/5 | Enforced: 5/5 |
| `process_fork` | Enforced: 5/5 | Enforced: 5/5 |
| `process_subprocess` | Enforced: 5/5 | Enforced: 5/5 |
| `process_exec` | Enforced: 5/5 | Enforced: 5/5 |
| `timeout` | Enforced: 5/5 | Enforced: 5/5 |
| `cancellation` | Enforced: 5/5 | Enforced: 5/5 |
| `controller_termination` | Enforced: 5/5 | Enforced: 5/5 |
| `session_own_state` | Enforced: 5/5 | Enforced: 5/5 |
| `session_other_variable` | Enforced: 5/5 | Enforced: 5/5 |
| `session_other_artifact` | Enforced: 5/5 | Enforced: 5/5 |
| `session_other_artifact_write` | Enforced: 5/5 | Enforced: 5/5 |
| `session_timeout` | Enforced: 5/5 | Enforced: 5/5 |
| `session_cancellation` | Enforced: 5/5 | Enforced: 5/5 |
| `session_controller_termination` | Enforced: 5/5 | Enforced: 5/5 |
| `required_aggregate_cpu` | Rejected before execution: 5/5 | Rejected before execution: 5/5 |
| `required_syscall_filter` | Rejected before execution: 5/5 | Enforced: 5/5 |
| `extensible_required_cpu` | Rejected before execution: 5/5 | Rejected before execution: 5/5 |
| `extensible_required_syscalls` | Rejected before execution: 5/5 | Rejected before execution: 5/5 |
| `missing_obligation` | Rejected before execution: 5/5 | Inconclusive: 5/5 |
| `altered_obligation` | Rejected before execution: 5/5 | Inconclusive: 5/5 |
| `admission_mutation` | Rejected before execution: 5/5 | Rejected before execution: 5/5 |

## Linux timing and Pandas campaign

All requested Linux stages were run in one campaign at `79c6309`. The original security-verification/ledger stages failed on the incomplete observer record; their failed logs remain. After the explicitly retained retry, both rechecks pass. All timing stages began only after final Mac security verification and archive replay. Final source-before/source-after inventories are identical.

The harness records kernel 7.0.0-42-generic, ARM64, Landlock ABI 8, outer AppArmor unconfined and Seccomp=0, and a successful actual bubblewrap activation gate. The privileged outer container is trusted harness infrastructure; generated worker confinement is applied inside it. The qualified runtime image supplies identical libpython bytes in the default loader search directory, and declares trusted interpreter package roots explicitly. The Pandas snapshot includes the shared host helper. Earlier failed attempts and the interrupted condition remain in the development archive.

Each microbenchmark uses five fresh process sessions, ten warmups and twenty measured protected calls per session, plus a first-use call. Each route therefore has 155 valid protected calls, including 100 measured calls; no invalid protected calls are included below. One-off setup is recorded separately.

| Route | Measured calls | Mean elapsed ms | Median elapsed ms |
| --- | ---: | ---: | ---: |
| Linux / bubblewrap | 100 | 66.430 | 65.837 |
| Container | 100 | 86.316 | 86.315 |
| Resource broker | 100 | 59.200 | 57.918 |

These retain the original protocol's different guard mixes: direct Linux has compiled Lean checks but no sealed operator MAC; broker and container enable operator MAC but do not integrate that checker in these protocols. The elapsed values are route measurements, not timings for interchangeable security guarantees. Phase counters are instrumentation estimates; primary latency is the measured end-to-end elapsed value. [Raw summary including session means](microbenchmark-summary.json).

Pandas ran all ten frozen tasks, five repetitions, both conditions, using the pinned qwen3:8b digest, unchanged dataset/policies/model/oracle and common subprocess wall-clock boundary. The only native pin changes select the rebuilt Linux core/runtime. Validation replays the unchanged utility oracle and checks all task/repetition pairs, source identities, baseline negative evidence and protected admission/activation evidence.

| Pandas condition | Correct / attempts | Mean attempted duration |
| --- | ---: | ---: |
| Baseline | 50/50 | 14.373 s |
| Argus | 45/50 | 15.236 s |

The all-attempt duration ratio is **1.060×**, with a five-repetition-block bootstrap 95% interval of 1.042–1.088× (100,000 resamples). This includes five Argus `monthly_mean` output refusals and is not a claim of identical successful utility. The 45 pairs where both conditions succeeded have a descriptive ratio of 1.061×, interval 1.044–1.087×; this excludes failed pairs and is secondary.

All five Argus failures are the known non-finite-output refusal in `monthly_mean`, one per repetition. There are no timeouts, activation failures or execution errors. The cohort records 65 protected computation calls. Framework source hashes remain stable throughout. Both original and extracted-artifact validation pass. [Outcomes and failure rows](pandas-outcomes.json), [validation](pandas-validation.json), [statistics](pandas-statistics.json).

This is a rerun of the Pandas case study, not a new matched rerun of the 15-application/350-attempt dataset. Earlier Mac application campaigns remain separate evidence.

## Evidence and reproducibility

- [Matched comparison and identical-source checks](matched-security-comparison.json); [Mac verification](macos-verification.json); [Linux verification](linux-verification.json).
- [Mac attempt ledger](attempt-ledger-macos.jsonl); [Linux attempt ledger](attempt-ledger-linux.jsonl); [original v1 ledger](attempt-ledger-v1.jsonl), which regenerates 185/25/10 from the original 440 trials.
- [Mac refusal records](macos-refusals.json); [additional per-process refusal records](per-process-refusals-macos.json); [Linux aggregate refusal records](linux-refusals.json).
- [Mac negative controls](macos-mutation-controls.json) and [Linux negative controls](linux-mutation-controls.json): nine each; [additional host-control oracle negative controls](host-control-oracle-checks.json): eight.
- `security-runs.tar.gz` contains final `run-macos-02`, `run-linux-02/security` and supplementary `per-process-macos-02` raw trials, resource backups, captured framework/attacker sources and source inventories for both hosts plus the additional CPU case. `native-macos.tar.gz` contains shared Mac native images; extract it, then copy `run-macos-01/native` to both `run-macos-02/native` and `per-process-macos-02/native`. `native-linux.tar.gz` retains the rebuilt Linux core/runtime and build manifest.
- `development-evidence.tar.gz` retains diagnostic pilots, direct Mac CPU transcripts, setup failures and validation logs. Its manifest describes the shared native images. Diagnostic repetitions are never pooled with frozen runs. The first complete security matrices are retained in `security-runs-attempt-01.tar.gz`; the first joint application attempt was stopped and retained with 11 completed rows plus one interrupted condition.

Regenerate a ledger using `eval/.venv/bin/python eval/campaigns/cross-host-security-v2/regenerate_ledger.py RUN --output LEDGER.jsonl`. For historical v1, select `--verifier eval/campaigns/cross-host-security-v1/verify.py`. Mac certificate replay requires Mac native images; Linux timing reruns require the configured Docker harness. See README.md for setup and REVIEW-RESPONSE.md for the reviewer-facing explanation.

These are matched-case security observations, not an OS performance comparison. The VM boundary, runtime transport, supported obligations and Lean integration differ. A successful refusal is evidence of fail-closed negotiation, not evidence that the requested resource primitive was enforced.

The frozen configuration uses a legacy `macOS_checkout` metadata key on both hosts; its value is the shared implementation revision, not an OS-specific fork. `wip_evidence_tree` is a historical reference, not the Linux execution revision. A post-campaign observer-only correction at `87e5fa3` treats ESRCH as normal process disappearance; live PID, vanished PID and explicit ESRCH regression checks pass. Frozen records and classifications were not rewritten by that correction.
