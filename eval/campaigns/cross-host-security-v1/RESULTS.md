# Cross-host security results

Full macOS campaign completed on October 31, 2026. Linux results are historical committed WIP observations, as requested; no Linux execution was performed for this campaign.

**44 distinct cases, five repetitions each, two conditions: 440 trials.** Protected comparisons: 185 Enforced, 10 Inconclusive, 25 Rejected before execution. All 220/220 unprotected positive controls demonstrated their intended effect. Allowed protected operations succeeded 25/25 times. No forbidden effects were observed in the protected trials. Repetitions are repeated observations, not distinct attacks.

**The macOS evidence does not establish complete identical-policy security equivalence with Linux.** Historical Linux evidence supports several individual resource guarantees, but its policies, authorization envelopes and Lean/admission composition differ. Cases without equivalent Linux evidence are inconclusive for cross-host validation.

## Requirement results

Every entry below covers five protected trials and five unprotected controls on macOS. Historical Linux entries cover five production observations unless stated otherwise. “Historical target” means supporting evidence for that requirement; it does not count as an exact same-policy cross-platform validation.

| Security requirement / case | macOS | Linux committed WIP evidence |
|---|---|---|
| `allowed_record_read` | Enforced: 5/5 (allowed success) | Enforced, historical target: allowed 5/5; `sqlite/allowed_read` |
| `allowed_record_update` | Enforced: 5/5 (allowed success) | Enforced, historical target: allowed 5/5; `sqlite/allowed_write` |
| `bob_read` | Enforced: 5/5 | Enforced, historical target: 0/5 forbidden effects; controls 5/5; `sqlite/selector_substitution` |
| `bob_update` | Enforced: 5/5 | Inconclusive: related `sqlite/denied_write` only; Not equivalent: old denial precedes release; new attempt is inside the worker. |
| `bob_delete` | Enforced: 5/5 | Inconclusive: related `sqlite/denied_delete` only; Not equivalent: old denial precedes release; new attempt is inside the worker. |
| `direct_database_read` | Enforced: 5/5 | Enforced, historical target: 0/5 forbidden effects; controls 5/5; `sqlite/direct_database` |
| `direct_database_update` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `direct_database_delete` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `direct_wal` | Enforced: 5/5 | Enforced, historical target: 0/5 forbidden effects; controls 5/5; `sqlite/direct_wal` |
| `direct_shm` | Enforced: 5/5 | Inconclusive: related `sqlite/direct_shm` only; Related only: the old Bob oracle does not establish SHM confidentiality. |
| `direct_journal` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `retry_after_denial` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `allowed_pump_inspect` | Enforced: 5/5 (allowed success) | Enforced, historical target: allowed 5/5; `pump/allowed_inspect` |
| `allowed_pump_set_flow` | Enforced: 5/5 (allowed success) | Enforced, historical target: allowed 5/5; `pump/allowed_set_flow` |
| `pump_calibrate` | Enforced: 5/5 | Inconclusive: related `pump/broker_escalation` only; Not equivalent: Charlie escalates inspect to set_flow, not Alice calibration. |
| `direct_device` | Enforced: 5/5 | Inconclusive: related `pump/direct_socket` only; Not equivalent: Unix socket/set_flow versus TCP/calibration. |
| `identity_principal` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `identity_tool` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `identity_invocation` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `identity_session` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `old_invocation_reuse` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `private_file_read` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `outside_artifact_write` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `live_network` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `process_fork` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `process_subprocess` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `process_exec` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `timeout` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `cancellation` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `controller_termination` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `session_own_state` | Enforced: 5/5 (allowed success) | Inconclusive: no equivalent retained case |
| `session_other_variable` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `session_other_artifact` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `session_other_artifact_write` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `session_timeout` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `session_cancellation` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `session_controller_termination` | Enforced: 5/5 | Inconclusive: no equivalent retained case |
| `required_aggregate_cpu` | Inconclusive: 5/5; public-interface gap | Inconclusive: no equivalent retained case |
| `required_syscall_filter` | Inconclusive: 5/5; public-interface gap | Inconclusive: no equivalent retained case |
| `extensible_required_cpu` | Rejected before execution: 5/5 | Inconclusive: no equivalent retained case |
| `extensible_required_syscalls` | Rejected before execution: 5/5 | Inconclusive: no equivalent retained case |
| `missing_obligation` | Rejected before execution: 5/5 | Inconclusive: no equivalent retained case |
| `altered_obligation` | Rejected before execution: 5/5 | Inconclusive: no equivalent retained case |
| `admission_mutation` | Rejected before execution: 5/5 | Inconclusive: no equivalent retained case |

## What the evidence establishes

On macOS, permitted Alice record operations and pump commands succeed. Attempted Bob record access, direct database/main/WAL/journal reads or mutations, retry after denial, calibration escalation and direct endpoint bypass are judged by canary disclosure or independent resource state. SHM is separately a prohibited metadata-file access test: its fixture contains no Bob canary, so it is not presented as a Bob-disclosure test. The independent listener records actual connections and data; a closed-port exception is never counted as confinement.

Private-file access, outside writes, process escape attempts and cross-session variable/artifact access use the same attack bodies in both conditions. Process cases establish absence of forbidden authority in forked, spawned or replacement execution, rather than asserting that every attempted process creation itself occurred. Wrong-identity cases establish that conflicting broker fields cannot obtain Bob access; because Bob is also outside the grant, these cases alone do not isolate each identity-binding check as the sole reason for refusal.

The old-invocation case captures and completes a real Alice-write request, resets Alice from the trusted harness, then replays it from a fresh worker with only trace authority. It tests stale request reuse through another invocation channel; it does not claim that a destroyed process’s file descriptor remains usable.

Timeout, cancellation and controller termination each cover short workers and actual persistent Python/chart session backends. Every protected cleanup verdict requires observed progress, PID plus start-identity absence, no surviving descendants, and no new resource effects in a fixed five-second window after confirmation. The unconfined controls continue effects during that window. The production persistent-session execution timeout remains 30 seconds; cancellation can wait for that backend timeout. This is a cleanup experiment, not a responsiveness or CPU benchmark. The production session backend has a dedicated native activation/guardian path, without a separate session Lean lifecycle certificate. Replayed Lean certificates cover the admitted object-call wrapper; the resource/session mediator remains trusted code.

Native aggregate-CPU and Linux-style syscall requirement syntax is not expressible in this object-policy interface. Those ten protected trials are **Inconclusive interface gaps**, not qualified host-lowering rejection. Separate extensible `enforced_by kernel` CPU/syscall-named contracts are retained verbatim and rejected with `macos_object:unsupported_filesystem_authority` before tool entry. This demonstrates fail-closed handling of unknown mandatory kernel contracts, not implementation of their named CPU/filter semantics. A wall timeout never counts as aggregate CPU enforcement.

Removing or changing a required bypass obligation passes the damaged input to the real compiled Lean checker; it refuses tool release. Mutating the dispatcher descriptor after compilation is refused by admission. These are refusal tests, not successful attacks against an admitted worker.

## Linux comparison limits

The frozen WIP evidence tree is `60a73efb1c072b95aa38f6b1d7c39fe3ea6db5f1`. `linux-reference.json` pins ten exact Git blobs and their SHA-256 digests. Historical row `source_revision` values identify worker source hashes; the original full execution commit is not recorded. We do not relabel the containing WIP commit as that execution revision. No new Linux trials were run.

The old SQLite policy additionally permits Alice deletion and uses the class name `db_record`; the new policy permits Alice read/update and includes pump/trace/session capabilities. Old update/delete denials occur before body release, unlike the new inside-worker Bob attempts. Old pump escalation is Charlie inspect→set_flow, and direct access is Unix-socket set_flow; these are not equivalent to Alice calibration over TCP. Old SHM controls do not disclose Bob, so their old Bob oracle cannot establish metadata confidentiality. No retained retry case is available.

Historical `call_authorization_native` controls retain native access and are an incomplete reference mode, rather than the new unrestricted process control. Historical resource composition also lacks the current macOS route’s integrated closed admission and runtime Lean path. Supporting observations on both hosts cover Alice read/update, Bob selector substitution refusal, direct database/WAL disclosure prevention, and allowed pump inspection/set flow. The remaining matrix has no matched Linux evidence and is not counted as cross-host validation.

## Existing application evaluation preserved

| Cohort | 15 applications | Pandas |
|---|---|
| macOS baseline | 115 correct / 175 attempts | 50 correct / 50 attempts |
| macOS Argus | 107 correct / 175 attempts | 45 correct / 50 attempts |

`application-preservation.json` verifies both complete matrices and retains the existing failures. `application-original-comparison.json` also compares the frozen WIP task/fixture/model definitions with the macOS cohort: task digest `5518b7cbf4e22276cda21c8425543dd32ca508f56841f75d473df49818a6d725`, identical fixture hashes, identical ordinary correctness runner, matching Pandas task/fixture/oracle ASTs, model digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`, demo timeouts 180/300 seconds and Pandas timeout 180 seconds. No model calls or application timing reruns were made.

Retained failures include plan-execution recursion, chart timeouts, time-travel checkpoint incompatibility, native-channel errors overlapping sleep, and the monthly-mean nonfinite Pandas output. Native host selection, broker transport, persistent chart sessions, dataset descriptor reads and Darwin Lean loading are platform setup changes; they do not change the original correctness criteria. Historical Linux activation failures remain in their original reports.

## Reproduction and retained artifacts

- macOS campaign execution commit: `a5a61400b668351c4c00a64ea855bf0bb0b29aeb`; application-evaluation base: `aed89a5ee4870f252ec4f3a31422ae2ee85c96f0`.
- `verification.json`: full matrix verified, fixture/state/source consistency checked; 170 successful native lifecycle certificates replayed with the compiled Lean core.
- `mutation-controls.json`: nine deliberately falsified or insufficient observations rejected as Failed/Inconclusive or inconsistent evidence.
- `development-pilots.tar.gz` and `development-pilots.json` preserve diagnostic setup failures separately: pilot-02 had five failed allowed operations and 34 inconclusive cases after a Cedar action/schema mismatch, corrected before the frozen campaign. Development pilots are never pooled with formal results.
- `linux-comparison.json`: outcomes recomputed from the frozen resource snapshots and attacker-visible values; unmatched cases explicit.
- `application-original-reference/`: exact historical configuration and oracle source blobs for preservation checks.
- `run-01.tar.gz`: 65,045,377 bytes; SHA-256 `7a86a067008f31ab4e046206ad40fa4aa1b87f257ef01aced96c61e3c169a5f4`. Contains raw per-trial records, independent database backups/file bytes/events, inputs/results/audits/lowering/cleanup observations, frozen framework sources, native checker/runtime images and environment metadata.
- `run-01/SHA256SUMS.json` inventories retained raw files. `acceptance.json` records verification and archive checks.
- Focused native regression tests: 16 passed. Library `make format` and `make lint` passed. `make test` could not start its Docker services because Docker is absent; this limitation is retained in the validation logs.

See `README.md` for setup, policies, observation boundaries and verifier commands. No production enforcement requirements were dropped to obtain these results.
