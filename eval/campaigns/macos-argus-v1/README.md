# macOS protected application campaign

This campaign runs the Argus condition of the existing 15-application demo
matrix and Pandas case study on macOS: 175 demo attempts and 50 Pandas attempts.
The [baseline cohort](../macos-baseline-v1/RESULTS.md) was executed separately.
The two cohorts reuse frozen tasks, fixtures, model identity, correctness checks
and timeout boundaries. Their schedules are not an interleaved timing experiment.

The host port selects native Seatbelt workers, private broker pipes, the existing
typed resource mediators, Cedar authorization, MAC policy, closed admission and
the compiled macOS Lean lifecycle checker. The persistent Python resource uses
a separate native guardian and confines writes to its chart artifact directory.
See [the host implementation](../../../docs/security/users/macos-object-execution.md).

CPU qualification remains deferred. The certified application inventory does
not promise an aggregate CPU ceiling; the launcher still installs a hard rlimit.
No Linux syscall-filter capability is advertised on macOS.

## Reproduction

Prepare the model, application interpreter and frozen fixtures using the
[baseline setup](../macos-baseline-v1/README.md). Build the native launcher with
that interpreter, build Lean using the pinned toolchain, and install Cedar CLI
4.13.0. The host documentation above describes these steps. Then run:

```sh
eval/.venv/bin/python eval/remaining/setup_macos_argus.py \
  --launcher-manifest /absolute/native-launcher/manifest.json \
  --lean-manifest proofs/worker-route/.lake/build/lib/libargus_worker_route.dylib.json \
  --recovery-directory /absolute/protected/recovery \
  --output /absolute/macos-host.json

ARGUS_MACOS_CONFIGURATION=/absolute/macos-host.json \
  caffeinate -i eval/.venv/bin/python eval/remaining/macos_baseline_campaign.py \
  --mode Argus --output eval/campaigns/macos-argus-v1/new-run

eval/.venv/bin/python eval/campaigns/macos-argus-v1/verify_evidence.py \
  eval/campaigns/macos-argus-v1/new-run
```

Output directories must be new. Full runs use five repetitions and retain every
failure and timeout. `--pilot` is a separate diagnostic cohort and must not be
reported as the full evaluation.

`caffeinate -i` prevents idle sleep for the command's lifetime. Lid closure or
forced low-battery sleep can still suspend the host. The native guardian's
deadline clock includes suspension; an expired worker is killed on wake. Such
interruptions remain failed observations rather than successful executions.

The runner freezes application and framework sources before execution. Native
journals live outside every worker-writable artifact directory. Each successful
call records its original certificate, observed binding, lifecycle events and
confirmed cleanup. The verifier recomputes utility from raw outputs and replays
the captured native certificates through the compiled Lean core. Answer
correctness and actual protected tool use are counted separately.

The harness exports these journals at orderly process exit. Timeout-killed
applications can lose in-memory journals, so published replay counts are lower
bounds on executed calls. They do not credit missing traces.

The archive verifier checks the complete inventory of copied Python execution
files and build-source identities before loading the cohort's captured verifier
and framework. For an extracted published bundle, add `--require-checksums` to
verify its byte index as well. Checksums provide integrity checks; they are not
authenticated host attestation.

See [RESULTS.md](RESULTS.md) for the evaluated cohort. The original failed
startup probes remain in [PREFLIGHT.md](PREFLIGHT.md) and `preflight-02.tar.gz`;
they precede the host integration and are not the current implementation result.
