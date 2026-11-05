# Matched host-comparator campaign

This campaign runs the same fixed 15 applications under Baseline, final Argus,
NoNo, and APF/OpenShell. The directory name is retained for artifact compatibility;
the current `NoNo-enforced` and `APF-enforced` modes are not permissive modes.

Each comparator receives every restriction it can enforce for the invocation:

- NoNo grants the interpreter and application code read-only, grants only the
  invocation's external input paths read-only, makes only its fresh trial directory
  writable, blocks networking by default, and permits direct TCP only on the local
  model port. It does not use `--trust-override`.
- APF/OpenShell uses a fresh sandbox for every invocation. The official APF compiler
  projects a policy containing only that invocation's read-only inputs, read-only
  code/runtime paths, a private writable workspace, and the local model relay. The
  harness confirms sandbox deletion before completing the trial.
- Audit is disabled for NoNo because the final Argus configuration also disables
  optional audit. NoNo rollback is disabled because rollback is not an Argus claim.

These are the closest enforceable host policies, not semantic security equivalence.
Neither comparator models Argus's typed Cedar resource/action checks inside an
already permitted Python/library process. NoNo's direct port grant also cannot narrow
the destination host. `enforcement-probes.json` verifies that ungranted files, source
writes, and other network ports are denied while the model endpoint remains usable.

## Timers

- `invocation_ms` is reported by the application after application preparation.
- `process_wall_ms` covers parent dispatch through process exit. It includes Python
  startup and NoNo activation or OpenShell exec transport, but excludes fresh APF
  sandbox preparation and cleanup.
- `secured_wall_ms` uses `process_wall_ms` for Baseline, Argus, and per-command NoNo.
  For APF it includes policy projection, fresh sandbox creation and admission,
  dispatch, and confirmed deletion.

The report shows all three rather than hiding lifecycle work or charging it to the
model call.

## Reproduction

The campaign expects the pinned NoNo binary, APF projector, OpenShell CLI and gateway,
the `slg-apf-apps:bd035dd06` image, the local model relay, and `qwen3:8b` described in
`configuration.json`.

Build the official APF/OpenShell projector helper once:

```bash
cargo +1.95.0 build \
  --manifest-path eval/remaining/apf_probe/Cargo.toml \
  --bin export_policy
```

Run one task per application and mode:

```bash
eval/.venv/bin/python \
  eval/campaigns/langgraph-demos-v3/permissive-comparators/run_campaign.py \
  --run-id matched-comparators-smoke --smoke
```

Run the fixed five-block campaign (700 attempts):

```bash
eval/.venv/bin/python \
  eval/campaigns/langgraph-demos-v3/permissive-comparators/run_campaign.py \
  --run-id matched-comparators-final --repetitions 5
```

Regenerate paired statistics and the Markdown report:

```bash
eval/.venv/bin/python \
  eval/campaigns/langgraph-demos-v3/permissive-comparators/regenerate.py \
  --run-id matched-comparators-final \
  --output-dir eval/campaigns/langgraph-demos-v3/retained/matched-comparators-final
```

The analysis retains every outcome and uses only task/repetition pairs that completed
correctly in both named modes for latency ratios. It does not retry or replace failed
applications.
