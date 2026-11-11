# Argus Linux paper-revision handoff

This directory is the revision entry point. macOS is explicitly out of scope.
The final evaluated Linux object-broker implementation is
`f76cbebf85c28cfef520cc779a2c180914808d44`. Its measurement, security evidence,
application route, and reproduction commands are in `OPTIMIZED_LINUX_REPORT.md`.

## Reproduction order

1. Build the checked worker route:

   ```sh
   python3 proofs/worker-route/build_native.py \
     --lake "$HOME/.elan/bin/lake" \
     --output proofs/worker-route/.lake/build/lib/libargus_worker_route.so
   ```

2. Run the fail-closed complete-route preflight:

   ```sh
   PATH="$HOME/.cargo/bin:$PATH" uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/preflight.py \
     --checker-library proofs/worker-route/.lake/build/lib/libargus_worker_route.so \
     --checker-runtime "$HOME/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so" \
     --output /tmp/argus-preflight --run-example
   ```

3. Run the deterministic boundary regressions:

   ```sh
   uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/run_adversarial_regressions.py \
     --output /tmp/argus-boundaries
   ```

4. Run the 44-case Linux matrix, the dependency-complete seven-session subset,
   and the per-process CPU supplement with the commands recorded in
   `SECURITY_RESULTS.md` and each raw `configuration.json`.

5. Qualify a quiet CPU, then run complete-configuration measurements:

   ```sh
   uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/qualify_host.py \
     --output /tmp/argus-host.json --seconds 30

   uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/run_performance.py \
     --checker-library proofs/worker-route/.lake/build/lib/libargus_worker_route.so \
     --checker-runtime "$HOME/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so" \
     --qualification /tmp/argus-host.json \
     --output /tmp/argus-performance \
     --acknowledge-controlled-host
   ```

6. Run the deterministic remote-tool deployment case:

   ```sh
   uv run --project eval python -m slanggraph_eval.remote_tool \
     --output /tmp/argus-remote-tool
   ```

The qualification establishes only an otherwise-quiet selected CPU. This host
is shared and dynamically frequency-scaled; that limitation is recorded and
must accompany timing results.

The performance runner measures the baseline through an unprotected compiled
LangGraph with the same `ToolNode`, request, SQLite workload, and result shape.
It runs in a separate clean interpreter because the sealed operator MAC must
refuse unsecured graphs in the protected interpreter. Raw SQLite timing is
retained only as a diagnostic and is never used as the Argus baseline.

## Tool deployment coverage

The evaluation now has an explicit case for each of the three deployment
shapes discussed in the paper:

| Deployment shape | Evaluation case | Boundary exercised |
| --- | --- | --- |
| Tool executes in the controller process | Distributed-monitor `language` route | Admitted in-process language program and mediated terminal |
| Tool executes as a local binary/worker | This campaign's Alice/Bob example and application route | Cedar, isolated Linux worker, typed resource broker, Lean lifecycle checks |
| Tool is implemented by another server | `retained/remote-tool/` | `ToolNode` and Cedar followed by request-bound delegation over HTTP to a separate toy service process |

The remote case intentionally uses a deterministic loopback weather service,
not a live external system. One allowed call executes remotely; a denied
principal and denied selector produce no remote request, and the service rejects
a replayed capability and a post-authorization argument change. This is evidence
for call authorization and scoped delegation across the server boundary only.
The evaluation-only HTTP dispatcher is not a supported production adapter,
closed admission does not admit it, and Argus does not confine or prove the
remote implementation. The service, transport, signing-key custody, and service
enforcement are trusted premises for this case.

## Evidence map

- `CONFIGURATIONS.md`: complete-label criteria and production path.
- `SECURITY_RESULTS.md`: 45 cases, controls, classifications, fixes, trust
  assumptions, and retained inconclusive attempts.
- `PERFORMANCE_RESULTS.md`: preparation/cold/steady boundaries and reconciled
  timing results for the original fresh-worker/subprocess configuration.
- `OPTIMIZED_LINUX_REPORT.md`: the final evaluated configuration, measurements,
  enforcement results, and application applicability.
- `APPLICATIONS.md`: 15 applications, Pandas, effort, compatibility, and failure
  analysis.
- `PROOF_MAP.md`: exact theorem/checker/assumption map.
- `RUNNING_EXAMPLE.md`: readable Alice/Bob end-to-end trace.
- `retained/remote-tool/`: toy remote-server plan, five trial records, and
  machine-readable summary.
- `generated/application-inventory.json` and `generated/patches/`: exact
  inventory and adaptation patches.
- `raw/`: complete preflight/example plus retained campaign records or compact
  archives/checksums referenced by the result documents.

`preflight.json` is authoritative for `complete`. Missing Cedar, Landlock ABI
below 5, a missing checker, non-`wip` branch, dirty implementation sources, or
any failed example assertion yields `incomplete` and a nonzero exit.

The unrelated checkpoint README edits in the worktree are not part of this
campaign or its commits.
