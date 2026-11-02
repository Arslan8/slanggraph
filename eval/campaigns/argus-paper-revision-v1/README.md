# Argus Linux paper-revision handoff

This directory is the revision entry point. macOS is explicitly out of scope.
The authoritative implementation freeze is
`e29c882ffc892cd1847c3190f21a0aa8cc4f0904`; later evidence/documentation
commits do not change the measured implementation paths.

## Reproduction order

1. Build the checked worker route:

   ```sh
   cd proofs/worker-route
   PATH="$HOME/.elan/bin:$PATH" lake build workerRoute
   ```

2. Run the fail-closed complete-route preflight:

   ```sh
   PATH="$HOME/.cargo/bin:$PATH" uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/preflight.py \
     --checker proofs/worker-route/.lake/build/bin/workerRoute \
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
     --checker proofs/worker-route/.lake/build/bin/workerRoute \
     --qualification /tmp/argus-host.json \
     --output /tmp/argus-performance \
     --acknowledge-controlled-host
   ```

The qualification establishes only an otherwise-quiet selected CPU. This host
is shared and dynamically frequency-scaled; that limitation is recorded and
must accompany timing results.

## Evidence map

- `CONFIGURATIONS.md`: complete-label criteria and production path.
- `SECURITY_RESULTS.md`: 45 cases, controls, classifications, fixes, trust
  assumptions, and retained inconclusive attempts.
- `PERFORMANCE_RESULTS.md`: preparation/cold/steady boundaries and reconciled
  timing results.
- `APPLICATIONS.md`: 15 applications, Pandas, effort, compatibility, and failure
  analysis.
- `PROOF_MAP.md`: exact theorem/checker/assumption map.
- `RUNNING_EXAMPLE.md`: readable Alice/Bob end-to-end trace.
- `generated/application-inventory.json` and `generated/patches/`: exact
  inventory and adaptation patches.
- `raw/`: complete preflight/example plus retained campaign records or compact
  archives/checksums referenced by the result documents.

`preflight.json` is authoritative for `complete`. Missing Cedar, Landlock ABI
below 5, a missing checker, non-`wip` branch, dirty implementation sources, or
any failed example assertion yields `incomplete` and a nonzero exit.

The unrelated checkpoint README edits in the worktree are not part of this
campaign or its commits.
