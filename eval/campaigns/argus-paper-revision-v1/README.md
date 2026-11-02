# Argus paper-revision handoff

This directory is the revision entry point. It defines one complete Linux
configuration, refuses to label a run complete when a component is absent, and
links the retained macOS/application evidence without treating application
completion as a security result.

## Reproduction order

1. Build the checked worker-route executable:

   ```sh
   cd proofs/worker-route
   PATH="$HOME/.elan/bin:$PATH" lake build workerRoute
   ```

2. Run the complete-route preflight and example from the repository root:

   ```sh
   PATH="$HOME/.cargo/bin:$PATH" uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/preflight.py \
     --checker proofs/worker-route/.lake/build/bin/workerRoute \
     --output /tmp/argus-revision-preflight --run-example
   ```

3. Run the focused implementation checks, then the library gates:

   ```sh
   PATH="$HOME/.elan/bin:$PATH" uv run --project libs/prebuilt pytest -q \
     libs/prebuilt/tests/security/test_object_broker.py \
     libs/prebuilt/tests/security/test_lean_lifecycle.py
   cd libs/prebuilt
   make format
   make lint
   make test
   ```

4. Only on a qualified quiet host, launch the final interleaved measurement:

   ```sh
   uv run --project libs/prebuilt python \
     eval/campaigns/argus-paper-revision-v1/run_performance.py \
     --checker proofs/worker-route/.lake/build/bin/workerRoute \
     --output /retained/argus-final-linux \
     --acknowledge-controlled-host
   ```

   The acknowledgement is an operator assertion, not an automatic proof of a
   quiet machine. The runner still executes the complete-route preflight and
   records load, CPU configuration, hashes, and source stability.

`preflight.json` is authoritative for the label. A missing Cedar executable,
Landlock ABI below 5, missing checker, non-`wip` branch, or failed example makes
the label `incomplete` and exits nonzero. `example/invocation.json` records the
admission descriptor, outer grants, native lowerings, activation receipts,
checker traces, broker decisions, security audit, and independent SQLite state.

## Evidence generations

- `cross-host-security-v2` is the frozen pre-fix Linux/macOS matrix at
  `79c6309604835277333393d426a0c7fc22eb49e0`. Its ten Linux altered/missing
  Lean-obligation pairs are retained as inconclusive.
- This revision adds the missing Linux object-broker checker integration. New
  evidence must use the implementation freeze named in `CONFIGURATIONS.md`.
- Historical performance rows remain historical. A final campaign must run on
  a controlled Linux host after the freeze; see `PERFORMANCE_RESULTS.md`.

The two unrelated checkpoint README edits present in the development worktree
are outside this campaign and are not part of its commits.
