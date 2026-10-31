# Cross-host security campaign v1

This campaign tests policy requirements after deterministic malicious operations. It does not use an LLM or measure overhead. Read `RESULTS.md` for the measured scope and limitations. The Linux comparison imports committed WIP observations; this campaign does not execute Linux trials.

## Execution

From the repository root, on macOS, configure the production operator image as described in `eval/campaigns/macos-argus-v1/README.md`. The configuration must pin the native launcher, Python image, Lean core and runtime digests. Use the application Python environment with Cedar on PATH:

```sh
PATH="$PWD/eval/vendor/macos-toolchains/cedar/bin:$PATH" \
ARGUS_MACOS_CONFIGURATION="$PWD/eval/vendor/macos-argus-configuration.json" \
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
eval/.venv/bin/python eval/campaigns/cross-host-security-v1/run.py \
  --output eval/campaigns/cross-host-security-v1/run-01
```

Default: 44 distinct cases, five repetitions, two conditions, three independent fixture pairs concurrently: 440 trials. Each unprotected control uses exactly the same attacker source as its Argus partner, with fresh independent canaries. Controls intentionally retain ambient resource access. Protected workers use `MacOSObjectDispatcher`, Cedar, sealed operator MAC, closed admission, native Seatbelt confinement, invocation broker, resource mediators and compiled Lean checks. No permissive substitute dispatcher is installed. Fault cases alter inputs passed to the real checker, which still decides whether execution can proceed.

`host.py` contains native configuration and process-identity primitives. Semantic policies, fixture operations, attack program and oracles are shared. The existing Linux resource production dispatcher is available in the setup module, but lacks the macOS route's integrated Lean lifecycle path. Its use must not be described as the complete admitted route. Historical Linux data are consequently compared requirement by requirement, with policy and envelope differences retained.

To inspect an extracted macOS run on compatible macOS, with its Python dependencies installed:

```sh
eval/.venv/bin/python eval/campaigns/cross-host-security-v1/verify.py /absolute/path/to/run-01
eval/.venv/bin/python eval/campaigns/cross-host-security-v1/mutation_controls.py /absolute/path/to/run-01
eval/.venv/bin/python eval/campaigns/cross-host-security-v1/linux_reference.py
```

The verifier loads retained framework sources and pinned native Lean images, verifies the source inventory, fixture bytes and SQLite backups, replays successful certificates, and recomputes outcomes. It never accepts a `blocked` message as an oracle. Raw timestamps are observations, not benchmark results. The archive contains disposable generated canaries and ephemeral fixture connection tokens, not real customer records.

## Policy and evidence

`specification.py` is authoritative; `policy.cedar`, `operator-policy.cedar`, `classes.slp` and `manifest.slp` expose its ordinary policy. Per-trial evidence retains the exact classes and manifest, including required-contract and narrowed-invocation variants. Alice may read/update `notes/alice`, inspect/set flow on `pump-1`, append a trusted entry/progress marker and execute session B. Bob and session A are excluded. Broker endpoint access alone does not authorize a device command. SQLite connections and resource-side authentication tokens stay outside the worker.

Each trial retains input, controller output, attacker-visible result, authorization audit/grants, lowering/receipts, broker audit, successful lifecycle certificates, independent resource events/state and pretrial file bytes. SQLite main/WAL/journal probes verify the selected source contains Bob's marker. SHM has metadata rather than a Bob marker: its case tests prohibited direct file access, not Bob disclosure. A live independent TCP listener establishes network reachability before protected isolation is judged.

Cleanup uses resource-side ticks and PID plus process-start identities. The observer survives controller termination. Persistent sessions are the actual application `PersistentPythonBackend`; the unprotected control uses the same session server without native activation. Its public execution timeout remains 30 seconds. After confirmed process absence, a fixed five-second window must show no further effects. The harness only kills remaining control processes after that window. A failed positive control or unconfirmed cleanup is inconclusive.

Old invocation reuse captures a real completed request, resets its prior effect, then replays that request through a different worker's channel with narrower authority. It does not claim an inherited descriptor survives process destruction. Principal/tool/call/session identity probes send conflicting real broker fields. Process escape checks forbidden resource authority, while separately retaining whether process creation itself succeeded.

Native aggregate-CPU and syscall requirements have no public policy syntax in this object interface: those cases are interface gaps. Additional `enforced_by kernel` extensible contracts test fail-closed rejection of unknown mandatory contracts; their names do not implement or qualify actual CPU accounting or syscall filtering. Wall timeouts are never counted as aggregate CPU enforcement.

## Historical comparison and preservation

`linux-reference.tar.gz` contains exact committed WIP resource-composition blobs. `linux-reference.json` records the containing tree commit, Git blob IDs and SHA-256 digests. The historical trial rows retain worker-source hashes, not a full execution commit; the containing tree is not presented as their execution revision. `linux_reference.py` recomputes resource/canary outcomes. Old `call_authorization_native` controls retain native access and are an incomplete reference condition, not the new unrestricted process control. Related attacks with different subjects, commands or entry boundaries do not count as equivalent validation.

`application_preservation.py` reads the existing macOS application cohorts and source snapshots without rerunning them. Its result retains all 175+175 application and 50+50 Pandas attempts, failures, fixture/model/task/oracle/timeout checks and setup differences. Those checks establish consistency of the two macOS cohorts; historical Linux environment differences remain in the original reports.

Pilot directories are development diagnostics, excluded from the deliverable. `run-01` is the frozen full campaign. Source-before/source-after must match; partial pilots cannot satisfy the full-matrix verifier. `mutation_controls.py` deliberately corrupts copied observations in memory to establish that false defenses and fabricated state are rejected.
