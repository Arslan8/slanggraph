# macOS execution configuration

The evaluated route is `StateGraph.compile(security=...)` with `closed_admission=True`, `cedar_security(...)`, a sealed `RuntimeMAC`, authenticated `Principal`, `MacOSObjectDispatcher`, `ResourceMediatorAdapter`, a native Seatbelt launcher, `LeanLifecycleChecker`, an audit sink, and a recovery directory. `evaluation.assert_complete_path` refuses a configuration missing any of these. The nine `preflight_*` cases in `specification.py` remove one component at a time. The successful `allowed_record_read` trial records the principal, Cedar grant, native plan, mediator event, activation receipt, live Lean phases, audit, and confirmed cleanup.

## Trust boundary

The controller, authentication adapter, Cedar CLI/policy loading, MAC policy, graph admission, dispatcher, decoder, resource mediators, audit sink, Lean native checker, launcher/guardian, and operating system are trusted. SQLite credentials and handles remain with the controller. The attacker tool module and its imports execute in a fresh Seatbelt worker. Only the worker's bound protocol pipes reach the mediator. The closed graph's declared `TRUSTED_APPLICATION` Python node bodies and branches run in the controller and remain trusted. The whole application is **not** confined. A direct call from an admitted trusted graph node can use controller authority. The specific direct and nested entry attempts in the supplemental harness fail admission because their node bodies do not satisfy the trusted-node declaration rules.

The production path is `ObjectPolicyHostExecutor` → `MacOSObjectDispatcher.invoke` → `_MacOSObjectWorker._compile_grant` / `_prepare_execution` → `MacOSSandboxExecutor._invoke` → native launcher → worker protocol → `_ObjectBroker` / typed mediator → lifecycle checker and cleanup. Admission binds code artifacts and the graph inventory before invocation. A changed worker artifact is refused before activation.

## Unsupported requirements

Mandatory total per-process CPU time, aggregate process-tree CPU time, and syscall filtering are retained as `need` requirements and refused during lowering. `RLIMIT_CPU` is not treated as an exact total-CPU guarantee on the tested macOS build. Elapsed wall time is a separate supervisor deadline. The prior observed CPU overrun remains a qualification failure; this resubmission did not repeat that benchmark. The native object route now also refuses mandatory direct filesystem `read` grants because a Seatbelt pathname rule can follow a renamed or hard-linked object after authorization. Read the resource through a semantic mediator instead. The generic macOS path executor retains pathname semantics and does not claim object identity.

Positive controls and refusals are in `security-final-03/trials/`, `advanced-run-01/` (before fix), and `advanced-run-02/` (after fix). Those generated run directories are local evidence and are ignored by the repository's evaluation output rule. The committed `acceptance.json` summarizes the checked runs.

## Reproduce

From the repository root, set `ARGUS_MACOS_CONFIGURATION` to a locally pinned macOS launcher/Lean manifest and put the pinned Cedar CLI on `PATH`. Run `eval/.venv/bin/python eval/campaigns/macos-resubmission-v1/run.py --output <new-directory> --repetitions 5 --jobs 3`, then `eval/.venv/bin/python eval/campaigns/macos-resubmission-v1/verify.py <new-directory>`. Run `advanced.py --output <new-directory> --repetitions 3` for the supplemental cases. These scripts make no Linux execution or performance measurements.
