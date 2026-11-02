# Supported configurations

| Route | Principal + Cedar | Sealed operator policy | Closed admission | Isolation | Resource mediation / direct bypass | Grant, activation, lifecycle | Audit + cleanup | Complete? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux object broker + Lean v1 | Required | Required | Required | Landlock + `no_new_privs` + minimal seccomp + rlimits; cgroup when delegated | Parent-owned typed mediator; Landlock denies protected DB and side files; spawn-bound broker channel | Exact outer `ObjectGrant`, derived native grant, host negotiation, receipt validation, Lean object-grant and lifecycle checks before `GO` and result release | Security audit, broker audit, mediator release, worker/broker termination confirmation | **Yes**, only after preflight and successful trace |
| macOS native object route | Required | Required | Required | Native launcher + Seatbelt + hard limits | Parent-owned typed mediator and private inherited pipes | Object-grant/lifecycle checker integrated | Audit, guardian recovery, confirmed cleanup | Complete for requirements the host enforces; mandatory unsupported CPU/syscall requirements reject |
| Linux object broker without checker | Present | May be present | May be present | Present | Present | **Checker absent** | Present | **No** |
| Direct Linux sandbox + Lean | Cedar/profile route | Runtime-MAC route-dependent | Supported | bubblewrap/Landlock/seccomp | Exact files, not the record broker composition | Lean integrated | Audit/cleanup | **No** for the paper's record-mediation configuration |
| Authorization-only / isolation-only ablations | Partial | No | No | At most one layer | Direct bypass remains or useful access is denied | Incomplete | Partial | **No** |

The complete label is conjunctive. `preflight.py` does not infer completeness
from a successful process exit. It requires all components and then validates a
trace containing four checker-backed calls and independent database state.

## Production path

`ToolNode` closed admission → authenticated `Principal` →
`ObjectPolicyHostExecutor` → caller/owner/operator Cedar → exact `ObjectGrant` →
`ObjectBrokerDispatcher` → typed mediator negotiation → native grant and
obligations → Lean object-grant check → Landlock/seccomp worker startup →
activation receipt validation → Lean `GO` check → broker operation → worker and
broker cleanup → Lean result-release check → audit publication.

The pre-fix blocker was concrete: `ObjectBrokerDispatcher` instantiated
`LandlockSandboxExecutor` without a `LeanLifecycleChecker`. This revision adds
the checker parameter, canonical resource-rule projection, pre-effect grant
gate, pre-`GO` lifecycle gate, post-cleanup result gate, and retained lifecycle
records. The fixed test executes the compiled checker, not a mock.
