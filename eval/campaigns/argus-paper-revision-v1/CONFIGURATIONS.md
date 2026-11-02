# Supported Linux configurations

macOS is outside this campaign. No Linux result below depends on macOS evidence.

| Route | Principal + Cedar | Sealed operator policy | Admission | Isolation | Resource mediation and direct bypass | Grant / activation / lifecycle | Audit and cleanup | Complete? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux object broker + Lean v1 | Required | Required | Closed admission required | Landlock, `no_new_privs`, minimal seccomp, rlimits; cgroup only when delegated | Parent-owned typed mediator; protected SQLite file and side files denied to worker | Exact outer `ObjectGrant`, native lowering, activation receipt validation, compiled Lean object-grant and lifecycle checks | Security/broker audit, mediator release, worker and broker termination confirmation | **Yes**, after preflight and successful trace |
| Linux object broker without checker | Present | May be present | May be present | Present | Present | Checker absent | Present | **No** |
| Direct Linux sandbox + Lean | Cedar/profile route | Route-dependent | Supported | bubblewrap/Landlock/seccomp | Exact files, not the record-broker composition | Lean integrated | Audit/cleanup | **No** for the paper's record-mediation configuration |
| Authorization-only or isolation-only ablation | Partial | No | No | At most one layer | Direct bypass remains or useful access is denied | Incomplete | Partial | **No** |

The complete label is conjunctive. `preflight.py` requires every component and
then validates four checker-backed calls plus independent SQLite state. The
authoritative final preflight is `retained/example/preflight.json`
at implementation commit `e29c882ffc892cd1847c3190f21a0aa8cc4f0904`.

## Production path

`ToolNode` closed admission → authenticated `Principal` →
`ObjectPolicyHostExecutor` → caller/owner/operator Cedar → exact `ObjectGrant` →
`ObjectBrokerDispatcher` → typed mediator negotiation → native grant and
obligations → Lean object-grant check → Landlock/seccomp worker startup →
activation receipt validation → Lean `GO` check → broker operation → confirmed
worker/broker cleanup → Lean result-release check → audit publication.

The fixed Linux gap was concrete: the broker previously instantiated the
Landlock executor without a `LeanLifecycleChecker`. The complete route now
requires the checker, projects canonical resource rules, checks the grant before
effects, checks lifecycle state before `GO` and result release, and retains the
certificates. Missing or altered obligations are rejected before tool execution.
