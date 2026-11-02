# Linux security results and findings ledger

## Final accounting

The retained campaign covers **45 distinct attack/requirement cases**. Each has
five repetitions and paired unprotected/protected conditions: 450 final
comparison trials. The original 44-case run is retained even though seven
persistent-session rows were inconclusive because their controllers lacked an
application dependency. Those seven were rerun, with the same attacks and
oracles, in the validated Linux container harness and replace only those rows.
The per-process cumulative CPU case is the 45th case.

Final selected outcomes are **39 Enforced**, **6 Rejected before execution**,
**0 Failed**, and **0 Inconclusive**. The six refusals are aggregate process-tree
CPU, the two extensible mandatory requirements, missing/altered checker
obligations, and modified admission artifacts. Mandatory minimal syscall
filtering and per-process cumulative CPU both entered execution and were
enforced. Aggregate process-tree CPU was not substituted with a wall timeout or
bandwidth cap; it was rejected before the body.

The separate deterministic boundary suite contributes 51 implementation
investigations and 2,000 parallel scheduling trials. These overlap the campaign
conceptually and are not added to the 45-case attack count.

## Fixtures and outcome criteria

`cross-host-security-v2/fixtures.py` creates a disposable Alice/Bob SQLite
database with random canaries and side files, a stateful pump with `inspect`,
`set_flow`, and `calibrate`, private and artifact paths, and live local
listeners. The parent retains an independent SQLite connection, command log,
pump state, listener observations, hashes, and process identities. Every final
case has a successful unprotected effect. Protected classifications use those
independent observations; worker text, exceptions, and exit status are not the
security oracle.

| Boundary | Tests and scheduling | Final finding |
| --- | --- | --- |
| Authorization → resource | selector/principal/tool/call/session substitution; old invocation; rebinding regression; missing/altered inventory | Fixed campaign cases enforced; missing/altered obligations reject before execution. Deterministic rebinding requires a new authorization. |
| Filesystem identity | ancestor rename + symlink replacement, pre/post-pin swaps, magic links, hard-link alias identity | Descriptor route refuses changed ancestors or retains the pinned object. Hard-link test compares device/inode and actual content. A trusted host namespace mutator remains a trust assumption. |
| Worker startup | environment, descriptor inventory, broker FD and credential custody, live socket, import side effect | Direct database/listener/import effects absent; intended broker authority remains usable. Two production-worker probes also passed in the privileged Linux validation container: ambient environment/credential values were cleared and ambient descriptors were absent. |
| Child processes | fork, subprocess, executable replacement, descendant access and cleanup | All three attacks enforced in 5/5 pairs; child creation cannot turn inherited state into usable authority. |
| Controller/guardian | timeout, cancellation, controller death, signals/process observation, bounded resource exhaustion | Fixed cleanup cases enforced. Same-UID tracing of the trusted controller is explicitly outside the threat model. |
| Reused contexts | alternating sessions/principals, variables, artifacts, timeout/cancellation/controller death | All seven cases enforced in 5/5 dependency-complete reruns. The dependency-missing attempts remain preserved as inconclusive pre-fix evidence. |
| Parallel execution | two ToolNode modes; 1,000 synchronous and 1,000 asynchronous calls; identity substitution, oversized-frame confusion, concurrent source/egress barriers | Eight regressions pass; identity transfers remain unique, framing is unambiguous, and responses do not cross calls. |
| Admission/framework | modified artifacts, unsupported node bodies, checkpoint replay/tamper, direct/foreign paths | Ten regressions pass; changed admission artifact is rejected before execution in 5/5 campaign pairs. Unadmitted direct graph-node and checkpoint/store paths are unsupported, not claimed as enforced. |

## Before/after findings ledger

| Finding | Before | Change | After |
| --- | --- | --- | --- |
| Linux broker lacked Lean integration | Injected missing/altered obligations never reached a checker | Checker made mandatory on the object broker; grant, `GO`, result and cleanup gates connected | Missing and altered inventories rejected before execution 5/5 each; successful certificates replayed independently |
| Persistent-session campaign environment | Seven cases had no control or protected execution because `scikit-learn` was absent | Reran unchanged cases in the dependency-complete privileged outer harness; inner production isolation unchanged | 35/35 protected comparisons enforced and all controls effective |
| Per-process cumulative CPU | Earlier probe did not consume enough CPU to establish the limit | CPU-bound body consumes 2.5 process seconds, then attempts a forbidden update | Required `RLIMIT_CPU` activated; body terminated before effect 5/5 |
| Aggregate process-tree CPU | Host has no cumulative tree-time primitive | Requirement retained unchanged | Rejected before execution 5/5 |
| Pandas monthly mean | Missing month became `NaN` during vendor DataFrame reconstruction and hit the strict guard | v23 carries a versioned JSON-null sentinel through reconstruction and restores it only at the admitted wrangling boundary | Baseline 10/10 and protected 10/10; monthly mean completed with zero output-validation failures |
| Checkpoint restoration | Time travel raises `checkpoint:broken_chain` | Integrity checks retained | Classified as an intended-history conflict requiring an authenticated branch transition, not bypassed |

## Trust assumptions and abandoned attempts

- Trusted operator/controller compromise, same-UID tracing of that controller,
  malicious mediator code, checker/compiler/runtime correspondence errors, and
  kernel compromise are assumptions, not successful defenses.
- Closed-port probes were abandoned; the retained network test uses a live
  listener and a successful control.
- A path changed by a trusted host namespace mutator after authorization is not
  credited as a worker defense. Worker-accessible rename/symlink routes are
  blocked or identity-pinned.
- Historical heterogeneous timing rows are not combined with the final complete
  configuration.

Compact raw records, configurations, source inventories, checksums and all
regression logs are committed under `retained/security/`. The expanded local
campaign directories are `raw/linux-security-0d3e69976/`,
`raw/linux-security-sessions-e5ab8da61/`, and
`raw/linux-security-per-process-cpu-e5ab8da61/`.
The exact startup-probe command, image identity, and result are retained in
`retained/security/linux-container-startup-probes.log`.
