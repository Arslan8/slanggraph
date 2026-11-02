# Security findings ledger

## Accounting

The frozen cross-host matrix contains **44 distinct cases**, five repetitions
and two conditions: 220 protected/control comparisons per host. Repetitions are
not counted as distinct attacks. Linux retained 221 comparison attempts because
one incomplete observer-race attempt is preserved separately.

The revision boundary inventory below is a test inventory, not a claim that all
rows have already been rerun under the new complete freeze. “Regression” means
the implementation test executed its boundary; “campaign” means an independent
resource oracle and positive control exist in retained raw campaign evidence.

## Concrete fixtures and oracles

`../cross-host-security-v2/fixtures.py` creates a disposable SQLite database
with distinct random Alice and Bob canaries, open WAL/rollback side files, a
stateful pump (`inspect`, `set_flow`, `calibrate`), private and artifact files,
and two live local listeners. Its parent process retains an independent SQLite
connection, command log, pump state, listener observations, file hashes and
process inventory. `verify.py` derives outcomes from those observations and
cross-checks its JSON snapshot against a SQLite backup; worker text and exit
status are not security oracles. `mutation_controls.py` verifies that fabricated
state, a Bob disclosure, listener connection and pump mutation are detected.
Every frozen attack has an unconfined positive-control row using the same
fixture, and all 220 control rows on each host produced their intended effect.

| Boundary | Concrete cases / evidence | Current finding |
| --- | --- | --- |
| Authorization → resource | selector substitution, principal/tool/call/session mismatch, old invocation reuse, resource support recheck | Campaign enforced for fixed cases; `test_mediation.py::test_rebinding_after_authorization_requires_another_decision` and broker binding tests are regressions. Delayed barrier and concurrent mediator mutation need a new complete-freeze campaign rerun. |
| Filesystem identity | pre/post pin symlink swap, ancestor replacement, magic link, hard-link aliases | Regression enforced/rejected. Cross-host macOS hard-link/symlink controls retained. Linux rename + hard-link mutation around a broker-protected path remains an unmatched campaign case. |
| Worker startup | ambient environment, inherited descriptor inventory, credential custody, broker FD identity, import side effect | Regression enforced; import-time protected-file write and direct socket controls use independent state. |
| Child processes | fork, subprocess, exec replacement, descendant direct access, cleanup | Campaign enforced for three fixed process cases; direct Landlock descendant regression also retained. Child broker-FD inheritance is denied by the minimal filter; an exec-enabled profile is outside this route and must not be credited. |
| Controller / guardian | timeout, cancellation, controller death, PID identity, signals, `/proc`, resource exhaustion | Campaign cleanup cases enforced with five-second post-cleanup observation. Same-UID controller tracing is a trusted-controller assumption. Aggregate CPU is rejected, not replaced with wall time or `cpu.max`. |
| Reused contexts | old channel, alternating principals/sessions, session private variables/artifacts, timeout/cancellation/death | Campaign enforced for fixed session cases. Linux object workers are fresh per call; persistent Python sessions use their separate guardian. Cache/session alternation requires a complete-freeze rerun. |
| Parallel execution | parallel ToolNode identity transfers, cancellation, audit serialization, concurrent source/egress | Regression enforced. Request/response confusion and transaction-interleaving stress against one complete mediator remain unmatched campaign cases. |
| Admission/framework | import effects, changed artifact, direct/foreign node bodies, branch mutation, checkpoint/store mediation | Admission/artifact regressions enforced or rejected before execution. Nested graphs, direct graph-node tool calls, and all checkpoint/store variants are only supported when admitted/mediated; other paths are explicit unsupported/trusted surfaces. |

## Before/after fix

| Finding | Before | Fix | After evidence |
| --- | --- | --- | --- |
| Linux broker missing/altered Lean obligation | 10/10 pairs **inconclusive** in `cross-host-security-v2`; injected hook never reached a checker | Checker is required by the complete configuration; Linux grant conditions now expose resource selector, protected paths and required capabilities; exact generated guard inventory is checked | Compiled-checker broker test reaches `grant_ready`, `running`, and `ready`; complete example retains four successful traces |
| Linux controller-death persistent session orphan | Development pilot observed survivor | parent-death signal + expected-parent check | Frozen cross-host rerun: 5/5 controller-termination session pairs enforced; diagnostic retained |
| macOS syscall filter / aggregate CPU | Host cannot establish requirement | No weakening; retain request and reject before body release | 5/5 explicit refusals for each requirement |
| macOS per-process total CPU | syscall-heavy reproducer exceeded intended ceiling | Classified unqualified; mandatory request rejects | 5/5 supplementary explicit refusals; raw CPU transcript retained |
| Pandas missing period | `null` reconstructed as Pandas `NaN`, strict output guard refuses | Versioned period-aggregation primitive completes mean buckets then serializes missing values as JSON `null`; guard and oracle unchanged | Unit/contract tests pass; historical 5/5 failures retained until a fresh matched model campaign |
| Time-travel checkpoint restore | `checkpoint:broken_chain` after successful tool call | Not bypassed | Classified as a conflict with the current authenticated history chain until a continuation protocol is specified; 5/5 failures retained |

## Trust assumptions and abandoned attempts

- Operator/controller compromise, same-UID tracing of the trusted controller,
  malicious mediator code, checker/compiler/runtime refinement bugs, and kernel
  compromise are trust assumptions, not successful defenses.
- Closed-port network probes were abandoned; the retained test uses a live local
  listener and a successful unprotected control.
- Worker-returned “blocked” strings are never the sole oracle. SQLite, pump,
  listener, file, process, and cleanup state are inspected by the parent.
- Historical route timings with different guard mixes are not recombined.

Raw prior evidence and mutation controls are under
`../cross-host-security-v2/`. The new complete invocation is generated by
`preflight.py --run-example`.
