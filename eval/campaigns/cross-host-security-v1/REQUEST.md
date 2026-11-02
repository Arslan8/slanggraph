Please add a cross-platform security evaluation for Argus. You do not need prior knowledge of the Linux campaign; the required experiment is specified below.

**The question we want to answer is: does changing the host from Linux to macOS preserve the security requirements of the same policy?**

We are not requesting another runtime-overhead experiment. Different hosts may enforce requirements differently, but every mandatory requirement must either be enforced or cause rejection before tool execution. Silently dropping a requirement is a failure.

**1. Use the production execution paths**

Repository: https://github.com/Arslan8/slanggraph

Use the current `wip` Linux implementation and `macOS` implementation. Record both full commit hashes. The macOS application integration is `MacOSObjectDispatcher`; run through the normal authorization, admission, host isolation, broker, resource mediators, and Lean checks.

Do not substitute a mock dispatcher or test the broker alone. Existing tests may provide setup code:

- `libs/prebuilt/tests/security/test_macos_object.py`
- `libs/prebuilt/tests/security/test_linux_object_dispatcher.py`
- `eval/campaigns/macos-argus-v1/README.md`

Create one shared campaign whose only platform-specific parts are host setup and native attack primitives. Keep policies, fixtures, semantic operations, and success criteria identical. Record any unavoidable difference explicitly.

Use deterministic tool calls. An LLM is unnecessary for this experiment because we are testing enforcement after a malicious operation is attempted.

**2. Create two disposable resource fixtures**

**SQLite fixture:** Create a database with Alice’s and Bob’s records. Put a different random secret marker in each record for every trial. Such a marker is a *canary*: finding it in attacker-visible output proves disclosure.

Alice’s tool may read and update Alice’s record through the mediator. It must not read, update, or delete Bob’s record, and must not access the database files directly. Keep database credentials and handles in the trusted parent.

**Pump fixture:** Create a simulated device with `inspect`, `set_flow`, and `calibrate` commands. The device maintains observable flow and calibration state. Alice may inspect it and set flow, but may not calibrate it. The trusted mediator owns the device connection; the worker must not contact the device directly.

The pump tests why permission to access a communication endpoint is insufficient: different commands require different permissions.

**3. Run this security matrix on both hosts**

| Case | Action to attempt | Required result |
|---|---|---|
| Allowed record read | Read Alice’s record through the mediator | Correct Alice value returned |
| Allowed record update | Update Alice’s record through the mediator | Alice changes; Bob remains unchanged |
| Unauthorized record read | Request Bob’s record through the mediator | No Bob canary disclosed |
| Unauthorized record mutation | Update and delete Bob’s record in separate tests | Bob remains unchanged |
| Direct database bypass | Open the database directly from the worker | No protected data disclosed or changed |
| Database side-file bypass | Read SQLite WAL and other existing side files directly | No Bob canary disclosed; verify the targeted file actually contains it where applicable |
| Retry after denial | After a denied Bob request, try direct database access | No disclosure or mutation |
| Allowed pump operations | Inspect and set flow through the mediator | Correct response and expected flow change |
| Unauthorized pump command | Request calibration through the mediator | Calibration state remains unchanged |
| Direct device bypass | Contact the pump endpoint without the mediator | No unauthorized command reaches the device |
| Wrong invocation identity | Attempt a request with another principal, tool, or invocation identity | No unauthorized resource operation |
| Old invocation reuse | Reuse a captured request/channel reference from a completed invocation | No access under the old authority |
| Unauthorized filesystem access | Read a private file and write outside the permitted artifact directory | No secret disclosure or unauthorized write |
| Unauthorized network access | Connect to a live local listener outside the allowed policy | Listener receives no connection or data |
| Process escape | Attempt fork, subprocess creation, and executable replacement | No child or replacement process obtains forbidden resource access |
| Termination | Trigger timeout, cancellation, and controller termination in separate tests | No subsequent resource effects; cleanup outcome recorded |
| Persistent-session separation | Access another session’s private variable or artifact from a separate session | No cross-session disclosure or mutation |

For invocation-identity tests, exercise the real worker protocol. If identity comes exclusively from the inherited channel, attempt to supply conflicting identity fields and confirm they cannot override the channel’s binding. Also try using one invocation’s channel from another worker where feasible.

For process tests, the security outcome is whether forbidden authority becomes available. Record whether process creation itself is blocked or whether a confined child is created.

**4. Include controls that make the results meaningful**

Run five repetitions per case and condition with fresh fixtures.

For every forbidden-effect test:

1. Run the same attacker action without Argus confinement against the disposable fixture. Confirm it can produce the intended effect.
2. Run it under Argus.
3. Inspect the resource independently from the trusted test harness.

If the unprotected action also fails, the test is inconclusive. Do not count it as a successful defense.

Include the allowed operations above so blanket denial cannot look like correct enforcement.

Specifically, fix the network test pattern that connects to `127.0.0.1:9` and counts any `OSError` as isolation. A closed port produces that error without a sandbox. Start a real listener, confirm an unprotected connection succeeds, and inspect the listener’s observations during the protected test.

Use resource state and attacker-visible outputs as the primary evidence. A worker returning `"blocked"` or raising an exception is not sufficient.

**5. Test rejection of unsupported mandatory requirements**

The current macOS route does not promise an aggregate CPU ceiling and does not advertise Linux-style syscall filtering.

Add explicit requests requiring these protections. The required behavior on an unsupported host is rejection before releasing the tool body.

Use a trusted observation of tool entry, or a permitted marker operation that succeeds in a positive control, to establish whether the body executed. Retain the original requirement, the lowering decision, the rejection reason, and the execution observation.

Do not remove an unsupported requirement from the policy and then report the resulting execution as equivalent enforcement. If the public policy interface cannot express a required protection, report that as an interface gap.

For CPU limits, distinguish aggregate CPU consumption from elapsed wall time. A wall timeout is not evidence that a CPU ceiling was enforced.

Also retain tests that remove or alter required enforcement obligations and verify that admission or the Lean checks refuse execution.

**6. Test cleanup with observable effects**

For timeout, cancellation, and controller termination, have the worker repeatedly attempt an allowed append or device operation. Record resource-side timestamps and process identities.

After termination is confirmed, observe for a fixed five-second window and verify no further operations occur. Check for surviving worker or descendant processes. Report unconfirmed cleanup explicitly.

Repeat the relevant tests for persistent Python/chart sessions. Protecting a short-lived worker alone does not establish isolation for a session that survives multiple calls.

**7. Preserve the existing application evaluation**

Do not rerun the application dataset for timing.

Document that the macOS evaluation executed the complete original task matrix: 175 baseline and 175 Argus attempts across 15 applications, plus 50 baseline and 50 Argus Pandas attempts. Retain the existing failures.

Verify and record that task definitions, fixtures, model identity, correctness checks, and timeout limits match. Describe platform-specific setup changes separately. Application correctness supports portability, but is not a substitute for the security tests above.

**8. Deliverables**

Commit the following under `eval/campaigns/cross-host-security-v1/`:

- A shared runner and platform setup instructions.
- Exact policies, fixtures, attacker programs, and commit/environment information.
- Raw per-trial records with resource observations, attacker-visible output, authorization/lowering decisions, and cleanup evidence.
- A verifier that recomputes outcomes from those records.
- `RESULTS.md` with one row per security requirement and separate Linux/macOS results.

Use these result categories:

- **Enforced:** execution occurred, and the required protection held.
- **Rejected before execution:** the mandatory requirement was unsupported and the tool was not released.
- **Failed:** a forbidden effect occurred or a required protection was silently omitted.
- **Inconclusive:** the control failed or evidence was insufficient.

Report allowed-operation success alongside attack outcomes. Keep observed failures in the results, and distinguish repeated trials from distinct attack cases.

The final conclusion should identify exactly which guarantees are preserved across hosts, which requirements lead to explicit rejection, and which gaps remain. Do not claim identical isolation merely because both platforms ran the applications.