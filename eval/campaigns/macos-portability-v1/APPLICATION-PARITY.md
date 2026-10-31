# Requirements for matched application portability

Status: **not executed on macOS**. This is the next evaluation milestone, not a
result or evidence of an admitted macOS application route.

## Freeze the existing applications

Use the ordinary-demo v3 runner, task definitions, fixtures, tool schemas,
correctness oracles, and protected policies as the common starting point:

- `eval/campaigns/langgraph-demos-v3/run_campaign.py` and `regenerate.py`.
- D1–D5 frozen tasks in `eval/campaigns/langgraph-demos-v1/tasks.json`.
- T1–T10 historical tasks and oracles already embedded in the v3 runner.
- The eight application scripts and fixture digests listed in each existing
  run's `configuration.json`.

The denominator is 15 applications, 35 tasks, five repetition blocks, and two
conditions: 350 planned trials **per OS**. D1–D5 each retain five tasks; T1–T10
each retain one. Freeze one common source/configuration manifest before either
new OS campaign; report differences from historical Linux runs separately.
Historical Linux observations do not become a newly matched run merely because
macOS uses the same task names.

Preserve model-visible tool names, descriptions and argument schemas; prompts;
fixtures and per-trial resets; retry and termination behavior; and correctness
checks for returned values and resource state. Retain the existing model pin
(`qwen3:8b`, digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`),
temperature 0, generation seed 20261005, and reasoning effort `none`, or declare
and freeze a new shared configuration for both OS runs. Verify the pin on the
actual model service instead of inferring it from its tag.

## Integrate and qualify the protected route first

The macOS component currently uses typed mandatory policy and an experimental
executor. It is not the same complete admitted route used by these applications.
The demo adapters select Linux routes, while the resource monitors construct
object-policy executors and broker-backed resources. Changing `runs linux` to
`runs macos` is insufficient.

Before crediting a protected application trial:

1. Integrate native macOS execution with the existing principal, sealed operator
   policy, Cedar/object-policy and resource-monitor paths used by that application.
2. Port the pinned runtime Lean transport and retain the required lifecycle
   checks. Record the OS-specific binary/runtime hashes and common protocol/core
   identity. The Linux sealed-memfd transport cannot be assumed to work on macOS.
3. Establish closed admission and source-bound route validation for those paths.
   Do not substitute experimental open execution for a missing admitted route.
4. Qualify the actual SQL, retrieval, search, Python-session and travel resource
   operations. Pandas requires its generated-code and native-extension execution
   path as well as its resource/output mediation.
5. Map every frozen policy obligation through the actual lowerer. An unsupported
   requirement remains unsupported; do not remove it to manufacture parity.

CPU qualification is explicitly deferred by the user. Retain that exception in
scope and raw results. A claim about the remaining protections still requires
all other application-route checks; CPU deferral does not waive Lean, admission,
policy or resource mediation.

## Execute and retain the complete matrix

First run an application preflight on each host. Keep a separate admission/
support matrix for every application and policy obligation. Do not count a
planned unsupported job as an executed trial. If execution is attempted and
refused, record the actual refusal stage and timing.

For supported routes, preserve five paired repetition blocks and the existing
within-block shuffle seed 20261028. Use parent-subprocess wall time including
startup and shutdown in both conditions. Exclude only shared preparation and
warmup symmetrically, and record them. Preserve the existing per-application
timeouts (180 seconds or 300 seconds), failures, retries and resource-state
oracles. Verify source and fixture identities before and after the campaign.

Run the separate ten-task Pandas cohort under its own frozen workflow and
180-second boundary, with five repetitions and both conditions: 100 planned
trials per OS. Retain the latest Linux activation failures rather than treating
its failed-attempt duration as useful execution overhead.

## Report support and correctness before timing

Publish planned, attempted, unsupported, refused, failed, timed-out, completed
and correct counts separately for each OS, application and condition. Retain raw
outputs, resource-state snapshots, policy/receipt/audit evidence, model metadata,
host metadata, source/fixture pins and subprocess logs.

Apply the existing paired-block resampling to valid within-host application
comparisons. Exclude undefined ratios explicitly when a condition has no
completed trials; never present fast refusal as successful execution overhead.
Report OS/hardware differences and enabled-protection differences. Cross-host
latency differences cannot establish an OS performance effect. Application-level
portability requires the shared workloads, policies and correctness checks to
succeed under the declared protections; matching microbenchmark sample counts
alone does not establish it.
