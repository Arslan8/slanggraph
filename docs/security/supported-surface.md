# Supported surface inventory (schema 2, route-scoped)

`supported-surface.json` is the authoritative route/check mapping. Acceptance
recomputes each supported route's applicable SGV901–903 obligations, requires
registered refusal codes for its exclusions, and rejects ungated exclusions.
The [evidence standard](evidence-standard.md), [threat model](threat-model.md)
and [runtime operation catalog](runtime-operations.md) state the premises.

## Accepted routes

| Route | Accepted evidence and boundary |
| --- | --- |
| R1 `language-sandbox-tool` | Admission and router checks; language derivation and fresh `proofs/language-route` Lean audit. The model proves accepted programs call only registered terminals; interpreter fidelity and terminal implementations are trusted. |
| R2 `tool-node-dispatch` | Closed admission, captured descriptor identity and router correspondence for supported tool dispatch. |
| R3 `linux-worker-compute` | Admission/router checks, fresh `proofs/worker-route` Lean audit, source-bound native and grant-v3 pandas observations, and a structural host guard. Model/runtime correspondence and OS enforcement remain explicit premises. |
| R4 `output-publication` | Admission/router checks, host-output correspondence, output-validator contract and output-mediator correspondence. |
| R5 `model-invoke-hook` | Admission/router checks: the policy hook precedes the captured model call; denial prevents that call. No prompt/reply content guarantee. |
| R6 `dataset-read` | Source-derived policy-before-open ordering and pinned-byte correspondence, registered refusal codes, and live controls. |
| `sql-bounded-select` | Unsupported production route. The bounded mediator and RM1 cohort remain evaluation-harness evidence. |

All six supported routes also require `operation-catalog` for SGV901.
The catalog checks the finite pandas runtime surface and its source citations.
It is not containment for arbitrary effects of trusted application code.
Whole-system completeness remains not established.

## Application evidence

The grant-v3 cohort in
`eval/campaigns/remediation-v2/raw/pandas-grant-v3-full-v1/verification.json`
records 150/150 utility successes (A/B/C 50/50 each). Those graphs do not select
closed admission. Historical v19 and RM1 observations remain separate.

The later `raw/pandas-closed-v1/full-v1/verification.json` cohort runs under
closed admission with 14 declared trusted application nodes, three trusted
branches, and a separately admitted compute ToolNode. Dataset input uses
`dataset_read`; generated computation uses R3; output uses the mediator.
It records **45/50** utility successes and five `monthly_mean` refusals for
`output_data:nonfinite_float`. Its verifier reports `passed: false` with no
integrity issues. The disclosed v21 `json-null-v1` transport normalization is
part of this separate configuration. A safe refusal remains a utility failure.

## Admission and trust

Closed admission is opt-in through `SecurityConfig(closed_admission=True)`.
Supported tool/model descriptors and explicitly declared trusted application
nodes and branches are captured and rechecked; undeclared unsupported bodies
refuse. Trusted declarations do not contain or prove application Python.
ToolNodes cannot use a trusted-application declaration to bypass containment.

Under D11, developer graph code and framework machinery are trusted. Application
code must follow the deployment rule: route generated code to compute, tools
through supported tool dispatch, and publication through the output mediator.
Direct application effects and direct LLM calls are outside these route
guarantees. The admitted model-operation hook covers only calls through that
operation. Imported code, initialization and runtime/OS correctness retain
their stated premises.

## Evidence and exclusions

The JSON manifest lists the exact check ids and refusal codes. Source-derived
checks, Lean model proofs, structural regressions, registered-code checks and
recorded runtime observations are distinct evidence classes. Both Lean audits
are recomputed for the route gate. Runtime records bind source identities but
remain observations. Earlier failed audits and stale captures are retained as
history and do not replace current checks.

R3 covers generated computation inside the worker. Worker-private `/tmp` is
intentionally writable. Network confinement remains an OS/seccomp premise;
the application-level negative network probe remains absent. Dataset input
and output publication have their own routes. Trusted state, checkpoints and
approval machinery are premises, and the backend cohort does not establish
UI authentication, upload, rendering or session-storage guarantees.

Language computation and unrestricted-loop semantics are documented in
[Language computation](language-computation.md), including the distinction
between the straight-line type model and the control-flow effect proof.
