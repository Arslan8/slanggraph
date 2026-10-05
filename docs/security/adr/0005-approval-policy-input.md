# 0005: Human approval is policy input

Status: Accepted

## Context

Treating approval as an authorization override would let a user bypass DAC,
capability limits, or another module. Tool arguments in approval payloads can
also disclose secrets through checkpoint or user-interface channels.

## Decision

Send a redacted `EscalationRequest` through `interrupt()`. Require a checkpointer
for escalating modules. After resume, rerun normalization, DAC, permission, and
`resume_permission`; rejection is a mandatory denial.

## Consequences

Approval can add a restrictive fact but never grant missing authority. Resume
is replay-safe, and approval payloads contain identifiers and reasons only.
