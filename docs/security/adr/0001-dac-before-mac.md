# 0001: DAC runs before mandatory policy

Status: Accepted

## Context

Tool authors and operators express different kinds of authority. A module must
not be able to grant an operation the author or operator DAC rejected.

## Decision

Run framework-owned DAC first and again after every prepare transform. Only an
`ALLOW` proceeds into the mandatory capability and configured module stack.
Module composition is restrictive; no later allow reverses a denial.

## Consequences

Policy modules can narrow calls or object, but cannot expand author authority.
Argument transforms pay a second normalization and DAC cost.
