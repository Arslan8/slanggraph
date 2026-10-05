# 0006: Policy failures and timeouts fail closed

Status: Accepted

## Context

Policy code is extensible and can raise, hang, return malformed data, or fail to
normalize hostile resource identifiers.

## Decision

Run non-framework policy hooks with a bounded timeout. Convert timeout,
exception, malformed decision, and normalization failure into `DENY`. Keep the
framework-owned capability fast path in-process.

## Consequences

Policy availability can reduce tool availability but cannot silently reduce
enforcement. Operators need timeout, failure, and denial telemetry.
