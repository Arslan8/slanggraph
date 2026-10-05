# 0002: Security blobs are private

Status: Accepted

## Context

Independent policy modules need per-principal and per-tool state without a
shared namespace that permits accidental or hostile cross-module mutation.

## Decision

Allocate one named `Slot` per module inside `Blobs`. Pass only that slot to
allocation, credential, transfer, and post hooks. Copy slots for delegation.
Never serialize blobs into graph state or expose them to the model.

## Consequences

Modules own their state and can evolve independently. Delegation cannot mutate
the parent's slots, and checkpoint data does not become a credential store.
