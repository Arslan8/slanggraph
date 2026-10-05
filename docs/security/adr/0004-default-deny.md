# 0004: Undeclared tools default deny

Status: Accepted

## Context

Permissive inference would silently expose new tools and misclassified side
effects during migration or dynamic registration.

## Decision

Infer an undeclared tool as critical, irreversible `EXEC` and assign an operator
DAC that denies all callers while requiring its tool-specific scope.

## Consequences

New tools fail safely and require an explicit declaration or operator override.
Adoption requires inventory work instead of relying on optimistic inference.
