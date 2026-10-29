# Lean authority-preservation composition proof

This project proves the layered execution-boundary claim and the paper's
authority-preservation chain:

```text
E_{B,H}(c) ⊆ L_{B,H}(c) ⊆ G(c) ⊆ R(c)
```

`CompositionRoute.lean` contains the ordered lifecycle invariant.
`LayeredComposition.lean` proves that every invocation crosses a language
sandbox or an activated host sandbox and covers every selected resource
mediator. `AuthorityPreservation.lean` imports those results together with the
existing `SlpCedar` authorization proof and `GrantCoverage` obligation proof.

## Semantic model

`Permission` and `Effect` carry principal, tool, protected domain, object
selector, operation, and the exact recursive `GrantCoverage.Value` conditions.
`RequestedAuthority.lines` is the application request followed by its approved
runtime baseline. An explicit `SlpCedar.Line → GrantCoverage.Rule` translation
attaches selectors and conditions; because authorization retains the identical
line, filtering cannot widen any translated field.

`authorized_grant_subset_request` reuses `SlpCedar.no_amplification` to prove
`G ⊆ R`. `authorized_grant_policy_compliant` recovers the owner,
principal-or-share, and mandatory-forbid decisions for every granted line.
`accepted_inventory_covers_every_grant_rule` and
`accepted_inventory_covers_every_domain_complement` reuse the exact generated
inventory from `GrantCoverage`; a merely nonempty inventory is never accepted
as completeness evidence.

Each `LoweredPermission` has an actual `permits` predicate. `exact` requires
semantic equivalence with its source permission; `tightened` requires semantic
subset; `unsupported` cannot inhabit a valid plan. The host lowering roster,
full generated obligation inventory, activated inventory, source rules, and
grant digest are bound explicitly. `semantic_lowering_preserves_grant` proves
`L ⊆ G`; a classification label alone proves nothing.

`E` is ordinary membership in an execution trace and performs no authorization
check. `CompleteMediation` routes every occurrence through the selected
language/host boundary or the domain's selected mediator.
`ActivatedComponentSound` is the primitive local guarantee: only after the
exact grant/route binding and successful activation may the selected sandbox or
mediator guarantee that effects observed at that component are in `L`.
`effect_confinement_from_composition` derives `E ⊆ L`; it is not an assumption.
`complete_authority_preservation` combines all three inclusions.

`AuthorityPreservation.lean` adds 19 named theorems and five examples. These
counts apply only to that file; existing lifecycle, receipt, grant,
language-route, and audit counts are unchanged.

## Explicit component and refinement premises

- `SlpCedar.authorize` succeeds for the combined application request and
  approved runtime baseline. Its existing proof supplies authorization
  non-amplification and policy compliance.
- The line-to-rule translation faithfully represents the production normalized
  selector, operation, protected domain, principal/tool binding, and typed
  conditions. The Lean theorem is parametric in this translation; applying it
  to production requires this refinement fact.
- `GrantCoverage.obligationsAccept` succeeds, establishing exact full-record
  coverage of every grant rule and every default-deny domain complement.
- `ValidSemanticPlan` binds the plan to that grant digest and exact obligation
  inventory; every lowering carries its semantic equivalence/subset proof and
  every required obligation is activated.
- `LayeredComposition.dispatch = invoked` supplies the selected execution
  boundary, restricted host lowering where applicable, exact mediator roster,
  and confirmed activation observation. Applying this to production assumes
  the observation is authentic and fresh.
- `ActivatedComponentSound` states primitive language-sandbox, host-sandbox,
  and mediator soundness only for effects seen at the selected, activated
  component. `CompleteMediation` separately excludes direct bypass and routes
  mediator-owned domains through the matching selected mediator.
- Production entry points, serialization, compiler/loader behavior, and runtime
  traces faithfully refine these model values. This is a system-refinement
  premise, not a theorem about Python or the operating system.

## Constructive and negative cases

Constructive examples cover language isolation, host isolation, and host
isolation combined with semantic resource mediation.

| Negative case | Violated premise |
| --- | --- |
| Omitted selected mediator | `CompleteMediation` |
| Direct resource bypass | `CompleteMediation` |
| Missing host activation | `LayeredComposition.dispatch = invoked` |
| Unsupported lowering | `ValidSemanticPlan` and host `LoweringAccepted` |
| “Tightening” that permits an outside effect | `SemanticPreserving` |

## Paper-ready statement

For every modeled call whose application request and approved runtime baseline
are filtered by the verified SLP/Cedar authorization procedure, whose complete
grant-derived obligation inventory is bound to a semantically preserving and
fully activated enforcement plan, and whose authenticated execution route has
complete mediation with sound selected sandbox and mediator components, every
reachable protected-domain effect is permitted by the composed plan, every
plan-permitted effect is authorized by the grant, and every granted permission
was requested; formally, `E_{B,H}(c) ⊆ L_{B,H}(c) ⊆ G(c) ⊆ R(c)`. The theorem
assumes faithful line-to-rule and implementation refinement, authentic/fresh
activation evidence, complete mediation, and primitive component soundness; it
does not assume the global `E ⊆ L` conclusion, define reachability in terms of
authorization, prove policy intent, or verify Python, compiler, kernel, or
mediator implementations.

## Reproduce

With the pinned toolchain selected by `lean-toolchain`:

```sh
lake update
lake build
lake env leanchecker --fresh AuthorityPreservation
```

See `THEOREM_DEPENDENCIES.md` for recorded dependency output.
