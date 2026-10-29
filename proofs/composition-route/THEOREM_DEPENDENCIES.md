# Authority-preservation theorem dependencies

Recorded with Lean 4.34.1 using:

```sh
lake build AuthorityPreservation
```

The `#print axioms` commands in `AuthorityPreservation.lean` report:

```text
authorized_grant_subset_request: [propext, Quot.sound]
authorized_call_gate: [propext, Quot.sound]
authorized_grant_policy_compliant: [propext, Quot.sound]
semantic_lowering_preserves_grant: [propext]
exact_semantic_entry_preserves: [propext, Quot.sound]
tightened_semantic_entry_preserves: [propext]
effect_confinement_from_composition: [propext]
complete_authority_preservation: [propext, Quot.sound]
complete_chain_effect: [propext, Quot.sound]
direct_resource_bypass_violates_complete_mediation: [propext]
omitted_mediator_violates_complete_mediation: [propext]
purported_tightening_that_broadens_is_invalid: [propext]
```

These are Lean standard axioms. The source contains no `sorry`, `admit`,
`unsafe` declaration, or custom security axiom. `leanchecker --fresh` is Lean's
own kernel replay, not an independent verifier.
