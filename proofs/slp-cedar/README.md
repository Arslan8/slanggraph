# Argus SLP-to-Cedar authorization proof

This project connects Argus's modeled object-policy construction to Cedar's
official Lean semantics. It pins `cedar-policy/cedar-spec` commit
`8aa1a2a67f62d824abead35a9aef757ad3a35595` (tag `v4.13.0`), Cedar CLI
`4.13.0`, and `leanprover/lean4:v4.33.1`.

Run the complete drift gate from the repository root:

```sh
cd libs/prebuilt
make security-verify
```

Or run only this boundary:

```sh
libs/prebuilt/.venv/bin/python proofs/slp-cedar/check.py
```

The latter builds this proof and `proofs/composition-route`, runs the repaired
Unicode encoder regression through the real production authorizer,
and runs the real-Cedar differential cases. A Cedar CLI other than `4.13.0`, a
changed dependency pin, a failed encoder case, or a failed Lean theorem stops
the check.

For a from-clean-project validation report suitable for committing:

```sh
libs/prebuilt/.venv/bin/python proofs/slp-cedar/check.py \
  --clean-build --output proofs/slp-cedar/validation-report.json
```

## Proof boundary

`SlpCedar.lean` imports `Cedar.Thm.Authorization`; it does not copy a Cedar
interpreter. The following values use official Cedar definitions directly:

- `query` constructs a `Cedar.Spec.Request` with principal, action, resource,
  tool-context, and NEED/WANT identity.
- `Policies` contains official `Cedar.Spec.Policies` and an official
  `Cedar.Spec.Entities` store. Policy expressions may therefore inspect entity
  attributes and ancestor relationships using Cedar's evaluator.
- `candidatePermit` is the official policy AST corresponding to production
  `_candidate_permit`.
- `cedarAllows`, `noSatisfiedForbid`, and `cedarEvaluationErrors` project the
  official authorizer result, satisfied-forbid set, and erroring-policy set.

The production `CedarPolicySet` constructor is the supported-fragment gate:
owner, principal, and share partitions are permit-only; MAC is forbid-only.
The Lean semantic connection itself is robust to additional non-determining
policies, but no broader production syntax claim is made. Owner, envelope
(`principal ++ share`), and candidate-plus-MAC are separate authorization
queries, exactly as in `CedarObjectAuthorizer.authorize`.

The candidate policy intentionally leaves `resource` unconstrained. The theorem
`candidate_query_authorized_iff_no_forbid` applies only to the corresponding
generated request. The negative example at the end of `SlpCedar.lean` prevents
this from being misreported as equivalence on arbitrary unrelated requests.

## Main theorems

- `candidate_permits_generated_query`: the official evaluator satisfies the
  generated candidate policy for its generated request.
- `candidate_query_authorized_iff_no_forbid`: under official `isAuthorized`,
  candidate-plus-MAC allows exactly when no MAC forbid is satisfied. This uses
  Cedar's default denial, permit existence, and forbid-overrides behavior.
- `query_sound_complete`: Argus's three concrete Cedar decisions equal its
  intended owner AND envelope AND no-MAC-forbid line rule.
- `slp_to_cedar_sound_complete`: a successful modeled authorization returns
  exactly the requested authorized subsequence, rejects a denied mandatory
  line, filters denied optional lines, rejects empty retained access, and
  preserves the support gate.
- `argus_authorization_official_sound_complete`: instantiates owner-call,
  empty-manifest principal-call, and candidate-plus-MAC call gates with official
  Cedar decisions; only the separate operational prerequisite remains abstract.
- `no_amplification`: every returned line was both requested and authorized.

`AuthorityPreservation.complete_authority_preservation` now takes
`targetAllows`, not the declarative source predicate. Its `G ⊆ R` step calls
`slp_to_cedar_sound_complete`; the complete `E ⊆ L ⊆ G ⊆ R` chain
therefore depends on the official-semantics connection.

## Error boundary

Cedar evaluation errors are not silently equated with transport failures. In
the official semantics an erroring policy is recorded in `erroringPolicies` and
does not satisfy either effect; other policies can still determine ALLOW or
DENY. Argus separately fails closed on executable lookup, validation, timeout,
subprocess, request parsing, and malformed CLI output. Those conditions remain
in `Gates.operational`; successful CLI `DENY` is a semantic denial.

## Production translation and differential evidence

`check_translation.py` runs the former Unicode counterexample as a positive
regression. The shared `_cedar_strings.cedar_string_body` encoder emits Unicode
scalars literally, preserves identity without normalization, escapes quotes,
backslashes, and Cedar-supported controls, and rejects surrogate code points.
It is used by both production Cedar authorizers. The original failing capture
remains in `counterexample-evidence.json` as historical evidence.

The differential tests use `CedarObjectAuthorizer`'s actual manifest expansion,
schema, entity, request, policy, serialization, subprocess, and grant/refusal
paths. They cover ALLOW/DENY, conflicting permit/forbid, mandatory refusal,
optional filtering, resource mismatch, tool context, role attributes, Unicode
and combining identities, quotes, backslashes, and supported escapes. This is
implementation evidence, not a proof of Python refinement.

`Differential.lean` is an executable oracle over the official
`Cedar.Spec.isAuthorized` evaluator. `differential.py` runs the same seven named
policy/query/entity scenarios through that oracle and through the production
`CedarObjectAuthorizer`, comparing every actually executed owner, envelope, and
MAC query plus the resulting grant or refusal. Six cases require exact
agreement. The evaluation-error case requires the documented boundary: Lean
reports ALLOW with an erroring policy, while Cedar CLI does not return a bare
decision and Argus refuses operationally.

## Remaining assumptions

Lean does not verify Python parsing/serialization or the Rust CLI. The drift
gate and differential cases cover those executable boundaries. SLP expansion,
normalizers, SHA-256 resource IDs (including collision freedom on the concrete
candidate set), production schema validation, subprocess integrity, grant
activation, mediator correctness, and runtime enforcement retain their existing
contracts. The proof begins after successful expansion and operational setup.
No Lean checker executes on the authorization invocation path.
