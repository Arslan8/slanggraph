# SLP-to-Cedar authorization model

## Unicode encoding regression

The production authorizers share `security/_cedar_strings.py`, which emits
Cedar string syntax rather than JSON Unicode escapes. It preserves Unicode
scalar values without normalization, escapes quotes, backslashes and controls,
and rejects surrogate code points. JSON transport remains separately encoded.
Both the object authorizer and `CedarPolicyBackend` use this encoder.

Run the production authorizer and replay its requests with the real Cedar CLI:

```sh
libs/prebuilt/.venv/bin/python proofs/slp-cedar/check_translation.py --output /tmp/slp-cedar-regression
```

The script requires all five identities (ASCII, accented, decomposed accent,
non-Latin and non-BMP) to receive the required grant and replay as `ALLOW`.
It saves actual policies, entity data, requests, engine version and source
hash. `tests/security/test_cedar_strings.py` additionally covers quoted and
backslash-containing identities and selectors, controls, distinct identities,
and denied requests, including all three `CedarPolicyBackend` modes.

## Retained counterexample and proof boundary

The fixed bug used `json.dumps(value, ensure_ascii=True)[1:-1]` as a Cedar
string body. For `josé` this emitted `jos\u00e9`, which Cedar CLI 4.13.0
rejected. This was an implementation bug that denied a valid user.
`counterexample-evidence.json` and `ProductionCapture.lean` retain the original
source hash and captured bad output. They are historical evidence, not a
claim about the repaired encoder. To reproduce the original failure, use
`reproduce_translation_failure.py` at commit
`e53773a4f58b532750649e073a29062635158226`.

`TranslationFailure.lean` proves the captured invalid escape is rejected by
an overapproximation of Cedar's string grammar; it also admits raw Unicode.
The Python capture, correspondence to Cedar and execution of the authorizer
are empirical evidence. Neither these lexical facts nor regression tests
prove universal correctness of the Python-to-Cedar translator.

## Conditional authorization model

This project proves soundness and completeness of a **formal model of the v2
authorization boundary**, after successful SLP expansion. It does **not** yet
prove soundness and completeness of the executable Python-to-Cedar translation.
The older `CedarPolicyBackend` in `security/cedar.py` is outside this project.

Run with the pinned Lean 4 toolchain (no third-party Lean dependencies):

```sh
cd proofs/slp-cedar
lake build
```

`SlpCedar.lean` prints the axioms of its main theorems. Successful verification
must contain no `sorryAx`; standard Lean logical axioms are expected.

## Statement

`slp_to_cedar_sound_complete` proves, for every finite list of expanded lines,
every policy predicate, every call gate, and every support predicate:

```text
authorize(gates, translatedQueries, support, candidates) = some(output)
  if and only if
ValidGrant(gates, sourceAuthorization, support, candidates, output)
```

`ValidGrant` requires all of the following:

- Successful call gates and operational prerequisites.
- Every `need` line is authorized.
- Output is exactly the authorized subsequence of input, preserving order and
  duplicates. Denied `want` lines are omitted.
- A nonempty candidate list has a nonempty output.
- Every retained line has enforcement support or an accepted waiver.

The forward implication is soundness; the reverse implication is completeness
**relative to these prerequisites**. An unavailable Cedar executable cannot be
complete relative to a specification that only asks whether a policy permits.
`no_amplification` separately proves every returned line was requested and allowed.

The source line decision is owner permission AND (principal OR share permission)
AND no matching mandatory forbid. The target model evaluates the owner,
envelope, and ephemeral candidate-plus-MAC queries separately. It uses Cedar's
[default-deny and forbid-overrides rules](https://docs.cedarpolicy.com/auth/authorization.html).
It abstracts successful individual policy evaluation as Boolean predicates;
it does not implement Cedar expressions or import Cedar's formal semantics.

## Correspondence to the implementation

All Python references below are in
[`object_policy.py`](../../libs/prebuilt/langgraph/prebuilt/security/object_policy.py).

| Lean definition | Python boundary |
| --- | --- |
| Input `List Line` | Result of `SecurityManifest.expand` |
| `query` | `_request`, before string/JSON encoding |
| `candidatePermit` | `_candidate_permit` |
| `targetAllows` | Owner, envelope, and MAC checks in `CedarObjectAuthorizer.authorize` |
| `collect` | The per-line loop's retain/skip/raise behavior |
| `callGate` | Owner call, MAC call, and empty-manifest principal call checks |
| `authorize` | Collection, nonempty-access check, and support/waiver checks |

Resource-free calls use the principal call gate alone, not a principal/share
union, matching the implementation. `operational` abstracts successful policy
validation, executable availability, and error-free subprocess evaluation for
the queries actually executed. Diagnostics and failure reasons are not modeled.

## Remaining proof obligations

The table is a manual correspondence, not a verified refinement relation.
Before calling this an end-to-end proof, establish:

1. **SLP expansion:** parsing, operation selection, bindings, normalization,
   labels, and `need`/`want` classification faithfully implement the intended
   source language. User-defined normalizers and label providers are trusted
   today; this proof starts after they finish successfully.
2. **Request/entity encoding:** abstract natural-number identities preserve the
   equality of actual principal, tool, class, action, and resource identities.
   Prove string escaping, schema construction, attributes, entity lookup, and
   JSON decoding preserve those values. Python hashes resource identities with
   SHA-256; unconditional injectivity over arbitrary resources cannot be assumed
   as a mathematical theorem. An end-to-end statement needs an explicit
   collision-free condition on the concrete candidate set or a different encoding.
3. **Cedar evaluation:** connect the Boolean predicates to actual policy semantics,
   including errors, entity attributes, missing entities, and policy partition
   restrictions. The principal/share disjunction assumes permit-only partitions;
   the MAC predicate assumes a forbid-only partition.
4. **Python refinement:** prove that Python control flow implements `authorize`,
   including errors and short-circuit behavior. Differential tests could catch
   drift but would not discharge this universal obligation.
5. **Runtime enforcement:** separately verify that execution respects the issued
   grant. This authorization theorem says nothing about trusted tool behavior,
   OS enforcement, resource races, or dispatch.

## Why query scope matters

`_candidate_permit` constrains principal and action but leaves resource
unconstrained. The final Lean example proves that such a permit also matches a
different resource with the same principal and action. Consequently, equivalence
of the generated policy to the SLP manifest for **all arbitrary requests** is
false. The proved statement is restricted to generated per-line queries and the
grant collector, as used by the authorizer. Do not reuse those ephemeral permits
as a standalone resource ceiling.
