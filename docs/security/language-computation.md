# Computation in the language sandbox

The language route separates ordinary computation from authority. A loop does
not acquire permissions: every resource operation still invokes a captured,
registered terminal under the current invocation grant. The original Python
tool body is never executed.

## Supported computation

- Input-dependent `while` loops, with `else`, `break`, and `continue`.
- `for` over strings and `range(start, stop, step)`, including negative steps.
  The range arguments and iterable are evaluated once. The interpreter retains
  its own iterator state, separate from assignments to the loop target.
- Nested loops, local assignments, augmented assignments, and returns.
- Scalar arithmetic (`+`, `-`, `*`, `/`, `//`, `%`), unary signs, ordering,
  string equality/inequality, and string indexing.
- Explicit scalar conversions (`int`, `float`, `str`, `bool`) and string `len`.
  These are interpreter operations over exact inert types, not dynamically
  resolved Python callables. Invalid operands refuse without invoking user
  object protocols.

There is **no iteration cap or requirement to prove termination**. The finite
syntax-checking budget limits admission work, not the number of runtime loop
iterations. Denial of service is outside the current security guarantee.
A watchdog could be added as a separate availability policy; it is not required
for authority preservation and is not added here.

Explicit asynchronous cancellation sets a per-invocation signal checked between
interpreter steps. Cancellation waits for an active terminal to finish before
releasing the resource scope, then prevents further iterations or result release.
It cannot preempt a blocked terminal. This is lifecycle handling, not a runtime
deadline or a denial-of-service defense.

## Admission and remaining boundaries

The type checker validates all instructions, including unreachable branches.
Assignments to locals present at a loop head must preserve their admitted
types. A variable first assigned inside a possibly empty loop is not assumed
bound afterward. The manifest analysis forgets loop-written resource selectors
before inspecting effects; a first-iteration value cannot justify later access.
Unknown selectors remain refused, and terminals independently enforce the grant.

Invocation arguments still use the existing string contract. This change does
not add arbitrary imports, reflection, attributes, callbacks, recursive helper
functions, general container operations, or native Python libraries. Those
remain separate language extensions or use the host route. Supporting a useful
loop is not evidence that a particular ACE tool or application has been ported.

## Proof and executable evidence

`proofs/language-route/LanguageRoute.lean` retains the original straight-line
value/type model. `LanguageEffects.lean` adds a control-flow effect model that
overapproximates branch choices, returns, and arbitrary repetition. Its theorem
states that every effect in every finite trace prefix of an accepted projection
names a registered terminal. It applies to finite prefixes of nonterminating
computations as well as terminating programs, without a loop bound.

The Python-to-model projection and interpreter fidelity remain trusted
implementation contracts. Generated `EffectControls.lean` checks correspondence
for concrete lowered programs and rejects an unregistered call inside a loop;
the exporter refuses unknown instructions. The fresh audit builds both models,
replays their compiled declarations with `leanchecker`, and checks theorem
axioms. This is not a proof of Python, terminal implementations, or all scalar
arithmetic semantics.

The executable regressions cover more than 10,000 loop iterations, nested
loops, range iterator independence, zero steps, `break`/`continue`/`else`,
per-iteration terminal checks, denied resources, selector mutation, source
identity, foreign objects, and cancellation. An integration test executes a
file-record counter through `StateGraph` and `ToolNode` on the language route.
That test uses a fixture authorization executable and is a regression test,
not a replacement for the paper's real-policy security campaign or application
performance measurements.

Run from `libs/prebuilt`:

```sh
uv run pytest tests/security/test_language_loops.py tests/security/test_language_sandbox.py tests/security/test_language_verification.py tests/security/test_language_route_verification.py tests/security/test_manifest_admission.py tests/security/test_manifest_consistency.py
uv run python ../../proofs/language-route/check.py --lake /path/to/lake --output /new/evidence/directory
```
