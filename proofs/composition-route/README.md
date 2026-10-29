# Lean complete-mediation composition proof

This project proves a layered architectural claim about tool execution:

> Every physically invoked tool admitted by the model first crosses either its
> selected language sandbox or an activated host sandbox. Host admission accepts
> only a nonempty inventory of `exact` or `tightened` lowerings. Any selected
> semantic resource mediators must also have complete crossing evidence.

`CompositionRoute.lean` contains the original ordered lifecycle invariant.
`LayeredComposition.lean` gives the production-shaped composition: the language
or host sandbox is the execution boundary, while semantic resource mediators
supplement that boundary and may be combined with host confinement.

The lifecycle model provides closed route classification and an ordered
transition system. Admission binds a tool to one monitor class and opaque
monitor identity. The only transition that marks physical invocation requires
a matching monitor-crossing observation. The observation and the monotonic
`invoked` fact survive later refusal or cancellation.

The main layered results are:

- `invoked_implies_language_or_host_sandbox`
- `host_invocation_implies_restricted_lowering_and_activation`
- `invoked_implies_complete_resource_mediator_roster`
- `unsupported_host_lowering_cannot_invoke`
- `unclassified_cannot_invoke`

Parameterized useful-route theorems show that the language route and a combined
host-plus-resource route can execute; the result is not obtained by refusing
every tool. Negative theorems show that unsupported lowering refuses and that a
resource mediator cannot replace missing host activation.

## Scope

Monitor identifiers and crossing observations are opaque inputs. This proof
does not establish that any monitor implements its intended policy, makes a
correct decision, mediates effects inside the tool, or corresponds to the
Python runtime, interpreter, compiler, loader, kernel, or resource adapters.
Those remain separate source-placement, refinement, activation, and trusted
boundary obligations. Completeness of the host obligation inventory is also a
premise: the model proves that every supplied obligation has an accepted
lowering, not that production supplied every necessary obligation. In
particular, production may claim this theorem only
after showing that all physical tool entry points refine this transition system
and cannot invoke a raw callable or fallback route.

Build with the pinned toolchain:

```sh
/home/faculty/abk6349/.elan/bin/lake build
```
