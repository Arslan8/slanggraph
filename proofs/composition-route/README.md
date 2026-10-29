# Lean complete-mediation composition proof

This project proves a narrow architectural claim about tool execution:

> Every physically invoked tool admitted by the model first crosses either its
> selected language sandbox or its selected resource mediator. If admission
> cannot classify a tool into one of those routes, the tool cannot execute.

`CompositionRoute.lean` models closed route classification and an ordered
transition system. Admission binds a tool to one monitor class and opaque
monitor identity. The only transition that marks physical invocation requires
a matching monitor-crossing observation. The observation and the monotonic
`invoked` fact survive later refusal or cancellation.

The main results are:

- `invoked_implies_selected_monitor_crossed`
- `invoked_implies_language_or_resource_mediation`
- `unmediated_cannot_invoke`
- `unclassified_cannot_invoke`

Parameterized useful-route theorems show that both monitor classes can execute;
the result is not obtained by refusing every tool. Negative theorems cover the
wrong monitor and invocation before crossing.

## Scope

Monitor identifiers and crossing observations are opaque inputs. This proof
does not establish that either monitor implements its intended policy, makes a
correct decision, mediates effects inside the tool, or corresponds to the
Python runtime, interpreter, compiler, loader, kernel, or resource adapters.
Those remain separate source-placement, refinement, activation, and trusted
boundary obligations. In particular, production may claim this theorem only
after showing that all physical tool entry points refine this transition system
and cannot invoke a raw callable or fallback route.

Build with the pinned toolchain:

```sh
/home/faculty/abk6349/.elan/bin/lake build
```
