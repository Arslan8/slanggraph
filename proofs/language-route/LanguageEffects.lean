/-!
Effect projection for control flow with arbitrary iteration counts.

The Python interpreter and projection remain trusted implementation contracts.
`Code` deliberately overapproximates data-dependent paths: choices are
nondeterministic and repetition is unrestricted. `Trace` includes finite
prefixes, including prefixes of nonterminating computations. No fuel or
iteration limit is imposed on the implementation or the theorem.
-/
namespace LanguageEffects

inductive Code where
  | pure
  | effect (name : String)
  | seq (first second : Code)
  | choice (left right : Code)
  | repeat (body : Code)
  deriving Repr

def check (registered : List String) : Code → Bool
  | .pure => true
  | .effect name => registered.contains name
  | .seq a b | .choice a b => check registered a && check registered b
  | .repeat body => check registered body

/-- All finite effect prefixes; the relation also permits extra paths, so the
result is independent of arithmetic, branch outcomes, and termination. -/
inductive Trace : Code → List String → Prop where
  | empty (code : Code) : Trace code []
  | effect (name : String) : Trace (.effect name) [name]
  | seqLeft {a b t} : Trace a t → Trace (.seq a b) t
  | seqBoth {a b t u} : Trace a t → Trace b u → Trace (.seq a b) (t ++ u)
  | choiceLeft {a b t} : Trace a t → Trace (.choice a b) t
  | choiceRight {a b t} : Trace b t → Trace (.choice a b) t
  | repeatStep {body t u} : Trace body t → Trace (.repeat body) u →
      Trace (.repeat body) (t ++ u)

theorem checked_trace_registered (registered : List String)
    {code : Code} {trace : List String} (execution : Trace code trace) :
    check registered code = true → ∀ name ∈ trace, name ∈ registered := by
  induction execution with
  | empty => simp
  | effect name =>
      intro accepted candidate member
      simp only [List.mem_singleton] at member
      subst candidate
      simpa [check] using accepted
  | seqLeft execution ih =>
      intro accepted name member
      have parts := Bool.and_eq_true_iff.mp accepted
      exact ih parts.1 name member
  | seqBoth left right ihLeft ihRight =>
      intro accepted name member
      have parts := Bool.and_eq_true_iff.mp accepted
      rcases List.mem_append.mp member with member | member
      · exact ihLeft parts.1 name member
      · exact ihRight parts.2 name member
  | choiceLeft execution ih =>
      intro accepted name member
      have parts := Bool.and_eq_true_iff.mp accepted
      exact ih parts.1 name member
  | choiceRight execution ih =>
      intro accepted name member
      have parts := Bool.and_eq_true_iff.mp accepted
      exact ih parts.2 name member
  | repeatStep first rest ihFirst ihRest =>
      intro accepted name member
      rcases List.mem_append.mp member with member | member
      · exact ihFirst accepted name member
      · exact ihRest accepted name member

example : check ["read_text"] (.repeat (.effect "open")) = false := by decide
example : check ["read_text"] (.repeat (.effect "read_text")) = true := by decide

end LanguageEffects
