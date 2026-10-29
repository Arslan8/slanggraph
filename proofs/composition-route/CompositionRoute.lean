import Std

/-!
# Complete-mediation composition model

This file proves a deliberately narrow architectural property: every physical
tool invocation admitted by this transition system has first crossed either its
selected language sandbox or its selected resource mediator. An unclassified
tool cannot be invoked.

The model treats monitor identifiers and crossing observations as opaque. It
does not claim that a monitor implements the intended policy, makes a correct
decision, mediates every effect inside a tool, or corresponds to a particular
Python, compiler, interpreter, or operating-system execution. Those are
separate refinement and trusted-boundary obligations.
-/
namespace CompositionRoute

/-- The two distributed reference-monitor classes in the composition. -/
inductive Monitor where
  | languageSandbox
  | resourceMediator
  deriving DecidableEq, Repr

/-- A closed route classification, carrying the selected monitor identity. -/
inductive Route where
  | languageSandbox (sandboxId : String)
  | resourceMediator (mediatorId : String)
  deriving DecidableEq, Repr

def Route.monitor : Route → Monitor
  | .languageSandbox _ => .languageSandbox
  | .resourceMediator _ => .resourceMediator

def Route.monitorId : Route → String
  | .languageSandbox sandboxId => sandboxId
  | .resourceMediator mediatorId => mediatorId

/-- `none` means admission could not establish a monitored execution route. -/
structure Candidate where
  toolId : String
  route : Option Route
  deriving DecidableEq, Repr

inductive Phase where
  | proposed
  | admitted
  | monitorCrossed
  | invoking
  | finished
  | refused
  deriving DecidableEq, Repr

/--
`invoked` is monotonic. Refusal after invocation therefore cannot rewrite
history and make an already-started physical call appear not to have happened.
-/
structure State where
  candidate : Candidate
  phase : Phase
  crossed : Option (Monitor × String)
  invoked : Bool
  deriving DecidableEq, Repr

inductive Event where
  | admit (observed : Route)
  | cross (monitor : Monitor) (monitorId : String)
  | invoke
  | finish
  | cancel
  deriving DecidableEq, Repr

def initial (candidate : Candidate) : State :=
  { candidate, phase := .proposed, crossed := none, invoked := false }

def refuse (state : State) : State := { state with phase := .refused }

/--
The only transition that starts physical execution is `invoke`. It requires the
route chosen at admission and the preceding monitor-crossing observation to
agree in both monitor class and opaque monitor identity.
-/
def step (state : State) : Event → State
  | .admit observed =>
      match state.phase, state.candidate.route with
      | .proposed, some expected =>
          if observed = expected then { state with phase := .admitted }
          else refuse state
      | _, _ => refuse state
  | .cross monitor monitorId =>
      match state.phase, state.candidate.route with
      | .admitted, some expected =>
          if monitor = expected.monitor ∧ monitorId = expected.monitorId then
            { state with
              phase := .monitorCrossed
              crossed := some (monitor, monitorId) }
          else refuse state
      | _, _ => refuse state
  | .invoke =>
      match state.phase, state.candidate.route, state.crossed with
      | .monitorCrossed, some expected, some observed =>
          if observed = (expected.monitor, expected.monitorId) then
            { state with phase := .invoking, invoked := true }
          else refuse state
      | _, _, _ => refuse state
  | .finish =>
      if state.phase = .invoking then { state with phase := .finished }
      else refuse state
  | .cancel => refuse state

def runFrom (state : State) : List Event → State
  | [] => state
  | event :: events => runFrom (step state event) events

def run (candidate : Candidate) (events : List Event) : State :=
  runFrom (initial candidate) events

/-- The selected route has a matching crossing observation in this state. -/
def SelectedMonitorCrossed (state : State) : Prop :=
  ∃ route, state.candidate.route = some route ∧
    state.crossed = some (route.monitor, route.monitorId)

def LanguageSandboxMediated (state : State) : Prop :=
  ∃ sandboxId, state.candidate.route = some (.languageSandbox sandboxId) ∧
    state.crossed = some (.languageSandbox, sandboxId)

def ResourceMediatorMediated (state : State) : Prop :=
  ∃ mediatorId, state.candidate.route = some (.resourceMediator mediatorId) ∧
    state.crossed = some (.resourceMediator, mediatorId)

/-- The invariant whose preservation gives the composition theorem. -/
def CompleteMediationInvariant (state : State) : Prop :=
  state.invoked = true → SelectedMonitorCrossed state

theorem initial_complete_mediation (candidate : Candidate) :
    CompleteMediationInvariant (initial candidate) := by
  simp [CompleteMediationInvariant, initial]

theorem step_preserves_candidate (state : State) (event : Event) :
    (step state event).candidate = state.candidate := by
  cases state with
  | mk candidate phase crossed invoked =>
    cases candidate with
    | mk toolId route =>
      cases event <;> cases phase <;> cases route <;> cases crossed <;>
        simp [step, refuse] <;> split <;> rfl

theorem step_preserves_complete_mediation (state : State) (event : Event)
    (invariant : CompleteMediationInvariant state) :
    CompleteMediationInvariant (step state event) := by
  cases state with
  | mk candidate phase crossed wasInvoked =>
    cases candidate with
    | mk toolId route =>
      cases event <;> cases phase <;> cases route <;> cases crossed <;>
        simp_all [CompleteMediationInvariant, SelectedMonitorCrossed, step, refuse] <;>
        split <;> simp_all

theorem runFrom_preserves_complete_mediation (state : State) (events : List Event)
    (invariant : CompleteMediationInvariant state) :
    CompleteMediationInvariant (runFrom state events) := by
  induction events generalizing state with
  | nil => exact invariant
  | cons event events ih =>
      exact ih (step state event) (step_preserves_complete_mediation state event invariant)

theorem runFrom_preserves_candidate (state : State) (events : List Event) :
    (runFrom state events).candidate = state.candidate := by
  induction events generalizing state with
  | nil => rfl
  | cons event events ih =>
      calc
        (runFrom state (event :: events)).candidate =
            (step state event).candidate := ih (step state event)
        _ = state.candidate := step_preserves_candidate state event

theorem run_preserves_candidate (candidate : Candidate) (events : List Event) :
    (run candidate events).candidate = candidate := by
  exact runFrom_preserves_candidate (initial candidate) events

/--
Core invariant: a physical invocation reachable from the initial state has a
matching crossing observation for the route selected at admission.
-/
theorem invoked_implies_selected_monitor_crossed
    (candidate : Candidate) (events : List Event)
    (invoked : (run candidate events).invoked = true) :
    SelectedMonitorCrossed (run candidate events) :=
  runFrom_preserves_complete_mediation (initial candidate) events
    (initial_complete_mediation candidate) invoked

/--
Composition completeness: every physical tool invocation crosses at least one
of the two distributed reference-monitor classes.
-/
theorem invoked_implies_language_or_resource_mediation
    (candidate : Candidate) (events : List Event)
    (invoked : (run candidate events).invoked = true) :
    LanguageSandboxMediated (run candidate events) ∨
      ResourceMediatorMediated (run candidate events) := by
  obtain ⟨route, selected, crossed⟩ :=
    invoked_implies_selected_monitor_crossed candidate events invoked
  cases route with
  | languageSandbox sandboxId =>
      left
      exact ⟨sandboxId, selected, crossed⟩
  | resourceMediator mediatorId =>
      right
      exact ⟨mediatorId, selected, crossed⟩

/-- The contrapositive form: without either monitor, physical invocation fails. -/
theorem unmediated_cannot_invoke (candidate : Candidate) (events : List Event)
    (unmediated :
      ¬LanguageSandboxMediated (run candidate events) ∧
      ¬ResourceMediatorMediated (run candidate events)) :
    (run candidate events).invoked = false := by
  cases invokedEq : (run candidate events).invoked with
  | false => rfl
  | true =>
      rcases invoked_implies_language_or_resource_mediation candidate events invokedEq with
        language | resource
      · exact False.elim (unmediated.1 language)
      · exact False.elim (unmediated.2 resource)

/-- An unclassified tool remains non-executable for every possible event list. -/
theorem unclassified_cannot_invoke (candidate : Candidate) (events : List Event)
    (unclassified : candidate.route = none) :
    (run candidate events).invoked = false := by
  apply unmediated_cannot_invoke
  constructor
  · rintro ⟨sandboxId, selected, _⟩
    rw [run_preserves_candidate] at selected
    rw [unclassified] at selected
    contradiction
  · rintro ⟨mediatorId, selected, _⟩
    rw [run_preserves_candidate] at selected
    rw [unclassified] at selected
    contradiction

def successfulEvents (route : Route) : List Event :=
  [.admit route, .cross route.monitor route.monitorId, .invoke, .finish]

/-- The theorem is useful, rather than a deny-all statement, for every sandbox. -/
theorem useful_language_route_invokes (toolId sandboxId : String) :
    (run ⟨toolId, some (.languageSandbox sandboxId)⟩
      (successfulEvents (.languageSandbox sandboxId))).invoked = true := by
  simp [run, runFrom, successfulEvents, step, initial, Route.monitor, Route.monitorId]

/-- The theorem is useful, rather than a deny-all statement, for every mediator. -/
theorem useful_resource_route_invokes (toolId mediatorId : String) :
    (run ⟨toolId, some (.resourceMediator mediatorId)⟩
      (successfulEvents (.resourceMediator mediatorId))).invoked = true := by
  simp [run, runFrom, successfulEvents, step, initial, Route.monitor, Route.monitorId]

theorem wrong_monitor_cannot_invoke (toolId sandboxId mediatorId : String) :
    (run ⟨toolId, some (.languageSandbox sandboxId)⟩
      [.admit (.languageSandbox sandboxId),
       .cross .resourceMediator mediatorId, .invoke]).invoked = false := by
  simp [run, runFrom, step, initial, Route.monitor, Route.monitorId, refuse]

theorem invoke_before_crossing_refuses (candidate : Candidate) :
    (run candidate [.invoke]).invoked = false ∧
      (run candidate [.invoke]).phase = .refused := by
  cases candidate with
  | mk toolId route =>
    cases route <;> simp [run, runFrom, step, initial, refuse]

end CompositionRoute

#print axioms CompositionRoute.invoked_implies_selected_monitor_crossed
#print axioms CompositionRoute.invoked_implies_language_or_resource_mediation
#print axioms CompositionRoute.unmediated_cannot_invoke
#print axioms CompositionRoute.unclassified_cannot_invoke
#print axioms CompositionRoute.useful_language_route_invokes
#print axioms CompositionRoute.useful_resource_route_invokes
