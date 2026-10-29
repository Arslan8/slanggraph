import CompositionRoute

/-!
# Layered complete-mediation composition

This model extends the lifecycle invariant in `CompositionRoute` to the actual
layered execution architecture. Every admitted physical tool invocation has an
execution boundary: either a language sandbox or an activated host sandbox. A
host sandbox is admissible only when its nonempty obligation inventory lowers
entirely as `exact` or `tightened`. A route may additionally select semantic
resource mediators; their complete identity roster must be observed as well.

The proof is about route coverage, restricted lowering, activation ordering as
represented by supplied evidence, and exact mediator-roster coverage. It does
not prove that any sandbox or mediator correctly implements its policy, that an
obligation inventory is complete, or that production code faithfully projects
and orders these observations.
-/
namespace LayeredComposition

inductive Support where
  | exact
  | tightened
  | unsupported
  deriving DecidableEq, Repr

structure Lowering where
  obligationId : String
  support : Support
  deriving DecidableEq, Repr

structure HostPlan where
  sandboxId : String
  lowerings : List Lowering
  deriving DecidableEq, Repr

def Lowering.accepted (lowering : Lowering) : Bool :=
  decide (lowering.obligationId ≠ "") &&
    decide (lowering.support = .exact ∨ lowering.support = .tightened)

/-- The restricted host-lowering set, with no empty or missing inventory. -/
def HostPlan.loweringAccepted (plan : HostPlan) : Bool :=
  decide (plan.sandboxId ≠ "") &&
    decide (plan.lowerings ≠ []) &&
    plan.lowerings.all Lowering.accepted

def HostPlan.LoweringAccepted (plan : HostPlan) : Prop :=
  plan.loweringAccepted = true

inductive ExecutionBoundary where
  | languageSandbox (sandboxId : String)
  | hostSandbox (plan : HostPlan)
  deriving DecidableEq, Repr

/--
Resource mediators supplement an execution boundary. They do not replace the
language/host boundary and need not be present for a resource-free tool.
-/
structure Route where
  boundary : ExecutionBoundary
  resourceMediators : List String := []
  deriving DecidableEq, Repr

def ExecutionBoundary.wellFormed : ExecutionBoundary → Bool
  | .languageSandbox sandboxId => decide (sandboxId ≠ "")
  | .hostSandbox plan => plan.loweringAccepted

def ExecutionBoundary.WellFormed (boundary : ExecutionBoundary) : Prop :=
  boundary.wellFormed = true

def Route.WellFormed (route : Route) : Prop :=
  route.boundary.WellFormed ∧
    route.resourceMediators.Nodup ∧
    route.resourceMediators.all (fun mediatorId => decide (mediatorId ≠ "")) = true

structure Candidate where
  toolId : String
  route : Option Route
  deriving DecidableEq, Repr

/-- Opaque observations supplied by the production bridge. -/
inductive BoundaryEvidence where
  | languageSandbox (sandboxId : String)
  | hostSandbox
      (sandboxId : String)
      (restrictedLowering : Bool)
      (activationConfirmed : Bool)
  deriving DecidableEq, Repr

structure Evidence where
  observedRoute : Route
  boundary : BoundaryEvidence
  crossedResourceMediators : List String := []
  deriving DecidableEq, Repr

/-- Exact boundary identity plus the host's restricted-lowering/activation facts. -/
def boundaryCovered : ExecutionBoundary → BoundaryEvidence → Bool
  | .languageSandbox expected, .languageSandbox observed => decide (observed = expected)
  | .hostSandbox plan, .hostSandbox observed restricted activated =>
      decide (observed = plan.sandboxId) && plan.loweringAccepted &&
        restricted && activated
  | _, _ => false

def BoundaryCovered (boundary : ExecutionBoundary) (evidence : BoundaryEvidence) : Prop :=
  boundaryCovered boundary evidence = true

/-- The complete finite certificate checked before physical invocation. -/
def ValidComposition (candidate : Candidate) (evidence : Evidence) : Prop :=
  candidate.toolId ≠ "" ∧
    candidate.route = some evidence.observedRoute ∧
    evidence.observedRoute.WellFormed ∧
    BoundaryCovered evidence.observedRoute.boundary evidence.boundary ∧
    evidence.crossedResourceMediators =
      evidence.observedRoute.resourceMediators

instance (candidate : Candidate) (evidence : Evidence) :
    Decidable (ValidComposition candidate evidence) := by
  unfold ValidComposition Route.WellFormed ExecutionBoundary.WellFormed
    BoundaryCovered
  infer_instance

def compositionAccept (candidate : Candidate) (evidence : Evidence) : Bool :=
  decide (ValidComposition candidate evidence)

inductive DispatchOutcome where
  | refused
  | invoked
  deriving DecidableEq, Repr

/-- Physical invocation is produced only after the complete certificate passes. -/
def dispatch (candidate : Candidate) (evidence : Evidence) : DispatchOutcome :=
  if compositionAccept candidate evidence then .invoked else .refused

theorem compositionAccept_iff (candidate : Candidate) (evidence : Evidence) :
    compositionAccept candidate evidence = true ↔
      ValidComposition candidate evidence := by
  simp [compositionAccept]

theorem dispatch_invoked_iff (candidate : Candidate) (evidence : Evidence) :
    dispatch candidate evidence = .invoked ↔
      ValidComposition candidate evidence := by
  simp [dispatch, compositionAccept]

def LanguageSandboxCovered (candidate : Candidate) (evidence : Evidence) : Prop :=
  ∃ route sandboxId,
    candidate.route = some route ∧
    route.boundary = .languageSandbox sandboxId ∧
    BoundaryCovered route.boundary evidence.boundary

def HostSandboxCovered (candidate : Candidate) (evidence : Evidence) : Prop :=
  ∃ route plan,
    candidate.route = some route ∧
    route.boundary = .hostSandbox plan ∧
    BoundaryCovered route.boundary evidence.boundary

/--
Primary layered-composition theorem: every physical invocation has crossed one
of the two execution boundaries. Resource mediators cannot substitute for it.
-/
theorem invoked_implies_language_or_host_sandbox
    (candidate : Candidate) (evidence : Evidence)
    (invoked : dispatch candidate evidence = .invoked) :
    LanguageSandboxCovered candidate evidence ∨
      HostSandboxCovered candidate evidence := by
  have valid := (dispatch_invoked_iff candidate evidence).mp invoked
  rcases valid with ⟨_, selected, _, covered, _⟩
  cases h : evidence.observedRoute.boundary with
  | languageSandbox sandboxId =>
      left
      exact ⟨evidence.observedRoute, sandboxId, selected, h, covered⟩
  | hostSandbox plan =>
      right
      exact ⟨evidence.observedRoute, plan, selected, h, covered⟩

/-- Host execution necessarily carries accepted lowering and confirmed activation. -/
theorem host_invocation_implies_restricted_lowering_and_activation
    (candidate : Candidate) (evidence : Evidence)
    (covered : HostSandboxCovered candidate evidence) :
    ∃ route plan sandboxId,
      candidate.route = some route ∧
      route.boundary = .hostSandbox plan ∧
      plan.LoweringAccepted ∧
      evidence.boundary = .hostSandbox sandboxId true true ∧
      sandboxId = plan.sandboxId := by
  rcases covered with ⟨route, plan, selected, boundary, observed⟩
  cases hEvidence : evidence.boundary with
  | languageSandbox sandboxId =>
      simp [boundary, hEvidence, BoundaryCovered, boundaryCovered] at observed
  | hostSandbox sandboxId restricted activated =>
      have facts : ((sandboxId = plan.sandboxId ∧ plan.LoweringAccepted) ∧
          restricted = true) ∧ activated = true := by
        simpa [boundary, hEvidence, BoundaryCovered, boundaryCovered,
          HostPlan.LoweringAccepted] using observed
      rcases facts with ⟨⟨⟨identity, lowering⟩, restrictedTrue⟩, activatedTrue⟩
      subst restricted
      subst activated
      exact ⟨route, plan, sandboxId, selected, boundary, lowering, rfl, identity⟩

/-- Every route-selected semantic mediator is present in the crossing evidence. -/
theorem invoked_implies_complete_resource_mediator_roster
    (candidate : Candidate) (evidence : Evidence)
    (invoked : dispatch candidate evidence = .invoked) :
    ∃ route,
      candidate.route = some route ∧
      evidence.crossedResourceMediators = route.resourceMediators ∧
      ∀ mediatorId ∈ route.resourceMediators,
        mediatorId ∈ evidence.crossedResourceMediators := by
  have valid := (dispatch_invoked_iff candidate evidence).mp invoked
  rcases valid with ⟨_, selected, _, _, mediators⟩
  refine ⟨evidence.observedRoute, selected, mediators, ?_⟩
  intro mediatorId member
  simpa [mediators] using member

/--
The complete layered result: every invocation has a language/host execution
boundary and exact coverage of every semantic mediator selected by that route.
-/
theorem invoked_implies_complete_layered_mediation
    (candidate : Candidate) (evidence : Evidence)
    (invoked : dispatch candidate evidence = .invoked) :
    (LanguageSandboxCovered candidate evidence ∨
      HostSandboxCovered candidate evidence) ∧
    ∃ route,
      candidate.route = some route ∧
      evidence.crossedResourceMediators = route.resourceMediators ∧
      ∀ mediatorId ∈ route.resourceMediators,
        mediatorId ∈ evidence.crossedResourceMediators := by
  exact ⟨invoked_implies_language_or_host_sandbox candidate evidence invoked,
    invoked_implies_complete_resource_mediator_roster candidate evidence invoked⟩

/-- An unclassified route cannot cause physical invocation. -/
theorem unclassified_cannot_invoke (candidate : Candidate) (evidence : Evidence)
    (unclassified : candidate.route = none) :
    dispatch candidate evidence = .refused := by
  simp [dispatch, compositionAccept, ValidComposition, unclassified]

/-- Unsupported host lowering cannot be repaired by claimed activation evidence. -/
theorem unsupported_host_lowering_cannot_invoke
    (toolId : String) (route : Route) (plan : HostPlan) (evidence : Evidence)
    (boundary : route.boundary = .hostSandbox plan)
    (unsupported : ¬plan.LoweringAccepted) :
    dispatch ⟨toolId, some route⟩ evidence = .refused := by
  cases outcome : dispatch ⟨toolId, some route⟩ evidence with
  | refused => rfl
  | invoked =>
      have valid := (dispatch_invoked_iff ⟨toolId, some route⟩ evidence).mp outcome
      rcases valid with ⟨_, selected, wellFormed, _, _⟩
      have sameRoute : evidence.observedRoute = route := by
        simpa using Option.some.inj selected.symm
      rw [sameRoute] at wellFormed
      exact False.elim (unsupported (by simpa [Route.WellFormed, boundary,
        ExecutionBoundary.WellFormed, ExecutionBoundary.wellFormed,
        HostPlan.LoweringAccepted] using wellFormed.1))

def exactLowering (obligationId : String) : Lowering :=
  ⟨obligationId, .exact⟩

def tightenedLowering (obligationId : String) : Lowering :=
  ⟨obligationId, .tightened⟩

/-- Constructive language-sandbox execution, showing the theorem is not deny-all. -/
theorem useful_language_route_invokes (toolId sandboxId : String)
    (toolPresent : toolId ≠ "") (sandboxPresent : sandboxId ≠ "") :
    let route : Route := ⟨.languageSandbox sandboxId, []⟩
    let evidence : Evidence := ⟨route, .languageSandbox sandboxId, []⟩
    dispatch ⟨toolId, some route⟩ evidence = .invoked := by
  simp [dispatch, compositionAccept, ValidComposition, Route.WellFormed,
    ExecutionBoundary.WellFormed, ExecutionBoundary.wellFormed,
    BoundaryCovered, boundaryCovered, toolPresent, sandboxPresent]

/--
Constructive host-plus-resource route. Exact and tightened obligations are both
accepted, activation is confirmed, and semantic mediation composes with rather
than replaces the host sandbox.
-/
theorem useful_host_and_resource_route_invokes
    (toolId sandboxId exactId tightenedId mediatorId : String)
    (toolPresent : toolId ≠ "")
    (sandboxPresent : sandboxId ≠ "")
    (exactPresent : exactId ≠ "")
    (tightenedPresent : tightenedId ≠ "")
    (mediatorPresent : mediatorId ≠ "") :
    let plan : HostPlan :=
      ⟨sandboxId, [exactLowering exactId, tightenedLowering tightenedId]⟩
    let route : Route := ⟨.hostSandbox plan, [mediatorId]⟩
    let evidence : Evidence :=
      ⟨route, .hostSandbox sandboxId true true, [mediatorId]⟩
    dispatch ⟨toolId, some route⟩ evidence = .invoked := by
  simp [dispatch, compositionAccept, ValidComposition, Route.WellFormed,
    ExecutionBoundary.WellFormed, ExecutionBoundary.wellFormed,
    HostPlan.loweringAccepted, Lowering.accepted, BoundaryCovered,
    boundaryCovered,
    exactLowering, tightenedLowering, toolPresent, sandboxPresent,
    exactPresent, tightenedPresent, mediatorPresent]

/-- A mediator observation alone cannot stand in for a missing host activation. -/
theorem resource_mediator_cannot_replace_host_sandbox
    (toolId sandboxId obligationId mediatorId : String) :
    let plan : HostPlan := ⟨sandboxId, [exactLowering obligationId]⟩
    let route : Route := ⟨.hostSandbox plan, [mediatorId]⟩
    let evidence : Evidence :=
      ⟨route, .hostSandbox sandboxId true false, [mediatorId]⟩
    dispatch ⟨toolId, some route⟩ evidence = .refused := by
  simp [dispatch, compositionAccept, ValidComposition, BoundaryCovered,
    boundaryCovered]

end LayeredComposition

#print axioms LayeredComposition.dispatch_invoked_iff
#print axioms LayeredComposition.invoked_implies_language_or_host_sandbox
#print axioms LayeredComposition.host_invocation_implies_restricted_lowering_and_activation
#print axioms LayeredComposition.invoked_implies_complete_resource_mediator_roster
#print axioms LayeredComposition.invoked_implies_complete_layered_mediation
#print axioms LayeredComposition.unsupported_host_lowering_cannot_invoke
#print axioms LayeredComposition.useful_host_and_resource_route_invokes
