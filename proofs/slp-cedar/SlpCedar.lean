import Cedar.Thm.Authorization

/-!
A model of the v2 object-policy query boundary, after successful SLP expansion.
Authorization decisions below are computed by Cedar's official Lean semantics.
Python serialization and subprocess transport remain outside this model.
-/
namespace SlpCedar

open Cedar.Data
open Cedar.Spec

structure Line where
  identity : Nat
  classId : Nat
  operation : Nat
  resource : Nat
  need : Bool
  deriving DecidableEq, Repr


def entityType (name : String) : EntityType := ⟨name, ["slangGraph"]⟩
def userUid (principal : Nat) : EntityUID := ⟨entityType "User", toString principal⟩
def toolUid (tool : Nat) : EntityUID := ⟨entityType "Tool", toString tool⟩
def actionUid (line : Line) : EntityUID :=
  ⟨entityType "Action", s!"{line.classId}::{line.operation}"⟩
def resourceUid (line : Line) : EntityUID :=
  ⟨entityType s!"Object{line.classId}", toString line.resource⟩

/-- Typed analogue of `object_policy._request`; JSON/Cedar-string encoding is
outside the model. The context records both the tool identity and NEED/WANT. -/
def query (principal tool : Nat) (line : Line) : Cedar.Spec.Request :=
  { principal := userUid principal
    action := actionUid line
    resource := resourceUid line
    context := Map.make
      [("requirement", if line.need then ("need" : Value) else ("want" : Value)),
       ("tool", toolUid tool)] }

/-- Typed analogue of `_call_request`. Production call context is empty. -/
def callQuery (principal tool : Nat) : Cedar.Spec.Request :=
  { principal := userUid principal
    action := ⟨entityType "Action", "call"⟩
    resource := toolUid tool
    context := Map.empty }

/-- The exact AST denoted by production `_candidate_permit`. It deliberately
leaves resource unconstrained, so all equivalence results below are scoped to
the corresponding generated query. -/
def candidatePermit (principal : Nat) (line : Line) : Policy :=
  { id := s!"constructive:{line.identity}"
    effect := .permit
    principalScope := .principalScope (.eq (userUid principal))
    actionScope := .actionScope (.eq (actionUid line))
    resourceScope := .resourceScope .any
    condition := [] }

/-- The official AST corresponding to production `_call_permit`. -/
def callPermit (principal tool : Nat) : Policy :=
  { id := "constructive:call"
    effect := .permit
    principalScope := .principalScope (.eq (userUid principal))
    actionScope := .actionScope (.eq ⟨entityType "Action", "call"⟩)
    resourceScope := .resourceScope (.eq (toolUid tool))
    condition := [] }

def cedarAllows (entities : Entities) (policies : Cedar.Spec.Policies)
    (request : Cedar.Spec.Request) : Bool :=
  (Cedar.Spec.isAuthorized request entities policies).decision == .allow

def noSatisfiedForbid (entities : Entities) (policies : Cedar.Spec.Policies)
    (request : Cedar.Spec.Request) : Bool :=
  (Cedar.Spec.satisfiedPolicies .forbid policies request entities).isEmpty

structure Policies where
  entities : Entities
  owner : Cedar.Spec.Policies
  principal : Cedar.Spec.Policies
  share : Cedar.Spec.Policies
  forbid : Cedar.Spec.Policies

/-- Independent source-side decision on a normalized SLP line. -/
def sourceAllows (s : Policies) (p t : Nat) (l : Line) : Bool :=
  cedarAllows s.entities s.owner (query p t l) &&
    cedarAllows s.entities (s.principal ++ s.share) (query p t l) &&
    noSatisfiedForbid s.entities s.forbid (query p t l)

/-- Three separate Cedar queries, as in `CedarObjectAuthorizer.authorize`. -/
def targetAllows (s : Policies) (p t : Nat) (l : Line) : Bool :=
  cedarAllows s.entities s.owner (query p t l) &&
    cedarAllows s.entities (s.principal ++ s.share) (query p t l) &&
    cedarAllows s.entities (candidatePermit p l :: s.forbid) (query p t l)

theorem candidate_permits_generated_query (s : Policies) (p t : Nat) (l : Line) :
    Cedar.Spec.satisfied (candidatePermit p l) (query p t l) s.entities = true := by
  simp [Cedar.Spec.satisfied, candidatePermit, query, userUid, actionUid,
    resourceUid, entityType, Cedar.Spec.Policy.toExpr, Cedar.Spec.PrincipalScope.toExpr,
    Cedar.Spec.ActionScope.toExpr, Cedar.Spec.ResourceScope.toExpr,
    Cedar.Spec.Scope.toExpr, Cedar.Spec.Conditions.toExpr, Cedar.Spec.evaluate,
    Cedar.Spec.Var.eqEntityUID, Cedar.Spec.apply₂, Cedar.Spec.Result.as]
  rfl

/-- Cedar policy-evaluation errors remain in `erroringPolicies`; as in Cedar,
they do not themselves satisfy either effect. This is distinct from Argus
transport/parsing failures, represented by `Gates.operational`. -/
def cedarEvaluationErrors (s : Policies) (p t : Nat) (l : Line) : Set PolicyID :=
  (Cedar.Spec.isAuthorized (query p t l) s.entities
    (candidatePermit p l :: s.forbid)).erroringPolicies

theorem candidate_query_authorized_iff_no_forbid
    (s : Policies) (p t : Nat) (l : Line) :
    cedarAllows s.entities (candidatePermit p l :: s.forbid) (query p t l) =
      noSatisfiedForbid s.entities s.forbid (query p t l) := by
  have hc := candidate_permits_generated_query s p t l
  have permitted : Cedar.Thm.IsExplicitlyPermitted (query p t l) s.entities
      (candidatePermit p l :: s.forbid) := by
    exact ⟨candidatePermit p l, by simp, rfl, hc⟩
  cases hf : noSatisfiedForbid s.entities s.forbid (query p t l) with
  | false =>
      have forbidden : Cedar.Thm.IsExplicitlyForbidden (query p t l) s.entities
          (candidatePermit p l :: s.forbid) := by
        rw [Cedar.Thm.explicitly_forbidden_iff_satisfying_forbid]
        simpa [noSatisfiedForbid, Cedar.Spec.satisfiedPolicies,
          Cedar.Spec.satisfiedWithEffect, candidatePermit] using hf
      have denied := Cedar.Thm.forbid_trumps_permit (query p t l) s.entities
        (candidatePermit p l :: s.forbid) forbidden
      simp [cedarAllows, denied]
  | true =>
      have notForbidden : ¬ Cedar.Thm.IsExplicitlyForbidden (query p t l) s.entities
          (candidatePermit p l :: s.forbid) := by
        rw [Cedar.Thm.explicitly_forbidden_iff_satisfying_forbid]
        simpa [noSatisfiedForbid, Cedar.Spec.satisfiedPolicies,
          Cedar.Spec.satisfiedWithEffect, candidatePermit] using hf
      have allowed := (Cedar.Thm.allowed_iff_explicitly_permitted_and_not_denied
        (query p t l) s.entities (candidatePermit p l :: s.forbid)).mp
          ⟨permitted, notForbidden⟩
      simp [cedarAllows, allowed]

theorem query_sound_complete (s : Policies) (p t : Nat) (l : Line) :
    targetAllows s p t l = sourceAllows s p t l := by
  simp [targetAllows, sourceAllows, candidate_query_authorized_iff_no_forbid]

/-- Recursive model of the Python loop: denied NEED aborts, denied WANT skips. -/
def collect (allow : Line → Bool) : List Line → Option (List Line)
  | [] => some []
  | l :: ls =>
    if allow l then (collect allow ls).map (l :: ·)
    else if l.need then none else collect allow ls

def needsSatisfied (allow : Line → Bool) (ls : List Line) : Prop :=
  ∀ l ∈ ls, l.need = true → allow l = true

theorem collect_formula (allow : Line → Bool) (ls : List Line) :
    collect allow ls =
      if ls.all (fun l => !l.need || allow l) then some (ls.filter allow) else none := by
  induction ls with
  | nil => rfl
  | cons l ls ih =>
    cases ha : allow l <;> cases hn : l.need <;>
      cases ht : ls.all (fun l => !l.need || allow l) <;>
      simp [collect, ih, ha, hn, ht]

theorem collect_exact (allow : Line → Bool) (ls out : List Line) :
    collect allow ls = some out ↔
      needsSatisfied allow ls ∧ out = ls.filter allow := by
  rw [collect_formula]
  have hneeds : ls.all (fun l => !l.need || allow l) = true ↔
      needsSatisfied allow ls := by
    simp only [List.all_eq_true, Bool.or_eq_true]
    constructor
    · intro h l hl hn
      rcases h l hl with hfalse | hallow
      · simp [hn] at hfalse
      · exact hallow
    · intro h l hl
      cases hn : l.need
      · exact Or.inl rfl
      · exact Or.inr (h l hl hn)
  split
  · rename_i h
    simp only [Option.some.injEq, hneeds.mp h, true_and]
    exact eq_comm
  · rename_i h
    simp only [reduceCtorEq, false_iff, not_and]
    intro hn
    exact False.elim (h (hneeds.mpr hn))

/-- Call gates include owner/MAC call checks and, only for empty manifests,
the principal call check. `operational` covers validation and CLI success. -/
structure Gates where
  operational : Bool
  ownerCall : Bool
  principalCall : Bool
  macCall : Bool

/-- All policy-dependent call gates derived from official Cedar decisions.
`operational` alone abstracts validation, serialization, transport, and CLI
result parsing. The principal partition (not share) is used for empty tools. -/
def semanticGates (operational : Bool) (s : Policies) (p t : Nat) : Gates :=
  { operational
    ownerCall := cedarAllows s.entities s.owner (callQuery p t)
    principalCall := cedarAllows s.entities s.principal (callQuery p t)
    macCall := cedarAllows s.entities (callPermit p t :: s.forbid) (callQuery p t) }

theorem call_candidate_permits_generated_query (s : Policies) (p t : Nat) :
    Cedar.Spec.satisfied (callPermit p t) (callQuery p t) s.entities = true := by
  simp [Cedar.Spec.satisfied, callPermit, callQuery, userUid, toolUid,
    entityType, Cedar.Spec.Policy.toExpr, Cedar.Spec.PrincipalScope.toExpr,
    Cedar.Spec.ActionScope.toExpr, Cedar.Spec.ResourceScope.toExpr,
    Cedar.Spec.Scope.toExpr, Cedar.Spec.Conditions.toExpr, Cedar.Spec.evaluate,
    Cedar.Spec.Var.eqEntityUID, Cedar.Spec.apply₂, Cedar.Spec.Result.as]
  rfl

def callGate (g : Gates) (ls : List Line) : Bool :=
  g.operational && g.ownerCall && g.macCall &&
    (if ls.isEmpty then g.principalCall else true)

/-- `supported` includes explicitly accepted enforcement waivers. -/
def authorize (g : Gates) (allow supported : Line → Bool)
    (ls : List Line) : Option (List Line) :=
  if callGate g ls then
    match collect allow ls with
    | none => none
    | some out =>
      if (!ls.isEmpty && out.isEmpty) || !(out.all supported) then none else some out
  else none

/-- Declarative contract: exact authorized subset, all NEEDs, nonempty resource
access, call eligibility, and support for every returned line. -/
def ValidGrant (g : Gates) (allow supported : Line → Bool)
    (ls out : List Line) : Prop :=
  callGate g ls = true ∧ needsSatisfied allow ls ∧
    out = ls.filter allow ∧
    (!ls.isEmpty && out.isEmpty) = false ∧ out.all supported = true

theorem authorize_sound_complete (g : Gates) (allow supported : Line → Bool)
    (ls out : List Line) :
    authorize g allow supported ls = some out ↔ ValidGrant g allow supported ls out := by
  unfold authorize ValidGrant
  by_cases hg : callGate g ls = true
  · simp only [hg, ↓reduceIte, true_and]
    cases hc : collect allow ls with
    | none =>
      simp only [reduceCtorEq, false_iff]
      intro ⟨hn, heq, _⟩
      have h := (collect_exact allow ls out).mpr ⟨hn, heq⟩
      rw [hc] at h
      contradiction
    | some result =>
      have h := collect_exact allow ls out
      simp only [hc, Option.some.injEq] at h
      rw [← @and_assoc (needsSatisfied allow ls) (out = ls.filter allow), ← h]
      by_cases hb : ((!ls.isEmpty && result.isEmpty) || !(result.all supported)) = true
      · simp only [hb, ↓reduceIte, reduceCtorEq, false_iff]
        intro ⟨heq, hn, hs⟩
        subst out
        simp [hn, hs] at hb
      · simp only [hb, Bool.false_eq_true, ↓reduceIte, Option.some.injEq]
        have good : (!ls.isEmpty && result.isEmpty) = false ∧ result.all supported = true := by
          cases hn : (!ls.isEmpty && result.isEmpty) <;>
            cases hs : result.all supported <;> simp_all
        constructor
        · intro heq; subst out; exact ⟨rfl, good⟩
        · exact fun heq => heq.1
  · simp only [hg, ↓reduceIte, reduceCtorEq, false_and]

theorem slp_to_cedar_sound_complete (g : Gates) (s : Policies) (p t : Nat)
    (supported : Line → Bool) (ls out : List Line) :
    authorize g (targetAllows s p t) supported ls = some out ↔
      ValidGrant g (sourceAllows s p t) supported ls out := by
  have heq : targetAllows s p t = sourceAllows s p t :=
    funext (query_sound_complete s p t)
  rw [heq]
  exact authorize_sound_complete g _ supported ls out

/-- P1 with both the per-line queries and the owner/principal/MAC call gates
instantiated by official Cedar semantics. -/
theorem argus_authorization_official_sound_complete (operational : Bool)
    (s : Policies) (p t : Nat) (supported : Line → Bool) (ls out : List Line) :
    authorize (semanticGates operational s p t) (targetAllows s p t)
        supported ls = some out ↔
      ValidGrant (semanticGates operational s p t) (sourceAllows s p t)
        supported ls out := by
  exact slp_to_cedar_sound_complete (semanticGates operational s p t) s p t
    supported ls out

/-- No authority can be introduced by the collector. -/
theorem no_amplification (g : Gates) (allow supported : Line → Bool)
    (ls out : List Line) (h : authorize g allow supported ls = some out) :
    ∀ l ∈ out, l ∈ ls ∧ allow l = true := by
  have hv := (authorize_sound_complete g allow supported ls out).mp h
  rw [hv.2.2.1]
  intro l hl
  simpa using hl

/-- An unrestricted policy-equivalence claim is false: candidate permits are
ephemeral and must only be evaluated on their corresponding generated query. -/
example :
    let l : Line := ⟨0, 1, 2, 3, true⟩
    let other := { query 0 0 l with resource := ⟨entityType "Object1", "999"⟩ }
    Cedar.Spec.satisfied (candidatePermit 0 l) other (Map.empty : Entities) = true ∧
      other.resource ≠ (query 0 0 l).resource := by
  native_decide

#print axioms query_sound_complete
#print axioms candidate_query_authorized_iff_no_forbid
#print axioms argus_authorization_official_sound_complete
#print axioms collect_exact
#print axioms slp_to_cedar_sound_complete
#print axioms no_amplification

end SlpCedar
