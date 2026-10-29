import LayeredComposition
import SlpCedar
import GrantCoverage

/-!
# Semantic authority preservation

This file composes the existing SLP/Cedar authorization, grant-obligation, and
layered-route models into the paper's authority chain

`E_{B,H}(c) ⊆ L_{B,H}(c) ⊆ G(c) ⊆ R(c)`.

Reachability is an ordinary trace-membership predicate and contains no policy
test. The global `E ⊆ L` conclusion is derived from complete mediation plus
separate local sandbox and mediator guarantees. Primitive enforcement soundness,
authentic observations, and implementation refinement remain explicit external
premises, described in the project README.
-/
namespace AuthorityPreservation

/-! ## Common semantic vocabulary and translations -/

structure ProtectedObject where
  domain : GrantCoverage.Domain
  selector : String
  deriving DecidableEq, Repr

/-- A permission retains the exact typed condition value from `GrantCoverage.Rule`. -/
structure Permission where
  principal : String
  tool : String
  object : ProtectedObject
  operation : String
  conditions : GrantCoverage.Value
  deriving DecidableEq, Repr

/-- Effects are observations, not pre-authorized permissions. -/
structure Effect where
  principal : String
  tool : String
  object : ProtectedObject
  operation : String
  conditions : GrantCoverage.Value
  deriving DecidableEq, Repr

def Effect.Satisfies (effect : Effect) (permission : Permission) : Prop :=
  effect.principal = permission.principal ∧
    effect.tool = permission.tool ∧
    effect.object = permission.object ∧
    effect.operation = permission.operation ∧
    effect.conditions = permission.conditions

abbrev Authority := Effect → Prop

def AuthoritySubset (left right : Authority) : Prop :=
  ∀ effect, left effect → right effect

infix:50 " ⊑ " => AuthoritySubset

structure GrantMetadata where
  principal : String
  session : String
  tool : String
  artifact : String
  call : String
  intent : String
  policy : String
  deployment : String
  runtime : String
  digest : String
  deriving DecidableEq, Repr

def buildGrant (metadata : GrantMetadata) (rules : List GrantCoverage.Rule) : GrantCoverage.Grant :=
  { principal := metadata.principal
    session := metadata.session
    tool := metadata.tool
    artifact := metadata.artifact
    call := metadata.call
    intent := metadata.intent
    policy := metadata.policy
    deployment := metadata.deployment
    runtime := metadata.runtime
    digest := metadata.digest
    rules }

def permissionOfRule (metadata : GrantMetadata) (rule : GrantCoverage.Rule) : Permission :=
  { principal := metadata.principal
    tool := metadata.tool
    object := ⟨rule.domain, rule.selector⟩
    operation := rule.operation
    conditions := rule.conditions }

/--
`translate` is the explicit bridge from an admitted SLP line to the full rule
record. Exact line identity is preserved by authorization, so selectors and
typed conditions attached by this translation cannot be widened by filtering.
-/
def permissionOfLine (metadata : GrantMetadata)
    (translate : SlpCedar.Line → GrantCoverage.Rule) (line : SlpCedar.Line) : Permission :=
  permissionOfRule metadata (translate line)

structure RequestedAuthority where
  application : List SlpCedar.Line
  runtimeBaseline : List SlpCedar.Line
  deriving Repr

def RequestedAuthority.lines (request : RequestedAuthority) : List SlpCedar.Line :=
  request.application ++ request.runtimeBaseline

def authorityOfLines (metadata : GrantMetadata) (translate : SlpCedar.Line → GrantCoverage.Rule)
    (lines : List SlpCedar.Line) : Authority :=
  fun effect => ∃ line ∈ lines, effect.Satisfies (permissionOfLine metadata translate line)

def R (metadata : GrantMetadata) (translate : SlpCedar.Line → GrantCoverage.Rule)
    (request : RequestedAuthority) : Authority :=
  authorityOfLines metadata translate request.lines

def G (metadata : GrantMetadata) (translate : SlpCedar.Line → GrantCoverage.Rule)
    (granted : List SlpCedar.Line) : Authority :=
  authorityOfLines metadata translate granted

def grantRecord (metadata : GrantMetadata) (translate : SlpCedar.Line → GrantCoverage.Rule)
    (granted : List SlpCedar.Line) : GrantCoverage.Grant :=
  buildGrant metadata (granted.map translate)

/-! ## Authorization: `G ⊆ R` and policy compliance -/

def PolicyFacts (policies : SlpCedar.Policies) (principal tool : Nat)
    (line : SlpCedar.Line) : Prop :=
  policies.owner (SlpCedar.query principal tool line) = true ∧
    (policies.principal (SlpCedar.query principal tool line) = true ∨
      policies.share (SlpCedar.query principal tool line) = true) ∧
    policies.forbid (SlpCedar.query principal tool line) = false

theorem sourceAllows_policy_facts (policies : SlpCedar.Policies) (principal tool : Nat)
    (line : SlpCedar.Line) (allowed : SlpCedar.sourceAllows policies principal tool line = true) :
    PolicyFacts policies principal tool line := by
  have facts :
      (policies.owner (SlpCedar.query principal tool line) = true ∧
        (policies.principal (SlpCedar.query principal tool line) = true ∨
          policies.share (SlpCedar.query principal tool line) = true)) ∧
        policies.forbid (SlpCedar.query principal tool line) = false := by
    simpa [SlpCedar.sourceAllows, Bool.or_eq_true] using allowed
  exact ⟨facts.1.1, facts.1.2, facts.2⟩

theorem authorized_grant_subset_request
    (gates : SlpCedar.Gates) (policies : SlpCedar.Policies) (principal tool : Nat)
    (supported : SlpCedar.Line → Bool) (metadata : GrantMetadata)
    (translate : SlpCedar.Line → GrantCoverage.Rule) (request : RequestedAuthority)
    (granted : List SlpCedar.Line)
    (authorized : SlpCedar.authorize gates (SlpCedar.sourceAllows policies principal tool)
      supported request.lines = some granted) :
    G metadata translate granted ⊑ R metadata translate request := by
  intro effect inGrant
  rcases inGrant with ⟨line, lineGranted, semantic⟩
  have origin := SlpCedar.no_amplification gates
    (SlpCedar.sourceAllows policies principal tool) supported request.lines granted
    authorized line lineGranted
  exact ⟨line, origin.1, semantic⟩

theorem authorized_call_gate
    (gates : SlpCedar.Gates) (allow supported : SlpCedar.Line → Bool)
    (requested granted : List SlpCedar.Line)
    (authorized : SlpCedar.authorize gates allow supported requested = some granted) :
    SlpCedar.callGate gates requested = true := by
  exact ((SlpCedar.authorize_sound_complete gates allow supported requested granted).mp
    authorized).1

theorem authorized_grant_policy_compliant
    (gates : SlpCedar.Gates) (policies : SlpCedar.Policies) (principal tool : Nat)
    (supported : SlpCedar.Line → Bool) (metadata : GrantMetadata)
    (translate : SlpCedar.Line → GrantCoverage.Rule) (request : RequestedAuthority)
    (granted : List SlpCedar.Line)
    (authorized : SlpCedar.authorize gates (SlpCedar.sourceAllows policies principal tool)
      supported request.lines = some granted) :
    ∀ effect, G metadata translate granted effect →
      ∃ line ∈ granted,
        effect.Satisfies (permissionOfLine metadata translate line) ∧
        PolicyFacts policies principal tool line := by
  intro effect inGrant
  rcases inGrant with ⟨line, lineGranted, semantic⟩
  have origin := SlpCedar.no_amplification gates
    (SlpCedar.sourceAllows policies principal tool) supported request.lines granted
    authorized line lineGranted
  exact ⟨line, lineGranted, semantic,
    sourceAllows_policy_facts policies principal tool line origin.2⟩

/-! ## Exact obligation inventory from the existing grant model -/

theorem accepted_inventory_covers_every_grant_rule
    (grant : GrantCoverage.Grant) (obligations : List GrantCoverage.Obligation)
    (accepted : GrantCoverage.obligationsAccept grant obligations = true) :
    ∀ rule ∈ grant.rules, GrantCoverage.deriveRule rule ∈ obligations := by
  intro rule present
  exact GrantCoverage.no_missing_generated grant obligations accepted _
    (GrantCoverage.generated_rule_present grant rule present)

theorem accepted_inventory_covers_every_domain_complement
    (grant : GrantCoverage.Grant) (obligations : List GrantCoverage.Obligation)
    (accepted : GrantCoverage.obligationsAccept grant obligations = true) :
    ∀ domain, GrantCoverage.denyComplement domain ∈ obligations := by
  intro domain
  exact GrantCoverage.no_missing_generated grant obligations accepted _
    (GrantCoverage.generated_complement_present grant domain)

/-! ## Semantic lowering: `L ⊆ G` -/

structure LoweredPermission where
  obligation : GrantCoverage.Obligation
  sourceRule : Option GrantCoverage.Rule
  support : LayeredComposition.Support
  permits : Effect → Prop

def SemanticPreserving (metadata : GrantMetadata)
    (entry : LoweredPermission) : Prop :=
  match entry.sourceRule with
  | none => entry.support ≠ .unsupported ∧ ∀ effect, ¬entry.permits effect
  | some rule =>
      entry.obligation = GrantCoverage.deriveRule rule ∧
      match entry.support with
      | .exact => ∀ effect,
          entry.permits effect ↔ effect.Satisfies (permissionOfRule metadata rule)
      | .tightened => ∀ effect,
          entry.permits effect → effect.Satisfies (permissionOfRule metadata rule)
      | .unsupported => False

def exactSemanticEntry (metadata : GrantMetadata)
    (rule : GrantCoverage.Rule) : LoweredPermission :=
  { obligation := GrantCoverage.deriveRule rule
    sourceRule := some rule
    support := .exact
    permits := fun effect => effect.Satisfies (permissionOfRule metadata rule) }

theorem exact_semantic_entry_preserves (metadata : GrantMetadata)
    (rule : GrantCoverage.Rule) :
    SemanticPreserving metadata (exactSemanticEntry metadata rule) := by
  simp [SemanticPreserving, exactSemanticEntry]

def tightenedSemanticEntry (rule : GrantCoverage.Rule)
    (permits : Effect → Prop) : LoweredPermission :=
  { obligation := GrantCoverage.deriveRule rule
    sourceRule := some rule
    support := .tightened
    permits }

theorem tightened_semantic_entry_preserves
    (metadata : GrantMetadata) (rule : GrantCoverage.Rule)
    (permits : Effect → Prop)
    (subset : ∀ effect, permits effect →
      effect.Satisfies (permissionOfRule metadata rule)) :
    SemanticPreserving metadata (tightenedSemanticEntry rule permits) := by
  change GrantCoverage.deriveRule rule = GrantCoverage.deriveRule rule ∧
    ∀ effect, permits effect → effect.Satisfies (permissionOfRule metadata rule)
  exact ⟨rfl, subset⟩

structure SemanticPlan where
  grantDigest : String
  route : LayeredComposition.Route
  obligations : List GrantCoverage.Obligation
  entries : List LoweredPermission
  activated : List GrantCoverage.Obligation
  mediatorFor : GrantCoverage.Domain → Option String

def SameObligations (left right : List GrantCoverage.Obligation) : Prop :=
  (∀ obligation ∈ left, obligation ∈ right) ∧
    (∀ obligation ∈ right, obligation ∈ left)

def EntryRosterMatchesHost (plan : SemanticPlan) : Prop :=
  match plan.route.boundary with
  | .languageSandbox _ => True
  | .hostSandbox host =>
      (∀ entry ∈ plan.entries,
        ∃ lowering ∈ host.lowerings,
          lowering.obligationId = entry.obligation.id ∧
          lowering.support = entry.support) ∧
      (∀ lowering ∈ host.lowerings,
        ∃ entry ∈ plan.entries,
          entry.obligation.id = lowering.obligationId ∧
          entry.support = lowering.support)

def ValidSemanticPlan (metadata : GrantMetadata) (grant : GrantCoverage.Grant)
    (plan : SemanticPlan) : Prop :=
  grant.digest = plan.grantDigest ∧
    GrantCoverage.obligationsAccept grant plan.obligations = true ∧
    SameObligations (plan.entries.map LoweredPermission.obligation) plan.obligations ∧
    SameObligations plan.activated plan.obligations ∧
    EntryRosterMatchesHost plan ∧
    (∀ entry ∈ plan.entries,
      entry.obligation ∈ plan.obligations ∧
      (∀ rule, entry.sourceRule = some rule → rule ∈ grant.rules) ∧
      SemanticPreserving metadata entry)

def L (plan : SemanticPlan) : Authority :=
  fun effect => ∃ entry ∈ plan.entries, entry.permits effect

theorem semantic_lowering_preserves_grant
    (metadata : GrantMetadata) (grant : GrantCoverage.Grant) (plan : SemanticPlan)
    (valid : ValidSemanticPlan metadata grant plan) :
    L plan ⊑ fun effect => ∃ rule ∈ grant.rules,
      effect.Satisfies (permissionOfRule metadata rule) := by
  intro effect permitted
  rcases permitted with ⟨entry, entryMem, effectPermitted⟩
  have entryValid := valid.2.2.2.2.2 entry entryMem
  cases sourceEq : entry.sourceRule with
  | none =>
      have sound := entryValid.2.2
      simp [SemanticPreserving, sourceEq] at sound
      exact False.elim (sound.2 effect effectPermitted)
  | some rule =>
      have ruleMem := entryValid.2.1 rule sourceEq
      have sound := entryValid.2.2
      simp only [SemanticPreserving, sourceEq] at sound
      rcases sound with ⟨_, semantic⟩
      refine ⟨rule, ruleMem, ?_⟩
      cases supportEq : entry.support with
      | exact =>
          simp [supportEq] at semantic
          exact (semantic effect).mp effectPermitted
      | tightened =>
          simp [supportEq] at semantic
          exact semantic effect effectPermitted
      | unsupported =>
          simp [supportEq] at semantic

theorem grant_record_authority_eq_authorized_grant
    (metadata : GrantMetadata) (translate : SlpCedar.Line → GrantCoverage.Rule)
    (granted : List SlpCedar.Line) :
    (fun effect => ∃ rule ∈ (grantRecord metadata translate granted).rules,
      effect.Satisfies (permissionOfRule metadata rule)) =
      G metadata translate granted := by
  funext effect
  apply propext
  constructor
  · rintro ⟨rule, ruleMem, semantic⟩
    rcases List.mem_map.mp ruleMem with ⟨line, lineMem, rfl⟩
    exact ⟨line, lineMem, semantic⟩
  · rintro ⟨line, lineMem, semantic⟩
    exact ⟨translate line, List.mem_map.mpr ⟨line, lineMem, rfl⟩, semantic⟩

theorem lowered_plan_subset_authorized_grant
    (metadata : GrantMetadata) (translate : SlpCedar.Line → GrantCoverage.Rule)
    (granted : List SlpCedar.Line) (plan : SemanticPlan)
    (valid : ValidSemanticPlan metadata
      (grantRecord metadata translate granted) plan) :
    L plan ⊑ G metadata translate granted := by
  rw [← grant_record_authority_eq_authorized_grant metadata translate granted]
  exact semantic_lowering_preserves_grant metadata
    (grantRecord metadata translate granted) plan valid

theorem valid_plan_contains_no_unsupported_entry
    (metadata : GrantMetadata) (grant : GrantCoverage.Grant) (plan : SemanticPlan)
    (valid : ValidSemanticPlan metadata grant plan) :
    ∀ entry ∈ plan.entries, entry.support ≠ .unsupported := by
  intro entry entryMem
  have semantic := (valid.2.2.2.2.2 entry entryMem).2.2
  cases sourceEq : entry.sourceRule with
  | none =>
      simp [SemanticPreserving, sourceEq] at semantic
      exact semantic.1
  | some rule =>
      intro unsupported
      simp [SemanticPreserving, sourceEq, unsupported] at semantic

/-! ## Independent reachable traces and local enforcement -/

inductive EffectPath where
  | languageSandbox (sandboxId : String)
  | hostSandbox (sandboxId : String)
  | resourceMediator (mediatorId : String)
  | direct
  deriving DecidableEq, Repr

structure Occurrence where
  effect : Effect
  path : EffectPath
  deriving DecidableEq, Repr

abbrev ExecutionTrace := List Occurrence

/-- Reachability is plain occurrence in a trace; it has no authority premise. -/
def E (trace : ExecutionTrace) : Authority :=
  fun effect => ∃ occurrence ∈ trace, occurrence.effect = effect

def boundaryPath : LayeredComposition.ExecutionBoundary → EffectPath
  | .languageSandbox sandboxId => .languageSandbox sandboxId
  | .hostSandbox host => .hostSandbox host.sandboxId

/-- Every effect uses its selected mediator, or otherwise the execution sandbox. -/
def CompleteMediation (plan : SemanticPlan) (trace : ExecutionTrace) : Prop :=
  ∀ occurrence ∈ trace,
    match plan.mediatorFor occurrence.effect.object.domain with
    | some mediatorId =>
        occurrence.path = .resourceMediator mediatorId ∧
          mediatorId ∈ plan.route.resourceMediators
    | none => occurrence.path = boundaryPath plan.route.boundary

/--
Primitive local guarantees. Neither clause is the global `E ⊆ L` statement:
each speaks only about effects observed at one selected enforcement component.
-/
def LocalEnforcementSound (plan : SemanticPlan) (trace : ExecutionTrace) : Prop :=
  (∀ occurrence ∈ trace,
    occurrence.path = boundaryPath plan.route.boundary → L plan occurrence.effect) ∧
  (∀ occurrence ∈ trace, ∀ mediatorId,
    occurrence.path = .resourceMediator mediatorId →
    mediatorId ∈ plan.route.resourceMediators → L plan occurrence.effect)

def InvocationBound (candidate : LayeredComposition.Candidate) (evidence : LayeredComposition.Evidence)
    (grant : GrantCoverage.Grant) (plan : SemanticPlan) : Prop :=
  candidate.toolId = grant.tool ∧
    candidate.route = some plan.route ∧
    evidence.observedRoute = plan.route ∧
    plan.grantDigest = grant.digest

/--
Primitive component soundness is usable only for the exact grant-bound route
whose activation passed the layered decision core. This is the explicit local
sandbox/mediator assumption accepted by the global theorem.
-/
def ActivatedComponentSound
    (candidate : LayeredComposition.Candidate)
    (evidence : LayeredComposition.Evidence)
    (grant : GrantCoverage.Grant) (plan : SemanticPlan)
    (trace : ExecutionTrace) : Prop :=
  InvocationBound candidate evidence grant plan →
    LayeredComposition.dispatch candidate evidence = .invoked →
    LocalEnforcementSound plan trace

theorem effect_confinement_from_composition
    (candidate : LayeredComposition.Candidate) (evidence : LayeredComposition.Evidence)
    (grant : GrantCoverage.Grant) (plan : SemanticPlan) (trace : ExecutionTrace)
    (invoked : LayeredComposition.dispatch candidate evidence = .invoked)
    (bound : InvocationBound candidate evidence grant plan)
    (complete : CompleteMediation plan trace)
    (componentSound : ActivatedComponentSound
      candidate evidence grant plan trace) :
    E trace ⊑ L plan := by
  have localSound := componentSound bound invoked
  intro effect reachable
  rcases reachable with ⟨occurrence, occurrenceMem, rfl⟩
  have routed := complete occurrence occurrenceMem
  cases mediatorEq : plan.mediatorFor occurrence.effect.object.domain with
  | none =>
      simp [mediatorEq] at routed
      exact localSound.1 occurrence occurrenceMem routed
  | some mediatorId =>
      simp [mediatorEq] at routed
      exact localSound.2 occurrence occurrenceMem mediatorId routed.1 routed.2

/-! ## Complete authority chain -/

theorem complete_authority_preservation
    (gates : SlpCedar.Gates) (policies : SlpCedar.Policies) (principal tool : Nat)
    (supported : SlpCedar.Line → Bool) (metadata : GrantMetadata)
    (translate : SlpCedar.Line → GrantCoverage.Rule) (request : RequestedAuthority)
    (granted : List SlpCedar.Line) (plan : SemanticPlan)
    (candidate : LayeredComposition.Candidate) (evidence : LayeredComposition.Evidence)
    (trace : ExecutionTrace)
    (authorized : SlpCedar.authorize gates (SlpCedar.sourceAllows policies principal tool)
      supported request.lines = some granted)
    (validPlan : ValidSemanticPlan metadata
      (grantRecord metadata translate granted) plan)
    (invoked : LayeredComposition.dispatch candidate evidence = .invoked)
    (bound : InvocationBound candidate evidence
      (grantRecord metadata translate granted) plan)
    (complete : CompleteMediation plan trace)
    (componentSound : ActivatedComponentSound candidate evidence
      (grantRecord metadata translate granted) plan trace) :
    E trace ⊑ L plan ∧
      L plan ⊑ G metadata translate granted ∧
      G metadata translate granted ⊑ R metadata translate request := by
  exact ⟨effect_confinement_from_composition candidate evidence
      (grantRecord metadata translate granted) plan trace invoked bound complete componentSound,
    lowered_plan_subset_authorized_grant metadata translate granted plan validPlan,
    authorized_grant_subset_request gates policies principal tool supported metadata
      translate request granted authorized⟩

theorem complete_chain_effect
    (gates : SlpCedar.Gates) (policies : SlpCedar.Policies) (principal tool : Nat)
    (supported : SlpCedar.Line → Bool) (metadata : GrantMetadata)
    (translate : SlpCedar.Line → GrantCoverage.Rule) (request : RequestedAuthority)
    (granted : List SlpCedar.Line) (plan : SemanticPlan)
    (candidate : LayeredComposition.Candidate) (evidence : LayeredComposition.Evidence)
    (trace : ExecutionTrace)
    (authorized : SlpCedar.authorize gates (SlpCedar.sourceAllows policies principal tool)
      supported request.lines = some granted)
    (validPlan : ValidSemanticPlan metadata
      (grantRecord metadata translate granted) plan)
    (invoked : LayeredComposition.dispatch candidate evidence = .invoked)
    (bound : InvocationBound candidate evidence
      (grantRecord metadata translate granted) plan)
    (complete : CompleteMediation plan trace)
    (componentSound : ActivatedComponentSound candidate evidence
      (grantRecord metadata translate granted) plan trace)
    (effect : Effect) (reachable : E trace effect) :
    L plan effect ∧ G metadata translate granted effect ∧
      R metadata translate request effect := by
  have chain := complete_authority_preservation gates policies principal tool supported
    metadata translate request granted plan candidate evidence trace authorized validPlan
    invoked bound complete componentSound
  exact ⟨chain.1 effect reachable,
    chain.2.1 effect (chain.1 effect reachable),
    chain.2.2 effect (chain.2.1 effect (chain.1 effect reachable))⟩

/-! ## Negative witnesses: each isolates one failed premise -/

theorem direct_resource_bypass_violates_complete_mediation
    (plan : SemanticPlan) (effect : Effect) :
    ¬CompleteMediation plan [⟨effect, .direct⟩] := by
  intro complete
  have routed := complete ⟨effect, .direct⟩ (by simp)
  cases mediatorEq : plan.mediatorFor effect.object.domain with
  | some mediatorId =>
      simp [mediatorEq] at routed
  | none =>
      cases boundaryEq : plan.route.boundary with
      | languageSandbox sandboxId =>
          simp [mediatorEq, boundaryEq, boundaryPath] at routed
      | hostSandbox host =>
          simp [mediatorEq, boundaryEq, boundaryPath] at routed

theorem omitted_mediator_violates_complete_mediation
    (plan : SemanticPlan) (effect : Effect) (mediatorId : String)
    (required : plan.mediatorFor effect.object.domain = some mediatorId) :
    ¬CompleteMediation plan [⟨effect, boundaryPath plan.route.boundary⟩] := by
  intro complete
  have routed := complete ⟨effect, boundaryPath plan.route.boundary⟩ (by simp)
  have routed' : boundaryPath plan.route.boundary = .resourceMediator mediatorId ∧
      mediatorId ∈ plan.route.resourceMediators := by
    simpa [required] using routed
  cases boundaryEq : plan.route.boundary with
  | languageSandbox sandboxId =>
      have impossible : EffectPath.languageSandbox sandboxId =
          .resourceMediator mediatorId := by
        simpa [boundaryEq, boundaryPath] using routed'.1
      cases impossible
  | hostSandbox host =>
      have impossible : EffectPath.hostSandbox host.sandboxId =
          .resourceMediator mediatorId := by
        simpa [boundaryEq, boundaryPath] using routed'.1
      cases impossible

theorem unsupported_entry_is_not_semantic_preserving
    (metadata : GrantMetadata) (entry : LoweredPermission)
    (source : entry.sourceRule ≠ none) (unsupported : entry.support = .unsupported) :
    ¬SemanticPreserving metadata entry := by
  intro semantic
  cases sourceEq : entry.sourceRule with
  | none => exact source sourceEq
  | some rule => simp [SemanticPreserving, sourceEq, unsupported] at semantic

theorem purported_tightening_that_broadens_is_invalid
    (metadata : GrantMetadata) (entry : LoweredPermission) (rule : GrantCoverage.Rule)
    (source : entry.sourceRule = some rule)
    (tightened : entry.support = .tightened)
    (effect : Effect) (permitted : entry.permits effect)
    (outside : ¬effect.Satisfies (permissionOfRule metadata rule)) :
    ¬SemanticPreserving metadata entry := by
  intro semantic
  simp [SemanticPreserving, source, tightened] at semantic
  exact outside (semantic.2 effect permitted)

/-! ## Constructive route witnesses -/

example :
    let route : LayeredComposition.Route := ⟨.languageSandbox "lang", []⟩
    let evidence : LayeredComposition.Evidence := ⟨route, .languageSandbox "lang", []⟩
    LayeredComposition.dispatch ⟨"tool", some route⟩ evidence = .invoked := by decide

example :
    let host : LayeredComposition.HostPlan :=
      ⟨"host", [⟨"rule:fs:operate", .exact⟩]⟩
    let route : LayeredComposition.Route := ⟨.hostSandbox host, []⟩
    let evidence : LayeredComposition.Evidence := ⟨route, .hostSandbox "host" true true, []⟩
    LayeredComposition.dispatch ⟨"tool", some route⟩ evidence = .invoked := by decide

example :
    let host : LayeredComposition.HostPlan :=
      ⟨"host", [⟨"rule:record:operate", .tightened⟩]⟩
    let route : LayeredComposition.Route := ⟨.hostSandbox host, ["record-mediator"]⟩
    let evidence : LayeredComposition.Evidence :=
      ⟨route, .hostSandbox "host" true true, ["record-mediator"]⟩
    LayeredComposition.dispatch ⟨"tool", some route⟩ evidence = .invoked := by decide

example :
    let host : LayeredComposition.HostPlan :=
      ⟨"host", [⟨"rule:fs:operate", .exact⟩]⟩
    let route : LayeredComposition.Route := ⟨.hostSandbox host, []⟩
    let evidence : LayeredComposition.Evidence := ⟨route, .hostSandbox "host" true false, []⟩
    LayeredComposition.dispatch ⟨"tool", some route⟩ evidence = .refused := by decide

example :
    let host : LayeredComposition.HostPlan :=
      ⟨"host", [⟨"rule:fs:operate", .unsupported⟩]⟩
    let route : LayeredComposition.Route := ⟨.hostSandbox host, []⟩
    let evidence : LayeredComposition.Evidence := ⟨route, .hostSandbox "host" true true, []⟩
    LayeredComposition.dispatch ⟨"tool", some route⟩ evidence = .refused := by decide

end AuthorityPreservation

#print axioms AuthorityPreservation.authorized_grant_subset_request
#print axioms AuthorityPreservation.authorized_call_gate
#print axioms AuthorityPreservation.authorized_grant_policy_compliant
#print axioms AuthorityPreservation.semantic_lowering_preserves_grant
#print axioms AuthorityPreservation.exact_semantic_entry_preserves
#print axioms AuthorityPreservation.tightened_semantic_entry_preserves
#print axioms AuthorityPreservation.effect_confinement_from_composition
#print axioms AuthorityPreservation.complete_authority_preservation
#print axioms AuthorityPreservation.complete_chain_effect
#print axioms AuthorityPreservation.direct_resource_bypass_violates_complete_mediation
#print axioms AuthorityPreservation.omitted_mediator_violates_complete_mediation
#print axioms AuthorityPreservation.purported_tightening_that_broadens_is_invalid
