import GrantCoverage

/-! Broker obligations are generated from the captured native grant, including
the mediator's declared protected paths and required host capabilities. Their
native truth and assessment provenance remain controller/OS premises. -/
namespace ResourceGrantCoverage
open GrantCoverage WorkerRoute

def lookup (key : String) : Entries → Value
  | .nil => .null
  | .cons name value rest => if key == name then value else lookup key rest

def conditionField (rule : Rule) (key : String) : Value :=
  match rule.conditions with
  | .map entries => lookup key entries
  | _ => .null

def resourceSelector (rule : Rule) : String :=
  match conditionField rule "resource_selector" with
  | .text text => text
  | _ => ""

def guardID (rule : Rule) (kind : String) : String :=
  "resource:" ++ rule.id ++ ":" ++ kind

def guards (rule : Rule) : List Obligation :=
  [{id := guardID rule "bypass", rule := rule.id, kind := .bypassPrevention,
    domain := .service, operation := "deny_direct_resource_access",
    selector := resourceSelector rule,
    conditions := .map (.cons "protected_paths" (conditionField rule "protected_paths")
      (.cons "required_capabilities" (conditionField rule "required_capabilities") .nil)),
    dependencies := ["domain:filesystem:deny_complement", "domain:network:deny_complement",
      "domain:process:deny_complement"], waivable := false},
   {id := guardID rule "channel", rule := rule.id, kind := .authenticatedChannel,
    domain := .ipc, operation := "spawn_bound_broker", selector := resourceSelector rule,
    conditions := .map .nil, dependencies := ["domain:ipc:deny_complement"], waivable := false},
   {id := guardID rule "custody", rule := rule.id, kind := .credentialCustody,
    domain := .credential, operation := "parent_owned_credentials", selector := resourceSelector rule,
    conditions := .map .nil, dependencies := [guardID rule "bypass", guardID rule "channel"],
    waivable := false}]

def derive (rule : Rule) : List Obligation :=
  if rule.domain == .service then
    {deriveRule rule with dependencies := [guardID rule "bypass", guardID rule "channel",
      guardID rule "custody"]} :: guards rule
  else [deriveRule rule]

def generated (grant : Grant) : List Obligation :=
  grant.rules.flatMap derive ++ domains.map denyComplement

def textSequence : Value → Bool
  | .sequence values => allText values
  | _ => false
where
  allText : Values → Bool
    | .nil => true
    | .cons (.text _) rest => allText rest
    | _ => false

def ResourceRules (grant : Grant) : Prop :=
  ∀ rule ∈ grant.rules, rule.domain = .service →
    resourceSelector rule ≠ "" ∧ textSequence (conditionField rule "protected_paths") = true ∧
    textSequence (conditionField rule "required_capabilities") = true

def ExactGenerated (grant : Grant) (obligations : List Obligation) : Prop :=
  (obligations.map Obligation.id).Nodup ∧
  (∀ row ∈ obligations, row ∈ generated grant) ∧
  (∀ row ∈ generated grant, row ∈ obligations)

instance (grant : Grant) (obligations : List Obligation) :
    Decidable (ValidGrant grant ∧ ResourceRules grant ∧ ExactGenerated grant obligations) := by
  unfold ValidGrant RulesWellFormed ResourceRules ExactGenerated
  infer_instance

def obligationsAccept (grant : Grant) (obligations : List Obligation) : Bool :=
  decide (ValidGrant grant ∧ ResourceRules grant ∧ ExactGenerated grant obligations)

def ValidCertificate (binding : Binding) (certificate : Certificate) : Prop :=
  ValidGrant certificate.grant ∧ ResourceRules certificate.grant ∧
  GrantBound binding certificate.grant ∧ ExactGenerated certificate.grant certificate.obligations ∧
  ReceiptCoverage.SameIDs
    (certificate.coverage.plan.assignments.map ReceiptCoverage.Assignment.obligation)
    ((generated certificate.grant).map Obligation.id) ∧
  Selected certificate ∧ ReceiptCoverage.BoundTo binding certificate.coverage ∧
  ReceiptCoverage.ValidCoverage certificate.coverage

instance (binding : Binding) (certificate : Certificate) :
    Decidable (ValidCertificate binding certificate) := by
  unfold ValidCertificate ValidGrant RulesWellFormed ResourceRules GrantBound ExactGenerated Selected
  infer_instance

def certificateValid (binding : Binding) (certificate : Certificate) : Bool :=
  decide (ValidCertificate binding certificate)

def runCertified (binding : Binding) (certificate : Certificate) (events : List Event) : State :=
  if certificateValid binding certificate then run binding events else ⟨binding, .refused⟩

theorem obligationsAccept_iff (grant : Grant) (obligations : List Obligation) :
    obligationsAccept grant obligations = true ↔
      ValidGrant grant ∧ ResourceRules grant ∧ ExactGenerated grant obligations := by
  simp [obligationsAccept]

theorem certificateValid_iff (binding : Binding) (certificate : Certificate) :
    certificateValid binding certificate = true ↔ ValidCertificate binding certificate := by
  simp [certificateValid]

theorem accepted_inventory_complete (grant : Grant) (obligations : List Obligation)
    (accepted : obligationsAccept grant obligations = true) :
    ∀ row ∈ generated grant, row ∈ obligations :=
  ((obligationsAccept_iff _ _).mp accepted).2.2.2.2

theorem service_guards_required (grant : Grant) (obligations : List Obligation)
    (accepted : obligationsAccept grant obligations = true) (rule : Rule)
    (present : rule ∈ grant.rules) (service : rule.domain = .service) :
    ∀ row ∈ guards rule, row ∈ obligations := by
  intro row member
  apply accepted_inventory_complete grant obligations accepted
  apply List.mem_append_left
  apply List.mem_flatMap.mpr
  refine ⟨rule, present, ?_⟩
  simp [derive, service, member]

end ResourceGrantCoverage
