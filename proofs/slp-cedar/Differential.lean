import SlpCedar

namespace Differential

open Cedar.Data
open Cedar.Spec
open SlpCedar

def dbLine : Line := ⟨0, 1, 1, 11, true⟩
def secretLine : Line := ⟨1, 2, 1, 22, false⟩
def lines := [dbLine, secretLine]

def lineActions : List EntityUID := [actionUid dbLine, actionUid secretLine]

def entityData (attrs : List (Attr × Value)) : EntityData :=
  { attrs := Map.make attrs, ancestors := Set.empty, tags := Map.empty }

def entities (roles : List String) (dbOwner secretOwner : String) : Entities :=
  Map.make
    [(userUid 1, entityData [("roles", Value.set (Set.make (roles.map fun role => Value.prim (.string role))))]),
     (toolUid 1, entityData [("owner", ("reporting" : Value))]),
     (resourceUid dbLine, entityData [("owner", (dbOwner : Value))]),
     (resourceUid secretLine, entityData [("owner", (secretOwner : Value))])]

def policy (id : String) (effect : Effect) (principal : Scope)
    (action : ActionScope) (resource : Scope) (conditions : Conditions := []) : Policy :=
  { id, effect
    principalScope := .principalScope principal
    actionScope := action
    resourceScope := .resourceScope resource
    condition := conditions }

def callOwner : Policy :=
  policy "owner-call" .permit .any (.actionScope (.eq ⟨entityType "Action", "call"⟩)) .any

def toolCondition (tool : Nat) : Condition :=
  { kind := .when
    body := .binaryApp .eq (.getAttr (.var .context) "tool")
      (.lit (.entityUID (toolUid tool))) }

def ownerLines (tool : Nat) : Policy :=
  policy "owner-lines" .permit .any (.actionInAny lineActions) .any [toolCondition tool]

def roleCondition : Condition :=
  { kind := .when
    body := .binaryApp .contains (.getAttr (.var .principal) "roles")
      (.lit (.string "analyst")) }

def roleEnvelope : Policy :=
  policy "principal-role" .permit .any (.actionInAny lineActions) .any [roleCondition]

def wrongResourceEnvelope : Policy :=
  policy "principal-wrong-resource" .permit .any
    (.actionScope (.eq (actionUid dbLine)))
    (.eq ⟨entityType "Object1", "wrong"⟩)

def ownerAttrCondition (attr value : String) : Condition :=
  { kind := .when
    body := .binaryApp .eq (.getAttr (.var .resource) attr) (.lit (.string value)) }

def blockedForbid : Policy :=
  policy "blocked" .forbid .any (.actionInAny lineActions) .any
    [ownerAttrCondition "owner" "blocked"]

def errorForbid : Policy :=
  policy "error" .forbid .any (.actionInAny lineActions) .any
    [ownerAttrCondition "attribute_that_does_not_exist" "x"]

def policies (es : Entities) (ownerTool : Nat) (envelope : Cedar.Spec.Policies)
    (forbids : Cedar.Spec.Policies) : SlpCedar.Policies :=
  { entities := es
    owner := [callOwner, ownerLines ownerTool]
    principal := envelope
    share := []
    forbid := forbids }

structure Case where
  name : String
  policies : SlpCedar.Policies

def cases : List Case :=
  [{ name := "allowed"
     policies := policies (entities ["analyst"] "finance" "platform") 1
       [roleEnvelope] [blockedForbid] },
   { name := "optional_forbid"
     policies := policies (entities ["analyst"] "finance" "blocked") 1
       [roleEnvelope] [blockedForbid] },
   { name := "mandatory_forbid"
     policies := policies (entities ["analyst"] "blocked" "platform") 1
       [roleEnvelope] [blockedForbid] },
   { name := "role_denied"
     policies := policies (entities [] "finance" "platform") 1
       [roleEnvelope] [blockedForbid] },
   { name := "resource_mismatch"
     policies := policies (entities ["analyst"] "finance" "platform") 1
       [wrongResourceEnvelope] [blockedForbid] },
   { name := "context_mismatch"
     policies := policies (entities ["analyst"] "finance" "platform") 999
       [roleEnvelope] [blockedForbid] },
   { name := "evaluation_error"
     policies := policies (entities ["analyst"] "finance" "platform") 1
       [roleEnvelope] [errorForbid] }]

def response (s : SlpCedar.Policies) (ps : Cedar.Spec.Policies) (q : Request) : Response :=
  Cedar.Spec.isAuthorized q s.entities ps

def render (label : String) (r : Response) : String :=
  let decision := if r.decision == .allow then "ALLOW" else "DENY"
  s!"{label}={decision}:{r.erroringPolicies.size}"

def traceLines (s : SlpCedar.Policies) (p t : Nat) : List Line → List String
  | [] => []
  | line :: rest =>
    let q := query p t line
    let owner := response s s.owner q
    let ownerTrace := render "owner" owner
    if owner.decision != .allow then
      if line.need then [ownerTrace] else ownerTrace :: traceLines s p t rest
    else
      let envelope := response s (s.principal ++ s.share) q
      let envelopeTrace := render "envelope" envelope
      if envelope.decision != .allow then
        if line.need then [ownerTrace, envelopeTrace]
        else ownerTrace :: envelopeTrace :: traceLines s p t rest
      else
        let mac := response s (candidatePermit p line :: s.forbid) q
        let macTrace := render "mac-eval" mac
        if mac.decision != .allow then
          if line.need then [ownerTrace, envelopeTrace, macTrace]
          else ownerTrace :: envelopeTrace :: macTrace :: traceLines s p t rest
        else ownerTrace :: envelopeTrace :: macTrace :: traceLines s p t rest

def trace (s : SlpCedar.Policies) (p t : Nat) : List String :=
  let owner := response s s.owner (callQuery p t)
  let ownerTrace := render "owner-call" owner
  if owner.decision != .allow then [ownerTrace]
  else
    let mac := response s (callPermit p t :: s.forbid) (callQuery p t)
    let macTrace := render "mac-call" mac
    if mac.decision != .allow then [ownerTrace, macTrace]
    else ownerTrace :: macTrace :: traceLines s p t lines

def outcome (s : SlpCedar.Policies) : String :=
  match authorize (semanticGates true s 1 1) (targetAllows s 1 1) (fun _ => true) lines with
  | none => "REFUSE"
  | some granted => "GRANT:" ++ String.intercalate "," (granted.map (·.identity.repr))

def emit (c : Case) : IO Unit :=
  IO.println s!"{c.name}|{String.intercalate "," (trace c.policies 1 1)}|{outcome c.policies}"

end Differential

def main : IO Unit := Differential.cases.forM Differential.emit
