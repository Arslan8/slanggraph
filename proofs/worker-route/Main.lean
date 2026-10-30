import Lean
import WorkerRoute
import ReceiptCoverage
import GrantCoverage

/-! Typed JSON transport for the executable core. Decoder/compiler/IO correctness
are explicit bridge premises, not consequences of the WorkerRoute theorems. -/
open Lean WorkerRoute

/- The parser uses Lean's Parsec primitives, but checks keys before building a
JSON map and rejects invalid surrogate escapes rather than replacing them.
String escape handling is adapted from Lean/Data/Json/Parser.lean (Apache 2.0,
copyright 2019 Gabriel Ebner; authors Gabriel Ebner and Marc Huisinga). -/
namespace ProtocolParser
open Std.Internal.Parsec Std.Internal.Parsec.String

private def escapedChar : Parser Char := do
  match ← any with
  | '\\' => return '\\'
  | '"' => return '"'
  | '/' => return '/'
  | 'b' => return '\x08'
  | 'f' => return '\x0c'
  | 'n' => return '\n'
  | 'r' => return '\x0d'
  | 't' => return '\t'
  | 'u' =>
    let u1 ← Json.Parser.hexChar; let u2 ← Json.Parser.hexChar
    let u3 ← Json.Parser.hexChar; let u4 ← Json.Parser.hexChar
    let val := (u1 <<< 12) ||| (u2 <<< 8) ||| (u3 <<< 4) ||| u4
    if h : val < 0xD800 then
      return ⟨val.toUInt32, Or.inl h⟩
    else if h' : val < 0xE000 then
      if val < 0xDC00 then
        Json.Parser.finishSurrogatePair val
      else
        fail "unpaired surrogate"
    else
      return ⟨val.toUInt32, Or.inr ⟨Nat.not_lt.mp h', Nat.lt_trans val.toFin.isLt (by decide)⟩⟩
  | _ => fail "invalid string escape"

private partial def stringCore (acc : String) : Parser String := do
  let c ← any
  if c == '"' then
    return acc
  else if acc.length ≥ 4096 then
    fail "string budget"
  else if c == '\\' then
    stringCore (acc.push (← escapedChar))
  else if c.val ≥ 0x20 then
    stringCore (acc.push c)
  else
    fail "invalid string character"

mutual
  private partial def arrayCore (depth : Nat) (acc : Array Json) : Parser Json := do
    if acc.size ≥ 256 then fail "array budget"
    let item ← value depth
    let acc := acc.push item
    match ← any with
    | ']' => ws; return .arr acc
    | ',' => ws; arrayCore depth acc
    | _ => fail "invalid array delimiter"

  private partial def objectCore (depth : Nat) (count : Nat)
      (acc : Std.TreeMap.Raw String Json) : Parser Json := do
    if count ≥ 16 then fail "object budget"
    skipChar '"'
    let key ← stringCore ""
    if acc.contains key then fail "duplicate object key"
    ws; skipChar ':'; ws
    let item ← value depth
    let acc := acc.insert key item
    match ← any with
    | '}' => ws; return .obj acc
    | ',' => ws; objectCore depth (count + 1) acc
    | _ => fail "invalid object delimiter"

  private partial def value (depth : Nat) : Parser Json := do
    if depth > 12 then fail "nesting budget"
    match ← any with
    | '"' =>
      let result ← stringCore ""
      ws
      return .str result
    | '[' =>
      ws
      if (← peek!) == ']' then
        skip; ws; return .arr #[]
      arrayCore (depth + 1) #[]
    | '{' =>
      ws
      if (← peek!) == '}' then
        skip; ws; return .obj ∅
      objectCore (depth + 1) 0 ∅
    | 't' => skipString "rue"; ws; return .bool true
    | 'f' => skipString "alse"; ws; return .bool false
    | _ => fail "unsupported protocol value"
end

def parse (input : String) : Except String Json :=
  Parser.run (do ws; let result ← value 0; eof; return result) input
end ProtocolParser

private partial def readInput (stream : IO.FS.Stream) (acc : ByteArray := .empty) :
    IO (Option String) := do
  let chunk ← stream.read 4096
  if acc.size + chunk.size > 1048576 then return none
  let acc := acc ++ chunk
  if chunk.isEmpty then return String.fromUTF8? acc
  readInput stream acc

private def fields (value : Json) (names : List String) : Except String Unit := do
  let object ← value.getObj?
  let keys := object.toList.map Prod.fst
  unless keys.length == names.length && names.all keys.contains do
    throw "unexpected fields"

private def textField (value : Json) (name : String) : Except String String := do
  let result ← (← value.getObjVal? name).getStr?
  unless !result.isEmpty && result.length ≤ 4096 do throw "invalid identity"
  return result

private def optionalIdentity (value : Json) (name : String) : Except String String := do
  let result ← (← value.getObjVal? name).getStr?
  unless result.length ≤ 4096 do throw "invalid optional identity"
  return result

private def textArray (value : Json) (name : String) : Except String (List String) := do
  let items ← (← value.getObjVal? name).getArr?
  unless items.size ≤ 256 do throw "array budget"
  items.toList.mapM fun item => do
    let text ← item.getStr?
    unless !text.isEmpty && text.length ≤ 4096 do throw "invalid array identity"
    return text

private def recordArray {α : Type} (value : Json) (name : String)
    (decode : Json → Except String α) : Except String (List α) := do
  let items ← (← value.getObjVal? name).getArr?
  unless items.size ≤ 256 do throw "array budget"
  items.toList.mapM decode

private def booleanField (value : Json) (name : String) : Except String Bool := do
  (← value.getObjVal? name).getBool?

private def binding (value : Json) : Except String Binding := do
  fields value ["principal", "session", "call", "tool", "artifact", "grant", "plan", "nonce", "host", "context", "deployment", "runtime", "intent", "policy", "worker"]
  let worker ← value.getObjVal? "worker"
  fields worker ["pid", "startTime", "bootId"]
  return {
    principal := ← textField value "principal"
    session := ← textField value "session"
    call := ← textField value "call"
    tool := ← textField value "tool"
    artifact := ← textField value "artifact"
    grant := ← textField value "grant"
    plan := ← textField value "plan"
    nonce := ← textField value "nonce"
    host := ← textField value "host"
    context := ← textField value "context"
    deployment := ← optionalIdentity value "deployment"
    runtime := ← optionalIdentity value "runtime"
    intent := ← textField value "intent"
    policy := ← textField value "policy"
    worker := {
      pid := ← textField worker "pid"
      startTime := ← textField worker "startTime"
      bootId := ← textField worker "bootId"
    }
  }

private def mode (value : Json) : Except String ReceiptCoverage.Mode := do
  match ← value.getStr? with
  | "enforced" => return .enforced
  | "degraded" => return .degraded
  | _ => throw "unsupported mode"

private def support (value : Json) : Except String ReceiptCoverage.Support := do
  match ← value.getStr? with
  | "exact" => return .exact
  | "tightened" => return .tightened
  | _ => throw "unsupported assignment"

private def assignment (value : Json) : Except String ReceiptCoverage.Assignment := do
  fields value ["obligation", "adapter", "support"]
  return {
    obligation := ← textField value "obligation"
    adapter := ← textField value "adapter"
    support := ← support (← value.getObjVal? "support")
  }

private def nativePlan (value : Json) : Except String ReceiptCoverage.NativePlan := do
  fields value ["adapter", "digest", "obligations"]
  return {
    adapter := ← textField value "adapter"
    digest := ← textField value "digest"
    obligations := ← textArray value "obligations"
  }

private def evidence (value : Json) : Except String ReceiptCoverage.Evidence := do
  fields value ["adapter", "digest", "context", "nonce", "obligations"]
  return {
    adapter := ← textField value "adapter"
    digest := ← textField value "digest"
    context := ← textField value "context"
    nonce := ← textField value "nonce"
    obligations := ← textArray value "obligations"
  }

private def plan (value : Json) : Except String ReceiptCoverage.Plan := do
  fields value ["grant", "host", "digest", "mode", "assignments", "nativePlans", "waived", "removedWants"]
  return {
    grant := ← textField value "grant"
    host := ← textField value "host"
    digest := ← textField value "digest"
    mode := ← mode (← value.getObjVal? "mode")
    assignments := ← recordArray value "assignments" assignment
    nativePlans := ← recordArray value "nativePlans" nativePlan
    waived := ← textArray value "waived"
    removedWants := ← textArray value "removedWants"
  }

private def receipt (value : Json) : Except String ReceiptCoverage.Receipt := do
  fields value ["grant", "plan", "host", "context", "nonce", "artifact", "deployment", "runtime", "mode", "activated", "removedWants", "evidence"]
  return {
    grant := ← textField value "grant"
    plan := ← textField value "plan"
    host := ← textField value "host"
    context := ← textField value "context"
    nonce := ← textField value "nonce"
    artifact := ← textField value "artifact"
    deployment := ← optionalIdentity value "deployment"
    runtime := ← optionalIdentity value "runtime"
    mode := ← mode (← value.getObjVal? "mode")
    activated := ← textArray value "activated"
    removedWants := ← textArray value "removedWants"
    evidence := ← recordArray value "evidence" evidence
  }

private def signedInteger (text : String) : Except String Int := do
  let (negative, digits) := match text.toList with
    | '-' :: rest => (true, rest)
    | rest => (false, rest)
  match digits with
  | [] => throw "empty integer"
  | '0' :: rest =>
    unless !negative && rest.isEmpty do throw "noncanonical zero"
  | first :: _ =>
    unless first ≥ '1' && first ≤ '9' do throw "noncanonical integer"
  let magnitude ← digits.foldlM (init := 0) fun acc digit => do
    unless digit ≥ '0' && digit ≤ '9' do throw "invalid decimal digit"
    return acc * 10 + (digit.toNat - '0'.toNat)
  let result := if negative then -(Int.ofNat magnitude) else Int.ofNat magnitude
  unless result ≥ -9223372036854775808 && result ≤ 9223372036854775807 do
    throw "integer budget"
  return result

private partial def condition (value : Json) : Except String GrantCoverage.Value := do
  match ← textField value "kind" with
  | "null" =>
    fields value ["kind"]
    return .null
  | "bool" =>
    fields value ["kind", "value"]
    return .bool (← booleanField value "value")
  | "int" =>
    fields value ["kind", "value"]
    return .int (← signedInteger (← textField value "value"))
  | "text" =>
    fields value ["kind", "value"]
    return .text (← optionalIdentity value "value")
  | "sequence" =>
    fields value ["kind", "value"]
    let values ← recordArray value "value" condition
    return .sequence (values.foldr GrantCoverage.Values.cons .nil)
  | "map" =>
    fields value ["kind", "value"]
    let entries ← recordArray value "value" fun entry => do
      fields entry ["key", "value"]
      return (← optionalIdentity entry "key", ← condition (← entry.getObjVal? "value"))
    let mut previous : Option String := none
    for entry in entries do
      if let some key := previous then
        unless key < entry.1 do throw "noncanonical map keys"
      previous := some entry.1
    return .map (entries.foldr (fun entry rest => GrantCoverage.Entries.cons entry.1 entry.2 rest) .nil)
  | _ => throw "unsupported condition value"

private def conditions (value : Json) : Except String GrantCoverage.Value := do
  let result ← condition value
  match result with
  | .map _ => return result
  | _ => throw "conditions require a map"

private def domain (value : Json) : Except String GrantCoverage.Domain := do
  match ← value.getStr? with
  | "filesystem" => return .filesystem
  | "network" => return .network
  | "process" => return .process
  | "ipc" => return .ipc
  | "service" => return .service
  | "credential" => return .credential
  | "runtime" => return .runtime
  | "delegation" => return .delegation
  | "resource_limit" => return .resourceLimit
  | _ => throw "unsupported domain"

private def requirement (value : Json) : Except String GrantCoverage.Requirement := do
  match ← value.getStr? with
  | "need" => return .need
  | "want" => return .want
  | _ => throw "unsupported requirement"

private def obligationKind (value : Json) : Except String GrantCoverage.Kind := do
  match ← value.getStr? with
  | "operate" => return .operate
  | "deny_complement" => return .denyComplement
  | "bypass_prevention" => return .bypassPrevention
  | "credential_custody" => return .credentialCustody
  | "authenticated_channel" => return .authenticatedChannel
  | "resource_limit" => return .resourceLimit
  | "evidence" => return .evidence
  | _ => throw "unsupported obligation kind"

private def rule (value : Json) : Except String GrantCoverage.Rule := do
  fields value ["id", "domain", "operation", "selector", "conditions", "requirement", "provenance", "baseline"]
  return {
    id := ← textField value "id"
    domain := ← domain (← value.getObjVal? "domain")
    operation := ← textField value "operation"
    selector := ← textField value "selector"
    conditions := ← conditions (← value.getObjVal? "conditions")
    requirement := ← requirement (← value.getObjVal? "requirement")
    provenance := ← textArray value "provenance"
    baseline := ← booleanField value "baseline"
  }

private def grant (value : Json) : Except String GrantCoverage.Grant := do
  fields value ["principal", "session", "tool", "artifact", "call", "intent", "policy", "deployment", "runtime", "digest", "rules"]
  return {
    principal := ← textField value "principal"
    session := ← textField value "session"
    tool := ← textField value "tool"
    artifact := ← textField value "artifact"
    call := ← textField value "call"
    intent := ← textField value "intent"
    policy := ← textField value "policy"
    deployment := ← optionalIdentity value "deployment"
    runtime := ← optionalIdentity value "runtime"
    digest := ← textField value "digest"
    rules := ← recordArray value "rules" rule
  }

private def obligation (value : Json) : Except String GrantCoverage.Obligation := do
  fields value ["id", "rule", "kind", "domain", "operation", "selector", "conditions", "dependencies", "waivable"]
  return {
    id := ← textField value "id"
    rule := ← textField value "rule"
    kind := ← obligationKind (← value.getObjVal? "kind")
    domain := ← domain (← value.getObjVal? "domain")
    operation := ← textField value "operation"
    selector := ← textField value "selector"
    conditions := ← conditions (← value.getObjVal? "conditions")
    dependencies := ← textArray value "dependencies"
    waivable := ← booleanField value "waivable"
  }

private def certificate (value : Json) : Except String GrantCoverage.Certificate := do
  fields value ["grant", "obligations", "plan", "receipt"]
  return {
    grant := ← grant (← value.getObjVal? "grant")
    obligations := ← recordArray value "obligations" obligation
    coverage := {
      plan := ← plan (← value.getObjVal? "plan")
      receipt := ← receipt (← value.getObjVal? "receipt")
    }
  }

private def event (value : Json) : Except String Event := do
  match ← textField value "kind" with
  | "authorize" =>
    fields value ["kind", "binding", "authorized"]
    return .authorize (← binding (← value.getObjVal? "binding")) (← booleanField value "authorized")
  | "activate" =>
    fields value ["kind", "binding", "supported", "confirmed"]
    return .activate (← binding (← value.getObjVal? "binding"))
      (← booleanField value "supported") (← booleanField value "confirmed")
  | "go" =>
    fields value ["kind", "binding"]
    return .go (← binding (← value.getObjVal? "binding"))
  | "result" =>
    fields value ["kind", "binding", "accepted"]
    return .result (← binding (← value.getObjVal? "binding")) (← booleanField value "accepted")
  | "cleanup" =>
    fields value ["kind", "confirmed"]
    return .cleanup (← booleanField value "confirmed")
  | "cancel" =>
    fields value ["kind"]
    return .cancel
  | _ => throw "unknown event"

private def phaseName : Phase → String
  | .prepared => "prepared"
  | .authorized => "authorized"
  | .activated => "activated"
  | .running => "running"
  | .resultReady => "resultReady"
  | .ready => "ready"
  | .refused => "refused"

private def requestPhase (value : Json) : Except String String := do
  match ← textField value "kind" with
    | "grant" => do
      fields value ["protocol", "kind", "grant", "obligations"]
      let original ← grant (← value.getObjVal? "grant")
      let obligations ← recordArray value "obligations" obligation
      return if GrantCoverage.obligationsAccept original obligations then "grant_ready" else "refused"
    | "route" => do
      fields value ["protocol", "kind", "binding", "certificate", "events"]
      let original ← binding (← value.getObjVal? "binding")
      let certificate ← certificate (← value.getObjVal? "certificate")
      let events ← (← value.getObjVal? "events").getArr?
      unless events.size ≤ 32 do throw "event budget"
      let events ← events.toList.mapM event
      return phaseName (GrantCoverage.runCertified original certificate events).phase
    | _ => throw "unsupported request kind"

private def check (input : String) : Except String Json := do
  let value ← ProtocolParser.parse input
  unless (← textField value "protocol") == "worker-route-grant-v3" do
    throw "unsupported protocol"
  let phase ← requestPhase value
  return Json.mkObj [("protocol", toJson "worker-route-grant-v3"),
    ("schema", toJson (3 : Nat)), ("phase", toJson phase)]

/-- Native-library entry point. An empty response is a fail-closed parse or
    decision failure; successful responses use the exact CLI protocol. -/
@[export argus_worker_route_check]
def checkNative (input : String) : String :=
  match check input with
  | .error _ => ""
  | .ok response => response.compress

def main : IO UInt32 := do
  let some input ← readInput (← IO.getStdin) | return 2
  match check input with
  | .error _ => return 2
  | .ok response =>
    (← IO.getStdout).putStrLn response.compress
    return 0
