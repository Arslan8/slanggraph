/-!
# Language-sandbox route model

A finite model of the original straight-line execution language and of the Python checker
`language_verification.derive_program`. The checker here mirrors that function
rule for rule; `Controls.lean` checks agreement on programs exported from the
real Python lowering. The extended control-flow effect projection is in
`LanguageEffects.lean`; this value/type model does not cover loops.

Threat model (docs/security/threat-model.md): the interpreter, registered
terminals and admission code are trusted. The theorems therefore concern the
checker and the intended evaluation semantics, not the Python implementation.

Main result (`checked_program_calls_only_registered`): if the checker accepts a
program, every terminal it calls during evaluation is registered.
-/

namespace LanguageRoute

/-- Type kinds tracked by the checker (`_DATA`). -/
structure Ty where
  str : Bool := false
  int : Bool := false
  float : Bool := false
  bool : Bool := false
  none : Bool := false
  dict : Bool := false
  deriving DecidableEq, Repr

namespace Ty
def union (a b : Ty) : Ty :=
  ⟨a.str || b.str, a.int || b.int, a.float || b.float, a.bool || b.bool,
   a.none || b.none, a.dict || b.dict⟩
def empty : Ty := {}
def S : Ty := { str := true }
def B : Ty := { bool := true }
def N : Ty := { none := true }
end Ty

/-- Scalar kinds a terminal parameter may declare (`_SCALARS`). -/
inductive Kind | str | int | float | bool | none
  deriving DecidableEq, Repr

def Kind.ty : Kind → Ty
  | .str => { str := true } | .int => { int := true }
  | .float => { float := true } | .bool => { bool := true }
  | .none => { none := true }

/-- Inert runtime data. Capabilities are not representable. -/
inductive Val
  | str (s : String) | int (i : Int) | float (repr : String) | bool (b : Bool) | none
  deriving DecidableEq, Repr

def Val.ty : Val → Ty
  | .str _ => Ty.S | .int _ => { int := true } | .float _ => { float := true }
  | .bool _ => Ty.B | .none => Ty.N

structure Contract where
  params : List (String × Kind)
  result : Ty
  deriving Repr

abbrev Contracts := List (String × Contract)
abbrev TyEnv := List (String × Ty)

def lookup {α} (k : String) : List (String × α) → Option α
  | [] => none
  | (k', v) :: rest => if k = k' then some v else lookup k rest

def update {α} (k : String) (v : α) : List (String × α) → List (String × α)
  | [] => [(k, v)]
  | (k', v') :: rest => if k = k' then (k, v) :: rest else (k', v') :: update k v rest

inductive Expr
  | const (v : Val)
  | local (x : String)
  | join (parts : List Expr)
  | compare (eq : Bool) (l r : Expr)
  | call (f : String) (args : List Expr) (kws : List (String × Expr))
  deriving Repr

inductive Stmt
  | ret (e : Expr)
  | expr (e : Expr)
  | assign (names : List String) (e : Expr)
  | ite (c : Expr) (t f : List Stmt)
  deriving Repr

/-! ## Call-argument rule (the `call` branch's arity/keyword/type checks) -/

/-- Bind positional types to parameter names; refuse surplus arguments. -/
def bindPositional : List (String × Kind) → List Ty → Option (List (String × Ty))
  | _, [] => some []
  | [], _ :: _ => none
  | (n, _) :: ps, t :: ts => (bindPositional ps ts).map ((n, t) :: ·)

/-- Add keyword types; refuse duplicates and unknown parameter names. -/
def bindKeywords (params : List (String × Kind)) :
    List (String × Ty) → List (String × Ty) → Option (List (String × Ty))
  | bound, [] => some bound
  | bound, (n, t) :: ks =>
    if (lookup n bound).isSome || (lookup n params).isNone then none
    else bindKeywords params (bound ++ [(n, t)]) ks

def callOk (c : Contract) (args : List Ty) (kws : List (String × Ty)) : Bool :=
  match bindPositional c.params args with
  | none => false
  | some pos =>
    match bindKeywords c.params pos kws with
    | none => false
    | some bound =>
      bound.length == c.params.length &&
      c.params.all (fun (n, k) => lookup n bound == some k.ty)

/-! ## Checker -/

mutual
def checkExpr (C : Contracts) (Γ : TyEnv) : Expr → Option Ty
  | .const v => some v.ty
  | .local x => lookup x Γ
  | .join ps =>
    match checkList C Γ ps with
    | some ts => if ts.all (· == Ty.S) then some Ty.S else none
    | none => none
  | .compare _ l r =>
    match checkExpr C Γ l, checkExpr C Γ r with
    | some a, some b => if a == Ty.S && b == Ty.S then some Ty.B else none
    | _, _ => none
  | .call f args kws =>
    match lookup f C with
    | none => none
    | some c =>
      match checkList C Γ args, checkKws C Γ kws with
      | some ats, some kts => if callOk c ats kts then some c.result else none
      | _, _ => none
def checkList (C : Contracts) (Γ : TyEnv) : List Expr → Option (List Ty)
  | [] => some []
  | e :: es =>
    match checkExpr C Γ e, checkList C Γ es with
    | some t, some ts => some (t :: ts)
    | _, _ => none
def checkKws (C : Contracts) (Γ : TyEnv) : List (String × Expr) → Option (List (String × Ty))
  | [] => some []
  | (n, e) :: ks =>
    match checkExpr C Γ e, checkKws C Γ ks with
    | some t, some ts => some ((n, t) :: ts)
    | _, _ => none
end

/-- Intersection of keys with union of types (the `if` merge rule). -/
def mergeEnv (l r : TyEnv) : TyEnv :=
  l.filterMap fun (n, t) => (lookup n r).map fun u => (n, t.union u)

def assignAll (names : List String) (t : Ty) (Γ : TyEnv) : TyEnv :=
  names.foldl (fun g n => update n t g) Γ

mutual
/-- Returns `(environment, returned, result types)`, like `statements`. -/
def checkStmts (C : Contracts) : TyEnv → List Stmt → Option (TyEnv × Bool × Ty)
  | Γ, [] => some (Γ, false, Ty.empty)
  | Γ, s :: ss =>
    match checkStmt C Γ s with
    | none => none
    | some x =>
      match checkStmts C x.1 ss with
      | none => none
      | some y => some (y.1, x.2.1 || y.2.1, x.2.2.union y.2.2)
def checkStmt (C : Contracts) : TyEnv → Stmt → Option (TyEnv × Bool × Ty)
  | Γ, .ret e => (checkExpr C Γ e).map fun t => (Γ, true, t)
  | Γ, .expr e => (checkExpr C Γ e).map fun _ => (Γ, false, Ty.empty)
  | Γ, .assign ns e => (checkExpr C Γ e).map fun t => (assignAll ns t Γ, false, Ty.empty)
  | Γ, .ite c t f =>
    match checkExpr C Γ c with
    | some k =>
      if k == Ty.B then
        match checkStmts C Γ t, checkStmts C Γ f with
        | some x, some y =>
          let env :=
            if x.2.1 && !y.2.1 then y.1 else if y.2.1 && !x.2.1 then x.1 else mergeEnv x.1 y.1
          some (env, x.2.1 && y.2.1, x.2.2.union y.2.2)
        | _, _ => none
      else none
    | none => none
end

/-- Parameters are bound as strings (`derive_program`'s initial environment). -/
def checkProgram (C : Contracts) (params : List String) (body : List Stmt) : Option Ty :=
  match checkStmts C (params.map fun p => (p, Ty.S)) body with
  | some (_, returned, t) => some (if returned then t else t.union Ty.N)
  | none => none

/-! ## Syntactic call sites -/

mutual
def callsExpr : Expr → List String
  | .const _ => [] | .local _ => []
  | .join ps => callsList ps
  | .compare _ l r => callsExpr l ++ callsExpr r
  | .call f args kws => f :: (callsList args ++ callsKws kws)
def callsList : List Expr → List String
  | [] => [] | e :: es => callsExpr e ++ callsList es
def callsKws : List (String × Expr) → List String
  | [] => [] | (_, e) :: ks => callsExpr e ++ callsKws ks
end

mutual
def callsStmt : Stmt → List String
  | .ret e => callsExpr e | .expr e => callsExpr e | .assign _ e => callsExpr e
  | .ite c t f => callsExpr c ++ callsStmts t ++ callsStmts f
def callsStmts : List Stmt → List String
  | [] => [] | s :: ss => callsStmt s ++ callsStmts ss
end

/-! ## Static theorem: every call site of an accepted program is registered -/

mutual
theorem checkExpr_calls_registered (C : Contracts) (Γ : TyEnv) :
    ∀ (e : Expr) (t : Ty), checkExpr C Γ e = some t → ∀ f ∈ callsExpr e, (lookup f C).isSome
  | .const _, _, _, f, hf => by simp [callsExpr] at hf
  | .local _, _, _, f, hf => by simp [callsExpr] at hf
  | .join ps, t, h, f, hf => by
    simp only [checkExpr] at h
    split at h
    · rename_i ts hts
      exact checkList_calls_registered C Γ ps ts hts f (by simpa [callsExpr] using hf)
    · simp at h
  | .compare _ l r, t, h, f, hf => by
    simp only [checkExpr] at h
    split at h
    · rename_i a b ha hb
      simp only [callsExpr, List.mem_append] at hf
      rcases hf with hf | hf
      · exact checkExpr_calls_registered C Γ l a ha f hf
      · exact checkExpr_calls_registered C Γ r b hb f hf
    · simp at h
  | .call g args kws, t, h, f, hf => by
    simp only [checkExpr] at h
    split at h
    · simp at h
    · rename_i c hc
      split at h
      · rename_i ats kts ha hk
        simp only [callsExpr, List.mem_cons, List.mem_append] at hf
        rcases hf with rfl | hf | hf
        · simp [hc]
        · exact checkList_calls_registered C Γ args ats ha f hf
        · exact checkKws_calls_registered C Γ kws kts hk f hf
      · simp at h
theorem checkList_calls_registered (C : Contracts) (Γ : TyEnv) :
    ∀ (es : List Expr) (ts : List Ty), checkList C Γ es = some ts →
      ∀ f ∈ callsList es, (lookup f C).isSome
  | [], _, _, f, hf => by simp [callsList] at hf
  | e :: es, ts, h, f, hf => by
    simp only [checkList] at h
    split at h
    · rename_i t ts' he hes
      simp only [callsList, List.mem_append] at hf
      rcases hf with hf | hf
      · exact checkExpr_calls_registered C Γ e t he f hf
      · exact checkList_calls_registered C Γ es ts' hes f hf
    · simp at h
theorem checkKws_calls_registered (C : Contracts) (Γ : TyEnv) :
    ∀ (ks : List (String × Expr)) (ts : List (String × Ty)), checkKws C Γ ks = some ts →
      ∀ f ∈ callsKws ks, (lookup f C).isSome
  | [], _, _, f, hf => by simp [callsKws] at hf
  | (n, e) :: ks, ts, h, f, hf => by
    simp only [checkKws] at h
    split at h
    · rename_i t ts' he hks
      simp only [callsKws, List.mem_append] at hf
      rcases hf with hf | hf
      · exact checkExpr_calls_registered C Γ e t he f hf
      · exact checkKws_calls_registered C Γ ks ts' hks f hf
    · simp at h
end

mutual
theorem checkStmt_calls_registered (C : Contracts) :
    ∀ (Γ : TyEnv) (s : Stmt) (r : TyEnv × Bool × Ty), checkStmt C Γ s = some r →
      ∀ f ∈ callsStmt s, (lookup f C).isSome
  | Γ, .ret e, r, h, f, hf => by
    simp only [checkStmt, Option.map_eq_some_iff] at h
    obtain ⟨t, ht, _⟩ := h
    exact checkExpr_calls_registered C Γ e t ht f (by simpa [callsStmt] using hf)
  | Γ, .expr e, r, h, f, hf => by
    simp only [checkStmt, Option.map_eq_some_iff] at h
    obtain ⟨t, ht, _⟩ := h
    exact checkExpr_calls_registered C Γ e t ht f (by simpa [callsStmt] using hf)
  | Γ, .assign _ e, r, h, f, hf => by
    simp only [checkStmt, Option.map_eq_some_iff] at h
    obtain ⟨t, ht, _⟩ := h
    exact checkExpr_calls_registered C Γ e t ht f (by simpa [callsStmt] using hf)
  | Γ, .ite c tb fb, r, h, f, hf => by
    simp only [checkStmt] at h
    split at h
    · rename_i k hk
      split at h
      · split at h
        · rename_i a b hl hr
          simp only [callsStmt, List.mem_append] at hf
          rcases hf with (hf | hf) | hf
          · exact checkExpr_calls_registered C Γ c k hk f hf
          · exact checkStmts_calls_registered C Γ tb a hl f hf
          · exact checkStmts_calls_registered C Γ fb b hr f hf
        · simp at h
      · simp at h
    · simp at h
theorem checkStmts_calls_registered (C : Contracts) :
    ∀ (Γ : TyEnv) (ss : List Stmt) (r : TyEnv × Bool × Ty), checkStmts C Γ ss = some r →
      ∀ f ∈ callsStmts ss, (lookup f C).isSome
  | _, [], _, _, f, hf => by simp [callsStmts] at hf
  | Γ, s :: ss, r, h, f, hf => by
    simp only [checkStmts] at h
    split at h
    · simp at h
    · rename_i r1 h1
      split at h
      · simp at h
      · rename_i r2 h2
        simp only [callsStmts, List.mem_append] at hf
        rcases hf with hf | hf
        · exact checkStmt_calls_registered C Γ s _ h1 f hf
        · exact checkStmts_calls_registered C r1.1 ss r2 h2 f hf
end

/-! ## Evaluation semantics with an effect trace -/

/-- Terminals are arbitrary (trusted) functions returning inert data. -/
abbrev Oracle := String → List Val → List (String × Val) → Val
abbrev Env := List (String × Val)

def strOf : Val → Option String
  | .str s => some s | _ => none

mutual
def evalExpr (O : Oracle) (ρ : Env) : Expr → Option (Val × List String)
  | .const v => some (v, [])
  | .local x => (lookup x ρ).map fun v => (v, [])
  | .join ps =>
    match evalList O ρ ps with
    | some (vs, tr) =>
      match vs.mapM strOf with
      | some ss => some (.str (String.join ss), tr)
      | none => none
    | none => none
  | .compare eq l r =>
    match evalExpr O ρ l, evalExpr O ρ r with
    | some (.str a, t1), some (.str b, t2) => some (.bool (if eq then a == b else a != b), t1 ++ t2)
    | _, _ => none
  | .call f args kws =>
    match evalList O ρ args, evalKws O ρ kws with
    | some (vs, t1), some (kvs, t2) => some (O f vs kvs, t1 ++ t2 ++ [f])
    | _, _ => none
def evalList (O : Oracle) (ρ : Env) : List Expr → Option (List Val × List String)
  | [] => some ([], [])
  | e :: es =>
    match evalExpr O ρ e, evalList O ρ es with
    | some (v, t1), some (vs, t2) => some (v :: vs, t1 ++ t2)
    | _, _ => none
def evalKws (O : Oracle) (ρ : Env) : List (String × Expr) → Option (List (String × Val) × List String)
  | [] => some ([], [])
  | (n, e) :: ks =>
    match evalExpr O ρ e, evalKws O ρ ks with
    | some (v, t1), some (kvs, t2) => some ((n, v) :: kvs, t1 ++ t2)
    | _, _ => none
end

inductive Outcome | cont (ρ : Env) | ret (v : Val)

mutual
def evalStmts (O : Oracle) : Env → List Stmt → Option (Outcome × List String)
  | ρ, [] => some (.cont ρ, [])
  | ρ, s :: ss =>
    match evalStmt O ρ s with
    | some (.ret v, t) => some (.ret v, t)
    | some (.cont ρ', t1) =>
      match evalStmts O ρ' ss with
      | some (o, t2) => some (o, t1 ++ t2)
      | none => none
    | none => none
def evalStmt (O : Oracle) : Env → Stmt → Option (Outcome × List String)
  | ρ, .ret e => (evalExpr O ρ e).map fun (v, t) => (.ret v, t)
  | ρ, .expr e => (evalExpr O ρ e).map fun (_, t) => (.cont ρ, t)
  | ρ, .assign ns e =>
    (evalExpr O ρ e).map fun (v, t) => (.cont (ns.foldl (fun g n => update n v g) ρ), t)
  | ρ, .ite c tb fb =>
    match evalExpr O ρ c with
    | some (.bool true, t1) =>
      match evalStmts O ρ tb with
      | some (o, t2) => some (o, t1 ++ t2)
      | none => none
    | some (.bool false, t1) =>
      match evalStmts O ρ fb with
      | some (o, t2) => some (o, t1 ++ t2)
      | none => none
    | _ => none
end

/-! ## Dynamic theorem: every executed call is a syntactic call site -/

mutual
theorem evalExpr_trace (O : Oracle) (ρ : Env) :
    ∀ (e : Expr) (v : Val) (tr : List String), evalExpr O ρ e = some (v, tr) →
      ∀ f ∈ tr, f ∈ callsExpr e
  | .const _, v, tr, h, f, hf => by
    simp only [evalExpr, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨_, rfl⟩ := h; simp at hf
  | .local x, v, tr, h, f, hf => by
    simp only [evalExpr, Option.map_eq_some_iff, Prod.mk.injEq] at h
    obtain ⟨_, _, _, rfl⟩ := h; simp at hf
  | .join ps, v, tr, h, f, hf => by
    simp only [evalExpr] at h
    split at h
    · rename_i vs t1 hps
      split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨_, rfl⟩ := h
        exact by simpa [callsExpr] using evalList_trace O ρ ps vs _ hps f hf
      · simp at h
    · simp at h
  | .compare eq l r, v, tr, h, f, hf => by
    simp only [evalExpr] at h
    split at h
    · rename_i a t1 b t2 hl hr
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      simp only [callsExpr, List.mem_append] at hf ⊢
      rcases hf with hf | hf
      · exact Or.inl (evalExpr_trace O ρ l _ _ hl f hf)
      · exact Or.inr (evalExpr_trace O ρ r _ _ hr f hf)
    · simp at h
  | .call g args kws, v, tr, h, f, hf => by
    simp only [evalExpr] at h
    split at h
    · rename_i vs t1 kvs t2 ha hk
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      simp only [callsExpr, List.mem_cons, List.mem_append] at hf ⊢
      rcases hf with (hf | hf) | hf
      · exact Or.inr (Or.inl (evalList_trace O ρ args _ _ ha f hf))
      · exact Or.inr (Or.inr (evalKws_trace O ρ kws _ _ hk f hf))
      · simp at hf; exact Or.inl hf
    · simp at h
theorem evalList_trace (O : Oracle) (ρ : Env) :
    ∀ (es : List Expr) (vs : List Val) (tr : List String), evalList O ρ es = some (vs, tr) →
      ∀ f ∈ tr, f ∈ callsList es
  | [], vs, tr, h, f, hf => by
    simp only [evalList, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨_, rfl⟩ := h; simp at hf
  | e :: es, vs, tr, h, f, hf => by
    simp only [evalList] at h
    split at h
    · rename_i v t1 vs' t2 he hes
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      simp only [callsList, List.mem_append] at hf ⊢
      rcases hf with hf | hf
      · exact Or.inl (evalExpr_trace O ρ e _ _ he f hf)
      · exact Or.inr (evalList_trace O ρ es _ _ hes f hf)
    · simp at h
theorem evalKws_trace (O : Oracle) (ρ : Env) :
    ∀ (ks : List (String × Expr)) (kvs : List (String × Val)) (tr : List String),
      evalKws O ρ ks = some (kvs, tr) → ∀ f ∈ tr, f ∈ callsKws ks
  | [], kvs, tr, h, f, hf => by
    simp only [evalKws, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨_, rfl⟩ := h; simp at hf
  | (n, e) :: ks, kvs, tr, h, f, hf => by
    simp only [evalKws] at h
    split at h
    · rename_i v t1 kvs' t2 he hks
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      simp only [callsKws, List.mem_append] at hf ⊢
      rcases hf with hf | hf
      · exact Or.inl (evalExpr_trace O ρ e _ _ he f hf)
      · exact Or.inr (evalKws_trace O ρ ks _ _ hks f hf)
    · simp at h
end

mutual
theorem evalStmt_trace (O : Oracle) :
    ∀ (ρ : Env) (s : Stmt) (o : Outcome) (tr : List String), evalStmt O ρ s = some (o, tr) →
      ∀ f ∈ tr, f ∈ callsStmt s
  | ρ, .ret e, o, tr, h, f, hf => by
    simp only [evalStmt, Option.map_eq_some_iff, Prod.exists, Prod.mk.injEq] at h
    obtain ⟨v, t, he, _, rfl⟩ := h
    exact by simpa [callsStmt] using evalExpr_trace O ρ e v t he f hf
  | ρ, .expr e, o, tr, h, f, hf => by
    simp only [evalStmt, Option.map_eq_some_iff, Prod.exists, Prod.mk.injEq] at h
    obtain ⟨v, t, he, _, rfl⟩ := h
    exact by simpa [callsStmt] using evalExpr_trace O ρ e v t he f hf
  | ρ, .assign ns e, o, tr, h, f, hf => by
    simp only [evalStmt, Option.map_eq_some_iff, Prod.exists, Prod.mk.injEq] at h
    obtain ⟨v, t, he, _, rfl⟩ := h
    exact by simpa [callsStmt] using evalExpr_trace O ρ e v t he f hf
  | ρ, .ite c tb fb, o, tr, h, f, hf => by
    simp only [evalStmt] at h
    split at h
    · rename_i t1 hc
      split at h
      · rename_i o' t2 hb
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨_, rfl⟩ := h
        simp only [callsStmt, List.mem_append] at hf ⊢
        rcases hf with hf | hf
        · exact Or.inl (Or.inl (evalExpr_trace O ρ c _ _ hc f hf))
        · exact Or.inl (Or.inr (evalStmts_trace O ρ tb _ _ hb f hf))
      · simp at h
    · rename_i t1 hc
      split at h
      · rename_i o' t2 hb
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨_, rfl⟩ := h
        simp only [callsStmt, List.mem_append] at hf ⊢
        rcases hf with hf | hf
        · exact Or.inl (Or.inl (evalExpr_trace O ρ c _ _ hc f hf))
        · exact Or.inr (evalStmts_trace O ρ fb _ _ hb f hf)
      · simp at h
    · simp at h
theorem evalStmts_trace (O : Oracle) :
    ∀ (ρ : Env) (ss : List Stmt) (o : Outcome) (tr : List String),
      evalStmts O ρ ss = some (o, tr) → ∀ f ∈ tr, f ∈ callsStmts ss
  | ρ, [], o, tr, h, f, hf => by
    simp only [evalStmts, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨_, rfl⟩ := h; simp at hf
  | ρ, s :: ss, o, tr, h, f, hf => by
    simp only [evalStmts] at h
    split at h
    · rename_i v t hs
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      exact List.mem_append_left _ (evalStmt_trace O ρ s _ _ hs f hf)
    · rename_i ρ' t1 hs
      split at h
      · rename_i o' t2 hss
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨_, rfl⟩ := h
        simp only [callsStmts, List.mem_append] at hf ⊢
        rcases hf with hf | hf
        · exact Or.inl (evalStmt_trace O ρ s _ _ hs f hf)
        · exact Or.inr (evalStmts_trace O ρ' ss _ _ hss f hf)
      · simp at h
    · simp at h
end

/-! ## Main theorem -/

/-- If the checker accepts a program, every terminal it calls during any
evaluation, for any terminal behavior and any string arguments, is registered. -/
theorem checked_program_calls_only_registered
    (C : Contracts) (params : List String) (body : List Stmt) (t : Ty)
    (hcheck : checkProgram C params body = some t)
    (O : Oracle) (ρ : Env) (o : Outcome) (tr : List String)
    (heval : evalStmts O ρ body = some (o, tr)) :
    ∀ f ∈ tr, (lookup f C).isSome := by
  intro f hf
  unfold checkProgram at hcheck
  split at hcheck
  · rename_i r hr
    exact checkStmts_calls_registered C _ body _ hr f (evalStmts_trace O ρ body o tr heval f hf)
  · simp at hcheck

/-- An unregistered terminal is never accepted. -/
theorem unregistered_call_refused (C : Contracts) (Γ : TyEnv) (f : String)
    (args : List Expr) (kws : List (String × Expr)) (h : lookup f C = none) :
    checkExpr C Γ (.call f args kws) = none := by
  simp [checkExpr, h]

end LanguageRoute
