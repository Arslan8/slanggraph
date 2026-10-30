# Worker lifecycle, grant, and receipt decision core

This project implements a finite decision core in Lean 4.34.1. Protocol
`worker-route-grant-v3` requires the admitted filtered grant, the independently
compiled obligation inventory, a receipt certificate, and a matching lifecycle
trace. The selected synchronous Linux executor checks the grant before native
attestation and again at the worker boundary, then checks the full route before `GO` and after
confirmed cleanup. This is an implemented component, not a complete SGV901–903
proof or a proof of Python, compiler, decoder or operating-system correspondence.

## Executable contract

`WorkerRoute` defines `WorkerIdentity`, `Binding`, `Phase`, `State` and `Event`.
The binding contains principal, session, call, tool, artifact, grant, plan,
nonce, host, context, deployment, runtime, and worker PID/start time/boot ID.
Every identity-bearing event compares the complete binding. The useful route is
matching positive authorization, supported/confirmed activation, GO, an accepted
result, and confirmed cleanup, in exactly that order. Unexpected events,
mismatches, cancellation, false required facts and unknown cleanup refuse;
refusal is permanent. A fresh worker is not cleanup evidence.

`ReceiptCoverage` defines `Assignment`, `NativePlan`, `Evidence`, `Plan`,
`Receipt` and `Certificate`, with finite `Support` and `Mode` enums. Its checks are:

- `ValidAssignments`: nonempty assignments with unique nonempty obligation IDs
  and nonempty adapter owners; support is `exact` or `tightened`.
- `ValidPlans`: unique adapter IDs, exactly the assignment owners, with nonempty
  digests and nonempty, unique obligation lists exactly assigned to each adapter.
- `ValidEvidence`: exactly one row per native-plan adapter, matching digest,
  context, nonce and exact obligation IDs; row obligations are nonempty and unique.
- `ValidReceipt`: unique activated IDs equal both assignments and the evidence
  union; mode and the ordered `removedWants` list equal the plan's.
- `ValidWaivers`: unique nonempty waived IDs disjoint from assignments; mode is
  enforced exactly when there are no waivers, otherwise degraded.
- `BoundTo`: the plan's grant/host/digest and the receipt's
  grant/plan/host/context/nonce/artifact/deployment/runtime match the binding.

`SameIDs` compares membership in both directions; uniqueness is checked
separately. Row and obligation ordering is immaterial to coverage.
`removedWants` uses exact list equality, including order.

`GrantCoverage` defines the complete grant/rule/obligation records, including a
tagged recursive condition value that keeps booleans distinct from signed
integers. It derives one full-semantic obligation per grant rule plus nine fixed
default-deny domain complements. The v3 certificate requires exactly those
generated obligations: no missing, extra, duplicate, or semantically substituted
row is accepted. The selected route additionally requires the complete
assignment, activation, and evidence inventories to equal that generated set and
requires an enforced, waiver-free receipt.

`coverageAccept` decides `ValidCoverage`. `certificateValid` decides
`BoundTo ∧ ValidCoverage`. The CLI executes `runCertified`, which refuses an
invalid certificate before evaluating the lifecycle. `certifiedRoute` tests its
successful result. The abstract lifecycle-only `decideRoute` remains available
as a model definition; the v3 CLI does not use it as an alternative admission path.

## Checked statements

There are **89 public model theorems**: 30 in `WorkerRoute.lean`, 24 in
`ReceiptCoverage.lean`, and 35 in `GrantCoverage.lean`, plus private proof helpers.
The fixed audit selects 72 security-relevant theorems. Main results:

- `success_iff_exact_route` and `running_trace_exact` characterize the lifecycle
  full route and pre-GO prefix.
- `coverageAccept_iff` and `certificateValid_iff` connect the executable checks
  to the explicit coverage and binding predicates.
- `assignment_owner_unique`, `plan_evidence_unique` and
  `assignment_evidence_unique` establish unique ownership and coverage;
  the no-extra/no-missing theorems connect assignments, evidence and activated IDs.
- `useful_partition_certificate` and `useful_partition_route` construct valid
  certificates for arbitrary nonempty, disjoint multi-adapter partitions with
  authorized-as-input disjoint waiver lists. Their premises do not assume acceptance.
- `runCertified_running_exact` and `certifiedRoute_exact` characterize the
  combined pre-GO prefix and complete route by binding, coverage and exact events.
  `certifiedRoute_useful` proves the useful converse.
- `invalid_certificate_refuses_every_trace` and
  `runCertified_preserves_binding` prevent a different trace from bypassing
  certificate refusal or replacing the captured model binding.

The grant results cover the admitted v3 generator contract: complete rule fields,
one rule obligation per rule, and all nine complements. They do not prove the
earlier Python policy filter, grant provenance, digest preimages, or correspondence
between Python compilation and this generator. The receipt model permits valid
degraded certificates, but the selected Linux route requires enforced,
waiver-free activation. No theorem authorizes a waiver.

## Captured build and audit

For development, `lake build` builds both libraries and `workerRoute`. For
retained evidence, run from the repository root:

```sh
python3 proofs/worker-route/check.py --output /absolute/path/to/new-worker-audit
```

The same checked decision procedure can be exported as an inline native
library, eliminating per-transition process creation:

```sh
python3 proofs/worker-route/build_native.py \
  --lake /absolute/path/to/pinned/lake \
  --output /absolute/path/to/libargus_worker_route.so
```

The build emits a manifest containing the library, generated-code runtime, and
source digests. The Python bridge pins and loads both artifacts from sealed
memfds once, then invokes the decision procedure through the narrow C ABI. This
removes the per-decision executable copy, process launch, and response pipe. It
does not prove the Lean compiler, generated C, C shim, dynamic loader, or Python
FFI correspondence; those remain explicit trusted assumptions.

The directory must be new. The driver snapshots the sources and build
configuration, checks the `leanprover/lean4:v4.34.1` pin, builds in that snapshot,
and typechecks **72 fixed semantic obligations** in generated `KernelAudit.lean`.
It also checks full record constructor/projection witnesses, independent
expansions of the coverage and binding predicates, arbitrary constructive
partitions, and concrete multi-adapter and degraded positives. Five malformed
semantic controls must fail at their expected type errors. A theorem name alone
cannot satisfy this audit.

The driver records axiom dependencies and rejects custom security axioms. The
observed dependencies are Lean's standard `propext`, `Quot.sound` and
`Classical.choice`. Source hygiene rejects proof-bypass constructs; that scan is
not a Lean parser or a proof. The models use no `sorry` or `native_decide`.
The pinned toolchain's `leanchecker --fresh` must replay the audit. This is
Lean's own kernel, not an independent verifier implementation. Sources must
remain stable; commands, logs, failure reports, source snapshots, `.olean`
artifacts and executable bytes are retained. `--lake` selects the launcher;
`--timeout` bounds each subprocess. The driver runs its 20 self-tests, also
available with `python3 -m unittest discover -s proofs/worker-route -p test_check.py`.

The current [v3 audit](../../eval/campaigns/remediation-v2/raw/checks/codex-grant-lean-audit-v2/report.json)
passed the typed audit, all five controls, all driver tests and fresh kernel
replay with stable sources. Its binary SHA-256 is
`6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08`.
All source/runtime/compiler/decoder/OS refinement and `system_complete` flags
remain false. The earlier [v1 audit](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-formal-v3/report.json)
and [three native v1 executions](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-native-v5.json)
remain historical evidence; that executable is incompatible with the v2 bridge.

Separate current runtime observations record
[349 passing grant/bridge/integration tests](../../eval/campaigns/remediation-v2/raw/grant-integration-v1/grant-focused-final-v1.json)
and [3/3 direct native cases](../../eval/campaigns/remediation-v2/raw/grant-integration-v1/native-runtime-evidence.json)
against the audited v3 binary, with current source identities and binary bytes.
The native diagnostic also retains an observer-assisted 3/3 rerun. Its outer
Docker harness was explicitly unconfined; the inner production worker activated
bubblewrap, seccomp and resource limits. These finite observations do not change
the audit's unproved refinement flags or establish a new full application cohort.

## Wire and runtime boundary

The exact v3 route envelope contains `protocol`, `kind`, `binding`, `certificate`
and `events`; the certificate contains `grant`, `obligations`, `plan`, and
`receipt`. A separate preflight envelope contains `kind: "grant"`, the grant,
and obligations, and must return `grant_ready`. The route response must contain
the same protocol, schema 3 and a phase. There is no
missing-certificate, old-binary or boolean-only fallback. The strict decoder
rejects duplicate decoded keys, unknown fields/enums, invalid UTF-8/surrogates,
extra documents, and budget excess. It bounds input to 1 MiB, nesting to 12,
certificate arrays to 256 entries, and event traces to 32. Required strings are
nonempty and bounded; deployment/runtime may be empty optional metadata.

The bridge captures the executable by digest and executes sealed `memfd` bytes.
It projects actual native plan/receipt records, then retains binding, certificate
and event history as immutable JSON bytes. Fresh decoded arguments are used at
each call. Input-alias and observing-callback mutation regressions exercise this
reuse across GO and cleanup; they do not prove controller immutability, safe
module rebinding or all concurrent Python behaviors. Existing receipt validation,
cleanup and failure handling remain necessary. The selected route refuses async
invocation; cancellation theorems alone do not establish native async behavior.

The retained [cross-adapter probe](../../eval/campaigns/remediation-v2/raw/checks/receipt-cross-adapter-scope-v2/result.json)
used a separately identified development v2 binary. Crossed evidence ownership
refused, while consistently altered assignment/native/evidence rows with unchanged
opaque digest strings were accepted. This exposes the deliberate provenance
premise: digest preimages and faithfully signed object projection are not proved
by equal strings. No production signature bypass is claimed.

See the [runtime guide](../../docs/security/lean-worker-route.md) for wiring and
required test commands, and the [receipt contract](../../docs/security/lean-receipt-composition-plan.md)
for remaining work. Actual signatures, freshness/expiry, `RuleEnforcement`,
complete grant inventory, authorized waivers, digest derivation, actual activation,
worker identity/lifetime observations, Python call placement and outer-graph
coverage remain outside this model. Serialization, decoder, native compiler,
loader and OS refinement also remain open. This component does not establish
publication mediation, persistent-container cleanup, metadata secrecy or
universal confinement, and does not replace any failed historical cohort.
