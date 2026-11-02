# Formal-result map

Model guarantees and implementation correspondence are separate. “Runtime”
below means the compiled checker runs on the captured certificate; it does not
mean Lean proves Python, Cedar, the compiler, the decoder, or the kernel.

| Property | Proved conclusion | Assumptions | Connected implementation/checker | Negative example rejected |
| --- | --- | --- | --- | --- |
| Exact route lifecycle | Success iff matching authorization, confirmed supported activation, `GO`, accepted result and confirmed cleanup occur in order | Event observations and bindings are truthful; controller/checker transport trusted | `WorkerRoute.lean`; `LeanLifecycleSession`; Linux pre-`GO` and result gates | invocation/principal/grant binding mismatch, result before `GO`, cancellation without cleanup |
| Grant generation coverage | Accepted obligation inventory equals deterministic rules plus deny-complement obligations | Python capture corresponds to modeled grant and obligation constructors | `GrantCoverage.lean`; `require_grant` | omitted/altered operation, selector, condition, dependency, complement or extra row |
| Receipt coverage | Enforced plan/receipt cover the same obligations with no waiver and matching native plan/evidence | Signatures, freshness and native observation provenance trusted | `ReceiptCoverage.lean`; coordinator receipt validation; certificate capture | missing assignment/evidence, altered nonce/context/plan |
| Resource broker coverage | Every service rule has bypass, authenticated-channel and credential-custody guards; exact generated inventory selected | Mediator protected paths/capabilities and OS enforcement truthful | `ResourceGrantCoverage.lean`; object-route checker protocol; Linux object workers | omitted bypass guard; altered selector, dependency, binding, or custody operation |
| Authority preservation | Layer composition cannot increase modeled authority | Each adapter correctly implements its modeled restriction | `composition-route/AuthorityPreservation.lean` and `LayeredComposition.lean` | broader/lost binding in modeled layer composition |

## Enforcement status

- Runtime checker: grant/obligation inventory, certificate coverage, lifecycle
  transition order and result release.
- Model only: abstract composition theorems unless a separate correspondence
  argument connects every runtime layer.
- Trusted implementation: Cedar CLI semantics/invocation, Python capture code,
  mediator correctness, OS primitive semantics, observation provenance,
  controller integrity and compiler/runtime correctness.

## Outside proof coverage

- The Python-to-Cedar Unicode translation defect is a serializer/runtime bug,
  not something the theorem claims to detect. Its reproducer remains under
  `proofs/slp-cedar/`.
- TOCTOU in pathname resolution, inherited descriptors, controller tracing,
  cgroup semantics, process cleanup races, broker framing and application state
  serialization require implementation tests and independent oracles.
- Negative unit tests witness particular rejected examples; they are not the
  universal theorem. Conversely, the theorem does not detect arbitrary bugs in
  the implementation that constructs its input.
