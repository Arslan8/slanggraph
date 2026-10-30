# Online residual audit

This audit follows the exact protected Linux file-read route measured in
`activation-pool-v1`. Worker provisioning remains a separately reported
preflight cost and is not included in online invocation overhead.

## What the old timers measured

The former `policy_lowering_ms` timer wrapped
`_LinuxObjectWorker._compile_grant`. It did **not** wrap host-policy lowering
(`EnforcementCoordinator.negotiate` and `_LinuxBubblewrapAdapter.lower`). The
19.54 ms label was therefore wrong. Most of that span was rebuilding baseline
grant records and hashing the Python interpreter, not lowering policy.

The former `framework_residual_ms` was an arithmetic remainder. Source tracing
and a parent-path diagnostic split its dominant work as follows:

| Repeated online operation | Mean ms | Classification |
|---|---:|---|
| Construct a new Linux executor frontend | 42.606 | redundant dispatcher setup |
| Rebuild the invocation grant | 17.778 | invocation binding, formerly mislabeled lowering |
| Complete preparation (grant, attestation, obligations, negotiation) | 42.129 | inclusive parent span |
| Clone the prepared executor frontend | 0.007 | replacement path |
| Bind against a prepared policy | 18.306 | inclusive; dominated by fresh host attestation |

The frontend constructor re-ran the bubblewrap host probe and hashed the
interpreter while recreating adapters. The invocation grant rebuilt baseline
rules and hashed the interpreter again. A standalone digest of the pinned
Python executable averaged 17.840 ms (20 iterations); exact-file
canonicalization averaged 0.013 ms (100 iterations), so path resolution was
not the large cost.

The old 87.443 ms residual therefore consisted primarily of the 42.606 ms
frontend recreation, roughly 17.8 ms of fresh attestation/integrity work, and
the actual obligation/negotiation plus graph, ToolNode, bridge, receipt, and
serialization work that the old harness did not distinguish. The updated
harness records inclusive parent spans and an exclusive residual partition for
each call:

- graph dispatch outside `ToolNode`;
- `ToolNode` orchestration outside the individual call;
- secured-tool framework work outside host execution and audit;
- host bridge work outside authorization and dispatch;
- dispatcher setup and other dispatcher work;
- host preparation split into invocation binding, attestation, prepared-policy
  matching, actual policy lowering, lifecycle checking, and other work.

`residual_partition_error_ms` checks that this exclusive partition reconciles
with the arithmetic residual. These fields require a new full host run; old raw
records cannot be retroactively decomposed.

## Architecture change

Preflight now retains the host-specific `AdapterPlan`, obligation assignments,
support mode, and stable host-configuration digest. Runtime performs fresh
authorization and constructs a fresh invocation grant, then:

1. requires an exact prepared-authority match;
2. requires the current host configuration and obligation digest to match the
   prepared values;
3. binds the prepared native plan to the fresh grant and fresh host
   attestation;
4. requires an already prepared single-use worker;
5. performs fresh activation, receipt validation, lifecycle checks, execution,
   audit, and cleanup.

Runtime does not call `EnforcementCoordinator.negotiate` or the adapter's
`lower` method on the prepared route. Missing or changed authority, host
capabilities, obligations, or worker availability refuses rather than falling
back to online lowering or cold activation.

The object dispatcher also retains the prepared executor frontend and immutable
native rules. Runtime shallow-clones only invocation-local state, reducing that
parent operation from 42.606 ms to 0.007 ms in the diagnostic.

## Validation boundary

The parent-path diagnostic does not execute a sandboxed tool and is not a new
headline latency result. It isolates controller work while bypassing only the
bubblewrap availability probe. The full route must be rerun on a host that can
create the required network namespace. In the current automation environment,
bubblewrap refuses with `loopback: Failed RTM_NEWADDR: Operation not permitted`;
using `--share-net` would weaken the evaluated isolation and was not used.

## Configurable integrity follow-up

An isolated 100-attestation diagnostic measured the three runtime integrity
modes against the same bubblewrap binary, resolved Python executable, and
worker shim:

| Mode | Preflight setup ms | Attestation mean ms | p50 ms | p95 ms |
|---|---:|---:|---:|---:|
| Full-file rehash | 27.260 | 19.919 | 19.761 | 22.096 |
| Four 64 KiB Merkle samples per artifact | 42.834 | 0.458 | 0.442 | 0.483 |
| Preflight-only hash | 23.009 | 0.104 | 0.103 | 0.110 |

This is a controller microbenchmark, not an end-to-end result. The Merkle mode
checks size on every call and selects samples without replacement using system
randomness. Its guarantee is probabilistic. Preflight-only provides no runtime
content-change detection and is appropriate only when another mechanism makes
the prepared artifacts immutable. All modes retain fresh nonce-bound host
evidence, prepared-worker identity checks, kernel-state validation, activation,
and receipt validation.
