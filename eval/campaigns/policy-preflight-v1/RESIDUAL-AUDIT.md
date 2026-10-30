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

## Post-release worker split

The remaining combined `execution_ms` label covered more than tool execution.
The production worker shim now has opt-in evaluation telemetry around its
post-`GO` phases. A 5-session, 20-measured-call-per-session diagnostic used the
same one-file-read tool and production worker shim (five warmups per session):

| Post-`GO` phase | Mean ms | p95 ms | Share of total |
|---|---:|---:|---:|
| Entire path through synchronous worker reap | 18.438 | 19.153 | 100.0% |
| Parent's timed wait for one-shot Python process exit | 15.328 | 15.374 | 83.1% |
| Execute tool module | 2.957 | 3.643 | 16.0% |
| Call the actual file-read function | 0.068 | 0.077 | 0.4% |
| Resolve entrypoint | 0.001 | 0.001 | <0.1% |
| Serialize returned value | 0.007 | 0.007 | <0.1% |
| `GO` write, parent decode, pipe/envelope/scheduling remainder | 0.064 | — | 0.3% |

The largest online cost is therefore synchronous interpreter shutdown/reaping,
not the resource operation or pipe transport. A second 100-call control changed
only the parent from `Popen.wait(timeout=5)` to blocking `Popen.wait()`. Its
post-response wait averaged 9.628 ms. Thus about 9.6 ms is real Python shutdown
after the result is flushed, while approximately 5.7 ms is delayed observation
from `subprocess`'s timed-wait polling. The second cost is executing the already
compiled module on every single-use worker; for this fixture that is almost
entirely `from pathlib import Path`. Worker provisioning and source compilation
happened before `GO` and are not included.

This diagnostic directly launches the production worker shim because the
current automation host cannot create bubblewrap's network namespace. It
therefore isolates the real post-release protocol implementation but is not a
protected-route headline latency result. Raw records and the reproduction
metadata are in `worker-transport-diagnostic.json`; the blocking-wait control is
in `worker-transport-blocking-wait-control.json`. Regenerate both with:

```bash
libs/prebuilt/.venv/bin/python \
  eval/distributed/worker_transport_diagnostic.py \
  --sessions 5 --calls 20 --warmups 5 \
  --output eval/campaigns/policy-preflight-v1/worker-transport-diagnostic.json
libs/prebuilt/.venv/bin/python \
  eval/distributed/worker_transport_diagnostic.py \
  --sessions 5 --calls 20 --warmups 5 --wait-mode blocking \
  --output \
  eval/campaigns/policy-preflight-v1/worker-transport-blocking-wait-control.json
```

### Trusted-commit optimization

The successful worker protocol now treats a flushed, validated result as the
trusted commit boundary. The worker immediately calls its pre-captured hard-exit
primitive, bypassing Python `atexit` handlers and finalizers. The parent returns
the result after validation and transfers process collection, descriptor
cleanup, termination recovery, and lease release to a daemon reaper. Timeout,
cancellation, malformed-response, activation-failure, and other non-commit
paths retain synchronous termination handling.

The same 5-session × 20-call worker diagnostic measured 3.048 ms mean and
3.450 ms p95 from `GO` through parent result decoding after this change. The
remaining process wait averaged 1.262 ms but is no longer on the successful
invocation path. Relative to the former 18.438 ms post-`GO` path through
synchronous reaping, this isolated path removes 15.390 ms (83.5%). It does not
include the small parent thread-scheduling cost and is not a protected-route
end-to-end result. Raw records are in `worker-transport-async-reap.json`.

```bash
libs/prebuilt/.venv/bin/python \
  eval/distributed/worker_transport_diagnostic.py \
  --sessions 5 --calls 20 --warmups 5 \
  --output eval/campaigns/policy-preflight-v1/worker-transport-async-reap.json
```

## Trusted asynchronous audit

The aggressive configuration now treats acceptance by Argus's trusted audit
writer as the online boundary. The caller assigns the next hash-chain entry and
enqueues it in a bounded queue. A dedicated writer preserves order, batches
SQLite transactions, and performs `synchronous=FULL` persistence off-path.
Queue exhaustion and a previously observed writer failure refuse later audit
writes. `flush()`, `records()`, verification, sealing, and `close()` wait for all
accepted records. The synchronous durability mode remains available when the
caller requires physical persistence before every return.

A matched current-revision language-route diagnostic used five fresh sessions,
five warmups, and 20 measured calls per session and changed only audit
durability:

| Audit durability | Complete call mean | Online audit mean | Success |
|---|---:|---:|---:|
| Synchronous SQLite | 11.456 ms | 7.349 ms | 100/100 |
| Trusted asynchronous | 5.325 ms | 0.283 ms | 100/100 |

Trusted asynchronous acceptance removed 6.131 ms (53.5%) from the complete
language-route call. Its remaining arithmetic framework residual was 3.678 ms,
which is now the largest aggregate phase on that route. An isolated one-record
diagnostic measured 0.471 ms synchronous acceptance versus 0.012 ms trusted
asynchronous acceptance. The route raw records are under `audit-route-sync/`
and `audit-route-async/`; isolated raw records are in
`audit-async-diagnostic.json`.

```bash
libs/prebuilt/.venv/bin/python eval/distributed/common_language_costs.py \
  --output audit-route-sync --sessions 5 --warmups 5 --measured 20 \
  --audit-durability synchronous
libs/prebuilt/.venv/bin/python eval/distributed/common_language_costs.py \
  --output audit-route-async --sessions 5 --warmups 5 --measured 20 \
  --audit-durability trusted-async
libs/prebuilt/.venv/bin/python eval/distributed/audit_costs.py \
  --output audit-async-diagnostic.json
```
