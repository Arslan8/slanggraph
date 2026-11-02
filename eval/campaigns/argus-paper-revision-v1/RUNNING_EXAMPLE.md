# Complete Alice/Bob example

Run `preflight.py --run-example`. The readable source artifacts are
`run_example.py` and `worker.py`; the generated `invocation.json` contains the
exact grants, plans, receipts and trace.

## Manifest

```text
runs linux
db_record read notes/alice need
returns normal
```

## Caller and operator Cedar

```cedar
permit(
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"db_record::read",
  resource
) when { resource.selector == "notes/alice" };
```

```cedar
forbid(
  principal == slangGraph::User::"blocked",
  action,
  resource
);
```

The sealed operator policy is independently installed and cannot be replaced by
the graph. Writes and Bob are absent from the caller/manifest authority; the
worker cannot manufacture either permission.

## Trace

1. Closed admission binds the exact `ToolNode`, schema tool, dispatcher and
   worker artifact.
2. Alice's authenticated call is expanded and Cedar produces one outer line:
   `db_record/read/notes/alice/need`.
3. Linux lowering derives a service rule plus bypass, spawn-bound-channel and
   parent-credential-custody guards, deny-complement obligations, minimal
   syscall filtering and resource limits.
4. The compiled Lean core accepts the exact object-grant inventory.
5. Landlock/seccomp activates; the coordinator validates the receipt; Lean
   accepts the activation and permits `GO`.
6. The parent-owned SQLite mediator reads Alice. The worker has no database
   handle or path authority.
7. Cleanup confirms worker and broker termination; Lean permits result release.

Expected outcomes:

```json
{
  "allowed_read": {"found": true, "value": "ALICE_ALLOWED_VALUE"},
  "denied_bob_read": {"broker_denied": "broker:not_granted"},
  "denied_write": {"broker_denied": "broker:not_granted"},
  "denied_direct_database": {"direct_blocked": "PermissionError"}
}
```

Independent SQLite snapshots before and after are identical and retain Bob's
unique canary. The canary is absent from attacker-visible outcomes.

## Lowering examples

| Kind | Request | Decision component | Outcome |
| --- | --- | --- | --- |
| Exact | mandatory Alice read and supported broker/isolation requirements | Cedar authorizer + mediator/host negotiator + Lean inventory checker | Execute with the same requested permission |
| Tightened | mandatory Alice read plus an optional (`want`) unsupported permission | Cedar may remove an optional permission; host lowering may also remove an optional unsupported rule and records `removed_wants` | Execute only if every `need` remains; provenance identifies whether authorization or host lowering removed it |
| Unsupported | mandatory aggregate process-tree CPU limit on a host without a cumulative tree-time primitive | Host lowerer | Reject before tool body; original request and lowering refusal remain recorded |

Authorization removes permissions because caller/operator policy does not grant
them. Host lowering starts from the authorized grant and removes only optional
permissions that the selected native primitives cannot implement. Either stage
removing a mandatory permission rejects; neither may silently relabel the result
as complete.
