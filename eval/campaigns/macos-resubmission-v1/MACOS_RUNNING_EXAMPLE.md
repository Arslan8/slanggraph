# Alice's SQLite record: macOS end-to-end trace

The concrete trial is `security-final-03/trials/allowed_record_read-0/Argus/trial.json`, paired with `bob_read-0` and `direct_database_read-0`. Each uses fresh disposable SQLite rows and unique Alice/Bob markers. The unprotected controls read Bob's row and open the database directly; protected resource state is independently read from SQLite backups and the resource event log.

## 1. Manifest and Cedar policy

The actual tool manifest is `runs macos`, `record read notes/alice need`, `record write notes/alice need`, `pump inspect pump-1 need`, `pump set_flow pump-1 need`, `trace append entry need`, and `returns normal`. The `record` class declares `operations read write delete`, `object row`, `normalizer identity`, and `enforced_by broker`. The relevant Cedar rule is:

```cedar
permit(principal == slangGraph::User::"alice",
  action in [slangGraph::Action::"record::read", slangGraph::Action::"record::write"],
  resource) when { resource.selector == "notes/alice" };
```

The full policy also grants the pinned pump/trace selectors and denies Bob by absence of a permit. The sealed operator policy is `forbid(principal == slangGraph::User::"blocked", action, resource);`. Exact policy, class declarations and manifest are in `specification.py` and `security-final-03/configuration.json`.

## 2. Invocation grant

The trusted HMAC test authenticator binds `alice`, session `security-campaign`, to the `Principal` before graph invocation. Cedar emits an `ObjectGrant` for tool `probe`, call `f095699fd13cb65527ef92f3cf391127`, with `probe:0 = record/read/notes/alice/need/broker`, four other named lines, and no waivers. The object grant digest in the retained trace is `077667c8a2239254a3f281dd994d26764538586cfc68beb3404727f8f80c4e4c`. The full grant is in the trial's `evidence.json` under `dispatchers[0].authorization_grants[0]`.

## 3. Enforcement plan

`MacOSObjectDispatcher` translates `probe:0` to service `["record","notes/alice"]` and generates an `operate` obligation with `bypass`, `channel`, and `custody` dependencies. The trial has 75 obligations and 75 exact assignments. The host adapter owns Seatbelt and private-channel obligations; the typed fixture mediator owns resource custody and operations. The plan mode is `enforced`, with no dropped mandatory requirement. The compiled Lean grant gate precedes worker release.

## 4. Seatbelt and channel

The native launcher closes unrelated descriptors, installs `(version 1)` / `(deny default)` before Python initialization, then allows only pinned runtime reads/maps and required sysctls. It does not grant the SQLite path to the worker. The private request/response pipes are bound to the worker spawn nonce, principal, tool and grant. `macos_launcher.c` installs the profile; `_MacOSObjectWorker._prepare_execution` binds the broker spawn; `_ObjectBroker._handle_frame` checks each request against the grant.

## 5. Mediator authorization

The broker log records `trace/append/entry` and `record/read/notes/alice`, both with `allowed=true`, reason `exact_object_grant`, principal `alice`, and the same grant hash and spawn nonce. The trusted mediator makes the SQLite request; its event log records `notes/alice` and never a Bob selector for this trial. Direct SQLite credentials remain in the controller.

## 6. Activation and cleanup

The receipt has mode `enforced`, bound host/context/plan digests and activated obligation IDs. The live lifecycle events are `authorize → activate → go → result → cleanup`; `cleanup_confirmed=true`. The verifier replays this retained certificate through the compiled Lean core as an additional check. No recovery record remains for the successful invocation.

## 7. Outcomes and alternatives

The protected Alice read returned the Alice marker and a matching SQLite row. Protected `bob_read-0` returned `broker:not_granted`, and the independent SQLite/event snapshot shows Bob unchanged and no Bob read event. Protected `direct_database_read-0` could not open the private database, while its unprotected control read Bob's marker. These observations concern the confined tool worker; declared trusted graph-node Python retains controller authority.

The optional `record read notes/bob want` probe in `advanced-run-01/optional_permission-0` succeeded for Alice but Cedar omitted Bob from the object grant. Its receipt has `removed_wants=[]`; this is authorization omission, **not** a supported lowerer tightening, so no tightening example is claimed. In `required_aggregate_cpu-0`, the original `cpu aggregate 1000 need` line becomes `rule:probe:5:operate`, `resource_limit/limit/aggregate_cpu_ms`, maximum 1000. Assessment reason `macos:aggregate_process_tree_cpu_budget_unavailable` gives decision `unsupported` and `tool_released=false` before `go`. `required_per_process_cpu` records `macos:total_cpu_ceiling_unqualified`; `required_syscall_filter` maps `syscalls @minimal need` to `process/syscall_set/minimal` and records `macos:syscall_filter_unavailable`. The `race_rename` and `race_hardlink` before-fix trials show why mandatory direct filesystem reads now refuse object identity claims.
