# macOS host-security refresh

This package evaluates the 45 shared host-security cases from Linux `wip`
`30bb18375c36ee9634ed9b7d7af04c8e21546a96` on the macOS backend. The
macOS source under test is `bb9db36b18aa56aa3ddbcf640ec17708ac2cc4f5`.
The host reported macOS Tahoe **26.7.2** on arm64. No Linux run was made on this
host. This is a security evaluation, with no runtime or application benchmark.

## Inventory and native route

`../unified-final-v1/host_cases.json` is the shared case inventory. The pinned
file marks two Linux-only mandatory gate probes as `macos: false`. The macOS
wrapper includes `required_syscall_filter` and
`extensible_required_syscalls` explicitly so that all **45** shared identifiers
are exercised. Their original `need` requirements, attack bodies, and oracles
remain intact. The wrapper records this inclusion in each request file.

The runner uses the Darwin `host.dispatcher` route to
`eval/apps/demos/native_host.py`, `MacOSObjectDispatcher`, the native macOS
launcher, and the Lean lifecycle checker. The qualification's authorized
record read has a native activation receipt, lifecycle record, broker audit,
and independent record result. `native-configuration.json` pins the executable,
Python library, Lean library/runtime, source hashes, and toolchain identities.
The wrapper verifies the native binary hashes before invoking the runner. The
run copies that configuration into each evidence directory, and the case
audit checks the copied bytes.

The environment manifest records Python **3.11.18**, Cedar CLI **4.13.0**,
and installed package versions. The local `uv` executable was **0.13.8**;
`eval/uv.lock` pins the project dependencies. The shared campaign configuration
pins `qwen3:8b` at digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`;
no model is invoked by these deterministic host-security cases. Absolute local
paths in the native configuration identify the original host. A fresh run on
another Mac needs equivalent locally built, hash-checked binaries.

## Qualification

The frozen one-pair run is `qualification`: **45 cases, 90 trials**. All
unprotected attacks produced the intended positive-control effect, all five
authorized protected controls succeeded, and every protected outcome has an
independent effect oracle. The qualification verifier and case audit both
report `evidence_valid: true`; there were no harness errors. This run preceded
the five-pair collection. An earlier setup pilot is not part of this package.

The SQLite shared-memory fixture places a separate `SHM_` canary beyond the
live WAL-index bytes. For each pair the unprotected result must contain that
canary, the archived fixture must contain it, and the protected result must
omit it. A failed positive control is inconclusive. An exception alone does
not establish isolation.

## Final outcome

The five-pair run contains **45 distinct cases, 225 paired observations, and
450 raw trials**. All 45 unprotected positive controls demonstrated their
intended effects in every repetition. The protected outcomes by distinct case
are **5 authorized controls succeeded, 32 forbidden effects prevented, and
8 rejected before execution**. By observation the counts are 25, 160, and
40 respectively. There were **zero forbidden effects, inconclusive outcomes,
or harness errors**. The independent verifier replayed **170 native Lean
success certificates** and reported `full_requested_matrix: true`.

The final per-case classification is in `final-case-results.csv` and
`final-case-results.json`. Each row has the requested guarantee, five
positive-control outcomes, five protected outcomes, oracle evidence paths,
and any host-capability refusal witness. The summary counts distinct cases;
the JSON also counts observations. Authorized controls are kept separate from
forbidden attacks. A refusal is recorded separately from an attack prevented
after execution.

The five host-capability refusal cases are `required_aggregate_cpu`,
`required_per_process_cpu`, `required_syscall_filter`,
`extensible_required_cpu`, and `extensible_required_syscalls`. The other
three refusals are `missing_obligation` and `altered_obligation` at the Lean
checker, plus `admission_mutation` at language admission. The mandatory CPU
and syscall probes retain `need`. The backend does not
claim to enforce those host features. The case audit requires an attributable
non-waivable grant line, no activation receipt, no entered worker, and, where
available, a lowerer record with `tool_released: false`. The extensible host
classes currently report the less specific native-grant refusal
`macos_object:unsupported_filesystem_authority`; the audit also checks the
unchanged mandatory line. This diagnostic wording should not be read as CPU
or syscall enforcement.

The process-tree sampler retained extra controller descendants in some
refusal trials, including five extensible-gate observations. It does not
retain their executable identity. The source path for this exact refusal
raises in `MacOSObjectDispatcher._compile_grant` before `_run` or `_spawn`,
and those trials have no activation receipt or trusted worker-entry event.
The case table preserves the observed PIDs rather than treating every
controller descendant as a released worker.

## Reproduce and verify

From the repository root on macOS 26.7.2, with `uv` and the pinned Cedar CLI
on `PATH` (this host used `eval/vendor/macos-toolchains/cedar/bin`):

```bash
uv run --project eval python eval/campaigns/unified-final-v1/macos_student.py \
  --output eval/campaigns/macos-host-security-refresh-v1/qualification-new \
  --native-configuration eval/campaigns/macos-host-security-refresh-v1/native-configuration.json \
  --jobs 1 --repetitions 1

uv run --project eval python eval/campaigns/cross-host-security-v2/verify.py \
  eval/campaigns/macos-host-security-refresh-v1/qualification-new \
  > eval/campaigns/macos-host-security-refresh-v1/qualification-new-verification.json

uv run --project eval python eval/campaigns/macos-host-security-refresh-v1/audit.py \
  eval/campaigns/macos-host-security-refresh-v1/qualification-new \
  eval/campaigns/macos-host-security-refresh-v1/qualification-new-verification.json \
  --repetitions 1 \
  --prefix eval/campaigns/macos-host-security-refresh-v1/qualification-new-case-results

uv run --project eval python eval/campaigns/unified-final-v1/macos_student.py \
  --output eval/campaigns/macos-host-security-refresh-v1/final-new \
  --native-configuration eval/campaigns/macos-host-security-refresh-v1/native-configuration.json \
  --jobs 1

uv run --project eval python eval/campaigns/cross-host-security-v2/verify.py \
  eval/campaigns/macos-host-security-refresh-v1/final-new \
  > eval/campaigns/macos-host-security-refresh-v1/final-new-verification.json

uv run --project eval python eval/campaigns/macos-host-security-refresh-v1/audit.py \
  eval/campaigns/macos-host-security-refresh-v1/final-new \
  eval/campaigns/macos-host-security-refresh-v1/final-new-verification.json \
  --repetitions 5 \
  --prefix eval/campaigns/macos-host-security-refresh-v1/final-new-case-results
```

`python eval/campaigns/macos-host-security-refresh-v1/verify_package.py`
checks the committed checksums, both run summaries, source snapshots, and
the reassembled final raw archive. The archive parts named in
`archive-index.json` contain every final raw trial, fixture snapshot, native
receipt, process witness, and captured executable/library. `SHA256SUMS`
covers the package's standalone evidence and verification scripts. Fresh
execution requires the original native binaries or a rebuilt equivalent;
package verification needs only committed files.
