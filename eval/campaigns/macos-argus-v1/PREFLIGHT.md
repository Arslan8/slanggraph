# macOS Argus application readiness

The unchanged protected entry points were attempted on macOS. **No protected
tool execution qualified.** This is a first-task pilot and readiness result,
not the full 175-demo-trial plus 50-Pandas-trial protected evaluation.

The native macOS component exists, but these applications still select Linux
object/broker dispatchers. Running with `--mode Argus` does not select that
experimental macOS component automatically.

## Actual attempts

| Entry point | Result | Evidence |
| --- | --- | --- |
| D1 SQL | Process completed; incorrect | Tool denied with `object_policy:cedar:executable_unavailable`; no grant/lowering/broker record |
| D2 RAG | Process completed; oracle-correct | Model answered without calling a tool; no grant/lowering/broker record |
| D3 plan-execute | Execution error | `GraphRecursionError` after 25 model calls; no grant/lowering/broker record |
| D4 multi-agent | Startup failed | `OSError: [Errno 78] Landlock ABI is unavailable` in persistent Python backend initialization |
| D5 support | Process completed; oracle-correct | Model answered without calling a tool; no grant/lowering/broker record |
| T1–T10 tutorials | All ten failed startup | Missing `proofs/worker-route/.lake/build/lib/libargus_worker_route.so` |
| Pandas `C-full-lean` campaign | Preflight failed; no application task executed | Manifest selects missing `/data/langgraph/proofs/worker-route/.lake/build/lib/libargus_worker_route.so` |
| Lean loader probe | Refused host | `_memfd()` raises `OSError: Linux sealed executables required` on macOS |

Demo counts: 15 attempted, 3 process completions, 1 execution error, 11
nonzero-exit compatibility failures, 0 timeouts. Two completed outputs satisfy
their existing answer oracle; **zero establish protected tool execution**.
These pilot observations are not a full-cohort utility success rate. No
overhead or OS performance comparison is calculated.

## Setup and implementation work still required

Cedar is absent from this host's PATH. Installing the pinned CLI is ordinary
environment preparation; that absence alone does not establish an OS limitation.
The Lean build artifact is also absent. Building a macOS artifact alone is
insufficient: the existing runtime bridge uses Linux sealed memfds and the
applications pin Linux runtime paths and hashes.

The remaining implementation work is to connect macOS object-grant lowering and
broker transport to the existing policy and resource mediators, port persistent
Python/generated-code confinement, provide a pinned macOS Lean transport, and
qualify closed admission and route validation. The existing native macOS adapter
does not provide these complete application paths. Linux Landlock cannot be
enabled on macOS by installing a dependency.

The CPU-limit qualification exception remains deferred as requested. No other
protection or policy obligation was disabled. Application sources were not
edited to bypass these failures. Once the protected routes qualify, the full
matched task matrix can run with the existing baseline protocol and oracles.

## Reproduction and evidence

Executed from revision `ac9ff2d57013c6cf90dfba417ded8961830e9329` with the added
readiness launcher. Python 3.11.18, Apple M4 Pro, macOS 26.7.2. Ollama v0.40.13
served the frozen `qwen3:8b` digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
The original command builder, first task per application, prompts, timeout limits
and correctness oracles were reused. Model settings remain in the original
application code. CPU affinity was uncontrolled. The model's initial load was
not excluded; these timings are diagnostic only.

```sh
eval/.venv/bin/python eval/remaining/macos_argus_preflight.py \
  --output eval/campaigns/macos-argus-v1/new-preflight
```

Start the pinned local model service first as described in the
[baseline setup](../macos-baseline-v1/README.md). The output directory must be new.

[Raw evidence bundle](preflight-02.tar.gz), SHA-256
`0f1da05262a0bc1f35b471c469719c511ee001632749741e15a062402e11e1d0`,
contains commands, subprocess return codes, stdout/stderr, available application
outputs/audits, model metadata, package versions, source hashes and all 113
hashed source files. Source identities before and after execution agree.
Record copies were checked and completed output oracles replayed. The bundle
omits two copied database files; their sizes and hashes are retained in
`bundle-omissions.json`.

An earlier exploratory `preflight-01` ran with the model service stopped and
encountered connection errors. It remains local and is excluded from this
reported pilot. `preflight-02` above verified the pinned served model first.

The existing [baseline results](../macos-baseline-v1/RESULTS.md) remain separate.
