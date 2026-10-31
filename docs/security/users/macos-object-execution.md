# macOS object-policy execution

`MacOSObjectDispatcher` connects native Seatbelt workers to Cedar object
authorization, sealed operator MAC policy, closed graph admission, and the
pinned runtime Lean checker. It supports read-only direct filesystem grants and
existing typed resource mediators. SQL, retrieval, search, travel updates and
persistent chart sessions keep resources in trusted parent-owned backends.

Worker requests use private inherited pipes. The parent binds each channel to
the principal, tool, native grant digest and fresh spawn nonce. Workers cannot
supply those identities or connect to arbitrary local sockets. Negotiation
checks the semantic operation, protected-path bypass prevention, channel
ownership and parent credential custody before granting access.

The compiled Lean core checks the complete obligation inventory, matching
authorization/activation/GO transitions before release, and result plus
confirmed cleanup before returning success. `ResourceGrantCoverage.lean`
generates broker guard obligations from the captured grant. Compiler, decoder,
controller, mediator and OS correspondence remain separate premises.

CPU qualification is deferred. The application route's certified inventory
therefore **does not promise an aggregate CPU ceiling**. The launcher still
installs the hard rlimit as a best-effort restriction. Wall deadlines,
descriptor limits and the remaining selected obligations are retained.
Seatbelt does not advertise Linux `@minimal` syscall filtering. Unsupported
required authority is refused.

## Build and configure

Build the [native launcher](macos-host-execution.md) with the application
interpreter. Build Lean using `proofs/worker-route/lean-toolchain`:

```sh
eval/.venv/bin/python proofs/worker-route/build_native.py \
  --lake /absolute/path/to/pinned/lean/bin/lake \
  --cc /Library/Developer/CommandLineTools/usr/bin/clang \
  --output proofs/worker-route/.lake/build/lib/libargus_worker_route.dylib
```

The operator build inventories non-system dyld dependency roots, aliases and
image hashes. Dependency images load under Seatbelt and are measured and
acknowledged before tool release. Alias targets require explicit read/map
authority. Runtime roots must contain trusted code, with no protected resources,
credentials or attacker-writable data.

The application harness accepts an explicit operator configuration:

```sh
eval/.venv/bin/python eval/remaining/setup_macos_argus.py \
  --launcher-manifest /absolute/launcher-build/manifest.json \
  --lean-manifest proofs/worker-route/.lake/build/lib/libargus_worker_route.dylib.json \
  --recovery-directory /absolute/protected/recovery \
  --output /absolute/macos-host.json

ARGUS_MACOS_CONFIGURATION=/absolute/macos-host.json \
  eval/.venv/bin/python eval/remaining/macos_baseline_campaign.py \
  --mode Argus --output eval/campaigns/macos-argus-v1/new-run

eval/.venv/bin/python eval/remaining/verify_macos_baseline.py \
  eval/campaigns/macos-argus-v1/new-run
```

Install Cedar CLI 4.13.0 on `PATH` and serve the frozen model first. The runner
reuses existing tasks, prompts, fixtures and utility oracles. Native journals
also retain each successful call's original Lean certificate, observed binding,
lifecycle trace and cleanup result for replay through the compiled core.
See the [application campaign](../../../eval/campaigns/macos-argus-v1/RESULTS.md).

macOS loads captured Lean images through private, immutable files and unlinks
them after loading; Linux retains its sealed-memfd transport. Same-UID debugging
and malicious operator code are outside the trusted controller/runtime premise.

Dataset and in-process reads use `O_SEARCH | O_NOFOLLOW` directory traversal and
a pinned readable descriptor. They reject symlinks in the bound path and never
reopen that pathname after binding. Dataset reads also enforce their byte cap
and content hash.

The persistent Python resource uses a separate native guardian and Seatbelt
profile. Its namespace survives calls; writes are confined to the declared
artifact directory. Frames are bounded, and timeout or transport failure kills
and reaps the session before releasing the resource operation.
