# Host-control lowering and matched-host follow-up

This follow-up preserves the v1 campaign and its 44 cases. Its scope is (1) direct CPU qualification, (2) recognized CPU/syscall obligations reaching host negotiation, (3) attributable unsupported records, and (4) a single Linux Docker campaign containing security, route microbenchmarks and matched Pandas utility.

The proposed extra native setrlimit call was already present in revision 33504f3 and the v1 execution revision, before Seatbelt installation and Python initialization. Direct transcripts under `cpu-sanity/` reproduce both computation-heavy termination and the syscall-heavy total-CPU overrun. This host is not qualified for a total CPU ceiling. The code does not replace that contract with user CPU time, elapsed time or a more favorable loop.

New platform-neutral policy vocabulary:

```text
cpu per_process 1000 need
cpu aggregate 1000 need
syscalls @minimal need
```

Milliseconds are explicit in the CPU class's budget contract. Per-process and aggregate process-tree requests remain distinct. CPU and syscall classes are reserved kernel controls, available to the parser independently of the selected host. Parsing never implies enforceability. Cedar must authorize the requested line, then host lowering assesses it. A mandatory unsupported obligation retains its original object grant, native candidate, host attestation/capabilities, obligation IDs/parameters and adapter assessments. No body is released.

The current macOS adapter advertises Seatbelt, descriptor limits and supervised wall time, but does not advertise qualified total CPU ceilings or syscall filtering. It still installs RLIMIT_CPU as a best-effort guard. Aggregate CPU is refused as unavailable; per-process total CPU is refused as unqualified after the syscall-heavy reproducer; syscall filtering is refused as unavailable. Linux uses worker setrlimit for per-process CPU. Optional cgroup CPU control is bandwidth (`cpu.max`), not a cumulative process-tree CPU budget.

The default matrix remains exactly the original 44 cases. `required_per_process_cpu` is a separately selectable extra case, not silently substituted for `required_aggregate_cpu`. All source changes must finish before frozen runs; record the same implementation commit on both hosts. Development pilots are not formal repetitions.

macOS setup uses the existing pinned operator configuration. From the repository root:

```sh
PATH="$PWD/eval/vendor/macos-toolchains/cedar/bin:$PATH" \
ARGUS_MACOS_CONFIGURATION="$PWD/eval/vendor/macos-argus-configuration.json" \
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
eval/.venv/bin/python eval/campaigns/cross-host-security-v2/run.py --output eval/campaigns/cross-host-security-v2/run-macos-01
```

Run `verify.py` and `regenerate_ledger.py` with the resulting directory. To regenerate the old 185/25/10 split, select the **v1 verifier**:

```sh
eval/.venv/bin/python eval/campaigns/cross-host-security-v2/regenerate_ledger.py \
  eval/campaigns/cross-host-security-v1/run-01 \
  --verifier eval/campaigns/cross-host-security-v1/verify.py \
  --output eval/campaigns/cross-host-security-v2/attempt-ledger-v1.jsonl
```

For Linux, `Dockerfile` provides Cedar 4.13.0 and Lean 4.34.1. Record the actual image digest, Python packages, CPU architecture, kernel and outer security settings. The task-local Colima VM needs a kernel providing the production object adapter's required Landlock ABI. The outer evaluation container is privileged, with AppArmor/seccomp unconfined, solely to permit the inner production isolation mechanisms; it is part of the trusted harness. Bubblewrap must successfully activate before protected runs are counted. No failed activation duration is execution overhead.

`joint_linux_campaign.py` runs the same 44 security cases, three existing microbenchmark protocols (five sessions, ten warmups and twenty measured calls per session), and all ten Pandas tasks with five baseline and five Argus attempts each, within one campaign/stage ledger. Microbenchmark source copies differ only in runtime/image pin configuration. Pandas accepts a recorded runtime-manifest path for the rebuilt native image; model/task/dataset/policy/oracle settings are retained. The inner Docker route needs the daemon socket and identical shared filesystem paths for its temporary roots. The model endpoint must serve the existing pinned qwen3:8b digest on loopback. Do not report unavailable Lean integration or failed admitted routes as successful security validation.

The requested stronger conclusion is conditional on actual evidence. Successful parsing/refusal does not retire a prior observed CPU overrun. `RESULTS.md` and the review response must retain that limitation if it reproduces.

The syscall-filter body now attempts fork followed by a forbidden Bob update; entry alone is not a violation when Linux supports the requested filter. Success requires the declared filter in the activation receipt, observed NoNewPrivs/Seccomp state on the entered worker, and the independent resource oracle. This is a probe revision relative to v1. Missing/altered Lean obligations are inconclusive on Linux when the route never invokes the injected checker. Development pilot 04 also exposed a Linux persistent-session orphan; the production demo backend now installs PR_SET_PDEATHSIG(SIGKILL) before imports and checks the expected parent PID, closing the startup race. Pilot 05 confirms controller-death cleanup.

Linux preparation: build Dockerfile; install linux-requirements.txt into /opt/argus; install libs/{prebuilt,langgraph,checkpoint,sdk-py,checkpoint-postgres,checkpoint-sqlite} and eval/vendor/ai-data-science-team editable with --no-deps. Copy proofs/worker-route to /opt/argus-proof (preserve the Mac build tree), run build_native.py with /opt/lean/bin/lake, and retain its library manifest. The test environment additionally installs pytest-mock, pytest-asyncio, syrupy, pytest-timeout, psycopg[binary,pool], redis and aiosqlite. Commit this prepared image and build NestedDockerfile for the worker's /usr/bin/python3 path. The final outer image is sha256:eee2aefcf1fe8db615eb597df26a1e7e9314c7fed94a372a34b874e3ab7fc6d5; the nested worker image is sha256:4a97331b53b1e9f2066da456a127a0ae4661daacc75172996e779220127efd5a.

Use a trusted privileged outer container with seccomp/AppArmor unconfined, host networking, the Docker socket, the repository mounted at its identical absolute path, and /var/tmp/argus-eval mounted at that identical VM path. Set TMPDIR=/var/tmp/argus-eval (long shared workspace paths exceed Unix-socket limits), DOCKER_API_VERSION=1.44 for the Debian Docker client, ARGUS_EVAL_NATIVE_MANIFEST=/opt/argus-proof/libargus_worker_route.so.json and ARGUS_EVAL_DOCKER_IMAGE to the worker digest. The model endpoint is a loopback-only SSH reverse forward to the pinned Mac Ollama server; the outer container shares VM networking. The joint driver can wait for the Mac security source-after.json before starting timing stages.

The unchanged Pandas harness expects its upstream at `/data/slanggraph-eval-upstreams/ai-data-science-team`. Inside the Linux outer container, copy `eval/vendor/ai-data-science-team` there (excluding caches and `.venv`), link that copy's `.venv` to `/opt/argus`, and install the copied project editable with `--no-deps`. Its upstream revision is `4ffeb7f38178aa250917f29b01355f8b89ba809e`; all 41 package Python sources were checked byte-identical after copying. This is environment path setup, not a task, policy or model change. The native runtime-manifest pins are the only Pandas CLI configuration change.

The first joint attempt exposed two runtime packaging failures and is retained separately. Pandas snapshots now include `demos/native_host.py`; the Linux helper explicitly declares the selected interpreter's trusted purelib/platlib directories because isolated Python skips site initialization. The Docker image also copies the identical libpython bytes to the loader's default search directory, avoiding dependence on procfs-based origin lookup or the absent loader cache. These changes preserve task/policy/model/oracle semantics. Qualified outer runtime image: `sha256:835fd1d06e9dc127deac52ceb1cba538eaba692bdeba63e09cf78f39cfa28244`. The joint driver validates protected microbenchmark rows and expected phase counts independently of process exit status.

Published final runs are `run-macos-02`, `run-linux-02` and the separate `per-process-macos-02` probe at implementation revision `79c6309604835277333393d426a0c7fc22eb49e0`. The first security matrices and failed application attempt are preserved separately. Linux needed one explicitly retained observer-race retry; the complete matrix has 220 comparisons, while the all-attempt ledger has 221 comparisons / 442 condition attempts (one incomplete condition record). Original failed verification logs and subsequent successful rechecks remain in the joint campaign. The post-campaign observer-only guard at `87e5fa3` handles ESRCH as process disappearance; the frozen records remain unchanged.

Extract `security-runs.tar.gz`, `joint-linux-application.tar.gz`, `native-macos.tar.gz` and `native-linux.tar.gz` into this campaign directory. Copy the shared `run-macos-01/native` directory to `run-macos-02/native` and `per-process-macos-02/native`. `joint-linux-application-files.json` identifies the two captured Pandas native images to restore from `native-linux/`. File manifests and archive verification records cover all payloads. `development-evidence-files.json` similarly maps shared images for diagnostic runs; `security-runs-attempt-01.tar.gz` retains the first complete matrices. Verify archive hashes against `SHA256SUMS` before extraction.

To regenerate the all-attempt ledger (including the incomplete harness attempt):

```sh
eval/.venv/bin/python eval/campaigns/cross-host-security-v2/validation/regenerate_all_attempts.py \
  eval/campaigns/cross-host-security-v2/run-linux-02/security \
  --output /tmp/linux-all-attempts.jsonl
```

This reproduces the published ledger byte-for-byte. The final Pandas validation checks all 100 rows and replays the frozen correctness oracle; `pandas-statistics.json` retains all-attempt and matched-success analyses separately. Route summaries retain their different guard mixes. The legacy `macOS_checkout` configuration key contains the same implementation revision on both hosts; `wip_evidence_tree` is only a historical reference.
