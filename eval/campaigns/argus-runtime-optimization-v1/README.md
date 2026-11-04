# Argus runtime optimization artifact

This artifact records the final evaluated Linux configuration at implementation
commit `f76cbebf85c28cfef520cc779a2c180914808d44`.

- `raw/performance/summary.json`: matched five-session result.
- `raw/performance/session-*.jsonl`: complete diagnostic timing records.
- `raw/performance/preflight.json`: complete-route preflight.
- `raw/adversarial/`: 51-case boundary regression logs and summary.
- `raw/application/`: SQLite Records macro plan, compact summary, and compressed
  full trials.
- `raw/host-qualification.json`: accepted 30-second qualification.
- `raw/host-qualification-refused.json`: retained refused repeat.
- `raw/baseline-verification-*`: current-configuration verification of the
  prior committed 98.100 ms profile; the attempted host qualification was
  refused and the diagnostic run is labeled accordingly.

The paper-facing result is
`../argus-paper-revision-v1/OPTIMIZED_LINUX_REPORT.md`. It describes only the
final evaluated configuration and its requested reference comparison.

## Baseline verification

Before changing the invocation path, PR #47's exact structural prepared-worker
key was incorporated as commit `ce9005710`. The complete broker configuration
still had the reported shape: fresh invocation binding, three inline Lean gates,
spawn-bound transport, synchronous audit, and confirmed cleanup. The shared
host refused publication qualification, so this check is retained only as a
diagnostic: 87.936 ms mean, 87.244 ms median, and 93.143 ms p95 over ten pairs,
with 41.914 ms binding/activation, 18.593 ms transport, 15.389 ms across the
three compiled checks, and 7.795 ms audit. This confirmed that the committed
98.100 ms measurement was not an obsolete or enforcement-reduced configuration;
its accepted 100-pair result remains the reference in the paper-facing table.

Run `sha256sum -c eval/campaigns/argus-runtime-optimization-v1/SHA256SUMS` from
the repository root to verify retained files.
