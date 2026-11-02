# Complete Linux configuration performance

## Host and protocol

The final campaign ran at commit `e29c882ff3a2fefbd3218a5476844f26f675a8af`
on Linux 6.17.0-1033-oem, Python 3.13.11, Cedar CLI 4.13.0, Landlock ABI 7,
and checker SHA-256
`7d8b9f15e294fa37ff462d249e6e74cfaf58b22deaa9cfbb0253760203cce44d`.
All measured sources were identical before and after the campaign.

This is a shared 32-CPU Intel host, not a dedicated benchmark machine. CPU 26
was selected and the runner pinned itself and every child to that CPU. During
the 30-second qualification its utilization was 0.10%; load-1 fell from 2.83 to
1.77. The host uses `intel_pstate`, `powersave`, 0.8–4.5 GHz dynamic frequency,
with no isolated/nohz-full CPU. Results are therefore valid as an
otherwise-quiet-host measurement and carry that limitation; they are not
frequency-fixed dedicated-host numbers.

Five independent process sessions each retained one cold pair, ten warmups, and
20 measured steady pairs. The baseline and protected calls both read the same
Alice value from an identically initialized SQLite database. Conditions are
interleaved within each session. The protected route enables authenticated
principal, owner/caller/operator Cedar, closed admission, typed SQLite mediator,
Landlock/no-new-privileges/seccomp/rlimits, activation receipt validation, all
three Lean lifecycle gates, SQLite audit, and confirmed cleanup.

## Boundaries and results

| Boundary | Baseline | Complete Argus | Relative / delta |
| --- | ---: | ---: | ---: |
| Preparation (5 sessions, mean) | database/fixture creation reported separately by harness | dispatcher 0.402 ms + admission/policy preparation 320.057 ms | 320.459 ms protected setup |
| Cold invocation (5 pairs, mean) | 0.140 ms | 415.563 ms | 2,977.17×; +415.423 ms |
| Steady invocation (100 pairs, mean) | 0.149 ms | 373.781 ms | 2,513.40×; +373.633 ms |
| Steady invocation (median) | 0.145 ms | 373.819 ms | — |
| Steady invocation (p95) | 0.171 ms | 381.789 ms | — |

Standard deviations are 0.013 ms baseline and 5.207 ms protected. Protected
steady observations range from 362.095 to 394.555 ms. All 155 protected calls,
all 155 baseline calls, audit counts, broker counts, and lifecycle counts passed
their correctness checks.

## Reconciled steady-state cost

These are means over the 100 measured complete-route calls. The spans are
non-overlapping; nested Lean time is subtracted from activation/transport.

| Component | Mean ms |
| --- | ---: |
| Cedar authorization | 0.720 |
| Host lowering / activation excluding Lean grant check | 121.688 |
| Lean grant check | 71.201 |
| Lean pre-`GO` check | 72.862 |
| Lean result/cleanup release check | 72.979 |
| Broker transport excluding checker/resource work | 14.853 |
| SQLite resource execution | 0.235 |
| Audit | 15.366 |
| Cleanup | 0.169 |
| Instrumented framework residual | 3.708 |
| **Reconciled end-to-end** | **373.781** |

The component sum equals the measured end-to-end mean exactly. “Framework
residual” is 0.99% of elapsed time and is retained rather than folded into a
larger unnamed category.

The exact qualification, environment, source hashes, preflight, raw JSONL
records and logs are committed under `retained/performance/` and expanded under
`raw/linux-performance-e29c882ff/`. Warmups and diagnostics are retained but
excluded from the steady table; no older configuration is pooled into these
headline numbers.
