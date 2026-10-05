# Week-one baselines

Recorded October 5, 2026 from the unmodified `1.2.12` tag at commit
`49cce0ca852be4cfb567a1cbe0e511ff325a1682`.

## Upstream `langgraph-prebuilt` suite

Command: `make test` from `libs/prebuilt`.

- Result: 284 passed, 16 snapshots passed, 191 warnings.
- Pytest-reported duration: 53.87 seconds.
- Cold end-to-end wall time, including service startup and teardown: 83.10 seconds.
- Process resources: 7.75 seconds user CPU, 1.27 seconds system CPU, 102,820 KiB maximum RSS.

## ToolNode hot path

The preliminary baseline measured a complete `ToolNode.invoke` or
`ToolNode.ainvoke` of one no-op tool. Each mode used 100 warm-up calls and five
samples of 1,000 calls with garbage collection disabled during each sample.

| Mode | Median per call | Best sample | Five samples, microseconds per call |
| --- | ---: | ---: | --- |
| Sync | 706.703 us | 620.235 us | 620.235, 706.137, 708.031, 720.505, 706.703 |
| Async | 413.723 us | 314.248 us | 314.248, 357.156, 413.723, 447.441, 541.726 |

These are absolute full-invocation costs, not security overhead. Step 13 will
compare identical benchmark cases with security disabled, `cap` only, and five
no-op modules. The production budgets apply to the incremental cost relative to
the disabled-security case.

The reproducible `pytest-benchmark` case lives at
`libs/prebuilt/benchmarks/test_tool_node.py`. CI publishes its JSON result so the
week-one runner result can be used for the later regression gate.

Local calibration of that committed case on Python 3.12.3, with 100 warm-up
iterations and garbage collection disabled, produced a 551.460 us median and
653.293 us mean over 2,533 rounds. The CI artifact, rather than this
developer-machine number, will be the hardware-matched comparison point.
