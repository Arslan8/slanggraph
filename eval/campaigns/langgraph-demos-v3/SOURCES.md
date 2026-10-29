# Frozen sources and task selection

The upstream LangGraph snapshot is
`23961cff61a42b52525f3b20b4094d8d2fba1744`. The D1-D5 source-cell maps,
fixtures, adaptations, and task definitions are retained in
`eval/campaigns/langgraph-demos-v1/`. The resource-monitor implementation and its
protected preflight are documented in `eval/campaigns/langgraph-demos-v2/`.

The ten historical demos and their frozen task oracles are defined in
`eval/campaigns/argus-compatible-demo-v1/run_expanded.py`. The v3 runner embeds the
same oracles and records source, fixture, task, model, and Lean-worker SHA-256 hashes
in each run's `configuration.json`.

Model: local `qwen3:8b`, digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`,
temperature 0, generation seed `20261005`, reasoning effort `none`.
