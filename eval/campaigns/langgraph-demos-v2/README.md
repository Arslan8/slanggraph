# Argus ordinary LangGraph demos v2

This campaign extends, rather than replaces, `langgraph-demos-v1`.  It keeps the
same five frozen upstream applications, tasks, fixtures, model, and validators,
and adds programmable resource monitors for the boundaries that the first
integration attempt correctly refused.

Run a one-task-per-application protected smoke test:

```bash
uv run --python 3.11 --project eval \
  --with langchain-openai==1.7.2 --with scikit-learn --with pandas \
  --with langchain-community --with langchain-experimental \
  --with matplotlib --with pytz \
  python eval/campaigns/langgraph-demos-v2/run_preflight.py --smoke
```

Omit `--smoke` to run all five frozen tasks for every application.  The model
service is the same pinned local `qwen3:8b` service used by v1.  The script never
deletes old results and refuses to overwrite an existing run directory.

The ten-demo compatibility survey remains at
`eval/campaigns/argus-compatible-demo-v1/`; it is not counted again here.
