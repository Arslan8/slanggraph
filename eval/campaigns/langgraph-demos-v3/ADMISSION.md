# Language-isolation admission inventory

The final campaign selects language isolation whenever the tool can be expressed
as inert computation plus a registered resource terminal. Host isolation is not
the default fallback for a missing library binding: each such failure is first
treated as a reusable-mediator gap.

| Application | Argus route | Integration | API adaptation | Remaining blocker |
| --- | --- | --- | --- | --- |
| D1 SQL | language | `readonly_sqlite_resource` | toolkit-compatible wrappers return bounded text | none |
| D2 RAG | language | `sklearn_text_retrieval_resource` | registered retrieval client | none |
| D3 plan/execute | language | `sklearn_json_search_resource` | search result is inert JSON text | application planner may still fail independently of admission |
| D4 multi-agent chart | host | typed search mediator plus confined persistent Python session | none | model-generated Python requires OS confinement |
| D5 customer support | language | `airline_sqlite_resource`, text retrieval, static JSON search | database results are inert JSON text | none |
| T1 add-tools | language | `sklearn_json_search_resource` | search result is inert JSON text | none |
| T2 custom weather | language | pure data-only implementation | implementation inlined | none |
| T3 fixed weather | language | pure data-only implementation | implementation inlined | none |
| T4 parallel weather | language | pure data-only implementations | implementations inlined | none |
| T5 multiply | language | typed scalar computation | implementation inlined | none |
| T6 return-direct | language | typed scalar computation | implementation inlined | none |
| T7 forced tool | language | pure data-only implementation | implementation inlined | none |
| T8 serial tools | language | typed scalar computation | implementations inlined | none |
| T9 add-memory | language | same registered JSON search integration as T1 | search result is inert JSON text | none |
| T10 time-travel | language | same registered JSON search integration as T1 | search result is inert JSON text | checkpoint replay correctness is independent of tool admission |

Thus 14/15 applications are language-routed. D4 is the only host-routed
application, for the specific node that executes arbitrary generated Python.
The language proof establishes that admitted effects are registered terminal
calls. Library and mediator implementations remain trusted against their
documented contracts; their Python source is not verified by Lean.

Every output JSON records `isolation_route`, and `run_campaign.py` copies it to
the retained trial record. A source-admission build check can be reproduced with:

```bash
cd eval
PYTHONPATH=apps/demos .venv/bin/python campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id language-routes-smoke --smoke
```

The campaign still requires the documented model, Cedar executable, and host
isolation prerequisites because its fixed population includes D4.
