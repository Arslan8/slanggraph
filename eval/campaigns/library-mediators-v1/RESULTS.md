# Reusable language-mediator evaluation

The exact final implementation revision is reported by `git rev-parse HEAD`
after the implementation commit (and in the delivery summary). The ACE source revision is
`e88f6dc16e5404131fbefe5684c7f05f856edbdd`; the enabled manifest SHA-256 is
`e1d99bc3aa03a415f726796ed1d6263a9a63a0138a9d3ae4d14b77e641c613e2`.

The population is unchanged: every enabled case-study-1 manifest entry with a
checked-in source file. Five pass-only sources remain listed and are excluded
from the eight-real-tool denominator.

| Tool | Language admission | Expected function | Integration | Disposition / precise rejection |
| --- | --- | --- | --- | --- |
| `create_gmail_draft` | not attempted | not implemented upstream | none | pass-only placeholder |
| `delete_gmail_message` | yes, unchanged | succeeds | inert language computation | admitted and executed |
| `empty_arg_test` | yes, unchanged | succeeds | inert language computation | admitted and executed |
| `get_gmail_message` | not attempted | not implemented upstream | none | pass-only placeholder |
| `get_gmail_thread` | not attempted | not implemented upstream | none | pass-only placeholder |
| `google_drive_retrieve` | no | not attempted | `library.text_retrieval.v1` is available, but no credentialed Google Drive retriever was configured | `manifest_consistency:unregistered_import`; a real setup must construct the trusted retriever with credentials and folder configuration, then adapt the tool to `text_retrieval.search` |
| `health_companion` | yes, adapted | succeeds | `python.secrets.booking.v1` | original source rejects because its `None` default is outside the inert-string input contract; the explicit adapter uses the registered randomness API |
| `metro_hail` | yes, unchanged | succeeds | inert language computation | admitted and executed |
| `poem_generator` | yes, unchanged | succeeds | inert language computation | admitted and executed |
| `quick_ride` | yes, unchanged | succeeds | inert language computation | admitted and executed |
| `search_gmail` | not attempted | not implemented upstream | none | pass-only placeholder |
| `send_gmail_message` | not attempted | not implemented upstream | none | pass-only placeholder |
| `travel_mate` | yes, adapted | succeeds | `python.secrets.booking.v1` | original source rejects its unregistered `json`, `random`, `string`, and `time` imports; the explicit adapter uses the registered randomness API |

Coverage is 5/8 unchanged and 2/8 with a declared API adaptation: 7/8 real tools
admit and execute successfully. One tool remains blocked by trusted Google Drive
setup. No fixture or placeholder replaced that functionality.

The SQLite/Records regression separately executes the documented local import
path through language isolation. Reading `notes/alice` succeeds; presenting a
grant only for `notes/bob` makes the same call fail with
`resource:not_granted`. The test also removes the database immediately after the
invocation, exercising connection cleanup.

## Security and performance reruns

The focused security suite covers allowed calls, denied selectors/actions,
registered aliases, unregistered members/imports, backend traversal, closed
invocations, cleanup, and generated effect terminals. Full library validation is
run with the required `make format`, `make lint`, and `make test` commands.

The final common language-route measurement used five fresh sessions, five
warmups per session, and 20 measured calls per session (`n=100`), with trusted
asynchronous audit durability. All 100 results passed the oracle.

| Measurement | Mean (ms) | Median (ms) | P95 (ms) |
| --- | ---: | ---: | ---: |
| End-to-end language call | 5.968 | 5.605 | 8.574 |
| Authorization | 0.946 | 0.928 | 1.239 |
| Resource activation | 0.176 | 0.173 | 0.219 |
| Interpreted execution | 0.248 | 0.233 | 0.316 |
| Audit | 0.288 | 0.283 | 0.344 |

Mean protected setup time was 427.534 ms across the five sessions. These are
same-host measurements of the existing common file-read workload after the
admission changes, not a new macOS campaign or a claim about Google Drive
latency.

## Reproduction

From the repository root, with the frozen ACE checkout available:

```text
PYTHONPATH=libs/prebuilt:eval/distributed libs/prebuilt/.venv/bin/python \
  eval/distributed/tool_census.py \
  --output /tmp/argus-library-census-final \
  --ace-root /tmp/ace-llm-source

PYTHONPATH=libs/prebuilt libs/prebuilt/.venv/bin/python \
  eval/distributed/common_language_costs.py \
  --output /tmp/argus-library-performance-final \
  --sessions 5 --warmups 5 --measured 20 \
  --audit-durability trusted-async
```
