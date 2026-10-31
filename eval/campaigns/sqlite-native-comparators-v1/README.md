# SQLite native-comparator campaign

This campaign runs the Alice/Bob SQLite attack corpus through released system
mechanisms and checks effects with the existing canary-disclosure and
before/after database oracle. Findings are configuration gaps at documented
mechanism boundaries, not vulnerability or zero-day claims.

`raw/external` contains Progent, nono, Sandlock, APF, and CaMeL results.
`raw/ablations` contains the same corpus under the local ablations. The requested
Progent revision `07eb844` is not reachable in either public repository, so the
campaign uses the available vendored checkout at `5be7b63` as directed.
`raw/progent-resolution.json` retains the two upstream resolution responses and
the substitution decision.

Regenerate the derived summary from the retained trials with:

```bash
eval/.venv/bin/python eval/campaigns/sqlite-native-comparators-v1/regenerate.py
```

The external trial plan records the exact revisions, commands, native binary
hashes, and adapter details. Progent runs the native body only after the same
`check_tool_call` used by its proxy middleware accepts `record=alice`. The nono mechanism check runs the pinned
`test_from_profile_allow_net_overrides_*` tests to reproduce CLI authorization
override drift. The APF checks run its pinned wire-pipeline and non-MCP request
tests; the SQLite body follows APF's documented local native-tool path outside
request content middleware. `statistics.json` is the machine-readable source
copied into the paper's evidence directory for Figure 4, while `RESULTS.md` is
the human-readable rollup.
