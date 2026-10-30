# Argus aggressive matched Pandas rerun

This fresh campaign ran all ten tasks in five interleaved repetition blocks under `Baseline` and the highest-optimization Argus configuration. The Argus configuration selected aggressive Cedar evaluation, preflight-only integrity, trusted asynchronous audit persistence, and the digest-pinned inline native lifecycle checker. Common setup and model warmup are recorded separately and excluded symmetrically.

The host could not activate mandatory bubblewrap isolation. Baseline completed 50/50 tasks correctly; Argus completed 0/50. All failed attempts are retained, but their duration is not reported as execution overhead. `validation.json` intentionally fails because protected activation/audit evidence cannot exist for a route that refused before activation.

Reproduce:

```bash
libs/prebuilt/.venv/bin/python eval/apps/pandas/closed_campaign.py \
  --output /absolute/path/to/fresh/raw --configuration matched --repetitions 5
libs/prebuilt/.venv/bin/python eval/apps/pandas/analyze_matched.py \
  --raw /absolute/path/to/fresh/raw --output /absolute/path/to/fresh
libs/prebuilt/.venv/bin/python eval/apps/pandas/validate_matched.py \
  /absolute/path/to/fresh/raw --output /absolute/path/to/fresh/validation.json
```

Evaluated revision: `41ea67d74530de858b59e3a565a7d15a13428cfb` plus the campaign/configuration corrections committed with this artifact.

The 223 MiB copied `libleanshared.so` and redundant frozen-framework byte copies are omitted from Git. Their exact digests and identities are recorded in `raw/plan.json`, `raw/framework-sources.json`, and `SHA256SUMS`. The 560 KiB checker library, harness snapshot, per-trial records, outputs, transcripts, and failure traces are retained.
