# Final-commit Pandas rerun

This artifact summarizes the fixed ten-task Pandas population rerun at runtime
commit `0db4bf9f3f7cbf13fecb5c1329dfd4decc1acf78` (full revision recorded in the
raw `plan.json`). The campaign used manifest `23-full`, `qwen3:8b` digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`,
five deterministically shuffled paired repetition blocks, and the digest-pinned
Lean checker `aa2bcfbb000cae794fd4667228bca1476544db987a8f3092a04a411a30219502`.

The host blocks unprivileged user namespaces, so the campaign ran in the
established `slg-linux-test` container with unconfined AppArmor, seccomp, and
system-path Docker profiles. That outer container supplies bubblewrap; the
inner Argus condition still activates its normal bubblewrap, Landlock, and
seccomp isolation route. Both conditions use the same host Ollama service and
frozen upstream checkout.

Results:

- Baseline: 50/50 correct, mean 10,228.4 ms.
- Argus `C-full-lean`: 50/50 correct, mean 11,388.9 ms.
- Ratio of complete-condition means: 1.113x, or 11.3% overhead.
- Paired-block 95% interval: 1.107x-1.121x, or 10.7%-12.1% overhead.
- Zero timeouts, admission failures, policy denials, execution errors, or
  output-validation failures.
- The independent matched validator passed with zero issues.

See `RESULTS.md`, `statistics.json`, and `validation.json`. `SHA256SUMS` covers
the retained raw artifact. The 259 MiB raw directory is kept locally at
`../raw/pandas-final-0db4bf9f3`; large copied runtimes and frozen-framework
bytes are not committed.

Reproduce the inner campaign after starting the pinned Ollama model:

```sh
python3 eval/apps/pandas/closed_campaign.py \
  --output /absolute/path/to/fresh/raw \
  --repetitions 5 --manifest v23 --configuration matched

libs/prebuilt/.venv/bin/python eval/apps/pandas/validate_matched.py \
  /absolute/path/to/fresh/raw \
  --output /absolute/path/to/fresh/validation.json

libs/prebuilt/.venv/bin/python eval/apps/pandas/analyze_matched.py \
  --raw /absolute/path/to/fresh/raw --output /absolute/path/to/fresh
```
