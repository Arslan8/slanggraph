# Unified final Argus evaluation campaign

This directory is the sole configuration and reporting authority for the final
four-evaluation campaign. It does not combine historical measurements with new
records. `configuration.json` freezes the cohort, sampling, seeds, timeouts,
model, aggressive Argus settings, comparator identities, timing boundary, and
the only four evaluations.

The fixed macrobenchmark cohort is D1–D5, T1, T2, and T5–T10. T3 and T4 are
not in the cohort. Pandas is separate. APF/OpenShell and nono occur only in
Evaluation 1. Sustained load occurs only in Evaluation 3.

## Files

- `run.py` is the single preparation, qualification, freeze, and collection
  entry point. It refuses collection before a passing qualification and freeze.
- `validate.py` rejects missing or duplicate samples, timer inconsistencies,
  route fallback, mixed builds/configurations, incomplete enforcement counters,
  invalid equivalence labels, and incomplete sustained inventory restoration.
- `report.py` is the one reporting pipeline. It produces `summary.json` and
  `REPORT.md` containing exactly four summaries in protocol order.
- `configuration.json`, `admission_inventory.json`, `host_cases.json`, and
  `policy_mapping.json` are versioned inputs copied into every result directory.
- `admission_fuzz.py` generates the fixed 10,000-program, five-seed supporting
  corpus and compares admitted programs with an independent generator-side
  evaluator and grant-checking fake terminal.

## Reproducible commands

Run from the repository root. The result directory must not already exist.

```bash
uv run --project eval python eval/campaigns/unified-final-v1/run.py prepare \
  --output eval/campaigns/unified-final-v1/results/final

uv run --project eval python eval/campaigns/unified-final-v1/run.py qualify \
  --result eval/campaigns/unified-final-v1/results/final

uv run --project eval python eval/campaigns/unified-final-v1/run.py freeze \
  --result eval/campaigns/unified-final-v1/results/final

for evaluation in 1 2 3 4; do
  uv run --project eval python eval/campaigns/unified-final-v1/run.py collect \
    --result eval/campaigns/unified-final-v1/results/final \
    --evaluation "$evaluation"
done

uv run --project eval python eval/campaigns/unified-final-v1/validate.py \
  eval/campaigns/unified-final-v1/results/final \
  --output eval/campaigns/unified-final-v1/results/final/validation.json

uv run --project eval python eval/campaigns/unified-final-v1/report.py \
  eval/campaigns/unified-final-v1/results/final
```

Inspect the frozen schedule without collecting:

```bash
uv run --project eval python eval/campaigns/unified-final-v1/run.py schedule \
  --evaluation 1 > /tmp/unified-final-e1-schedule.json
```

Run only the admission/interpreter corpus:

```bash
out=$(mktemp -d /tmp/unified-final-fuzz.XXXXXX)
uv run --project eval python eval/campaigns/unified-final-v1/run.py fuzz \
  --output "$out/results"
```

Linux is the collection backend in this campaign. The macOS operator can run
the separately prepared portability test on Tahoe 26.7.2 with the same source
revision and frozen case manifest:

```bash
uv run --project eval python eval/campaigns/unified-final-v1/macos_student.py \
  --output /absolute/path/to/macos-host-evidence \
  --native-configuration /absolute/path/to/macos-native-configuration.json
```

That external evidence is not a Linux qualification blocker. A macOS
application-completion record is not accepted in its place: every applicable
case retains its unprotected positive control and independent effect oracle.

## Final retained result

The completed Linux collection is retained under `retained/final-r2/` with
campaign ID `unified-final-v1` and configuration ID
`0fb5bdc04419ce1c05f3d5010f22c6949c787a64e4991b7c5d8f82c136ec71e8`.
It contains 5,635 request records, 225 host-security records, and 60 sustained
records. `validation.json` passes with zero errors.

The large JSONL files are losslessly compressed. The sustained archive is
split into sub-50-MiB parts for ordinary Git hosting. See
`retained/final-r2/README.md` for reconstruction, checksum, and regeneration
commands. Per-trial application sandboxes and transient service state are not
versioned; the records retain their timing, outcome, oracle, route, lifecycle,
and source/configuration identities.

APF/OpenShell and nono remain explicitly classified as best-available reduced
enforcement. Their omitted typed-mediation and direct-bypass obligations are
listed in `policy_mapping.json` and in the final report. macOS was not collected
on the Linux machine; `macos_student.py` and the frozen manifest are the handoff
for the separate macOS operator.
