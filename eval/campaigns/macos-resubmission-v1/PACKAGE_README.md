# macOS final evidence package

This directory is the macOS half of the resubmission. `acceptance.json` is the machine-readable index, `SHA256SUMS` checks committed artifact bytes, and `verify_final_package.py` checks the portable package's key counts and report flags. The pinned Linux WIP commit is used only as a source and evidence inventory; this package performs no Linux execution or runtime-overhead benchmark.

## Portable artifacts

- `cross-host-common-cases.json` and `.csv`: 45 behavior-matched case rows with policy guarantee, worker action, fixture, oracle, comparability, and evidence paths. `cross-host-common-verification.json` checks 450 selected macOS trials and pinned Linux trial keys. `common-source-equivalence.json` records shared source identities.
- `security-trials.jsonl.gz` and `common-cpu-trials.jsonl.gz`: main macOS security and new five-pair CPU records. `advanced-trials.jsonl.gz`, `before-fix-aliases.jsonl.gz`, `cancellation-witness-trials.jsonl.gz`, and `per-process-trials.jsonl.gz` preserve supplemental, before-fix, and historical attempts.
- `filesystem-identity-finding.json`: two confirmed protected disclosures before the fix, six affected refusals after it, and five legitimate mediated reads. `cancellation-witness-verification.json` separates resource completion, graph result delivery, and process termination.
- `app-baseline-trials.jsonl.gz`, `app-argus-trials.jsonl.gz`, their compact output/native-evidence archives, and their verification reports: the final 15-application correctness cohorts. The archives omit large input fixtures and source trees but retain per-trial output, observer/chart, logs, and available native records. The earlier complete Pandas cohort is `pandas-trials.jsonl.gz` and `pandas-verification.json`.
- Source inventories, configurations, dependency lists, native pins, model identity, and the case-level findings ledger accompany the trial records. All committed files are listed in `SHA256SUMS`.

## Verification and local-only steps

Run `eval/.venv/bin/python eval/campaigns/macos-resubmission-v1/verify_final_package.py` from the repository root for portable checksums and summary counts. `eval/.venv/bin/python eval/remaining/verify_macos_filesystem_finding.py` uses only committed compressed rows. `eval/.venv/bin/python eval/remaining/verify_macos_cross_host_mapping.py` uses committed compressed macOS rows **and** the pinned Linux Git object. Fetch WIP history with `git fetch origin wip` if that object is absent; the verifier reads it with `git show` and does not execute Linux code.

The following deeper checks still require ignored, uncommitted local run directories, or a fresh reproduction run: `verify.py security-final-03` for copied SQLite backups and frozen native binaries; `verify_macos_resubmission_advanced.py advanced-run-02`; `verify_macos_cancellation_witness.py cancellation-witness-01` for its contemporaneous process observations; `verify_macos_resubmission_app.py pandas-argus-rerun-11`; and `eval/remaining/verify_macos_baseline.py` on each final demo cohort for complete output files, source blobs, and native certificate replay. The compressed portable rows and reports permit case-by-case inspection, but they do not contain every copied SQLite file, model transcript, chart artifact, and frozen execution tree. Their absence from Git is explicit; do not claim an offline full replay from the compact bundle alone.

Each runner writes to a new output directory. `MACOS_CONFIGURATION.md`, `CROSS_HOST_SECURITY.md`, `MACOS_SECURITY_RESULTS.md`, `SUPPLEMENTAL_DISPOSITIONS.md`, `MACOS_APPLICATION_RESULTS.md`, `MACOS_PROOF_MAP.md`, and `MACOS_RUNNING_EXAMPLE.md` provide the exact commands and scope for their respective checks.
