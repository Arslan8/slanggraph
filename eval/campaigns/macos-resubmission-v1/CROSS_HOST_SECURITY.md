# Behavior-matched cross-host security inventory

`cross-host-common-cases.csv` is a spreadsheet-friendly view of the complete 45-row JSON mapping; the JSON is the generated source of record. `build_macos_cross_host_mapping.py` regenerates both files from the pinned Git object and the macOS evidence with stable row order and line endings.

`verify_common_source_equivalence.py` confirms identical attacker and fixture bytes and an identical permitted-operation oracle at the pinned Linux commit. The forbidden-effect classifier differs where CPU/syscall support and macOS-only live mutations differ; those decisions are reported separately rather than treated as identical mechanisms.

The original 44-case macOS run froze an attacker file lacking only the later `required_per_process_cpu` branch. Its 44 exercised branches match the pinned Linux body; the new CPU supplement freezes the byte-identical complete attacker file. Each run has its own source inventory and is verified separately.

The Linux comparison inventory is the **45 distinct cases** at WIP commit `caded83cf4e8ef83d3df1065f6acf3d808a4abb3`, under `eval/campaigns/argus-paper-revision-v1/retained/security/`. The macOS base is `794b17338eea0b71b67e084b720eb8d6d604b413`; the per-process CPU supplement and this mapping are in the follow-up revision. `cross-host-common-cases.json` has one row per case with both IDs, guarantee, attacker action, fixture, independent oracle, comparability, macOS result, and exact evidence paths. The pinned Linux and current macOS `attacker.py` bytes are identical for all 45 cases. The 44 primary semantic case definitions and disposable `fixtures.py` are likewise shared. Native launchers, supported controls, and result classifications may differ.

The original macOS main run contains the first **44 cases × 5 pairs = 440 trials**. The original one-pair per-process CPU probe did not use the Linux CPU-consuming body and was not suitable for the common matrix. `common-cpu-5-01` reruns that exact Linux body, including 2.5 process CPU seconds followed by Bob's SQLite update, in **5 pairs = 10 trials**. All five unprotected controls changed Bob. All five protected attempts retained `cpu per_process 1000 need` and refused before `GO` with the original grant, obligation, support reason, and `tool_released=false`. The selected macOS common matrix is **45 cases × 5 pairs = 450 trials**: 185 enforced protected observations and 40 pre-execution refusals, with valid independent controls. The Linux selected inventory reports 39 enforced and 6 pre-execution refusals at the case level. The difference reflects host support decisions, especially cumulative CPU and minimal syscall filtering; it does not establish equivalent kernel isolation.

The five permitted-operation cases are marked as controls in the mapping. They demonstrate legitimate work and are not counted as thwarted attacks. Attack outcomes come from independently copied SQLite records, pump state, file contents and identities, live listener events, resource logs, and process identities. Unsupported mandatory requirements remain unchanged. `verify_macos_cross_host_mapping.py` checks the pinned Git source, common attacker bytes, every Linux and macOS trial key, effective macOS controls, and each protected classification. `cross-host-common-verification.json` records its result. The Linux campaign's seven session cases use its selected dependency-complete rerun, not the earlier inconclusive attempts.

Within the macOS common matrix, the 185 `Enforced` observations consist of **25 permitted-operation successes** (5 cases × 5) and **160 blocked attack observations** (32 cases × 5). The other **40 observations** are pre-execution refusals (8 cases × 5). Each case also has five effective unprotected observations. These are counts of trial outcomes, not 185 distinct attacks.

## Shared specification and Linux counterpart requests

The Linux student can consume `cross-host-common-cases.json` and the pinned `specification.py`, `attacker.py`, `fixtures.py`, and `verify.py` in `cross-host-security-v2/` at the WIP commit. Every current common case already has a Linux counterpart; no Linux execution is requested here. The macOS-only extensions remain outside this matrix: five live-checker mutations, nine preflight removals, and 21 supplemental adversarial cases, listed in `macos_only_extensions` in the mapping. A future matched comparison of any extension requires a Linux case with the same requested guarantee, worker action, fixture, and independent oracle. In particular, the rename/hard-link object-identity attack, pending cancellation, startup authority, and parallel-response cases require explicit Linux counterparts before cross-host claims can include them. The historical Linux filesystem identity regression differs in route and oracle; a name-level match is insufficient.

## Reproduce

From the repository root, fetch the pinned WIP object if absent (`git fetch origin wip`), then run:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  eval/.venv/bin/python eval/remaining/build_macos_cross_host_mapping.py
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
  eval/.venv/bin/python eval/remaining/verify_macos_cross_host_mapping.py
```

For a fresh macOS per-process supplement, set `ARGUS_MACOS_CONFIGURATION` to the pinned native manifest, put the pinned Cedar CLI on `PATH`, then run `run.py --output <new-directory> --cases required_per_process_cpu --repetitions 5 --jobs 2` and `verify.py <new-directory>`. The original selected macOS raw records are in `security-trials.jsonl.gz`; the new CPU records are in `common-cpu-trials.jsonl.gz`. Full SQLite backups and execution copies remain in ignored local run directories and are identified in each mapping row. The portable records and source inventories permit independent classification review; reproducing all copied SQLite backup checks requires those local run directories or a fresh run.
