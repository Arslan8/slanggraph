# Linux final-r3 handoff

Campaign `unified-final-v1`, configuration
`d8fdb318506dd84466339a78d433c290b467bbde379a379b5fef0798c33f468c`,
build `0bcca90c2988dea43e299c993f175bd8488cbc6d228687a5ac9e3b2fd47c6542`.

## Root causes and fixes

- `D3-plan-execute`: empty/repeated plans caused the shared execution failure.
  Empty plans, completed steps, and no-progress replans are now handled without
  changing the task oracle or security policy.
- `T10-time-travel`: authenticated checkpoint history did not establish a
  one-use historical restore authorization, and resumed branches retained the
  wrong issued tip. Historical selection is now principal-bound and one-use;
  resume resets the tip to the selected branch. Tampered, repeated, and
  cross-principal restores remain denied.
- `D4-multi-agent`: weak handoff/termination rules allowed recursion, baseline
  chart execution unnecessarily allocated multiprocessing IPC, and the APF
  image/export path was stale. Handoffs now carry exact values, completion is
  tied to a verified artifact, baseline execution is in-process, and the APF
  image and policy-scoped export path are pinned.
- `D5-support`: the itinerary update touched every ticket leg instead of the
  requested leg. The application, mediator, and backend now update only the
  matching leg.
- Pandas date/monthly tasks: the old workflow/API, date-period handling,
  scalar aggregation, null handling, and chart reaggregation disagreed with
  the pinned data semantics. The v23 workflow and independently checked
  task-specific operations now produce the frozen expected results.
- Host microbenchmark: the old body repeatedly imported the full application
  stack and did recurring setup. A minimal production adapter now exercises
  the same useful file operation after preflight. The write policy grants only
  write/truncate to the workload; backend-internal rights are not exposed.
- APF timing: result/artifact retrieval is inside submit-to-safe-return;
  one-time provisioning and logical-session teardown are excluded
  symmetrically and recorded separately.

The detailed diagnosis, representative outputs, expected behavior, and
regression evidence are in `DEBUGGING-QUALIFICATION.md` in the campaign source.

## Final outcomes

- Validation passed with zero errors: 5,635 request records, 225 Linux host
  security records, and 60 sustained records.
- The repaired D3, D4, D5, and T10 cells contain no execution or compatibility
  failures. D4, D5, and T10 pass every measured oracle. D3 retains genuine
  model-answer errors: baseline 66/150 correct; Argus, nono, and APF each
  60/150 correct.
- Pandas passes 300/300 measured trials in each of baseline and Argus. The four
  formerly all-failing date/monthly tasks each pass 30/30 per condition.
- The host request-latency means are 32.6--34.5 ms rather than the prior
  533--545 ms. Sustained host throughput remains about 6.4--6.5 requests/s
  because safe worker replacement is a recurring lifecycle cost and is not
  moved outside the timer.
- Linux host security reports 33 demonstrated preventions, 5 allowed controls,
  and 7 inconclusive cases across 45 distinct cases. The direct-shared-memory
  probe remains inconclusive because its positive control did not observe the
  protected canary. No macOS result is claimed.
- APF/OpenShell and nono are reported as best-available reduced enforcement.
  Exact missing obligations per application are in `policy_mapping.json` and
  the policy comparison in `REPORT.md`.

## Rerun and retention decision

Rerun: every APF macro cell; all four modes for D3, D4, D5, and T10; all Pandas
cells; forced-host latency/security/sustained microbenchmark cells; and the
Linux host-security cases on the qualified frozen build. Retained: unaffected
macro cells and baseline/language microbenchmark cells from `final-r2`.
`retained-lineage.json` records source identities and invalidation rules.

## Reproduction

From the repository root:

```bash
uv run --project eval python eval/campaigns/unified-final-v1/run.py qualify \
  --result eval/campaigns/unified-final-v1/results/final-r3
uv run --project eval python eval/campaigns/unified-final-v1/run.py \
  retain-compatible --result eval/campaigns/unified-final-v1/results/final-r3
uv run --project eval python eval/campaigns/unified-final-v1/run.py \
  collect-invalidated --result eval/campaigns/unified-final-v1/results/final-r3
uv run --project eval python eval/campaigns/unified-final-v1/validate.py \
  eval/campaigns/unified-final-v1/results/final-r3 \
  --output eval/campaigns/unified-final-v1/results/final-r3/validation.json
uv run --project eval python eval/campaigns/unified-final-v1/report.py \
  eval/campaigns/unified-final-v1/results/final-r3
```

The versioned, checksum-authenticated result is
`eval/campaigns/unified-final-v1/retained/final-r3/`.
