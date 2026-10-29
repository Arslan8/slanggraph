# Preflight results

These are integration preflights, not the requested five-repetition performance
campaign.  They establish that the newly monitored paths execute before the
larger campaign is scheduled.

| Demo | Current protected result | Enforcement evidence |
|---|---|---|
| D1 SQL agent | task 1 correct: 3,503 tracks | 3 grants, 3 lowerings, 3 broker records |
| D2 Agentic RAG | task 1 correct against the required-fact checklist | 1 grant, 1 lowering, 1 broker record |
| D3 Plan/execute | search executes under Argus, but the pinned model repeats its final combine step and reaches the unchanged recursion limit | protected search grants/lowerings retained with the execution error |
| D4 Multi-agent | task 1 correct; observed series exactly matches all five UK values and a PNG is produced | 2 grants, 2 lowerings, 2 broker records |
| D5 Customer support | read task correct and unchanged; approved change interrupts, resumes, mutates the owned ticket, and retrieves it | read: 1 record; change flow: 3 records |

The D3 outcome is a utility/termination failure, not an unsupported resource
boundary.  The same pinned model and replanning prompt exhibit the loop without
Argus.  We retain it instead of weakening the recursion oracle or changing only
the protected prompt.

During D5 integration, a valid post-resume conversation exposed a checkpoint
monitor defect: locally issued descendants were not recorded, so the next turn
was falsely rejected as a broken chain.  The monitor now tracks issued and
restored tips separately.  Replay rejection remains intact and the synchronous
and asynchronous continuation regression tests pass.

Validation on this worktree: `make format` and `make lint` pass in
`libs/prebuilt`; its full suite reports 5,428 passed and 264 skipped.  The demo
resource-monitor tests report 4 passed, including an actual Landlock denial of
a sibling-file read from the persistent Python session.
