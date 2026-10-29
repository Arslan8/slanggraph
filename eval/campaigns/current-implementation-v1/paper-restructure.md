# Proposed evaluation section structure

1. **Frozen artifact and claims.** Put the exact revision, host, dependencies,
   model/dataset/task identities and the three configuration definitions before
   any number. State the runtime-MAC/Linux dispatcher gap here.
2. **Current route costs.** One table for cold setup/removal and one for reused
   calls. Lead with absolute time and its 95% CI, and put the non-overlapping
   phase ledger directly below it. Keep primitive-relative multiples and
   percentage overhead in an artifact appendix rather than the headline figure.
3. **Application utility and latency.** Present the matched A/B/C Pandas matrix,
   then C-closed as a distinct configuration. Count refusal as utility failure.
   Explain the historical 29/50→50/50 configuration changes in a boxed
   change-analysis paragraph, not as an unexplained trend.
4. **Useful interpreter subworkflow.** Show the two-source decision and a compact
   supported / worker-or-broker / refused operation table.
5. **Alice/Bob worked comparison.** Make the single shared database the main
   baseline table: Alice utility, Bob confidentiality, file-bypass outcome and
   trusted-code requirement. Follow with SQLite and pump ablations.
6. **Coverage and engineering surface.** List protected/unsupported paths and
   adapter source size. Mark historical implementation effort unavailable rather
   than replacing it with retrospective guesses.
7. **Lean contribution.** State the five theorems verbatim, assumptions, model
   size, check command/cost, implementation connection and unproved refinement.
8. **Threats and change log.** Separate current measurements from older evidence,
   current implementation gaps from evaluation limitations, and modeling-driven
   obligations from test-discovered bugs.

The main text should carry the configuration definitions, headline numbers,
Alice/Bob comparison and Lean scope. Raw trial schemas, all commands, failure
transcripts, per-task timings and full coverage details can move to the artifact
appendix, with stable paths from every table row.

The latency discussion should compare protected tool-call time with the model
call that precedes it and with other process/sandbox routes. A syscall or direct
SQLite read is useful only as a labeled primitive floor. Broker `execution_ms`
must be described as worker startup, import, Unix-socket request/response, and
tool execution; it is not a transport-only span.
