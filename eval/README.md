# slangGraph evaluation

This directory contains evaluation source for the kernel-enforced slangGraph
design: code, pinned baseline metadata, synthetic vulnerable tools, adapters,
and input transcripts. Generated evidence is kept locally and excluded from Git.
Nothing in this directory is required by the LangGraph libraries at runtime.

## Generated evidence and reproduction

Raw cohorts, captured source archives, Lean audit binaries, audit databases,
process logs and generated data/plots are not distributed in this repository.
Campaign narratives and acceptance dispositions summarize historical runs;
their artifact paths refer to locally retained files and need not exist in a
fresh clone. The original files remain on the evaluation host. A rerun produces
a new observation; it cannot recreate missing historical provenance or guarantee
identical model output, host availability or timings.

Start with `PINS.md`, `ISOLATION.md`, the application READMEs, and the Makefile
targets for dependencies and execution requirements. The current acceptance
boundary is `docs/security/supported-surface.json`. Lean audits can be generated
with `python3 proofs/worker-route/check.py --output NEW_DIR` and
`python3 proofs/language-route/check.py --output NEW_DIR` from the repository
root (with the pinned Lean toolchain and Python dependencies installed).

The pandas drivers are `eval/remaining/application_campaign.py` and
`eval/apps/pandas/closed_campaign.py`; the latter selects the closed v21
configuration with `--manifest v21 --output NEW_DIR`. They require the pinned
vendor checkout, local model service, host isolation capabilities and a Lean
worker binary matching the selected manifest's path and digest. Verify cohorts
with `eval/remaining/verify_pandas_campaign.py` or
`eval/apps/pandas/verify_closed_campaign.py`. Use a new configuration/cohort for
changed paths or binary pins; do not edit a historical observation to pass.

`make security-verify` still requires valid runtime evidence at the paths named
by the route manifest. A fresh clone without it fails closed. Regenerate and
validate that evidence before claiming acceptance; proof-only or unit-test
success is not a substitute. Saved-artifact tests skip explicitly when their
local evidence is absent; code-level tests continue to run.

## Completed evaluation

Start with the [current evaluation](reports/paper-evaluation.md) and the
[validated alternative-backend report](reports/alternatives-v2/report.md).
The new results compare actual verified-language execution with Landlock and
rootless-container adapters, include 16 operation/API microbenchmarks and a real
Pandas computation replay, and separately evaluate an opaque native binary chain.

Every primary timing cell has **100 measured calls across five process sessions**,
with ten warmups per session. Reports include variance, paired session intervals,
policy/execution attribution, operation-body timing, container lifecycle costs,
host configuration, security coverage and exposure reduction. See the
[fixed protocol](REPETITION_PROTOCOL.md), [CSV](reports/alternatives-v2/timings.csv),
[comparison PDF](reports/alternatives-v2/comparison.pdf), and
[operation PDF](reports/alternatives-v2/operations.pdf).

The current host implementations are named evaluation adapters. Container setup
is amortized across a session; each call gets a fresh worker. The Bubblewrap
preflight failure and earlier single-session estimates remain available in the
[historical appendix](reports/historical-runtime.md); they are not pooled with
new measurements. The [native-chain report](reports/native-chain-v2/report.md)
uses an explicitly separate exec-enabled profile.

The paper-revision campaign also includes a deterministic
[remote-tool deployment case](campaigns/argus-paper-revision-v1/README.md#tool-deployment-coverage).
It sends an authorized tool request to a separate loopback HTTP service process,
so the evaluation covers in-process, local executable, and server-hosted tool
shapes without relying on a live external system. The case is explicitly scoped
to authorization and request-bound delegation; it is not evidence that local
isolation confines or verifies the remote service.

## Application study

The new local-model application study is documented in [APPLICATIONS.md](APPLICATIONS.md).
It tracks eight candidates from seven repositories separately from the synthetic
experiments below. The [pilot evidence report](reports/application-pilot.md)
records three local baselines and an experimental Pandas A/B/C integration,
including failures and limitations. These are not completed protected ports or
large-study results.

## Claim and primary measure

The primary claim is structural: interface-level defenses leave security-sensitive
sinks below their mediation point, while a sufficiently capable set of enforcement
adapters can mediate the resulting resource operation. The headline measure is
**sink exposure**, not attack-success rate.

slangGraph itself is not a Landlock system. Its policy pipeline constructs a
platform-neutral grant, and a selected adapter set lowers that grant to enforcement
available on the deployment. Landlock plus seccomp is the planned Linux reference
adapter; Windows isolation, WASI, microVM, service-broker, and resource-side adapters
can implement the same capability contract. E1 therefore names slangGraph adapter
models by capability rather than treating a Linux mechanism as the architecture.
It also records a separate host model. A projected adapter capability counts only
when the host model provides the corresponding host-bound capability; otherwise
the sink remains exposed with a `host lacks ... capability` decision.

The shared static instrument emits one record for every filesystem, network,
process, database/service, native, or dynamic sink reachable from a tool argument.
It then projects that one report through explicit mediation models for each defense.
This is intentionally generous to interface defenses: a sink is credited as
mediated whenever a sound argument constraint could dominate every tainted path,
even when the released policy does not contain that constraint.

Static exposure is an upper bound. A reported path may not be feasible at runtime.
The local canary PoCs provide a lower bound. The artifact reports the gap rather
than treating either number as ground truth.

## Safety boundary

PoCs target only deliberately vulnerable tools under `vulntools/` and benchmark
harnesses intended for evaluation. They use temporary directories, loopback
listeners, and local canaries. They do not exploit, probe, or modify Progent,
CaMeL, bolt-ons, or any third-party deployment.

## Reproducibility rules

- All model calls use the local Ollama OpenAI-compatible endpoint.
- Hosted and closed-source models are prohibited, including transcript generation
  and judging.
- Temperature is zero; model tag, immutable model ID/layer digest, context size,
  and seed are recorded with each run.
- Git repositories and Python distributions are pinned in `PINS.md`.
- Hardware and local model inventory are recorded in `HARDWARE.md`.
- Absolute ASR and utility are not compared with papers using GPT-4-class hosted
  models. Only within-artifact comparisons are valid.

## Experiment map

| ID | Purpose | Live model |
| --- | --- | --- |
| E0 | Reproduce released Progent/CaMeL baselines | as required by baseline |
| E1 | Static exposure census | no |
| E2 | Deterministic canary PoCs | seed generation once; replay thereafter |
| E3 | AgentDojo, InjecAgent, and ASB parity | yes, both local models |
| E4 | Mediation completeness on synthetic graph shapes | no |
| E5 | Per-stage and end-to-end overhead | no |

## Current implementation status

Hardware, exact model identities, dependency pins, the static instrument, eight
deliberately vulnerable tools, the E1 census, frozen local-model E2 transcripts,
local E2 canaries, and released Progent/bolt-on call-boundary runs are implemented.
CaMeL's released tests and a local-Ollama plumbing smoke test also run at the pin.
See `STATUS.md` for the exact completed/pending boundary and `reproduction/E0.md`
for baseline qualifications.

The original static experiment's adapter projections are capability-model results,
not runtime blocking evidence. The current implementation now documents a Grant
pipeline and Linux bubblewrap executor; see
[Linux host execution](../docs/security/users/linux-host-execution.md) for its
supported filesystem/resource subset and unsupported service/network authority.
That implementation does not retroactively validate static projections or existing
reports. No application condition is dynamically verified without its own activation
and independent effect evidence.

## Local commands

```bash
cd eval
make format
make lint
make test
make tables
make bolt-on-pocs
make seed-transcripts
```

`make tables` only reads audit databases and reports; it never runs an experiment.

## Trusted code versus host isolation

[E6](ISOLATION.md) adds a matched runtime operation census across trusted Python,
a synthetic restricted language, an admitted trusted helper, Linux host
isolation, and their combination. It reports positive controls, per-operation
effect evidence, activation receipts, and separate error/unavailable outcomes.
The language frontend is a mechanism ablation, not a released sandbox baseline.

```sh
uv run --project . python -m slanggraph_eval.isolation.run \
  --repetitions 3 --output reports/e6/new-run
```

## October 26 remaining evaluation handoff

The expanded campaign is in `campaigns/remaining-v1/`, with a distributable archive
under `handoffs/remaining-evaluation-20261026.tar.gz`. Start with its `RESULTS.md`
and `FAILURES.md`: application failures, unsupported routes and failed verifier
gates remain explicit. Original v2 cohorts are preserved under `completed-v2/`.
Regenerate summaries with `python3 scripts/summarize.py .` from the extracted
package; no benchmark rerun is required. New executable harnesses live in
`remaining/`; measured source snapshots are separate from reporting cleanups.
