# Full aggressive ordinary-demo campaign

This is the valid replacement for the two failed setup attempts on 2026-10-30.
It contains 350 retained attempts over 15 applications and five paired
repetition blocks. The evaluated revision is
`fc6d2aafff281611d101daa9951aeb354075a058`.

The outer Docker harness deliberately relaxes its AppArmor, seccomp, and
system-path restrictions so the production inner bubblewrap/Landlock/seccomp
boundary can activate. The outer container is not presented as an additional
security boundary. `ENVIRONMENT.json` records the image, mounts, executables,
and exact digests.

The primary timer is parent subprocess wall time inside the already running
campaign container. It includes per-task process startup, model calls, graph
execution, Argus checks, tools, retries, audit acceptance, and shutdown. It
does not include one-time outer-container creation or campaign preflight.

## Reproduction

Start the pinned model service, then run from the repository root:

```bash
docker run --rm --user 0:0 --network host \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v /data/langgraph:/data/langgraph \
  -v /data/.cache/uv:/data/.cache/uv \
  -v /home/faculty/abk6349/.local/share/uv:/home/faculty/abk6349/.local/share/uv:ro \
  -v /home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1:/home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1:ro \
  -v /home/faculty/abk6349/.cargo/bin/cedar:/opt/cedar/cedar:ro \
  -e PATH=/opt/cedar:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -w /data/langgraph slg-linux-test:latest \
  uv run --python 3.11 --project eval \
  --with langchain-openai==1.7.2 --with scikit-learn --with pandas \
  --with langchain-community --with langchain-experimental \
  --with matplotlib --with pytz \
  python eval/campaigns/langgraph-demos-v3/run_campaign.py \
  --run-id reproduction-docker-cedar --repetitions 5
```

Regenerate the paper outputs without rerunning trials:

```bash
MPLBACKEND=Agg uv run --python 3.11 --project eval --with matplotlib \
  python eval/campaigns/langgraph-demos-v3/regenerate.py \
  --run-id aggressive-inline-docker-cedar-20261030 \
  --output-dir eval/campaigns/langgraph-demos-v3/aggressive-inline-docker-cedar-20261030
```

Disposable per-trial SQLite copies and chart intermediates remain local and
are not stored in Git. The complete aggregate trial records, outputs embedded
in those records, frozen source/fixture identities, and result hashes are
retained.
