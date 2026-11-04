#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || $1 != /* ]]; then
  echo "usage: $0 /absolute/path/to/new-output-directory" >&2
  exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
output=$1
artifacts="${output}.artifacts"
qualification="${output}.host-qualification.json"
library="$artifacts/libargus_worker_route.so"
runtime=/home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so

mkdir -p "$artifacts"
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/proofs/worker-route/build_native.py" \
  --lake /home/faculty/abk6349/.elan/bin/lake \
  --output "$library"
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/campaigns/argus-paper-revision-v1/qualify_host.py" \
  --output "$qualification" --seconds 30
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/campaigns/argus-paper-revision-v1/run_performance.py" \
  --output "$output" \
  --checker-library "$library" \
  --checker-runtime "$runtime" \
  --qualification "$qualification" \
  --acknowledge-controlled-host \
  --sessions 5 --warmups 10 --measured 20
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/campaigns/argus-paper-revision-v1/summarize_performance.py" \
  --raw "$output/raw" --output "$output/summary.json"
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/campaigns/argus-paper-revision-v1/run_adversarial_regressions.py" \
  --output "${output}.adversarial"
PYTHONPATH="$root/libs/prebuilt:$root/libs/langgraph:$root/libs/checkpoint" \
  "$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/remaining/composition.py" \
  --output "${output}.application" --repetitions 1 \
  --checker-library "$library" --checker-runtime "$runtime"
