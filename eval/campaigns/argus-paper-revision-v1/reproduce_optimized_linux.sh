#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /absolute/path/to/new-output-directory" >&2
  exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
output=$1
artifacts="${output}.artifacts"
qualification="${output}.host-qualification.json"
library="$artifacts/libargus_worker_route.so"

mkdir -p "$artifacts"
python3 "$root/proofs/worker-route/build_native.py" \
  --lake /home/faculty/abk6349/.elan/bin/lake \
  --output "$library"
runtime=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["native_runtime"])' \
  "$library.json")
python3 "$root/eval/campaigns/argus-paper-revision-v1/qualify_host.py" \
  --output "$qualification"
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/campaigns/argus-paper-revision-v1/run_performance.py" \
  --output "$output" \
  --checker-library "$library" \
  --checker-runtime "$runtime" \
  --qualification "$qualification" \
  --acknowledge-controlled-host
"$root/libs/prebuilt/.venv/bin/python" \
  "$root/eval/campaigns/argus-paper-revision-v1/summarize_performance.py" \
  --raw "$output/raw" \
  --output "$output/RESULTS.json"
