# Unified final retained result (`final-r2`)

This directory is the versioned result bundle for the completed Linux
`unified-final-v1` campaign. The report was generated from the raw request,
host-security, and sustained records and then accepted by `validate.py` with
zero errors.

The bundle uses lossless compression. Reconstruct a validator-ready result
directory from the repository root:

```bash
result=$(mktemp -d /tmp/unified-final-r2.XXXXXX)
retained=eval/campaigns/unified-final-v1/retained/final-r2

zstd -d --stdout "$retained/records.jsonl.zst" > "$result/records.jsonl"
zstd -d --stdout "$retained/host-security.jsonl.zst" \
  > "$result/host-security.jsonl"
zstd -d --stdout "$retained/micro-security.jsonl.zst" \
  > "$result/micro-security.jsonl"
cat "$retained"/sustained.jsonl.zst.part-* \
  | zstd -d --stdout > "$result/sustained.jsonl"

cp "$retained"/{configuration,schedule,source-pins,prepared}.json "$result/"
cp "$retained"/{supporting-validation,qualification,freeze}.json "$result/"
cp "$retained"/{admission_inventory,policy_mapping,host_cases}.json "$result/"
cp "$retained"/{pandas-security,summary,validation}.json "$result/"
cp "$retained/REPORT.md" "$result/"

(cd "$retained" && sha256sum --check SHA256SUMS)
(cd "$result" && sha256sum --check "$OLDPWD/$retained/RAW_SHA256SUMS")

uv run --project eval python eval/campaigns/unified-final-v1/validate.py \
  "$result" --output "$result/regenerated-validation.json"
uv run --project eval python eval/campaigns/unified-final-v1/report.py "$result"
```

`SHA256SUMS` authenticates the versioned bundle. `RAW_SHA256SUMS` authenticates
the reconstructed raw and metadata files. The split sustained parts must be
concatenated in lexical order.

The ignored local result directory also contains bulky application sandboxes,
service state, and diagnostic logs. Those transient files are not needed to
regenerate the four summaries or validate sample completeness, configuration
identity, timing fields, routes, enforcement labels, and worker lifecycle
counters.
