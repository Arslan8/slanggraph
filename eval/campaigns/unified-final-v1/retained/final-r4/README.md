# Unified final retained Linux result (`final-r4`)

This is the versioned result bundle for the qualified Linux
`unified-final-v1` campaign. `validation.json` accepts the complete collection
with zero errors. All 45 Linux security cases have decisive outcomes; see
`HANDOFF.md` for fixes, selective-rerun lineage, model errors, and result
interpretation.

Reconstruct a validator-ready result directory from the repository root:

```bash
result=$(mktemp -d /tmp/unified-final-r4.XXXXXX)
retained=eval/campaigns/unified-final-v1/retained/final-r4

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
cp "$retained"/{pandas-security,summary,validation,retained-lineage}.json \
  "$result/"
cp "$retained"/{REPORT,HANDOFF}.md "$result/"

(cd "$retained" && sha256sum --check SHA256SUMS)
(cd "$result" && sha256sum --check "$OLDPWD/$retained/RAW_SHA256SUMS")

uv run --project eval python eval/campaigns/unified-final-v1/validate.py \
  "$result" --output "$result/regenerated-validation.json"
uv run --project eval python eval/campaigns/unified-final-v1/report.py "$result"
```

`SHA256SUMS` authenticates the committed bundle. `RAW_SHA256SUMS`
authenticates the reconstructed raw and metadata files. Concatenate sustained
parts in lexical order. `micro-security.jsonl.zst` and `pandas-security.json`
are unchanged retained diagnostics authenticated by `retained-lineage.json`;
all 225 Linux host-security records are freshly collected on the final-r4
build.

Transient application sandboxes and verbose diagnostic logs are not needed to
regenerate the four summaries or validate completeness, configuration
identity, timing, routes, policy labels, and lifecycle counters.
