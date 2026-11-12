# Unified final retained Linux result (`final-r3`)

This is the versioned result bundle for the qualified Linux
`unified-final-v1` campaign. `validation.json` accepts the collection with zero
errors. See `HANDOFF.md` for the fixes, selective-rerun decision, remaining
model errors, and result interpretation.

Reconstruct a validator-ready result directory from the repository root:

```bash
result=$(mktemp -d /tmp/unified-final-r3.XXXXXX)
retained=eval/campaigns/unified-final-v1/retained/final-r3

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
parts in lexical order.

The ignored local result directory also contains transient application
sandboxes and diagnostic logs. They are not needed to regenerate the four
summaries or validate completeness, configuration identity, timing, routes,
policy labels, and lifecycle counters.
