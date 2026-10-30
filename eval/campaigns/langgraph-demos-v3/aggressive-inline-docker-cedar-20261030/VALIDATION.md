# Validation

- Campaign matrix: 350/350 attempts retained in five paired blocks.
- Baseline security-evidence records: 0.
- Missing-Cedar failures: 0.
- Missing-bubblewrap failures: 0.
- Configuration preflight: pinned Cedar and bubblewrap both passed before the
  campaign directory was created.
- Evaluation source formatting and Ruff lint: passed.
- Statistics and graph regeneration with the noninteractive Agg backend:
  passed.
- SHA-256 verification of committed campaign artifacts: passed.

D3 has 25 execution errors in each mode. T10 has five protected
`checkpoint:broken_chain` compatibility failures. D4 includes retained
compatibility failures and timeout-capped trials. These are reported outcomes,
not missing observations or validation failures.
