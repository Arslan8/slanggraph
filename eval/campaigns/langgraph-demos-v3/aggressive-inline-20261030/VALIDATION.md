# Validation

The changed evaluation Python files passed Ruff formatting and lint checks.
The targeted object-broker security tests passed (`25 passed`).

The required `libs/prebuilt` checks produced:

- `make format`: passed
- `make lint`: passed
- `make test`: 5,657 passed, 65 failed, 8 skipped in 648.94 seconds

All 65 failures are Linux resource-boundary tests whose setup raised
`RuntimeError: bubblewrap isolation is unavailable on this host`. This is the
same missing host capability recorded by the T1-T10 Argus campaign trials; no
different failure class appeared. The failures are retained rather than
reported as passing or skipped.
