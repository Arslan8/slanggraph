# ruff: noqa: E501
"""Regenerate the aggressive execution-cost rerun summary."""

from __future__ import annotations

import hashlib
import json
import random
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEED = 20261030
RESAMPLES = 100_000


def rows(route: str) -> list[dict]:
    result = []
    for path in sorted((ROOT / "raw" / route).glob("*.jsonl")):
        result.extend(json.loads(line) for line in path.read_text().splitlines())
    return result


def interval(values: list[float]) -> list[float]:
    randomizer = random.Random(SEED)
    samples = sorted(
        statistics.mean(randomizer.choices(values, k=len(values))) for _ in range(RESAMPLES)
    )
    return [samples[2_500], samples[97_499]]


def main() -> None:
    calls = [row for row in rows("language") if row.get("phase") == "measured"]
    by_route = {
        name: [row for row in calls if row["route"] == name] for name in ("direct", "language")
    }
    summary = {}
    for name, selected in by_route.items():
        sessions = sorted({int(row["session"]) for row in selected})
        session_means = [
            statistics.mean(row["elapsed_ms"] for row in selected if row["session"] == session)
            for session in sessions
        ]
        summary[name] = {
            "calls": len(selected),
            "valid": sum(bool(row["valid"]) for row in selected),
            "sessions": len(sessions),
            "mean_ms": statistics.mean(row["elapsed_ms"] for row in selected),
            "session_block_ci95_ms": interval(session_means),
        }
    protected = by_route["language"]
    for phase in (
        "authorization_ms",
        "activation_ms",
        "execution_ms",
        "audit_ms",
        "framework_residual_ms",
        "policy_lowering_ms",
        "lean_ms",
    ):
        summary["language"][phase] = statistics.mean(float(row[phase]) for row in protected)
    summary["language"]["added_ms"] = summary["language"]["mean_ms"] - summary["direct"]["mean_ms"]
    summary["linux"] = {
        "status": "configuration_failed",
        "boundary": "preflight",
        "reason": "bubblewrap isolation is unavailable on this host",
        "security_weakened": False,
        "log": "raw/linux/linux-session-0.log",
    }
    output = {
        "revision": "41ea67d74530de858b59e3a565a7d15a13428cfb",
        "optimization": {
            "integrity": "preflight-only",
            "audit": "trusted-async",
            "runtime_policy_lowering": False,
            "runtime_lean": False,
        },
        "protocol": "five independent sessions, five warmups, twenty measured calls",
        "bootstrap": {"seed": SEED, "resamples": RESAMPLES, "unit": "session mean"},
        "routes": summary,
    }
    (ROOT / "statistics.json").write_text(json.dumps(output, indent=2) + "\n")
    direct = summary["direct"]
    language = summary["language"]
    markdown = f"""# Aggressive execution-cost rerun

Revision `41ea67d74530de858b59e3a565a7d15a13428cfb`; five fresh sessions, five warmups, and twenty measured calls per session. Admission, policy preparation/lowering, integrity setup, and worker prewarming are preflight and outside the online timer.

| Route | Valid calls | Mean ms | 95% session-block interval | Added ms |
|---|---:|---:|---:|---:|
| Direct | {direct["valid"]}/{direct["calls"]} | {direct["mean_ms"]:.3f} | [{direct["session_block_ci95_ms"][0]:.3f}, {direct["session_block_ci95_ms"][1]:.3f}] | — |
| Argus language | {language["valid"]}/{language["calls"]} | {language["mean_ms"]:.3f} | [{language["session_block_ci95_ms"][0]:.3f}, {language["session_block_ci95_ms"][1]:.3f}] | {language["added_ms"]:.3f} |

The protected mean comprises authorization {language["authorization_ms"]:.3f} ms, activation {language["activation_ms"]:.3f} ms, execution {language["execution_ms"]:.3f} ms, trusted-async audit acceptance {language["audit_ms"]:.3f} ms, and framework residual {language["framework_residual_ms"]:.3f} ms. Runtime policy lowering and runtime Lean are both {language["policy_lowering_ms"]:.3f} ms.

The pooled Linux routes could not run: mandatory bubblewrap isolation was unavailable during preflight. The configuration failed closed; no isolation option was weakened, and no runtime number is reported.
"""
    (ROOT / "RESULTS.md").write_text(markdown)
    hashes = []
    for path in sorted((ROOT / "raw").rglob("*")):
        if path.is_file():
            hashes.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT)}"
            )
    (ROOT / "SHA256SUMS").write_text("\n".join(hashes) + "\n")


if __name__ == "__main__":
    main()
