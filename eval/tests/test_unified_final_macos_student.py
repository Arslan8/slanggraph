"""Static contract tests for the external macOS host-security runner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns/unified-final-v1"
sys.path.insert(0, str(CAMPAIGN))

from macos_student import applicable_cases, build_command  # noqa: E402


def test_macos_student_uses_the_frozen_applicable_case_union() -> None:
    manifest = json.loads((CAMPAIGN / "host_cases.json").read_text())
    cases = applicable_cases(manifest)
    assert cases == [case["id"] for case in manifest["cases"] if case["macos"]]
    assert "required_syscall_filter" not in cases
    assert "extensible_required_syscalls" not in cases
    assert "direct_shm" in cases
    assert "required_per_process_cpu" in cases


def test_macos_student_command_fixes_repetitions_and_cases(tmp_path: Path) -> None:
    manifest = json.loads((CAMPAIGN / "host_cases.json").read_text())
    command = build_command(tmp_path / "evidence", repetitions=5, jobs=1, manifest=manifest)
    assert command[command.index("--repetitions") + 1] == "5"
    assert command[command.index("--jobs") + 1] == "1"
    assert command[command.index("--cases") + 1 :] == applicable_cases(manifest)
