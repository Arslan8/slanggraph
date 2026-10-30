"""Configurable executable-integrity rechecks for prepared Linux workers."""

from __future__ import annotations

from pathlib import Path

import pytest

from langgraph.prebuilt.security import IntegrityRecheckMode
from langgraph.prebuilt.security import linux as linux_security
from langgraph.prebuilt.security.execution import HostExecutionDenied


class _FixedRandom:
    def __init__(self, selected: int) -> None:
        self.selected = selected

    def sample(self, population, count):
        assert self.selected in population
        assert count == 1
        return [self.selected]


def test_highest_optimization_level_requires_preflight_only() -> None:
    assert (
        IntegrityRecheckMode.for_optimization("aggressive")
        is IntegrityRecheckMode.PREFLIGHT_ONLY
    )
    assert IntegrityRecheckMode.for_optimization("normal") is IntegrityRecheckMode.FULL
    assert IntegrityRecheckMode.for_optimization("no") is IntegrityRecheckMode.FULL
    with pytest.raises(ValueError, match="optimization level"):
        IntegrityRecheckMode.for_optimization("unknown")


def test_merkle_sample_detects_selected_chunk_and_size_changes(
    tmp_path: Path, monkeypatch
) -> None:
    artifact = tmp_path / "runtime.bin"
    artifact.write_bytes(b"A" * 4096 + b"B" * 4096 + b"C" * 4096)
    commitment = linux_security._merkle_commitment(artifact, 4096)
    monkeypatch.setattr(linux_security.secrets, "SystemRandom", lambda: _FixedRandom(1))

    assert linux_security._verify_merkle_sample(artifact, commitment, 1)
    artifact.write_bytes(b"A" * 4096 + b"X" * 4096 + b"C" * 4096)
    assert not linux_security._verify_merkle_sample(artifact, commitment, 1)
    artifact.write_bytes(b"A" * 4096 + b"B" * 4096)
    assert not linux_security._verify_merkle_sample(artifact, commitment, 1)


def test_merkle_sample_documents_unsampled_same_size_gap(
    tmp_path: Path, monkeypatch
) -> None:
    artifact = tmp_path / "runtime.bin"
    artifact.write_bytes(b"A" * 4096 + b"B" * 4096)
    commitment = linux_security._merkle_commitment(artifact, 4096)
    artifact.write_bytes(b"A" * 4096 + b"X" * 4096)
    monkeypatch.setattr(linux_security.secrets, "SystemRandom", lambda: _FixedRandom(0))

    assert linux_security._verify_merkle_sample(artifact, commitment, 1)


@pytest.mark.parametrize(
    ("mode", "detects_change"),
    [
        (IntegrityRecheckMode.FULL, True),
        (IntegrityRecheckMode.PREFLIGHT_ONLY, False),
    ],
)
def test_attestation_integrity_modes(
    tmp_path: Path, mode: IntegrityRecheckMode, detects_change: bool
) -> None:
    artifact = tmp_path / "runtime.bin"
    artifact.write_bytes(b"A" * 8192)
    adapter = linux_security._LinuxBubblewrapAdapter(
        str(artifact),
        b"test-key",
        artifact,
        artifact,
        30.0,
        mode,
        4096,
        1,
    )
    artifact.write_bytes(b"X" * 8192)

    if detects_change:
        with pytest.raises(HostExecutionDenied, match="bubblewrap_changed"):
            adapter.attest("nonce")
    else:
        attestation = adapter.attest("nonce")
        assert attestation.evidence["integrity_recheck"]["mode"] == mode.value


def test_merkle_attestation_records_commitment_and_detects_sample(
    tmp_path: Path, monkeypatch
) -> None:
    artifact = tmp_path / "runtime.bin"
    artifact.write_bytes(b"A" * 4096 + b"B" * 4096)
    adapter = linux_security._LinuxBubblewrapAdapter(
        str(artifact),
        b"test-key",
        artifact,
        artifact,
        30.0,
        IntegrityRecheckMode.MERKLE_SAMPLE,
        4096,
        1,
    )
    monkeypatch.setattr(linux_security.secrets, "SystemRandom", lambda: _FixedRandom(1))
    evidence = adapter.attest("first")
    integrity = evidence.evidence["integrity_recheck"]
    assert integrity["mode"] == "merkle-sample"
    assert integrity["merkle_roots"]["interpreter"]
    assert integrity["merkle_sizes"]["interpreter"] == 8192

    artifact.write_bytes(b"A" * 4096 + b"X" * 4096)
    with pytest.raises(HostExecutionDenied, match="bubblewrap_sample_changed"):
        adapter.attest("second")
