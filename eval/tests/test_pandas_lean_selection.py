"""Explicit pinned checker selection; these tests do not execute a worker."""

import hashlib
import importlib.util
from pathlib import Path

import pytest


def _load(name, relative):
    path = Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


campaign = _load("pandas_campaign_selection", "remaining/application_campaign.py")
integration = _load("pandas_integration_selection", "apps/pandas/integration.py")


def test_cohort_captures_exact_selected_bytes_and_cannot_overwrite(tmp_path):
    original = tmp_path / "selected"
    original.write_bytes(b"pinned test image; not an executable proof artifact")
    image = original.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    output = tmp_path / "cohort"
    output.mkdir()
    selection = campaign.capture_lean_worker(output, original, digest)
    original.write_bytes(b"later source replacement")
    assert Path(selection["binary"]).read_bytes() == image
    assert selection["sha256"] == digest
    assert selection["protocol"] == "worker-route-grant-v3"
    with pytest.raises(FileExistsError):
        campaign.capture_lean_worker(output, Path(selection["binary"]), digest)
    assert Path(selection["binary"]).read_bytes() == image


def test_cohort_captures_native_checker_and_runtime_bytes(tmp_path):
    checker = tmp_path / "checker.so"
    runtime = tmp_path / "runtime.so"
    checker.write_bytes(b"pinned native checker fixture")
    runtime.write_bytes(b"pinned native runtime fixture")
    output = tmp_path / "cohort"
    output.mkdir()
    selection = campaign.capture_lean_worker(
        output,
        checker,
        hashlib.sha256(checker.read_bytes()).hexdigest(),
        runtime,
        hashlib.sha256(runtime.read_bytes()).hexdigest(),
    )
    assert Path(selection["binary"]).name == "libargus_worker_route.so"
    assert Path(selection["binary"]).read_bytes() == checker.read_bytes()
    assert Path(selection["runtime"]).name == "libleanshared.so"
    assert Path(selection["runtime"]).read_bytes() == runtime.read_bytes()


@pytest.mark.parametrize("digest", [None, "", "0" * 64, "G" * 64])
def test_bad_or_missing_pin_refuses_before_creating_cohort_image(tmp_path, digest):
    source = tmp_path / "selected"
    source.write_bytes(b"changed")
    with pytest.raises(ValueError):
        campaign.capture_lean_worker(tmp_path, source, digest)
    assert not (tmp_path / "workerRoute").exists()


def test_explicit_unselected_route_remains_unselected(tmp_path):
    assert campaign.capture_lean_worker(tmp_path, None, None) is None
    for configuration in ("A", "B", "C"):
        assert integration.selected_lifecycle_checker({"configuration": configuration}) is None


@pytest.mark.parametrize(
    "configuration,selection",
    [
        ("A", {"binary": "/unused", "sha256": "0" * 64, "protocol": "worker-route-grant-v3"}),
        ("B", {"binary": "/unused", "sha256": "0" * 64, "protocol": "worker-route-grant-v3"}),
        ("C", {}),
        ("C", []),
        ("C", {"binary": "/unused", "sha256": "0" * 64, "protocol": "worker-route-v1"}),
        ("C", {"binary": "/unused", "sha256": "0" * 64, "protocol": "worker-route-receipt-v2"}),
        (
            "C",
            {
                "binary": "/unused",
                "sha256": "0" * 64,
                "protocol": "worker-route-grant-v3",
                "fallback": True,
            },
        ),
    ],
)
def test_wrong_condition_version_or_unknown_fields_cannot_fall_back(configuration, selection):
    with pytest.raises(ValueError, match="Invalid selected Lean worker route"):
        integration.selected_lifecycle_checker(
            {"configuration": configuration, "lean_worker": selection}
        )


def test_selected_c_route_captures_pin_and_rejects_later_substitution(tmp_path):
    from langgraph.prebuilt.security.execution import HostExecutionDenied

    source = tmp_path / "selected"
    source.write_bytes(b"bounded constructor fixture; not native execution evidence")
    selection = {
        "binary": str(source),
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "protocol": "worker-route-grant-v3",
    }
    request = {"configuration": "C", "lean_worker": selection}
    checker = integration.selected_lifecycle_checker(request)
    assert checker.binary_sha256 == selection["sha256"]
    source.write_bytes(b"replacement")
    with pytest.raises(HostExecutionDenied):
        integration.selected_lifecycle_checker(request)
