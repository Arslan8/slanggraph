"""Canonical-path admission stays symlink-free during the descriptor open."""

import os
from pathlib import Path

import pytest

from langgraph.prebuilt.security import linux


def test_ancestor_replaced_after_canonical_check_cannot_redirect_mount(tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "record").write_text("allowed")
    (outside / "record").write_text("outside")
    checked = linux._canonical_existing_path(allowed / "record")
    allowed.rename(tmp_path / "moved")
    allowed.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        linux._verified_resource_fd(checked)


@pytest.mark.parametrize("directory", [False, True])
def test_canonical_native_resource_still_opens_and_is_identity_bound(
    tmp_path, directory
):
    resource = tmp_path / "resource"
    if directory:
        resource.mkdir()
    else:
        resource.write_text("useful resource")
    fd = linux._verified_resource_fd(resource)
    try:
        assert os.fstat(fd).st_ino == resource.stat().st_ino
        assert not os.get_inheritable(fd)
        if not directory:
            assert Path(f"/proc/self/fd/{fd}").read_text() == "useful resource"
    finally:
        os.close(fd)


def test_hard_link_alias_resolves_to_the_authorized_object_identity(tmp_path):
    resource = tmp_path / "authorized-record"
    alias = tmp_path / "record-alias"
    resource.write_text("alice-record")
    os.link(resource, alias)

    fd = linux._verified_resource_fd(alias)
    try:
        opened = os.fstat(fd)
        intended = resource.stat()
        assert (opened.st_dev, opened.st_ino) == (intended.st_dev, intended.st_ino)
        assert Path(f"/proc/self/fd/{fd}").read_text() == "alice-record"
        assert not os.get_inheritable(fd)
    finally:
        os.close(fd)


def test_missing_atomic_path_resolution_refuses_without_pathname_fallback(
    tmp_path, monkeypatch
):
    resource = tmp_path / "resource"
    resource.write_text("useful resource")

    def unavailable(*args, **kwargs):
        raise OSError("openat2 unavailable")

    monkeypatch.setattr(linux, "open_path_descriptor", unavailable)
    with pytest.raises(OSError, match="openat2 unavailable"):
        linux._verified_resource_fd(resource)
